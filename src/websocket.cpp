#include "websocket.h"

#include <cstdlib>
#include <cstring>

#include "log.h"
#include "util.h"

namespace ws {
namespace {

const char* kWsGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
// A control-channel AgentMessage is small; data frames are bounded by the MGS
// stream chunking (~1 KB payloads). 1 MiB rejects a corrupt length field
// before it turns into an allocation.
constexpr uint64_t kMaxFrameSize = 1024 * 1024;

}  // namespace

std::string accept_key_for(const std::string& sec_websocket_key) {
    return util::base64_encode(util::sha1_raw(sec_websocket_key + kWsGuid));
}

std::string make_frame(uint8_t opcode, const std::string& payload, const unsigned char mask[4]) {
    std::string out;
    out.reserve(payload.size() + 14);
    out += static_cast<char>(0x80 | (opcode & 0x0F));  // FIN, no fragmentation on send
    const size_t len = payload.size();
    if (len < 126) {
        out += static_cast<char>(0x80 | len);  // MASK bit
    } else if (len <= 0xFFFF) {
        out += static_cast<char>(0x80 | 126);
        out += static_cast<char>((len >> 8) & 0xFF);
        out += static_cast<char>(len & 0xFF);
    } else {
        out += static_cast<char>(0x80 | 127);
        for (int shift = 56; shift >= 0; shift -= 8)
            out += static_cast<char>((static_cast<uint64_t>(len) >> shift) & 0xFF);
    }
    out.append(reinterpret_cast<const char*>(mask), 4);
    const size_t data_at = out.size();
    out += payload;
    for (size_t i = 0; i < len; i++)
        out[data_at + i] = static_cast<char>(out[data_at + i] ^ mask[i % 4]);
    return out;
}

int parse_frame(std::string& buf, bool& fin, uint8_t& opcode, std::string& payload,
                std::string& err) {
    if (buf.size() < 2) return 0;
    const unsigned char b0 = static_cast<unsigned char>(buf[0]);
    const unsigned char b1 = static_cast<unsigned char>(buf[1]);
    fin = (b0 & 0x80) != 0;
    if (b0 & 0x70) {
        err = "reserved bits set (no extensions negotiated)";
        return -1;
    }
    opcode = b0 & 0x0F;
    const bool masked = (b1 & 0x80) != 0;  // server frames must not be masked
    uint64_t len = b1 & 0x7F;
    size_t at = 2;
    if (len == 126) {
        if (buf.size() < 4) return 0;
        len = (static_cast<uint64_t>(static_cast<unsigned char>(buf[2])) << 8) |
              static_cast<unsigned char>(buf[3]);
        at = 4;
    } else if (len == 127) {
        if (buf.size() < 10) return 0;
        len = 0;
        for (int i = 0; i < 8; i++)
            len = (len << 8) | static_cast<unsigned char>(buf[2 + i]);
        at = 10;
    }
    if (len > kMaxFrameSize) {
        err = "frame too large: " + std::to_string(len);
        return -1;
    }
    unsigned char mask[4] = {0, 0, 0, 0};
    if (masked) {
        if (buf.size() < at + 4) return 0;
        std::memcpy(mask, buf.data() + at, 4);
        at += 4;
    }
    if (buf.size() < at + len) return 0;
    payload.assign(buf, at, static_cast<size_t>(len));
    if (masked)
        for (size_t i = 0; i < payload.size(); i++)
            payload[i] = static_cast<char>(payload[i] ^ mask[i % 4]);
    buf.erase(0, at + static_cast<size_t>(len));
    return 1;
}

bool Client::connect(const std::string& host, int port, bool tls, const std::string& path,
                     const std::vector<std::pair<std::string, std::string>>& extra_headers,
                     int timeout_ms, std::string& err) {
    close();
    if (!stream_.connect(host, port, tls, timeout_ms, err)) return false;

    const std::string key_raw = util::random_bytes(16);
    if (key_raw.size() != 16) {
        err = "no entropy for Sec-WebSocket-Key";
        return false;
    }
    const std::string key = util::base64_encode(key_raw);

    std::string req = "GET " + path + " HTTP/1.1\r\n";
    req += "Host: " + host + "\r\n";
    req += "Upgrade: websocket\r\n";
    req += "Connection: Upgrade\r\n";
    req += "Sec-WebSocket-Key: " + key + "\r\n";
    req += "Sec-WebSocket-Version: 13\r\n";
    for (const auto& h : extra_headers) req += h.first + ": " + h.second + "\r\n";
    req += "\r\n";
    if (!stream_.write(req, err)) return false;

    // Read the 101 response head; anything after \r\n\r\n is already frames.
    std::string head;
    while (head.find("\r\n\r\n") == std::string::npos) {
        char chunk[4096];
        ssize_t n = stream_.read(chunk, sizeof(chunk), err);
        if (n <= 0) {
            if (err.empty())
                err = (n == -2) ? "upgrade timed out" : "connection closed during upgrade";
            return false;
        }
        head.append(chunk, static_cast<size_t>(n));
        if (head.size() > 64 * 1024) {
            err = "oversized upgrade response";
            return false;
        }
    }
    const size_t end = head.find("\r\n\r\n");
    read_buf_ = head.substr(end + 4);
    head.resize(end);

    const size_t sp = head.find(' ');
    const int status = (sp == std::string::npos) ? 0 : std::atoi(head.c_str() + sp + 1);
    if (status != 101) {
        err = "upgrade refused: " + util::clip(head, 400, "...");
        return false;
    }
    // Verify the accept key: proves the peer actually spoke WebSocket.
    const std::string want = accept_key_for(key);
    std::string lower = util::lower(head);
    size_t pos = lower.find("sec-websocket-accept:");
    if (pos == std::string::npos) {
        err = "upgrade response missing Sec-WebSocket-Accept";
        return false;
    }
    size_t eol = head.find("\r\n", pos);
    std::string got = util::trim(head.substr(pos + 21, eol - pos - 21));
    if (got != want) {
        err = "Sec-WebSocket-Accept mismatch";
        return false;
    }

    open_ = true;
    return true;
}

bool Client::send(uint8_t opcode, const std::string& payload, std::string& err) {
    if (!open_) {
        err = "websocket not open";
        return false;
    }
    std::string mask = util::random_bytes(4);
    if (mask.size() != 4) mask.assign(4, '\x5a');  // still valid masking, just not random
    const std::string frame =
        make_frame(opcode, payload, reinterpret_cast<const unsigned char*>(mask.data()));
    std::lock_guard<std::mutex> lock(write_mu_);
    if (!stream_.write(frame, err)) {
        open_ = false;
        return false;
    }
    return true;
}

int Client::recv(Frame& out, std::string& err) {
    if (!open_) {
        err = "websocket not open";
        return -1;
    }
    while (true) {
        bool fin = false;
        uint8_t opcode = 0;
        std::string payload;
        int rc = parse_frame(read_buf_, fin, opcode, payload, err);
        if (rc < 0) {
            open_ = false;
            return -1;
        }
        if (rc == 0) {
            char chunk[16 * 1024];
            std::string rerr;
            ssize_t n = stream_.read(chunk, sizeof(chunk), rerr);
            if (n == -2) return 0;  // recv timeout: nothing yet
            if (n <= 0) {
                err = rerr.empty() ? "connection closed" : rerr;
                open_ = false;
                return -1;
            }
            read_buf_.append(chunk, static_cast<size_t>(n));
            continue;
        }

        switch (opcode) {
            case kOpPing: {
                std::string perr;
                send(kOpPong, payload, perr);  // best effort
                continue;
            }
            case kOpPong:
                continue;
            case kOpClose: {
                std::string cerr;
                send(kOpClose, payload, cerr);  // echo per RFC 6455 5.5.1
                open_ = false;
                err = "close frame received";
                return -1;
            }
            case 0x0:  // continuation
                frag_payload_ += payload;
                if (fin) {
                    out.opcode = frag_opcode_;
                    out.payload = std::move(frag_payload_);
                    frag_payload_.clear();
                    frag_opcode_ = 0;
                    return 1;
                }
                continue;
            default:  // text or binary
                if (!fin) {
                    frag_opcode_ = opcode;
                    frag_payload_ = std::move(payload);
                    continue;
                }
                out.opcode = opcode;
                out.payload = std::move(payload);
                return 1;
        }
    }
}

void Client::close() {
    if (open_) {
        std::string err;
        send(kOpClose, std::string("\x03\xe8", 2), err);  // 1000 normal closure
    }
    open_ = false;
    read_buf_.clear();
    frag_payload_.clear();
    stream_.close();
}

}  // namespace ws
