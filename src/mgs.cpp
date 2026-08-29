#include "mgs.h"

#include <cctype>
#include <cstring>

#include "http.h"
#include "log.h"
#include "util.h"

namespace mgs {

const char* kMsgInteractiveShell = "interactive_shell";
const char* kMsgAgentJob = "agent_job";
const char* kMsgChannelClosed = "channel_closed";
const char* kMsgAcknowledge = "acknowledge";
const char* kMsgAgentSessionState = "agent_session_state";
const char* kMsgInputStreamData = "input_stream_data";
const char* kMsgOutputStreamData = "output_stream_data";
const char* kMsgPausePublication = "pause_publication";
const char* kMsgStartPublication = "start_publication";
const char* kMsgTaskComplete = "agent_task_complete";
const char* kMsgTaskAcknowledge = "agent_task_acknowledge";

namespace {

// agentmessage.go offsets: HL(4) + MessageType(32) + SchemaVersion(4) +
// CreatedDate(8) + SequenceNumber(8) + Flags(8) + MessageId(16) + Digest(32) +
// PayloadType(4) = 116, then PayloadLength(4), then payload.
constexpr size_t kHeaderLength = 116;
constexpr size_t kTypeOffset = 4;
constexpr size_t kTypeLength = 32;
constexpr size_t kSchemaOffset = 36;
constexpr size_t kCreatedOffset = 40;
constexpr size_t kSequenceOffset = 48;
constexpr size_t kFlagsOffset = 56;
constexpr size_t kUuidOffset = 64;
constexpr size_t kDigestOffset = 80;
constexpr size_t kPayloadTypeOffset = 112;
constexpr size_t kPayloadLenOffset = 116;
constexpr size_t kPayloadOffset = 120;

void put_u32(std::string& b, size_t at, uint32_t v) {
    for (int i = 0; i < 4; i++) b[at + i] = static_cast<char>((v >> (24 - 8 * i)) & 0xFF);
}

void put_u64(std::string& b, size_t at, uint64_t v) {
    for (int i = 0; i < 8; i++) b[at + i] = static_cast<char>((v >> (56 - 8 * i)) & 0xFF);
}

uint32_t get_u32(const std::string& b, size_t at) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) v = (v << 8) | static_cast<unsigned char>(b[at + i]);
    return v;
}

uint64_t get_u64(const std::string& b, size_t at) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | static_cast<unsigned char>(b[at + i]);
    return v;
}

int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

}  // namespace

bool uuid_to_wire(const std::string& uuid_text, unsigned char out[16]) {
    unsigned char bytes[16];
    size_t n = 0;
    for (size_t i = 0; i + 1 < uuid_text.size() && n < 16; i++) {
        if (uuid_text[i] == '-') continue;
        int hi = hex_nibble(uuid_text[i]);
        int lo = hex_nibble(uuid_text[i + 1]);
        if (hi < 0 || lo < 0) return false;
        bytes[n++] = static_cast<unsigned char>((hi << 4) | lo);
        i++;
    }
    if (n != 16) return false;
    // putUuid: least-significant 8 bytes first, then most-significant 8.
    std::memcpy(out, bytes + 8, 8);
    std::memcpy(out + 8, bytes, 8);
    return true;
}

std::string uuid_from_wire(const unsigned char in[16]) {
    unsigned char bytes[16];
    std::memcpy(bytes, in + 8, 8);  // most-significant half was stored second
    std::memcpy(bytes + 8, in, 8);
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(36);
    for (int i = 0; i < 16; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10) out += '-';
        out += digits[bytes[i] >> 4];
        out += digits[bytes[i] & 0x0F];
    }
    return out;
}

std::string serialize(const AgentMessage& m) {
    std::string out(kPayloadOffset + m.payload.size(), '\0');
    put_u32(out, 0, kHeaderLength);
    // MessageType is space-padded to its 32-byte field (putString).
    for (size_t i = 0; i < kTypeLength; i++)
        out[kTypeOffset + i] = i < m.message_type.size() ? m.message_type[i] : ' ';
    put_u32(out, kSchemaOffset, m.schema_version);
    put_u64(out, kCreatedOffset, m.created_ms);
    put_u64(out, kSequenceOffset, static_cast<uint64_t>(m.sequence));
    put_u64(out, kFlagsOffset, m.flags);
    unsigned char uuid_bytes[16] = {0};
    uuid_to_wire(m.message_id, uuid_bytes);
    std::memcpy(&out[kUuidOffset], uuid_bytes, 16);
    const std::string digest = util::sha256_raw(m.payload);
    std::memcpy(&out[kDigestOffset], digest.data(), 32);
    put_u32(out, kPayloadTypeOffset, m.payload_type);
    put_u32(out, kPayloadLenOffset, static_cast<uint32_t>(m.payload.size()));
    std::memcpy(&out[kPayloadOffset], m.payload.data(), m.payload.size());
    return out;
}

bool deserialize(const std::string& raw, AgentMessage& out, std::string& err) {
    if (raw.size() < kPayloadOffset) {
        err = "message too short: " + std::to_string(raw.size()) + " bytes";
        return false;
    }
    const uint32_t header_len = get_u32(raw, 0);
    if (header_len != kHeaderLength) {
        // Tolerate a larger declared header (schema evolution), never a smaller one.
        if (header_len < kHeaderLength || raw.size() < header_len + 4) {
            err = "unexpected header length " + std::to_string(header_len);
            return false;
        }
    }
    std::string type = raw.substr(kTypeOffset, kTypeLength);
    // Field is space/NUL padded.
    while (!type.empty() && (type.back() == ' ' || type.back() == '\0')) type.pop_back();
    out.message_type = type;
    out.schema_version = get_u32(raw, kSchemaOffset);
    out.created_ms = get_u64(raw, kCreatedOffset);
    out.sequence = static_cast<int64_t>(get_u64(raw, kSequenceOffset));
    out.flags = get_u64(raw, kFlagsOffset);
    out.message_id =
        uuid_from_wire(reinterpret_cast<const unsigned char*>(raw.data() + kUuidOffset));
    out.payload_type = get_u32(raw, kPayloadTypeOffset);

    // Payload is everything after the header + the 4-byte PayloadLength field.
    // We deliberately take the whole remainder rather than a PayloadLength-bounded
    // slice, and we do NOT verify the payload digest here. Both match the
    // reference Go agent's Deserialize (agentmessage.go): it sets
    //   Payload = input[HeaderLength+4:]
    // and never compares PayloadDigest. Verifying the digest broke real sessions
    // on the live service (issue #2): the service's stored digest for some
    // inbound messages, e.g. the HandshakeResponse, does not equal
    // sha256(payload) as we compute it, so a strict check silently dropped the
    // handshake and the pty was never spawned. TLS already protects transport
    // integrity, which is why the reference agent trusts the payload.
    const size_t payload_at = static_cast<size_t>(header_len) + 4;
    out.payload = raw.substr(payload_at);
    return true;
}

std::string endpoint(const std::string& region) {
    return "ssmmessages." + region + ".amazonaws.com";
}

std::vector<std::pair<std::string, std::string>> ws_upgrade_headers(
    const aws::Credentials& creds, const std::string& region, const std::string& host,
    const std::string& path, const std::string& query) {
    // The Go agent signs the upgrade GET with an empty payload (websocketchannel.go).
    return aws::sigv4_headers("GET", "ssmmessages", region, creds, host, path, query,
                              util::sha256_hex(""), util::now_epoch());
}

bool create_channel(aws::CredentialProvider& creds, const std::string& region,
                    const std::string& channel_type, const std::string& channel_id,
                    std::string& token, std::string& err) {
    aws::Credentials c;
    if (!creds.get(c)) {
        err = "no credentials available";
        return false;
    }

    json::Value body = json::obj();
    body.object["MessageSchemaVersion"] = json::str("1.0");
    body.object["RequestId"] = json::str(util::uuid4());
    const std::string payload = json::dump(body);

    const std::string host = endpoint(region);
    const std::string path = "/v1/" + channel_type + "/" + channel_id;

    http::Request req;
    req.method = "POST";
    req.tls = true;
    req.host = host;
    req.path = path;
    req.body = payload;
    req.timeout_ms = 15000;  // mgsClientTimeout in the Go agent
    req.headers.push_back({"Content-Type", "application/json"});
    for (auto& h : aws::sigv4_headers("POST", "ssmmessages", region, c, host, path, "",
                                      util::sha256_hex(payload), util::now_epoch()))
        req.headers.push_back(h);
    req.headers.push_back({"User-Agent", "haiku-mgmt-agent"});

    http::Response resp = http::perform(req);
    // The service replies 201 Created (service.go httpStatusCodeCreated).
    if (!resp.error.empty() || resp.status < 200 || resp.status >= 300) {
        err = "Create" + channel_type + " failed: status=" + std::to_string(resp.status) + " " +
              resp.error + " " + util::clip(resp.body, 300, "...");
        return false;
    }

    // Body observed as JSON; the Go agent decodes it as XML. Accept both.
    std::string jerr;
    json::Value v = json::parse(resp.body, &jerr);
    if (jerr.empty() && v.is_obj()) token = v.str_at("TokenValue");
    if (token.empty()) {
        size_t open = resp.body.find("<TokenValue>");
        size_t close = resp.body.find("</TokenValue>");
        if (open != std::string::npos && close != std::string::npos && close > open)
            token = resp.body.substr(open + 12, close - open - 12);
    }
    if (token.empty()) {
        err = "no TokenValue in Create" + channel_type + " response: " +
              util::clip(resp.body, 300, "...");
        return false;
    }
    return true;
}

}  // namespace mgs
