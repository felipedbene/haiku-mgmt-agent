// websocket.h -- minimal RFC 6455 client over http::Stream (F6: MGS channels).
//
// Exists for the same reason as http.cpp: there is no WebSocket library on
// haiku/arm64 to link against. Client-side only, no extensions, no
// compression; text/binary/ping/pong/close and fragmentation are enough for
// the MGS control and data channels.
#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "http.h"

namespace ws {

constexpr uint8_t kOpText = 0x1;
constexpr uint8_t kOpBinary = 0x2;
constexpr uint8_t kOpClose = 0x8;
constexpr uint8_t kOpPing = 0x9;
constexpr uint8_t kOpPong = 0xA;

struct Frame {
    uint8_t opcode = 0;
    std::string payload;
};

// ---- pure helpers, host-testable ----

// Client frames must be masked (RFC 6455 5.3); `mask` are the 4 key bytes.
std::string make_frame(uint8_t opcode, const std::string& payload, const unsigned char mask[4]);

// Parses one (possibly partial) frame from buf. Returns:
//   1 complete frame consumed (out + header/payload erased from buf)
//   0 need more bytes
//  -1 protocol error (err set)
int parse_frame(std::string& buf, bool& fin, uint8_t& opcode, std::string& payload,
                std::string& err);

// Sec-WebSocket-Accept for a given Sec-WebSocket-Key (RFC 6455 4.2.2).
std::string accept_key_for(const std::string& sec_websocket_key);

// ---- client ----

class Client {
public:
    // Performs the HTTP upgrade. `path` includes the query string;
    // `extra_headers` carries the SigV4 signature for MGS.
    bool connect(const std::string& host, int port, bool tls, const std::string& path,
                 const std::vector<std::pair<std::string, std::string>>& extra_headers,
                 int timeout_ms, std::string& err);

    // Thread-safe (one writer lock): the data-channel sender and the ping
    // timer write concurrently.
    bool send(uint8_t opcode, const std::string& payload, std::string& err);

    // Blocks up to the stream's recv timeout. Returns:
    //   1 a data frame (text/binary) is in `out`
    //   0 timeout, nothing received (connection healthy)
    //  -1 closed or failed (err says why)
    // Pings are answered and pongs swallowed internally; a close frame is
    // replied to and reported as -1.
    int recv(Frame& out, std::string& err);

    void set_recv_timeout(int timeout_ms) { stream_.set_recv_timeout(timeout_ms); }
    void close();
    bool open() const { return open_; }

private:
    http::Stream stream_;
    std::mutex write_mu_;
    std::string read_buf_;
    // Fragmented message reassembly (continuation frames).
    uint8_t frag_opcode_ = 0;
    std::string frag_payload_;
    bool open_ = false;
};

}  // namespace ws
