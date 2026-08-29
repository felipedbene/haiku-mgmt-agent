// http.h -- minimal HTTP/1.1 client, with TLS via statically linked mbedTLS.
//
// Replaces libcurl + OpenSSL, neither of which exists for haiku/arm64
// (NOTES.md 1). Outbound only; this file never listens (BRIEF.md 5).
#pragma once

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace http {

struct Request {
    std::string method = "GET";
    bool tls = true;
    std::string host;
    int port = 0;  // 0 => 443 for tls, 80 otherwise
    std::string path = "/";
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    int timeout_ms = 25000;  // must exceed the MDS long-poll ceiling (20 s)

    // Streaming, for S3-sized payloads that must not be buffered in RAM on a
    // 4 GiB builder. When body_path is set it is streamed as the request body
    // (Content-Length = file size; `body` must be empty). When sink_path is
    // set, a 2xx response body is streamed to that file instead of resp.body;
    // error bodies (non-2xx) still land in resp.body so S3's XML reason is
    // loggable.
    std::string body_path;
    std::string sink_path;
};

struct Response {
    int status = 0;
    std::map<std::string, std::string> headers;  // lower-cased keys
    std::string body;
    size_t sink_bytes = 0;  // bytes streamed to Request::sink_path, when used
    std::string error;  // non-empty => transport/TLS failure, status is 0

    bool ok() const { return error.empty() && status >= 200 && status < 300; }
};

// Performs one request on a fresh connection. Thread-safe.
Response perform(const Request& req);

// A persistent bidirectional connection (F6: the WebSocket transport for MGS).
// Unlike perform(), the caller owns framing and connection lifetime. Not
// thread-safe by itself; ws::Client serializes access.
class Stream {
public:
    Stream();
    ~Stream();
    Stream(const Stream&) = delete;
    Stream& operator=(const Stream&) = delete;

    bool connect(const std::string& host, int port, bool tls, int timeout_ms, std::string& err);
    bool write(const char* data, size_t len, std::string& err);
    bool write(const std::string& data, std::string& err) {
        return write(data.data(), data.size(), err);
    }
    // >0 bytes read; 0 clean EOF; -1 fatal error; -2 recv timeout (no data yet,
    // connection still healthy -- how the WS loop polls without blocking forever).
    ssize_t read(char* buf, size_t len, std::string& err);
    // Adjust the per-recv timeout after connect (poll cadence for WS reads).
    void set_recv_timeout(int timeout_ms);
    void close();
    bool connected() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Trust anchors used for TLS. The agent ships its own set rather than relying
// on a system CA store, because haiku/arm64 has none (open question 3).
void set_ca_bundle(const std::string& pem);

}  // namespace http
