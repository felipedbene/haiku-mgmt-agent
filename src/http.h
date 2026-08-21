// http.h -- minimal HTTP/1.1 client, with TLS via statically linked mbedTLS.
//
// Replaces libcurl + OpenSSL, neither of which exists for haiku/arm64
// (NOTES.md 1). Outbound only; this file never listens (BRIEF.md 5).
#pragma once

#include <map>
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
};

struct Response {
    int status = 0;
    std::map<std::string, std::string> headers;  // lower-cased keys
    std::string body;
    std::string error;  // non-empty => transport/TLS failure, status is 0

    bool ok() const { return error.empty() && status >= 200 && status < 300; }
};

// Performs one request on a fresh connection. Thread-safe.
Response perform(const Request& req);

// Trust anchors used for TLS. The agent ships its own set rather than relying
// on a system CA store, because haiku/arm64 has none (open question 3).
void set_ca_bundle(const std::string& pem);

}  // namespace http
