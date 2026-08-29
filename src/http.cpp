#include "http.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>

#include "log.h"
#include "util.h"

namespace http {
namespace {

std::mutex g_ca_mutex;
std::string g_ca_pem;

std::string mbed_err(int rc) {
    char buf[160];
    mbedtls_strerror(rc, buf, sizeof(buf));
    char out[220];
    std::snprintf(out, sizeof(out), "%s (-0x%04x)", buf, static_cast<unsigned>(-rc));
    return out;
}

// ------------------------------------------------------------------ socket

class Socket {
public:
    ~Socket() { close(); }

    bool connect(const std::string& host, int port, int timeout_ms, std::string& err) {
        char portstr[12];
        std::snprintf(portstr, sizeof(portstr), "%d", port);

        struct addrinfo hints {};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        struct addrinfo* res = nullptr;
        int rc = ::getaddrinfo(host.c_str(), portstr, &hints, &res);
        if (rc != 0 || !res) {
            err = "getaddrinfo(" + host + "): " + std::string(gai_strerror(rc));
            return false;
        }

        std::string last;
        for (struct addrinfo* ai = res; ai; ai = ai->ai_next) {
            int s = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (s < 0) {
                last = std::string("socket: ") + std::strerror(errno);
                continue;
            }
            // Blocking connect with an explicit timeout, so a black-holed
            // endpoint cannot wedge the poll loop forever.
            struct timeval tv {};
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            ::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            int one = 1;
            ::setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

            if (::connect(s, ai->ai_addr, ai->ai_addrlen) == 0) {
                fd_ = s;
                break;
            }
            last = std::string("connect: ") + std::strerror(errno);
            ::close(s);
        }
        ::freeaddrinfo(res);
        if (fd_ < 0) {
            err = last.empty() ? "connect failed" : last;
            return false;
        }
        return true;
    }

    int fd() const { return fd_; }

    void close() {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

    bool send_all(const char* data, size_t len, std::string& err) {
        size_t sent = 0;
        while (sent < len) {
            ssize_t n = ::send(fd_, data + sent, len - sent, 0);
            if (n > 0) {
                sent += static_cast<size_t>(n);
                continue;
            }
            if (n < 0 && (errno == EINTR)) continue;
            err = std::string("send: ") + std::strerror(errno);
            return false;
        }
        return true;
    }

    // >0 bytes, 0 on clean EOF, -1 on error.
    ssize_t recv_some(char* buf, size_t len, std::string& err) {
        while (true) {
            ssize_t n = ::recv(fd_, buf, len, 0);
            if (n >= 0) return n;
            if (errno == EINTR) continue;
            err = std::string("recv: ") + std::strerror(errno);
            return -1;
        }
    }

private:
    int fd_ = -1;
};

// mbedTLS BIO callbacks over our own fd, so socket timeouts stay under our
// control rather than mbedtls_net_*'s.
int bio_send(void* ctx, const unsigned char* buf, size_t len) {
    Socket* s = static_cast<Socket*>(ctx);
    ssize_t n = ::send(s->fd(), buf, len, 0);
    if (n < 0) {
        if (errno == EINTR) return MBEDTLS_ERR_SSL_WANT_WRITE;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return MBEDTLS_ERR_SSL_TIMEOUT;
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return static_cast<int>(n);
}

int bio_recv(void* ctx, unsigned char* buf, size_t len) {
    Socket* s = static_cast<Socket*>(ctx);
    ssize_t n = ::recv(s->fd(), buf, len, 0);
    if (n < 0) {
        if (errno == EINTR) return MBEDTLS_ERR_SSL_WANT_READ;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return MBEDTLS_ERR_SSL_TIMEOUT;
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    return static_cast<int>(n);
}

// Entropy straight from /dev/urandom. mbedTLS's platform entropy poll is not
// something we want to rely on for a freshly ported OS; Haiku does provide
// /dev/urandom, and this keeps the dependency explicit.
int urandom_entropy(void*, unsigned char* out, size_t len) {
    FILE* f = std::fopen("/dev/urandom", "rb");
    if (!f) return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
    size_t got = std::fread(out, 1, len, f);
    std::fclose(f);
    if (got != len) return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
    return 0;
}

// ------------------------------------------------------------------- I/O

struct Transport {
    virtual ~Transport() = default;
    virtual bool write(const char* data, size_t len, std::string& err) = 0;
    bool write(const std::string& data, std::string& err) {
        return write(data.data(), data.size(), err);
    }
    virtual ssize_t read(char* buf, size_t len, std::string& err) = 0;
};

struct PlainTransport : Transport {
    Socket* sock;
    explicit PlainTransport(Socket* s) : sock(s) {}
    using Transport::write;
    bool write(const char* d, size_t len, std::string& err) override {
        return sock->send_all(d, len, err);
    }
    ssize_t read(char* buf, size_t len, std::string& err) override {
        return sock->recv_some(buf, len, err);
    }
};

struct TlsTransport : Transport {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_ctr_drbg_context drbg;
    bool inited = false;

    TlsTransport() {
        mbedtls_ssl_init(&ssl);
        mbedtls_ssl_config_init(&conf);
        mbedtls_x509_crt_init(&cacert);
        mbedtls_ctr_drbg_init(&drbg);
        inited = true;
    }

    ~TlsTransport() override {
        if (!inited) return;
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&conf);
        mbedtls_x509_crt_free(&cacert);
        mbedtls_ctr_drbg_free(&drbg);
    }

    bool handshake(Socket* sock, const std::string& host, std::string& err) {
        int rc = mbedtls_ctr_drbg_seed(&drbg, urandom_entropy, nullptr,
                                       reinterpret_cast<const unsigned char*>("debeos-ssm-agent"), 16);
        if (rc != 0) {
            err = "ctr_drbg_seed: " + mbed_err(rc);
            return false;
        }

        std::string pem;
        {
            std::lock_guard<std::mutex> lock(g_ca_mutex);
            pem = g_ca_pem;
        }
        if (pem.empty()) {
            err = "no CA bundle configured";
            return false;
        }
        rc = mbedtls_x509_crt_parse(&cacert, reinterpret_cast<const unsigned char*>(pem.c_str()),
                                    pem.size() + 1);
        if (rc != 0) {
            err = "x509_crt_parse: " + mbed_err(rc);
            return false;
        }

        rc = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                         MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
        if (rc != 0) {
            err = "ssl_config_defaults: " + mbed_err(rc);
            return false;
        }
        // Certificate verification is mandatory: this connection carries SigV4
        // credentials.
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_ca_chain(&conf, &cacert, nullptr);
        mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);

        rc = mbedtls_ssl_setup(&ssl, &conf);
        if (rc != 0) {
            err = "ssl_setup: " + mbed_err(rc);
            return false;
        }
        rc = mbedtls_ssl_set_hostname(&ssl, host.c_str());  // SNI + name verification
        if (rc != 0) {
            err = "ssl_set_hostname: " + mbed_err(rc);
            return false;
        }
        mbedtls_ssl_set_bio(&ssl, sock, bio_send, bio_recv, nullptr);

        while ((rc = mbedtls_ssl_handshake(&ssl)) != 0) {
            if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
            err = "tls handshake: " + mbed_err(rc);
            uint32_t flags = mbedtls_ssl_get_verify_result(&ssl);
            if (flags != 0) {
                char vrfy[512];
                mbedtls_x509_crt_verify_info(vrfy, sizeof(vrfy), "  ", flags);
                err += std::string("; verify: ") + vrfy;
            }
            return false;
        }
        return true;
    }

    using Transport::write;
    bool write(const char* d, size_t len, std::string& err) override {
        size_t sent = 0;
        while (sent < len) {
            int rc = mbedtls_ssl_write(&ssl, reinterpret_cast<const unsigned char*>(d) + sent,
                                       len - sent);
            if (rc > 0) {
                sent += static_cast<size_t>(rc);
                continue;
            }
            if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
            err = "ssl_write: " + mbed_err(rc);
            return false;
        }
        return true;
    }

    ssize_t read(char* buf, size_t len, std::string& err) override {
        while (true) {
            int rc = mbedtls_ssl_read(&ssl, reinterpret_cast<unsigned char*>(buf), len);
            if (rc > 0) return rc;
            if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
            if (rc == 0 || rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) return 0;
            err = "ssl_read: " + mbed_err(rc);
            return -1;
        }
    }
};

// --------------------------------------------------------------- response

bool read_headers(Transport& t, std::string& buf, Response& resp) {
    // Read until the blank line that ends the header block.
    while (buf.find("\r\n\r\n") == std::string::npos) {
        char chunk[4096];
        std::string err;
        ssize_t n = t.read(chunk, sizeof(chunk), err);
        if (n < 0) {
            resp.error = err;
            return false;
        }
        if (n == 0) {
            resp.error = "connection closed before headers completed";
            return false;
        }
        buf.append(chunk, static_cast<size_t>(n));
        if (buf.size() > 256 * 1024) {
            resp.error = "header block too large";
            return false;
        }
    }

    size_t end = buf.find("\r\n\r\n");
    std::string head = buf.substr(0, end);
    buf.erase(0, end + 4);

    std::vector<std::string> lines = util::split(head, '\n');
    if (lines.empty()) {
        resp.error = "empty response";
        return false;
    }
    // HTTP/1.1 200 OK
    {
        const std::string& s = lines[0];
        size_t sp = s.find(' ');
        if (sp == std::string::npos) {
            resp.error = "malformed status line";
            return false;
        }
        resp.status = std::atoi(s.c_str() + sp + 1);
    }
    for (size_t i = 1; i < lines.size(); i++) {
        std::string line = lines[i];
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        resp.headers[util::lower(util::trim(line.substr(0, colon)))] = util::trim(line.substr(colon + 1));
    }
    return true;
}

// Where decoded body bytes go: resp.body by default, or a file when the caller
// asked to stream (S3 GET of a multi-hundred-MiB artifact must not live in RAM).
class BodySink {
public:
    BodySink(Response* resp, const std::string& path) : resp_(resp) {
        if (!path.empty()) {
            file_ = std::fopen(path.c_str(), "wb");
            if (!file_) {
                resp_->error = "open(" + path + "): " + std::strerror(errno);
                failed_ = true;
            }
        }
    }
    ~BodySink() {
        if (file_) std::fclose(file_);
    }
    bool failed() const { return failed_; }
    bool append(const char* data, size_t len) {
        if (failed_) return false;
        if (file_) {
            if (std::fwrite(data, 1, len, file_) != len) {
                resp_->error = std::string("short write to body file: ") + std::strerror(errno);
                failed_ = true;
                return false;
            }
        } else {
            resp_->body.append(data, len);
        }
        resp_->sink_bytes += len;
        return true;
    }
    bool finish() {
        if (failed_) return false;
        if (file_) {
            if (std::fflush(file_) != 0 || ::fsync(::fileno(file_)) != 0) {
                resp_->error = std::string("flush body file: ") + std::strerror(errno);
                failed_ = true;
                return false;
            }
        }
        return true;
    }

private:
    Response* resp_;
    std::FILE* file_ = nullptr;
    bool failed_ = false;
};

bool read_body(Transport& t, std::string& pending, Response& resp, BodySink& sink) {
    auto it = resp.headers.find("transfer-encoding");
    bool chunked = it != resp.headers.end() && util::lower(it->second).find("chunked") != std::string::npos;
    if (sink.failed()) return false;

    // Consume up to `want` bytes from the wire into `pending`, then drain
    // `drain` of them into the sink. Keeps `pending` bounded even for bodies
    // far larger than memory.
    auto fill = [&](size_t want) -> bool {
        while (pending.size() < want) {
            char chunk[64 * 1024];
            std::string err;
            ssize_t n = t.read(chunk, sizeof(chunk), err);
            if (n < 0) {
                resp.error = err;
                return false;
            }
            if (n == 0) return false;  // EOF; caller decides if that is fatal
            pending.append(chunk, static_cast<size_t>(n));
        }
        return true;
    };

    if (chunked) {
        while (true) {
            size_t nl = pending.find("\r\n");
            while (nl == std::string::npos) {
                if (!fill(pending.size() + 1)) {
                    resp.error = resp.error.empty() ? "truncated chunked body" : resp.error;
                    return false;
                }
                nl = pending.find("\r\n");
            }
            size_t size = static_cast<size_t>(std::strtoul(pending.substr(0, nl).c_str(), nullptr, 16));
            pending.erase(0, nl + 2);
            if (size == 0) return sink.finish();  // trailers ignored
            // Stream the chunk through in bounded pieces rather than fill()ing
            // it whole: S3 is free to send one giant chunk.
            size_t remaining = size;
            while (remaining > 0) {
                if (pending.empty() && !fill(1)) {
                    resp.error = resp.error.empty() ? "truncated chunk" : resp.error;
                    return false;
                }
                size_t take = std::min(remaining, pending.size());
                if (!sink.append(pending.data(), take)) return false;
                pending.erase(0, take);
                remaining -= take;
            }
            if (!fill(2)) {  // CRLF after the chunk data
                resp.error = resp.error.empty() ? "truncated chunk" : resp.error;
                return false;
            }
            pending.erase(0, 2);
        }
    }

    auto cl = resp.headers.find("content-length");
    if (cl != resp.headers.end()) {
        size_t want = static_cast<size_t>(std::strtoul(cl->second.c_str(), nullptr, 10));
        size_t remaining = want;
        while (remaining > 0) {
            if (pending.empty() && !fill(1)) {
                resp.error = resp.error.empty() ? "truncated body" : resp.error;
                return false;
            }
            size_t take = std::min(remaining, pending.size());
            if (!sink.append(pending.data(), take)) return false;
            pending.erase(0, take);
            remaining -= take;
        }
        return sink.finish();
    }

    // No length and no chunking: read to EOF.
    if (!pending.empty()) {
        if (!sink.append(pending.data(), pending.size())) return false;
        pending.clear();
    }
    while (true) {
        char chunk[64 * 1024];
        std::string err;
        ssize_t n = t.read(chunk, sizeof(chunk), err);
        if (n < 0) {
            resp.error = err;
            return false;
        }
        if (n == 0) return sink.finish();
        if (!sink.append(chunk, static_cast<size_t>(n))) return false;
    }
}

}  // namespace

void set_ca_bundle(const std::string& pem) {
    std::lock_guard<std::mutex> lock(g_ca_mutex);
    g_ca_pem = pem;
}

Response perform(const Request& req) {
    Response resp;
    int port = req.port ? req.port : (req.tls ? 443 : 80);

    Socket sock;
    if (!sock.connect(req.host, port, req.timeout_ms, resp.error)) return resp;

    TlsTransport tls;
    PlainTransport plain(&sock);
    Transport* t = nullptr;
    if (req.tls) {
        if (!tls.handshake(&sock, req.host, resp.error)) return resp;
        t = &tls;
    } else {
        t = &plain;
    }

    // A file body is streamed after the headers; its size is the Content-Length.
    std::FILE* body_file = nullptr;
    size_t body_len = req.body.size();
    if (!req.body_path.empty()) {
        struct stat st {};
        if (::stat(req.body_path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) {
            resp.error = "body file " + req.body_path + ": " +
                         (errno ? std::strerror(errno) : "not a regular file");
            return resp;
        }
        body_file = std::fopen(req.body_path.c_str(), "rb");
        if (!body_file) {
            resp.error = "open(" + req.body_path + "): " + std::strerror(errno);
            return resp;
        }
        body_len = static_cast<size_t>(st.st_size);
    }

    std::string wire = req.method + " " + req.path + " HTTP/1.1\r\n";
    wire += "Host: " + req.host + "\r\n";
    // One request per connection: no keep-alive bookkeeping to get wrong.
    wire += "Connection: close\r\n";
    bool has_len = false;
    for (const auto& h : req.headers) {
        if (util::lower(h.first) == "content-length") has_len = true;
        wire += h.first + ": " + h.second + "\r\n";
    }
    if (!has_len && (body_len > 0 || req.method == "POST" || req.method == "PUT"))
        wire += "Content-Length: " + std::to_string(body_len) + "\r\n";
    wire += "\r\n";
    if (!body_file) wire += req.body;

    bool sent = t->write(wire, resp.error);
    if (sent && body_file) {
        char chunk[64 * 1024];
        size_t n;
        while ((n = std::fread(chunk, 1, sizeof(chunk), body_file)) > 0) {
            if (!t->write(chunk, n, resp.error)) {
                sent = false;
                break;
            }
        }
        if (sent && std::ferror(body_file)) {
            resp.error = "read(" + req.body_path + "): " + std::strerror(errno);
            sent = false;
        }
    }
    if (body_file) std::fclose(body_file);
    if (!sent) return resp;

    std::string pending;
    if (!read_headers(*t, pending, resp)) return resp;
    // Only a 2xx body goes to the sink file: an error body is the S3 XML
    // diagnostic and belongs in resp.body, not in the destination file.
    const bool stream_ok = resp.status >= 200 && resp.status < 300;
    BodySink sink(&resp, stream_ok ? req.sink_path : std::string());
    read_body(*t, pending, resp, sink);  // body errors are recorded in resp.error
    return resp;
}

}  // namespace http
