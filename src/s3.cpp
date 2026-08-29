#include "s3.h"

#include <algorithm>
#include <vector>

#include "log.h"
#include "util.h"

namespace s3 {
namespace {

// UNSIGNED-PAYLOAD keeps PUT single-pass: the alternative is reading the file
// twice (hash, then send) or buffering it whole. TLS already covers integrity.
const char* kUnsignedPayload = "UNSIGNED-PAYLOAD";

// Big transfers on a modest link: a 400 MiB tarball at 10 MiB/s is ~40 s, so
// the socket timeout must be generous. This bounds *stall*, not duration,
// because SO_RCVTIMEO/SO_SNDTIMEO apply per syscall.
constexpr int kTransferTimeoutMs = 120000;

bool expired_token(const http::Response& r) {
    if (r.status != 400 && r.status != 403) return false;
    return r.body.find("ExpiredToken") != std::string::npos ||
           r.body.find("InvalidToken") != std::string::npos ||
           r.body.find("TokenRefreshRequired") != std::string::npos;
}

http::Response transfer_once(aws::CredentialProvider& provider, const std::string& method,
                             const std::string& region, const std::string& bucket,
                             const std::string& key, const std::string& body_path,
                             const std::string& content, const std::string& sink_path,
                             const std::string& content_type) {
    http::Response bad;
    aws::Credentials creds;
    if (!provider.get(creds)) {
        bad.error = "no credentials available";
        return bad;
    }

    http::Request req = build_request(method, region, creds, bucket, key,
                                      util::now_epoch(), content_type);
    req.timeout_ms = kTransferTimeoutMs;
    req.body_path = body_path;
    if (body_path.empty()) req.body = content;
    req.sink_path = sink_path;
    return http::perform(req);
}

}  // namespace

bool parse_uri(const std::string& uri, std::string& bucket, std::string& key) {
    const std::string prefix = "s3://";
    if (!util::starts_with(uri, prefix)) return false;
    const std::string rest = uri.substr(prefix.size());
    const size_t slash = rest.find('/');
    if (slash == std::string::npos || slash == 0 || slash + 1 >= rest.size()) return false;
    bucket = rest.substr(0, slash);
    key = rest.substr(slash + 1);
    return true;
}

http::Request build_request(const std::string& method, const std::string& region,
                            const aws::Credentials& creds, const std::string& bucket,
                            const std::string& key, int64_t now, const std::string& content_type) {
    const std::string host = bucket + ".s3." + region + ".amazonaws.com";
    const std::string path = "/" + util::uri_encode(key, /*encode_slash=*/false);
    const std::string amzdate = util::amz_date(now);
    const std::string datestamp = util::amz_datestamp(now);

    std::vector<std::pair<std::string, std::string>> signed_headers = {
        {"host", host},
        {"x-amz-content-sha256", kUnsignedPayload},
        {"x-amz-date", amzdate},
    };
    if (!creds.token.empty()) signed_headers.push_back({"x-amz-security-token", creds.token});
    std::sort(signed_headers.begin(), signed_headers.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });

    std::string canonical_headers, signed_names;
    for (size_t i = 0; i < signed_headers.size(); i++) {
        canonical_headers += signed_headers[i].first + ":" + signed_headers[i].second + "\n";
        if (i) signed_names += ";";
        signed_names += signed_headers[i].first;
    }

    const std::string canonical_request =
        method + "\n" + path + "\n\n" + canonical_headers + "\n" + signed_names + "\n" +
        kUnsignedPayload;
    const std::string scope = datestamp + "/" + region + "/s3/aws4_request";
    const std::string string_to_sign =
        "AWS4-HMAC-SHA256\n" + amzdate + "\n" + scope + "\n" + util::sha256_hex(canonical_request);
    const std::string signature = util::to_hex(
        util::hmac_sha256(aws::signing_key(creds.secret_key, datestamp, region, "s3"),
                          string_to_sign));

    http::Request req;
    req.method = method;
    req.tls = true;
    req.host = host;
    req.path = path;
    req.headers.push_back({"X-Amz-Content-Sha256", kUnsignedPayload});
    req.headers.push_back({"X-Amz-Date", amzdate});
    if (!creds.token.empty()) req.headers.push_back({"X-Amz-Security-Token", creds.token});
    if (method == "PUT" && !content_type.empty())
        req.headers.push_back({"Content-Type", content_type});
    req.headers.push_back({"Authorization",
                           "AWS4-HMAC-SHA256 Credential=" + creds.access_key + "/" + scope +
                               ", SignedHeaders=" + signed_names + ", Signature=" + signature});
    req.headers.push_back({"User-Agent", "haiku-mgmt-agent"});
    return req;
}

http::Response get(aws::CredentialProvider& provider, const std::string& region,
                   const std::string& bucket, const std::string& key,
                   const std::string& dest_path) {
    http::Response r = transfer_once(provider, "GET", region, bucket, key, "", "", dest_path, "");
    if (expired_token(r)) {
        logging::info("s3 get: credentials rejected as expired; refreshing and retrying");
        provider.invalidate();
        r = transfer_once(provider, "GET", region, bucket, key, "", "", dest_path, "");
    }
    return r;
}

http::Response put(aws::CredentialProvider& provider, const std::string& region,
                   const std::string& bucket, const std::string& key,
                   const std::string& src_path, const std::string& content,
                   const std::string& content_type) {
    http::Response r =
        transfer_once(provider, "PUT", region, bucket, key, src_path, content, "", content_type);
    if (expired_token(r)) {
        logging::info("s3 put: credentials rejected as expired; refreshing and retrying");
        provider.invalidate();
        r = transfer_once(provider, "PUT", region, bucket, key, src_path, content, "", content_type);
    }
    return r;
}

}  // namespace s3
