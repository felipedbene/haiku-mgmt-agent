#include "aws.h"

#include <algorithm>
#include <vector>

#include "log.h"
#include "util.h"

namespace aws {
namespace {

const char* kImdsHost = "169.254.169.254";
const char* kMdsTargetPrefix = "EC2WindowsMessageDeliveryService";  // historical name, all platforms
const char* kSsmTargetPrefix = "AmazonSSM";
const char* kJsonContentType = "application/x-amz-json-1.1";

std::string endpoint(const std::string& service, const std::string& region) {
    return service + "." + region + ".amazonaws.com";
}

}  // namespace

// ------------------------------------------------------------------- IMDS

std::string Imds::token() {
    int64_t now = util::now_epoch();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!token_.empty() && now + 60 < token_expires_at_) return token_;
    }

    http::Request req;
    req.method = "PUT";
    req.tls = false;
    req.host = kImdsHost;
    req.path = "/latest/api/token";
    req.timeout_ms = 5000;
    req.headers.push_back({"X-aws-ec2-metadata-token-ttl-seconds", "21600"});

    http::Response resp = http::perform(req);
    if (!resp.ok() || resp.body.empty()) {
        logging::logf(logging::Error, "IMDSv2 token request failed: status=%d error=%s",
                      resp.status, resp.error.c_str());
        return "";
    }

    std::lock_guard<std::mutex> lock(mutex_);
    token_ = util::trim(resp.body);
    token_expires_at_ = now + 21600;
    return token_;
}

std::string Imds::get(const std::string& path) {
    std::string tok = token();
    if (tok.empty()) return "";

    http::Request req;
    req.method = "GET";
    req.tls = false;
    req.host = kImdsHost;
    req.path = path;
    req.timeout_ms = 5000;
    req.headers.push_back({"X-aws-ec2-metadata-token", tok});

    http::Response resp = http::perform(req);
    if (!resp.ok()) {
        logging::logf(logging::Error, "IMDS GET %s failed: status=%d error=%s",
                      path.c_str(), resp.status, resp.error.c_str());
        return "";
    }
    return resp.body;
}

bool Imds::server_time(int64_t& epoch) {
    // The token endpoint answers regardless of clock state and needs no token
    // itself, which makes it the right bootstrap source.
    http::Request req;
    req.method = "PUT";
    req.tls = false;
    req.host = kImdsHost;
    req.path = "/latest/api/token";
    req.timeout_ms = 5000;
    req.headers.push_back({"X-aws-ec2-metadata-token-ttl-seconds", "21600"});

    http::Response resp = http::perform(req);
    auto it = resp.headers.find("date");
    if (it == resp.headers.end()) {
        logging::logf(logging::Warn, "IMDS response carried no Date header (status=%d error=%s)",
                      resp.status, resp.error.c_str());
        return false;
    }
    epoch = util::parse_http_date(it->second);
    if (epoch <= 0) {
        logging::logf(logging::Warn, "could not parse IMDS Date header '%s'", it->second.c_str());
        return false;
    }
    return true;
}

bool Imds::identity(InstanceIdentity& out) {
    out.instance_id = util::trim(get("/latest/meta-data/instance-id"));
    out.region = util::trim(get("/latest/meta-data/placement/region"));
    out.availability_zone = util::trim(get("/latest/meta-data/placement/availability-zone"));
    out.private_ip = util::trim(get("/latest/meta-data/local-ipv4"));
    out.hostname = util::trim(get("/latest/meta-data/local-hostname"));
    return out.valid();
}

bool Imds::credentials(Credentials& out) {
    std::string role = util::trim(get("/latest/meta-data/iam/security-credentials/"));
    if (role.empty()) {
        logging::error("no IAM role in instance metadata; cannot sign requests");
        return false;
    }
    // The listing can carry more than one line; the first is the attached role.
    std::vector<std::string> lines = util::split(role, '\n');
    role = util::trim(lines.front());

    std::string body = get("/latest/meta-data/iam/security-credentials/" + role);
    if (body.empty()) return false;

    std::string err;
    json::Value v = json::parse(body, &err);
    if (!err.empty() || !v.is_obj()) {
        logging::logf(logging::Error, "could not parse role credentials: %s", err.c_str());
        return false;
    }

    out.access_key = v.str_at("AccessKeyId");
    out.secret_key = v.str_at("SecretAccessKey");
    out.token = v.str_at("Token");
    out.expires_at = util::parse_iso8601(v.str_at("Expiration"));
    if (out.empty()) {
        logging::error("role credentials missing AccessKeyId/SecretAccessKey");
        return false;
    }
    logging::logf(logging::Debug, "refreshed credentials for role %s (expire %s)",
                  role.c_str(), v.str_at("Expiration").c_str());
    return true;
}

bool CredentialProvider::get(Credentials& out) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!cached_.stale(util::now_epoch())) {
        out = cached_;
        return true;
    }
    Credentials fresh;
    if (!imds_->credentials(fresh)) {
        // Keep serving the old ones if they have not actually expired yet: a
        // transient IMDS failure should not take the agent offline.
        if (!cached_.empty() && !cached_.stale(util::now_epoch(), 0)) {
            out = cached_;
            return true;
        }
        return false;
    }
    cached_ = fresh;
    out = cached_;
    return true;
}

void CredentialProvider::invalidate() {
    std::lock_guard<std::mutex> lock(mutex_);
    cached_ = Credentials();
}

// ----------------------------------------------------------------- SigV4

std::string signing_key(const std::string& secret, const std::string& datestamp,
                        const std::string& region, const std::string& service) {
    std::string k_date = util::hmac_sha256("AWS4" + secret, datestamp);
    std::string k_region = util::hmac_sha256(k_date, region);
    std::string k_service = util::hmac_sha256(k_region, service);
    return util::hmac_sha256(k_service, "aws4_request");
}

http::Response call(const std::string& service, const std::string& target_prefix,
                    const std::string& operation, const std::string& region,
                    const Credentials& creds, const std::string& body, int timeout_ms) {
    http::Response bad;
    if (creds.empty()) {
        bad.error = "no credentials available";
        return bad;
    }

    const std::string host = endpoint(service, region);
    const std::string target = target_prefix + "." + operation;
    const int64_t now = util::now_epoch();
    const std::string amzdate = util::amz_date(now);
    const std::string datestamp = util::amz_datestamp(now);
    const std::string payload_hash = util::sha256_hex(body);

    // Canonical headers: lower-cased names, sorted, one per line.
    std::vector<std::pair<std::string, std::string>> signed_headers = {
        {"content-type", kJsonContentType},
        {"host", host},
        {"x-amz-date", amzdate},
        {"x-amz-target", target},
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
        "POST\n/\n\n" + canonical_headers + "\n" + signed_names + "\n" + payload_hash;
    const std::string scope = datestamp + "/" + region + "/" + service + "/aws4_request";
    const std::string string_to_sign =
        "AWS4-HMAC-SHA256\n" + amzdate + "\n" + scope + "\n" + util::sha256_hex(canonical_request);

    const std::string signature =
        util::to_hex(util::hmac_sha256(signing_key(creds.secret_key, datestamp, region, service),
                                       string_to_sign));

    http::Request req;
    req.method = "POST";
    req.tls = true;
    req.host = host;
    req.path = "/";
    req.body = body;
    req.timeout_ms = timeout_ms;
    req.headers.push_back({"Content-Type", kJsonContentType});
    req.headers.push_back({"X-Amz-Date", amzdate});
    req.headers.push_back({"X-Amz-Target", target});
    if (!creds.token.empty()) req.headers.push_back({"X-Amz-Security-Token", creds.token});
    req.headers.push_back({"Authorization",
                           "AWS4-HMAC-SHA256 Credential=" + creds.access_key + "/" + scope +
                               ", SignedHeaders=" + signed_names + ", Signature=" + signature});
    req.headers.push_back({"User-Agent", "debeos-ssm-agent"});

    return http::perform(req);
}

// ----------------------------------------------------------- API wrappers

http::Response update_instance_information(const std::string& region, const Credentials& creds,
                                           const InstanceIdentity& id, const std::string& platform_name,
                                           const std::string& platform_version,
                                           const std::string& agent_name,
                                           const std::string& agent_version) {
    json::Value b = json::obj();
    b.object["InstanceId"] = json::str(id.instance_id);
    b.object["AgentName"] = json::str(agent_name);
    b.object["AgentVersion"] = json::str(agent_version);
    b.object["AgentStatus"] = json::str("Active");
    // PlatformType is a closed enum (Windows|Linux|MacOS) -- BRIEF.md 9.2. Haiku
    // is not in it, so we report Linux for compatibility and tell the truth in
    // PlatformName, which is free-form.
    b.object["PlatformType"] = json::str("Linux");
    b.object["PlatformName"] = json::str(platform_name);
    b.object["PlatformVersion"] = json::str(platform_version);
    // We never open an MGS control channel (out of scope), so we always declare
    // ec2messages. The service handles this: BRIEF.md 9.1.
    b.object["SSMConnectionChannel"] = json::str("ec2messages");
    if (!id.private_ip.empty()) b.object["IPAddress"] = json::str(id.private_ip);
    if (!id.hostname.empty()) b.object["ComputerName"] = json::str(id.hostname);
    if (!id.availability_zone.empty()) b.object["AvailabilityZone"] = json::str(id.availability_zone);

    return call("ssm", kSsmTargetPrefix, "UpdateInstanceInformation", region, creds, json::dump(b));
}

http::Response get_messages(const std::string& region, const Credentials& creds,
                            const std::string& instance_id, int timeout_ms) {
    json::Value b = json::obj();
    b.object["Destination"] = json::str(instance_id);
    b.object["MessagesRequestId"] = json::str(util::uuid4());
    b.object["VisibilityTimeoutInSeconds"] = json::num(10);
    return call("ec2messages", kMdsTargetPrefix, "GetMessages", region, creds, json::dump(b), timeout_ms);
}

http::Response acknowledge_message(const std::string& region, const Credentials& creds,
                                   const std::string& message_id) {
    json::Value b = json::obj();
    b.object["MessageId"] = json::str(message_id);
    return call("ec2messages", kMdsTargetPrefix, "AcknowledgeMessage", region, creds, json::dump(b));
}

http::Response send_reply(const std::string& region, const Credentials& creds,
                          const std::string& message_id, const std::string& payload_json) {
    json::Value b = json::obj();
    b.object["MessageId"] = json::str(message_id);
    b.object["Payload"] = json::str(payload_json);  // a JSON *string* containing JSON
    b.object["ReplyId"] = json::str(util::uuid4());
    return call("ec2messages", kMdsTargetPrefix, "SendReply", region, creds, json::dump(b));
}

http::Response fail_message(const std::string& region, const Credentials& creds,
                            const std::string& message_id, const std::string& failure_type) {
    json::Value b = json::obj();
    b.object["MessageId"] = json::str(message_id);
    b.object["FailureType"] = json::str(failure_type);
    return call("ec2messages", kMdsTargetPrefix, "FailMessage", region, creds, json::dump(b));
}

}  // namespace aws
