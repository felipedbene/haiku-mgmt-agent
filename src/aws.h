// aws.h -- IMDSv2 credentials, SigV4 signing, and the SSM/MDS calls the MVP needs.
//
// Wire details are per BRIEF.md 9.2, derived from the Apache-2.0 Go agent:
//   MDS: ec2messages.<region>.amazonaws.com, AWS JSON 1.1,
//        X-Amz-Target: EC2WindowsMessageDeliveryService.<Op>, signing name ec2messages
//   SSM: ssm.<region>.amazonaws.com, AWS JSON 1.1,
//        X-Amz-Target: AmazonSSM.<Op>, signing name ssm
#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "http.h"
#include "json.h"

namespace aws {

struct Credentials {
    std::string access_key;
    std::string secret_key;
    std::string token;
    int64_t expires_at = 0;  // epoch seconds; 0 => unknown

    bool empty() const { return access_key.empty() || secret_key.empty(); }
    // Refresh early: a signature rejected mid-poll costs a whole cycle.
    bool stale(int64_t now, int64_t margin = 300) const {
        return empty() || (expires_at != 0 && now + margin >= expires_at);
    }
};

// Instance facts read once at startup from IMDSv2.
struct InstanceIdentity {
    std::string instance_id;
    std::string region;
    std::string availability_zone;
    std::string private_ip;
    std::string hostname;

    bool valid() const { return !instance_id.empty() && !region.empty(); }
};

// IMDSv2 client. Plain HTTP to 169.254.169.254 -- no TLS involved, which is why
// this half worked on Haiku even before mbedTLS (NOTES.md 2.3).
class Imds {
public:
    // Returns empty string on failure and logs the reason.
    std::string get(const std::string& path);
    bool identity(InstanceIdentity& out);
    bool credentials(Credentials& out);
    // Current UTC from IMDS's HTTP Date header. Plain HTTP, so it works even
    // when the local clock is so wrong that TLS cannot be established.
    bool server_time(int64_t& epoch);

private:
    std::string token();
    std::mutex mutex_;
    std::string token_;
    int64_t token_expires_at_ = 0;
};

// Caches credentials and refreshes them from IMDS when stale. Thread-safe:
// the poll loop and the health-ping thread share one provider.
class CredentialProvider {
public:
    explicit CredentialProvider(Imds* imds) : imds_(imds) {}
    bool get(Credentials& out);
    // Drop the cache after an auth failure so the next get() re-fetches.
    void invalidate();

private:
    Imds* imds_;
    std::mutex mutex_;
    Credentials cached_;
};

// Signs and sends one AWS JSON 1.1 request. `service` is both the endpoint
// prefix and the SigV4 signing name.
http::Response call(const std::string& service, const std::string& target_prefix,
                    const std::string& operation, const std::string& region,
                    const Credentials& creds, const std::string& body, int timeout_ms = 25000);

// Exposed for unit testing against the AWS SigV4 test vectors.
std::string signing_key(const std::string& secret, const std::string& datestamp,
                        const std::string& region, const std::string& service);

// Generic SigV4 header set for any HTTPS request. Used by MGS (F6): its REST
// calls POST to a path (not "/"), and its WebSocket upgrade is a signed GET
// with a query string -- neither fits call() above. `path` must already be
// URI-encoded; `query` must already be canonical (keys sorted, RFC 3986
// encoded) or empty. Returns X-Amz-Date, X-Amz-Security-Token (if any) and
// Authorization; the caller adds Host itself. `now` is exposed for tests.
std::vector<std::pair<std::string, std::string>> sigv4_headers(
    const std::string& method, const std::string& service, const std::string& region,
    const Credentials& creds, const std::string& host, const std::string& path,
    const std::string& query, const std::string& payload_sha256_hex, int64_t now);

// ---- API wrappers ----

// Health ping. Makes the instance appear as a managed node; no registration
// needed on EC2 (BRIEF.md 5).
http::Response update_instance_information(const std::string& region, const Credentials& creds,
                                           const InstanceIdentity& id, const std::string& platform_name,
                                           const std::string& platform_version,
                                           const std::string& agent_name,
                                           const std::string& agent_version);

// Long-poll for work. VisibilityTimeoutInSeconds=10 matches the Go agent, which
// is why redelivery is expected and dedup is mandatory.
http::Response get_messages(const std::string& region, const Credentials& creds,
                            const std::string& instance_id, int timeout_ms);

http::Response acknowledge_message(const std::string& region, const Credentials& creds,
                                   const std::string& message_id);

http::Response send_reply(const std::string& region, const Credentials& creds,
                          const std::string& message_id, const std::string& payload_json);

// FailMessage for documents we cannot parse at all.
http::Response fail_message(const std::string& region, const Credentials& creds,
                            const std::string& message_id, const std::string& failure_type);

// PutInventory with pre-built typed items (F5: AWS:PatchSummary and
// AWS:PatchCompliance, which populate the Patch Manager dashboard).
http::Response put_inventory(const std::string& region, const Credentials& creds,
                             const std::string& instance_id, const json::Value& items);

// CloudWatch PutMetricData (F7/#119). CloudWatch metrics use the AWS Query
// protocol, not JSON 1.1: an application/x-www-form-urlencoded POST to
// monitoring.<region>.amazonaws.com, SigV4-signed with service name
// "monitoring". `form_body` is the fully URL-encoded request body
// (Action=PutMetricData&Version=2010-08-01&Namespace=...&MetricData.member...).
http::Response put_metric_data(const std::string& region, const Credentials& creds,
                               const std::string& form_body);

// CloudWatch Logs (F7/#119). Unlike metrics, Logs speaks AWS JSON 1.1 on
// logs.<region>.amazonaws.com with X-Amz-Target: Logs_20140328.<Op> and signing
// name "logs" -- so these ride the existing call() unchanged.
//
// CreateLogGroup / CreateLogStream are idempotent for our purposes: a
// ResourceAlreadyExistsException (HTTP 400) is a normal "already there", not a
// failure. Callers treat it as success.
http::Response create_log_group(const std::string& region, const Credentials& creds,
                                const std::string& group);
http::Response create_log_stream(const std::string& region, const Credentials& creds,
                                 const std::string& group, const std::string& stream);

// Fetch the stream's current uploadSequenceToken (empty for a never-written
// stream). Used to seed the token at startup so we don't burn a cycle on the
// first InvalidSequenceTokenException.
http::Response describe_log_streams(const std::string& region, const Credentials& creds,
                                    const std::string& group, const std::string& stream_prefix);

// PutLogEvents. `events` is an ordered JSON array of {timestamp(ms),message}.
// `sequence_token` empty => the field is omitted, which is what a fresh stream
// (and, since 2023, any stream) accepts. The response carries nextSequenceToken.
http::Response put_log_events(const std::string& region, const Credentials& creds,
                              const std::string& group, const std::string& stream,
                              const json::Value& events, const std::string& sequence_token);

}  // namespace aws
