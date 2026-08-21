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

}  // namespace aws
