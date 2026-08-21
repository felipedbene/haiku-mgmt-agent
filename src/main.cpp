// haiku-mgmt-agent -- minimal SSM-compatible management agent for Haiku/arm64.
//
// Phase 1 scope (BRIEF.md 2): MDS long-poll, aws:runShellScript, inline output,
// health ping. No MGS, no Session Manager, no inventory, no self-update.
//
// Threads: one poll loop (this thread) and one health-ping thread, so a long
// running command cannot let the managed-node registration go stale.

#include <signal.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <set>
#include <string>
#include <thread>

#include "aws.h"
#include "ca_certs.h"
#include "http.h"
#include "json.h"
#include "log.h"
#include "runner.h"
#include "timesync.h"
#include "util.h"

namespace {

const char* kAgentName = "haiku-mgmt-agent";
const char* kAgentVersion = "0.1.0";
const char* kDefaultLogPath = "/var/log/haiku-mgmt-agent.log";

// BRIEF.md 9.2: the Go agent's long-poll ceiling is Mds.StopTimeoutMillis,
// default 20 s. Our HTTP timeout must exceed it.
constexpr int kPollHttpTimeoutMs = 25000;
constexpr int kHealthIntervalSeconds = 300;  // healthcheck.go default: 5 minutes
constexpr size_t kDedupHistory = 512;

const char* kSendCommandTopic = "aws.ssm.sendCommand";
const char* kCancelCommandTopic = "aws.ssm.cancelCommand";

std::atomic<bool> g_stop{false};

void on_signal(int sig) {
    g_stop.store(true);
    (void)sig;
}

struct Options {
    std::string log_path = kDefaultLogPath;
    logging::Level level = logging::Info;
    bool foreground = false;
    bool ping_once = false;  // Stage 1 gate: one UpdateInstanceInformation, then exit
    bool poll_once = false;
    bool time_sync = true;
};

// Haiku boots at epoch 0 with no NTP client, so this is not optional in practice.
constexpr int64_t kMaxClockDriftSeconds = 60;
// Boot-order tolerance: launch_daemon can start us before the NIC is up.
constexpr int kIdentityAttempts = 20;
constexpr int kIdentityRetrySeconds = 6;

void usage() {
    std::printf(
        "haiku-mgmt-agent %s -- minimal SSM agent for Haiku/arm64\n"
        "\n"
        "  --ping-once      send one UpdateInstanceInformation and exit (Stage 1 gate)\n"
        "  --poll-once      run a single MDS poll cycle and exit\n"
        "  --no-time-sync   do not set the system clock from IMDS (Haiku boots at 1970)\n"
        "  --foreground     log to stderr as well as the log file\n"
        "  --log-file PATH  default %s\n"
        "  --log-level L    debug|info|warn|error (default info)\n"
        "  --version        print version and exit\n",
        kAgentVersion, kDefaultLogPath);
}

// Report the platform honestly where the API allows it: PlatformType must be one
// of Windows|Linux|MacOS (BRIEF.md 9.2), but PlatformName/Version are free-form.
void detect_platform(std::string& name, std::string& version) {
    name = "Haiku";
    version = "unknown";
    struct utsname u {};
    if (::uname(&u) != 0) return;
    if (u.sysname[0]) name = u.sysname;
    // uname -v is like "hrev59996+dirty Aug 19 2026 22:.."; keep the hrev token.
    std::string v = u.version;
    size_t sp = v.find(' ');
    version = (sp == std::string::npos) ? v : v.substr(0, sp);
    if (version.empty()) version = u.release;
}

// aws.ssm.<command-id>.<instance-id>  (runcommand/contracts/model.go:50)
std::string command_id_from(const std::string& message_id) {
    std::vector<std::string> parts = util::split(message_id, '.');
    if (parts.size() < 2) return message_id;
    return parts[parts.size() - 2];
}

// Bounded set: redelivery is normal with a 10 s visibility timeout, so this is
// load-bearing, not an optimisation.
class SeenCommands {
public:
    bool seen(const std::string& id) const { return set_.count(id) > 0; }
    void add(const std::string& id) {
        if (set_.insert(id).second) {
            order_.push_back(id);
            if (order_.size() > kDedupHistory) {
                set_.erase(order_.front());
                order_.pop_front();
            }
        }
    }

private:
    std::set<std::string> set_;
    std::deque<std::string> order_;
};

struct Agent {
    aws::Imds imds;
    aws::CredentialProvider* creds = nullptr;
    aws::InstanceIdentity id;
    runner::AgentInfo info;
    SeenCommands seen;

    // Any signature/expiry rejection invalidates the cache so the next call
    // re-fetches from IMDS instead of failing identically forever.
    bool check_auth_failure(const http::Response& resp, const char* what) {
        if (resp.ok()) return false;
        const bool auth = resp.status == 403 || resp.status == 400;
        const bool expired = resp.body.find("ExpiredToken") != std::string::npos ||
                             resp.body.find("InvalidSignature") != std::string::npos ||
                             resp.body.find("InvalidClientTokenId") != std::string::npos;
        logging::logf(logging::Warn, "%s failed: status=%d error=%s body=%s", what, resp.status,
                      resp.error.c_str(), util::clip(resp.body, 400, "...").c_str());
        if (auth && expired) {
            logging::info("invalidating cached credentials after auth failure");
            creds->invalidate();
        }
        return true;
    }

    bool send_reply(const std::string& message_id, const std::string& payload, const char* what) {
        aws::Credentials c;
        if (!creds->get(c)) return false;
        http::Response r = aws::send_reply(id.region, c, message_id, payload);
        if (!r.ok()) {
            check_auth_failure(r, what);
            return false;
        }
        logging::logf(logging::Debug, "%s ok for %s", what, message_id.c_str());
        return true;
    }

    void handle_send_command(const json::Value& msg) {
        const std::string message_id = msg.str_at("MessageId");
        const std::string command_id = command_id_from(message_id);

        if (seen.seen(command_id)) {
            // Already handled; re-ack so MDS stops redelivering it.
            logging::logf(logging::Info, "duplicate delivery of command %s; re-acknowledging",
                          command_id.c_str());
            aws::Credentials c;
            if (creds->get(c)) aws::acknowledge_message(id.region, c, message_id);
            return;
        }
        // Mark before executing: execution can outlast the 10 s visibility
        // timeout, and a redelivery mid-run must not start a second copy.
        seen.add(command_id);

        std::string err;
        json::Value payload = json::parse(msg.str_at("Payload"), &err);
        if (!err.empty() || !payload.is_obj()) {
            logging::logf(logging::Error, "malformed SendCommand payload for %s: %s",
                          message_id.c_str(), err.c_str());
            // Tell the user (reply) and tell MDS to stop retrying (FailMessage).
            std::string trace = "haiku-mgmt-agent could not parse the document payload: " + err;
            send_reply(message_id, runner::reply_payload(info, "Failed", trace, {}), "SendReply(Failed)");
            aws::Credentials c;
            if (creds->get(c))
                aws::fail_message(id.region, c, message_id, "InternalHandlerException");
            return;
        }

        const json::Value* doc = payload.find("DocumentContent");
        const json::Value* params = payload.find("Parameters");
        const json::Value empty;
        logging::logf(logging::Info, "received command %s (document %s)", command_id.c_str(),
                      payload.str_at("DocumentName").c_str());

        if (!doc || !doc->is_obj()) {
            std::string trace = "document payload has no DocumentContent object";
            logging::error(trace);
            send_reply(message_id, runner::reply_payload(info, "Failed", trace, {}), "SendReply(Failed)");
            aws::Credentials c;
            if (creds->get(c))
                aws::fail_message(id.region, c, message_id, "InternalHandlerException");
            return;
        }

        // Ordering per BRIEF.md 9.2: InProgress, then ack, then run, then final.
        send_reply(message_id, runner::reply_payload(info, "InProgress", "", {}), "SendReply(InProgress)");

        {
            aws::Credentials c;
            if (creds->get(c)) {
                http::Response ack = aws::acknowledge_message(id.region, c, message_id);
                if (!ack.ok()) check_auth_failure(ack, "AcknowledgeMessage");
            }
        }

        runner::DocumentOutcome outcome = runner::run_document(*doc, params ? *params : empty);
        send_reply(message_id, runner::reply_payload(info, outcome.status, outcome.trace, outcome.steps),
                   "SendReply(final)");
        logging::logf(logging::Info, "command %s completed: %s", command_id.c_str(),
                      outcome.status.c_str());
    }

    void handle_message(const json::Value& msg) {
        const std::string message_id = msg.str_at("MessageId");
        const std::string topic = msg.str_at("Topic");
        if (message_id.empty() || topic.empty()) {
            logging::warn("ignoring message with no MessageId/Topic");
            return;
        }

        if (util::starts_with(topic, kSendCommandTopic)) {
            handle_send_command(msg);
            return;
        }

        if (util::starts_with(topic, kCancelCommandTopic)) {
            // Commands run synchronously in this loop, so by the time a cancel
            // arrives there is nothing in flight to interrupt. Ack it so it does
            // not redeliver, and say so plainly in the log.
            logging::logf(logging::Info,
                          "cancelCommand %s acknowledged but not actioned: execution is synchronous "
                          "in this MVP (see README)",
                          message_id.c_str());
            aws::Credentials c;
            if (creds->get(c)) aws::acknowledge_message(id.region, c, message_id);
            return;
        }

        logging::logf(logging::Warn, "unexpected topic '%s' for %s; failing the message",
                      topic.c_str(), message_id.c_str());
        aws::Credentials c;
        if (creds->get(c)) aws::fail_message(id.region, c, message_id, "InternalHandlerException");
    }

    // One GetMessages cycle. Returns the wall time it took, in ms.
    int64_t poll_once() {
        const int64_t started = util::now_epoch_ms();
        aws::Credentials c;
        if (!creds->get(c)) {
            logging::error("no credentials; skipping poll");
            return util::now_epoch_ms() - started;
        }

        http::Response resp = aws::get_messages(id.region, c, id.instance_id, kPollHttpTimeoutMs);
        if (!resp.ok()) {
            check_auth_failure(resp, "GetMessages");
            return util::now_epoch_ms() - started;
        }

        std::string err;
        json::Value body = json::parse(resp.body, &err);
        if (!err.empty()) {
            logging::logf(logging::Error, "could not parse GetMessages response: %s", err.c_str());
            return util::now_epoch_ms() - started;
        }

        const json::Value* messages = body.find("Messages");
        if (!messages || !messages->is_arr() || messages->array.empty())
            return util::now_epoch_ms() - started;

        logging::logf(logging::Info, "got %zu message(s)", messages->array.size());
        for (const json::Value& m : messages->array) {
            if (g_stop.load()) break;
            handle_message(m);
        }
        return util::now_epoch_ms() - started;
    }

    bool health_ping(const std::string& platform_name, const std::string& platform_version) {
        aws::Credentials c;
        if (!creds->get(c)) return false;
        http::Response r = aws::update_instance_information(id.region, c, id, platform_name,
                                                            platform_version, kAgentName,
                                                            kAgentVersion);
        if (!r.ok()) {
            check_auth_failure(r, "UpdateInstanceInformation");
            return false;
        }
        logging::debug("UpdateInstanceInformation ok");
        return true;
    }
};

}  // namespace

int main(int argc, char** argv) {
    Options opt;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--help" || a == "-h") { usage(); return 0; }
        if (a == "--version") { std::printf("%s %s\n", kAgentName, kAgentVersion); return 0; }
        if (a == "--foreground") { opt.foreground = true; continue; }
        if (a == "--ping-once") { opt.ping_once = true; opt.foreground = true; continue; }
        if (a == "--poll-once") { opt.poll_once = true; opt.foreground = true; continue; }
        if (a == "--no-time-sync") { opt.time_sync = false; continue; }
        if (a == "--log-file" && i + 1 < argc) { opt.log_path = argv[++i]; continue; }
        if (a == "--log-level" && i + 1 < argc) {
            std::string l = argv[++i];
            opt.level = (l == "debug") ? logging::Debug
                        : (l == "warn") ? logging::Warn
                        : (l == "error") ? logging::Error
                                         : logging::Info;
            continue;
        }
        std::fprintf(stderr, "unknown argument: %s\n", a.c_str());
        usage();
        return 2;
    }

    logging::init(opt.log_path, opt.level, opt.foreground);
    logging::logf(logging::Info, "%s %s starting", kAgentName, kAgentVersion);

    // Outbound only, and a peer that hangs up must not kill the process.
    ::signal(SIGPIPE, SIG_IGN);
    ::signal(SIGTERM, on_signal);
    ::signal(SIGINT, on_signal);

    // Trust anchors are compiled in: Haiku/arm64 has no system CA store.
    http::set_ca_bundle(ca::kAmazonTrustRoots);

    Agent agent;
    aws::CredentialProvider provider(&agent.imds);
    agent.creds = &provider;

    // At boot, launch_daemon may start us before the network is configured, so
    // retry rather than exiting and relying on the service restart loop.
    bool identified = false;
    for (int attempt = 1; attempt <= kIdentityAttempts && !g_stop.load(); attempt++) {
        // Before anything that needs TLS or a signature: the clock. On Haiku this
        // is the difference between working and "certificate validity starts in
        // the future" (TESTING.md).
        timesync::ensure_clock(agent.imds, opt.time_sync, kMaxClockDriftSeconds);
        if (agent.imds.identity(agent.id)) {
            identified = true;
            break;
        }
        logging::logf(logging::Warn, "IMDSv2 identity unavailable (attempt %d/%d); retrying in %ds",
                      attempt, kIdentityAttempts, kIdentityRetrySeconds);
        for (int s = 0; s < kIdentityRetrySeconds && !g_stop.load(); s++) ::sleep(1);
    }
    if (!identified) {
        logging::error("could not read instance identity from IMDSv2; is this an EC2 instance?");
        return 1;
    }
    std::string platform_name, platform_version;
    detect_platform(platform_name, platform_version);

    agent.info.name = kAgentName;
    agent.info.version = kAgentVersion;
    agent.info.os = platform_name;
    agent.info.os_ver = platform_version;

    logging::logf(logging::Info, "instance=%s region=%s az=%s platform=%s %s",
                  agent.id.instance_id.c_str(), agent.id.region.c_str(),
                  agent.id.availability_zone.c_str(), platform_name.c_str(),
                  platform_version.c_str());

    if (opt.ping_once) {
        bool ok = agent.health_ping(platform_name, platform_version);
        std::printf("UpdateInstanceInformation: %s\n", ok ? "OK" : "FAILED");
        return ok ? 0 : 1;
    }

    // Register before polling, so the node shows up even if MDS is quiet.
    if (!agent.health_ping(platform_name, platform_version))
        logging::warn("initial health ping failed; continuing to poll anyway");

    if (opt.poll_once) {
        agent.poll_once();
        return 0;
    }

    std::thread health([&agent, platform_name, platform_version, &opt]() {
        int64_t next = util::now_epoch() + kHealthIntervalSeconds;
        while (!g_stop.load()) {
            if (util::now_epoch() >= next) {
                // Re-check the clock every cycle: with no NTP on the platform it
                // will drift, and drift eventually breaks TLS outright.
                timesync::ensure_clock(agent.imds, opt.time_sync, kMaxClockDriftSeconds);
                agent.health_ping(platform_name, platform_version);
                next = util::now_epoch() + kHealthIntervalSeconds;
            }
            ::sleep(1);
        }
    });

    unsigned seed = static_cast<unsigned>(util::now_epoch_ms() ^ ::getpid());
    while (!g_stop.load()) {
        const int64_t elapsed = agent.poll_once();
        if (g_stop.load()) break;
        // Copied from the Go agent (mdsinteractor.go:454): if GetMessages came
        // back immediately, back off so we do not flood the service.
        if (elapsed < 1000) {
            const int jitter = 2000 + static_cast<int>(::rand_r(&seed) % 500);
            ::usleep(static_cast<useconds_t>(jitter) * 1000);
        }
    }

    logging::info("stop requested; shutting down");
    health.join();
    logging::logf(logging::Info, "%s stopped", kAgentName);
    return 0;
}
