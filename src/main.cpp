// haiku-mgmt-agent -- minimal SSM-compatible management agent for Haiku/arm64.
//
// Phase 1 (BRIEF.md 2): MDS long-poll, aws:runShellScript, inline output,
// health ping. Phase 2 (docs/design-roadmap.md): native S3 transfer (F1),
// OutputS3BucketName command output (F2), self-update (F3), plus real
// CancelCommand support. Still no MGS/Session Manager and no inventory.
//
// Threads: the poll loop (this thread), one health-ping thread, one worker
// thread per in-flight command (so a long build cannot stall the poll loop and
// a CancelCommand can actually land), and optionally a self-update checker.

#include <signal.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>

#include "aws.h"
#include "ca_certs.h"
#include "http.h"
#include "json.h"
#include "log.h"
#include "patch.h"
#include "runner.h"
#include "s3.h"
#include "selfupdate.h"
#include "timesync.h"
#include "util.h"

namespace {

const char* kAgentName = "haiku-mgmt-agent";
const char* kAgentVersion = "0.3.0";
const char* kDefaultLogPath = "/var/log/haiku-mgmt-agent.log";
const char* kLaunchJob = "x-vnd.haiku-mgmt-agent";
const char* kDefaultBinaryPath = "/boot/system/non-packaged/bin/haiku-mgmt-agent";

// BRIEF.md 9.2: the Go agent's long-poll ceiling is Mds.StopTimeoutMillis,
// default 20 s. Our HTTP timeout must exceed it.
constexpr int kPollHttpTimeoutMs = 25000;
constexpr int kHealthIntervalSeconds = 300;  // healthcheck.go default: 5 minutes
constexpr int kUpdateIntervalSeconds = 3600;
constexpr size_t kDedupHistory = 512;
// With S3 output there is somewhere to put a full build log, so capture far
// more than the 24 KB inline clip. Bounded: builders have 4-8 GiB total.
constexpr size_t kS3CaptureBytes = 8 * 1024 * 1024;
// How long shutdown waits for in-flight commands after cancelling them.
constexpr int kDrainSeconds = 15;

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
    std::string update_manifest;  // empty => no self-update polling
    std::string binary_path = kDefaultBinaryPath;
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
        "daemon options:\n"
        "  --ping-once            send one UpdateInstanceInformation and exit (Stage 1 gate)\n"
        "  --poll-once            run a single MDS poll cycle and exit\n"
        "  --no-time-sync         do not set the system clock from IMDS (Haiku boots at 1970)\n"
        "  --update-manifest URI  poll this s3://... or https://... manifest hourly and\n"
        "                         self-update when it names a newer version\n"
        "  --binary-path PATH     where a raw-binary self-update swaps the executable\n"
        "                         (default %s)\n"
        "  --foreground           log to stderr as well as the log file\n"
        "  --log-file PATH        default %s\n"
        "  --log-level L          debug|info|warn|error (default info)\n"
        "  --version              print version and exit\n"
        "\n"
        "subcommands (use the instance role via IMDS):\n"
        "  s3 cp <local> s3://bucket/key    upload a file\n"
        "  s3 cp s3://bucket/key <local>    download a file\n"
        "  patch scan|install [--no-report]\n"
        "                         run the Patch Manager operation now (pkgman-backed);\n"
        "                         --no-report skips the PutInventory compliance upload\n"
        "  self-update --manifest URI [--restart]\n"
        "                         check the manifest now; install a newer version;\n"
        "                         with --restart, restart the launch_daemon service after\n",
        kAgentVersion, kDefaultBinaryPath, kDefaultLogPath);
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

// Commands currently executing on worker threads, keyed by command id, so a
// CancelCommand can reach them and shutdown can drain them.
class InFlight {
public:
    std::shared_ptr<exec::Cancel> add(const std::string& command_id) {
        std::lock_guard<std::mutex> lock(mu_);
        auto token = std::make_shared<exec::Cancel>();
        map_[command_id] = token;
        count_++;
        return token;
    }
    void done(const std::string& command_id) {
        std::lock_guard<std::mutex> lock(mu_);
        map_.erase(command_id);
        count_--;
        cv_.notify_all();
    }
    bool cancel(const std::string& command_id) {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = map_.find(command_id);
        if (it == map_.end()) return false;
        it->second->request();
        return true;
    }
    void cancel_all() {
        std::lock_guard<std::mutex> lock(mu_);
        for (auto& kv : map_) kv.second->request();
    }
    // Returns false if commands were still running when the wait expired.
    bool drain(int seconds) {
        std::unique_lock<std::mutex> lock(mu_);
        return cv_.wait_for(lock, std::chrono::seconds(seconds), [this] { return count_ == 0; });
    }

private:
    std::mutex mu_;
    std::condition_variable cv_;
    std::map<std::string, std::shared_ptr<exec::Cancel>> map_;
    int count_ = 0;
};

struct Agent {
    aws::Imds imds;
    aws::CredentialProvider* creds = nullptr;
    aws::InstanceIdentity id;
    runner::AgentInfo info;
    SeenCommands seen;
    InFlight inflight;

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

    // F2: mirror the standard SSM S3 layout so console links resolve:
    //   <prefix>/<command-id>/<instance-id>/awsrunShellScript/<plugin>/{stdout,stderr}
    void upload_outputs(const std::string& command_id, const std::string& bucket,
                        const std::string& prefix, runner::DocumentOutcome& outcome) {
        if (bucket.empty()) return;
        for (runner::StepResult& sr : outcome.steps) {
            std::string key_prefix;
            if (!prefix.empty()) key_prefix = prefix + "/";
            key_prefix += command_id + "/" + id.instance_id + "/awsrunShellScript/" + sr.plugin_id;
            bool any = false, all_ok = true;
            const std::pair<const char*, const std::string*> streams[] = {
                {"stdout", &sr.full_stdout},
                {"stderr", &sr.full_stderr},
            };
            for (const auto& s : streams) {
                if (s.second->empty()) continue;
                any = true;
                http::Response r = s3::put(*creds, id.region, bucket, key_prefix + "/" + s.first,
                                           "", *s.second, "text/plain");
                if (!r.ok()) {
                    all_ok = false;
                    logging::logf(logging::Warn,
                                  "S3 output upload failed (%s/%s/%s): status=%d error=%s %s",
                                  bucket.c_str(), key_prefix.c_str(), s.first, r.status,
                                  r.error.c_str(), util::clip(r.body, 300, "...").c_str());
                }
            }
            if (any && all_ok) {
                sr.output_s3_bucket = bucket;
                sr.output_s3_key_prefix = key_prefix;
                logging::logf(logging::Info, "uploaded step %s output to s3://%s/%s",
                              sr.plugin_id.c_str(), bucket.c_str(), key_prefix.c_str());
            }
        }
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

        // Deep-copy what the worker needs: `msg` dies with this poll cycle.
        const json::Value document = *doc;
        const json::Value* params = payload.find("Parameters");
        const json::Value parameters = params ? *params : json::Value();
        const std::string s3_bucket = payload.str_at("OutputS3BucketName");
        const std::string s3_prefix = payload.str_at("OutputS3KeyPrefix");
        const std::string document_name = payload.str_at("DocumentName");

        std::shared_ptr<exec::Cancel> token = inflight.add(command_id);
        std::thread worker([this, message_id, command_id, document, parameters, s3_bucket,
                            s3_prefix, document_name, token]() {
            runner::Options opts;
            opts.cancel = token.get();
            if (!s3_bucket.empty()) opts.max_capture = kS3CaptureBytes;

            runner::DocumentOutcome outcome;
            if (patch::is_patch_document(document_name)) {
                // F5: the stock document's Linux step is a Python payload that
                // drives yum/apt; neither exists here. Run the equivalent
                // pkgman operation natively instead of executing the steps.
                patch::Context pctx;
                pctx.creds = creds;
                pctx.region = id.region;
                pctx.instance_id = id.instance_id;
                pctx.command_id = command_id;
                pctx.cancel = token.get();
                outcome = patch::run_baseline(pctx, parameters);
            } else {
                outcome = runner::run_document(document, parameters, opts);
            }
            upload_outputs(command_id, s3_bucket, s3_prefix, outcome);
            send_reply(message_id,
                       runner::reply_payload(info, outcome.status, outcome.trace, outcome.steps),
                       "SendReply(final)");
            logging::logf(logging::Info, "command %s completed: %s", command_id.c_str(),
                          outcome.status.c_str());
            inflight.done(command_id);
        });
        worker.detach();  // shutdown drains via InFlight, not join
    }

    void handle_cancel_command(const json::Value& msg) {
        const std::string message_id = msg.str_at("MessageId");
        std::string err;
        json::Value payload = json::parse(msg.str_at("Payload"), &err);
        // runcommand/contracts: {"CancelMessageId": "aws.ssm.<command-id>.<instance-id>"}
        const std::string target = payload.is_obj() ? payload.str_at("CancelMessageId") : "";
        const std::string command_id = command_id_from(target.empty() ? message_id : target);

        if (inflight.cancel(command_id)) {
            logging::logf(logging::Info, "cancelCommand: killing in-flight command %s",
                          command_id.c_str());
        } else {
            // Not running (already finished, or never started here). The final
            // state was or will be reported by the normal path; just ack.
            logging::logf(logging::Info, "cancelCommand for %s: nothing in flight",
                          command_id.c_str());
        }
        aws::Credentials c;
        if (creds->get(c)) aws::acknowledge_message(id.region, c, message_id);
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
            handle_cancel_command(msg);
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

// Shared bring-up for the CLI subcommands: CA bundle, clock, identity, creds.
bool cli_bootstrap(Agent& agent, aws::CredentialProvider& provider) {
    logging::init("", logging::Warn, true);  // subcommands talk via stdout, not the log file
    ::signal(SIGPIPE, SIG_IGN);
    http::set_ca_bundle(ca::kAmazonTrustRoots);
    agent.creds = &provider;
    timesync::ensure_clock(agent.imds, true, kMaxClockDriftSeconds);
    if (!agent.imds.identity(agent.id)) {
        std::fprintf(stderr, "error: no IMDSv2 identity; this command needs to run on EC2\n");
        return false;
    }
    return true;
}

// F1: `s3 cp <src> <dst>` with exactly one s3:// side.
int cmd_s3(int argc, char** argv) {
    if (argc < 4 || std::strcmp(argv[2], "cp") != 0) {
        usage();
        return 2;
    }
    if (argc != 5) {
        std::fprintf(stderr, "usage: %s s3 cp <src> <dst>\n", kAgentName);
        return 2;
    }
    const std::string src = argv[3], dst = argv[4];

    std::string bucket, key;
    const bool src_is_s3 = s3::parse_uri(src, bucket, key);
    std::string bucket2, key2;
    const bool dst_is_s3 = s3::parse_uri(dst, bucket2, key2);
    if (src_is_s3 == dst_is_s3) {
        std::fprintf(stderr, "error: exactly one of <src>/<dst> must be s3://bucket/key\n");
        return 2;
    }

    Agent agent;
    aws::CredentialProvider provider(&agent.imds);
    if (!cli_bootstrap(agent, provider)) return 1;

    const int64_t t0 = util::now_epoch_ms();
    http::Response r;
    if (src_is_s3) {
        r = s3::get(provider, agent.id.region, bucket, key, dst);
    } else {
        r = s3::put(provider, agent.id.region, bucket2, key2, src, "");
    }
    const double secs = static_cast<double>(util::now_epoch_ms() - t0) / 1000.0;

    if (!r.ok()) {
        std::fprintf(stderr, "error: status=%d %s\n%s\n", r.status, r.error.c_str(),
                     util::clip(r.body, 500, "...").c_str());
        return 1;
    }
    const size_t bytes = src_is_s3 ? r.sink_bytes : [&] {
        // PUT: report what we sent (the file size).
        std::FILE* f = std::fopen(src.c_str(), "rb");
        if (!f) return static_cast<size_t>(0);
        std::fseek(f, 0, SEEK_END);
        long n = std::ftell(f);
        std::fclose(f);
        return n > 0 ? static_cast<size_t>(n) : static_cast<size_t>(0);
    }();
    std::printf("%s -> %s: %zu bytes in %.1fs (%.1f MiB/s)\n", src.c_str(), dst.c_str(), bytes,
                secs, secs > 0 ? static_cast<double>(bytes) / (1024 * 1024) / secs : 0.0);
    return 0;
}

// F5, manual: `patch scan|install [--no-report]` -- the same code path a
// console-issued AWS-RunPatchBaseline takes, runnable on the box for testing.
int cmd_patch(int argc, char** argv) {
    std::string operation;
    bool report = true;
    for (int i = 2; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--no-report") { report = false; continue; }
        if (operation.empty() && (a == "scan" || a == "install")) { operation = a; continue; }
        std::fprintf(stderr, "unknown argument: %s\n", a.c_str());
        operation.clear();
        break;
    }
    if (operation.empty()) {
        std::fprintf(stderr, "usage: %s patch scan|install [--no-report]\n", kAgentName);
        return 2;
    }

    Agent agent;
    aws::CredentialProvider provider(&agent.imds);
    if (!cli_bootstrap(agent, provider)) return 1;

    json::Value params = json::obj();
    params.object["Operation"] = json::str(operation);
    // The agent never reboots the instance, so the CLI declares NoReboot.
    params.object["RebootOption"] = json::str("NoReboot");

    patch::Context ctx;
    ctx.creds = &provider;
    ctx.region = agent.id.region;
    ctx.instance_id = agent.id.instance_id;
    ctx.command_id = util::uuid4();
    ctx.report_inventory = report;

    runner::DocumentOutcome outcome = patch::run_baseline(ctx, params);
    for (const runner::StepResult& sr : outcome.steps) {
        if (!sr.full_stdout.empty()) std::fputs(sr.full_stdout.c_str(), stdout);
        if (!sr.full_stderr.empty()) std::fputs(sr.full_stderr.c_str(), stderr);
    }
    std::printf("%s\n", outcome.status.c_str());
    return outcome.status == "Success" ? 0 : 1;
}

// F3, manual: `self-update --manifest URI [--restart]`.
int cmd_self_update(int argc, char** argv) {
    std::string manifest, binary_path = kDefaultBinaryPath;
    bool restart = false;
    for (int i = 2; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--manifest" && i + 1 < argc) { manifest = argv[++i]; continue; }
        if (a == "--binary-path" && i + 1 < argc) { binary_path = argv[++i]; continue; }
        if (a == "--restart") { restart = true; continue; }
        std::fprintf(stderr, "unknown argument: %s\n", a.c_str());
        return 2;
    }
    if (manifest.empty()) {
        std::fprintf(stderr, "usage: %s self-update --manifest <s3://...|https://...> [--restart]\n",
                     kAgentName);
        return 2;
    }

    Agent agent;
    aws::CredentialProvider provider(&agent.imds);
    if (!cli_bootstrap(agent, provider)) return 1;

    std::string detail;
    selfupdate::Outcome o = selfupdate::check_and_apply(provider, agent.id.region, manifest,
                                                        kAgentVersion, binary_path, detail);
    switch (o) {
        case selfupdate::Outcome::UpToDate:
            std::printf("up to date: %s\n", detail.c_str());
            return 0;
        case selfupdate::Outcome::Updated:
            std::printf("updated: %s\n", detail.c_str());
            if (restart) {
                std::printf("restarting %s via launch_roster\n", kLaunchJob);
                std::string cmd = std::string("launch_roster restart ") + kLaunchJob;
                return std::system(cmd.c_str()) == 0 ? 0 : 1;
            }
            std::printf("restart the service to run the new version: launch_roster restart %s\n",
                        kLaunchJob);
            return 0;
        case selfupdate::Outcome::Error:
        default:
            std::fprintf(stderr, "self-update failed: %s\n", detail.c_str());
            return 1;
    }
}

}  // namespace

int main(int argc, char** argv) {
    if (argc >= 2 && std::strcmp(argv[1], "s3") == 0) return cmd_s3(argc, argv);
    if (argc >= 2 && std::strcmp(argv[1], "patch") == 0) return cmd_patch(argc, argv);
    if (argc >= 2 && std::strcmp(argv[1], "self-update") == 0) return cmd_self_update(argc, argv);

    Options opt;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--help" || a == "-h") { usage(); return 0; }
        if (a == "--version") { std::printf("%s %s\n", kAgentName, kAgentVersion); return 0; }
        if (a == "--foreground") { opt.foreground = true; continue; }
        if (a == "--ping-once") { opt.ping_once = true; opt.foreground = true; continue; }
        if (a == "--poll-once") { opt.poll_once = true; opt.foreground = true; continue; }
        if (a == "--no-time-sync") { opt.time_sync = false; continue; }
        if (a == "--update-manifest" && i + 1 < argc) { opt.update_manifest = argv[++i]; continue; }
        if (a == "--binary-path" && i + 1 < argc) { opt.binary_path = argv[++i]; continue; }
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
        agent.inflight.drain(kDrainSeconds);
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

    // F3: poll the manifest and roll the fleet forward with no rebake. After a
    // successful install the *service* is restarted, so this process exits via
    // launch_daemon's SIGTERM; the new binary reports the new AgentVersion.
    std::thread updater;
    if (!opt.update_manifest.empty()) {
        updater = std::thread([&agent, &provider, &opt]() {
            int64_t next = util::now_epoch() + 60;  // first check shortly after boot
            while (!g_stop.load()) {
                if (util::now_epoch() >= next) {
                    std::string detail;
                    selfupdate::Outcome o = selfupdate::check_and_apply(
                        provider, agent.id.region, opt.update_manifest, kAgentVersion,
                        opt.binary_path, detail);
                    if (o == selfupdate::Outcome::Updated) {
                        logging::logf(logging::Info,
                                      "self-update installed (%s); scheduling service restart",
                                      detail.c_str());
                        // Detached so the restart survives this process's exit.
                        std::string cmd = std::string("(sleep 2; launch_roster restart ") +
                                          kLaunchJob + ") >/dev/null 2>&1 &";
                        std::system(cmd.c_str());
                    } else if (o == selfupdate::Outcome::Error) {
                        logging::logf(logging::Warn, "self-update check failed: %s",
                                      detail.c_str());
                    }
                    next = util::now_epoch() + kUpdateIntervalSeconds;
                }
                ::sleep(1);
            }
        });
    }

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
    // Give in-flight commands the same treatment as a cancel: kill their
    // process groups, wait briefly for the final replies to go out.
    agent.inflight.cancel_all();
    if (!agent.inflight.drain(kDrainSeconds))
        logging::warn("in-flight commands did not finish within the drain window");
    health.join();
    if (updater.joinable()) updater.join();
    logging::logf(logging::Info, "%s stopped", kAgentName);
    return 0;
}
