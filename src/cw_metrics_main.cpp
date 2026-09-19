// debeos-cloudwatch -- standalone CloudWatch host-metrics daemon for DeBeOS on EC2.
//
// Publishes CPU/memory/disk/network/thread metrics to CloudWatch namespace
// DeBeOS/Host from Haiku's own kernel counters (a true CPU busy%, not the
// hypervisor number that under-reports a Haiku/arm64 guest by ~55x, DeBeOS
// #140). Authenticates with the instance role via IMDSv2 + SigV4.
//
// It deliberately does NOT register as an SSM node, heartbeat, or open a
// command channel -- that is the official amazon-ssm-agent's job. Two processes
// heartbeating the same instance (UpdateInstanceInformation) wedge Run Command,
// so the metrics feature is factored out of the SSM agent into this tiny daemon
// that only ever calls PutMetricData. It reuses the mgmt-agent's shared
// SigV4/TLS/HTTP/JSON/metrics/timesync code.
//
// The metrics collection + emit is identical to metrics::emit used by the agent
// (src/metrics.cpp); this file is only the standalone entry point and loop.
//
// Optionally (opt-in via --logs) it also tails a log file -- the DeBeOS syslog
// by default -- into CloudWatch Logs (cwlogs::emit), on its own interval but on
// this same single thread, so the two never contend. Like the metrics path it
// makes no SSM calls, so it never disturbs the amazon-ssm-agent.

#include <signal.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "aws.h"
#include "ca_certs.h"
#include "cwlogs.h"
#include "http.h"
#include "log.h"
#include "metrics.h"
#include "timesync.h"
#include "util.h"

namespace {

const char* kName = "debeos-cloudwatch";
const char* kVersion = "0.1.0";
const char* kDefaultNamespace = "DeBeOS/Host";
const char* kDefaultLogPath = "/var/log/debeos-cloudwatch.log";
constexpr int kDefaultIntervalSeconds = 60;
// CloudWatch Logs (opt-in). Default source is the system syslog; the stream
// name defaults to the instance id (set after IMDS identity).
const char* kDefaultLogsGroup = "DeBeOS/syslog";
const char* kDefaultLogsSource = "/var/log/syslog";
constexpr int kDefaultLogsIntervalSeconds = 30;
// Haiku boots at epoch 0 with no NTP client; correcting it is not optional for
// TLS/SigV4 (see timesync.h). IMDS is plain HTTP, reachable before TLS works.
constexpr int64_t kMaxClockDriftSeconds = 60;
// launch_daemon may start us before the NIC is up; retry rather than exit.
constexpr int kIdentityAttempts = 40;
constexpr int kIdentityRetrySeconds = 3;

std::atomic<bool> g_stop{false};
void on_signal(int) { g_stop.store(true); }

void usage() {
    std::printf(
        "%s %s -- publish host metrics to CloudWatch (namespace DeBeOS/Host)\n"
        "usage: debeos-cloudwatch [options]\n"
        "  --namespace N     CloudWatch namespace (default DeBeOS/Host)\n"
        "  --interval S      seconds between PutMetricData cycles (default 60, min 5)\n"
        "  --once            emit a single cycle (two samples ~5s apart) and exit\n"
        "  --foreground      log to stderr as well as the log file\n"
        "  --no-time-sync    do not set the system clock from IMDS\n"
        "  --log-file PATH   default %s\n"
        "  --log-level L     debug|info|warn|error (default info)\n"
        "  --logs            also tail a log file into CloudWatch Logs (opt-in)\n"
        "  --logs-source P   file to tail (default %s)\n"
        "  --logs-group N    CloudWatch Logs group (default %s)\n"
        "  --logs-stream N   log stream name (default: this instance id)\n"
        "  --logs-interval S seconds between PutLogEvents cycles (default %d, min 5)\n"
        "  --version         print version and exit\n",
        kName, kVersion, kDefaultLogPath, kDefaultLogsSource, kDefaultLogsGroup,
        kDefaultLogsIntervalSeconds);
}

}  // namespace

int main(int argc, char** argv) {
    std::string ns = kDefaultNamespace;
    int interval = kDefaultIntervalSeconds;
    bool once = false;
    bool foreground = false;
    bool time_sync = true;
    std::string log_path = kDefaultLogPath;
    logging::Level level = logging::Info;
    bool logs_enabled = false;
    std::string logs_source = kDefaultLogsSource;
    std::string logs_group = kDefaultLogsGroup;
    std::string logs_stream;  // default set to instance id after IMDS
    int logs_interval = kDefaultLogsIntervalSeconds;

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--namespace" && i + 1 < argc) { ns = argv[++i]; continue; }
        if (a == "--interval" && i + 1 < argc) { interval = std::atoi(argv[++i]); continue; }
        if (a == "--once") { once = true; continue; }
        if (a == "--foreground") { foreground = true; continue; }
        if (a == "--no-time-sync") { time_sync = false; continue; }
        if (a == "--log-file" && i + 1 < argc) { log_path = argv[++i]; continue; }
        if (a == "--logs") { logs_enabled = true; continue; }
        if (a == "--logs-source" && i + 1 < argc) { logs_source = argv[++i]; continue; }
        if (a == "--logs-group" && i + 1 < argc) { logs_group = argv[++i]; continue; }
        if (a == "--logs-stream" && i + 1 < argc) { logs_stream = argv[++i]; continue; }
        if (a == "--logs-interval" && i + 1 < argc) { logs_interval = std::atoi(argv[++i]); continue; }
        if (a == "--log-level" && i + 1 < argc) {
            std::string l = argv[++i];
            level = (l == "debug") ? logging::Debug
                    : (l == "warn") ? logging::Warn
                    : (l == "error") ? logging::Error
                                     : logging::Info;
            continue;
        }
        if (a == "--version") { std::printf("%s %s\n", kName, kVersion); return 0; }
        if (a == "-h" || a == "--help") { usage(); return 0; }
        std::fprintf(stderr, "unknown argument: %s\n", a.c_str());
        usage();
        return 2;
    }
    if (interval < 5) interval = 5;
    if (logs_interval < 5) logs_interval = 5;

    logging::init(log_path, level, foreground);
    logging::logf(logging::Info, "%s %s starting (namespace %s, interval %ds)",
                  kName, kVersion, ns.c_str(), interval);
    if (logs_enabled)
        logging::logf(logging::Info, "%s CloudWatch Logs on: %s -> group %s, interval %ds",
                      kName, logs_source.c_str(), logs_group.c_str(), logs_interval);

    ::signal(SIGPIPE, SIG_IGN);
    ::signal(SIGTERM, on_signal);
    ::signal(SIGINT, on_signal);

    // Trust anchors are compiled in: Haiku/arm64 has no system CA store.
    http::set_ca_bundle(ca::kAmazonTrustRoots);

    aws::Imds imds;
    aws::CredentialProvider provider(&imds);
    aws::InstanceIdentity id;

    bool identified = false;
    for (int attempt = 1; attempt <= kIdentityAttempts && !g_stop.load(); attempt++) {
        // Fix the clock before anything that needs TLS or a signature.
        timesync::ensure_clock(imds, time_sync, kMaxClockDriftSeconds);
        if (imds.identity(id)) { identified = true; break; }
        logging::logf(logging::Warn,
                      "IMDSv2 identity unavailable (attempt %d/%d); retry in %ds",
                      attempt, kIdentityAttempts, kIdentityRetrySeconds);
        for (int s = 0; s < kIdentityRetrySeconds && !g_stop.load(); s++) ::sleep(1);
    }
    if (!identified) {
        logging::error("could not read instance identity from IMDSv2; is this an EC2 instance?");
        return 1;
    }
    logging::logf(logging::Info, "instance=%s region=%s", id.instance_id.c_str(),
                  id.region.c_str());

    metrics::Sample prev = metrics::collect();  // seed; first delta is next cycle

    cwlogs::Options logs_opt;
    cwlogs::State logs_state;
    if (logs_enabled) {
        logs_opt.source_path = logs_source;
        logs_opt.group = logs_group;
        logs_opt.stream = logs_stream.empty() ? id.instance_id : logs_stream;
    }

    if (once) {
        for (int s = 0; s < 5 && !g_stop.load(); s++) ::sleep(1);
        bool ok = metrics::emit(provider, id.region, ns, id.instance_id, prev);
        logging::logf(logging::Info, "single cycle %s", ok ? "ok" : "failed");
        if (logs_enabled) {
            bool lok = cwlogs::emit(provider, id.region, logs_opt, logs_state);
            logging::logf(logging::Info, "single logs cycle %s", lok ? "ok" : "failed");
            ok = ok && lok;
        }
        return ok ? 0 : 1;
    }

    int64_t next = util::now_epoch() + interval;
    int64_t next_logs = util::now_epoch() + logs_interval;
    while (!g_stop.load()) {
        const int64_t now = util::now_epoch();
        if (now >= next) {
            // Re-check the clock each cycle: with no NTP it drifts, and drift
            // eventually breaks TLS/SigV4 outright.
            timesync::ensure_clock(imds, time_sync, kMaxClockDriftSeconds);
            metrics::emit(provider, id.region, ns, id.instance_id, prev);
            next = util::now_epoch() + interval;
        }
        if (logs_enabled && now >= next_logs) {
            cwlogs::emit(provider, id.region, logs_opt, logs_state);
            next_logs = util::now_epoch() + logs_interval;
        }
        ::sleep(1);
    }

    logging::logf(logging::Info, "%s stopped", kName);
    return 0;
}
