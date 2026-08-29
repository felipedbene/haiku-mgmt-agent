// exec.h -- run a shell script with a hard timeout, capturing stdout/stderr.
//
// The child is put in its own process group so a timeout kills the whole tree,
// not just /bin/sh. Reaping behaviour on Haiku is open question 5 in BRIEF.md;
// findings go in TESTING.md.
#pragma once

#include <atomic>
#include <string>

namespace exec {

struct Result {
    int exit_code = -1;
    bool timed_out = false;
    bool cancelled = false;
    bool signalled = false;
    int signal_number = 0;
    std::string stdout_data;
    std::string stderr_data;
    std::string error;  // harness failure (fork/pipe), distinct from script failure
};

// Cross-thread cancellation. The MDS poll thread flips the flag when a
// CancelCommand arrives; run_shell (on its worker thread) notices within one
// poll interval (<=1 s) and gives the process group the same SIGTERM->SIGKILL
// treatment as a timeout. Flag-only on the requesting side: no cross-thread
// kill(), so there is no race against the child being reaped.
struct Cancel {
    std::atomic<bool> requested{false};
    void request() { requested.store(true); }
};

// Runs `script` via /bin/sh -c. timeout_seconds <= 0 means the default cap.
// `working_dir` is chdir'd into when non-empty. `cancel` may be null.
Result run_shell(const std::string& script, int timeout_seconds, const std::string& working_dir,
                 size_t max_capture_bytes, Cancel* cancel = nullptr);

}  // namespace exec
