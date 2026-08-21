// exec.h -- run a shell script with a hard timeout, capturing stdout/stderr.
//
// The child is put in its own process group so a timeout kills the whole tree,
// not just /bin/sh. Reaping behaviour on Haiku is open question 5 in BRIEF.md;
// findings go in TESTING.md.
#pragma once

#include <string>

namespace exec {

struct Result {
    int exit_code = -1;
    bool timed_out = false;
    bool signalled = false;
    int signal_number = 0;
    std::string stdout_data;
    std::string stderr_data;
    std::string error;  // harness failure (fork/pipe), distinct from script failure
};

// Runs `script` via /bin/sh -c. timeout_seconds <= 0 means the default cap.
// `working_dir` is chdir'd into when non-empty.
Result run_shell(const std::string& script, int timeout_seconds, const std::string& working_dir,
                 size_t max_capture_bytes);

}  // namespace exec
