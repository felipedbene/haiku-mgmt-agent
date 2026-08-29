#include "exec.h"

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>

#include "log.h"
#include "util.h"

namespace exec {
namespace {

constexpr int kDefaultTimeoutSeconds = 3600;  // SSM's own executionTimeout default
constexpr int kGraceSeconds = 5;              // SIGTERM -> SIGKILL window

}  // namespace

Result run_shell(const std::string& script, int timeout_seconds, const std::string& working_dir,
                 size_t max_capture_bytes, Cancel* cancel) {
    Result r;
    if (timeout_seconds <= 0) timeout_seconds = kDefaultTimeoutSeconds;

    int out_pipe[2] = {-1, -1};
    int err_pipe[2] = {-1, -1};
    if (::pipe(out_pipe) != 0) {
        r.error = std::string("pipe: ") + std::strerror(errno);
        return r;
    }
    if (::pipe(err_pipe) != 0) {
        r.error = std::string("pipe: ") + std::strerror(errno);
        ::close(out_pipe[0]);
        ::close(out_pipe[1]);
        return r;
    }

    pid_t pid = ::fork();
    if (pid < 0) {
        r.error = std::string("fork: ") + std::strerror(errno);
        ::close(out_pipe[0]); ::close(out_pipe[1]);
        ::close(err_pipe[0]); ::close(err_pipe[1]);
        return r;
    }

    if (pid == 0) {
        // ---- child ----
        // New session/process group: a timeout can then signal the entire tree,
        // including anything the script backgrounded.
        ::setsid();

        ::close(out_pipe[0]);
        ::close(err_pipe[0]);
        ::dup2(out_pipe[1], STDOUT_FILENO);
        ::dup2(err_pipe[1], STDERR_FILENO);
        ::close(out_pipe[1]);
        ::close(err_pipe[1]);

        // stdin from /dev/null: a command that reads stdin must not hang the agent.
        int devnull = ::open("/dev/null", O_RDONLY);
        if (devnull >= 0) {
            ::dup2(devnull, STDIN_FILENO);
            ::close(devnull);
        }

        if (!working_dir.empty() && ::chdir(working_dir.c_str()) != 0) {
            std::string msg = "debeos-ssm-agent: chdir(" + working_dir + ") failed: " + std::strerror(errno) + "\n";
            ::write(STDERR_FILENO, msg.data(), msg.size());
            ::_exit(127);
        }

        ::execl("/bin/sh", "sh", "-c", script.c_str(), static_cast<char*>(nullptr));
        std::string msg = std::string("debeos-ssm-agent: exec /bin/sh failed: ") + std::strerror(errno) + "\n";
        ::write(STDERR_FILENO, msg.data(), msg.size());
        ::_exit(127);
    }

    // ---- parent ----
    ::close(out_pipe[1]);
    ::close(err_pipe[1]);

    const int64_t deadline_ms = util::now_epoch_ms() + static_cast<int64_t>(timeout_seconds) * 1000;
    bool killed_term = false, killed_kill = false;
    int64_t kill_deadline_ms = 0;
    bool out_open = true, err_open = true;
    bool out_clipped = false, err_clipped = false;

    while (out_open || err_open) {
        struct pollfd fds[2];
        int n = 0;
        int out_idx = -1;
        if (out_open) { fds[n].fd = out_pipe[0]; fds[n].events = POLLIN; out_idx = n; n++; }
        if (err_open) { fds[n].fd = err_pipe[0]; fds[n].events = POLLIN; n++; }

        int64_t now = util::now_epoch_ms();
        int64_t wait_ms = (killed_term ? kill_deadline_ms : deadline_ms) - now;
        if (wait_ms < 0) wait_ms = 0;
        if (wait_ms > 1000) wait_ms = 1000;  // wake regularly to re-check deadlines

        int pr = ::poll(fds, n, static_cast<int>(wait_ms));
        if (pr < 0 && errno != EINTR) {
            r.error = std::string("poll: ") + std::strerror(errno);
            break;
        }

        if (pr > 0) {
            for (int i = 0; i < n; i++) {
                if (!(fds[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
                char buf[8192];
                ssize_t got = ::read(fds[i].fd, buf, sizeof(buf));
                if (got > 0) {
                    std::string* sink = (i == out_idx) ? &r.stdout_data : &r.stderr_data;
                    bool* clipped = (i == out_idx) ? &out_clipped : &err_clipped;
                    if (sink->size() < max_capture_bytes) {
                        size_t room = max_capture_bytes - sink->size();
                        sink->append(buf, std::min(room, static_cast<size_t>(got)));
                        if (static_cast<size_t>(got) > room) *clipped = true;
                    } else {
                        *clipped = true;  // keep draining so the child never blocks on a full pipe
                    }
                } else if (got == 0 || (got < 0 && errno != EINTR && errno != EAGAIN)) {
                    if (i == out_idx) { out_open = false; ::close(out_pipe[0]); }
                    else { err_open = false; ::close(err_pipe[0]); }
                }
            }
        }

        now = util::now_epoch_ms();
        const bool cancel_now = cancel && cancel->requested.load() && !killed_term;
        if (cancel_now || (!killed_term && now >= deadline_ms)) {
            if (cancel_now) r.cancelled = true;
            else r.timed_out = true;
            killed_term = true;
            kill_deadline_ms = now + kGraceSeconds * 1000;
            // Negative pid => whole process group, i.e. the shell and its children.
            if (::kill(-pid, SIGTERM) != 0)
                logging::logf(logging::Warn, "SIGTERM to process group %d failed: %s", static_cast<int>(pid),
                              std::strerror(errno));
            else
                logging::logf(logging::Warn, "%s; sent SIGTERM to process group %d",
                              cancel_now ? "command cancelled"
                                         : "command exceeded its timeout",
                              static_cast<int>(pid));
        } else if (killed_term && !killed_kill && now >= kill_deadline_ms) {
            killed_kill = true;
            if (::kill(-pid, SIGKILL) != 0)
                logging::logf(logging::Warn, "SIGKILL to process group %d failed: %s", static_cast<int>(pid),
                              std::strerror(errno));
            else
                logging::logf(logging::Warn, "process group %d ignored SIGTERM; sent SIGKILL",
                              static_cast<int>(pid));
            break;  // stop draining: the tree is gone
        }
    }

    if (out_open) ::close(out_pipe[0]);
    if (err_open) ::close(err_pipe[0]);

    if (out_clipped) r.stdout_data += "\n--output truncated--";
    if (err_clipped) r.stderr_data += "\n--output truncated--";

    // Reap. Bounded wait so a wedged child cannot hang the poll loop forever;
    // open question 5 is exactly about whether Haiku behaves here.
    int status = 0;
    const int64_t reap_deadline = util::now_epoch_ms() + 10000;
    while (true) {
        pid_t w = ::waitpid(pid, &status, WNOHANG);
        if (w == pid) break;
        if (w < 0) {
            if (errno == EINTR) continue;
            r.error = std::string("waitpid: ") + std::strerror(errno);
            logging::logf(logging::Error, "waitpid(%d) failed: %s -- possible Haiku reap issue, see TESTING.md",
                          static_cast<int>(pid), std::strerror(errno));
            return r;
        }
        if (util::now_epoch_ms() > reap_deadline) {
            ::kill(-pid, SIGKILL);
            r.error = "child did not reap within 10s after exit/kill (see TESTING.md, open question 5)";
            logging::logf(logging::Error, "%s: pid=%d", r.error.c_str(), static_cast<int>(pid));
            return r;
        }
        ::usleep(50000);
    }

    if (WIFEXITED(status)) {
        r.exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        r.signalled = true;
        r.signal_number = WTERMSIG(status);
        r.exit_code = 128 + r.signal_number;
    }
    return r;
}

}  // namespace exec
