#include "log.h"

#include <cstdarg>
#include <cstdio>
#include <mutex>
#include <string>

#include "util.h"

namespace logging {
namespace {

std::mutex g_mutex;
std::string g_path;
Level g_min = Info;
bool g_stderr = true;

const char* name(Level l) {
    switch (l) {
        case Debug: return "DEBUG";
        case Info: return "INFO";
        case Warn: return "WARN";
        case Error: return "ERROR";
    }
    return "?";
}

}  // namespace

void init(const std::string& path, Level min_level, bool also_stderr) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_path = path;
    g_min = min_level;
    g_stderr = also_stderr || path.empty();
}

void log(Level level, const std::string& msg) {
    if (level < g_min) return;
    std::string line = util::iso8601(util::now_epoch_ms());
    line += " [";
    line += name(level);
    line += "] ";
    line += msg;
    line += '\n';

    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_path.empty()) {
        // Append-and-close per line: the log stays readable if the daemon is
        // killed, and there is no buffered tail to lose.
        if (FILE* f = std::fopen(g_path.c_str(), "a")) {
            std::fwrite(line.data(), 1, line.size(), f);
            std::fclose(f);
        } else if (!g_stderr) {
            std::fputs(line.c_str(), stderr);  // never lose a line silently
        }
    }
    if (g_stderr) std::fputs(line.c_str(), stderr);
}

void logf(Level level, const char* fmt, ...) {
    if (level < g_min) return;
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    log(level, buf);
}

}  // namespace logging
