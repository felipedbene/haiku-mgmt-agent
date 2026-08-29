// log.h -- thread-safe line logger to /var/log/debeos-ssm-agent.log (BRIEF.md 5).
#pragma once

#include <string>

namespace logging {

enum Level { Debug, Info, Warn, Error };

// path empty => stderr only. Also mirrors to stderr when `also_stderr`.
void init(const std::string& path, Level min_level, bool also_stderr);

void log(Level level, const std::string& msg);

inline void debug(const std::string& m) { log(Debug, m); }
inline void info(const std::string& m) { log(Info, m); }
inline void warn(const std::string& m) { log(Warn, m); }
inline void error(const std::string& m) { log(Error, m); }

// printf-style, for the many "%s failed: %s" call sites.
void logf(Level level, const char* fmt, ...);

}  // namespace logging
