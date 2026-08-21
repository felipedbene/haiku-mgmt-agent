#include "timesync.h"

#include <sys/time.h>
#include <time.h>

#include <cerrno>
#include <cstring>

#include "log.h"
#include "util.h"

namespace timesync {

Result ensure_clock(aws::Imds& imds, bool allow_set, int64_t max_drift) {
    Result r;
    int64_t reference = 0;
    if (!imds.server_time(reference)) {
        logging::warn("could not read reference time from IMDS; leaving the clock alone");
        return r;
    }
    r.checked = true;

    const int64_t local = util::now_epoch();
    r.drift = reference - local;
    if (r.drift > -max_drift && r.drift < max_drift) {
        logging::logf(logging::Debug, "clock is within %llds of IMDS (drift %llds)",
                      static_cast<long long>(max_drift), static_cast<long long>(r.drift));
        return r;
    }

    logging::logf(logging::Warn, "system clock is off by %llds (local=%s reference=%s)",
                  static_cast<long long>(r.drift), util::iso8601(local * 1000).c_str(),
                  util::iso8601(reference * 1000).c_str());

    if (!allow_set) {
        logging::warn("time sync disabled (--no-time-sync); TLS and SigV4 will likely fail");
        return r;
    }

    // clock_settime only: Haiku does not provide settimeofday().
    struct timespec ts {};
    ts.tv_sec = static_cast<time_t>(reference);
    ts.tv_nsec = 0;
    if (::clock_settime(CLOCK_REALTIME, &ts) != 0) {
        logging::logf(logging::Error,
                      "could not set the clock (clock_settime: %s); run as root, or TLS and SigV4 "
                      "will keep failing",
                      std::strerror(errno));
        return r;
    }
    r.adjusted = true;

    logging::logf(logging::Info, "system clock set from IMDS to %s",
                  util::iso8601(util::now_epoch_ms()).c_str());
    return r;
}

}  // namespace timesync
