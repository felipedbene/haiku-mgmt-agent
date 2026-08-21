// timesync.h -- keep the system clock correct enough for TLS and SigV4.
//
// Haiku on EC2 arm64 boots with the clock at 1970-01-01 and ships no NTP client
// (see TESTING.md). That breaks both halves of every AWS call:
//   * TLS: "The certificate validity starts in the future"
//   * SigV4: x-amz-date would be 56 years stale, so every signature is rejected
//
// IMDS is plain HTTP on a link-local address, so its Date header is reachable
// before any of that works. We use it as the time source.
#pragma once

#include <cstdint>

#include "aws.h"

namespace timesync {

struct Result {
    bool checked = false;   // did we get a reference time at all
    bool adjusted = false;  // did we change the clock
    int64_t drift = 0;      // reference - local, in seconds, before adjusting
};

// Compares the local clock against IMDS and sets it when it is off by more than
// max_drift seconds. Requires root to adjust; logs and continues if it cannot.
Result ensure_clock(aws::Imds& imds, bool allow_set, int64_t max_drift);

}  // namespace timesync
