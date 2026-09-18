// metrics.h -- native host metrics + CloudWatch PutMetricData (F7, issue #119).
//
// Collects CPU/memory/disk/network from Haiku's own kernel counters
// (get_system_info, get_cpu_info, statvfs, SIOCGIFSTATS) and ships them to
// CloudWatch via the "monitoring" Query protocol (aws::put_metric_data).
//
// Why native counters, not the hypervisor number: the EC2 platform-side
// CPUUtilization for a Haiku/arm64 guest under-reports by ~55x (DeBeOS #140) --
// the guest's idle/steal accounting is not what the Nitro side expects, so the
// value CloudWatch derives from the hypervisor is meaningless. Computing busy%
// from cpu_info::active_time (usec of useful work since boot) on the box gives
// the true figure. This is the whole point of the feature.
#pragma once

#include <cstdint>
#include <string>

#include "aws.h"

namespace metrics {

// A point-in-time reading of the box. Rates (CPU%, network) are derived from
// two samples; absolute gauges (memory, disk) are read straight off `cur`.
struct Sample {
    int64_t wall_us = 0;         // util::now_epoch_ms() * 1000, the sample instant
    uint32_t cpu_count = 0;
    uint64_t cpu_active_us = 0;  // sum of cpu_info::active_time over all CPUs
    uint64_t mem_total = 0;      // bytes
    uint64_t mem_used = 0;       // bytes (used_pages)
    uint64_t mem_cached = 0;     // bytes (cached_pages)
    uint64_t disk_total = 0;     // bytes, the system volume ("/boot")
    uint64_t disk_used = 0;      // bytes
    uint64_t net_rx_bytes = 0;   // summed over non-loopback interfaces
    uint64_t net_tx_bytes = 0;
    uint32_t thread_count = 0;
    bool valid = false;

    // A monotonic-since-boot counter reset (reboot) makes a delta negative;
    // callers must treat that as "no rate this cycle", not a huge spike.
    bool before(const Sample& later) const {
        return valid && later.valid && later.wall_us > wall_us;
    }
};

// Read the box now. `valid` is false only if get_system_info itself fails.
Sample collect();

// CPU busy percent across all CPUs from two samples, clamped to [0,100].
// Returns -1 when it cannot be computed (first cycle / counter reset).
double cpu_percent(const Sample& prev, const Sample& cur);

// Build the CloudWatch PutMetricData Query-protocol form body (URL-encoded,
// Version=2010-08-01) for namespace `ns`, dimensioned by InstanceId. `prev`
// may be invalid on the first cycle -- CPU% and the network rates are then
// omitted rather than reported as zero or garbage. Exposed for unit testing.
std::string build_put_body(const std::string& ns, const std::string& instance_id,
                           const Sample& prev, const Sample& cur);

// One collect+PutMetricData cycle. `prev` carries state across calls (the poll
// loop keeps one Sample); it is updated to the just-taken reading on success or
// failure alike so a dropped cycle does not corrupt the next rate. Returns true
// on an HTTP 200 from CloudWatch.
bool emit(aws::CredentialProvider& creds, const std::string& region, const std::string& ns,
          const std::string& instance_id, Sample& prev);

}  // namespace metrics
