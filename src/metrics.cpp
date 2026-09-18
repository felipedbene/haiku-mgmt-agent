#include "metrics.h"

#include <sys/statvfs.h>

#include <cstdio>
#include <string>
#include <vector>

#include "log.h"
#include "util.h"

#ifdef __HAIKU__
#include <OS.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cstring>
#endif

namespace metrics {
namespace {

// One metric row for the Query protocol serializer.
struct Metric {
    std::string name;
    std::string value;  // already formatted
    const char* unit;   // CloudWatch Unit enum literal
};

std::string fmt_pct(double v) {
    if (v < 0) v = 0;
    if (v > 100) v = 100;
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.2f", v);
    return buf;
}

std::string fmt_u64(uint64_t v) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(v));
    return buf;
}

#ifdef __HAIKU__
// Sum receive/send bytes over every non-loopback interface. Best-effort: any
// ioctl failure just leaves the totals at 0 (the emitter then omits the rate).
void collect_net(Sample& s) {
    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return;

    // First ask how many interfaces there are, then size the SIOCGIFCONF buffer
    // generously (addresses are variable-length; _SIZEOF_ADDR_IFREQ walks them).
    ifconf conf;
    std::memset(&conf, 0, sizeof(conf));
    conf.ifc_len = sizeof(conf.ifc_value);  // SIOCGIFCOUNT convention (NetworkRoster.cpp)
    if (::ioctl(fd, SIOCGIFCOUNT, &conf, sizeof(conf)) < 0 || conf.ifc_value <= 0) {
        ::close(fd);
        return;
    }
    // Room for count entries at max size, plus slack for long link addresses.
    std::vector<char> buf(static_cast<size_t>(conf.ifc_value) * sizeof(ifreq) + 512);
    conf.ifc_len = static_cast<int>(buf.size());
    conf.ifc_buf = buf.data();
    if (::ioctl(fd, SIOCGIFCONF, &conf, sizeof(conf)) < 0) {
        ::close(fd);
        return;
    }

    const char* p = buf.data();
    const char* end = buf.data() + conf.ifc_len;
    while (p + IF_NAMESIZE <= end) {
        const ifreq* entry = reinterpret_cast<const ifreq*>(p);
        size_t step = _SIZEOF_ADDR_IFREQ(*entry);
        if (step == 0) break;

        if (std::strncmp(entry->ifr_name, "loop", 4) != 0) {
            ifreq r;
            std::memset(&r, 0, sizeof(r));
            std::snprintf(r.ifr_name, IF_NAMESIZE, "%s", entry->ifr_name);
            if (::ioctl(fd, SIOCGIFSTATS, &r, sizeof(r)) == 0) {
                s.net_rx_bytes += r.ifr_stats.receive.bytes;
                s.net_tx_bytes += r.ifr_stats.send.bytes;
            }
        }
        p += step;
    }
    ::close(fd);
}
#endif  // __HAIKU__

}  // namespace

Sample collect() {
    Sample s;
    s.wall_us = util::now_epoch_ms() * 1000;

#ifdef __HAIKU__
    system_info si;
    if (get_system_info(&si) != B_OK) return s;  // valid stays false

    s.cpu_count = si.cpu_count;
    // active_time is per-CPU usec of useful work since boot; summing gives total
    // busy-CPU-microseconds, the numerator of a true multi-core utilisation.
    if (si.cpu_count > 0) {
        std::vector<cpu_info> cpus(si.cpu_count);
        if (get_cpu_info(0, si.cpu_count, cpus.data()) == B_OK) {
            for (uint32_t i = 0; i < si.cpu_count; i++)
                s.cpu_active_us += static_cast<uint64_t>(cpus[i].active_time);
        }
    }

    const uint64_t page = B_PAGE_SIZE;
    s.mem_total = si.max_pages * page;
    s.mem_used = si.used_pages * page;
    s.mem_cached = si.cached_pages * page;
    s.thread_count = si.used_threads;

    collect_net(s);

    const char* volume = "/boot";
#else
    // Host build (unit tests): populate what is portable so build_put_body has
    // something to serialize; CPU/mem come out as zero, which is fine for tests.
    const char* volume = "/";
#endif

    struct statvfs vfs;
    if (statvfs(volume, &vfs) == 0) {
        const uint64_t frsize = vfs.f_frsize ? vfs.f_frsize : vfs.f_bsize;
        s.disk_total = static_cast<uint64_t>(vfs.f_blocks) * frsize;
        const uint64_t avail = static_cast<uint64_t>(vfs.f_bavail) * frsize;
        s.disk_used = s.disk_total > avail ? s.disk_total - avail : 0;
    }

    s.valid = true;
    return s;
}

double cpu_percent(const Sample& prev, const Sample& cur) {
    if (!prev.before(cur) || cur.cpu_count == 0) return -1;
    if (cur.cpu_active_us < prev.cpu_active_us) return -1;  // counter reset (reboot)
    const double busy_us = static_cast<double>(cur.cpu_active_us - prev.cpu_active_us);
    const double wall_us = static_cast<double>(cur.wall_us - prev.wall_us);
    if (wall_us <= 0) return -1;
    double pct = 100.0 * busy_us / (wall_us * cur.cpu_count);
    if (pct < 0) pct = 0;
    if (pct > 100) pct = 100;
    return pct;
}

std::string build_put_body(const std::string& ns, const std::string& instance_id,
                           const Sample& prev, const Sample& cur) {
    std::vector<Metric> m;

    const double cpu = cpu_percent(prev, cur);
    if (cpu >= 0) m.push_back({"CPUUtilization", fmt_pct(cpu), "Percent"});

    if (cur.mem_total > 0) {
        m.push_back({"MemoryUtilization",
                     fmt_pct(100.0 * static_cast<double>(cur.mem_used) / cur.mem_total),
                     "Percent"});
        m.push_back({"MemoryUsedBytes", fmt_u64(cur.mem_used), "Bytes"});
        m.push_back({"MemoryAvailableBytes",
                     fmt_u64(cur.mem_total > cur.mem_used ? cur.mem_total - cur.mem_used : 0),
                     "Bytes"});
    }

    if (cur.disk_total > 0) {
        m.push_back({"DiskUtilization",
                     fmt_pct(100.0 * static_cast<double>(cur.disk_used) / cur.disk_total),
                     "Percent"});
        m.push_back({"DiskUsedBytes", fmt_u64(cur.disk_used), "Bytes"});
    }

    // Network is a monotonic byte counter; report the bytes moved this interval.
    // Skipped on the first cycle and across a counter reset (reboot).
    if (prev.before(cur) && cur.net_rx_bytes >= prev.net_rx_bytes &&
        cur.net_tx_bytes >= prev.net_tx_bytes) {
        m.push_back({"NetworkInBytes", fmt_u64(cur.net_rx_bytes - prev.net_rx_bytes), "Bytes"});
        m.push_back({"NetworkOutBytes", fmt_u64(cur.net_tx_bytes - prev.net_tx_bytes), "Bytes"});
    }

    if (cur.thread_count > 0)
        m.push_back({"ThreadCount", fmt_u64(cur.thread_count), "Count"});

    std::string body = "Action=PutMetricData&Version=2010-08-01&Namespace=" +
                       util::uri_encode(ns, true);
    for (size_t i = 0; i < m.size(); i++) {
        const std::string idx = std::to_string(i + 1);
        const std::string p = "&MetricData.member." + idx + ".";
        body += p + "MetricName=" + util::uri_encode(m[i].name, true);
        body += p + "Value=" + m[i].value;
        body += p + "Unit=" + m[i].unit;
        body += p + "Dimensions.member.1.Name=InstanceId";
        body += p + "Dimensions.member.1.Value=" + util::uri_encode(instance_id, true);
    }
    return body;
}

bool emit(aws::CredentialProvider& creds, const std::string& region, const std::string& ns,
          const std::string& instance_id, Sample& prev) {
    Sample cur = collect();
    if (!cur.valid) {
        logging::warn("metrics: get_system_info failed; skipping cycle");
        return false;
    }

    const std::string body = build_put_body(ns, instance_id, prev, cur);
    prev = cur;  // advance state even if the PUT fails, so the next delta is sane

    aws::Credentials c;
    if (!creds.get(c)) {
        logging::warn("metrics: no credentials; skipping cycle");
        return false;
    }

    http::Response r = aws::put_metric_data(region, c, body);
    if (!r.ok()) {
        if ((r.status == 400 || r.status == 403) &&
            (r.body.find("ExpiredToken") != std::string::npos ||
             r.body.find("InvalidSignature") != std::string::npos)) {
            creds.invalidate();
        }
        logging::logf(logging::Warn, "metrics: PutMetricData failed: status=%d error=%s %s",
                      r.status, r.error.c_str(), util::clip(r.body, 300, "...").c_str());
        return false;
    }
    logging::logf(logging::Debug, "metrics: published to %s for %s", ns.c_str(),
                  instance_id.c_str());
    return true;
}

}  // namespace metrics
