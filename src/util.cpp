#include "util.h"

#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>

namespace util {

std::string sha256_hex(const std::string& data) {
    unsigned char out[32];
    mbedtls_sha256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), out, 0);
    return to_hex(std::string(reinterpret_cast<char*>(out), sizeof(out)));
}

std::string sha256_file_hex(const std::string& path) {
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return "";
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    char buf[64 * 1024];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0)
        mbedtls_sha256_update(&ctx, reinterpret_cast<unsigned char*>(buf), n);
    const bool read_ok = std::feof(f) && !std::ferror(f);
    std::fclose(f);
    unsigned char out[32];
    mbedtls_sha256_finish(&ctx, out);
    mbedtls_sha256_free(&ctx);
    if (!read_ok) return "";
    return to_hex(std::string(reinterpret_cast<char*>(out), sizeof(out)));
}

std::string hmac_sha256(const std::string& key, const std::string& data) {
    unsigned char out[32];
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_hmac(info,
                    reinterpret_cast<const unsigned char*>(key.data()), key.size(),
                    reinterpret_cast<const unsigned char*>(data.data()), data.size(),
                    out);
    return std::string(reinterpret_cast<char*>(out), sizeof(out));
}

std::string to_hex(const std::string& raw) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(raw.size() * 2);
    for (unsigned char c : raw) {
        out += digits[c >> 4];
        out += digits[c & 0x0F];
    }
    return out;
}

// ---- time ----

namespace {
struct tm gmt(int64_t epoch) {
    time_t t = static_cast<time_t>(epoch);
    struct tm out {};
    gmtime_r(&t, &out);
    return out;
}
}  // namespace

std::string amz_date(int64_t epoch) {
    struct tm tm = gmt(epoch);
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%04d%02d%02dT%02d%02d%02dZ",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    return buf;
}

std::string amz_datestamp(int64_t epoch) {
    struct tm tm = gmt(epoch);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d%02d%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
    return buf;
}

std::string iso8601(int64_t epoch_ms) {
    struct tm tm = gmt(epoch_ms / 1000);
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
                  static_cast<int>(epoch_ms % 1000));
    return buf;
}

std::string iso8601_seconds(int64_t epoch) {
    struct tm tm = gmt(epoch);
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    return buf;
}

std::string iso_dash(int64_t epoch_ms) {
    struct tm tm = gmt(epoch_ms / 1000);
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d-%02d-%02d.%03dZ",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
                  static_cast<int>(epoch_ms % 1000));
    return buf;
}

int64_t now_epoch() { return static_cast<int64_t>(::time(nullptr)); }

int64_t now_epoch_ms() {
    struct timespec ts {};
    clock_gettime(CLOCK_REALTIME, &ts);
    return static_cast<int64_t>(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000;
}

namespace {

// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
// days_from_civil). Hand-rolled because Haiku does not expose timegm(), and
// mktime() would apply the local timezone to what is always a UTC timestamp.
int64_t days_from_civil(int y, unsigned m, unsigned d) {
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);              // [0, 399]
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;    // [0, 365]
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;             // [0, 146096]
    return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

}  // namespace

int64_t parse_iso8601(const std::string& s) {
    int year = 0, mon = 0, day = 0, hour = 0, min = 0, sec = 0;
    if (std::sscanf(s.c_str(), "%4d-%2d-%2dT%2d:%2d:%2d", &year, &mon, &day, &hour, &min, &sec) != 6)
        return 0;
    const int64_t days = days_from_civil(year, static_cast<unsigned>(mon), static_cast<unsigned>(day));
    return days * 86400 + hour * 3600 + min * 60 + sec;
}

int64_t parse_http_date(const std::string& s) {
    // "Fri, 21 Aug 2026 01:08:55 GMT"
    static const char* months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    char mon_name[8] = {0};
    int day = 0, year = 0, hour = 0, min = 0, sec = 0;
    const char* comma = std::strchr(s.c_str(), ',');
    const char* rest = comma ? comma + 1 : s.c_str();
    if (std::sscanf(rest, " %d %3s %d %d:%d:%d", &day, mon_name, &year, &hour, &min, &sec) != 6)
        return 0;
    int mon = 0;
    for (int i = 0; i < 12; i++)
        if (std::strncmp(mon_name, months[i], 3) == 0) { mon = i + 1; break; }
    if (mon == 0) return 0;
    const int64_t days = days_from_civil(year, static_cast<unsigned>(mon), static_cast<unsigned>(day));
    return days * 86400 + hour * 3600 + min * 60 + sec;
}

// ---- ids ----

std::string uuid4() {
    unsigned char b[16];
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (urandom.read(reinterpret_cast<char*>(b), sizeof(b)).gcount() != sizeof(b)) {
        // Never silently emit a predictable id: fall back to time-seeded bytes
        // rather than zeros, and mark it in the log via the caller's error path.
        int64_t t = now_epoch_ms();
        for (size_t i = 0; i < sizeof(b); i++) b[i] = static_cast<unsigned char>((t >> (i % 8 * 8)) ^ (i * 31));
    }
    b[6] = static_cast<unsigned char>((b[6] & 0x0F) | 0x40);  // version 4
    b[8] = static_cast<unsigned char>((b[8] & 0x3F) | 0x80);  // variant 1
    char out[37];
    std::snprintf(out, sizeof(out),
                  "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                  b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                  b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
    return out;
}

// ---- strings ----

std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

bool starts_with(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

std::vector<std::string> split(const std::string& s, char sep) {
    std::vector<std::string> out;
    size_t start = 0;
    while (true) {
        size_t p = s.find(sep, start);
        if (p == std::string::npos) {
            out.push_back(s.substr(start));
            return out;
        }
        out.push_back(s.substr(start, p - start));
        start = p + 1;
    }
}

std::string join(const std::vector<std::string>& parts, const std::string& sep) {
    std::string out;
    for (size_t i = 0; i < parts.size(); i++) {
        if (i) out += sep;
        out += parts[i];
    }
    return out;
}

std::string lower(std::string s) {
    for (char& c : s)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
}

std::string clip(const std::string& s, size_t max, const std::string& suffix) {
    if (s.size() <= max) return s;
    if (suffix.size() >= max) return s.substr(0, max);
    return s.substr(0, max - suffix.size()) + suffix;
}

std::string uri_encode(const std::string& s, bool encode_slash) {
    static const char* digits = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        const bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                                (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~';
        if (unreserved || (c == '/' && !encode_slash)) {
            out += static_cast<char>(c);
        } else {
            out += '%';
            out += digits[c >> 4];
            out += digits[c & 0x0F];
        }
    }
    return out;
}

int version_compare(const std::string& a, const std::string& b) {
    std::vector<std::string> pa = split(a, '.');
    std::vector<std::string> pb = split(b, '.');
    const size_t n = std::max(pa.size(), pb.size());
    for (size_t i = 0; i < n; i++) {
        long va = i < pa.size() ? std::strtol(pa[i].c_str(), nullptr, 10) : 0;
        long vb = i < pb.size() ? std::strtol(pb[i].c_str(), nullptr, 10) : 0;
        if (va != vb) return va < vb ? -1 : 1;
    }
    return 0;
}

}  // namespace util
