// util.h -- crypto primitives, time formatting, ids, string helpers.
//
// Crypto is mbedTLS-backed (statically linked): haiku/arm64 has no OpenSSL,
// which is the whole reason this agent exists in this shape. See NOTES.md 1.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace util {

// ---- crypto (mbedTLS) ----
std::string sha256_hex(const std::string& data);
// Streaming digest of a file, for artifacts too big to slurp (self-update
// binaries, S3 uploads). Returns "" when the file cannot be read.
std::string sha256_file_hex(const std::string& path);
std::string hmac_sha256(const std::string& key, const std::string& data);  // raw bytes out
std::string to_hex(const std::string& raw);

// ---- time ----
// x-amz-date: yyyyMMddTHHmmssZ
std::string amz_date(int64_t epoch);
// credential scope datestamp: yyyyMMdd
std::string amz_datestamp(int64_t epoch);
// SSM reply timestamps: yyyy-MM-ddTHH:mm:ss.fffZ  (agent/times/times.go ToIso8601UTC)
std::string iso8601(int64_t epoch_ms);
// SSM RunID: yyyy-MM-ddTHH-mm-ss.fffZ            (agent/times/times.go ToIsoDashUTC)
std::string iso_dash(int64_t epoch_ms);
// Inventory CaptureTime: yyyy-MM-ddTHH:mm:ssZ -- PutInventory rejects
// fractional seconds, unlike the SSM reply timestamps above.
std::string iso8601_seconds(int64_t epoch);

int64_t now_epoch();
int64_t now_epoch_ms();
// Parses yyyy-MM-ddTHH:mm:ssZ (IMDS credential Expiration). Returns 0 on failure.
int64_t parse_iso8601(const std::string& s);
// Parses an RFC 1123 HTTP Date header ("Fri, 21 Aug 2026 01:08:55 GMT").
// Returns 0 on failure. Used to bootstrap the clock: Haiku on EC2 boots at
// epoch 0 and has no NTP client (TESTING.md).
int64_t parse_http_date(const std::string& s);

// ---- ids ----
std::string uuid4();

// ---- strings ----
std::string trim(const std::string& s);
bool starts_with(const std::string& s, const std::string& prefix);
std::vector<std::string> split(const std::string& s, char sep);
std::string join(const std::vector<std::string>& parts, const std::string& sep);
std::string lower(std::string s);

// Truncate to `max` bytes, appending `suffix` when it had to cut.
std::string clip(const std::string& s, size_t max, const std::string& suffix = "");

// SigV4 canonical URI encoding (RFC 3986 unreserved set). `encode_slash`
// distinguishes path segments (false: '/' kept) from query values (true).
std::string uri_encode(const std::string& s, bool encode_slash);

// Compares dotted numeric versions ("0.1.0" < "0.2.0" < "0.10.0"). Non-numeric
// tails compare as 0, so a malformed manifest can never look "newer".
int version_compare(const std::string& a, const std::string& b);

}  // namespace util
