// cwlogs.h -- tail a log file into CloudWatch Logs (F7/#119, the logs half).
//
// The metrics half of #119 answers "how busy is the box"; this answers "what is
// it saying". It tails a file (the DeBeOS syslog by default), batches new
// lines, and ships them with PutLogEvents to a log group/stream, creating both
// on first use and carrying the upload sequence-token across cycles.
//
// It is deliberately a peer of metrics::emit, not a rewrite: it reuses the same
// CredentialProvider, region, SigV4/TLS/HTTP core and JSON serializer, and runs
// on the same single-threaded poll loop, so it can never race the PutMetricData
// call and -- like the metrics daemon -- makes no SSM calls, so it never
// contends with the amazon-ssm-agent's node registration / Run Command channel.
#pragma once

#include <sys/types.h>

#include <cstdint>
#include <string>
#include <vector>

#include "aws.h"
#include "json.h"

namespace cwlogs {

struct Options {
    std::string source_path;   // file to tail (e.g. /var/log/syslog)
    std::string group;         // log group name
    std::string stream;        // log stream name (default: instance id)
    // PutLogEvents hard limits are 10000 events / 1 MiB per call; stay well
    // under both. A cycle that reads more than one batch worth ships several.
    size_t max_batch_events = 1000;
    size_t max_batch_bytes = 900 * 1024;
    size_t max_line_bytes = 8192;  // clip a pathologically long line
};

// Tailer + handshake state, carried across emit() calls by the poll loop.
struct State {
    off_t offset = 0;            // bytes already consumed from source_path
    uint64_t last_size = 0;      // last observed file size (detects truncation)
    std::string partial;         // trailing bytes with no newline yet
    std::string sequence_token;  // nextSequenceToken from the last PutLogEvents
    bool stream_ready = false;   // group+stream ensured (+token seeded) this run
};

// Ensure the log group and stream exist and seed the sequence token from
// DescribeLogStreams. Idempotent: ResourceAlreadyExists is treated as success.
// Returns false only on a hard failure (no creds, network, AccessDenied) so the
// caller can retry next cycle. Sets st.stream_ready on success.
bool ensure_stream(aws::CredentialProvider& creds, const std::string& region,
                   const Options& opt, State& st);

// One tail+PutLogEvents cycle. Reads new complete lines from opt.source_path
// (holding an incomplete trailing line in st.partial), ships them in batches,
// and advances st.offset/st.sequence_token. Returns true when everything read
// was accepted (or there was nothing new); false on a shippable-but-failed
// batch (state is left so the next cycle retries from the same point).
bool emit(aws::CredentialProvider& creds, const std::string& region,
          const Options& opt, State& st);

// ---- pure helpers, exposed for unit testing ----

// Split `data` into complete lines. A trailing fragment with no '\n' is left in
// `partial` (and prepended on the next call). Empty lines are dropped -- an
// empty CloudWatch log event is rejected.
void split_lines(const std::string& data, std::string& partial,
                 std::vector<std::string>& lines);

// Build a PutLogEvents `logEvents` array from lines[start..], stamping each with
// `ts_ms`, honoring the event-count and byte budget (26 bytes overhead/event,
// per the API). `consumed` returns how many lines went into this batch (>=1 as
// long as lines remain, so a single oversized line still makes progress after
// being clipped to `max_line_bytes`).
json::Value build_events(const std::vector<std::string>& lines, size_t start,
                         int64_t ts_ms, size_t max_events, size_t max_bytes,
                         size_t max_line_bytes, size_t& consumed);

}  // namespace cwlogs
