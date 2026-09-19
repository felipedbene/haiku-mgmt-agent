#include "cwlogs.h"

#include <sys/stat.h>

#include <cstdio>
#include <cstring>
#include <vector>

#include "http.h"
#include "log.h"
#include "util.h"

namespace cwlogs {
namespace {

// Bound the memory a single cycle can pull off a large/backlogged file; the
// remainder is picked up next cycle. Complete lines only cross the wire, so a
// line split at this boundary is stitched back via State::partial.
constexpr size_t kMaxReadPerCycle = 4 * 1024 * 1024;

bool body_has(const http::Response& r, const char* needle) {
    return r.body.find(needle) != std::string::npos;
}

// An expired/rejected signature should drop the credential cache so the next
// cycle re-fetches from IMDS -- same pattern as metrics::emit.
void maybe_invalidate(aws::CredentialProvider& creds, const http::Response& r) {
    if ((r.status == 400 || r.status == 403) &&
        (body_has(r, "ExpiredToken") || body_has(r, "InvalidSignature") ||
         body_has(r, "UnrecognizedClient"))) {
        creds.invalidate();
    }
}

std::string parse_str_field(const std::string& body, const char* field) {
    std::string err;
    json::Value v = json::parse(body, &err);
    if (!err.empty()) return "";
    return v.str_at(field);
}

}  // namespace

void split_lines(const std::string& data, std::string& partial,
                 std::vector<std::string>& lines) {
    std::string buf;
    buf.swap(partial);
    buf += data;
    size_t pos = 0;
    while (true) {
        size_t nl = buf.find('\n', pos);
        if (nl == std::string::npos) {
            partial = buf.substr(pos);
            break;
        }
        std::string line = buf.substr(pos, nl - pos);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) lines.push_back(line);  // CW rejects an empty event
        pos = nl + 1;
    }
}

json::Value build_events(const std::vector<std::string>& lines, size_t start,
                         int64_t ts_ms, size_t max_events, size_t max_bytes,
                         size_t max_line_bytes, size_t& consumed) {
    json::Value events = json::arr();
    consumed = 0;
    size_t bytes = 0;
    for (size_t i = start; i < lines.size(); i++) {
        if (events.array.size() >= max_events) break;
        std::string msg = lines[i];
        if (msg.size() > max_line_bytes) msg = util::clip(msg, max_line_bytes, "...[clipped]");
        // The API bills 26 bytes of overhead per event against the 1 MiB batch.
        const size_t cost = msg.size() + 26;
        if (!events.array.empty() && bytes + cost > max_bytes) break;
        json::Value ev = json::obj();
        ev.object["timestamp"] = json::num(static_cast<double>(ts_ms));
        ev.object["message"] = json::str(msg);
        events.array.push_back(ev);
        bytes += cost;
        consumed++;
    }
    return events;
}

bool ensure_stream(aws::CredentialProvider& creds, const std::string& region,
                   const Options& opt, State& st) {
    aws::Credentials c;
    if (!creds.get(c)) {
        logging::warn("cwlogs: no credentials; deferring log-group setup");
        return false;
    }

    http::Response g = aws::create_log_group(region, c, opt.group);
    if (!g.ok() && !body_has(g, "ResourceAlreadyExists")) {
        maybe_invalidate(creds, g);
        logging::logf(logging::Warn, "cwlogs: CreateLogGroup %s failed: status=%d %s",
                      opt.group.c_str(), g.status, util::clip(g.body, 200, "...").c_str());
        return false;
    }

    http::Response s = aws::create_log_stream(region, c, opt.group, opt.stream);
    if (!s.ok() && !body_has(s, "ResourceAlreadyExists")) {
        maybe_invalidate(creds, s);
        logging::logf(logging::Warn, "cwlogs: CreateLogStream %s/%s failed: status=%d %s",
                      opt.group.c_str(), opt.stream.c_str(), s.status,
                      util::clip(s.body, 200, "...").c_str());
        return false;
    }

    // Seed the sequence token from the existing stream (empty for a fresh one).
    http::Response d = aws::describe_log_streams(region, c, opt.group, opt.stream);
    if (d.ok()) {
        std::string err;
        json::Value v = json::parse(d.body, &err);
        const json::Value* streams = v.find("logStreams");
        if (streams && streams->is_arr() && !streams->array.empty()) {
            st.sequence_token = streams->array.front().str_at("uploadSequenceToken");
        }
    }

    st.stream_ready = true;
    logging::logf(logging::Info, "cwlogs: streaming %s -> %s/%s (region %s)",
                  opt.source_path.c_str(), opt.group.c_str(), opt.stream.c_str(),
                  region.c_str());
    return true;
}

bool emit(aws::CredentialProvider& creds, const std::string& region,
          const Options& opt, State& st) {
    if (!st.stream_ready && !ensure_stream(creds, region, opt, st)) return false;

    struct stat sb;
    if (::stat(opt.source_path.c_str(), &sb) != 0) {
        // The syslog may not exist yet on a fresh boot; that is not an error.
        logging::logf(logging::Debug, "cwlogs: source %s not present yet",
                      opt.source_path.c_str());
        return true;
    }
    const uint64_t size = static_cast<uint64_t>(sb.st_size);

    // Rotation/truncation: the file shrank, so our offset points past the end.
    if (size < static_cast<uint64_t>(st.offset) || size < st.last_size) {
        st.offset = 0;
        st.partial.clear();
    }
    st.last_size = size;
    if (static_cast<uint64_t>(st.offset) >= size) return true;  // nothing new

    FILE* f = std::fopen(opt.source_path.c_str(), "rb");
    if (!f) {
        logging::logf(logging::Warn, "cwlogs: cannot open %s", opt.source_path.c_str());
        return false;
    }
    if (::fseeko(f, st.offset, SEEK_SET) != 0) {
        std::fclose(f);
        logging::warn("cwlogs: seek failed; resetting offset");
        st.offset = 0;
        return false;
    }
    size_t want = size - static_cast<uint64_t>(st.offset);
    if (want > kMaxReadPerCycle) want = kMaxReadPerCycle;
    std::string chunk(want, '\0');
    size_t got = std::fread(&chunk[0], 1, want, f);
    std::fclose(f);
    chunk.resize(got);
    st.offset += static_cast<off_t>(got);

    std::vector<std::string> lines;
    split_lines(chunk, st.partial, lines);
    if (lines.empty()) return true;

    const int64_t ts = util::now_epoch_ms();
    size_t idx = 0;
    while (idx < lines.size()) {
        size_t consumed = 0;
        json::Value events = build_events(lines, idx, ts, opt.max_batch_events,
                                          opt.max_batch_bytes, opt.max_line_bytes, consumed);
        if (consumed == 0) break;  // defensive: always make progress

        bool batch_done = false;
        for (int attempt = 0; attempt < 2 && !batch_done; attempt++) {
            aws::Credentials c;
            if (!creds.get(c)) {
                logging::warn("cwlogs: no credentials mid-batch; retry next cycle");
                return false;
            }
            http::Response r = aws::put_log_events(region, c, opt.group, opt.stream,
                                                   events, st.sequence_token);
            if (r.ok()) {
                std::string next = parse_str_field(r.body, "nextSequenceToken");
                if (!next.empty()) st.sequence_token = next;
                idx += consumed;
                batch_done = true;
                break;
            }
            // The stream already had these exact events (a retried batch): they
            // are durably stored, so advance and take the corrected token.
            if (body_has(r, "DataAlreadyAcceptedException")) {
                std::string exp = parse_str_field(r.body, "expectedSequenceToken");
                if (!exp.empty()) st.sequence_token = exp;
                idx += consumed;
                batch_done = true;
                break;
            }
            // Stale token: adopt the expected one and retry the same batch once.
            if (body_has(r, "InvalidSequenceTokenException")) {
                std::string exp = parse_str_field(r.body, "expectedSequenceToken");
                st.sequence_token = exp;  // may be "" (fresh stream)
                continue;
            }
            // Group/stream vanished (deleted out from under us): re-create it.
            if (body_has(r, "ResourceNotFoundException")) {
                st.stream_ready = false;
                logging::warn("cwlogs: log group/stream missing; will re-create");
                return false;
            }
            maybe_invalidate(creds, r);
            logging::logf(logging::Warn, "cwlogs: PutLogEvents failed: status=%d error=%s %s",
                          r.status, r.error.c_str(), util::clip(r.body, 300, "...").c_str());
            return false;
        }
        if (!batch_done) {
            logging::warn("cwlogs: PutLogEvents still rejected after token refresh");
            return false;
        }
    }

    logging::logf(logging::Debug, "cwlogs: shipped %zu line(s) to %s/%s", lines.size(),
                  opt.group.c_str(), opt.stream.c_str());
    return true;
}

}  // namespace cwlogs
