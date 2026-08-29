// runner.h -- parse an SSM document, run its steps, build the MDS reply payload.
//
// Scope is one plugin: aws:runShellScript. Anything else is reported as a
// terminal Failed with an explicit "unsupported on Haiku" message -- never
// silently skipped, which matters because DHMC pushes association documents
// (inventory) at instances whether or not they can run them.
#pragma once

#include <string>
#include <vector>

#include "exec.h"
#include "json.h"

namespace runner {

struct AgentInfo {
    std::string name;
    std::string version;
    std::string lang = "en-US";
    std::string os;       // "Haiku"
    std::string os_ver;   // hrev.....
};

struct StepResult {
    std::string plugin_id;   // key in runtimeStatus
    std::string action;      // e.g. aws:runShellScript
    std::string status;      // Success | Failed | TimedOut | Cancelled
    int code = 0;
    std::string output;          // combined, clipped to 2500 (MaximumPluginOutputSize)
    std::string standard_output;  // clipped to 24000 (MaxStdoutLength)
    std::string standard_error;
    // Unclipped capture (bounded by Options::max_capture), kept so the caller
    // can honor OutputS3BucketName with the *full* log, not the inline clip.
    std::string full_stdout;
    std::string full_stderr;
    // Set by the caller after a successful S3 upload; echoed in the reply so
    // the console links to the objects.
    std::string output_s3_bucket;
    std::string output_s3_key_prefix;
    std::string start_time;
    std::string end_time;
};

struct DocumentOutcome {
    std::string status;  // Success | Failed | Cancelled
    std::vector<StepResult> steps;
    std::string trace;   // documentTraceOutput: parse errors etc.
};

struct Options {
    // How much stdout/stderr to keep per stream. The inline reply always clips
    // to the SSM limits; raise this only when the full text has somewhere to
    // go (S3 output), so a 25-minute build log survives.
    size_t max_capture = 24000;
    // Non-null => a CancelCommand can kill the running step's process group.
    exec::Cancel* cancel = nullptr;
};

// Combined output exactly as the Go agent's iohandler.TruncateOutput does, so
// console output looks the same (agent/framework/.../iohandler.go:433).
std::string truncate_output(const std::string& stdout_data, const std::string& stderr_data,
                            size_t capacity);

// Substitutes {{ name }} placeholders using SendCommandPayload.Parameters, with
// document-level defaults as fallback.
json::Value resolve(const json::Value& node, const json::Value& parameters,
                    const json::Value& doc_parameters);

// Executes every step of the document. Never throws.
DocumentOutcome run_document(const json::Value& document_content, const json::Value& parameters,
                             const Options& options = Options());

// Builds a SendReplyPayload (agent/runcommand/contracts/model.go:42).
// `plugin_id` empty => document-level reply (used for the InProgress ping).
std::string reply_payload(const AgentInfo& agent, const std::string& document_status,
                          const std::string& trace, const std::vector<StepResult>& steps);

}  // namespace runner
