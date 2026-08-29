// runner.h -- parse an SSM document, run its steps, build the MDS reply payload.
//
// Scope is one plugin: aws:runShellScript. Anything else is reported as a
// terminal Failed with an explicit "unsupported on Haiku" message -- never
// silently skipped, which matters because DHMC pushes association documents
// (inventory) at instances whether or not they can run them.
#pragma once

#include <string>
#include <vector>

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
    std::string status;      // Success | Failed | TimedOut
    int code = 0;
    std::string output;          // combined, clipped to 2500 (MaximumPluginOutputSize)
    std::string standard_output;  // clipped to 24000 (MaxStdoutLength)
    std::string standard_error;
    std::string start_time;
    std::string end_time;

    // S3 command output (filled when the step's inputs set outputS3BucketName).
    // full_* hold the un-clipped capture (bounded, see kMaxS3CaptureBytes) so the
    // caller can upload the complete log; the inline standard_* stay clipped.
    std::string full_stdout;
    std::string full_stderr;
    std::string s3_bucket;      // OutputS3BucketName, empty => no S3 upload
    std::string s3_key_prefix;  // reported in the reply; the uploader sets the
                                // full per-step prefix once the objects are PUT.
};

struct DocumentOutcome {
    std::string status;  // Success | Failed
    std::vector<StepResult> steps;
    std::string trace;   // documentTraceOutput: parse errors etc.
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
DocumentOutcome run_document(const json::Value& document_content, const json::Value& parameters);

// Builds a SendReplyPayload (agent/runcommand/contracts/model.go:42).
// `plugin_id` empty => document-level reply (used for the InProgress ping).
std::string reply_payload(const AgentInfo& agent, const std::string& document_status,
                          const std::string& trace, const std::vector<StepResult>& steps);

}  // namespace runner
