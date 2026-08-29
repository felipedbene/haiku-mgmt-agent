#include "runner.h"

#include <algorithm>
#include <functional>
#include <map>

#include "exec.h"
#include "log.h"
#include "util.h"

namespace runner {
namespace {

constexpr size_t kMaxPluginOutputSize = 2500;   // iohandler.go:33
constexpr size_t kMaxStdoutLength = 24000;      // appconfig/constants.go:241
// When a command requests S3 output we capture far more than the inline cap so
// the uploaded log is complete. Bounded (in-memory) rather than streamed: a v0.2
// simplification -- 5 MiB covers a long build log; larger output is truncated
// with the usual marker and noted.
constexpr size_t kMaxS3CaptureBytes = 5 * 1024 * 1024;
constexpr const char* kErrTitle = "\n----------ERROR-------\n";
constexpr const char* kTruncateOut = "\n---Output truncated---";
constexpr const char* kTruncateError = "\n---Error truncated----";
constexpr const char* kRunShellScript = "aws:runShellScript";

// Replace every "{{ key }}" occurrence in a scalar string.
std::string substitute_scalar(const std::string& in, const std::map<std::string, json::Value>& params) {
    std::string out;
    size_t i = 0;
    while (i < in.size()) {
        size_t open = in.find("{{", i);
        if (open == std::string::npos) {
            out.append(in, i, std::string::npos);
            break;
        }
        size_t close = in.find("}}", open);
        if (close == std::string::npos) {
            out.append(in, i, std::string::npos);
            break;
        }
        out.append(in, i, open - i);
        std::string key = util::trim(in.substr(open + 2, close - open - 2));
        auto it = params.find(key);
        if (it == params.end()) {
            // Leave unknown placeholders verbatim: better a visibly unresolved
            // command than a silently mangled one.
            out.append(in, open, close + 2 - open);
        } else if (it->second.is_arr()) {
            std::vector<std::string> parts;
            for (const auto& e : it->second.array) parts.push_back(e.str());
            out += util::join(parts, "\n");
        } else {
            out += it->second.str(it->second.type == json::Value::Number
                                      ? json::dump(it->second)
                                      : "");
        }
        i = close + 2;
    }
    return out;
}

// Flatten document parameters + defaults into one lookup table.
std::map<std::string, json::Value> parameter_table(const json::Value& parameters,
                                                   const json::Value& doc_parameters) {
    std::map<std::string, json::Value> table;
    if (doc_parameters.is_obj()) {
        for (const auto& kv : doc_parameters.object) {
            const json::Value* def = kv.second.find("default");
            if (def) table[kv.first] = *def;
        }
    }
    if (parameters.is_obj())
        for (const auto& kv : parameters.object) table[kv.first] = kv.second;
    return table;
}

// Collect the shell commands from a step's inputs.
std::vector<std::string> command_lines(const json::Value& inputs) {
    std::vector<std::string> lines;
    const json::Value* rc = inputs.find("runCommand");
    if (!rc) return lines;
    if (rc->is_arr()) {
        for (const auto& e : rc->array) lines.push_back(e.str());
    } else if (rc->is_str()) {
        lines.push_back(rc->string);
    }
    return lines;
}

StepResult unsupported(const std::string& plugin_id, const std::string& action,
                       const std::string& start_time) {
    StepResult sr;
    sr.plugin_id = plugin_id;
    sr.action = action;
    sr.status = "Failed";
    sr.code = 1;
    sr.standard_error =
        "plugin '" + action + "' is not supported on Haiku. haiku-mgmt-agent implements " +
        std::string(kRunShellScript) +
        " only (see BRIEF.md section 2: Session Manager, inventory and self-update are out of scope).";
    sr.output = sr.standard_error;
    sr.start_time = start_time;
    sr.end_time = util::iso8601(util::now_epoch_ms());
    logging::logf(logging::Warn, "unsupported plugin reported as Failed: %s", action.c_str());
    return sr;
}

}  // namespace

std::string truncate_output(const std::string& stdout_data, const std::string& stderr_data,
                            size_t capacity) {
    const size_t out_size = stdout_data.size();
    const size_t err_size = stderr_data.size();
    const std::string err_title = err_size > 0 ? kErrTitle : "";
    const size_t available = capacity > err_title.size() ? capacity - err_title.size() : 0;

    if (out_size + err_size < available) return stdout_data + err_title + stderr_data;

    const size_t half = available / 2;
    if (out_size > half && err_size > half) {
        size_t truncate_size = available - std::string(kTruncateError).size() -
                               std::string(kTruncateOut).size();
        return stdout_data.substr(0, truncate_size / 2) + kTruncateOut + err_title +
               stderr_data.substr(0, truncate_size / 2) + kTruncateError;
    }
    if (out_size <= half) {
        size_t truncate_size = available - std::string(kTruncateError).size();
        size_t keep = truncate_size > out_size ? truncate_size - out_size : 0;
        return stdout_data + err_title + stderr_data.substr(0, std::min(keep, err_size)) + kTruncateError;
    }
    size_t truncate_size = available - std::string(kTruncateOut).size();
    size_t keep = truncate_size > err_size ? truncate_size - err_size : 0;
    return stdout_data.substr(0, std::min(keep, out_size)) + kTruncateOut + err_title + stderr_data;
}

json::Value resolve(const json::Value& node, const json::Value& parameters,
                    const json::Value& doc_parameters) {
    std::map<std::string, json::Value> table = parameter_table(parameters, doc_parameters);

    // Recursive walk; a string that is *exactly* one placeholder naming a list
    // expands to that list (how "runCommand": "{{ commands }}" works).
    std::function<json::Value(const json::Value&)> walk = [&](const json::Value& v) -> json::Value {
        switch (v.type) {
            case json::Value::String: {
                std::string s = util::trim(v.string);
                if (s.size() > 4 && util::starts_with(s, "{{") && s.rfind("}}") == s.size() - 2) {
                    std::string key = util::trim(s.substr(2, s.size() - 4));
                    auto it = table.find(key);
                    if (it != table.end() && it->second.is_arr()) return it->second;
                }
                return json::str(substitute_scalar(v.string, table));
            }
            case json::Value::Arr: {
                json::Value out = json::arr();
                for (const auto& e : v.array) out.array.push_back(walk(e));
                return out;
            }
            case json::Value::Obj: {
                json::Value out = json::obj();
                for (const auto& kv : v.object) out.object[kv.first] = walk(kv.second);
                return out;
            }
            default:
                return v;
        }
    };
    return walk(node);
}

DocumentOutcome run_document(const json::Value& document_content, const json::Value& parameters) {
    DocumentOutcome outcome;
    outcome.status = "Success";

    const json::Value* doc_params = document_content.find("parameters");
    const json::Value empty_params;

    // Build the step list: schemaVersion 2.x uses mainSteps, 1.2 uses runtimeConfig.
    struct Step {
        std::string plugin_id;
        std::string action;
        json::Value inputs;
    };
    std::vector<Step> steps;

    const json::Value* main_steps = document_content.find("mainSteps");
    if (main_steps && main_steps->is_arr()) {
        for (const auto& s : main_steps->array) {
            Step st;
            st.action = s.str_at("action");
            st.plugin_id = s.str_at("name", st.action);
            const json::Value* in = s.find("inputs");
            if (in) st.inputs = *in;
            steps.push_back(st);
        }
    } else if (const json::Value* rc = document_content.find("runtimeConfig")) {
        // schemaVersion 1.2: { "runtimeConfig": { "aws:runShellScript": { "properties": [...] } } }
        if (rc->is_obj()) {
            for (const auto& kv : rc->object) {
                Step st;
                st.action = kv.first;
                st.plugin_id = kv.first;
                const json::Value* props = kv.second.find("properties");
                if (props && props->is_arr() && !props->array.empty())
                    st.inputs = props->array.front();
                else if (props)
                    st.inputs = *props;
                steps.push_back(st);
            }
        }
    }

    if (steps.empty()) {
        outcome.status = "Failed";
        outcome.trace = "document contains no runnable steps (no mainSteps or runtimeConfig)";
        logging::error(outcome.trace);
        return outcome;
    }

    for (const Step& st : steps) {
        const std::string start_time = util::iso8601(util::now_epoch_ms());

        if (st.action != kRunShellScript) {
            outcome.steps.push_back(unsupported(st.plugin_id, st.action, start_time));
            outcome.status = "Failed";
            continue;
        }

        json::Value inputs = resolve(st.inputs, parameters, doc_params ? *doc_params : empty_params);
        std::vector<std::string> lines = command_lines(inputs);
        std::string script = util::join(lines, "\n");

        if (util::trim(script).empty()) {
            StepResult sr;
            sr.plugin_id = st.plugin_id;
            sr.action = st.action;
            sr.status = "Failed";
            sr.code = 1;
            sr.standard_error = "no commands to run (runCommand resolved to empty)";
            sr.output = sr.standard_error;
            sr.start_time = start_time;
            sr.end_time = util::iso8601(util::now_epoch_ms());
            outcome.steps.push_back(sr);
            outcome.status = "Failed";
            continue;
        }

        const int timeout = static_cast<int>(inputs.num_at("timeoutSeconds", 3600));
        const std::string workdir = inputs.str_at("workingDirectory");

        // OutputS3BucketName/KeyPrefix: when the command asks for S3 output, keep
        // the full capture so the uploader (which has the command/instance ids
        // and credentials) can PUT the complete log; the inline reply stays
        // clipped as before.
        const std::string s3_bucket = inputs.str_at("outputS3BucketName");
        const std::string s3_key_prefix = inputs.str_at("outputS3KeyPrefix");
        const size_t capture = s3_bucket.empty() ? kMaxStdoutLength : kMaxS3CaptureBytes;

        logging::logf(logging::Info, "running step %s (%s), timeout=%ds, %zu line(s)",
                      st.plugin_id.c_str(), st.action.c_str(), timeout, lines.size());

        exec::Result er = exec::run_shell(script, timeout, workdir, capture);

        StepResult sr;
        sr.plugin_id = st.plugin_id;
        sr.action = st.action;
        sr.start_time = start_time;
        sr.end_time = util::iso8601(util::now_epoch_ms());
        sr.standard_output = util::clip(er.stdout_data, kMaxStdoutLength);
        sr.standard_error = util::clip(er.stderr_data, kMaxStdoutLength);
        sr.code = er.exit_code;
        if (!s3_bucket.empty()) {
            sr.s3_bucket = s3_bucket;
            sr.s3_key_prefix = s3_key_prefix;  // the uploader extends this to the
                                               // full per-step prefix after PUT.
            sr.full_stdout = er.stdout_data;
            sr.full_stderr = er.stderr_data;
        }

        if (!er.error.empty()) {
            sr.status = "Failed";
            sr.standard_error += (sr.standard_error.empty() ? "" : "\n") + er.error;
            if (sr.code == 0) sr.code = 1;
        } else if (er.timed_out) {
            sr.status = "TimedOut";
            if (sr.code == 0) sr.code = 1;
        } else {
            sr.status = (er.exit_code == 0) ? "Success" : "Failed";
        }

        sr.output = truncate_output(sr.standard_output, sr.standard_error, kMaxPluginOutputSize);
        if (sr.status != "Success") outcome.status = "Failed";
        outcome.steps.push_back(sr);

        logging::logf(logging::Info, "step %s finished: status=%s code=%d stdout=%zuB stderr=%zuB",
                      sr.plugin_id.c_str(), sr.status.c_str(), sr.code, sr.standard_output.size(),
                      sr.standard_error.size());
    }

    return outcome;
}

std::string reply_payload(const AgentInfo& agent, const std::string& document_status,
                          const std::string& trace, const std::vector<StepResult>& steps) {
    const int64_t now_ms = util::now_epoch_ms();

    json::Value agent_obj = json::obj();
    agent_obj.object["lang"] = json::str(agent.lang);
    agent_obj.object["name"] = json::str(agent.name);
    agent_obj.object["os"] = json::str(agent.os);
    agent_obj.object["osver"] = json::str(agent.os_ver);
    agent_obj.object["ver"] = json::str(agent.version);

    json::Value counts = json::obj();
    for (const StepResult& s : steps) {
        auto it = counts.object.find(s.status);
        int prev = (it == counts.object.end()) ? 0 : static_cast<int>(it->second.number);
        counts.object[s.status] = json::num(prev + 1);
    }

    json::Value additional = json::obj();
    additional.object["agent"] = agent_obj;
    additional.object["dateTime"] = json::str(util::iso8601(now_ms));
    additional.object["runId"] = json::str(util::iso_dash(now_ms));
    additional.object["runtimeStatusCounts"] = counts;

    json::Value runtime = json::obj();
    for (const StepResult& s : steps) {
        json::Value st = json::obj();
        st.object["status"] = json::str(s.status);
        st.object["code"] = json::num(s.code);
        st.object["name"] = json::str(s.action);
        st.object["output"] = json::str(s.output);
        st.object["startDateTime"] = json::str(s.start_time);
        st.object["endDateTime"] = json::str(s.end_time);
        st.object["outputS3BucketName"] = json::str(s.s3_bucket);
        st.object["outputS3KeyPrefix"] = json::str(s.s3_key_prefix);
        st.object["stepName"] = json::str(s.plugin_id);
        st.object["standardOutput"] = json::str(s.standard_output);
        st.object["standardError"] = json::str(s.standard_error);
        runtime.object[s.plugin_id] = st;
    }

    json::Value payload = json::obj();
    payload.object["additionalInfo"] = additional;
    payload.object["documentStatus"] = json::str(document_status);
    payload.object["documentTraceOutput"] = json::str(trace);
    payload.object["runtimeStatus"] = runtime;
    return json::dump(payload);
}

}  // namespace runner
