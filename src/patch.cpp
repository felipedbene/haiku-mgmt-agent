#include "patch.h"

#include <cstdlib>

#include "log.h"
#include "util.h"

namespace patch {
namespace {

// Mirror runner.cpp's inline-reply limits: run_baseline builds its StepResult
// directly, without going through run_document's clipping.
constexpr size_t kMaxPluginOutputSize = 2500;
constexpr size_t kMaxStdoutLength = 24000;

// PutInventory caps one call at ~1 MB; a compliance row is well under 200 B.
constexpr size_t kMaxComplianceRows = 1000;

constexpr int kRefreshTimeoutSeconds = 300;
constexpr int kScanTimeoutSeconds = 600;
// The document's own default for the whole step; a full-sync sized update on a
// slow volume can genuinely take this long.
constexpr int kInstallTimeoutSeconds = 3300;

// A new haiku system package only takes effect after a reboot; everything else
// activates immediately on packagefs.
bool needs_reboot(const std::string& package_name) {
    return package_name == "haiku" || package_name == "haiku_loader";
}

std::string param_str(const json::Value& parameters, const std::string& key) {
    const json::Value* v = parameters.find(key);
    if (!v) return "";
    if (v->is_arr()) return v->array.empty() ? "" : v->array.front().str();
    return v->str();
}

std::string list_updates(const std::vector<Update>& updates) {
    std::string out;
    for (const Update& u : updates) {
        out += "  " + u.name + ": ";
        if (!u.from.empty()) out += u.from + " -> ";
        out += u.to + "\n";
    }
    return out;
}

json::Value compliance_row(const Update& u, const std::string& state,
                           const std::string& installed_time) {
    json::Value row = json::obj();
    row.object["Title"] = json::str(u.name + "-" + u.to);
    row.object["KBId"] = json::str(u.name);
    row.object["Classification"] = json::str("");
    row.object["Severity"] = json::str("");
    row.object["State"] = json::str(state);
    row.object["InstalledTime"] = json::str(installed_time);
    return row;
}

}  // namespace

bool is_patch_document(const std::string& document_name) {
    // Both the Run Command document and the State Manager association variant
    // (DHMC pushes the latter at every managed node it configures patching for).
    return document_name == "AWS-RunPatchBaseline" ||
           document_name == "AWS-RunPatchBaselineAssociation";
}

void split_name_version(const std::string& s, std::string& name, std::string& version) {
    // Haiku package names never contain '-' (underscores by convention); the
    // first dash separates name from version, e.g. "haiku-r1~beta5_hrev59996-1".
    size_t dash = s.find('-');
    if (dash == std::string::npos) {
        name = s;
        version = "";
        return;
    }
    name = s.substr(0, dash);
    version = s.substr(dash + 1);
}

std::vector<Update> parse_pkgman_transaction(const std::string& pkgman_output) {
    std::vector<Update> updates;
    for (std::string line : util::split(pkgman_output, '\n')) {
        line = util::trim(line);
        std::string kind;
        for (const char* k : {"upgrade", "install", "downgrade"}) {
            const std::string prefix = std::string(k) + " package ";
            if (util::starts_with(line, prefix)) {
                kind = k;
                line = line.substr(prefix.size());
                break;
            }
        }
        if (kind.empty()) continue;

        // Drop the "from repository <name>" tail some pkgman builds append.
        size_t repo = line.find(" from repository ");
        if (repo != std::string::npos) line = line.substr(0, repo);
        line = util::trim(line);

        Update u;
        u.kind = kind;
        size_t to = line.find(" to version ");
        size_t to_len = 12;
        if (to == std::string::npos) {
            to = line.find(" to ");
            to_len = 4;
        }
        if (to == std::string::npos) {
            // Fresh install: the whole token is name-version.
            split_name_version(line, u.name, u.to);
        } else {
            split_name_version(util::trim(line.substr(0, to)), u.name, u.from);
            u.to = util::trim(line.substr(to + to_len));
            // Some phrasings repeat the full name-version on the right.
            if (util::starts_with(u.to, u.name + "-")) u.to = u.to.substr(u.name.size() + 1);
        }
        if (!u.name.empty()) updates.push_back(u);
    }
    return updates;
}

Params parse_params(const json::Value& parameters) {
    Params p;
    const std::string op = util::lower(util::trim(param_str(parameters, "Operation")));
    if (op == "scan") {
        p.operation = "Scan";
    } else if (op == "install") {
        p.operation = "Install";
    } else {
        p.error = "Operation must be Scan or Install (got '" +
                  param_str(parameters, "Operation") + "')";
        return p;
    }
    const std::string reboot = util::lower(util::trim(param_str(parameters, "RebootOption")));
    p.reboot_option = (reboot == "noreboot") ? "NoReboot" : "RebootIfNeeded";
    p.snapshot_id = param_str(parameters, "SnapshotId");
    return p;
}

json::Value inventory_items(const Report& r, const std::string& capture_time) {
    int pending = 0;
    for (const Update& u : r.installed)
        if (needs_reboot(u.name)) pending++;

    // AWS:PatchSummary drives describe-instance-patch-states and the dashboard
    // counts. Inventory content values are all strings, per the schema.
    json::Value summary = json::obj();
    summary.object["BaselineId"] = json::str("haiku-pkgman");
    summary.object["SnapshotId"] = json::str(r.snapshot_id);
    summary.object["PatchGroup"] = json::str("");
    summary.object["InstalledCount"] = json::str(std::to_string(r.installed_count));
    summary.object["InstalledOtherCount"] = json::str("0");
    summary.object["InstalledPendingRebootCount"] = json::str(std::to_string(pending));
    summary.object["InstalledRejectedCount"] = json::str("0");
    summary.object["NotApplicableCount"] = json::str("0");
    summary.object["MissingCount"] = json::str(std::to_string(r.missing.size()));
    summary.object["FailedCount"] = json::str("0");
    summary.object["OperationType"] = json::str(r.operation);
    summary.object["OperationStartTime"] = json::str(r.operation_start);
    summary.object["OperationEndTime"] = json::str(r.operation_end);
    summary.object["RebootOption"] = json::str(r.reboot_option);
    summary.object["ExecutionId"] = json::str(r.execution_id);

    json::Value summary_item = json::obj();
    summary_item.object["TypeName"] = json::str("AWS:PatchSummary");
    summary_item.object["SchemaVersion"] = json::str("1.0");
    summary_item.object["CaptureTime"] = json::str(capture_time);
    json::Value summary_content = json::arr();
    summary_content.array.push_back(summary);
    summary_item.object["Content"] = summary_content;

    // AWS:PatchCompliance lists the individual patches. Always sent, even
    // empty: an empty content array replaces (clears) stale Missing rows after
    // a successful Install.
    json::Value rows = json::arr();
    for (const Update& u : r.installed) {
        if (rows.array.size() >= kMaxComplianceRows) break;
        rows.array.push_back(compliance_row(
            u, needs_reboot(u.name) ? "InstalledPendingReboot" : "Installed", capture_time));
    }
    for (const Update& u : r.missing) {
        if (rows.array.size() >= kMaxComplianceRows) break;
        rows.array.push_back(compliance_row(u, "Missing", ""));
    }

    json::Value compliance_item = json::obj();
    compliance_item.object["TypeName"] = json::str("AWS:PatchCompliance");
    compliance_item.object["SchemaVersion"] = json::str("1.0");
    compliance_item.object["CaptureTime"] = json::str(capture_time);
    compliance_item.object["Content"] = rows;

    json::Value items = json::arr();
    items.array.push_back(summary_item);
    items.array.push_back(compliance_item);
    return items;
}

runner::DocumentOutcome run_baseline(const Context& ctx, const json::Value& parameters) {
    runner::DocumentOutcome outcome;
    runner::StepResult sr;
    // Mirror the real document's Linux step so the console renders familiarly.
    sr.plugin_id = "PatchLinux";
    sr.action = "aws:runShellScript";
    sr.start_time = util::iso8601(util::now_epoch_ms());

    std::string out, errout;
    bool failed = false;
    bool cancelled = false;

    auto sh = [&](const std::string& script, int timeout) {
        exec::Result r = exec::run_shell(script, timeout, "", kMaxStdoutLength, ctx.cancel);
        if (r.cancelled) cancelled = true;
        return r;
    };

    Params p = parse_params(parameters);
    if (!p.error.empty()) {
        failed = true;
        errout += p.error + "\n";
    } else {
        Report rep;
        rep.operation = p.operation;
        rep.operation_start = util::iso8601_seconds(util::now_epoch());
        rep.snapshot_id = p.snapshot_id;
        rep.execution_id = ctx.command_id;
        rep.reboot_option = p.reboot_option;

        out += "Haiku patch baseline via pkgman: operation=" + p.operation +
               " reboot-option=" + p.reboot_option + "\n";
        logging::logf(logging::Info, "patch baseline: operation=%s", p.operation.c_str());

        exec::Result r = sh("pkgman refresh", kRefreshTimeoutSeconds);
        if (!cancelled) {
            if (r.exit_code == 0) {
                out += "repositories refreshed\n";
            } else {
                // Stale repo data degrades the scan, it does not invalidate it.
                errout += "warning: pkgman refresh failed (exit " +
                          std::to_string(r.exit_code) + "): " +
                          util::clip(util::trim(r.stderr_data), 300, "...") +
                          "; scanning against cached repository data\n";
            }
        }

        std::vector<Update> available;
        if (!cancelled) {
            // "echo n" answers the confirmation prompt, so this prints the
            // would-be transaction and then aborts: a dry run.
            r = sh("echo n | pkgman update", kScanTimeoutSeconds);
            if (!cancelled && !r.error.empty()) {
                failed = true;
                errout += "could not list available updates: " + r.error + "\n";
            } else if (!cancelled) {
                available = parse_pkgman_transaction(r.stdout_data + "\n" + r.stderr_data);
            }
        }

        if (!cancelled && !failed && p.operation == "Install" && !available.empty()) {
            out += std::to_string(available.size()) + " update(s) to install:\n" +
                   list_updates(available);
            r = sh("pkgman update -y", kInstallTimeoutSeconds);
            if (!cancelled) {
                if (r.exit_code == 0) {
                    rep.installed = available;
                    out += "installed " + std::to_string(available.size()) + " update(s)\n";
                } else {
                    failed = true;
                    errout += "pkgman update failed (exit " + std::to_string(r.exit_code) +
                              "): " +
                              util::clip(util::trim(r.stdout_data + r.stderr_data), 800, "...") +
                              "\n";
                }
                // Re-scan either way: what is still pending is what Missing means.
                exec::Result r2 = sh("echo n | pkgman update", kScanTimeoutSeconds);
                if (!cancelled)
                    rep.missing = parse_pkgman_transaction(r2.stdout_data + "\n" + r2.stderr_data);
            }
        } else if (!cancelled && !failed) {
            rep.missing = available;
            if (available.empty()) {
                out += "no updates available; system is up to date\n";
            } else {
                out += std::to_string(available.size()) + " update(s) available (Missing):\n" +
                       list_updates(available);
            }
        }

        for (const Update& u : rep.installed)
            if (needs_reboot(u.name)) rep.pending_reboot = true;
        if (rep.pending_reboot) {
            // The agent never reboots the node: it cannot resume the command
            // afterwards, and surprise reboots are worse than a pending flag.
            errout += "note: a haiku system package was updated; it takes effect on the next "
                      "reboot (reported as InstalledPendingReboot; the agent does not reboot "
                      "the instance)\n";
        }

        if (!cancelled) {
            r = sh("ls -1 /system/packages 2>/dev/null | grep -c '\\.hpkg$'", 60);
            rep.installed_count = std::atoi(util::trim(r.stdout_data).c_str());
            rep.operation_end = util::iso8601_seconds(util::now_epoch());
        }

        if (!cancelled && ctx.report_inventory) {
            aws::Credentials c;
            json::Value items = inventory_items(rep, rep.operation_end);
            http::Response resp;
            resp.error = "no credentials available";
            if (ctx.creds && ctx.creds->get(c))
                resp = aws::put_inventory(ctx.region, c, ctx.instance_id, items);
            if (resp.ok()) {
                out += "compliance reported to SSM inventory (AWS:PatchSummary: " +
                       std::to_string(rep.missing.size()) + " missing, " +
                       std::to_string(rep.installed.size()) + " installed this run)\n";
            } else {
                // A patch run whose compliance record did not land must be
                // visible as a failure, or the dashboard silently goes stale.
                failed = true;
                errout += "PutInventory failed: status=" + std::to_string(resp.status) + " " +
                          resp.error + " " + util::clip(resp.body, 400, "...") + "\n";
            }
        }
    }

    sr.end_time = util::iso8601(util::now_epoch_ms());
    sr.full_stdout = out;
    sr.full_stderr = errout;
    sr.standard_output = util::clip(out, kMaxStdoutLength);
    sr.standard_error = util::clip(errout, kMaxStdoutLength);
    if (cancelled) {
        sr.status = "Cancelled";
        sr.code = 1;
    } else if (failed) {
        sr.status = "Failed";
        sr.code = 1;
    } else {
        sr.status = "Success";
        sr.code = 0;
    }
    sr.output = runner::truncate_output(sr.standard_output, sr.standard_error,
                                        kMaxPluginOutputSize);
    outcome.status = sr.status;
    outcome.steps.push_back(sr);
    logging::logf(logging::Info, "patch baseline finished: %s", sr.status.c_str());
    return outcome;
}

}  // namespace patch
