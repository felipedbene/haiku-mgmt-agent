// patch.h -- native Patch Manager support (F5, docs/design-roadmap.md).
//
// AWS-RunPatchBaseline's Linux step downloads a Python payload and drives
// yum/apt/zypper; none of that exists on Haiku. Instead the agent intercepts
// the document by name and implements the two operations natively on pkgman:
//   Scan    -> pkgman refresh + a dry transaction listing (answer "no")
//   Install -> pkgman update -y, then a re-scan for what is still pending
// and reports the result to SSM inventory (PutInventory with AWS:PatchSummary
// and AWS:PatchCompliance), which is what populates the Patch Manager
// compliance dashboard (describe-instance-patch-states).
//
// There is no real patch baseline for Haiku (baselines model yum/apt repo
// metadata), so every available pkgman update counts as an approved, Missing
// patch. The agent never reboots the instance: a "haiku" system package
// update is reported as InstalledPendingReboot instead.
#pragma once

#include <string>
#include <vector>

#include "aws.h"
#include "exec.h"
#include "json.h"
#include "runner.h"

namespace patch {

// True for the documents we intercept instead of executing their steps.
bool is_patch_document(const std::string& document_name);

// One line of a pkgman transaction ("upgrade package x-1.0-1 to 1.1-1").
struct Update {
    std::string kind;  // upgrade | install | downgrade
    std::string name;  // openssl3
    std::string from;  // 1.0-1 (empty for fresh installs)
    std::string to;    // 1.1-1
};

// ---- pure helpers, host-testable (make check) ----

// Splits "openssl3-3.0.16-1" into name ("openssl3") and version ("3.0.16-1")
// at the first '-'. Haiku package names never contain '-' (underscores by
// convention), so the first dash always separates name from version.
void split_name_version(const std::string& s, std::string& name, std::string& version);

// Parses the "The following changes will be made:" block of pkgman output.
// Tolerant of the "to <ver>" and "to version <ver>" phrasings and of trailing
// "from repository <name>" suffixes. Unrecognized lines are ignored.
std::vector<Update> parse_pkgman_transaction(const std::string& pkgman_output);

struct Params {
    std::string operation;      // Scan | Install
    std::string reboot_option;  // RebootIfNeeded | NoReboot
    std::string snapshot_id;
    std::string error;  // non-empty => reject the command
};
// Reads SendCommandPayload.Parameters (values arrive as one-element arrays).
Params parse_params(const json::Value& parameters);

struct Report {
    std::string operation;
    std::string operation_start;  // yyyy-MM-ddTHH:mm:ssZ
    std::string operation_end;
    std::string snapshot_id;
    std::string execution_id;  // command id
    std::string reboot_option;
    int installed_count = 0;         // activated packages on the system
    std::vector<Update> missing;     // updates still available after the run
    std::vector<Update> installed;   // updates applied by this run (Install)
    bool pending_reboot = false;     // a haiku system package was updated
};

// Builds the PutInventory Items array (AWS:PatchSummary + AWS:PatchCompliance).
json::Value inventory_items(const Report& r, const std::string& capture_time);

// ---- orchestration (needs a live instance) ----

struct Context {
    aws::CredentialProvider* creds = nullptr;
    std::string region;
    std::string instance_id;
    std::string command_id;
    exec::Cancel* cancel = nullptr;
    bool report_inventory = true;  // CLI --no-report turns this off
};

// Runs the requested operation end to end and returns a document outcome whose
// single step mirrors the real document's Linux step ("PatchLinux"), so the
// console renders it the same way.
runner::DocumentOutcome run_baseline(const Context& ctx, const json::Value& parameters);

}  // namespace patch
