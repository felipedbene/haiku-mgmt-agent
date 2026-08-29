// test_main.cpp -- host-side unit tests for the logic that does not need Haiku.
//
// Deliberately dependency-free: no gtest on the build host, and certainly none
// on the target. Run with `make check`.

#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>

#include "aws.h"
#include "exec.h"
#include "json.h"
#include "log.h"
#include "mgs.h"
#include "patch.h"
#include "runner.h"
#include "s3.h"
#include "session.h"
#include "util.h"
#include "websocket.h"

namespace {

int g_failures = 0;
int g_checks = 0;

void check(bool cond, const std::string& what) {
    g_checks++;
    if (!cond) {
        g_failures++;
        std::printf("  FAIL: %s\n", what.c_str());
    }
}

void check_eq(const std::string& got, const std::string& want, const std::string& what) {
    g_checks++;
    if (got != want) {
        g_failures++;
        std::printf("  FAIL: %s\n    got:  %s\n    want: %s\n", what.c_str(), got.c_str(), want.c_str());
    }
}

void test_crypto() {
    std::printf("crypto\n");
    // NIST/RFC vectors.
    check_eq(util::sha256_hex(""),
             "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
             "sha256 of empty string");
    check_eq(util::sha256_hex("abc"),
             "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha256 of abc");

    // AWS SigV4 documented derived-signing-key vector.
    check_eq(util::to_hex(aws::signing_key("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                                           "20150830", "us-east-1", "iam")),
             "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9",
             "SigV4 derived signing key (AWS test vector)");
}

void test_json() {
    std::printf("json\n");
    std::string err;

    json::Value v = json::parse(R"({"a":1,"b":"x","c":[1,2,3],"d":{"e":true},"f":null})", &err);
    check(err.empty(), "parse simple object: " + err);
    check(v.is_obj(), "root is object");
    check(v.num_at("a") == 1, "a == 1");
    check_eq(v.str_at("b"), "x", "b == x");
    check(v.find("c") && v.find("c")->array.size() == 3, "c has 3 elements");
    check(v.find("d") && v.find("d")->find("e")->bl(), "d.e is true");
    check(v.find("f") && v.find("f")->is_null(), "f is null");

    // Escapes, including the surrogate pair path.
    v = json::parse(R"({"s":"line\nquote\"tab\tuniéA"})", &err);
    check(err.empty(), "parse escapes: " + err);
    check_eq(v.str_at("s"), "line\nquote\"tab\tuni\xc3\xa9" "A", "escape decoding");

    // Round trip through dump/parse.
    json::Value o = json::obj();
    o.object["n"] = json::num(42);
    o.object["s"] = json::str("a\"b\\c\nd");
    o.object["arr"] = json::arr();
    o.object["arr"].array.push_back(json::str("x"));
    std::string dumped = json::dump(o);
    json::Value back = json::parse(dumped, &err);
    check(err.empty(), "round trip parse: " + err);
    check(back.num_at("n") == 42, "round trip number");
    check_eq(back.str_at("s"), "a\"b\\c\nd", "round trip escaped string");

    // Integers must not render as 42.0 -- SSM's "code" is an int.
    check_eq(json::dump(json::num(0)), "0", "integral zero renders as 0");
    check_eq(json::dump(json::num(42)), "42", "integral renders without decimal point");

    // Malformed input must fail loudly, never yield a silently-empty document.
    json::parse("{\"a\":", &err);
    check(!err.empty(), "truncated object reports an error");
    json::parse("{} trailing", &err);
    check(!err.empty(), "trailing data reports an error");

    // Numbers arriving as strings (SSM does this for timeoutSeconds).
    v = json::parse(R"({"t":"3600"})", &err);
    check(v.num_at("t") == 3600, "string number coerces");
}

void test_truncation() {
    std::printf("truncate_output\n");
    // Fits: stdout, error title, stderr.
    check_eq(runner::truncate_output("out", "err", 2500), "out\n----------ERROR-------\nerr",
             "short output keeps both streams with the error title");
    check_eq(runner::truncate_output("out", "", 2500), "out", "no error title when stderr is empty");

    // Oversized stdout gets cut and marked.
    std::string big(5000, 'x');
    std::string got = runner::truncate_output(big, "", 2500);
    check(got.size() <= 2500, "oversized stdout clipped to capacity");
    check(got.find("---Output truncated---") != std::string::npos, "clip marker present");

    // Both oversized.
    got = runner::truncate_output(big, big, 2500);
    check(got.size() <= 2500 + 64, "both streams clipped near capacity");
    check(got.find("---Output truncated---") != std::string::npos, "stdout marker present");
    check(got.find("---Error truncated----") != std::string::npos, "stderr marker present");
}

void test_parameter_resolution() {
    std::printf("parameter substitution\n");
    std::string err;

    // The shape AWS-RunShellScript actually sends: runCommand is a single
    // placeholder string that must expand to the StringList.
    json::Value inputs = json::parse(R"({"runCommand":"{{ commands }}","workingDirectory":"{{ workingDirectory }}"})", &err);
    json::Value params = json::parse(R"({"commands":["uname -a","echo hi"],"workingDirectory":"/tmp"})", &err);
    json::Value doc_params = json::parse(R"({"workingDirectory":{"type":"String","default":"/"}})", &err);

    json::Value out = runner::resolve(inputs, params, doc_params);
    const json::Value* rc = out.find("runCommand");
    check(rc && rc->is_arr(), "runCommand expanded to a list");
    check(rc && rc->array.size() == 2, "both commands present");
    check_eq(rc && rc->array.size() == 2 ? rc->array[0].str() : "", "uname -a", "first command");
    check_eq(out.str_at("workingDirectory"), "/tmp", "explicit parameter wins over default");

    // Document default used when the command omits the parameter.
    json::Value no_params = json::parse(R"({"commands":["true"]})", &err);
    out = runner::resolve(inputs, no_params, doc_params);
    check_eq(out.str_at("workingDirectory"), "/", "document default applied");

    // Unknown placeholders stay visible rather than becoming empty strings.
    json::Value odd = json::parse(R"({"x":"a {{ nope }} b"})", &err);
    out = runner::resolve(odd, no_params, doc_params);
    check_eq(out.str_at("x"), "a {{ nope }} b", "unknown placeholder left verbatim");

    // Embedded (non-whole-string) substitution.
    json::Value embedded = json::parse(R"({"x":"pre {{ workingDirectory }} post"})", &err);
    out = runner::resolve(embedded, params, doc_params);
    check_eq(out.str_at("x"), "pre /tmp post", "scalar substituted inside a larger string");
}

void test_unsupported_plugin() {
    std::printf("unsupported plugin path\n");
    std::string err;
    // An inventory association document: must come back Failed with an
    // explanation, never silently skipped.
    json::Value doc = json::parse(
        R"({"schemaVersion":"2.2","mainSteps":[{"action":"aws:softwareInventory","name":"collectInventory","inputs":{}}]})",
        &err);
    check(err.empty(), "parse inventory document: " + err);

    runner::DocumentOutcome out = runner::run_document(doc, json::Value());
    check_eq(out.status, "Failed", "unsupported document is Failed");
    check(out.steps.size() == 1, "one step reported");
    if (out.steps.size() == 1) {
        check_eq(out.steps[0].status, "Failed", "step status Failed");
        check(out.steps[0].output.find("not supported on Haiku") != std::string::npos,
              "output explains why");
        check_eq(out.steps[0].plugin_id, "collectInventory", "plugin id is the step name");
    }
}

void test_shell_execution() {
    std::printf("shell execution\n");
    std::string err;

    json::Value doc = json::parse(
        R"({"schemaVersion":"2.2","mainSteps":[{"action":"aws:runShellScript","name":"runShellScript",
            "inputs":{"runCommand":"{{ commands }}"}}]})", &err);

    // Success path.
    json::Value params = json::parse(R"({"commands":["echo hello-haiku"]})", &err);
    runner::DocumentOutcome out = runner::run_document(doc, params);
    check_eq(out.status, "Success", "successful command");
    check(out.steps.size() == 1 && out.steps[0].code == 0, "exit code 0");
    check(out.steps.size() == 1 && out.steps[0].standard_output.find("hello-haiku") != std::string::npos,
          "stdout captured");

    // Failure path with stderr captured -- the second half of the definition of done.
    params = json::parse(R"({"commands":["echo to-stderr >&2; exit 3"]})", &err);
    out = runner::run_document(doc, params);
    check_eq(out.status, "Failed", "failing command reports Failed");
    check(out.steps.size() == 1 && out.steps[0].code == 3, "exit code propagated");
    check(out.steps.size() == 1 && out.steps[0].standard_error.find("to-stderr") != std::string::npos,
          "stderr captured");
    check(out.steps.size() == 1 && out.steps[0].output.find("----------ERROR-------") != std::string::npos,
          "combined output carries the error title");

    // Timeout path: the shell must be killed and reported as TimedOut.
    json::Value slow = json::parse(
        R"({"schemaVersion":"2.2","mainSteps":[{"action":"aws:runShellScript","name":"runShellScript",
            "inputs":{"runCommand":["sleep 30"],"timeoutSeconds":"1"}}]})", &err);
    int64_t began = util::now_epoch_ms();
    out = runner::run_document(slow, json::Value());
    int64_t took = util::now_epoch_ms() - began;
    check_eq(out.status, "Failed", "timed-out document is Failed overall");
    check(out.steps.size() == 1 && out.steps[0].status == "TimedOut", "step reports TimedOut");
    check(took < 20000, "timeout enforced promptly (took " + std::to_string(took) + "ms)");
}

void test_message_id_parsing() {
    std::printf("message id parsing\n");
    // aws.ssm.<command-id>.<instance-id>
    std::vector<std::string> parts =
        util::split("aws.ssm.2b196342-d7d4-436e-8f09-3883a1116ac3.i-57c0a7be", '.');
    check(parts.size() == 4, "message id splits into 4 parts");
    check_eq(parts[parts.size() - 2], "2b196342-d7d4-436e-8f09-3883a1116ac3", "command id extracted");
}

void test_uuid() {
    std::printf("uuid\n");
    std::string a = util::uuid4(), b = util::uuid4();
    check(a.size() == 36, "uuid length");
    check(a != b, "uuids differ");
    check(a[14] == '4', "version 4 nibble");
    check(b[19] == '8' || b[19] == '9' || b[19] == 'a' || b[19] == 'b', "variant nibble");
}

void test_time_formats() {
    std::printf("time formats\n");
    // 2026-08-20T12:34:56.789Z
    const int64_t ms = 1787229296789LL;
    check_eq(util::amz_date(ms / 1000), "20260820T123456Z", "x-amz-date format");
    check_eq(util::amz_datestamp(ms / 1000), "20260820", "credential scope datestamp");
    check_eq(util::iso8601(ms), "2026-08-20T12:34:56.789Z", "reply dateTime format");
    check_eq(util::iso_dash(ms), "2026-08-20T12-34-56.789Z", "runId format");
    check(util::parse_iso8601("2026-08-20T12:34:56Z") == ms / 1000, "credential expiry parsing");
    // The clock bootstrap source on Haiku, which has no NTP client.
    check(util::parse_http_date("Thu, 20 Aug 2026 12:34:56 GMT") == ms / 1000,
          "RFC 1123 HTTP Date parsing");
    check(util::parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT") == 0, "epoch zero");
    check(util::parse_http_date("garbage") == 0, "unparseable date reports 0");
}

void test_uri_encode() {
    std::printf("uri encode\n");
    check_eq(util::uri_encode("abc-123_~.txt", false), "abc-123_~.txt", "unreserved untouched");
    check_eq(util::uri_encode("a b+c", false), "a%20b%2Bc", "space and plus escaped");
    check_eq(util::uri_encode("path/to/key", false), "path/to/key", "slash kept in paths");
    check_eq(util::uri_encode("path/to/key", true), "path%2Fto%2Fkey", "slash escaped in query");
    check_eq(util::uri_encode("\xc3\xa9", false), "%C3%A9", "utf-8 bytes escaped uppercase");
}

void test_version_compare() {
    std::printf("version compare\n");
    check(util::version_compare("0.1.0", "0.2.0") < 0, "0.1.0 < 0.2.0");
    check(util::version_compare("0.2.0", "0.2.0") == 0, "equal versions");
    check(util::version_compare("0.10.0", "0.9.9") > 0, "numeric, not lexicographic");
    check(util::version_compare("1.0", "1.0.0") == 0, "missing component is 0");
    check(util::version_compare("garbage", "0.0.1") < 0, "malformed never looks newer");
}

void test_s3_uri() {
    std::printf("s3 uri parsing\n");
    std::string b, k;
    check(s3::parse_uri("s3://bkt/some/key.tar", b, k), "well-formed uri accepted");
    check_eq(b, "bkt", "bucket extracted");
    check_eq(k, "some/key.tar", "key extracted");
    check(!s3::parse_uri("s3://bkt", b, k), "bucket-only rejected");
    check(!s3::parse_uri("s3://bkt/", b, k), "empty key rejected");
    check(!s3::parse_uri("http://bkt/key", b, k), "wrong scheme rejected");
    check(!s3::parse_uri("s3:///key", b, k), "empty bucket rejected");
}

void test_s3_request_shape() {
    std::printf("s3 request shape\n");
    aws::Credentials creds;
    creds.access_key = "AKIAEXAMPLE";
    creds.secret_key = "secret";
    creds.token = "TOKEN";
    // Fixed time so the request is deterministic.
    http::Request r = s3::build_request("PUT", "us-west-2", creds, "bkt", "a dir/file.hpkg",
                                        1787229296, "application/octet-stream");
    check_eq(r.host, "bkt.s3.us-west-2.amazonaws.com", "virtual-hosted host");
    check_eq(r.path, "/a%20dir/file.hpkg", "key encoded, slash preserved");
    std::string auth, content_sha, token;
    for (const auto& h : r.headers) {
        if (h.first == "Authorization") auth = h.second;
        if (h.first == "X-Amz-Content-Sha256") content_sha = h.second;
        if (h.first == "X-Amz-Security-Token") token = h.second;
    }
    check_eq(content_sha, "UNSIGNED-PAYLOAD", "unsigned payload declared");
    check_eq(token, "TOKEN", "session token attached");
    check(auth.find("Credential=AKIAEXAMPLE/20260820/us-west-2/s3/aws4_request") != std::string::npos,
          "scope names the s3 service and the datestamp");
    check(auth.find("SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token") !=
              std::string::npos,
          "signed header list sorted and complete");
    check(auth.find("Signature=") != std::string::npos && auth.size() > auth.find("Signature=") + 64,
          "signature present and hex-sized");

    // Same inputs, same signature: the signing path is deterministic.
    http::Request r2 = s3::build_request("PUT", "us-west-2", creds, "bkt", "a dir/file.hpkg",
                                         1787229296, "application/octet-stream");
    std::string auth2;
    for (const auto& h : r2.headers)
        if (h.first == "Authorization") auth2 = h.second;
    check_eq(auth2, auth, "deterministic signature");
}

void test_cancellation() {
    std::printf("cancellation\n");
    exec::Cancel cancel;
    std::thread canceller([&cancel]() {
        ::usleep(300 * 1000);
        cancel.request();
    });
    int64_t began = util::now_epoch_ms();
    exec::Result r = exec::run_shell("sleep 30", 60, "", 4096, &cancel);
    int64_t took = util::now_epoch_ms() - began;
    canceller.join();
    check(r.cancelled, "result marked cancelled");
    check(!r.timed_out, "cancel is not a timeout");
    check(took < 15000, "cancel lands promptly (took " + std::to_string(took) + "ms)");

    // Cancelled step surfaces as a Cancelled document.
    std::string err;
    json::Value doc = json::parse(
        R"({"schemaVersion":"2.2","mainSteps":[{"action":"aws:runShellScript","name":"runShellScript",
            "inputs":{"runCommand":["sleep 30"]}}]})", &err);
    exec::Cancel cancel2;
    cancel2.request();  // pre-cancelled: fires on the first poll interval
    runner::Options opts;
    opts.cancel = &cancel2;
    runner::DocumentOutcome out = runner::run_document(doc, json::Value(), opts);
    check_eq(out.status, "Cancelled", "document status Cancelled");
    check(out.steps.size() == 1 && out.steps[0].status == "Cancelled", "step status Cancelled");
}

void test_full_capture() {
    std::printf("full capture for S3 output\n");
    std::string err;
    json::Value doc = json::parse(
        R"({"schemaVersion":"2.2","mainSteps":[{"action":"aws:runShellScript","name":"runShellScript",
            "inputs":{"runCommand":["i=0; while [ $i -lt 3000 ]; do echo line $i; i=$((i+1)); done"]}}]})",
        &err);
    runner::Options opts;
    opts.max_capture = 1024 * 1024;
    runner::DocumentOutcome out = runner::run_document(doc, json::Value(), opts);
    check_eq(out.status, "Success", "long output command succeeds");
    if (out.steps.size() == 1) {
        check(out.steps[0].full_stdout.find("line 2999") != std::string::npos,
              "full capture holds the last line");
        check(out.steps[0].standard_output.size() <= 24000, "inline stdout still clipped");
        check(out.steps[0].full_stdout.size() > out.steps[0].standard_output.size(),
              "full capture exceeds the inline clip");
    }
}

void test_sha256_file() {
    std::printf("sha256 of a file\n");
    const char* path = "/tmp/haiku-mgmt-agent-test-sha";
    std::FILE* f = std::fopen(path, "wb");
    if (f) {
        std::fwrite("abc", 1, 3, f);
        std::fclose(f);
    }
    check_eq(util::sha256_file_hex(path),
             "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
             "streamed digest matches the string digest");
    check_eq(util::sha256_file_hex("/nonexistent/nope"), "", "missing file reports empty");
    ::remove(path);
}

void test_patch_parsing() {
    std::printf("patch: pkgman transaction parsing\n");

    check(patch::is_patch_document("AWS-RunPatchBaseline"), "AWS-RunPatchBaseline intercepted");
    check(patch::is_patch_document("AWS-RunPatchBaselineAssociation"),
          "association variant intercepted");
    check(!patch::is_patch_document("AWS-RunShellScript"), "shell script not intercepted");

    std::string name, ver;
    patch::split_name_version("openssl3-3.0.16-1", name, ver);
    check_eq(name, "openssl3", "name with trailing digit");
    check_eq(ver, "3.0.16-1", "version with revision");
    patch::split_name_version("haiku-r1~beta5_hrev59996-1", name, ver);
    check_eq(name, "haiku", "name before non-numeric version");
    check_eq(ver, "r1~beta5_hrev59996-1", "hrev-style version");

    // Both phrasings pkgman is known to emit, plus repository tails and noise.
    const std::string transaction =
        "Refreshing repository \"Haiku\"...\n"
        "The following changes will be made:\n"
        "  in system:\n"
        "    upgrade package openssl3-3.0.14-1 to 3.0.16-1\n"
        "    upgrade package haiku-r1~beta5_hrev59996-1 to version r1~beta5_hrev60011-1 "
        "from repository Haiku\n"
        "    install package ncurses6-6.4-1 from repository HaikuPorts\n"
        "Continue? [yes/no] (yes) : \n";
    std::vector<patch::Update> ups = patch::parse_pkgman_transaction(transaction);
    check(ups.size() == 3, "three transaction lines parsed, got " + std::to_string(ups.size()));
    if (ups.size() == 3) {
        check_eq(ups[0].name, "openssl3", "upgrade name");
        check_eq(ups[0].from, "3.0.14-1", "upgrade from");
        check_eq(ups[0].to, "3.0.16-1", "upgrade to");
        check_eq(ups[1].name, "haiku", "system package name");
        check_eq(ups[1].to, "r1~beta5_hrev60011-1", "to-version phrasing, repo tail stripped");
        check_eq(ups[2].kind, "install", "install kind");
        check_eq(ups[2].name, "ncurses6", "install name");
        check_eq(ups[2].to, "6.4-1", "install version");
        check(ups[2].from.empty(), "install has no from-version");
    }
    check(patch::parse_pkgman_transaction("Nothing to do.\n").empty(),
          "up-to-date system parses to no updates");
}

void test_patch_params_and_inventory() {
    std::printf("patch: params and inventory items\n");
    std::string err;

    // SendCommandPayload parameters arrive as one-element arrays.
    json::Value params = json::parse(
        R"({"Operation":["Install"],"RebootOption":["NoReboot"],"SnapshotId":["snap-1"]})", &err);
    patch::Params p = patch::parse_params(params);
    check(p.error.empty(), "valid params accepted: " + p.error);
    check_eq(p.operation, "Install", "operation normalized");
    check_eq(p.reboot_option, "NoReboot", "reboot option honored");
    check_eq(p.snapshot_id, "snap-1", "snapshot id read");

    p = patch::parse_params(json::parse(R"({"Operation":["scan"]})", &err));
    check_eq(p.operation, "Scan", "case-insensitive operation");
    check_eq(p.reboot_option, "RebootIfNeeded", "default reboot option");

    p = patch::parse_params(json::parse(R"({"Operation":["Nuke"]})", &err));
    check(!p.error.empty(), "unknown operation rejected");

    patch::Report r;
    r.operation = "Install";
    r.operation_start = "2026-08-29T01:00:00Z";
    r.operation_end = "2026-08-29T01:05:00Z";
    r.execution_id = "cmd-123";
    r.reboot_option = "NoReboot";
    r.installed_count = 214;
    r.installed = {{"upgrade", "openssl3", "3.0.14-1", "3.0.16-1"},
                   {"upgrade", "haiku", "r1-1", "r2-1"}};
    r.missing = {{"upgrade", "ncurses6", "6.3-1", "6.4-1"}};

    json::Value items = patch::inventory_items(r, "2026-08-29T01:05:00Z");
    check(items.is_arr() && items.array.size() == 2, "summary + compliance items");
    const json::Value& summary = items.array[0];
    check_eq(summary.str_at("TypeName"), "AWS:PatchSummary", "summary type name");
    check_eq(summary.str_at("SchemaVersion"), "1.0", "summary schema version");
    const json::Value* content = summary.find("Content");
    check(content && content->array.size() == 1, "summary has one content row");
    if (content && content->array.size() == 1) {
        const json::Value& row = content->array[0];
        check_eq(row.str_at("MissingCount"), "1", "missing count");
        check_eq(row.str_at("InstalledCount"), "214", "installed count");
        check_eq(row.str_at("InstalledPendingRebootCount"), "1",
                 "haiku package counts as pending reboot");
        check_eq(row.str_at("OperationType"), "Install", "operation type");
        check_eq(row.str_at("ExecutionId"), "cmd-123", "execution id");
        // Inventory content values must all be strings.
        for (const auto& kv : row.object)
            check(kv.second.is_str(), "summary value is a string: " + kv.first);
    }
    const json::Value& compliance = items.array[1];
    check_eq(compliance.str_at("TypeName"), "AWS:PatchCompliance", "compliance type name");
    const json::Value* rows = compliance.find("Content");
    check(rows && rows->array.size() == 3, "one row per patch");
    if (rows && rows->array.size() == 3) {
        check_eq(rows->array[0].str_at("State"), "Installed", "installed state");
        check_eq(rows->array[1].str_at("State"), "InstalledPendingReboot",
                 "haiku package pending reboot state");
        check_eq(rows->array[2].str_at("State"), "Missing", "missing state");
        check_eq(rows->array[2].str_at("KBId"), "ncurses6", "KBId is the package name");
        check_eq(rows->array[2].str_at("Title"), "ncurses6-6.4-1", "title is name-version");
    }

    // After a clean install, compliance content must still be present (an
    // empty array clears stale Missing rows server-side).
    r.installed.clear();
    r.missing.clear();
    items = patch::inventory_items(r, "2026-08-29T01:05:00Z");
    const json::Value* empty_rows = items.array[1].find("Content");
    check(empty_rows && empty_rows->is_arr() && empty_rows->array.empty(),
          "empty compliance content still sent");
}

void test_precondition_skip() {
    std::printf("runner: schema-2.2 precondition\n");
    std::string err;
    json::Value doc = json::parse(R"({
        "schemaVersion": "2.2",
        "mainSteps": [
            {"action": "aws:runPowerShellScript", "name": "PatchWindows",
             "precondition": {"StringEquals": ["platformType", "Windows"]},
             "inputs": {"runCommand": ["exit 1"]}},
            {"action": "aws:runShellScript", "name": "PatchLinux",
             "precondition": {"StringEquals": ["platformType", "Linux"]},
             "inputs": {"runCommand": ["echo patched"]}}
        ]})", &err);
    check(err.empty(), "precondition doc parses: " + err);

    runner::DocumentOutcome out = runner::run_document(doc, json::Value());
    check_eq(out.status, "Success", "windows step skipped, linux step ran");
    check(out.steps.size() == 2, "both steps reported");
    if (out.steps.size() == 2) {
        check_eq(out.steps[0].status, "Skipped", "windows step status");
        check_eq(out.steps[1].status, "Success", "linux step status");
        check(out.steps[1].standard_output.find("patched") != std::string::npos,
              "linux step actually executed");
    }
}

void test_base64_and_ws_accept() {
    std::printf("crypto: base64 + websocket accept key\n");
    // RFC 4648 vectors.
    check_eq(util::base64_encode(""), "", "base64 empty");
    check_eq(util::base64_encode("f"), "Zg==", "base64 'f'");
    check_eq(util::base64_encode("fo"), "Zm8=", "base64 'fo'");
    check_eq(util::base64_encode("foo"), "Zm9v", "base64 'foo'");
    check_eq(util::base64_encode("foob"), "Zm9vYg==", "base64 'foob'");
    check_eq(util::base64_encode("foobar"), "Zm9vYmFy", "base64 'foobar'");
    // The canonical RFC 6455 handshake example.
    check_eq(ws::accept_key_for("dGhlIHNhbXBsZSBub25jZQ=="),
             "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", "RFC 6455 Sec-WebSocket-Accept");
}

void test_ws_framing() {
    std::printf("websocket: frame round-trip\n");
    const unsigned char mask[4] = {0x12, 0x34, 0x56, 0x78};

    // Short payload.
    std::string wire = ws::make_frame(ws::kOpBinary, "hello", mask);
    check(static_cast<unsigned char>(wire[0]) == 0x82, "FIN + binary opcode");
    check((static_cast<unsigned char>(wire[1]) & 0x80) != 0, "client frame is masked");
    check((static_cast<unsigned char>(wire[1]) & 0x7F) == 5, "length 5");
    // Servers send unmasked frames; build one directly (FIN + opcode, len, data).
    auto server_frame = [](uint8_t opcode, const std::string& data) {
        std::string f;
        f += static_cast<char>(0x80 | opcode);
        if (data.size() < 126) {
            f += static_cast<char>(data.size());
        } else {
            f += static_cast<char>(126);
            f += static_cast<char>((data.size() >> 8) & 0xFF);
            f += static_cast<char>(data.size() & 0xFF);
        }
        f += data;
        return f;
    };

    std::string server = server_frame(ws::kOpBinary, "hello");
    bool fin = false;
    uint8_t op = 0;
    std::string payload, err;
    int rc = ws::parse_frame(server, fin, op, payload, err);
    check(rc == 1, "parse short frame: " + err);
    check(fin && op == ws::kOpBinary, "fin + opcode preserved");
    check_eq(payload, "hello", "unmasked payload parses");

    // Extended 16-bit length.
    std::string big(300, 'x');
    std::string bframe = server_frame(ws::kOpText, big);
    payload.clear();
    rc = ws::parse_frame(bframe, fin, op, payload, err);
    check(rc == 1 && payload.size() == 300, "300-byte frame parses");

    // Partial frame: parser must ask for more, not error.
    std::string partial = server_frame(ws::kOpBinary, "abcdef").substr(0, 3);
    payload.clear();
    rc = ws::parse_frame(partial, fin, op, payload, err);
    check(rc == 0, "partial frame returns need-more");

    // And a client frame that we generate must decode back through its own mask.
    std::string masked = ws::make_frame(ws::kOpBinary, "roundtrip", mask);
    // Feed it to a mask-aware decode by clearing the "server must be unmasked"
    // assumption is not exposed; instead verify the mask actually changed bytes.
    check(masked.substr(6) != "roundtrip", "client payload is masked on the wire");
}

void test_mgs_agentmessage() {
    std::printf("mgs: AgentMessage serialize/deserialize\n");

    // UUID wire order: least-significant half is written first (putUuid).
    unsigned char wire[16];
    const std::string uuid = "12345678-9abc-def0-1122-334455667788";
    check(mgs::uuid_to_wire(uuid, wire), "uuid parses");
    check_eq(mgs::uuid_from_wire(wire), uuid, "uuid wire round-trip");
    // Verify the half-swap explicitly.
    check(wire[0] == 0x11 && wire[1] == 0x22, "LSB half written first");
    check(wire[8] == 0x12 && wire[9] == 0x34, "MSB half written second");

    mgs::AgentMessage m;
    m.message_type = mgs::kMsgOutputStreamData;
    m.schema_version = 1;
    m.created_ms = 1724900000000ULL;
    m.sequence = 7;
    m.flags = 1;
    m.message_id = uuid;
    m.payload_type = mgs::kPayloadOutput;
    m.payload = "some shell output\n";

    std::string raw = mgs::serialize(m);
    check(raw.size() == 120 + m.payload.size(), "frame is header(120) + payload");
    // Header length field is 116.
    check(static_cast<unsigned char>(raw[3]) == 116, "HeaderLength = 116");
    // MessageType is space-padded in its 32-byte field.
    check(raw[4 + m.message_type.size()] == ' ', "message type space-padded");

    mgs::AgentMessage back;
    std::string err;
    check(mgs::deserialize(raw, back, err), "deserialize ok: " + err);
    check_eq(back.message_type, m.message_type, "type round-trip");
    check(back.sequence == 7, "sequence round-trip");
    check(back.flags == 1, "flags round-trip");
    check(back.payload_type == mgs::kPayloadOutput, "payload type round-trip");
    check_eq(back.message_id, uuid, "message id round-trip");
    check_eq(back.payload, m.payload, "payload round-trip");

    // Inbound digest is intentionally NOT verified (matches the reference Go
    // agent, which never checks PayloadDigest on Deserialize). Issue #2: the
    // live service's stored digest for the HandshakeResponse did not equal
    // sha256(payload) as we compute it, and a strict check dropped the handshake
    // so the pty never spawned. A flipped payload byte must still deserialize.
    mgs::AgentMessage flipped;
    std::string flipped_raw = raw;
    flipped_raw[125] = flipped_raw[125] ^ 0xFF;
    check(mgs::deserialize(flipped_raw, flipped, err),
          "payload byte change still deserializes (digest not verified inbound): " + err);
    check(flipped.payload.size() == m.payload.size(), "flipped payload same length");
    check_eq(flipped.payload.substr(6), m.payload.substr(6),
             "payload past the flipped byte (index 5) round-trips");

    // Payload is the whole remainder after the header (input[HeaderLength+4:]),
    // matching the Go agent, so trailing bytes beyond a (smaller) PayloadLength
    // field are still delivered rather than truncated.
    mgs::AgentMessage rem;
    std::string with_trailer = raw + "EXTRA";
    check(mgs::deserialize(with_trailer, rem, err), "frame with trailer deserializes: " + err);
    check_eq(rem.payload, m.payload + "EXTRA", "payload takes the full remainder");

    // A truncated frame (shorter than the header) is still rejected.
    mgs::AgentMessage bad;
    check(!mgs::deserialize(raw.substr(0, 50), bad, err), "short frame rejected");
}

void test_session_parsing() {
    std::printf("session: start request + handshake\n");

    // interactive_shell payload: envelope with a stringified inner document.
    const std::string inner =
        R"({"SessionId":"user-0abc","DocumentName":"SSM-SessionManagerRunShell",)"
        R"("DocumentContent":{"schemaVersion":"1.0","sessionType":"Standard_Stream",)"
        R"("inputs":{"runAsEnabled":false,"runAsDefaultUser":"","kmsKeyId":"",)"
        R"("shellProfile":{"linux":"echo hi"}}}})";
    // The envelope's Content is that document as a JSON string.
    json::Value env = json::obj();
    env.object["Content"] = json::str(inner);
    session::StartRequest sr = session::parse_start_request(json::dump(env));
    check(sr.error.empty(), "start request parsed: " + sr.error);
    check_eq(sr.session_id, "user-0abc", "session id");
    check_eq(sr.session_type, "Standard_Stream", "session type");
    check_eq(sr.shell_commands, "echo hi", "shell profile commands");
    check(!sr.run_as_enabled, "runAs disabled");

    // Issue #2 regression: the LIVE MGS envelope uses a lowercase "content"
    // key (Go's json is case-insensitive; ours is not). Must parse the same.
    json::Value live_env = json::obj();
    live_env.object["schemaVersion"] = json::num(1);
    live_env.object["taskId"] = json::str("t-1");
    live_env.object["topic"] = json::str("test_topic");
    live_env.object["content"] = json::str(inner);
    session::StartRequest live = session::parse_start_request(json::dump(live_env));
    check(live.error.empty(), "lowercase 'content' envelope parses: " + live.error);
    check_eq(live.session_id, "user-0abc", "session id from lowercase-content envelope");
    check_eq(live.session_type, "Standard_Stream", "session type from lowercase-content envelope");

    session::StartRequest bad = session::parse_start_request("not json");
    check(!bad.error.empty(), "garbage payload rejected");

    // Handshake request shape.
    std::string hs = session::build_handshake_request("0.4.0", "Standard_Stream", json::obj());
    std::string jerr;
    json::Value hv = json::parse(hs, &jerr);
    check(jerr.empty() && hv.is_obj(), "handshake request is JSON");
    check_eq(hv.str_at("AgentVersion"), "0.4.0", "agent version in handshake");
    const json::Value* actions = hv.find("RequestedClientActions");
    check(actions && actions->is_arr() && actions->array.size() == 1, "one requested action");
    if (actions && actions->array.size() == 1) {
        check_eq(actions->array[0].str_at("ActionType"), "SessionType", "action type");
        const json::Value* ap = actions->array[0].find("ActionParameters");
        check(ap && ap->str_at("SessionType") == "Standard_Stream", "session type in params");
    }

    // Handshake response acceptance (numeric and string ActionStatus).
    std::string cv, herr;
    check(session::handshake_response_ok(
              R"({"ClientVersion":"1.2.0","ProcessedClientActions":[{"ActionType":"SessionType","ActionStatus":1}]})",
              cv, herr),
          "numeric success accepted: " + herr);
    check_eq(cv, "1.2.0", "client version extracted");
    check(!session::handshake_response_ok(
              R"({"ProcessedClientActions":[{"ActionType":"SessionType","ActionStatus":2,"Error":"nope"}]})",
              cv, herr),
          "failed action rejected");
}

}  // namespace

int main() {
    // Keep the expected warnings (timeouts, unsupported plugins) out of the way.
    logging::init("", logging::Error, true);

    test_crypto();
    test_json();
    test_truncation();
    test_parameter_resolution();
    test_unsupported_plugin();
    test_shell_execution();
    test_message_id_parsing();
    test_uuid();
    test_time_formats();
    test_uri_encode();
    test_version_compare();
    test_s3_uri();
    test_s3_request_shape();
    test_cancellation();
    test_full_capture();
    test_sha256_file();
    test_patch_parsing();
    test_patch_params_and_inventory();
    test_precondition_skip();
    test_base64_and_ws_accept();
    test_ws_framing();
    test_mgs_agentmessage();
    test_session_parsing();

    std::printf("\n%d checks, %d failure(s)\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
