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
#include "runner.h"
#include "s3.h"
#include "util.h"

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

    std::printf("\n%d checks, %d failure(s)\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
