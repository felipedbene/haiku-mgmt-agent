#include "selfupdate.h"

#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>

#include "exec.h"
#include "json.h"
#include "log.h"
#include "s3.h"
#include "util.h"

namespace selfupdate {
namespace {

const char* kWorkDir = "/tmp/debeos-ssm-agent-update";

// Fetch a small https:// resource into memory (manifests on the DeBeOS CDN).
bool https_get(const std::string& url, std::string& body, std::string& err) {
    const std::string prefix = "https://";
    if (!util::starts_with(url, prefix)) {
        err = "unsupported URL scheme: " + url;
        return false;
    }
    const std::string rest = url.substr(prefix.size());
    const size_t slash = rest.find('/');
    http::Request req;
    req.method = "GET";
    req.tls = true;
    req.host = slash == std::string::npos ? rest : rest.substr(0, slash);
    req.path = slash == std::string::npos ? "/" : rest.substr(slash);
    http::Response r = http::perform(req);
    if (!r.ok()) {
        err = "GET " + url + ": status=" + std::to_string(r.status) + " " + r.error;
        return false;
    }
    body = r.body;
    return true;
}

bool download(aws::CredentialProvider& creds, const std::string& region, const std::string& url,
              const std::string& dest, std::string& err) {
    std::string bucket, key;
    if (s3::parse_uri(url, bucket, key)) {
        http::Response r = s3::get(creds, region, bucket, key, dest);
        if (!r.ok()) {
            err = "s3 get " + url + ": status=" + std::to_string(r.status) + " " + r.error +
                  " " + util::clip(r.body, 300, "...");
            return false;
        }
        return true;
    }
    if (util::starts_with(url, "https://")) {
        const std::string prefix = "https://";
        const std::string rest = url.substr(prefix.size());
        const size_t slash = rest.find('/');
        http::Request req;
        req.method = "GET";
        req.tls = true;
        req.host = slash == std::string::npos ? rest : rest.substr(0, slash);
        req.path = slash == std::string::npos ? "/" : rest.substr(slash);
        req.sink_path = dest;
        req.timeout_ms = 120000;
        http::Response r = http::perform(req);
        if (!r.ok()) {
            err = "GET " + url + ": status=" + std::to_string(r.status) + " " + r.error;
            return false;
        }
        return true;
    }
    err = "unsupported artifact URL: " + url;
    return false;
}

}  // namespace

bool fetch_manifest(aws::CredentialProvider& creds, const std::string& region,
                    const std::string& manifest_uri, Manifest& out, std::string& err) {
    std::string body;
    std::string bucket, key;
    if (s3::parse_uri(manifest_uri, bucket, key)) {
        http::Response r = s3::get(creds, region, bucket, key, "");
        if (!r.ok()) {
            err = "s3 get " + manifest_uri + ": status=" + std::to_string(r.status) + " " +
                  r.error + " " + util::clip(r.body, 300, "...");
            return false;
        }
        body = r.body;
    } else if (!https_get(manifest_uri, body, err)) {
        return false;
    }

    std::string jerr;
    json::Value v = json::parse(body, &jerr);
    if (!jerr.empty() || !v.is_obj()) {
        err = "manifest is not valid JSON: " + jerr;
        return false;
    }
    out.version = v.str_at("version");
    out.sha256 = util::lower(util::trim(v.str_at("sha256")));
    out.url = v.str_at("url");
    if (out.version.empty() || out.sha256.empty() || out.url.empty()) {
        err = "manifest is missing version/sha256/url";
        return false;
    }
    return true;
}

Outcome check_and_apply(aws::CredentialProvider& creds, const std::string& region,
                        const std::string& manifest_uri, const std::string& current_version,
                        const std::string& binary_path, std::string& detail) {
    Manifest m;
    std::string err;
    if (!fetch_manifest(creds, region, manifest_uri, m, err)) {
        detail = err;
        return Outcome::Error;
    }

    // Strictly greater only: equal or older can never install, so a stale or
    // rolled-back manifest cannot make the fleet ping-pong between versions.
    if (util::version_compare(m.version, current_version) <= 0) {
        detail = "manifest version " + m.version + " <= running " + current_version;
        return Outcome::UpToDate;
    }
    logging::logf(logging::Info, "self-update: %s -> %s from %s", current_version.c_str(),
                  m.version.c_str(), m.url.c_str());

    ::mkdir(kWorkDir, 0700);
    const size_t base = m.url.find_last_of('/');
    const std::string artifact =
        std::string(kWorkDir) + "/" + (base == std::string::npos ? m.url : m.url.substr(base + 1));

    if (!download(creds, region, m.url, artifact, err)) {
        detail = err;
        return Outcome::Error;
    }

    // Checksum before anything irreversible. TLS protects the transport;
    // this protects against a wrong or truncated object in the bucket.
    const std::string got = util::sha256_file_hex(artifact);
    if (got != m.sha256) {
        ::unlink(artifact.c_str());
        detail = "sha256 mismatch for " + artifact + ": got " + got + " want " + m.sha256;
        return Outcome::Error;
    }

    const bool is_hpkg = artifact.size() > 5 && artifact.rfind(".hpkg") == artifact.size() - 5;
    if (is_hpkg) {
        // The installed binary lives on read-only packagefs, so the update IS a
        // package operation. pkgman handles removal of the old version and
        // activation atomically; the running process keeps its old image until
        // the caller restarts the service.
        exec::Result r = exec::run_shell("pkgman install -y '" + artifact + "'", 300, "", 65536);
        if (r.exit_code != 0) {
            detail = "pkgman install failed (exit " + std::to_string(r.exit_code) + "): " +
                     util::clip(r.stdout_data + r.stderr_data, 500, "...");
            return Outcome::Error;
        }
        detail = "installed " + m.version + " via pkgman (" + artifact + ")";
    } else {
        // Raw binary path, for non-packaged installs: write beside the target,
        // then rename -- atomic on the same volume. Keep the old one for
        // manual rollback.
        const std::string fresh = binary_path + ".new";
        if (::rename(artifact.c_str(), fresh.c_str()) != 0) {
            // /tmp and /boot are different volumes on Haiku; copy instead.
            std::string cp_err;
            exec::Result r =
                exec::run_shell("cp '" + artifact + "' '" + fresh + "'", 60, "", 4096);
            if (r.exit_code != 0) {
                detail = "could not place " + fresh + ": " + r.stderr_data;
                return Outcome::Error;
            }
        }
        ::chmod(fresh.c_str(), 0755);
        ::rename(binary_path.c_str(), (binary_path + ".old").c_str());
        if (::rename(fresh.c_str(), binary_path.c_str()) != 0) {
            detail = std::string("rename into place failed: ") + std::strerror(errno);
            // Put the old binary back so the service can still restart.
            ::rename((binary_path + ".old").c_str(), binary_path.c_str());
            return Outcome::Error;
        }
        detail = "swapped binary at " + binary_path + " (previous kept as .old)";
    }

    logging::logf(logging::Info, "self-update: %s", detail.c_str());
    return Outcome::Updated;
}

}  // namespace selfupdate
