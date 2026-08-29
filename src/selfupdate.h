// selfupdate.h -- fleet-wide agent updates with no AMI rebake (design-roadmap F3).
//
// A manifest (S3 object or plain https URL) names the newest version:
//
//   { "version": "0.2.0",
//     "sha256":  "<hex sha256 of the artifact>",
//     "url":     "s3://bucket/path/haiku_mgmt_agent-0.2.0-1-arm64.hpkg" }
//
// The agent updates only on a strictly greater version (loop guard), verifies
// the checksum before anything irreversible, and prefers the OS's own package
// machinery: an .hpkg artifact goes through `pkgman install`, because the
// running binary lives on read-only packagefs and cannot be swapped in place.
// A non-.hpkg artifact is treated as a raw binary and atomically swapped at
// `binary_path` (non-packaged installs), keeping the previous one as ".old".
#pragma once

#include <string>

#include "aws.h"

namespace selfupdate {

struct Manifest {
    std::string version;
    std::string sha256;
    std::string url;
};

enum class Outcome {
    UpToDate,
    Updated,   // new version installed; restart the service to run it
    Error,
};

// Fetches and parses the manifest. `manifest_uri` is s3://... (signed with the
// instance role) or https://... (public, e.g. the DeBeOS CDN repo).
bool fetch_manifest(aws::CredentialProvider& creds, const std::string& region,
                    const std::string& manifest_uri, Manifest& out, std::string& err);

// One full check-download-verify-install cycle. `detail` explains the outcome
// either way. Does not restart the running process; the caller decides
// (the daemon schedules `launch_roster restart`, the CLI just reports).
Outcome check_and_apply(aws::CredentialProvider& creds, const std::string& region,
                        const std::string& manifest_uri, const std::string& current_version,
                        const std::string& binary_path, std::string& detail);

}  // namespace selfupdate
