// s3.h -- native S3 GetObject/PutObject over the agent's own TLS/HTTP/SigV4.
//
// Exists so every builder in the fleet is I/O-autonomous: no aws CLI exists on
// haiku/arm64, so hpkgs used to leave the box over an scp bridge and source
// tarballs arrived over a wget shim (docs/design-roadmap.md F1). Streaming both
// directions: a 400 MiB artifact never lives in RAM on a 4 GiB builder.
//
// SigV4 for S3 differs from the JSON services (aws.cpp): virtual-hosted host,
// the key in the canonical path, and a mandatory x-amz-content-sha256 header --
// UNSIGNED-PAYLOAD here, exactly so uploads need not be buffered to hash them.
#pragma once

#include <string>

#include "aws.h"
#include "http.h"

namespace s3 {

// Parses "s3://bucket/key". Returns false (and leaves outputs alone) otherwise.
bool parse_uri(const std::string& uri, std::string& bucket, std::string& key);

// GET s3://bucket/key. dest_path empty => body returned in Response::body
// (manifests, small objects); otherwise streamed to the file. Refreshes
// credentials and retries once on an expired-token rejection, because IMDS
// role credentials rotate mid-flight on long transfers.
http::Response get(aws::CredentialProvider& creds, const std::string& region,
                   const std::string& bucket, const std::string& key,
                   const std::string& dest_path);

// PUT s3://bucket/key from a file (src_path) or, when src_path is empty, from
// `content` (F2 command output is already in memory).
http::Response put(aws::CredentialProvider& creds, const std::string& region,
                   const std::string& bucket, const std::string& key,
                   const std::string& src_path, const std::string& content,
                   const std::string& content_type = "application/octet-stream");

// Exposed for unit tests: the signed request skeleton without I/O.
http::Request build_request(const std::string& method, const std::string& region,
                            const aws::Credentials& creds, const std::string& bucket,
                            const std::string& key, int64_t now_epoch,
                            const std::string& content_type);

}  // namespace s3
