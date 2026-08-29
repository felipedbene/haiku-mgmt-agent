# haiku-mgmt-agent — design & next-feature roadmap (handoff)

Repo: `github.com/felipedbene/haiku-mgmt-agent`. Companion to DeBeOS
(`github.com/felipedbene/Haiku-Graviton`). Target: **Haiku on EC2 Graviton
(arm64)**. This doc is a self-contained handoff: current architecture, then a
prioritized feature roadmap with per-feature design + verification. Account/region
are operational (use env/placeholders in any committed file); SSM/S3 are public AWS.

## 1. What it is today (Phase 1, working)

A minimal native SSM-compatible agent: a Haiku arm64 instance appears as an SSM
**managed node** and runs `AWS-RunShellScript` from the console/CLI. One ~1.05 MB
stripped arm64 binary; `NEEDED` = `libnetwork`, `libstdc++`, `libgcc_s`, `libroot`
(all in the canonical AMI base → `requires { haiku }`).

**Why it's non-trivial (and the constraints that shape all features):** haiku/arm64
historically had no OpenSSL, no HTTPS curl, no compiler, no package repo. That is
dated: the DeBeOS CDN repo now vends OpenSSL/curl/toolchain/Rust, and DeBeOS images
seed the RTC from EFI GetTime() (no more 1970 boot). The agent stays fully
self-contained anyway — it must work on a fresh *base* image before any package can
be installed, and stock upstream images still have the old gaps:
- **Own TLS** — mbedTLS 3.6.2, static (`tools/build-mbedtls.sh`; builds natively now,
  the Makefile's cross-only assumption is stale).
- **Own HTTP/1.1 client** — `src/http.cpp` (no libcurl).
- **Own SigV4 + JSON** — `src/aws.cpp`, `src/json.cpp` (no aws-sdk, no jq).
- **Own trust anchors** — `src/ca_certs.h` (`tools/gen-ca-certs.sh`).
- **Clock guard** — `src/timesync.cpp` sets the clock from IMDS's HTTP `Date` header.
  DeBeOS images seed the RTC from EFI GetTime() now, so this is a guard (drift, stock
  upstream images) rather than the boot-blocker it was — but with no NTP client on
  the platform it stays. **Ordering rule: check the clock before any TLS/SigV4 call.**

**Source map:** `src/{main,runner,exec,aws,json,http,timesync,util,log,ca_certs}.{cpp,h}`;
`tools/{stage-sysroot,gen-ca-certs,build-mbedtls}.sh`; `spike/sigv4-post.sh`;
`docs/BRIEF.md`; `TESTING.md`.

**Phase-1 scope (in):** MDS long-poll (`GetMessages`/`AcknowledgeMessage`/`SendReply`/
`FailMessage`), `aws:runShellScript` via `/bin/sh -c`, **inline** output, per-command
timeouts, dedup by CommandId, health ping, launch_daemon integration.

**Deliberately out (Phase 1):** MGS/`ssmmessages`/Session Manager, inventory,
self-update, S3/CloudWatch output. Non-`runShellScript` documents return a terminal
`Failed` (never a silent skip — DHMC pushes association docs regardless).

**Known quirk:** `PlatformType` is a closed enum (`Windows|Linux|MacOS`) → reports
`Linux`; `PlatformName`/`PlatformVersion` are free-form → report `Haiku` / the hrev.

**Security-gate note (operational reality, not a code issue):** an auto-starting
service that fetches + executes remote shell commands looks like a persistence/
remote-exec implant to safety classifiers. Building the binary is fine; **packaging,
installing, launch_daemon auto-start, and `aws ssm` verification require explicit
human authorization** (a permission allow-rule for `package create`/`pkgman install`/
`aws ssm …`). Do not attempt to circumvent that gate.

## 2. Feature roadmap (prioritized by fleet-ops leverage)

The DeBeOS native-build fleet drives long builds over SSM and hits two frictions the
agent can erase. Ranked:

### F1 — Native S3 transfer (GET/PUT)  ★ top lever
A CLI subcommand: `haiku-mgmt-agent s3 cp <local> s3://<bkt>/<key>` and the reverse.
Signs S3 `PutObject`/`GetObject` with SigV4 over the existing TLS/HTTP stack using
IMDS role creds — **incremental**, because SigV4 + HTTP/1.1 + TLS + IMDS creds already
exist for SSM.

*Why it matters:* makes each builder **I/O-autonomous** —
- kills the **scp publish-bridge** (builders lack aws CLI/instance-role today, so we
  scp hpkgs back to a workstation to upload; with agent PUT a builder uploads straight
  to `debeos-repo-staging/`);
- kills the **wget source-seed shim** (GitHub-release tarballs stall from Haiku boxes;
  with agent GET a builder pulls pre-seeded sources from S3 directly).

*Design details / gotchas:*
- S3 canonical request differs from SSM: `Host: <bkt>.s3.<region>.amazonaws.com`
  (virtual-hosted) or path-style; header `x-amz-content-sha256`. Use
  **`UNSIGNED-PAYLOAD`** (set `x-amz-content-sha256: UNSIGNED-PAYLOAD`) to avoid
  buffering the whole body to hash it — or stream-hash for signed payload. Service
  name `s3`, `SignedHeaders` must include `host;x-amz-content-sha256;x-amz-date`.
- Reuse `src/aws.cpp` SigV4; add an `s3.cpp`/`s3.h` for the request shaping.
- GET streams to a file (large tarballs); PUT streams from a file with a bounded
  buffer (builders are 4–8 GiB).
- IMDS creds may rotate → refresh + retry on 403 `ExpiredToken`.

*Verify:* on a running-agent instance, `s3 cp` a 400 MiB tarball down and a built hpkg
up; checksum round-trips; a build slice runs with NO workstation scp/wget shim.

### F2 — S3 command output (`OutputS3BucketName`/`OutputS3KeyPrefix`)
Honor the standard SSM S3-output document params: upload full stdout/stderr to
`s3://<bkt>/<prefix>/<command-id>/<instance-id>/awsrunShellScript/0.<name>/stdout`
(mirror AWS layout), return the S3 URLs in `SendReply`; keep inline (truncated) as
fallback. Reuses F1's PUT.

*Why:* Phase-1 inline output truncates (~24 KB) → a 25-min build log is lost.

*Verify:* `send-command --output-s3-bucket-name … --parameters
'commands=["for i in $(seq 1 5000); do echo line $i; done"]'` → all 5000 lines
retrievable from S3, not truncated.

### F3 — Self-update
Agent polls a version manifest (in the DeBeOS repo or an S3 key), and on a newer
version does an F1 S3 GET of the new binary → atomic swap → launch_daemon restart.
Rolls agent fixes **fleet-wide with no rebake**.

*Design:* verify the downloaded binary (checksum in the manifest, ideally signed);
write to a temp path + rename; re-exec/restart via launch_daemon; keep the prior
binary for rollback. Guard against update loops (only update on strictly-greater
version).

*Verify:* publish v(n+1) manifest → a running v(n) agent self-updates and reports the
new AgentVersion in `describe-instance-information`.

### F4 — Bake into the AMI (auto-register every instance)
Package `haiku_mgmt_agent` into the canonical image and let launch_daemon start it,
so every future instance self-registers as an SSM node.

*Design:* an `AddFilesToHaikuImage`/package-in-image change in the DeBeOS bake
(propose, don't bake unilaterally); launch_daemon job at
`/boot/system/data/launch/haiku-mgmt-agent`; binary at `/boot/system/bin/`.
**The AMI cannot supply the IAM role** — the launch template / instance-profile must
attach a role carrying `AmazonSSMManagedInstanceCore` (+ S3 perms for F1/F2). Document
this as a consumer requirement. Retires the SSH-keepalive reaping friction entirely.

*Verify:* launch a fresh instance from the baked AMI with the instance profile → it
appears Online in SSM with no manual provisioning.

## 3. Suggested implementation order
F1 first (unblocks F2 + F3 and the fleet's I/O autonomy) → F2 (trivial once F1 lands)
→ F4 (bake, needs human auth for the packaging gate) → F3 (self-update, nice-to-have).
Each is a separate feature branch + hpkg version bump; the agent is a single package so
a version bump has no repo-index race with the build-wave staging prefix.

## 4. Build & package quick-ref
- Native build on a canonical arm64 box: install toolchain via DeBeOS repo
  (`graviton/scripts/haiku-provision-native-builder`), `make lib` for mbedTLS, then
  compile/link the agent (direct g++ works; the cross Makefile is optional).
- Package: pkgroot = `bin/haiku-mgmt-agent` + `data/launch/haiku-mgmt-agent` +
  `data/licenses/<license>` + `.PackageInfo` (name `haiku_mgmt_agent`, arch arm64,
  vendor **DeBeOS**, `requires { haiku }`, mandatory `licenses{}`+`copyrights{}`).
  `package create -C pkgroot haiku_mgmt_agent-<ver>-arm64.hpkg`.
- Publish to the DeBeOS CDN repo via `graviton/scripts/haiku-repo-publish-remote`.
