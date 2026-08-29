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

### F5 — Patch Manager (implemented on `phase3-patch-manager`, pending live gates)
`AWS-RunPatchBaseline`'s Linux step is a Python payload driving yum/apt/zypper —
none of which exist on Haiku — so the agent **intercepts the document by name**
(`AWS-RunPatchBaseline`, `AWS-RunPatchBaselineAssociation`) and implements the two
operations natively on pkgman (`src/patch.cpp`):
- **Scan**: `pkgman refresh`, then a dry transaction (`echo n | pkgman update`)
  parsed for upgrade/install/downgrade lines. Every available update counts as an
  approved **Missing** patch — there is no real Haiku patch baseline to filter by.
- **Install**: `pkgman update -y`, then a re-scan; what is still pending is Missing.
- **Compliance**: `PutInventory` with `AWS:PatchSummary` (drives
  `describe-instance-patch-states` / the dashboard counts) and `AWS:PatchCompliance`
  (per-patch rows). A failed PutInventory fails the step — a patch run whose record
  did not land must be visible, or the dashboard silently goes stale.
- **Reboots**: never. A `haiku`/`haiku_loader` update is reported as
  `InstalledPendingReboot`; the agent cannot resume a command across a reboot.
- **CLI**: `haiku-mgmt-agent patch scan|install [--no-report]` runs the same code
  path on-box for testing.
- Side fix: schema-2.2 `precondition` handling in `runner.cpp` — steps whose
  `{"StringEquals": ["platformType", ...]}` excludes Linux report `Skipped` instead
  of failing the document (we present PlatformType=Linux).

*Verify (needs a live instance + human gate):* `aws ssm send-command
--document-name AWS-RunPatchBaseline --parameters 'Operation=Scan'` → Success with a
readable update list; `describe-instance-patch-states` shows the counts;
`Operation=Install` applies updates and flips Missing→0; the pkgman transaction
parser assumptions (`tests/`) hold against real pkgman output — if the phrasing
differs, fix `parse_pkgman_transaction` and its vectors together. Also confirm
`PutInventory` accepts the 1.0 schemas (adjust attribute sets if it 400s).
IAM: the instance role needs `ssm:PutInventory` (in `AmazonSSMManagedInstanceCore`).

### F6 — Session Manager / MGS (implemented on `phase3-patch-manager`, live gates PENDING)
Phase 1/2 deliberately skipped MGS; F6 adds it. The agent opens the MGS **control
channel** (a SigV4-signed WebSocket to `ssmmessages.<region>.amazonaws.com`) and,
per `StartSession`, opens a **data channel**, runs the plugin handshake, and bridges
a `/bin/sh` pty to the customer. Interactive `Standard_Stream` shells only — port
forwarding and NonInteractiveCommands are out of scope; Run Command still rides MDS.

New self-contained building blocks (same "no library to link" reason as the rest):
- `src/websocket.{h,cpp}` — RFC 6455 client over a persistent `http::Stream`
  (masking, fragmentation, ping/pong/close). No libwebsockets on haiku/arm64.
- `src/http.cpp` `Stream` — a persistent bidirectional TLS connection (the WS
  transport), factored out of the one-shot `perform()` path.
- `src/mgs.{h,cpp}` — the binary `AgentMessage` frame (116-byte header, big-endian,
  space-padded 32-byte type, **UUID written least-significant-half-first** per the Go
  agent's `putUuid`, SHA-256 payload digest) and the `CreateControlChannel`/
  `CreateDataChannel` REST calls.
- `src/session.{h,cpp}` — control-channel loop + per-session pty bridge, plus the
  handshake request/response and `interactive_shell` envelope parsing (the payload
  is a JSON envelope whose `Content` is a *stringified* inner document).
- `aws::sigv4_headers` — generalized SigV4 (arbitrary method/path/query) for the MGS
  REST POSTs and the signed WS upgrade GET, which `call()`'s POST-to-"/" shape can't do.
- `util::{sha1_raw,sha256_raw,base64_encode,random_bytes}` — WS accept key + framing.

Control channel runs on its own thread with reconnect/backoff (mirrors the MDS poll
loop); each session forks a pty-backed shell on a worker thread (mirrors Run Command's
worker model). `--no-session-manager` disables it. SSMConnectionChannel stays
`ec2messages`: MDS remains the primary work channel and Run Command routing must not
change.

*Key hardware risks to validate first (cannot be exercised on the Linux build host):*
- **pty availability** — `posix_openpt`/`grantpt`/`unlockpt`/`ptsname` and
  `TIOCSWINSZ` on haiku/arm64. This is the make-or-break dependency; if the SUSv3
  pty layer is incomplete, the shell bridge needs a Haiku-specific path.
- **WebSocket upgrade signing** — whether MGS accepts our SigV4-over-GET upgrade
  (query string in the canonical request) exactly as the Go agent's does.
- **AgentMessage byte order** — the UUID half-swap and big-endian header, verified in
  unit tests against the documented layout but not yet against a live channel.

*Verify:* `aws ssm start-session --target <id>` from a machine with the session-manager
plugin → interactive prompt, keystrokes echo, `env`/`ls` work, terminal resize
propagates, `exit` closes cleanly and the console shows the session Terminated. IAM:
the instance role needs the `ssmmessages:*` actions (already in
`AmazonSSMManagedInstanceCore`).

## 3. Suggested implementation order
F1 first (unblocks F2 + F3 and the fleet's I/O autonomy) → F2 (trivial once F1 lands)
→ F4 (bake, needs human auth for the packaging gate) → F3 (self-update, nice-to-have).
Each is a separate feature branch + hpkg version bump; the agent is a single package so
a version bump has no repo-index race with the build-wave staging prefix.

## 3a. Rejected alternatives (revisit only if the premises change)

**Rewrite in Rust or Go — no.** The hard part was never the language; it was the
platform spadework (own TLS, HTTP/1.1, SigV4, JSON, CA anchors, clock guard), and
that is done and hardware-proven. A rewrite re-pays all of it for zero functional
gain. Go's runtime/GC and Rust's std both assume libc/OS surfaces haiku/arm64 only
partially provides, so you would port a runtime before writing agent logic. The
artifact is ~1.1 MB and boots as the *first* manageable thing on a bare image. Rust
now cross-compiles to Haiku arm64 in this project, so it is a candidate for a **new**
component (e.g. an F5 Session Manager PTY/websocket path) — never a reason to rewrite
the working agent.

**Adopt `aws-sdk-cpp` — deferred until it's a real need, not rejected outright.**
Today it is the wrong trade: no haiku/arm64 build, and it pulls in libcurl + OpenSSL +
CMake, which destroys the self-contained-on-a-base-image property that lets this run
before any package is installed — a 1.1 MB binary would become tens of MB of
dependencies to port and bake. So we keep the minimal hand-rolled SigV4/HTTP core *for
now*. Revisit only when a concrete need forces it — e.g. the agent moves off the
base-image critical path (a separate, richly-provisioned management box), or a feature
needs enough new AWS surface (many services/operations) that hand-rolling each call
costs more than porting the SDK once. Decision: **wait for that trigger; do not adopt
speculatively.**

## 4. Build & package quick-ref
- Native build on a canonical arm64 box: install toolchain via DeBeOS repo
  (`graviton/scripts/haiku-provision-native-builder`), `make lib` for mbedTLS, then
  compile/link the agent (direct g++ works; the cross Makefile is optional).
- Package: pkgroot = `bin/haiku-mgmt-agent` + `data/launch/haiku-mgmt-agent` +
  `data/licenses/<license>` + `.PackageInfo` (name `haiku_mgmt_agent`, arch arm64,
  vendor **DeBeOS**, `requires { haiku }`, mandatory `licenses{}`+`copyrights{}`).
  `package create -C pkgroot haiku_mgmt_agent-<ver>-arm64.hpkg`.
- Publish to the DeBeOS CDN repo via `graviton/scripts/haiku-repo-publish-remote`.
- Reproducible packaging now lives in-repo: `packaging/build-hpkg.sh` (+
  `packaging/PackageInfo.in`, `LICENSE`, `packaging/launch/haiku-mgmt-agent-packaged`).
  v0.1.0 was packaged by hand; v0.2.0 uses the script.

### First-hop install caveat (0.1 → 0.2)
A running instance has no downloader (no aws CLI / wget / curl on the base image) and
v0.1.0 has no `s3 cp`, so the **first** upgrade cannot pull its own artifact. Options:
publish the hpkg to the DeBeOS CDN repo and `pkgman install` (pkgman fetches over
https — the intended path, and it also arms F3 for every later upgrade); or transfer
once over SSH (keys) / a shared-SG HTTP port. Once v0.2.0 is on a node, its own `s3 cp`
and `--update-manifest` self-update make all subsequent hops network-autonomous.
