# Testing — haiku-mgmt-agent

## Phase 3 (v0.4.0, `phase3-patch-manager`) — host-validated, live gates PENDING

**Date:** 2026-08-29. Host-side: 209/209 unit checks pass (`make check`),
covering F5 (pkgman-transaction parser, patch params/inventory-item builders,
schema-2.2 precondition skip) and F6 (base64/WebSocket-accept vectors, RFC 6455
frame round-trip, MGS `AgentMessage` serialize/deserialize incl. the UUID
half-swap and payload-digest rejection, and session/handshake JSON parsing).
`main`, `session`, `mgs`, `websocket`, `selfupdate` and `timesync` compile
warning-free (`-Wall -Wextra`).

Live gates for F6 (Session Manager — need a Haiku node + human authorization;
see the F6 block in `docs/design-roadmap.md`):

| Gate | Result |
|---|---|
| `posix_openpt`/`grantpt`/`unlockpt`/`ptsname` work on haiku/arm64 | PENDING — make-or-break |
| Control channel opens (CreateControlChannel + signed WS upgrade) | PENDING |
| `aws ssm start-session --target <id>` reaches an interactive prompt | PENDING |
| Keystrokes echo; `ls`/`env` run; terminal resize (`TIOCSWINSZ`) applies | PENDING |
| `exit` closes cleanly; console shows session Terminated | PENDING |
| Run Command (MDS) still works with the control channel also open | PENDING |

The MGS wire format (binary `AgentMessage`, signed WS upgrade, handshake) is
unit-tested against the documented Go-agent layout, not yet against the live
service; the pty layer is the single largest unknown.

**Live battle-test 2026-08-29 (issue #2, commit cd92680, c7g.large, native
Haiku build).** F5 Patch Manager PASSED live end to end — `AWS-RunPatchBaseline`
Scan/Install intercepted, `PutInventory` accepted (`AWS:PatchSummary` visible via
`list-inventory-entries`), and the parser matched real pkgman phrasing
(`upgrade package sed-4.9_bootstrap-1 to 4.9-1 from repository DeBeOS`). Run
Command with the control channel concurrently open, and CancelCommand, also
PASSED. **F6 FAILED (pty unreachable)** on two live-wire divergences the
host tests missed because they used the documented layout, not the live bytes:
1. the live `interactive_shell` envelope uses a **lowercase `content`** key
   (Go's `json` is case-insensitive; our parser was not) → inner parse failed,
   no shell;
2. `mgs::deserialize` **verified the inbound payload digest and sliced payload by
   PayloadLength**; the reference Go agent does neither (it takes
   `input[HeaderLength+4:]` and never checks the digest), and the live service's
   digest for the HandshakeResponse didn't match our computation → the handshake
   was silently dropped and the pty never forked.

Both fixed and regression-tested (216/216 host checks). The pty layer itself
(`posix_openpt` et al., echo, resize, exit) is **still UNVERIFIED** — it was
unreachable until the handshake completes, so F6 needs a re-run on hardware.

## Phase 3 (v0.3.0) — Patch Manager, host-validated, live gates PENDING

Live gates for F5 (need a Haiku node + the usual human authorization; see the
F5 *Verify* block in `docs/design-roadmap.md`):

| Gate | Result |
|---|---|
| `patch scan` on-box CLI: readable list, PutInventory accepted | PENDING |
| `send-command --document-name AWS-RunPatchBaseline` Operation=Scan | PENDING |
| Operation=Install applies updates; re-scan shows Missing→0 | PENDING |
| `describe-instance-patch-states` reflects the reported counts | PENDING |
| pkgman transaction phrasing matches `parse_pkgman_transaction` vectors | PENDING |
| Cancel mid-install: process group killed, step `Cancelled` | PENDING |

Known risk to check first on hardware: the exact wording of pkgman's
transaction listing (the parser tolerates both "to <ver>" and "to version
<ver>" plus "from repository <name>" tails) and whether PutInventory accepts
the `AWS:PatchSummary`/`AWS:PatchCompliance` 1.0 attribute sets as built in
`patch::inventory_items` — both are unit-tested against assumptions, not
against the live service yet.

## Phase 2 (v0.2.0) verification state

**Date:** 2026-08-29. Host-side: 100/100 unit checks pass (`make check`),
including the new S3 request-shape, URI-encoding, version-compare,
cancellation, full-capture and streamed-sha256 tests; `main`, `selfupdate`
and `timesync` compile warning-free.

**Exercised live on Haiku hardware (2026-08-29, node i-01fe92119d18f09c8,
hrev59996 arm64):** all Phase-2 gates PASS.

| Gate | Result |
|---|---|
| F1 S3 round-trip, 64 MiB (`s3 cp` up then down) | PASS — 82/71 MiB/s, sha256 identical |
| F1 large transfer, 512 MiB | PASS — 107/41 MiB/s, sha256 identical, no OOM (streamed) |
| F2 S3 output, 5000-line log | PASS — full log in S3 at the standard SSM key layout; inline clipped as designed |
| CancelCommand | PASS — reports `Cancelled`, `sleep` killed, post-sleep line never ran |
| Concurrency, 4 workers | PASS — ran in parallel (~4 s window), poll loop not blocked |
| Rapid-fire, 12 back-to-back | PASS — 12/12, dedup + poll loop stable |
| F3 self-update 0.2.0 → 0.2.1 | PASS — manifest → sha256 verify → pkgman install → launch_roster restart; `describe-instance-information` then reports AgentVersion 0.2.1 |

Test fixtures were in a scoped account/bucket with a least-privilege role
(`s3:GetObject`/`PutObject`/`ListBucket` on the one bucket); the agent used the
instance role via IMDS for all S3 calls.

# Phase 1

**Date:** 2026-08-21
**Target:** `i-046a6d266c6c63e83`, t4g.medium, `ami-0c17f56477d32638f`
(`haiku-arm64-hrev59996-stage-a`, tagged `canonical=true`), Haiku
`R1~beta6+development hrev59996+dirty` arm64
**Build host:** `i-0f700cd427281e7d2`, c7g.4xlarge, Ubuntu 24.04 arm64

## 1. Build

Nothing is built natively on Haiku — there is no compiler on the target and no
package repository to get one from (NOTES.md §1). Everything cross-compiles:

| Step | Result |
|---|---|
| `configure --build-cross-tools arm64` (upstream haiku master + buildtools) | `aarch64-unknown-haiku-g++` 13.3.0 |
| `jam -q -j16 @minimum-raw` | 9247 targets, clean. Upstream master builds arm64 **without** the haiku-graviton patches (those add GICv3/PSCI/ENA, not build fixes) |
| `tools/stage-sysroot.sh` | sysroot at `/opt/haiku/sysroot-arm64`; hello-world links |
| `tools/build-mbedtls.sh` (mbedTLS 3.6.2, `make lib`) | `libmbedtls.a libmbedx509.a libmbedcrypto.a`, `elf64-littleaarch64`. Compiled clean first try, including `net_sockets.c` |
| `make` | `build/haiku-mgmt-agent`, 1.35 MB, warning-free |

Two portability fixes were needed for Haiku, both real gaps rather than
guesswork:

- **`timegm()` does not exist.** Replaced with a hand-rolled `days_from_civil`
  (`src/util.cpp`); `mktime()` would have applied a local timezone to what is
  always a UTC timestamp.
- **`settimeofday()` does not exist.** `clock_settime(CLOCK_REALTIME, …)` does
  and works as root (`src/timesync.cpp`).

## 2. Unit tests (host)

`make check` — 64 checks, 0 failures. Notable coverage:

- SigV4 derived signing key against **AWS's own documented test vector**
  (`c4afb1cc…a4b9`), plus SHA-256 vectors
- JSON: escapes, surrogate pairs, round trips, integers rendering as `0` not
  `0.0` (SSM's `code` is an int), and **malformed input reporting an error**
  rather than silently yielding an empty document
- `{{ commands }}` expanding a placeholder string into a StringList, document
  defaults, and unknown placeholders left verbatim
- `truncate_output` matching the Go agent's `iohandler.TruncateOutput`
- the unsupported-plugin path, and shell success / failure / timeout

## 3. Live tests

| # | Test | Result |
|---|---|---|
| 1 | `--ping-once` (Stage 1 gate) | **OK.** Node appears with `PlatformName: Haiku`, `PlatformVersion: hrev59996+dirty`, `AgentVersion: 0.1.0`, `PingStatus: Online` |
| 2 | Clock set to 1970, then `--ping-once` | **Self-recovers.** Reads IMDS `Date`, sets the clock, then signs successfully — unattended |
| 3 | `AWS-RunShellScript` `uname -a` | **Success**, code 0, real output. Run twice consecutively (`3234d769…`, `71cf8fe2…`) |
| 4 | Deliberate failure (`ls /nonexistent…; exit 42`) | **Failed**, code **42**, stderr captured verbatim (`03b6c354…`) |
| 5 | `AWS-UpdateSSMAgent` (unsupported plugins) | **Failed**, never silently skipped. Both steps report the reason at plugin level in the console (`aws:updateSsmAgent`, `aws:runPowerShellScript`) |
| 6 | `executionTimeout=30` with `sleep 300` | **Failed** after 34 s, code **143** (128+SIGTERM). See §4 |
| 7 | Cold boot (EC2 stop/start) | launch_daemon starts the agent as **pid 35**; first IMDS call fails `Network is unreachable`, retry succeeds 6 s later; clock corrected; registered |
| 8 | `AWS-RunShellScript` after that cold boot | **Success** (`b77fdf73…`) |

## 4. Open question 5 — timeout and reap semantics: answered

BRIEF.md §7.5 asked whether Haiku's wait/reap behaviour could be trusted for
fleet commands. Tested via test 6 above and directly:

- `kill(-pid, SIGTERM)` to the child's process group (the child `setsid()`s
  itself) **terminates the whole tree**, including `sleep` started by `/bin/sh`.
- The child is reaped **immediately** by the `waitpid(WNOHANG)` loop. The
  SIGTERM→SIGKILL escalation path (5 s grace) was never needed.
- `WIFSIGNALED` reports correctly: exit code surfaced as 143 = 128 + SIGTERM.
- **No zombies and no stray children** afterwards: `ps` showed no surviving
  `sleep 300`, and the process count returned to baseline.
- stdout produced before the kill is preserved (`starting-long-job` came back).

Verdict: reaping is trustworthy. No Haiku-specific weirdness observed. The 10 s
bounded reap wait in `src/exec.cpp` stays as a backstop, not a workaround.

## 5. Platform findings worth carrying to the AMI

These are Haiku-on-EC2 issues, not agent issues. They affect the wider
haiku-graviton work, so they are recorded here rather than only in code comments.

### 5.1 The clock boots at 1970-01-01 and nothing fixes it

No RTC read, and no NTP client of any kind on the image (`ntpd`, `ntpdate`,
`sntp`, `chronyd`, `rdate` are all absent). Consequences beyond this agent:

- **TLS fails outright**: mbedTLS rejected the AWS chain with *"The certificate
  validity starts in the future"* — the first symptom seen, before the cause.
- **SigV4 would fail too** even if TLS were skipped: `x-amz-date` would be 56
  years stale.

The agent fixes this itself: IMDS is plain HTTP on a link-local address, so its
`Date` header is readable when nothing else works. `src/timesync.cpp` sets the
clock from it at startup and re-checks every health cycle (5 min), since with no
NTP the clock will drift. `--no-time-sync` opts out.

**Recommendation for the AMI:** this is worth fixing at the OS level too, since
anything else needing TLS (pkgman, a future package install, a browser) hits it.

### 5.2 `ec2 reboot-instances` is ignored

The graceful ACPI reboot request had no effect: same PID, no new log lines, clock
untouched. A power cycle requires `stop-instances` + `start-instances`, and the
stop is therefore **forced** after EC2's grace period. Plausibly related to
`haiku-graviton/patches/proposed-arm64-teardown-panic.patch`.

### 5.3 An unclean stop can corrupt recently-written files

This one bit this project and cost a debugging cycle, so it is worth stating
plainly. After a forced stop, `/boot/system/settings/launch/haiku-mgmt-agent`
came back with **the correct length (1367 bytes) and garbage content** —
fragments of the ELF binary that had been copied to the same volume minutes
earlier, i.e. stale freed blocks. BFS journals metadata, not file data, so the
size survived while the unflushed data did not. launch_daemon then read a binary
blob, failed to parse it, and silently skipped the job — which looked exactly
like a wrong job definition.

**Always `sync` after writing to disk and before stopping the instance.** The
install steps in the README do this.

### 5.4 Missing userland tools to be aware of

Present: `bash`, `nohup`, `sync`, `sed`, `grep`, `find`, coreutils (`od`,
`b2sum`, …), `telnet`, `ssh`/`sshd` (built `--without-openssl`).

Absent, and each one broke something during this work: `curl`, `openssl`, `gcc`,
`make`, `python`, `wget`, `nc`, `jq`, `awk`, `setsid`, `xxd`, and `bash`'s
`/dev/tcp` (built without netredir). `nohup setsid …` fails silently if its
stderr is discarded — that cost a debugging cycle too.

## 6. Not exercised live

Stated explicitly so the matrix above is not read as broader than it is:

- **CommandId dedup.** Implemented (`SeenCommands` in `src/main.cpp`, marked
  before execution so a redelivery mid-run cannot start a second copy) and
  reachable in unit-test terms, but MDS never redelivered a message during these
  runs, so the re-acknowledge path has not fired against the real service. It is
  still mandatory rather than speculative: the visibility timeout is 10 s and
  commands can run far longer.
- **Credential expiry/refresh.** Role credentials were valid for the whole
  session (~6 h), so the refresh-on-`ExpiredToken` path is untested live.
- **Long-run stability.** Longest continuous run so far is minutes, not days. The
  clock re-check every health cycle exists precisely because drift is expected on
  a platform with no NTP, but that has not been observed over a long period yet.
- **Concurrent commands.** Not applicable — execution is deliberately serial.

## 7. Known limitations (not defects)

- **`cancelCommand` is acknowledged but not actioned.** Commands execute
  synchronously in the poll loop, so there is nothing in flight to interrupt when
  a cancel arrives. Logged explicitly at INFO.
- **A long command blocks polling.** The health-ping thread keeps the node
  registered, so the node does not go offline, but new commands wait. Acceptable
  for the MVP; concurrency is a Phase 2 decision.
- **Replies are retried in memory only.** The Go agent persists failed replies to
  disk and retries every 5 minutes; if the agent dies between execution and a
  successful `SendReply`, the result is lost and the command shows as InProgress
  until SSM times it out.
- **Timeout reports `TimedOut` at step level but the document shows `Failed`** in
  the console. That matches how the status is aggregated, and the exit code (143)
  makes the cause obvious.
