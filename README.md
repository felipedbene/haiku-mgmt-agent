# debeos_ssm_agent

An **independent, unofficial** SSM-compatible management agent for **DeBeOS on
EC2 Graviton (arm64)**. It is **not** AWS's official SSM agent and is not
affiliated with or endorsed by AWS — it is a clean-room client that implements
enough of the AWS Systems Manager wire protocol that a DeBeOS instance shows up
as a managed node and runs `AWS-RunShellScript` commands from the AWS console or
CLI. (DeBeOS is the ARM-first OS descended from Haiku/BeOS; "Haiku" below refers
to the kernel lineage wherever that is the accurate fact — the hrev, the 1970
boot clock, packagefs.)

Package name: `debeos_ssm_agent` (binary `debeos-ssm-agent`). Companion to
[`haiku-graviton`](https://github.com/felipedbene/Haiku-Graviton).

## Status: Phase 2 — fleet features on top of the proven Phase 1 MVP

Phase 2 (this tree, v0.2.0) adds, per [`docs/design-roadmap.md`](docs/design-roadmap.md):

- **F1 — native S3 transfer**: `debeos-ssm-agent s3 cp <local> s3://bkt/key` (and
  the reverse) with SigV4 `UNSIGNED-PAYLOAD` signing over the existing TLS stack,
  streaming both directions so a 400 MiB artifact never sits in RAM. Kills the
  scp publish-bridge and the wget source-seed shim.
- **F2 — S3 command output**: `send-command --output-s3-bucket-name ...` uploads the
  *full* stdout/stderr (up to 8 MiB per stream) to the standard SSM S3 layout and
  reports the location in the reply; inline output stays as the clipped fallback.
- **F3 — self-update**: `--update-manifest s3://...` polls a version manifest hourly
  and installs a strictly-newer `.hpkg` via `pkgman` (the running binary lives on
  read-only packagefs, so the update *is* a package operation), then restarts the
  service through `launch_roster`. Also available on demand: `debeos-ssm-agent
  self-update --manifest URI [--restart]`.
- **CancelCommand actually cancels**: commands now run on worker threads; a cancel
  kills the whole process group (SIGTERM, then SIGKILL) and reports `Cancelled`.

## Status: Phase 1 MVP working (hardware-verified)

```
$ aws ssm describe-instance-information --region us-west-2
InstanceId           PingStatus  PlatformType  PlatformName  PlatformVersion    AgentVersion
i-046a6d266c6c63e83  Online      Linux         Haiku         hrev59996+dirty    0.1.0
```

```
$ aws ssm send-command --instance-ids i-046a6d266c6c63e83 \
    --document-name AWS-RunShellScript --parameters 'commands=["uname -a"]'
Success
Haiku ip-10-42-0-85.us-west-2.compute R1~beta6+development hrev59996+dirty Aug 19 2026 22: arm64 other Haiku
```

Run Command, health ping, timeouts, and boot integration all verified on a real
instance — see [`TESTING.md`](TESTING.md) for the full matrix.

`PlatformType` is a closed enum (`Windows|Linux|MacOS`), so it reports `Linux`;
`PlatformName`/`PlatformVersion` are free-form and report the truth. That split
is deliberate — see `docs/BRIEF.md` §9.2.

## What made this non-trivial

At Phase-1 time, haiku/arm64 had **no OpenSSL, no HTTPS-capable curl, no
compiler, and no package repository at all** (HaikuPorts publishes
`["riscv64", "x86_64", "x86_gcc2"]`). The DeBeOS project has since closed much
of that gap — its own CDN package repository now vends OpenSSL, curl, a native
toolchain and Rust, and DeBeOS images seed the RTC from EFI `GetTime()` so the
clock no longer boots at 1970. The agent nevertheless **stays self-contained on
purpose**: it is the first thing that must work on a freshly booted *base*
image (it is how the instance becomes manageable at all), so it cannot assume
any package beyond the base set, and it still guards the clock for stock
upstream images and for drift (there is still no NTP client). The agent:

- **carries its own TLS**: mbedTLS 3.6.2, cross-compiled and statically linked
- **implements its own HTTP/1.1 client** (`src/http.cpp`) instead of libcurl
- **implements SigV4 and JSON from scratch** (`src/aws.cpp`, `src/json.cpp`) —
  there is no jq and no JSON library to link
- **ships its own trust anchors** (`src/ca_certs.h`) — there is no system CA store
- **guards the system clock** from IMDS's HTTP `Date` header. On stock upstream
  images Haiku on EC2 boots at 1970-01-01 (which breaks TLS *and* SigV4); DeBeOS
  images now seed the RTC from EFI `GetTime()`, but there is still no NTP
  client, so the agent corrects any drift beyond 60 s either way

The whole thing is one 1.35 MB binary whose only runtime dependencies are
`libroot`, `libnetwork` and `libstdc++`, all present on the canonical AMI.

## Scope

**In (Phase 1):** MDS long-poll (`GetMessages`/`AcknowledgeMessage`/`SendReply`/
`FailMessage`), `aws:runShellScript` via `/bin/sh -c`, inline output, per-command
timeouts, dedup by CommandId, health ping, launch_daemon integration.

**In (Phase 2):** native S3 GET/PUT (`s3 cp`), `OutputS3BucketName`/
`OutputS3KeyPrefix` command output, manifest-driven self-update, real
CancelCommand (worker-thread execution + process-group kill), credential
refresh-and-retry on expired-token rejections mid-transfer.

**Out, deliberately:** MGS/`ssmmessages` in any form, Session Manager, inventory,
CloudWatch output. Anything other than `aws:runShellScript`
returns a terminal `Failed` explaining it is unsupported — never a silent skip,
which matters because DHMC pushes association documents at instances regardless.

MDS-only is sufficient and supported: the agent declares
`SSMConnectionChannel: ec2messages`, and MGS is preferred-when-available rather
than required. Evidence in `docs/BRIEF.md` §9.1.

## Build

The agent builds **natively** on a DeBeOS arm64 box now (the DeBeOS repo vends a
native gcc/g++ toolchain): stage mbedTLS, then `make CXX=g++ STRIP=strip
MBEDTLS=<path-to-static-mbedtls>` produces `build/debeos-ssm-agent`, and
`packaging/build-hpkg.sh` (with the native `package` tool) produces the hpkg. The
cross-compile recipe below still works from a non-DeBeOS host with the Haiku tree
at `/opt/haiku/haiku`:

```sh
# 1. Haiku arm64 cross-tools + a jam build (provides the sysroot's crt glue)
cd /opt/haiku/haiku && mkdir -p generated.arm64 && cd generated.arm64
../configure --build-cross-tools arm64 --cross-tools-source /opt/haiku/buildtools -j$(nproc)
jam -q -j$(nproc) @minimum-raw

# 2. Sysroot + static TLS
./tools/stage-sysroot.sh
./tools/build-mbedtls.sh

# 3. The agent
make            # -> build/debeos-ssm-agent
make check      # host-side unit tests (needs libmbedtls-dev)
```

## Install on a DeBeOS instance

The instance needs an IAM role with `AmazonSSMManagedInstanceCore`.

**Preferred — from the DeBeOS package repository** (the image already has the
DeBeOS repo configured; this also arms F3 self-update for every later upgrade):

```sh
pkgman refresh
pkgman install debeos_ssm_agent
# binary lands at /boot/system/bin/debeos-ssm-agent
# launch_daemon job at /boot/system/data/launch/debeos_ssm_agent (starts on boot)
```

**Manual — non-packaged install** (dev/one-off, no repo needed):

```sh
KEY=~/.ssh/haiku-graviton-ed25519          # ed25519 only; RSA will not work
scp -i $KEY build/debeos-ssm-agent            baron@<ip>:/tmp/
scp -i $KEY packaging/launch/debeos_ssm_agent baron@<ip>:/tmp/launch-job

ssh -i $KEY baron@<ip>
  mkdir -p /boot/system/non-packaged/bin
  cp /tmp/debeos-ssm-agent /boot/system/non-packaged/bin/
  chmod +x /boot/system/non-packaged/bin/debeos-ssm-agent
  cp /tmp/launch-job /boot/system/settings/launch/debeos_ssm_agent
  sync    # NOT optional -- see TESTING.md 5.3
```

`sync` matters: an unclean stop (and EC2 has to force-stop Haiku, see
TESTING.md §5.2) can leave a just-written file with the right length and garbage
contents.

Verify without waiting for a boot:

```sh
/boot/system/non-packaged/bin/debeos-ssm-agent --ping-once --log-level debug
```

## Usage

```
debeos-ssm-agent [options]
  --ping-once      send one UpdateInstanceInformation and exit
  --poll-once      run a single MDS poll cycle and exit
  --no-time-sync   do not set the system clock from IMDS
  --foreground     log to stderr as well as the log file
  --log-file PATH  default /var/log/debeos-ssm-agent.log
  --log-level L    debug|info|warn|error
```

Outbound only — the agent never listens on a socket.

## Demo

```sh
IID=i-046a6d266c6c63e83

# 1. It is a managed node
aws ssm describe-instance-information --filters "Key=InstanceIds,Values=$IID"

# 2. Run Command succeeds, with output
aws ssm send-command --instance-ids $IID --document-name AWS-RunShellScript \
  --parameters 'commands=["uname -a","id","df -h /boot | head -3"]'

# 3. Failures report properly: Failed, exit code 42, stderr captured
aws ssm send-command --instance-ids $IID --document-name AWS-RunShellScript \
  --parameters 'commands=["echo about-to-fail","ls /nonexistent-path-xyz","exit 42"]'

# 4. Timeouts are enforced: Failed with code 143 (128+SIGTERM) after ~30s
aws ssm send-command --instance-ids $IID --document-name AWS-RunShellScript \
  --parameters 'commands=["sleep 300"],executionTimeout=["30"]'

# 5. Unsupported plugins fail loudly instead of silently
aws ssm send-command --instance-ids $IID --document-name AWS-UpdateSSMAgent

# fetch any result
aws ssm get-command-invocation --command-id <id> --instance-id $IID
```

## Layout

| Path | What |
|---|---|
| [`docs/BRIEF.md`](docs/BRIEF.md) | Design doc / ADR. §9 is the MDS wire-protocol reference. **Canonical copy.** |
| [`NOTES.md`](NOTES.md) | Spike log and the TLS decision that shaped the design |
| [`TESTING.md`](TESTING.md) | Test matrix, plus Haiku-on-EC2 platform findings |
| `src/` | The agent. `http.cpp` = TLS/HTTP, `aws.cpp` = SigV4 + API, `runner.cpp` = documents, `exec.cpp` = process control, `timesync.cpp` = the clock |
| `tools/` | Cross-build helpers |
| `packaging/launch/` | launch_daemon job definition |
| [`spike/sigv4-post.sh`](spike/sigv4-post.sh) | The shell SigV4 signer from Stage 1; still handy for poking the API by hand |
