# haiku-mgmt-agent

A minimal native SSM-compatible management agent for **Haiku on EC2 Graviton
(arm64)** — enough of the AWS Systems Manager wire protocol that a Haiku instance
shows up as a managed node and runs `AWS-RunShellScript` commands from the AWS
console or CLI.

Companion to [`haiku-graviton`](https://github.com/felipedbene/Haiku-Graviton) and
[`haiku-on-ec2`](https://github.com/felipedbene/haiku-on-ec2).

## Status: Phase 1 MVP working

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

haiku/arm64 has **no OpenSSL, no HTTPS-capable curl, no compiler, and no package
repository at all** (HaikuPorts publishes `["riscv64", "x86_64", "x86_gcc2"]`).
The agent therefore:

- **carries its own TLS**: mbedTLS 3.6.2, cross-compiled and statically linked
- **implements its own HTTP/1.1 client** (`src/http.cpp`) instead of libcurl
- **implements SigV4 and JSON from scratch** (`src/aws.cpp`, `src/json.cpp`) —
  there is no jq and no JSON library to link
- **ships its own trust anchors** (`src/ca_certs.h`) — there is no system CA store
- **fixes the system clock** from IMDS's HTTP `Date` header, because Haiku on EC2
  boots at 1970-01-01 with no NTP client, which otherwise breaks TLS *and* SigV4

The whole thing is one 1.35 MB binary whose only runtime dependencies are
`libroot`, `libnetwork` and `libstdc++`, all present on the canonical AMI.

## Scope

**In (Phase 1):** MDS long-poll (`GetMessages`/`AcknowledgeMessage`/`SendReply`/
`FailMessage`), `aws:runShellScript` via `/bin/sh -c`, inline output, per-command
timeouts, dedup by CommandId, health ping, launch_daemon integration.

**Out, deliberately:** MGS/`ssmmessages` in any form, Session Manager, inventory,
self-update, S3/CloudWatch output. Anything other than `aws:runShellScript`
returns a terminal `Failed` explaining it is unsupported — never a silent skip,
which matters because DHMC pushes association documents at instances regardless.

MDS-only is sufficient and supported: the agent declares
`SSMConnectionChannel: ec2messages`, and MGS is preferred-when-available rather
than required. Evidence in `docs/BRIEF.md` §9.1.

## Build

Cross-compiled; there is no native toolchain on the target. On an Ubuntu arm64
host with the Haiku tree at `/opt/haiku/haiku`:

```sh
# 1. Haiku arm64 cross-tools + a jam build (provides the sysroot's crt glue)
cd /opt/haiku/haiku && mkdir -p generated.arm64 && cd generated.arm64
../configure --build-cross-tools arm64 --cross-tools-source /opt/haiku/buildtools -j$(nproc)
jam -q -j$(nproc) @minimum-raw

# 2. Sysroot + static TLS
./tools/stage-sysroot.sh
./tools/build-mbedtls.sh

# 3. The agent
make            # -> build/haiku-mgmt-agent
make check      # host-side unit tests (needs libmbedtls-dev)
```

## Install on a Haiku instance

The instance needs an IAM role with `AmazonSSMManagedInstanceCore`.

```sh
KEY=~/.ssh/haiku-graviton-ed25519          # ed25519 only; RSA will not work
scp -i $KEY build/haiku-mgmt-agent            baron@<ip>:/tmp/
scp -i $KEY packaging/launch/haiku-mgmt-agent baron@<ip>:/tmp/launch-job

ssh -i $KEY baron@<ip>
  mkdir -p /boot/system/non-packaged/bin
  cp /tmp/haiku-mgmt-agent /boot/system/non-packaged/bin/
  chmod +x /boot/system/non-packaged/bin/haiku-mgmt-agent
  cp /tmp/launch-job /boot/system/settings/launch/haiku-mgmt-agent
  sync    # NOT optional -- see TESTING.md 5.3
```

`sync` matters: an unclean stop (and EC2 has to force-stop Haiku, see
TESTING.md §5.2) can leave a just-written file with the right length and garbage
contents.

Verify without waiting for a boot:

```sh
/boot/system/non-packaged/bin/haiku-mgmt-agent --ping-once --log-level debug
```

## Usage

```
haiku-mgmt-agent [options]
  --ping-once      send one UpdateInstanceInformation and exit
  --poll-once      run a single MDS poll cycle and exit
  --no-time-sync   do not set the system clock from IMDS
  --foreground     log to stderr as well as the log file
  --log-file PATH  default /var/log/haiku-mgmt-agent.log
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
