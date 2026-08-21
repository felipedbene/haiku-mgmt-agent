# Design Doc: Remote Management for Haiku on EC2 ("SSM for Haiku")

**Status:** Draft
**Date:** 2026-08-20
**Author:** Felipe de Bene
**Related:** felipedbene/Haiku-Graviton, felipedbene/haiku-on-ec2

## 1. Context

Haiku now boots natively on EC2 Graviton (2/3/3E) with a working ENA driver, SSH access, and a browser-based remote desktop (app_server remote mode over SSH tunnel + websockify). The AMI is distributed as build-your-own via the companion repo.

What's missing is a *management plane*: today every instance is a pet. There is no way to run a command across N Haiku instances, collect inventory, or get a shell without pre-shared SSH keys. On Linux this is what amazon-ssm-agent provides (Run Command, Session Manager, inventory, patching).

Question under evaluation: can we get SSM Agent — or an SSM-equivalent capability — on Haiku/ARM64?

### Hard constraints

- **No Go toolchain for haiku/arm64.** The Haiku Go port (1.18, via pkgman) is x86_64 only. amazon-ssm-agent is ~99% Go. Cross-compiling requires a Go runtime port to haiku/arm64 that does not exist.
- **SSM Agent assumes Linux.** systemd/init lifecycle, `ssm-user` + sudo provisioning, Linux PTY ioctls for Session Manager, FHS paths (`/etc/amazon/ssm`), rpm/deb packaging.
- **What works for free:** IMDSv2 (`169.254.169.254`) is plain HTTP — instance identity, region, and IAM role credentials are already reachable from Haiku. ~~Curl and OpenSSL exist on Haiku. The C++ toolchain is first-class (it built the OS).~~
  > **Amendment, 2026-08-20 (Stage 1 spike):** the struck-through claim is **false for haiku/arm64**. It holds for Haiku/x86_64. On the canonical arm64 AMI there is no OpenSSL, no HTTPS-capable curl, no CA bundle and no compiler; HaikuPorts publishes no arm64 repository at all. IMDSv2 is reachable at the TCP level but there is no HTTP client to talk to it. A TLS stack for haiku/arm64 is therefore a **hard prerequisite for Phase 1**, not a given. See [`../NOTES.md`](../NOTES.md) §1 and §4.
- **One-person project, nights and weekends, competing with Stage 2 of the remote desktop work.** Scope discipline is a requirement, not a nice-to-have.

## 2. Decision (proposed)

Do **not** port amazon-ssm-agent. Build capability in phases, cheapest first:

- **Phase 0 (now):** SSH-based fleet orchestration from a Linux control point. Zero new code on Haiku.
- **Phase 1 (the real project):** `haiku-mgmt-agent` — a small native C++ daemon implementing the minimum SSM wire protocol: SigV4-signed calls to ec2messages (MDS) long-poll, execute `AWS-RunShellScript` documents via `/bin/sh`, report results. Run Command works from the AWS console/CLI against Haiku instances.
- **Phase 2 (explicitly parked):** Session Manager (MGS websocket protocol), inventory, self-update. Not in scope until Phase 1 is proven.

## 3. Options Considered

### Option A — Port Go runtime to haiku/arm64, then build amazon-ssm-agent

| Dimension | Assessment |
|-----------|------------|
| Complexity | Very high (two stacked porting projects) |
| Time to first value | Many months, possibly never |
| Maintenance | Fork of Go toolchain + fork of ssm-agent, forever |
| Reuse by others | High (a Go port would benefit all Haiku/ARM64) |

**Pros:**
- Unmodified SSM semantics; future agent features come "for free" after rebase
- A haiku/arm64 Go port is a genuinely valuable contribution on its own

**Cons:**
- Runtime port = syscall layer, signal handling, TLS/G-register conventions, netpoller mapping onto Haiku primitives, `spawn_thread`/`find_thread` semantics — comparable in effort to the ENA driver work, but against a moving upstream
- After all that, the agent itself still needs patching for its Linux assumptions (init, users, PTYs, paths)
- Two upstreams to track (golang/go and aws/amazon-ssm-agent), neither of which will take Haiku patches

### Option B — Minimal native agent in C++ speaking the SSM protocol

| Dimension | Assessment |
|-----------|------------|
| Complexity | Medium (bounded: SigV4 + one long-poll API + shell exec) |
| Time to first value | Weeks of evenings for Run Command MVP |
| Maintenance | Small codebase we own; AWS API surface is stable/versioned |
| Reuse by others | Medium (useful to any exotic-OS-on-EC2 effort) |

**Pros:**
- Uses the toolchain that already works (C++/OpenSSL/curl on Haiku)
- Credentials via IMDSv2 role — no registration, no secrets on disk
- Instance shows up as managed in the SSM console; Run Command "just works" from the AWS side
- Naturally scoped: each capability (inventory, sessions) is an explicit later decision, not a dependency

**Cons:**
- MDS long-poll protocol is not publicly documented as a spec; must be derived from the open-source agent's Go code (it is Apache-2.0, so reading it is fine)
- Session Manager (MGS) is a separate, harder protocol (websocket + binary framing + KMS handshake) — deliberately out of MVP
- We own the security posture of a daemon that executes remote commands as root

### Option C — No agent on Haiku: SSH-based orchestration from outside

| Dimension | Assessment |
|-----------|------------|
| Complexity | Low (config, not code) |
| Time to first value | Same day |
| Maintenance | Near zero |
| Reuse by others | Low (it's just SSH) |

**Pros:**
- Works today with the existing AMI (cloud-init-lite already injects the launcher's key)
- A Linux bastion with ssm-agent can proxy: SSM → bastion → `ssh haiku-instance 'cmd'` — gives console-triggered fleet commands without touching Haiku
- Zero new attack surface on the Haiku side

**Cons:**
- Haiku instances never appear as managed nodes; no per-instance IAM story
- Key distribution is the control plane — exactly the pet problem, automated
- Doesn't advance the "Haiku as a first-class EC2 citizen" narrative

## 4. Trade-off Analysis

Option A is rejected on effort/value: it front-loads the hardest possible work (a language runtime port) before delivering any management capability, and it creates two permanent forks. If a haiku/arm64 Go port ever becomes desirable, it should be its own project with its own justification — not a dependency of remote management.

Option C costs nothing and should exist regardless — it is the operational fallback and the comparison baseline. But it doesn't produce the interesting artifact.

Option B is the right shape: it converts "port two ecosystems" into "implement one narrow, stable wire protocol with tools that already work on the platform." The MDS surface needed for Run Command is small: SigV4 signing, `GetMessages` long-poll, `SendReply`/`AcknowledgeMessage`, document parse, shell exec, S3/inline output upload. Everything else is optional and separable.

## 5. Proposed Architecture (Phase 1: haiku-mgmt-agent)

```
┌──────────────────────────────── Haiku instance ───┐
│  haiku-mgmt-agent (C++ daemon, launched at boot)  │
│   ├─ creds: IMDSv2 → role creds, auto-refresh     │
│   ├─ mds client: SigV4 + HTTPS long-poll          │
│   │    (libcurl + OpenSSL)                        │
│   ├─ executor: parse AWS-RunShellScript doc,      │
│   │    run via /bin/sh, capture stdout/stderr,    │
│   │    enforce timeouts                           │
│   └─ reporter: SendReply + health ping            │
└───────────────────────────────────────────────────┘
            │ HTTPS (443) outbound only
            ▼
   ec2messages.<region>.amazonaws.com  (MDS)
   ssm.<region>.amazonaws.com          (health/UpdateInstanceInformation)
```

Design points:

- **Single binary, single thread pool, no plugin system.** The Go agent's worker/IPC architecture exists for features we are not building.
- **Registration:** none needed on EC2 — `UpdateInstanceInformation` with role creds makes the instance appear as managed. Report `PlatformType` honestly (likely as Linux for console compatibility, with `PlatformName: Haiku` — verify what the console tolerates).
- **Execution model:** MVP supports exactly one document type, `AWS-RunShellScript`, executed with `/bin/sh -c`. Unknown plugins are reported as Failed/Unsupported, never silently skipped.
- **Boot integration:** Haiku UserBootscript or a proper launch_daemon entry; logs to `/var/log/haiku-mgmt-agent.log`.
- **Security:** outbound-only; no listening sockets. Command execution as root is the SSM model, gated by IAM on the AWS side. `DeniedPortForwardingRemoteIPs`-style protections are irrelevant until sessions exist.
- **Protocol source of truth:** the Apache-2.0 Go agent source (`agent/` and `core/` trees) — read for wire format and error semantics, not translated line-by-line.

## 6. Consequences

**Easier:**
- Fleet operations on Haiku instances from the AWS console/CLI
- Demos: "Run Command against a Haiku box" is a strong artifact for the repo/blog
- Future exotic ports (anyone's) get a reference minimal-agent

**Harder:**
- We own a security-sensitive daemon; protocol changes on AWS's side are our problem to track (mitigated: MDS has been stable for years and the open-source agent telegraphs changes)
- Session Manager expectations: people will ask for it; the answer is "Phase 2, maybe" (fallback: existing SSH + remote desktop path)

**Revisit when:**
- Haiku's Go port grows arm64 support upstream → re-evaluate Option A economics
- MGS protocol is needed badly enough to justify Phase 2

## 7. Open Questions

1. ~~Does the SSM console/`DescribeInstanceInformation` accept an unknown `PlatformName`?~~ **Answered at the wire level (§9.2): `PlatformType` is a closed enum (Windows | Linux | MacOS), `PlatformName`/`PlatformVersion` are free-form strings.** Residual risk is console/`DescribeInstanceInformation` *presentation* only — still worth eyeballing once during the §8.1 spike.
2. ~~MDS vs. the newer MGS-based Run Command delivery.~~ **Answered: MDS long-poll alone is sufficient. MGS is preferred-when-available, not required; the agent itself declares which channel it uses. See §9.**
3. TLS trust store on Haiku: is the shipped CA bundle current enough for AWS endpoints, and who updates it in the AMI?
4. Licensing/optics: personal-account project by an AWS employee reimplementing an AWS agent protocol — same review as the AMI decision (probably fine since it's a client of public APIs with role creds, but flag it before publishing).
5. Timeout/zombie semantics: Haiku's `wait_for_thread`/POSIX wait behavior under `/bin/sh` timeouts — needs a test matrix before trusting it with fleet commands.

## 8. Action Items (Phase 1 MVP)

1. [ ] Spike: from a Haiku instance, sign and send `ssm:UpdateInstanceInformation` with IMDSv2 role creds (curl + manual SigV4 first, then C++). Success = instance visible as managed node. Send `PlatformType=Linux`, `PlatformName=Haiku`, `SSMConnectionChannel=ec2messages` (§9.2).
2. [x] ~~Answer open question #2 (MDS sufficiency) by reading current agent source.~~ Done — see §9. MDS-only is sufficient and is a first-class supported agent state. Live-queue confirmation folded into item 5.
3. [ ] Implement MDS long-poll loop + `AWS-RunShellScript` executor + `SendReply`.
4. [ ] launch_daemon integration + log rotation; bake into the canonical AMI build docs.
5. [ ] End-to-end demo: `aws ssm send-command` → output in console from a t4g.small running Haiku. Blog it.
6. [ ] Decide Phase 2 (sessions/inventory) only after the MVP has run for a while.

## 9. Findings: MDS Sufficiency (Open Question #2)

Source read: `aws/amazon-ssm-agent` at `VERSION` **3.3.0.0** (commit `b05af2a`). Citations are file:line in that tree.

### 9.1 Verdict

**MDS long-poll alone is sufficient for Run Command. The MVP does not need the MGS control channel.**

The choice of channel is made *by the agent*, not imposed by the service, and the agent's own fallback path is exactly the design in §5. Chain of evidence:

- **Both interactors are independent and optional.** `messageservice.go:73-87` appends `MGSInteractor` (skipped on Nano Server) and `MDSInteractor` (skipped in container mode) to a list; each is initialized in its own goroutine and each registers its own document processor. Neither depends on the other.
- **MGS-first-with-MDS-fallback is the documented behavior, not MGS-only.** `RELEASENOTES.md:659` (v3.1.821.0, when the unified `MessageService` landed): *"Receive run command documents through MGS if connected and fallback to MDS otherwise. This functionality requires appropriate permissions for both endpoints…"* — and `RELEASENOTES.md:350` (v3.3.40.0): *"Update Messaging module to switch off ec2messages when ssmmessages connected successfully."* MDS is turned **off** as an optimization once MGS works; it is not deprecated.
- **The agent tells the service which channel it is on.** `UpdateInstanceInformation` carries an `SSMConnectionChannel` field (`agent/ssm/service.go:272`), sourced from `ssmconnectionchannel.GetConnectionChannel()` at `agent/health/healthcheck.go:224-226`, whose values are literally `"ec2messages"` / `"ssmmessages"` (`agent/contracts/model.go:177-178`). A client that only ever reports `ec2messages` is describing a state the service already handles.
- **Reply payloads carry the same signal.** `AbleToOpenMGSConnection *bool` in `additionalInfo` (`agent/contracts/model.go:270`, populated in `agent/messageservice/utils/messageutil.go:302-323`) — set to `false` whenever the control channel fails to open (`mgsinteractor.go:199-201`, `controlchannel.go:136-137`). Again: "MGS unavailable" is a first-class, reported condition, not an error state.
- **MGS failure is explicitly non-fatal.** `ssmconnectionchannel.go:76-98`: on `MGSFailedDueToAccessDenied` the agent switches MDS back **on**; on any other MGS failure the channel stays/defaults to MDS. And `RELEASENOTES.md:69` downgraded `ec2messages` access-denied to a debug log to reduce noise — i.e. running with only one of the two endpoints reachable is a normal deployment.

**What MDS-only costs us:** nothing in MVP scope. One real item: `mdsinteractor.go:278-283` notes *"document with updateAgent plugin comes only via MDS"* — self-update arrives over MDS, which is convenient rather than a problem, since we are not implementing it. Session Manager is MGS-only and stays parked (§2, Phase 2).

**Residual risk to watch:** AWS could eventually require MGS for new Run Command delivery. The tell would be release notes deprecating `ec2messages`, or `GetMessages` returning empty while `send-command` shows the instance as unreachable. Mitigation is the item-5 live test, then periodic re-runs.

### 9.2 Wire details harvested for Phase 1

Concrete enough to skip re-deriving during implementation.

**MDS endpoint / protocol** — `vendor/github.com/aws/aws-sdk-go/service/ssmmds/service.go:33-75`:

| Property | Value |
|---|---|
| Endpoint | `ec2messages.<region>.amazonaws.com` (HTTPS, POST to `/`) |
| SigV4 signing name | `ec2messages` |
| Protocol | AWS JSON 1.1 (`Content-Type: application/x-amz-json-1.1`) |
| API version | `2015-06-19` |
| Target prefix | `X-Amz-Target: EC2WindowsMessageDeliveryService.<Operation>` |

The `EC2Windows…` target prefix is a historical artifact — it is the target for all platforms. Full operation set: `GetMessages`, `AcknowledgeMessage`, `SendReply`, `FailMessage`, `DeleteMessage`, `GetEndpoint` (`ssmmds/api.go`). MVP needs the first three; `FailMessage` for malformed documents.

**The poll loop** (`agent/runcommand/mds/service.go:145-152`, `mdsinteractor.go:430-469`):
- `GetMessages{ Destination: <instance-id>, MessagesRequestId: <uuid v4>, VisibilityTimeoutInSeconds: 10 }`
- HTTP client timeout is `Mds.StopTimeoutMillis`, default **20 s** (`appconfig/constants.go:51`) — that is the long-poll ceiling.
- Reference agent re-polls immediately on return, but sleeps `2000 + rand(500) ms` if the call returned in under a second, to avoid hammering the service on fast-empty responses. Worth copying verbatim.

**Message dispatch** (`mdsinteractor.go:483-555`): switch on `Topic` prefix — `aws.ssm.sendCommand` vs `aws.ssm.cancelCommand` (`messageutil.go:58-62`). `MessageId` format is `aws.ssm.<command-id>.<instance-id>`; the command ID is parsed out by string split (`runcommand/contracts/model.go:50-66`).

**Payload shapes** (`agent/runcommand/contracts/model.go:30-48`): `SendCommandPayload` (`DocumentContent`, `Parameters`, `CommandId`, `DocumentName`, `OutputS3BucketName`/`KeyPrefix`, CloudWatch fields) in, `SendReplyPayload` (`additionalInfo`, `documentStatus`, `documentTraceOutput`, `runtimeStatus`) out.

**Required ack sequence per message** (`mdsinteractor.go:545-554`) — order matters:
1. `SendReply` with status `InProgress`
2. `AcknowledgeMessage{MessageId}`
3. execute, then `SendReply` with the terminal status

The reference agent persists replies to disk on send failure and retries every 5 minutes (`mdsinteractor.go:613-646`); MVP can start with in-memory retry and add persistence when it bites.

**Identity fields for `ssm:UpdateInstanceInformation`** (`agent/ssm/service.go:266-327`, and the SDK shape at `.../service/ssm/api.go:74673-74690`):
- `PlatformType` — closed enum, `Windows | Linux | MacOS`; the Go agent hard-errors on any other GOOS (`service.go:295-297`). **Report `Linux`.**
- `PlatformName`, `PlatformVersion` — plain `type:"string"`, no enum, no length constraint. **`PlatformName: "Haiku"` is wire-legal.** This is the "honest where we can, compatible where we must" split flagged in §5.
- `SSMConnectionChannel` — plain string, send `ec2messages`.
- Health ping cadence: default **5 min**, clamped to the service's min/max (`healthcheck.go:258-274`).
