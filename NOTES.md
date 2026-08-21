# Spike Notes — haiku-mgmt-agent Phase 1

**Date:** 2026-08-20
**Design doc:** [`docs/BRIEF.md`](docs/BRIEF.md) (§9 = MDS wire protocol findings)

---

## 0. Status: Stage 1 gate NOT passed — blocked, not failed

`ssm:UpdateInstanceInformation` was **never successfully sent from the Haiku instance**, because
the canonical Haiku/arm64 image has **no TLS capability of any kind**. This is a platform
blocker, not an AWS rejection, and not an IAM problem.

Per the Stage 1 rules ("HARD STOP and report if UpdateInstanceInformation is rejected for any
reason other than IAM permissions"), Stage 2 was **not started**. No C++ was written.

**Phase 1 as designed has an unmet hard prerequisite: a TLS stack for haiku/arm64.**

---

## 1. The blocker: no TLS on haiku/arm64

Established on a live instance (`i-046a6d266c6c63e83`, `ami-0c17f56477d32638f`,
Haiku `hrev59996+dirty` arm64, t4g.medium):

| Probe | Result |
|---|---|
| `curl` | **absent** |
| `openssl` | **absent** |
| `gcc` / `g++` / `make` / `cmake` | **absent** (only `gcc_syslibs` bootstrap runtime) |
| `wget` / `nc` / `python` / `python3` / `perl` | **absent** |
| `bash` `/dev/tcp` | **unsupported** — `warning: /dev/(tcp|udp)/host/port not supported without networking` |
| `libssl*` / `libcrypto*` / `libtls*` anywhere under `/boot` | **none** |
| `ssh -V` | `OpenSSH_10.4p1, without OpenSSL` |
| Installed packages | 17 total, all bootstrap |
| `/boot` capacity | 300 MiB total, 174 MiB free |
| uid | 0 (`baron` is root) |

There is **no HTTP client at all** on the image. `telnet` exists and *does* reach IMDS
(`Connected to instance-data.us-west-2.compute.internal`), so the network path is fine —
but telnet cannot usefully script an HTTP request.

### Why it cannot be fixed with a package install

```
$ pkgman install -y curl openssl
Refreshing repository "Haiku" failed
Refreshing repository "HaikuPorts" failed
*** Failed to find a match for "openssl": Name not found
: Operation not supported
```

Two independent causes, both dead ends:

1. **Haiku's package fetcher cannot do HTTPS on this image.**
   `pkgman refresh` → `Fetching repository checksum from https://... *** failed! : Operation not supported`.
   Chicken-and-egg: installing OpenSSL requires HTTPS, which requires OpenSSL.
2. **There is no arm64 package repository upstream.** Measured from the laptop:
   - `haikuports/master/arm64/current/repo` → 200, **1.3 KB** (empty; `packages/` → 404 `Invalid repository`)
   - `haikuports/master/x86_64/current/repo` → 200, **2,442,272 bytes** (fully populated)

This is already documented in the companion repo, more precisely than the spike could infer —
`haiku-graviton/docs/ssh-access.md:18-25`:

> ```
> $ curl -s https://eu.hpkg.haiku-os.org/haikuports/master/
> ["riscv64", "x86_64", "x86_gcc2"]
> ```
> HaikuPorts publishes **no arm64 package repository at all**. The only arm64 packages that
> exist are the ~30 *bootstrap* packages […] `openssh` is not among them, and neither is `openssl`.

and `docs/stage-b-remote-desktop.md:610-613`, enumerating all 35 arm64 bootstrap packages:
`curl(+devel)`, `python3.10`, `gcc`, `make`, `binutils`, `ca_root_certificates` … but
**"No libpng, no libjpeg, no openssl, no libvncserver."**

and `docs/ssh-access.md:86`:

> **`--without-openssl` is the significant one.** No OpenSSL exists for Haiku/arm64.

`docs/ssh-access.md:173` already anticipated the fix: *"or build OpenSSL for arm64 and rebuild
OpenSSH against it to regain RSA."* That prerequisite is now also on Phase 1's critical path.

### Consequence for BRIEF.md §1

The design doc's hard-constraints section states:

> **What works for free:** IMDSv2 […] Curl and OpenSSL exist on Haiku. The C++ toolchain is
> first-class (it built the OS).

That is true of **Haiku/x86_64** and false of **haiku/arm64**, which is the actual target.
Corrected in `docs/BRIEF.md` §1 with a pointer here. Consequences:

- Option B (the chosen option) assumed libcurl + OpenSSL were present. They are not.
- "The C++ toolchain is first-class (it built the OS)" is true of the **cross**-toolchain on the
  Linux builder, not of the Haiku box. Stage 2's "built natively on the Haiku box" is not
  possible on this image: no compiler, and no way to fetch one over HTTPS.
- Note the irony worth carrying into the decision: BRIEF §4 rejected Option A because it
  "front-loads the hardest possible work (a language runtime port) before delivering any
  management capability." Option B now also front-loads a porting project — a much smaller
  one (a C TLS library, not a language runtime), but a real one.

---

## 2. What *was* proven (all of Stage 1 except the TLS leg)

### 2.1 SigV4 by hand works — validated end to end

[`spike/sigv4-post.sh`](spike/sigv4-post.sh) — POSIX `sh` + `openssl` only, no `jq`, no AWS CLI.
Validated from the laptop against the real API:

```
$ ./sigv4-post.sh ssm AmazonSSM DescribeInstanceInformation '{}'
{"InstanceInformationList":[{"AgentVersion":"3.3.4793.0", … }]}
200
```

Deliberately run against **LibreSSL 3.3.6** (macOS `/usr/bin/openssl`), the more constrained of
the two available builds, to confirm `dgst -sha256 -mac HMAC -macopt hexkey:` — the one
non-obvious primitive the derived-key chain needs — is not an OpenSSL 3 exclusive. It is
supported by both LibreSSL 3.3.6 and OpenSSL 3.6.3, so the signer will port unchanged to
whatever TLS stack haiku/arm64 eventually gets.

This is the reference implementation for the C++ signer, and it is the part of Stage 1 that
carries forward unchanged.

### 2.2 New AWS-side finding: no off-box registration

Sending the exact Stage 1 payload from the laptop, with the correct `InstanceId`:

```json
{"InstanceId":"i-046a6d266c6c63e83","AgentName":"haiku-mgmt-agent","AgentVersion":"0.1.0",
 "AgentStatus":"Active","PlatformType":"Linux","PlatformName":"Haiku",
 "PlatformVersion":"hrev59996","SSMConnectionChannel":"ec2messages",
 "IPAddress":"10.42.0.85","ComputerName":"ip-10-42-0-85.us-west-2.compute.internal",
 "AvailabilityZone":"us-west-2a"}
```

```
HTTP 400
{"__type":"AccessDeniedException","Message":"Caller instance identity does not match the given instanceId"}
```

**`UpdateInstanceInformation` requires credentials bound to that instance's own identity.**
Role creds from IMDS on the instance itself are mandatory; there is no proxy or laptop-side
shortcut, and no way to pre-register a node before the agent runs. The request was parsed and
the signature verified before this check — so the wire shape and signing are correct.

Implication for testing: every future attempt at the gate must originate on the Haiku box.
A "sign on the laptop with creds shipped from Haiku" workaround was considered to close open
question #1 early; it is **impossible**, since fetching those creds needs an HTTP client on
Haiku, which does not exist.

### 2.3 Network path is fine

- IMDS TCP reachable from Haiku (via `telnet`): `Connected to instance-data.us-west-2.compute.internal`
- SG `sg-008114891fd207df1` egress is all-traffic → 443 outbound is open
- SSH from the laptop worked on the **first** 12-second poll after `instance-running`

---

## 3. Open questions — updated

| # | Status |
|---|---|
| **1** PlatformName/console tolerance | **Still open, and now un-testable until TLS exists** (see §2.2). Wire-level answer from BRIEF §9.2 stands: `PlatformType` is a closed enum, `PlatformName`/`PlatformVersion` are free-form. |
| **3** TLS trust store on Haiku | **Answered, far worse than framed.** The question was "is the shipped CA bundle current enough". The actual answer: there is no TLS stack, no CA bundle, and no OpenSSL for arm64 at all. `ca_root_certificates` exists as an "any"-arch bootstrap package, so the bundle is the easy half; the library is the blocker. |
| **5** Timeout/zombie semantics | **Not reached.** Needs a compiler on the target. |
| 2, 4 | Unchanged (2 answered in BRIEF §9; 4 untouched). |

---

## 4. Decision needed before any further work

Phase 1 needs a TLS client on haiku/arm64. Three ways, none of which are "just start Stage 2":

**A. Cross-build `openssl3` for haiku/arm64, then relink curl.**
Follows the project's established pattern (`ssh/build-openssh-arm64.sh` already cross-builds
OpenSSH the same way). OpenSSL supports Haiku as a platform for x86_64, so this is a target
triplet + `no-asm` exercise rather than a port from scratch. Biggest payoff beyond this project:
it also regains RSA/ECDSA for OpenSSH (`ssh-access.md:173`) and unblocks every other TLS-needing
port. Biggest cost: it is a system-wide dependency to build, package as `.hpkg`, and bake into
the AMI.

**B. Statically link a small TLS stack into the agent + hand-rolled HTTP/1.1.**
mbedTLS or BearSSL: pure C, no asm, no autotools, builds with just the cross-gcc. Avoids
system-wide packaging entirely — one self-contained binary, matching BRIEF §5's
"single binary, no plugin system". Costs ~200 lines of HTTP client instead of libcurl, and the
TLS stack is then ours to keep current (a security-relevant maintenance item BRIEF §6 already
flags for the daemon itself).

**C. Park Phase 1; ship BRIEF Option C now.**
SSH-based orchestration from a Linux control point delivers actual fleet management today with
zero new code on Haiku. Haiku never becomes a managed node, so it does not produce the artifact
BRIEF §6 wants — but it is the honest fallback while A or B is decided.

Recommendation: **B for this project, A as the more valuable contribution.** B is the shortest
path to a working `haiku-mgmt-agent` and keeps the blast radius inside one binary; A is worth
more to the wider Haiku/arm64 effort and would be the right call if the OpenSSH RSA win and
other ports matter. Either way it is a **Phase 0.5** with its own scope, not a footnote in
Stage 2 — and C is worth doing regardless, since it is nearly free.

---

## 5. Reproducing this spike

```sh
# Instance used (leave or terminate as you prefer — see cost note below)
IID=i-046a6d266c6c63e83; IP=16.146.16.178
ssh -i ~/.ssh/haiku-graviton-ed25519 baron@$IP    # ed25519 only; RSA will not work

# Signer, from anywhere with openssl (validated on LibreSSL 3.3.6 + OpenSSL 3.6.3)
eval "$(aws configure export-credentials --format env)"
AWS_REGION=us-west-2 ./spike/sigv4-post.sh ssm AmazonSSM DescribeInstanceInformation '{}'
# On Haiku it will use IMDSv2 role creds automatically — once an HTTPS-capable curl exists.
```

### Infrastructure created for this spike

Dedicated per the "don't share the box" decision — the ENA/builder instance
(`i-0f7f6f3e8922acffd`, `c7g.metal`, Ubuntu) was **not touched**.

| Resource | Name/ID | Note |
|---|---|---|
| IAM role + instance profile | `haiku-mgmt-spike` | `AmazonSSMManagedInstanceCore` only |
| EC2 key pair | `haiku-mgmt-spike` | imported from `~/.ssh/haiku-graviton-ed25519.pub` |
| Instance | `i-046a6d266c6c63e83` | t4g.medium, `haiku-mgmt-agent-dev`, tagged `Project=haiku-graviton` |

**Cost note:** the t4g.medium is still running (~$0.034/h) and is useless until a TLS decision
lands. Stop or terminate it; the canonical AMI relaunches an equivalent in ~20 seconds and SSH
was up 12 s after `instance-running`.
