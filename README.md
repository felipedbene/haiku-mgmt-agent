# haiku-mgmt-agent

A minimal native SSM-compatible management agent for **Haiku on EC2 Graviton (arm64)** —
enough of the AWS Systems Manager wire protocol to make a Haiku instance appear as a managed
node and run `AWS-RunShellScript` commands from the AWS console/CLI.

Companion to [`haiku-graviton`](https://github.com/felipedbene/Haiku-Graviton) and
[`haiku-on-ec2`](https://github.com/felipedbene/haiku-on-ec2).

## Status: blocked before first code

**Phase 1 has not started.** The Stage 1 spike ran and did *not* pass its gate, for a reason
that invalidates a premise of the design:

> **haiku/arm64 has no TLS stack.** No OpenSSL, no HTTPS-capable curl, no CA bundle, no
> compiler on the canonical AMI — and no arm64 package repository upstream to install them
> from. HaikuPorts publishes `["riscv64", "x86_64", "x86_gcc2"]` only.

Since the agent's entire job is signed HTTPS to `ssm.<region>.amazonaws.com` and
`ec2messages.<region>.amazonaws.com`, a TLS client for haiku/arm64 is a **hard prerequisite**
that must be resolved first. Options and a recommendation are in [`NOTES.md`](NOTES.md) §4.

What the spike *did* establish, and what carries forward:

- **SigV4 by hand works.** [`spike/sigv4-post.sh`](spike/sigv4-post.sh) signs and sends AWS
  JSON 1.1 requests with nothing but POSIX `sh` and `openssl` — validated against the live SSM
  API (HTTP 200), deliberately on LibreSSL to prove it does not need OpenSSL 3. This is the
  reference implementation for the eventual C++ signer.
- **`UpdateInstanceInformation` cannot be called off-box.** It requires credentials bound to
  the instance's own identity (`AccessDeniedException: Caller instance identity does not match
  the given instanceId`), so there is no laptop-side shortcut for registering a node.
- **The MDS wire protocol is fully mapped** — endpoints, target prefixes, poll cadence, reply
  ordering — in [`docs/BRIEF.md`](docs/BRIEF.md) §9.2, derived from the Apache-2.0 Go agent.

## Layout

| Path | What |
|---|---|
| [`docs/BRIEF.md`](docs/BRIEF.md) | Design doc / ADR. §9 is the MDS wire-protocol reference. **Canonical copy.** |
| [`NOTES.md`](NOTES.md) | Spike log: what was proven, the blocker, updated open questions, decision needed. |
| [`spike/sigv4-post.sh`](spike/sigv4-post.sh) | Hand-rolled SigV4 for AWS JSON 1.1 APIs. Works on Haiku's constraints (no jq, no AWS CLI). |

## Scope (when unblocked)

Phase 1 is Run Command only: MDS long-poll, `aws:runShellScript` via `/bin/sh -c`, inline
output, health ping. Explicitly **out of scope**: MGS/`ssmmessages` in any form, Session
Manager, self-update, inventory, S3/CloudWatch output. See `docs/BRIEF.md` §2.
