# CLAUDE.md — haiku-mgmt-agent

Minimal native SSM-compatible agent for **Haiku on EC2 Graviton (arm64)**.
Read `docs/design-roadmap.md` first — it is the self-contained handoff
(architecture, constraints, feature roadmap, rejected alternatives).
`docs/BRIEF.md` has the wire-protocol details derived from the Apache-2.0 Go
agent; `TESTING.md` is the verification ledger (host checks + live gates).

## Hard constraints (do not regress these)

- **Self-contained on a base image.** No OpenSSL, no libcurl, no aws-sdk, no
  JSON library, no system CA store. The agent carries its own TLS (static
  mbedTLS), HTTP/1.1 client, SigV4, JSON, and trust anchors. It must run on a
  freshly booted stock image whose only libs are `libroot`, `libnetwork`,
  `libstdc++`. Do not add runtime dependencies.
- **Clock before crypto.** Haiku has no NTP client and stock images boot at
  1970. Any code path that does TLS or SigV4 must run after
  `timesync::ensure_clock`.
- **No rewrites.** Rust/Go rewrite and aws-sdk-cpp are recorded as
  rejected/deferred in the roadmap §3a — don't relitigate without new premises.

## Build & test

- Host unit tests (run these for every change):
  `make check HOST_MBEDTLS=/tmp/mbedtls-host/mbedtls-3.6.2`
  (that tree needs a one-time `ln -sfn library .../lib` symlink; if it is gone,
  rebuild: download mbedTLS 3.6.2 and `make lib`).
- Cross-build needs the Haiku cross toolchain at `/opt/haiku` (see `Makefile`
  and `tools/`) — **not present on this workdesk**; target builds happen on the
  Linux build box or natively on a DeBeOS-provisioned Haiku box.
- Also keep `main.cpp`/`selfupdate.cpp`/`timesync.cpp` warning-free:
  `g++ -fsyntax-only -std=c++17 -Wall -Wextra -Wno-unused-parameter -Isrc
  -I/tmp/mbedtls-host/mbedtls-3.6.2/include src/main.cpp src/selfupdate.cpp src/timesync.cpp`

## Conventions

- One feature per branch (`phaseN-...`), version bump per release
  (`kAgentVersion` in `src/main.cpp`, package via `packaging/build-hpkg.sh`).
- Tests are dependency-free `check()` assertions in `tests/test_main.cpp`;
  pure logic goes in testable free functions, orchestration stays thin.
- New protocol behavior mirrors the Go agent's constants/layouts and cites the
  source file in a comment (see existing `iohandler.go:33`-style comments).
- Update `TESTING.md` with a gate table (PASS or PENDING) for every feature;
  never claim a live gate passed without hardware evidence.

## Security gate (operational)

Building/testing on the host is unrestricted. **Packaging, installing,
launch_daemon auto-start, and live `aws ssm` verification require explicit
human authorization** — the agent looks like a remote-exec implant to safety
tooling, and live AWS touches real accounts. Don't attempt to work around a
permission denial; leave live gates as PENDING for the human.
