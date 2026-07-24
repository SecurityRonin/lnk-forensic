# 5. forbid(unsafe), panic-free by lint, fuzzed — the Paranoid Gatekeeper posture

Date: 2026-07-24
Status: Accepted

## Context

Every input these crates parse is attacker-controllable evidence: a `.lnk` file,
a `*.automaticDestinations-ms` CFB compound file, a `*.customDestinations-ms`
blob — all off a potentially compromised host. A length field that lies, a
truncated `LinkInfo`, a malformed `DestList` offset must never crash the tool or
silently emit wrong output. The fleet Paranoid Gatekeeper standard requires this
posture for every `*-core` / `*-forensic` crate. Unlike the mmap-based container
readers (`ewf`, `memory-forensic`) that must downgrade to `unsafe_code = "deny"`
plus a bounded `#[allow]`, this repo does purely in-memory `&[u8]` parsing with
no mmap and no FFI — so it can keep the strongest setting.

## Decision

Enforce a panic-free posture statically and dynamically.

- **Statically** (`Cargo.toml` `[workspace.lints]`, applied via `#![forbid(unsafe_code)]`
  in both `lib.rs`): `unsafe_code = "forbid"` (never downgraded — no mmap/FFI),
  `clippy::correctness`/`suspicious` = deny, and `clippy::unwrap_used` /
  `expect_used` = deny in production. `clippy.toml` re-allows unwrap/expect *in
  tests only* so tests still fail loudly.
- **Bounds-checked reads.** Every integer/length/offset read is range-checked;
  malformed headers yield `None` or absent sub-structures, never a partial garbage
  value (`core/src/lib.rs`, `core/src/jumplist.rs` doc headers). Declared
  shell-link sizes inside a Jump List are treated as unreliable (see ADR 7).
- **Dynamically:** three `cargo-fuzz` targets — `shelllink` (the reader),
  `jumplist` (CFB/DestList + custom-destinations), and `forensic` (the full
  parse → audit pipeline) (`fuzz/fuzz_targets/`), built and smoke-run in CI. The
  fuzz job runs on nightly (`cargo +nightly fuzz`, commit `2168616`) because the
  `rust-toolchain.toml` pin otherwise wins over `@nightly`.

## Consequences

- Malformed evidence degrades to an error or a partial result, never a crash or a
  raw-pointer path; the "unsafe forbidden" README badge is earned, not aspirational.
- The README leads with the *measured* claim ("fuzzed") and qualifies the static
  claim ("panic-free by lint"), per the fleet Evidence-Based Rigor wording rule —
  fuzzing tests robustness empirically; the lints make panics unreachable by
  construction.
- Bounds-checked code is more verbose than a quick `unwrap`; the fuzz targets are
  part of the maintained surface.
