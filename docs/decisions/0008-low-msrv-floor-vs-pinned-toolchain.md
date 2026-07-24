# 8. Low CI-verified MSRV floor, separate from the pinned dev toolchain

Date: 2026-07-24
Status: Accepted

## Context

The fleet MSRV policy separates two numbers that are easy to conflate: the **dev
toolchain** (what contributors and CI build/fmt/clippy with) and the **declared
MSRV** (`rust-version` — a downstream-facing compatibility promise). Apps declare
MSRV = the pinned toolchain because nothing pins a library dependency against
them. Published *libraries* instead keep a low, CI-verified MSRV, because raising
it narrows the crates.io audience and is close to a breaking change.

`lnk-core` and `lnk-forensic` are published libraries — other crates link them —
so they fall on the library side of that split.

## Decision

- Pin the **dev toolchain** to the current fleet stable: `rust-toolchain.toml`
  → `channel = "1.96.0"`, `components = ["rustfmt", "clippy"]` (commit `30ce8b7`).
- Declare a **low MSRV floor** of `1.81`, inherited workspace-wide:
  `Cargo.toml` `[workspace.package] rust-version = "1.81"`, consumed by both
  members via `rust-version.workspace = true`. The README badge reads `Rust 1.81+`.

`1.81` is the floor the dependency graph (`forensicnomicon`, `cfb`, `shellitem`)
compiles cleanly against, kept deliberately below the `1.96.0` dev pin so the
crates stay broadly consumable.

## Consequences

- Downstream projects on an older-than-1.96 toolchain can still depend on
  `lnk-core` / `lnk-forensic`; the floor is a real, verifiable guarantee, not a
  copy of the dev pin.
- Raising `1.81` is treated as a near-breaking change requiring a genuine
  newer-Rust need, not merely matching the toolchain.
- The exact dependency that sets the `1.81` floor (versus a lower `1.75`/`1.80`)
  is not recorded in the git history; the number is honored as the CI-verified
  floor. Rationale for the specific value is reconstructed from the fleet MSRV
  policy, not an explicit original decision.
