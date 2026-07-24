# 1. Two-crate reader/analyzer workspace (lnk-core + lnk-forensic)

Date: 2026-07-24
Status: Accepted

## Context

The repository serves two audiences at once. A Rust developer or another fleet
crate may want only to *read* a Windows Shell Link — parse the `[MS-SHLLINK]`
header, `LinkInfo`, `StringData`, `TrackerDataBlock`, and Jump Lists into typed
values. A forensic examiner wants *graded findings* — "this target came off
removable media", "this was authored on machine X". These are different
responsibilities with different stability contracts: the reader is a
value-producing parser; the analyzer is an opinionated grader that emits
`forensicnomicon::report::Finding`s.

The fleet Crate-structure standard (`ronin-issen/CLAUDE.md`, "Crate-structure
standard — reader/analyzer split") makes this split the default for every
single-format repo: one workspace named `<x>-forensic`, a `core/` reader crate
and a `forensic/` analyzer crate.

## Decision

Ship one workspace (`Cargo.toml` → `members = ["core", "forensic"]`) with two
published crates:

- **`lnk-core`** (`core/`) — the reader. Parses `[MS-SHLLINK]` and Jump Lists
  into `ShellLink` / `JumpList`; emits no findings (`core/src/lib.rs`,
  `core/src/jumplist.rs`).
- **`lnk-forensic`** (`forensic/`) — the analyzer. Consumes a `lnk_core::ShellLink`
  / `JumpList` and emits graded `Finding`s (`forensic/src/lib.rs`:
  `audit`, `audit_findings`, `audit_jumplist`).

Shared build policy — edition, MSRV, license, authors, and the Paranoid
Gatekeeper lint block — lives once in `[workspace.package]` / `[workspace.lints]`
and each member inherits via `[lints] workspace = true`.

## Consequences

- A downstream tool that only needs to read `.lnk`/Jump-List bytes depends on
  `lnk-core` alone and never compiles the grading surface.
- The reader stays medium-agnostic and reusable outside DFIR; the forensic
  opinions (severity, MITRE narration) are quarantined in `lnk-forensic`.
- Two crates must be versioned and released together (they move in lockstep in
  the `CHANGELOG`), which release-plz handles per-crate from the workspace.
- Anomaly-detection logic must never leak into `lnk-core`, nor raw parsing into
  `lnk-forensic` — the layering is the contract this ADR exists to protect.
