# lnk-forensic — Design Intent (Purpose & Scope)

This is a **library** design document, not a product requirements document. It
records what `lnk-core` and `lnk-forensic` are for, where their boundaries sit,
and how correctness is established. The decision rationale behind these choices
lives in [`docs/decisions/`](decisions/).

## Purpose

Turn a Windows Shell Link (`.lnk`) — or a whole Jump List — into typed values and
graded forensic findings, so a DFIR examiner or another fleet crate can answer:

- What file did this shortcut point at, and where did it live (local path,
  removable volume, or network share)?
- What is the **volume serial** of the media it came off — the join key that ties
  an opened file back to a physical peripheral device connection?
- Which machine was the link authored on (`TrackerDataBlock` NetBIOS name and
  distributed-link-tracking droid GUIDs)?
- For a Jump List: what per-application MRU history (recency, pin state, access
  count, origin hostname) surrounds each embedded link?

A `.lnk` frequently records a target that no longer exists on disk, which makes it
high-value residual evidence of past activity.

## Users

- **Forensic analysts / incident responders** who want graded, hedged findings
  ("consistent with a file opened from external media") for triage, consumed
  through Issen or another orchestrator rather than a standalone CLI here.
- **Rust developers and other fleet crates** that need a panic-free reader for
  `.lnk` / Jump List bytes and nothing more — they depend on `lnk-core` alone.

## What it does

Two published crates (see ADR 1):

- **`lnk-core`** parses `[MS-SHLLINK]` into a typed `ShellLink`: header (flags,
  attributes, the three target FILETIMEs, file size, icon, show command, hotkey),
  the optional `LinkInfo` (`VolumeID` drive type / **volume serial** / label, the
  local base path, and a `CommonNetworkRelativeLink` for network targets), the
  `StringData` block, the `TrackerDataBlock`, and the `LinkTargetIDList` PIDL
  (decoded to typed shell items + a reconstructed shell-namespace path via the
  `shellitem` primitive). It also parses **Jump Lists** — both
  `*.automaticDestinations-ms` (an OLE/CFB compound file with a `DestList` MRU
  stream + one embedded `.lnk` per entry) and `*.customDestinations-ms` (a flat
  run of embedded links) — into `JumpList` / `JumpListEntry` / `DestListEntry`.

- **`lnk-forensic`** consumes that typed output and emits
  `forensicnomicon::report::Finding`s. Per-link codes: `LNK-REMOVABLE-MEDIA-TARGET`
  (Medium / Threat), `LNK-NETWORK-TARGET` (Low / Threat),
  `LNK-TRACKER-MACHINE` (Info / Provenance). Jump-List-level codes:
  `JUMPLIST-PINNED-TARGET`, `JUMPLIST-CROSS-MACHINE`, `JUMPLIST-MRU-RECENCY`,
  `JUMPLIST-APPID-IDENTIFIED`. Entry points: `audit`, `audit_findings`,
  `audit_jumplist`.

Every finding is an **observation** ("consistent with …"); MITRE techniques are
narrated as consistency, never as a verdict. The examiner draws the conclusions.

## Scope

- Read `[MS-SHLLINK]` Shell Links authored on any Windows host.
- Read Automatic and Custom Destinations Jump Lists.
- Decode the `LinkTargetIDList` to a reconstructed target path.
- Grade the removable-media / network / machine-attribution / MRU signals that
  matter for triage, as canonical `report::Finding`s.
- Accept `&[u8]` in memory; degrade to `None` / partial results / a structured
  `JumplistError` on malformed input, never a panic (ADR 5, ADR 7).

## Non-goals

- **Not a CLI, GUI, or MCP server.** The user-facing front end is Issen /
  disk4n6; this repo ships libraries plus fuzz harnesses only. (Tier: LIBRARY.)
- **Not a full shell-item / shellbag parser.** PIDL decoding is delegated to the
  `shellitem` primitive; deep shell-namespace reconstruction belongs there.
- **Not an OLE/CFB implementation.** The compound-file container is read via the
  mature `cfb` crate (ADR 4).
- **Not a source/container reader.** It takes bytes; locating a `.lnk` on disk,
  in an image, or in memory is the caller's job (medium-agnostic, per the fleet
  PARSER layering).
- **No legal conclusions.** Findings stop at "consistent with"; severity and
  category are triage aids, not verdicts.

## Artifact family

Windows Shell Link (`.lnk`) and Windows Jump Lists
(`*.automaticDestinations-ms`, `*.customDestinations-ms`).

## Validation approach

- **Spec-exact fixtures, end-to-end.** The parse → audit pipeline is exercised
  against hand-authored `[MS-SHLLINK]` links (a removable-media link with a volume
  serial + a network-share link — `forensic/tests/real_data.rs`) and Jump List
  fixtures (a real CFB automatic-destinations file, a custom-destinations file —
  `forensic/tests/jumplist.rs`), with generators under `tests/data/`.
- **Fuzzing.** `cargo-fuzz` targets `shelllink`, `jumplist`, and `forensic`
  (`fuzz/fuzz_targets/`), built and smoke-run in CI; the invariant is that no
  input panics.
- **Static posture.** `#![forbid(unsafe_code)]`, `clippy::unwrap_used` /
  `expect_used` denied in production, bounds-checked reads (ADR 5).
- **Coverage.** 100% library line coverage gated in CI (`// cov:unreachable`
  reserved for provably-dead defensive arms).

Provenance for every test artifact is recorded in `tests/data/README.md` and the
fleet catalog `ronin-issen/docs/test-data-catalog.md`.
