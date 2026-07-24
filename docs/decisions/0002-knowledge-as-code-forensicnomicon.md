# 2. Format constants come from forensicnomicon, parsing stays here

Date: 2026-07-24
Status: Accepted

## Context

Reading a `.lnk` and a Jump List depends on a body of reference facts: the
`LinkCLSID`, the `LinkFlags` / `FileAttributesFlags` / drive-type constants, the
`[MS-SHLLINK]` structure offsets, the `0xBABFFBAB` custom-destinations footer
signature, the embedded-LNK CLSID boundary, `DestList` layout markers, and the
`AppID → application` map. Baking these tables inside the parser would fork them
from the rest of the fleet and let them drift — the same fact would live in
`lnk-core` and in every other artifact reader that touches shell links.

The fleet architecture (`ronin-issen/CLAUDE.md`) designates `forensicnomicon` as
the zero-dependency KNOWLEDGE leaf: "Magic bytes, record markers, format header
offsets … NO parsing algorithms, NO file I/O."

## Decision

Consume `forensicnomicon` for the *facts* and keep the *algorithm* here. Both
crates depend on `forensicnomicon = "1"` (`core/Cargo.toml`, `forensic/Cargo.toml`).

- `lnk-core` reads structural constants from `forensicnomicon::shlink` and Jump
  List markers from `forensicnomicon::jumplist` (`core/src/lib.rs` doc header:
  "The format **constants** live in `forensicnomicon::shlink` … the **parsing
  algorithm** lives here"; `core/src/jumplist.rs`: "The offset tables and the
  `0xBABFFBAB` footer / CLSID boundary live in `forensicnomicon::jumplist`").
- `lnk-forensic` resolves the `AppID` label via
  `forensicnomicon::jumplist::appid_name` (`forensic/src/lib.rs`) and emits every
  finding through the shared `forensicnomicon::report` model (`Observation`,
  `Finding`, `Severity`, `Category`).

## Consequences

- A new `AppID`, a corrected offset, or an added flag updates once in
  `forensicnomicon` and every fleet consumer picks it up on a version bump; the
  parser holds only logic.
- The `lnk-forensic` findings render uniformly beside every other analyzer's in
  Issen because they are the one canonical `report::Finding` type.
- Both crates take a dependency on `forensicnomicon` and its release cadence; the
  jump from `forensicnomicon` 0.5 → 0.11 → 1.0 (commits `e4c7ba7`, `ecc9263`)
  was absorbed by this repo as the catalog matured.
