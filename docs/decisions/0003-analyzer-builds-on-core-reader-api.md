# 3. The analyzer builds on the lnk-core reader API

Date: 2026-07-24
Status: Accepted

## Context

The fleet Crate-structure standard says a `-forensic` analyzer *may* depend on
`-core`, but is not required to: when a happy-path reader hides the very anomaly
the auditor hunts (slack, deleted/overwritten records, malformed fields a robust
reader normalizes away), the analyzer should drop to the raw bytes or a lower
layer instead of contorting an audit through a normalizing API.

For Shell Links the anomalies of interest are *present, well-formed* structural
facts, not slack or deletion residue: a `VolumeID.DriveType` of `DRIVE_REMOVABLE`,
a `CommonNetworkRelativeLink`, a `TrackerDataBlock` machine name, a `DestList`
pinned flag / origin hostname / access count. `lnk-core` already surfaces each of
these as a typed, first-class field (`VolumeId.drive_type`,
`VolumeId.drive_serial_number`, `LinkInfo.common_network_relative_link`,
`TrackerDataBlock`, `DestListEntry`). The reader's typed view *is* the evidence
the audit needs — there is no lower-level structure being hidden.

## Decision

`lnk-forensic` depends on `lnk-core` and audits its typed output — it does not
re-parse `.lnk` bytes independently. `forensic/Cargo.toml`:
`lnk-core = { version = "0.4", path = "../core" }`; `forensic/src/lib.rs`
operates entirely over `&ShellLink` / `&JumpList`. `audit_jumplist` reuses the
per-link `audit` over every embedded link so removable/network/tracker findings
come for free.

The dependency is declared with **both** a registry `version` and a workspace
`path` — the path resolves during in-workspace development, the version is what
external consumers and a published build get (fleet Dependency-Preference rule:
"prefer the published registry crate … once it is on crates.io").

## Consequences

- One parser, one place: a fix to Shell Link decoding lands in `lnk-core` and the
  audit inherits it; there is no second `[MS-SHLLINK]` parser to keep in sync.
- If a future audit needs raw byte-level structure that `lnk-core` normalizes
  away (e.g. carving deleted Jump List entries), this decision is revisited and
  `lnk-forensic` would parse the raw stream directly, per the standard's
  "go lower when the reader hides the anomaly" clause.
