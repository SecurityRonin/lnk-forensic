# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [lnk-core 0.3.0 / lnk-forensic 0.3.0] — 2026-06-13

### Added

- **`LinkTargetIDList` PIDL decode via the `shellitem` primitive.**
  `LinkTargetIdList` now carries `items: Vec<shellitem::ShellItem>` (typed shell
  items — volume, folder, file entry with long name / size / MAC times / NTFS MFT
  reference) and `path: Option<String>` (the reconstructed shell-namespace path,
  e.g. `My Computer\C:\…\evil.exe`). This resolves the real target even when the
  `LinkInfo` block is absent. The raw blob is still kept verbatim in `raw`.

## [lnk-core 0.2.0 / lnk-forensic 0.2.0] — 2026-06-13

### Added — `lnk-core` (reader)

- **Jump Lists.** `parse_automatic_destinations(&[u8], Option<&str>) -> Option<JumpList>`
  opens a `*.automaticDestinations-ms` as an OLE/CFB compound file (via the `cfb`
  crate), reads the `DestList` MRU stream (Windows 7 v1 and Windows 10/11 v2+
  layouts), and decodes each hex-named embedded `.lnk` sub-stream with
  `parse_shell_link`. `parse_custom_destinations(&[u8], Option<&str>) -> Option<JumpList>`
  splits a flat `*.customDestinations-ms` into its embedded `.lnk`s by the
  `[MS-SHLLINK]` CLSID prefix and the `0xBABFFBAB` footer (declared sizes are
  treated as unreliable).
- New types: `JumpList`, `JumpListKind` (`Automatic` / `Custom`), `JumpListEntry`,
  and `DestListEntry` (droid + birth-droid volume/file GUIDs, hostname,
  entry number, last-access, pinned, access count, path). DestList paths are
  decoded **lossily** (unpaired surrogates occur).
- Offset tables, the footer signature, the embedded-LNK CLSID boundary, and the
  `AppID` map come from `forensicnomicon::jumplist` (knowledge-only).

### Added — `lnk-forensic` (analyzer)

- `audit_jumplist(&JumpList, Option<&str>, scope) -> Vec<Finding>` runs the
  existing per-link `audit` over **every** embedded link (removable / network /
  tracker findings come for free) plus four Jump-List-level codes:
  - `JUMPLIST-PINNED-TARGET` (Low / Provenance) — a pinned `DestList` entry.
  - `JUMPLIST-CROSS-MACHINE` (Low / Provenance) — an origin hostname with no
    match to the acquisition host.
  - `JUMPLIST-MRU-RECENCY` (Info / History) — last-access + access count.
  - `JUMPLIST-APPID-IDENTIFIED` (Info / Provenance) — the `AppID` resolves via
    `forensicnomicon::jumplist::appid_name`.
- All notes are hedged observations ("consistent with"); the cross-machine note
  states "no match to the acquisition host", never "belongs to another machine".

### Dependencies

- `lnk-core` adds the mature MIT-licensed [`cfb`](https://crates.io/crates/cfb)
  crate for OLE Compound-File reading (Automatic Destinations) — a documented
  "prefer our own" exception, on the same footing as `lznt1` for NTFS. Our code
  stays `#![forbid(unsafe_code)]`.
- Requires `forensicnomicon` ≥ 0.5.1 for the `jumplist` knowledge module.

### Security / Testing

- New `cargo-fuzz` target `jumplist` (invariant: must not panic) over the
  CFB/DestList + custom-destinations parse → audit pipeline.
- Validated end-to-end against spec-exact fixtures: a real CFB
  `*.automaticDestinations-ms` (pinned, cross-machine, removable embedded LNK)
  and a flat `*.customDestinations-ms` (`forensic/tests/jumplist.rs`).

## [lnk-core 0.1.0 / lnk-forensic 0.1.0] — 2026-06-13

### Added — `lnk-core` (reader)

- `parse_shell_link(&[u8]) -> Option<ShellLink>` — a bounds-checked, panic-free
  `[MS-SHLLINK]` reader. A wrong `HeaderSize` or `LinkCLSID` yields `None`.
- `ShellLinkHeader` — `LinkFlags`, `FileAttributes`, the three target FILETIMEs
  (creation / access / write → Unix epoch seconds), `file_size`, `icon_index`,
  `show_command`, `hotkey`.
- `LinkInfo` — the `VolumeID` (`drive_type`, **`drive_serial_number`**,
  `volume_label`), the `local_base_path`, and the `CommonNetworkRelativeLink`
  (`net_name`, `device_name`).
- `StringData` — `name`, `relative_path`, `working_dir`, `arguments`,
  `icon_location`, honoring the `IsUnicode` flag.
- `LinkTargetIdList` — the raw PIDL ItemID blob (full PIDL decode deferred to a
  shellbag parser).
- `TrackerDataBlock` — the origin machine NetBIOS name and the droid /
  birth-droid volume+object GUIDs.
- Format constants sourced from `forensicnomicon::shlink` (knowledge-only); the
  parsing algorithm lives in `lnk-core`.

### Added — `lnk-forensic` (analyzer)

- `LNK-REMOVABLE-MEDIA-TARGET` (Medium / Threat) — a `DRIVE_REMOVABLE` `VolumeID`;
  MITRE T1052.001 / T1091. The volume serial is surfaced as the join key to a
  peripheral device connection.
- `LNK-NETWORK-TARGET` (Low / Threat) — a `CommonNetworkRelativeLink`; MITRE
  T1021.
- `LNK-TRACKER-MACHINE` (Info / Provenance) — a `TrackerDataBlock` origin machine
  NetBIOS name (attribution).
- `audit` (typed `LnkAnomaly` stream) and `audit_findings` (graded
  `forensicnomicon::report::Finding`s in one call).
- Each anomaly emits a graded `Finding` via the `Observation` trait; `source(scope)`
  stamps the analyzer provenance. Notes are hedged observations, never verdicts.

### Security

- `#![forbid(unsafe_code)]` across both crates; bounds-checked reads (no length
  field trusted); `clippy::unwrap_used` / `expect_used` denied in production code.
- `cargo-fuzz` targets `shelllink` and `forensic` (both invariant: must not
  panic).

### Testing

- Validated end-to-end against spec-exact hand-authored `[MS-SHLLINK]` fixtures
  (a removable-media link with a volume serial + local base path + tracker block,
  and a network-share link), reconciling the surfaced serial and findings.
