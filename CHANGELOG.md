# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
