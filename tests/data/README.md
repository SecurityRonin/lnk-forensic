# lnk-forensic test corpus

Fixtures backing `forensic/tests/real_data.rs`. This is the co-located,
human-facing detail; the single fleet-wide machine index is
[`issen/docs/corpus-catalog.md`](https://github.com/SecurityRonin/issen/blob/main/docs/corpus-catalog.md) —
cross-reference, never duplicate.

The host is macOS and cannot natively author a Windows Shell Link, so both
fixtures are **spec-exact, hand-authored** byte-for-byte per `[MS-SHLLINK]`. No
real user's `.lnk` is committed.

## Authoritative spec

`[MS-SHLLINK]` — *Shell Link (.LNK) Binary File Format*:
<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943>
(§2.1 ShellLinkHeader, §2.3 LinkInfo / §2.3.1 VolumeID / §2.3.2
CommonNetworkRelativeLink, §2.4 StringData, §2.5.10 TrackerDataBlock).

## Fixtures

### `removable_media.lnk` — SYNTHETIC (`✓` confirmed)

- **Classification:** SYNTHETIC (spec-exact hand-authored).
- **MD5:** `ba3dbe2429bdfa93d8a0a9be80ca0fbe` (268 bytes).
- **Contents:** a valid 0x4C `ShellLinkHeader` (LinkCLSID
  `00021401-0000-0000-C000-000000000046`), a `LinkInfo` with a `VolumeID`
  carrying `DriveType = DRIVE_REMOVABLE` (2), `DriveSerialNumber = 0xDEADBEEF`,
  label `KINGSTON USB`, and `LocalBasePath = E:\payload.exe`; a `NAME_STRING`
  (`Removable shortcut`); and a `TrackerDataBlock` with `MachineID = ANALYST-PC`
  and droid/birth-droid GUIDs. Exercises `LNK-REMOVABLE-MEDIA-TARGET` (with the
  volume-serial join key surfaced) and `LNK-TRACKER-MACHINE`.

### `network_share.lnk` — SYNTHETIC (`✓` confirmed)

- **Classification:** SYNTHETIC (spec-exact hand-authored).
- **MD5:** `547e0d2686e6652d8d144fb1b767bf9a` (147 bytes).
- **Contents:** a valid header plus a `LinkInfo` with a
  `CommonNetworkRelativeLink` (`NetName = \\SERVER\share`, `DeviceName = Z:`).
  Exercises `LNK-NETWORK-TARGET`.

## Generator (verbatim)

Both files are produced by the standalone Rust program `gen_lnk.rs` (the same
byte-layout builders mirrored in `core/src/tests.rs`):

```sh
rustc -O gen_lnk.rs -o gen_lnk
./gen_lnk   # writes removable_media.lnk + network_share.lnk into this directory
```

The `gen_lnk.rs` source is reproduced from the in-repo test builders
(`core/src/tests.rs` `header()` / `link_info_volume()` / `link_info_network()` /
`tracker_block()`); regenerating requires only `rustc` (no dependencies).

## Capturing a real `.lnk` (for deeper validation)

Any Windows host's Recent-items folder is full of genuine links:

```
%APPDATA%\Microsoft\Windows\Recent\*.lnk
```

Copy one out and parse it with `lnk_core::parse_shell_link`. **Never commit a
real user's `.lnk`** — it embeds local paths, volume serials, the machine
NetBIOS name, and droid GUIDs (personally identifying / case-sensitive).
