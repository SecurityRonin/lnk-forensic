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

### `pinned_removable.automaticDestinations-ms` — SYNTHETIC (`✓` confirmed)

- **Classification:** SYNTHETIC (spec-exact hand-authored, real CFB container).
- **Contents:** a genuine OLE/CFB compound file (built with the `cfb` crate)
  holding a `DestList` v2 (Windows 10, `FormatVersion = 3`) stream with one
  **pinned** entry — origin hostname `OTHER-PC` (redacted placeholder, not a real
  machine), access count `7`, path `E:\report.docx` — plus a hex-named `1`
  sub-stream carrying a removable-media `.lnk` (`VolumeID` `DRIVE_REMOVABLE`,
  serial `0xDEADBEEF`). Exercises the CFB/DestList automatic path: pinned,
  cross-machine (vs. the test's acquisition host), MRU-recency, AppID
  (`1b4dd67f29cb1962` → Windows Explorer), and the reused embedded-LNK
  `LNK-REMOVABLE-MEDIA-TARGET` finding.

### `tasks.customDestinations-ms` — SYNTHETIC (`✓` confirmed)

- **Classification:** SYNTHETIC (spec-exact hand-authored).
- **MD5:** see §H of the corpus catalog (192 bytes).
- **Contents:** a flat custom-destinations file (`FormatVersion = 2`, one
  user-tasks category) with one embedded shell-object entry — the
  `[MS-SHLLINK]` CLSID prefix then a removable-media `.lnk` (serial
  `0xDEADBEEF`) — terminated by the `0xBABFFBAB` footer. Exercises the
  CLSID/footer splitter and the AppID lookup (`5d696d521de238c3` → Chrome).

## Jump List spec + generator (verbatim)

Jump List layout per libyal `dtformats`, *Jump lists format*:
<https://github.com/libyal/dtformats/blob/main/documentation/Jump%20lists%20format.asciidoc>
(DestList header/entry, CustomDestinations categories + `0xBABFFBAB` footer).
The `AppID` → application map is kacos2000's `AppIdlist.csv`
(<https://github.com/kacos2000/Jumplist-Browser>).

Both Jump List fixtures are produced by the cargo example
`core/examples/gen_jumplist.rs` (it needs the workspace's `cfb` crate to author
the automatic-destinations compound file — a plain-`rustc` build cannot):

```sh
cargo run --example gen_jumplist -p lnk-core
```

A non-runnable copy of the generator source is kept at
`tests/data/gen_jumplist.rs` for provenance. **No real user's Jump List is
committed** — every hostname/serial/path above is a synthetic placeholder.

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
