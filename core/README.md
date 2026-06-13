# lnk-core

[![Crates.io](https://img.shields.io/crates/v/lnk-core)](https://crates.io/crates/lnk-core)
[![Docs.rs](https://img.shields.io/docsrs/lnk-core)](https://docs.rs/lnk-core)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](../LICENSE)

**A panic-free Windows Shell Link (`.lnk`) reader — `[MS-SHLLINK]` bytes into a typed `ShellLink`, no findings.**

The reader half of [`lnk-forensic`](https://github.com/SecurityRonin/lnk-forensic).
For graded forensic findings, use the
[`lnk-forensic`](https://crates.io/crates/lnk-forensic) analyzer crate.

```rust
use lnk_core::parse_shell_link;

let link = parse_shell_link(lnk_bytes).expect("valid [MS-SHLLINK] header");
if let Some(info) = &link.link_info {
    if let Some(vol) = &info.volume_id {
        println!("drive type {} serial {:#010X}", vol.drive_type, vol.drive_serial_number);
    }
}
```

## What it parses

- **`ShellLinkHeader`** — `LinkFlags`, `FileAttributes`, the three target
  FILETIMEs (creation / access / write → Unix epoch seconds), file size, icon
  index, show command, hotkey. A wrong `HeaderSize` or `LinkCLSID` yields `None`.
- **`LinkInfo`** — the `VolumeID` (`drive_type`, **`drive_serial_number`**,
  `volume_label`), the `local_base_path`, and the `CommonNetworkRelativeLink`
  (`net_name`, `device_name`).
- **`StringData`** — `name`, `relative_path`, `working_dir`, `arguments`,
  `icon_location`, honoring the `IsUnicode` flag (UTF-16LE vs ANSI).
- **`LinkTargetIDList`** — the raw PIDL ItemID blob (kept verbatim; full PIDL
  decode is a shellbag parser's job).
- **`ExtraData` `TrackerDataBlock`** — the origin machine NetBIOS name and the
  droid / birth-droid volume+object GUIDs.

Format constants (HeaderSize, LinkCLSID, the LinkFlags / FileAttributes bits, the
ExtraData block signatures) come from
[`forensicnomicon::shlink`](https://crates.io/crates/forensicnomicon); the parsing
algorithm lives here.

## Trust, but verify

`#![forbid(unsafe_code)]`, bounds-checked on every read (no length field
trusted), and fuzzed — a truncated or hostile link yields absent sub-structures or
`None`, never a panic.

[Privacy Policy](https://securityronin.github.io/lnk-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/lnk-forensic/terms/) · © 2026 Security Ronin Ltd
