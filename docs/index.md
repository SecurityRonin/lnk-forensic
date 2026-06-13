# lnk-forensic

A from-scratch Windows Shell Link (`.lnk`) reader and a graded anomaly auditor —
parse the `[MS-SHLLINK]` header, the `LinkInfo` volume/path data, the `StringData`
block, and the `ExtraData` tracker block from a link authored on **any** Windows
host, then surface the removable-media targets, network-share targets, and origin
machine attribution a triage analyst cares about.

Two crates, one workspace:

- **[`lnk-core`](https://crates.io/crates/lnk-core)** — the reader: the 0x4C
  `ShellLinkHeader` (LinkFlags, FileAttributes, the three target FILETIMEs, file
  size, icon index, show command, hotkey), the `LinkInfo` block (the `VolumeID`
  drive type / **volume serial number** / label, the local base path, and the
  `CommonNetworkRelativeLink`), ANSI/Unicode `StringData`, the raw
  `LinkTargetIDList` PIDL blob, and the `TrackerDataBlock` (origin machine NetBIOS
  name + droid GUIDs) into a typed `ShellLink`. No `unsafe`; bounds-checked;
  never panics on hostile input.
- **[`lnk-forensic`](https://crates.io/crates/lnk-forensic)** — the auditor: turns
  a parsed `ShellLink` into severity-graded
  [`forensicnomicon::report::Finding`](https://crates.io/crates/forensicnomicon)s
  so a host's link artifacts aggregate uniformly with the rest of the fleet.

The format **constants** (HeaderSize, LinkCLSID, the LinkFlags/FileAttributes
bits, and the ExtraData block signatures) come from
[`forensicnomicon::shlink`](https://crates.io/crates/forensicnomicon); the
**parsing algorithm** lives in `lnk-core`.

## Audit a Shell Link

```rust
use lnk_core::parse_shell_link;
use lnk_forensic::{audit, source};

let link = parse_shell_link(lnk_bytes).expect("valid [MS-SHLLINK] header");

for anomaly in audit(&link) {
    let finding = anomaly.to_finding(source("volume: E:"));
    println!("[{:?}] {} — {}", finding.severity, finding.code, finding.note);
    // e.g. [Some(Medium)] LNK-REMOVABLE-MEDIA-TARGET — the link target resolves to a removable …
}
```

## The anomaly codes

Each anomaly is an **observation** ("consistent with …"); the examiner draws the
conclusions. Codes are a stable, published contract.

| Code | Severity | Category | What it observes |
|---|---|---|---|
| `LNK-REMOVABLE-MEDIA-TARGET` | Medium | Threat | The `VolumeID` describes a `DRIVE_REMOVABLE` volume — consistent with a file opened from external media (MITRE T1052.001 / T1091). The **volume serial** is surfaced as the join key to a peripheral device connection. |
| `LNK-NETWORK-TARGET` | Low | Threat | The link carries a `CommonNetworkRelativeLink` — consistent with a file opened from a network share (MITRE T1021). |
| `LNK-TRACKER-MACHINE` | Info | Provenance | The `TrackerDataBlock` records the origin machine's NetBIOS name — consistent with the link having been authored on that machine (attribution). |

## The volume serial as a cross-artifact join key

A `.lnk`'s `VolumeID.DriveSerialNumber` is the same 32-bit volume serial that a
USB mass-storage device records in the Windows registry / setupapi log. Surfacing
it first-class on the removable-media anomaly lets an examiner **correlate** a
file opened from external media (this link) with the **physical device** that
carried it (a
[`peripheral-forensic`](https://github.com/SecurityRonin/peripheral-forensic)
`DeviceConnection`) — the serial is the join key. The link never *proves* the
correlation; it surfaces the value the examiner reconciles.

## Trust but verify

`lnk-core` is panic-free on untrusted input (bounds-checked reads, no length
field trusted), `#![forbid(unsafe_code)]`, fuzzed (`shelllink` + `forensic`
targets), and validated end-to-end against spec-exact `[MS-SHLLINK]` fixtures
(see `forensic/tests/real_data.rs`). A truncated or garbled link yields absent
sub-structures or `None`, never a crash.

[Privacy Policy](https://securityronin.github.io/lnk-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/lnk-forensic/terms/) · © 2026 Security Ronin Ltd
