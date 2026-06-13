# lnk-forensic

[![Crates.io](https://img.shields.io/crates/v/lnk-forensic)](https://crates.io/crates/lnk-forensic)
[![Docs.rs](https://img.shields.io/docsrs/lnk-forensic)](https://docs.rs/lnk-forensic)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](../LICENSE)

**Graded anomaly auditor for Windows Shell Link (`.lnk`) files — removable-media targets, network-share targets, and origin-machine attribution as `forensicnomicon::report::Finding`s.**

The analyzer half of
[`lnk-forensic`](https://github.com/SecurityRonin/lnk-forensic); pair it with the
[`lnk-core`](https://crates.io/crates/lnk-core) reader.

```rust
use lnk_core::parse_shell_link;
use lnk_forensic::audit_findings;

if let Some(link) = parse_shell_link(lnk_bytes) {
    for f in audit_findings(&link, "volume: E:") {
        println!("[{:?}] {} — {}", f.severity, f.code, f.note);
    }
}
```

## The anomaly codes

| Code | Severity | Category | What it observes |
|---|---|---|---|
| `LNK-REMOVABLE-MEDIA-TARGET` | Medium | Threat | The `VolumeID` describes a `DRIVE_REMOVABLE` volume — consistent with a file opened from external media (MITRE T1052.001 / T1091). The **volume serial** is surfaced as the join key to a peripheral device connection. |
| `LNK-NETWORK-TARGET` | Low | Threat | The link carries a `CommonNetworkRelativeLink` — consistent with a file opened from a network share (MITRE T1021). |
| `LNK-TRACKER-MACHINE` | Info | Provenance | The `TrackerDataBlock` records the origin machine's NetBIOS name — consistent with the link having been authored on that machine (attribution). |

Each anomaly is an **observation** ("consistent with …"), never a verdict; the
examiner draws the conclusions. `audit(&link)` returns the typed `LnkAnomaly`
stream; each emits a graded `report::Finding` via `to_finding(source)`, and
`audit_findings(&link, scope)` does both in one call. `source(scope)` stamps the
analyzer provenance.

## The volume serial join key

A `.lnk`'s `VolumeID.DriveSerialNumber` is the same 32-bit serial a USB
mass-storage device records elsewhere on the host. It is surfaced first-class on
the removable-media anomaly so a file opened from external media can be correlated
with the physical device that carried it (a
[`peripheral-forensic`](https://github.com/SecurityRonin/peripheral-forensic)
`DeviceConnection`).

[Privacy Policy](https://securityronin.github.io/lnk-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/lnk-forensic/terms/) · © 2026 Security Ronin Ltd
