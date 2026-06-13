# lnk-forensic

[![Crates.io lnk-core](https://img.shields.io/crates/v/lnk-core?label=lnk-core)](https://crates.io/crates/lnk-core)
[![Crates.io lnk-forensic](https://img.shields.io/crates/v/lnk-forensic?label=lnk-forensic)](https://crates.io/crates/lnk-forensic)
[![Docs.rs](https://img.shields.io/docsrs/lnk-core?label=docs.rs)](https://docs.rs/lnk-core)
[![Rust 1.81+](https://img.shields.io/badge/rust-1.81%2B-blue.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

[![CI](https://github.com/SecurityRonin/lnk-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/lnk-forensic/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-100%25%20lib-brightgreen.svg)](https://github.com/SecurityRonin/lnk-forensic/actions/workflows/ci.yml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![Security advisories](https://img.shields.io/badge/security-advisories%20clean-brightgreen.svg)](deny.toml)

**Turn a Windows `.lnk` shortcut into graded forensic findings — surface the file opened from a USB stick, the share it came off, and the machine it was authored on, with the volume serial that ties it back to the physical device.**

A `.lnk` is a rich `[MS-SHLLINK]` artifact: it records the target path, the volume
serial and MAC timestamps, the origin machine's NetBIOS name, and a distributed-
link-tracking droid GUID — often evidence of a file that no longer exists.
`lnk-forensic` reads it from a link authored on **any** Windows host and grades
what matters for triage.

## Audit a Shell Link in 30 seconds

```toml
[dependencies]
lnk-forensic = "0.1"   # pulls in lnk-core
```

```rust
use lnk_core::parse_shell_link;
use lnk_forensic::{audit_findings};

// .lnk bytes off disk; a malformed header yields None, never a panic.
if let Some(link) = parse_shell_link(lnk_bytes) {
    for f in audit_findings(&link, "volume: E:") {
        println!("[{:?}] {} — {}", f.severity, f.code, f.note);
        // e.g. [Some(Medium)] LNK-REMOVABLE-MEDIA-TARGET — the link target resolves to a removable …
    }
}
```

Want the typed stream instead of graded findings? `audit(&link)` returns
`Vec<LnkAnomaly>`; each anomaly emits a `forensicnomicon::report::Finding` via
`to_finding(source)`.

## The anomaly codes

Each anomaly is an **observation** ("consistent with …"); the examiner draws the
conclusions. Codes are a stable, published contract.

| Code | Severity | Category | What it observes |
|---|---|---|---|
| `LNK-REMOVABLE-MEDIA-TARGET` | Medium | Threat | The `VolumeID` describes a `DRIVE_REMOVABLE` volume — consistent with a file opened from external media (MITRE T1052.001 / T1091). The **volume serial** is surfaced as the join key to a peripheral device connection. |
| `LNK-NETWORK-TARGET` | Low | Threat | The link carries a `CommonNetworkRelativeLink` — consistent with a file opened from a network share (MITRE T1021). |
| `LNK-TRACKER-MACHINE` | Info | Provenance | The `TrackerDataBlock` records the origin machine's NetBIOS name — consistent with the link having been authored on that machine (attribution). |

## The volume serial is a cross-artifact join key

A `.lnk`'s `VolumeID.DriveSerialNumber` is the same 32-bit volume serial a USB
mass-storage device records in the registry / setupapi log. `lnk-forensic`
surfaces it first-class on the removable-media anomaly so an examiner can
**correlate** a file opened from external media (this link) with the **physical
device** that carried it (a
[`peripheral-forensic`](https://github.com/SecurityRonin/peripheral-forensic)
`DeviceConnection`). The serial is the join key — the link surfaces the value, the
examiner reconciles it.

## The two-crate split

- **`lnk-core`** — the reader. Parses the 0x4C `ShellLinkHeader` (LinkFlags,
  FileAttributes, the three target FILETIMEs → Unix epoch, file size, icon index,
  show command, hotkey), the `LinkInfo` block (`VolumeID` drive type + serial +
  label, local base path, `CommonNetworkRelativeLink`), ANSI/Unicode `StringData`,
  the raw `LinkTargetIDList` PIDL blob (full PIDL decode is a shellbag parser's
  job), and the `ExtraData` `TrackerDataBlock`. Format constants come from
  [`forensicnomicon::shlink`](https://crates.io/crates/forensicnomicon); the
  parsing algorithm lives here. No findings.
- **`lnk-forensic`** — the analyzer. Audits a `ShellLink` into graded
  `forensicnomicon::report::Finding`s. Depends on `lnk-core`.

## Trust, but verify

Built for untrusted `.lnk` files from potentially compromised systems:

- **`#![forbid(unsafe_code)]`** across both crates — no FFI, no C bindings.
- **Panic-free on malicious input** — every integer/length/offset read is
  bounds-checked; the workspace denies `clippy::unwrap_used` and
  `clippy::expect_used` in production code. A truncated or garbled link yields
  absent sub-structures or `None`, never a crash.
- **Fuzzed** — `cargo-fuzz` targets `shelllink` (the reader) and `forensic` (the
  full parse → audit pipeline); a `fuzz.yml` CI workflow builds and smoke-runs
  each.
- **Validated against spec-exact artifacts** — the pipeline is exercised
  end-to-end against hand-authored `[MS-SHLLINK]` fixtures (a removable-media link
  with a volume serial + a network-share link), with the removable, tracker, and
  network findings re-surfaced (see `forensic/tests/real_data.rs`).

```bash
cargo test
cargo +nightly fuzz run forensic   # requires nightly + cargo-fuzz
```

## Where this fits

`lnk-forensic` is a parser/analyzer in the SecurityRonin forensic fleet: each
crate is a deep expert in one artifact family, emitting the shared
`forensicnomicon::report` vocabulary so findings aggregate uniformly across disk,
memory, log, and registry artifacts.

[Privacy Policy](https://securityronin.github.io/lnk-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/lnk-forensic/terms/) · © 2026 Security Ronin Ltd
