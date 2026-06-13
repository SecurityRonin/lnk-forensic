#![allow(clippy::unwrap_used, clippy::expect_used)]
//! End-to-end validation against spec-exact, hand-authored `.lnk` fixtures —
//! the Doer-Checker front door for the parse → audit pipeline. The host is
//! macOS and cannot natively author a Windows Shell Link, so the fixtures are
//! built byte-for-byte per `[MS-SHLLINK]`; the generator and how to capture a
//! real `.lnk` are recorded in `tests/data/README.md`.

use lnk_core::{drive_type, parse_shell_link};
use lnk_forensic::{audit, audit_findings, LnkAnomaly};

const REMOVABLE: &[u8] = include_bytes!("../../tests/data/removable_media.lnk");
const NETWORK: &[u8] = include_bytes!("../../tests/data/network_share.lnk");

#[test]
fn removable_fixture_parses_volume_serial_and_local_base_path() {
    let link = parse_shell_link(REMOVABLE).expect("valid [MS-SHLLINK] header");
    let info = link.link_info.as_ref().expect("HasLinkInfo set");
    let vol = info.volume_id.as_ref().expect("VolumeID present");
    assert_eq!(vol.drive_type, drive_type::REMOVABLE);
    assert_eq!(
        vol.drive_serial_number, 0xDEAD_BEEF,
        "drive serial surfaced"
    );
    assert_eq!(vol.volume_label.as_deref(), Some("KINGSTON USB"));
    assert_eq!(info.local_base_path.as_deref(), Some("E:\\payload.exe"));
    // The TrackerDataBlock records the origin machine.
    assert_eq!(
        link.tracker.as_ref().expect("tracker present").machine_id,
        "ANALYST-PC"
    );
}

#[test]
fn removable_fixture_audit_fires_removable_media_finding_with_serial() {
    let link = parse_shell_link(REMOVABLE).unwrap();
    let anomalies = audit(&link);
    let codes: Vec<&str> = anomalies.iter().map(LnkAnomaly::code).collect();
    assert!(
        codes.contains(&"LNK-REMOVABLE-MEDIA-TARGET"),
        "removable-media target not detected; got {codes:?}"
    );
    assert!(
        codes.contains(&"LNK-TRACKER-MACHINE"),
        "tracker-machine attribution not detected; got {codes:?}"
    );

    // The drive serial — the join key to a peripheral DeviceConnection — is
    // surfaced first-class on the removable-media anomaly.
    let serial = anomalies.iter().find_map(|a| match a {
        LnkAnomaly::RemovableMediaTarget { drive_serial, .. } => Some(*drive_serial),
        _ => None,
    });
    assert_eq!(serial, Some(0xDEAD_BEEF), "volume serial join key surfaced");

    // Findings render as graded, hedged observations.
    let findings = audit_findings(&link, "volume: E:");
    assert!(findings
        .iter()
        .any(|f| f.code == "LNK-REMOVABLE-MEDIA-TARGET"));
    for f in &findings {
        assert!(
            f.note.to_ascii_lowercase().contains("consistent with"),
            "must hedge: {}",
            f.note
        );
    }
}

#[test]
fn network_fixture_fires_network_target() {
    let link = parse_shell_link(NETWORK).expect("valid [MS-SHLLINK] header");
    let cnrl = link
        .link_info
        .as_ref()
        .expect("HasLinkInfo")
        .common_network_relative_link
        .as_ref()
        .expect("CommonNetworkRelativeLink present");
    assert_eq!(cnrl.net_name.as_deref(), Some("\\\\SERVER\\share"));

    let codes: Vec<&str> = audit(&link).iter().map(LnkAnomaly::code).collect();
    assert!(
        codes.contains(&"LNK-NETWORK-TARGET"),
        "network target not detected; got {codes:?}"
    );
}
