#![allow(clippy::unwrap_used, clippy::expect_used)]
//! End-to-end validation against spec-exact, hand-authored Jump List fixtures —
//! the Doer-Checker front door for the CFB/DestList + custom-destinations parse
//! → audit pipeline. The host is macOS and cannot natively author a Windows Jump
//! List, so the fixtures are built byte-for-byte per the libyal dtformats spec
//! (the runnable generator is `core/examples/gen_jumplist.rs`); see
//! `tests/data/README.md` for provenance and citations. No real user's Jump List
//! is committed.

use forensicnomicon::jumplist::appid_name;
use lnk_core::{drive_type, parse_automatic_destinations, parse_custom_destinations, JumpListKind};
use lnk_forensic::audit_jumplist;

const AUTOMATIC: &[u8] =
    include_bytes!("../../tests/data/pinned_removable.automaticDestinations-ms");
const CUSTOM: &[u8] = include_bytes!("../../tests/data/tasks.customDestinations-ms");

#[test]
fn automatic_fixture_parses_destlist_and_embedded_removable_lnk() {
    let jl =
        parse_automatic_destinations(AUTOMATIC, Some("1b4dd67f29cb1962.automaticDestinations-ms"))
            .expect("valid CFB automatic-destinations");

    assert_eq!(jl.kind, JumpListKind::Automatic);
    assert_eq!(jl.app_id.as_deref(), Some("1b4dd67f29cb1962"));
    assert_eq!(jl.entries.len(), 1);

    let e = &jl.entries[0];
    let dl = e.destlist.as_ref().expect("destlist metadata");
    assert_eq!(dl.entry_number, 1);
    assert_eq!(dl.hostname, "OTHER-PC");
    assert!(dl.pinned, "the entry is pinned");
    assert_eq!(dl.access_count, Some(7));
    assert_eq!(dl.path, "E:\\report.docx");

    // The embedded LNK surfaces the removable VolumeID serial join key.
    let vol = e
        .link
        .link_info
        .as_ref()
        .unwrap()
        .volume_id
        .as_ref()
        .unwrap();
    assert_eq!(vol.drive_type, drive_type::REMOVABLE);
    assert_eq!(vol.drive_serial_number, 0xDEAD_BEEF);
}

#[test]
fn automatic_fixture_audit_fires_pinned_appid_and_removable() {
    let jl =
        parse_automatic_destinations(AUTOMATIC, Some("1b4dd67f29cb1962.automaticDestinations-ms"))
            .unwrap();

    // The AppID resolves to Windows Explorer.
    assert_eq!(appid_name("1b4dd67f29cb1962"), Some("Windows Explorer"));

    let findings = audit_jumplist(&jl, Some("ACQUISITION-HOST"), "jumplist: explorer");
    let codes: Vec<&str> = findings.iter().map(|f| f.code.as_ref()).collect();

    assert!(
        codes.contains(&"JUMPLIST-APPID-IDENTIFIED"),
        "got {codes:?}"
    );
    assert!(codes.contains(&"JUMPLIST-PINNED-TARGET"), "got {codes:?}");
    // OTHER-PC != ACQUISITION-HOST → cross-machine.
    assert!(codes.contains(&"JUMPLIST-CROSS-MACHINE"), "got {codes:?}");
    assert!(codes.contains(&"JUMPLIST-MRU-RECENCY"), "got {codes:?}");
    // The embedded LNK audit is reused — removable finding surfaces for free.
    assert!(
        codes.contains(&"LNK-REMOVABLE-MEDIA-TARGET"),
        "embedded LNK audit not reused; got {codes:?}"
    );

    // Every finding is a hedged observation, never a verdict.
    for f in &findings {
        let note = f.note.to_ascii_lowercase();
        assert!(note.contains("consistent with"), "must hedge: {note}");
        for forbidden in ["proves", "confirms"] {
            assert!(!note.contains(forbidden), "must not assert: {note}");
        }
    }
}

#[test]
fn custom_fixture_parses_and_audits_embedded_lnk() {
    let jl = parse_custom_destinations(CUSTOM, Some("5d696d521de238c3.customDestinations-ms"))
        .expect("valid custom-destinations");

    assert_eq!(jl.kind, JumpListKind::Custom);
    assert_eq!(jl.app_id.as_deref(), Some("5d696d521de238c3"));
    assert_eq!(jl.entries.len(), 1, "one embedded LNK split out");

    let vol = jl.entries[0]
        .link
        .link_info
        .as_ref()
        .unwrap()
        .volume_id
        .as_ref()
        .unwrap();
    assert_eq!(vol.drive_serial_number, 0xDEAD_BEEF);

    // The AppID resolves to Chrome; the embedded removable LNK audits for free.
    assert_eq!(appid_name("5d696d521de238c3"), Some("Chrome"));
    let findings = audit_jumplist(&jl, None, "jumplist: chrome tasks");
    let codes: Vec<&str> = findings.iter().map(|f| f.code.as_ref()).collect();
    assert!(
        codes.contains(&"JUMPLIST-APPID-IDENTIFIED"),
        "got {codes:?}"
    );
    assert!(
        codes.contains(&"LNK-REMOVABLE-MEDIA-TARGET"),
        "embedded LNK audit not reused; got {codes:?}"
    );
}
