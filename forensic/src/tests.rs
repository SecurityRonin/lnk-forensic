// Included into `lib.rs` via `mod tests { include!("tests.rs"); }`.

use super::*;
use lnk_core::{
    CommonNetworkRelativeLink, DroidGuids, LinkInfo, ShellLink, ShellLinkHeader, StringData,
    TrackerDataBlock, VolumeId,
};

fn header() -> ShellLinkHeader {
    ShellLinkHeader {
        link_flags: 0,
        file_attributes: 0,
        creation_time: 0,
        access_time: 0,
        write_time: 0,
        file_size: 0,
        icon_index: 0,
        show_command: 1,
        hotkey: 0,
    }
}

fn link(link_info: Option<LinkInfo>, tracker: Option<TrackerDataBlock>) -> ShellLink {
    ShellLink {
        header: header(),
        link_target_idlist: None,
        link_info,
        string_data: StringData::default(),
        tracker,
    }
}

fn removable_info(serial: u32) -> LinkInfo {
    LinkInfo {
        volume_id: Some(VolumeId {
            drive_type: drive_type::REMOVABLE,
            drive_serial_number: serial,
            volume_label: Some("USB".to_string()),
        }),
        local_base_path: Some("E:\\payload.exe".to_string()),
        common_network_relative_link: None,
    }
}

fn fixed_info() -> LinkInfo {
    LinkInfo {
        volume_id: Some(VolumeId {
            drive_type: drive_type::FIXED,
            drive_serial_number: 0x1111_2222,
            volume_label: Some("OS".to_string()),
        }),
        local_base_path: Some("C:\\Windows\\notepad.exe".to_string()),
        common_network_relative_link: None,
    }
}

fn network_info() -> LinkInfo {
    LinkInfo {
        volume_id: None,
        local_base_path: None,
        common_network_relative_link: Some(CommonNetworkRelativeLink {
            net_name: Some("\\\\SERVER\\share".to_string()),
            device_name: Some("Z:".to_string()),
        }),
    }
}

fn tracker(machine: &str) -> TrackerDataBlock {
    TrackerDataBlock {
        machine_id: machine.to_string(),
        droid: DroidGuids {
            volume: "11111111-2222-3333-4444-555555555555".to_string(),
            object: "66666666-7777-8888-9999-AAAAAAAAAAAA".to_string(),
        },
        birth_droid: DroidGuids {
            volume: "11111111-2222-3333-4444-555555555555".to_string(),
            object: "66666666-7777-8888-9999-AAAAAAAAAAAA".to_string(),
        },
    }
}

fn codes(a: &[LnkAnomaly]) -> Vec<&str> {
    a.iter().map(LnkAnomaly::code).collect()
}

#[test]
fn removable_media_target_fires_medium_threat_and_surfaces_serial() {
    let a = audit(&link(Some(removable_info(0xDEAD_BEEF)), None));
    assert!(codes(&a).contains(&"LNK-REMOVABLE-MEDIA-TARGET"));
    let removable = a
        .iter()
        .find(|x| x.code() == "LNK-REMOVABLE-MEDIA-TARGET")
        .unwrap();
    assert_eq!(removable.severity(), Some(Severity::Medium));
    assert_eq!(removable.category(), Category::Threat);
    assert!(removable.mitre().contains(&"T1052.001"));
    assert!(removable.mitre().contains(&"T1091"));
    // The drive serial is surfaced first-class on the anomaly.
    match removable {
        LnkAnomaly::RemovableMediaTarget { drive_serial, .. } => {
            assert_eq!(*drive_serial, 0xDEAD_BEEF);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn fixed_internal_volume_does_not_fire_removable() {
    let a = audit(&link(Some(fixed_info()), None));
    assert!(!codes(&a).contains(&"LNK-REMOVABLE-MEDIA-TARGET"));
}

#[test]
fn network_target_fires_low_threat_with_share_name() {
    let a = audit(&link(Some(network_info()), None));
    assert!(codes(&a).contains(&"LNK-NETWORK-TARGET"));
    let net = a.iter().find(|x| x.code() == "LNK-NETWORK-TARGET").unwrap();
    assert_eq!(net.severity(), Some(Severity::Low));
    assert!(net.mitre().contains(&"T1021"));
    assert!(net.note().contains("\\\\SERVER\\share"));
}

#[test]
fn tracker_machine_fires_info_provenance() {
    let a = audit(&link(None, Some(tracker("ANALYST-PC"))));
    assert!(codes(&a).contains(&"LNK-TRACKER-MACHINE"));
    let t = a.iter().find(|x| x.code() == "LNK-TRACKER-MACHINE").unwrap();
    assert_eq!(t.severity(), Some(Severity::Info));
    assert_eq!(t.category(), Category::Provenance);
    assert!(t.mitre().is_empty());
    assert!(t.note().contains("ANALYST-PC"));
}

#[test]
fn empty_tracker_machine_does_not_fire() {
    let a = audit(&link(None, Some(tracker(""))));
    assert!(!codes(&a).contains(&"LNK-TRACKER-MACHINE"));
}

#[test]
fn link_with_no_info_or_tracker_fires_nothing() {
    let a = audit(&link(None, None));
    assert!(a.is_empty());
}

#[test]
fn all_three_anomalies_fire_together() {
    // A removable volume + network relative link on one info, plus a tracker.
    let info = LinkInfo {
        volume_id: Some(VolumeId {
            drive_type: drive_type::REMOVABLE,
            drive_serial_number: 0x1234_5678,
            volume_label: None,
        }),
        local_base_path: Some("F:\\nc.exe".to_string()),
        common_network_relative_link: Some(CommonNetworkRelativeLink {
            net_name: Some("\\\\NAS\\pub".to_string()),
            device_name: None,
        }),
    };
    let a = audit(&link(Some(info), Some(tracker("DESKTOP-9"))));
    let c = codes(&a);
    assert!(c.contains(&"LNK-REMOVABLE-MEDIA-TARGET"));
    assert!(c.contains(&"LNK-NETWORK-TARGET"));
    assert!(c.contains(&"LNK-TRACKER-MACHINE"));
}

#[test]
fn findings_are_hedged_observations_never_verdicts() {
    let info = LinkInfo {
        volume_id: Some(VolumeId {
            drive_type: drive_type::REMOVABLE,
            drive_serial_number: 0x1234_5678,
            volume_label: None,
        }),
        local_base_path: Some("F:\\nc.exe".to_string()),
        common_network_relative_link: Some(CommonNetworkRelativeLink {
            net_name: Some("\\\\NAS\\pub".to_string()),
            device_name: None,
        }),
    };
    let f = audit_findings(&link(Some(info), Some(tracker("DESKTOP-9"))), "host");
    assert_eq!(f.len(), 3, "removable + network + tracker = 3 findings");
    for finding in &f {
        let note = finding.note.to_ascii_lowercase();
        assert!(note.contains("consistent with"), "must hedge: {note}");
        for forbidden in ["proves", "confirms", "definitely"] {
            assert!(
                !note.contains(forbidden),
                "must not assert a verdict: {note}"
            );
        }
    }
}

#[test]
fn source_stamps_analyzer_and_version() {
    let s = source("volume: E:");
    assert_eq!(s.analyzer, "lnk-forensic");
    assert_eq!(s.scope, "volume: E:");
    assert!(s.version.is_some());
}
