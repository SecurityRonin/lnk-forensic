//! `lnk-forensic` — graded anomaly auditor over Windows Shell Link (`.lnk`) files.
//!
//! Consumes a [`lnk_core::ShellLink`] and emits
//! [`forensicnomicon::report::Finding`]s. Every anomaly is an **observation**
//! ("consistent with …"); the examiner draws the conclusions. MITRE techniques
//! are narrated as consistency, never as a verdict.

#![forbid(unsafe_code)]

use forensicnomicon::report::{Category, Finding, Observation, Severity, Source};
use lnk_core::{drive_type, ShellLink};

/// A graded Shell Link anomaly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LnkAnomaly {
    /// The link's `VolumeID` describes a removable/external volume — the target
    /// file was opened from external media. MITRE T1052.001 / T1091.
    ///
    /// `drive_serial` is the **join key** to a peripheral `DeviceConnection`:
    /// the same volume serial recorded against a USB mass-storage connection ties
    /// this opened file to that physical device.
    RemovableMediaTarget {
        /// The `VolumeID.DriveType` value.
        drive_type: u32,
        /// The `VolumeID.DriveSerialNumber` — the join key to peripheral-forensic.
        drive_serial: u32,
        /// The local base path on the removable volume, when known.
        path: Option<String>,
    },
    /// The link carries a `CommonNetworkRelativeLink` — the target was opened
    /// from a network share. MITRE T1021.
    NetworkTarget {
        /// The UNC / network share name, when known.
        net_name: Option<String>,
    },
    /// The `TrackerDataBlock` records the origin machine's NetBIOS name —
    /// attribution evidence tying the link to the machine it was authored on.
    TrackerMachine {
        /// The recorded origin machine NetBIOS name.
        machine_id: String,
    },
}

impl LnkAnomaly {
    /// The stable, published anomaly code (scheme-prefixed SCREAMING-KEBAB).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::RemovableMediaTarget { .. } => "LNK-REMOVABLE-MEDIA-TARGET",
            Self::NetworkTarget { .. } => "LNK-NETWORK-TARGET",
            Self::TrackerMachine { .. } => "LNK-TRACKER-MACHINE",
        }
    }
}

impl Observation for LnkAnomaly {
    fn severity(&self) -> Option<Severity> {
        Some(match self {
            Self::RemovableMediaTarget { .. } => Severity::Medium,
            Self::NetworkTarget { .. } => Severity::Low,
            Self::TrackerMachine { .. } => Severity::Info,
        })
    }

    fn code(&self) -> &'static str {
        LnkAnomaly::code(self)
    }

    fn category(&self) -> Category {
        match self {
            Self::RemovableMediaTarget { .. } | Self::NetworkTarget { .. } => Category::Threat,
            Self::TrackerMachine { .. } => Category::Provenance,
        }
    }

    fn mitre(&self) -> &'static [&'static str] {
        match self {
            Self::RemovableMediaTarget { .. } => &["T1052.001", "T1091"],
            Self::NetworkTarget { .. } => &["T1021"],
            Self::TrackerMachine { .. } => &[],
        }
    }

    fn note(&self) -> String {
        match self {
            Self::RemovableMediaTarget {
                drive_type,
                drive_serial,
                path,
            } => format!(
                "the link target resolves to a removable/external volume \
                 (drive_type {drive_type}, drive serial {drive_serial:#010X}{}); consistent with a \
                 file opened from external media (MITRE T1052.001 / T1091). The volume serial is \
                 the join key to a peripheral device connection",
                path.as_deref()
                    .map_or_else(String::new, |p| format!(", path {p:?}"))
            ),
            Self::NetworkTarget { net_name } => format!(
                "the link carries a network relative link{}; consistent with a file opened from a \
                 network share (MITRE T1021)",
                net_name
                    .as_deref()
                    .map_or_else(String::new, |n| format!(" to {n}"))
            ),
            Self::TrackerMachine { machine_id } => format!(
                "the tracker block records the origin machine {machine_id:?}; consistent with the \
                 link having been authored on that machine (attribution)"
            ),
        }
    }
}

/// Audit a [`ShellLink`] into a typed [`LnkAnomaly`] stream.
#[must_use]
pub fn audit(link: &ShellLink) -> Vec<LnkAnomaly> {
    let mut out = Vec::new();

    if let Some(info) = &link.link_info {
        if let Some(vol) = &info.volume_id {
            if is_removable_volume(vol.drive_type, vol.drive_serial_number) {
                out.push(LnkAnomaly::RemovableMediaTarget {
                    drive_type: vol.drive_type,
                    drive_serial: vol.drive_serial_number,
                    path: info.local_base_path.clone(),
                });
            }
        }
        if let Some(cnrl) = &info.common_network_relative_link {
            out.push(LnkAnomaly::NetworkTarget {
                net_name: cnrl.net_name.clone(),
            });
        }
    }

    if let Some(tracker) = &link.tracker {
        if !tracker.machine_id.is_empty() {
            out.push(LnkAnomaly::TrackerMachine {
                machine_id: tracker.machine_id.clone(),
            });
        }
    }

    out
}

/// Whether a `VolumeID` describes external/removable media.
///
/// A `DRIVE_REMOVABLE` drive type is the explicit signal; some links record a
/// `DRIVE_FIXED`/unknown type for a removable volume but still carry a non-zero
/// drive serial, which by itself does not prove removability — so the removable
/// finding fires only on the explicit `DRIVE_REMOVABLE` type. The serial is
/// always surfaced as the cross-artifact join key regardless of type.
fn is_removable_volume(drive_type: u32, _drive_serial: u32) -> bool {
    drive_type == drive_type::REMOVABLE
}

/// Audit and convert directly to graded [`Finding`]s.
#[must_use]
pub fn audit_findings(link: &ShellLink, scope: impl Into<String>) -> Vec<Finding> {
    let src = source(scope);
    audit(link)
        .iter()
        .map(|a| a.to_finding(src.clone()))
        .collect()
}

/// The [`Source`] stamp for findings this analyzer emits.
#[must_use]
pub fn source(scope: impl Into<String>) -> Source {
    Source {
        analyzer: "lnk-forensic".to_string(),
        scope: scope.into(),
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
