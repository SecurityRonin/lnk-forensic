//! `lnk-forensic` — graded anomaly auditor over Windows Shell Link (`.lnk`) files.
//!
//! Consumes a [`lnk_core::ShellLink`] and emits
//! [`forensicnomicon::report::Finding`]s. Every anomaly is an **observation**
//! ("consistent with …"); the examiner draws the conclusions. MITRE techniques
//! are narrated as consistency, never as a verdict.

#![forbid(unsafe_code)]

use forensicnomicon::jumplist::appid_name;
use forensicnomicon::report::{Category, Finding, Observation, Severity, Source};
use lnk_core::{drive_type, JumpList, ShellLink};

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

// ── Jump List anomalies ───────────────────────────────────────────────────────

/// A graded Jump List anomaly, layered on top of the per-link [`LnkAnomaly`]
/// findings (each embedded shell link is audited with [`audit`] for free).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JumpListAnomaly {
    /// A `DestList` entry is pinned — the user deliberately fixed this target to
    /// the application's Jump List. Provenance, not suspicious on its own.
    PinnedTarget {
        /// The pinned target path recorded in the `DestList`.
        path: String,
    },
    /// A `DestList` entry's origin hostname has no match to the acquisition host
    /// — consistent with the artifact (or the target) having originated on a
    /// different machine. We state only "no match to the acquisition host".
    CrossMachine {
        /// The origin hostname recorded in the `DestList`.
        hostname: String,
        /// The acquisition host the hostname was compared against.
        acquisition_host: String,
    },
    /// A `DestList` entry records MRU recency: a last-access time and an access
    /// count — the application's own usage history for this target.
    MruRecency {
        /// The target path.
        path: String,
        /// Access count (Windows 10/11 `DestList`), when present.
        access_count: Option<u32>,
        /// Last-access time, Unix epoch seconds.
        last_access: i64,
    },
    /// The Jump List's `AppID` resolves to a known application — provenance for
    /// which program owns this MRU history.
    AppIdIdentified {
        /// The `AppID` (lowercase hex).
        app_id: String,
        /// The resolved application name.
        application: &'static str,
    },
}

impl JumpListAnomaly {
    /// The stable, published anomaly code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::PinnedTarget { .. } => "JUMPLIST-PINNED-TARGET",
            Self::CrossMachine { .. } => "JUMPLIST-CROSS-MACHINE",
            Self::MruRecency { .. } => "JUMPLIST-MRU-RECENCY",
            Self::AppIdIdentified { .. } => "JUMPLIST-APPID-IDENTIFIED",
        }
    }
}

impl Observation for JumpListAnomaly {
    fn severity(&self) -> Option<Severity> {
        Some(match self {
            Self::PinnedTarget { .. } | Self::CrossMachine { .. } => Severity::Low,
            Self::MruRecency { .. } | Self::AppIdIdentified { .. } => Severity::Info,
        })
    }

    fn code(&self) -> &'static str {
        JumpListAnomaly::code(self)
    }

    fn category(&self) -> Category {
        match self {
            Self::MruRecency { .. } => Category::History,
            Self::PinnedTarget { .. }
            | Self::CrossMachine { .. }
            | Self::AppIdIdentified { .. } => Category::Provenance,
        }
    }

    fn note(&self) -> String {
        match self {
            Self::PinnedTarget { path } => format!(
                "the Jump List entry for {path:?} is pinned; consistent with the user having \
                 deliberately fixed this target to the application's Jump List"
            ),
            Self::CrossMachine {
                hostname,
                acquisition_host,
            } => format!(
                "the Jump List entry records origin hostname {hostname:?}, which has no match to \
                 the acquisition host {acquisition_host:?}; consistent with the target having been \
                 accessed from, or the artifact having originated on, a different machine"
            ),
            Self::MruRecency {
                path,
                access_count,
                last_access,
            } => format!(
                "the Jump List records MRU recency for {path:?} (access count {}, last access \
                 {last_access}); consistent with the application's own usage history for this \
                 target",
                access_count.map_or_else(|| "unknown".to_string(), |c| c.to_string())
            ),
            Self::AppIdIdentified {
                app_id,
                application,
            } => format!(
                "the Jump List AppID {app_id} is consistent with the application {application:?}"
            ),
        }
    }
}

/// Audit a [`JumpList`] into graded [`Finding`]s.
///
/// Runs the existing per-link [`audit`] over **every** embedded shell link
/// (so removable-media / network / tracker findings come for free), then adds
/// the Jump-List-level findings: pinned targets, cross-machine origin
/// hostnames (compared against `acquisition_host`), MRU recency, and a resolved
/// `AppID`. `acquisition_host` is the examiner's host for the cross-machine
/// comparison; pass `None` to skip that check.
#[must_use]
pub fn audit_jumplist(
    jl: &JumpList,
    acquisition_host: Option<&str>,
    scope: impl Into<String>,
) -> Vec<Finding> {
    let src = source(scope);
    let mut out = Vec::new();

    // The AppID is a property of the whole list — emit it once.
    if let Some(app_id) = &jl.app_id {
        if let Some(application) = appid_name(app_id) {
            out.push(
                JumpListAnomaly::AppIdIdentified {
                    app_id: app_id.clone(),
                    application,
                }
                .to_finding(src.clone()),
            );
        }
    }

    for entry in &jl.entries {
        // Reuse the per-link LNK audit — removable/network/tracker for free.
        for anomaly in audit(&entry.link) {
            out.push(anomaly.to_finding(src.clone()));
        }

        let Some(dl) = &entry.destlist else {
            continue;
        };

        if dl.pinned {
            out.push(
                JumpListAnomaly::PinnedTarget {
                    path: dl.path.clone(),
                }
                .to_finding(src.clone()),
            );
        }

        if let Some(host) = acquisition_host {
            if !dl.hostname.is_empty() && !dl.hostname.eq_ignore_ascii_case(host) {
                out.push(
                    JumpListAnomaly::CrossMachine {
                        hostname: dl.hostname.clone(),
                        acquisition_host: host.to_string(),
                    }
                    .to_finding(src.clone()),
                );
            }
        }

        // MRU recency: emit when the entry carries usage history.
        if dl.access_count.is_some() || dl.last_access > 0 {
            out.push(
                JumpListAnomaly::MruRecency {
                    path: dl.path.clone(),
                    access_count: dl.access_count,
                    last_access: dl.last_access,
                }
                .to_finding(src.clone()),
            );
        }
    }

    out
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
