//! `lnk-core` — a reader for Windows Shell Link (`.lnk`) files.
//!
//! Parses the `[MS-SHLLINK]` *Shell Link (.LNK) Binary File Format* into a typed
//! [`ShellLink`]: the `ShellLinkHeader` (flags, attributes, the three target
//! FILETIMEs, file size, icon index, show command, hotkey), the optional
//! `LinkInfo` (the `VolumeID` drive type / **volume serial number** / label and
//! the local base path, plus a `CommonNetworkRelativeLink` for network targets),
//! the `StringData` block, and the `ExtraData` `TrackerDataBlock` (the origin
//! machine NetBIOS name and the distributed-link-tracking droid GUIDs).
//!
//! The input is attacker-controllable evidence: parsing is bounds-checked, never
//! panics, and never trusts a length field. No `unsafe`. Malformed headers yield
//! [`None`] rather than a partial/garbage value. The format **constants** live in
//! [`forensicnomicon::shlink`] (knowledge-only); the **parsing algorithm** lives
//! here.
//!
//! # Authoritative source
//!
//! `[MS-SHLLINK]` — *Shell Link (.LNK) Binary File Format*:
//! <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943>

#![forbid(unsafe_code)]

use forensicnomicon::shlink;

/// The number of 100-nanosecond intervals between the Windows FILETIME epoch
/// (1601-01-01) and the Unix epoch (1970-01-01).
const FILETIME_UNIX_DELTA_100NS: i64 = 116_444_736_000_000_000;

/// A fully parsed Windows Shell Link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellLink {
    /// The fixed-size `ShellLinkHeader` (`[MS-SHLLINK]` §2.1).
    pub header: ShellLinkHeader,
    /// The raw `LinkTargetIDList` ItemID blob, when `HasLinkTargetIDList` is set.
    ///
    /// v0.1 keeps the PIDL as raw bytes — full ItemID decoding is the job of a
    /// shellbag parser (`shellbag-core`), not this reader.
    pub link_target_idlist: Option<LinkTargetIdList>,
    /// The `LinkInfo` block, when `HasLinkInfo` is set (`[MS-SHLLINK]` §2.3).
    pub link_info: Option<LinkInfo>,
    /// The decoded `StringData` block (`[MS-SHLLINK]` §2.4).
    pub string_data: StringData,
    /// The `TrackerDataBlock` from `ExtraData`, when present (`[MS-SHLLINK]` §2.5.10).
    pub tracker: Option<TrackerDataBlock>,
}

/// The `ShellLinkHeader` (`[MS-SHLLINK]` §2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellLinkHeader {
    /// `LinkFlags` bitfield (`[MS-SHLLINK]` §2.1.1).
    pub link_flags: u32,
    /// `FileAttributesFlags` of the target (`[MS-SHLLINK]` §2.1.2).
    pub file_attributes: u32,
    /// Target creation time, Unix epoch seconds (0 when the FILETIME was 0).
    pub creation_time: i64,
    /// Target last-access time, Unix epoch seconds (0 when the FILETIME was 0).
    pub access_time: i64,
    /// Target last-write time, Unix epoch seconds (0 when the FILETIME was 0).
    pub write_time: i64,
    /// Target file size in bytes (low 32 bits per the spec).
    pub file_size: u32,
    /// Icon index.
    pub icon_index: i32,
    /// `ShowCommand` (e.g. `SW_SHOWNORMAL` = 1).
    pub show_command: u32,
    /// `HotKey` flags.
    pub hotkey: u16,
}

impl ShellLinkHeader {
    /// Whether `LinkFlags` bit `flag` is set.
    #[must_use]
    pub fn has_flag(&self, flag: u32) -> bool {
        self.link_flags & flag != 0
    }
}

/// The raw `LinkTargetIDList` (`[MS-SHLLINK]` §2.2) — PIDL bytes kept verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkTargetIdList {
    /// The `IDListSize`-delimited ItemID blob, raw (no PIDL decode in v0.1).
    pub raw: Vec<u8>,
}

/// The `LinkInfo` block (`[MS-SHLLINK]` §2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkInfo {
    /// The `VolumeID`, when the local-volume bit of `LinkInfoFlags` is set.
    pub volume_id: Option<VolumeId>,
    /// The local base path (ANSI), when present.
    pub local_base_path: Option<String>,
    /// The `CommonNetworkRelativeLink`, when the network bit is set.
    pub common_network_relative_link: Option<CommonNetworkRelativeLink>,
}

/// The `VolumeID` (`[MS-SHLLINK]` §2.3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeId {
    /// `DriveType` (e.g. `DRIVE_REMOVABLE` = 2, `DRIVE_FIXED` = 3).
    pub drive_type: u32,
    /// `DriveSerialNumber` — the join key to a peripheral `DeviceConnection`'s
    /// volume serial. Surfaced as a first-class field.
    pub drive_serial_number: u32,
    /// The volume label, when decodable.
    pub volume_label: Option<String>,
}

/// `DriveType` values (`[MS-SHLLINK]` §2.3.1 / Win32 `GetDriveType`).
pub mod drive_type {
    /// The drive type cannot be determined.
    pub const UNKNOWN: u32 = 0;
    /// The root path is invalid (no volume mounted).
    pub const NO_ROOT_DIR: u32 = 1;
    /// A removable drive (USB stick, memory card, floppy).
    pub const REMOVABLE: u32 = 2;
    /// A fixed (internal) disk.
    pub const FIXED: u32 = 3;
    /// A remote (network) drive.
    pub const REMOTE: u32 = 4;
    /// An optical drive (CD/DVD).
    pub const CDROM: u32 = 5;
    /// A RAM disk.
    pub const RAMDISK: u32 = 6;
}

/// The `CommonNetworkRelativeLink` (`[MS-SHLLINK]` §2.3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommonNetworkRelativeLink {
    /// The UNC share / network name (e.g. `\\\\server\\share`).
    pub net_name: Option<String>,
    /// The local device the share was mapped to (e.g. `Z:`), when present.
    pub device_name: Option<String>,
}

/// The decoded `StringData` block (`[MS-SHLLINK]` §2.4).
///
/// Each field is present only when its corresponding `LinkFlags` bit is set; the
/// encoding follows `IsUnicode` (UTF-16LE) versus the ANSI code page.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StringData {
    /// `NAME_STRING` — the link description (`HasName`).
    pub name: Option<String>,
    /// `RELATIVE_PATH` (`HasRelativePath`).
    pub relative_path: Option<String>,
    /// `WORKING_DIR` (`HasWorkingDir`).
    pub working_dir: Option<String>,
    /// `COMMAND_LINE_ARGUMENTS` (`HasArguments`).
    pub arguments: Option<String>,
    /// `ICON_LOCATION` (`HasIconLocation`).
    pub icon_location: Option<String>,
}

/// The `TrackerDataBlock` (`[MS-SHLLINK]` §2.5.10) — origin machine + droid GUIDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackerDataBlock {
    /// The NetBIOS name of the machine the link was created on.
    pub machine_id: String,
    /// The volume+object `Droid` GUID pair (current).
    pub droid: DroidGuids,
    /// The volume+object `DroidBirth` GUID pair (at creation).
    pub birth_droid: DroidGuids,
}

/// A `Droid` volume/object GUID pair, rendered in the canonical 8-4-4-4-12 form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DroidGuids {
    /// The volume identifier GUID.
    pub volume: String,
    /// The object (file) identifier GUID.
    pub object: String,
}

// ── Bounds-checked little-endian readers (never panic on short input) ─────────

fn le_u16(data: &[u8], off: usize) -> u16 {
    let mut b = [0u8; 2];
    if let Some(s) = data.get(off..off + 2) {
        b.copy_from_slice(s);
    }
    u16::from_le_bytes(b)
}

fn le_u32(data: &[u8], off: usize) -> u32 {
    let mut b = [0u8; 4];
    if let Some(s) = data.get(off..off + 4) {
        b.copy_from_slice(s);
    }
    u32::from_le_bytes(b)
}

fn le_i32(data: &[u8], off: usize) -> i32 {
    le_u32(data, off) as i32
}

fn le_u64(data: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    if let Some(s) = data.get(off..off + 8) {
        b.copy_from_slice(s);
    }
    u64::from_le_bytes(b)
}

/// Convert a Windows FILETIME (100-ns ticks since 1601) to Unix epoch seconds.
/// A zero FILETIME (the "not set" sentinel) maps to 0.
fn filetime_to_unix(ft: u64) -> i64 {
    if ft == 0 {
        return 0;
    }
    ((ft as i64) - FILETIME_UNIX_DELTA_100NS) / 10_000_000
}

/// Format the `LinkCLSID` 16 bytes as the canonical 8-4-4-4-12 GUID string.
///
/// The first three components are little-endian; the last two are big-endian
/// (Microsoft GUID wire order).
fn guid_string(b: &[u8]) -> Option<String> {
    let g = b.get(0..16)?;
    Some(format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
        u16::from_le_bytes([g[4], g[5]]),
        u16::from_le_bytes([g[6], g[7]]),
        g[8],
        g[9],
        g[10],
        g[11],
        g[12],
        g[13],
        g[14],
        g[15],
    ))
}

/// Read a NUL-terminated ANSI string starting at `off` (lossy UTF-8).
fn ansi_z(data: &[u8], off: usize) -> Option<String> {
    let slice = data.get(off..)?;
    let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
    Some(String::from_utf8_lossy(&slice[..end]).into_owned())
}

/// Read a NUL-terminated UTF-16LE string starting at `off`.
fn unicode_z(data: &[u8], off: usize) -> Option<String> {
    let slice = data.get(off..)?;
    let mut units = Vec::new();
    let mut i = 0;
    while i + 1 < slice.len() {
        let u = u16::from_le_bytes([slice[i], slice[i + 1]]);
        if u == 0 {
            break;
        }
        units.push(u);
        i += 2;
    }
    Some(String::from_utf16_lossy(&units))
}

/// Parse a Shell Link from its bytes.
///
/// Returns [`None`] when the `ShellLinkHeader` is not a valid `[MS-SHLLINK]`
/// header (wrong `HeaderSize` or `LinkCLSID`). Never panics on malformed,
/// truncated, or hostile input — every field read is bounds-checked, so a
/// short/garbled body degrades to absent sub-structures rather than a crash.
#[must_use]
pub fn parse_shell_link(data: &[u8]) -> Option<ShellLink> {
    // §2.1 ShellLinkHeader — HeaderSize and LinkCLSID gate validity.
    if le_u32(data, 0) != shlink::HEADER_SIZE {
        return None;
    }
    let clsid = guid_string(data.get(4..20)?)?;
    if clsid != shlink::LINK_CLSID {
        return None;
    }

    let link_flags = le_u32(data, 20);
    let file_attributes = le_u32(data, 24);
    let creation_time = filetime_to_unix(le_u64(data, 28));
    let access_time = filetime_to_unix(le_u64(data, 36));
    let write_time = filetime_to_unix(le_u64(data, 44));
    let file_size = le_u32(data, 52);
    let icon_index = le_i32(data, 56);
    let show_command = le_u32(data, 60);
    let hotkey = le_u16(data, 64);

    let header = ShellLinkHeader {
        link_flags,
        file_attributes,
        creation_time,
        access_time,
        write_time,
        file_size,
        icon_index,
        show_command,
        hotkey,
    };

    // The variable-length sections begin immediately after the 0x4C header.
    let mut off = shlink::HEADER_SIZE as usize;

    // §2.2 LinkTargetIDList — IDListSize-prefixed PIDL blob (kept raw).
    let link_target_idlist = if header.has_flag(shlink::LINK_FLAG_HAS_LINK_TARGET_ID_LIST) {
        let id_list_size = le_u16(data, off) as usize;
        let blob_start = off + 2;
        let raw = data
            .get(blob_start..blob_start + id_list_size)
            .map(<[u8]>::to_vec)
            .unwrap_or_default();
        off = blob_start + id_list_size;
        Some(LinkTargetIdList { raw })
    } else {
        None
    };

    // §2.3 LinkInfo — its own LinkInfoSize-prefixed self-contained structure.
    let link_info = if header.has_flag(shlink::LINK_FLAG_HAS_LINK_INFO) {
        let info = parse_link_info(data, off);
        // Advance past the LinkInfo by its declared size.
        let size = le_u32(data, off) as usize;
        off += size.max(4);
        info
    } else {
        None
    };

    // §2.4 StringData — a run of size-counted strings, each honoring IsUnicode.
    let is_unicode = header.has_flag(shlink::LINK_FLAG_IS_UNICODE);
    let mut string_data = StringData::default();
    for (flag, slot) in [
        (
            shlink::LINK_FLAG_HAS_NAME,
            &mut string_data.name as &mut Option<String>,
        ),
        (shlink::LINK_FLAG_HAS_RELATIVE_PATH, &mut string_data.relative_path),
        (shlink::LINK_FLAG_HAS_WORKING_DIR, &mut string_data.working_dir),
        (shlink::LINK_FLAG_HAS_ARGUMENTS, &mut string_data.arguments),
        (shlink::LINK_FLAG_HAS_ICON_LOCATION, &mut string_data.icon_location),
    ] {
        if header.has_flag(flag) {
            let (value, next) = read_sized_string(data, off, is_unicode);
            *slot = value;
            off = next;
        }
    }

    // §2.5 ExtraData — a chain of {size,signature,payload} blocks, terminated by
    // a size < 0x4. We dispatch only the TrackerDataBlock; the rest are skipped.
    let tracker = parse_extra_data_tracker(data, off);

    Some(ShellLink {
        header,
        link_target_idlist,
        link_info,
        string_data,
        tracker,
    })
}

/// Parse the §2.3 LinkInfo block anchored at `base`.
fn parse_link_info(data: &[u8], base: usize) -> Option<LinkInfo> {
    let size = le_u32(data, base) as usize;
    if size < 0x1C {
        return None;
    }
    let header_size = le_u32(data, base + 4) as usize;
    let flags = le_u32(data, base + 8);
    let volume_id_offset = le_u32(data, base + 12) as usize;
    let local_base_path_offset = le_u32(data, base + 16) as usize;
    let cnrl_offset = le_u32(data, base + 20) as usize;
    // Optional Unicode offsets appear only when the header is >= 0x24.
    let local_base_path_offset_unicode = if header_size >= 0x24 {
        le_u32(data, base + 28) as usize
    } else {
        0
    };

    const VOLUME_ID_AND_LOCAL_BASE_PATH: u32 = 0x1;
    const CNRL_AND_PATH_SUFFIX: u32 = 0x2;

    let volume_id = if flags & VOLUME_ID_AND_LOCAL_BASE_PATH != 0 && volume_id_offset != 0 {
        parse_volume_id(data, base + volume_id_offset)
    } else {
        None
    };

    let local_base_path = if flags & VOLUME_ID_AND_LOCAL_BASE_PATH != 0 {
        if local_base_path_offset_unicode != 0 {
            unicode_z(data, base + local_base_path_offset_unicode)
        } else if local_base_path_offset != 0 {
            ansi_z(data, base + local_base_path_offset)
        } else {
            None
        }
    } else {
        None
    };

    let common_network_relative_link = if flags & CNRL_AND_PATH_SUFFIX != 0 && cnrl_offset != 0 {
        parse_cnrl(data, base + cnrl_offset)
    } else {
        None
    };

    Some(LinkInfo {
        volume_id,
        local_base_path,
        common_network_relative_link,
    })
}

/// Parse the §2.3.1 VolumeID anchored at `base`.
fn parse_volume_id(data: &[u8], base: usize) -> Option<VolumeId> {
    let size = le_u32(data, base) as usize;
    if size < 0x10 {
        return None;
    }
    let drive_type = le_u32(data, base + 4);
    let drive_serial_number = le_u32(data, base + 8);
    let label_offset = le_u32(data, base + 12) as usize;

    // VolumeLabelOffset == 0x14 signals the Unicode label offset lives at +0x10.
    let volume_label = if label_offset == 0x14 {
        let uni_off = le_u32(data, base + 16) as usize;
        unicode_z(data, base + uni_off)
    } else if label_offset != 0 {
        ansi_z(data, base + label_offset)
    } else {
        None
    }
    .filter(|s| !s.is_empty());

    Some(VolumeId {
        drive_type,
        drive_serial_number,
        volume_label,
    })
}

/// Parse the §2.3.2 CommonNetworkRelativeLink anchored at `base`.
fn parse_cnrl(data: &[u8], base: usize) -> Option<CommonNetworkRelativeLink> {
    let size = le_u32(data, base) as usize;
    if size < 0x14 {
        return None;
    }
    let flags = le_u32(data, base + 4);
    let net_name_offset = le_u32(data, base + 8) as usize;
    let device_name_offset = le_u32(data, base + 12) as usize;

    const VALID_DEVICE: u32 = 0x1;

    let net_name = if net_name_offset != 0 {
        ansi_z(data, base + net_name_offset)
    } else {
        None
    };
    let device_name = if flags & VALID_DEVICE != 0 && device_name_offset != 0 {
        ansi_z(data, base + device_name_offset)
    } else {
        None
    };

    Some(CommonNetworkRelativeLink {
        net_name,
        device_name,
    })
}

/// Read a §2.4 size-counted string: a u16 CountCharacters then the chars.
/// Returns the decoded value (when non-empty) and the offset just past it.
fn read_sized_string(data: &[u8], off: usize, is_unicode: bool) -> (Option<String>, usize) {
    let count = le_u16(data, off) as usize;
    let body = off + 2;
    if is_unicode {
        let byte_len = count * 2;
        let value = data
            .get(body..body + byte_len)
            .map(decode_utf16le)
            .filter(|s| !s.is_empty());
        (value, body + byte_len)
    } else {
        let value = data
            .get(body..body + count)
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .filter(|s| !s.is_empty());
        (value, body + count)
    }
}

fn decode_utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Walk the §2.5 ExtraData chain and return the TrackerDataBlock if present.
fn parse_extra_data_tracker(data: &[u8], start: usize) -> Option<TrackerDataBlock> {
    let mut off = start;
    // Bound the walk by the buffer length; a size < 0x4 terminates the chain.
    while off + 8 <= data.len() {
        let block_size = le_u32(data, off) as usize;
        if (block_size as u32) < shlink::EXTRA_DATA_TERMINAL_BLOCK_SIZE {
            break;
        }
        let signature = le_u32(data, off + 4);
        if signature == shlink::EXTRA_TRACKER_DATA_BLOCK {
            return parse_tracker_block(data, off);
        }
        // Advance past this block; a zero/under-size block would loop forever.
        if block_size < 4 {
            break; // cov:unreachable: block_size >= 0x4 guaranteed by the check above
        }
        off += block_size;
    }
    None
}

/// Parse the §2.5.10 TrackerDataBlock anchored at `base`.
fn parse_tracker_block(data: &[u8], base: usize) -> Option<TrackerDataBlock> {
    // Layout from base: +0 BlockSize, +4 BlockSignature, +8 Length, +12 Version,
    // +16 MachineID[16] (ASCII, NUL-padded), +32 Droid (32 bytes = 2 GUIDs),
    // +64 DroidBirth (32 bytes = 2 GUIDs).
    let machine_id = ansi_z(data, base + 16)?;
    let droid = DroidGuids {
        volume: guid_string(data.get(base + 32..base + 48)?)?,
        object: guid_string(data.get(base + 48..base + 64)?)?,
    };
    let birth_droid = DroidGuids {
        volume: guid_string(data.get(base + 64..base + 80)?)?,
        object: guid_string(data.get(base + 80..base + 96)?)?,
    };
    Some(TrackerDataBlock {
        machine_id,
        droid,
        birth_droid,
    })
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
