//! Windows Jump List reader — `*.automaticDestinations-ms` (an OLE/CFB compound
//! file holding a `DestList` MRU stream plus one embedded `[MS-SHLLINK]` shell
//! link per entry) and `*.customDestinations-ms` (a flat sequence of categories,
//! each a run of concatenated shell links).
//!
//! Forensic value: a Jump List ties a per-application MRU history (recency, pin
//! state, access count, origin hostname) to the full target evidence of each
//! embedded `.lnk` (path, volume serial, droid GUIDs). The offset tables and the
//! `0xBABFFBAB` footer / CLSID boundary live in
//! [`forensicnomicon::jumplist`] (knowledge-only); the parsing is here.
//!
//! Input is attacker-controllable evidence: every read is bounds-checked, the
//! CFB layer is the mature `cfb` crate, declared shell-link sizes are treated as
//! unreliable (the custom-destinations splitter scans for the CLSID/footer
//! rather than trusting a length), and the path string is decoded **lossily**
//! because a `DestList` path may carry unpaired surrogates. Malformed input
//! yields [`None`] or an empty entry list, never a panic.
//!
//! # Authoritative source
//!
//! libyal `dtformats`, *Jump lists format*:
//! <https://github.com/libyal/dtformats/blob/main/documentation/Jump%20lists%20format.asciidoc>

use std::io::{Cursor, Read};

use forensicnomicon::jumplist as jl;
use forensicnomicon::shlink;

use crate::{filetime_to_unix, guid_string, parse_shell_link, ShellLink};

/// Which Jump List family a [`JumpList`] was parsed from.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JumpListKind {
    /// `*.automaticDestinations-ms` — a CFB compound file with a `DestList`
    /// MRU stream and one shell-link sub-stream per entry.
    Automatic,
    /// `*.customDestinations-ms` — flat category list of embedded shell links.
    Custom,
}

/// A parsed Jump List.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpList {
    /// Which family the list came from.
    pub kind: JumpListKind,
    /// The owning application's `AppID` (lowercase hex), when the caller passed
    /// the source filename. Resolve a friendly name with
    /// [`forensicnomicon::jumplist::appid_name`].
    pub app_id: Option<String>,
    /// The entries, in stream/category order.
    pub entries: Vec<JumpListEntry>,
}

/// One Jump List entry: an embedded shell link plus, for automatic
/// destinations, its `DestList` MRU metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpListEntry {
    /// The `DestList` MRU record, present only for automatic destinations.
    pub destlist: Option<DestListEntry>,
    /// The embedded `[MS-SHLLINK]` shell link.
    pub link: ShellLink,
}

/// A `DestList` stream entry — the per-target MRU metadata that accompanies an
/// embedded shell link in an automatic-destinations Jump List.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestListEntry {
    /// `DroidVolumeIdentifier` GUID (NTFS object-id volume), canonical form.
    pub droid_volume_guid: String,
    /// `DroidFileIdentifier` GUID (NTFS object-id file), canonical form.
    pub droid_file_guid: String,
    /// `BirthDroidVolumeIdentifier` GUID (at creation), canonical form.
    pub birth_droid_volume_guid: String,
    /// `BirthDroidFileIdentifier` GUID (at creation), canonical form.
    pub birth_droid_file_guid: String,
    /// Origin hostname / NetBIOS name (ASCII, NUL padding trimmed).
    pub hostname: String,
    /// Entry number — also the name of the LNK sub-stream (lowercase hex).
    pub entry_number: u32,
    /// Last-access time, Unix epoch seconds (0 when the FILETIME was 0).
    pub last_access: i64,
    /// Whether the entry is pinned (`PinStatus >= 0`).
    pub pinned: bool,
    /// Access count — present only in the v2+ (Windows 10/11) layout.
    pub access_count: Option<u32>,
    /// The target path recorded in the `DestList` (UTF-16, decoded lossily).
    pub path: String,
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

/// Decode `count` UTF-16LE code units starting at `off`, **lossily** (a DestList
/// path may carry unpaired surrogates). Returns the decoded string and the
/// offset just past the consumed bytes.
fn utf16le_lossy(data: &[u8], off: usize, count: usize) -> (String, usize) {
    let byte_len = count.saturating_mul(2);
    let end = off.saturating_add(byte_len);
    let units: Vec<u16> = data
        .get(off..end)
        .unwrap_or_default()
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    (String::from_utf16_lossy(&units), end)
}

/// Extract the `AppID` (lowercase hex) from a Jump List filename such as
/// `1b4dd67f29cb1962.automaticDestinations-ms`.
fn appid_from_filename(name: &str) -> Option<String> {
    let stem = name
        .rsplit('/')
        .next()
        .unwrap_or(name)
        .rsplit('\\')
        .next()
        .unwrap_or(name);
    let id = stem.split('.').next().unwrap_or(stem);
    if !id.is_empty() && id.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(id.to_ascii_lowercase())
    } else {
        None
    }
}

/// Parse a `*.automaticDestinations-ms` Jump List from its bytes.
///
/// Opens the bytes as a CFB compound file, reads the `DestList` MRU stream, and
/// for each entry opens the matching hex-named shell-link sub-stream and decodes
/// it with [`parse_shell_link`]. `app_id` is taken from `filename` when given
/// (e.g. `"1b4dd67f29cb1962.automaticDestinations-ms"`).
///
/// Returns [`None`] when the bytes are not a valid CFB compound file or carry no
/// `DestList` stream. Never panics on hostile input.
#[must_use]
pub fn parse_automatic_destinations(data: &[u8], filename: Option<&str>) -> Option<JumpList> {
    let mut comp = cfb::CompoundFile::open(Cursor::new(data)).ok()?;

    // Read the whole DestList stream into memory (bounded by the CFB layer).
    let destlist = {
        let mut stream = comp.open_stream("DestList").ok()?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).ok()?;
        buf
    };

    let format_version = le_u32(&destlist, jl::DESTLIST_HEADER_FORMAT_VERSION_OFFSET);
    let extended = format_version >= 2;

    let mut entries = Vec::new();
    let mut off = jl::DESTLIST_HEADER_SIZE;
    // Bound the walk by the buffer; each iteration must make forward progress.
    while off + jl::DESTLIST_ENTRY_PIN_STATUS_OFFSET + 4 <= destlist.len() {
        let (destlist_entry, next) = parse_destlist_entry(&destlist, off, extended);
        if next <= off {
            break; // cov:unreachable: parse_destlist_entry always advances past the path
        }
        off = next;

        // The LNK sub-stream is named by the entry number in lowercase hex.
        let stream_name = format!("{:x}", destlist_entry.entry_number);
        if let Ok(mut stream) = comp.open_stream(&stream_name) {
            let mut lnk = Vec::new();
            if stream.read_to_end(&mut lnk).is_ok() {
                if let Some(link) = parse_shell_link(&lnk) {
                    entries.push(JumpListEntry {
                        destlist: Some(destlist_entry),
                        link,
                    });
                }
            }
        }
    }

    Some(JumpList {
        kind: JumpListKind::Automatic,
        app_id: filename.and_then(appid_from_filename),
        entries,
    })
}

/// Parse one `DestList` entry anchored at `base`. Returns the decoded entry and
/// the offset of the next entry (past the path and, for v2+, the alignment).
fn parse_destlist_entry(data: &[u8], base: usize, extended: bool) -> (DestListEntry, usize) {
    let guid_at = |field_off: usize| -> String {
        data.get(base + field_off..base + field_off + 16)
            .and_then(guid_string)
            .unwrap_or_default()
    };

    let droid_volume_guid = guid_at(jl::DESTLIST_ENTRY_DROID_VOLUME_GUID_OFFSET);
    let droid_file_guid = guid_at(jl::DESTLIST_ENTRY_DROID_FILE_GUID_OFFSET);
    let birth_droid_volume_guid = guid_at(jl::DESTLIST_ENTRY_BIRTH_DROID_VOLUME_GUID_OFFSET);
    let birth_droid_file_guid = guid_at(jl::DESTLIST_ENTRY_BIRTH_DROID_FILE_GUID_OFFSET);

    let hostname = {
        let start = base + jl::DESTLIST_ENTRY_HOSTNAME_OFFSET;
        let raw = data
            .get(start..start + jl::DESTLIST_ENTRY_HOSTNAME_SIZE)
            .unwrap_or_default();
        let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
        String::from_utf8_lossy(&raw[..end]).into_owned()
    };

    let entry_number = le_u32(data, base + jl::DESTLIST_ENTRY_ENTRY_NUMBER_OFFSET);
    let last_access =
        filetime_to_unix(le_u64(data, base + jl::DESTLIST_ENTRY_LAST_ACCESS_FILETIME_OFFSET));
    let pin_status = le_i32(data, base + jl::DESTLIST_ENTRY_PIN_STATUS_OFFSET);
    let pinned = pin_status >= 0;

    let (access_count, path_size_off, path_off, trailing) = if extended {
        (
            Some(le_u32(data, base + jl::DESTLIST_ENTRY_V2_ACCESS_COUNT_OFFSET)),
            jl::DESTLIST_ENTRY_V2_PATH_SIZE_OFFSET,
            jl::DESTLIST_ENTRY_V2_PATH_OFFSET,
            jl::DESTLIST_ENTRY_V2_TRAILING_ALIGNMENT,
        )
    } else {
        (
            None,
            jl::DESTLIST_ENTRY_V1_PATH_SIZE_OFFSET,
            jl::DESTLIST_ENTRY_V1_PATH_OFFSET,
            0,
        )
    };

    let path_chars = le_u16(data, base + path_size_off) as usize;
    let (path, after_path) = utf16le_lossy(data, base + path_off, path_chars);
    let next = after_path.saturating_add(trailing);

    (
        DestListEntry {
            droid_volume_guid,
            droid_file_guid,
            birth_droid_volume_guid,
            birth_droid_file_guid,
            hostname,
            entry_number,
            last_access,
            pinned,
            access_count,
            path,
        },
        next,
    )
}

/// Parse a `*.customDestinations-ms` Jump List from its bytes.
///
/// Validates the flat header (`FormatVersion == 2`), then splits the embedded
/// shell links by scanning for the `[MS-SHLLINK]` CLSID and the `0xBABFFBAB`
/// footer — declared sizes are unreliable — and structurally decodes each LNK
/// with [`parse_shell_link`]. Category boundaries are not preserved in v0.2; the
/// entries are returned flat in file order.
///
/// Returns [`None`] when the header format version is not `2`.
#[must_use]
pub fn parse_custom_destinations(data: &[u8], filename: Option<&str>) -> Option<JumpList> {
    if le_u32(data, 0) != jl::CUSTOM_DESTINATIONS_FORMAT_VERSION {
        return None;
    }

    // The 16-byte LNK CLSID, in little-endian wire order, prefixes every
    // shell-object entry. NB: the embedded LNK's *own* header also carries this
    // CLSID at its byte +4 — so a position only marks a shell-object boundary
    // when the bytes right after it begin a valid LNK header (HeaderSize 0x4C +
    // a second CLSID copy). That structural test rejects the internal header.
    let clsid_bytes = clsid_wire_bytes();
    let is_entry_prefix = |p: usize| -> bool {
        // p..p+16 is the prefix CLSID; the LNK starts at p+16 and must open with
        // HeaderSize 0x4C and the LinkCLSID at p+20.
        data.get(p..p + 16) == Some(&clsid_bytes[..])
            && le_u32(data, p + 16) == shlink::HEADER_SIZE
            && data.get(p + 20..p + 36) == Some(&clsid_bytes[..])
    };

    // Find each shell-object-entry boundary (skip 0x4C past a match so the LNK's
    // own internal CLSID copy is never mistaken for the next entry).
    let mut starts = Vec::new();
    let mut i = 12; // past the 12-byte file header
    while i + 36 <= data.len() {
        if is_entry_prefix(i) {
            starts.push(i);
            i += 16 + shlink::HEADER_SIZE as usize;
        } else {
            i += 1;
        }
    }

    let mut entries = Vec::new();
    for (idx, &prefix) in starts.iter().enumerate() {
        // The LNK data begins right after the 16-byte CLSID prefix and runs to
        // the next entry prefix, the footer signature, or end-of-buffer.
        let lnk_start = prefix + 16;
        let hard_end = starts.get(idx + 1).copied().unwrap_or(data.len());
        let end = footer_before(data, lnk_start, hard_end).unwrap_or(hard_end);
        if let Some(slice) = data.get(lnk_start..end) {
            if let Some(link) = parse_shell_link(slice) {
                entries.push(JumpListEntry {
                    destlist: None,
                    link,
                });
            }
        }
    }

    Some(JumpList {
        kind: JumpListKind::Custom,
        app_id: filename.and_then(appid_from_filename),
        entries,
    })
}

/// Find the `0xBABFFBAB` footer signature within `start..hard_end`, returning
/// the byte offset where it begins (so the shell-link slice ends there).
fn footer_before(data: &[u8], start: usize, hard_end: usize) -> Option<usize> {
    let sig = jl::CUSTOM_DESTINATIONS_FOOTER_SIGNATURE.to_le_bytes();
    let region = data.get(start..hard_end)?;
    region
        .windows(4)
        .position(|w| w == sig)
        .map(|p| start + p)
}

/// The `[MS-SHLLINK]` CLSID rendered as its 16 little-endian wire bytes — the
/// byte sequence that prefixes each embedded shell link in a custom
/// destinations file. Derived from [`forensicnomicon::jumplist::LNK_CLSID`].
fn clsid_wire_bytes() -> [u8; 16] {
    // 00021401-0000-0000-C000-000000000046: Data1/2/3 little-endian, Data4 BE.
    let hex: String = jl::LNK_CLSID.chars().filter(|c| *c != '-').collect();
    let mut raw = [0u8; 16];
    for (i, slot) in raw.iter_mut().enumerate() {
        *slot = u8::from_str_radix(hex.get(i * 2..i * 2 + 2).unwrap_or("00"), 16).unwrap_or(0);
    }
    [
        raw[3], raw[2], raw[1], raw[0], // Data1 LE
        raw[5], raw[4], // Data2 LE
        raw[7], raw[6], // Data3 LE
        raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15], // Data4 BE
    ]
}
