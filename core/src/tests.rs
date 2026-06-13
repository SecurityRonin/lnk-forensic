// Included into `lib.rs` via `mod tests { include!("tests.rs"); }`.
// Spec-exact `.lnk` byte builders per [MS-SHLLINK], used to drive the reader.

use super::*;

/// The canonical LinkCLSID bytes (00021401-0000-0000-C000-000000000046).
const CLSID_BYTES: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

fn filetime_bytes(unix_secs: i64) -> [u8; 8] {
    let ft = ((unix_secs * 10_000_000) + FILETIME_UNIX_DELTA_100NS) as u64;
    ft.to_le_bytes()
}

/// Build a minimal valid ShellLinkHeader (0x4C bytes).
fn header(link_flags: u32, file_attrs: u32) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(&shlink::HEADER_SIZE.to_le_bytes()); // HeaderSize
    h.extend_from_slice(&CLSID_BYTES); // LinkCLSID
    h.extend_from_slice(&link_flags.to_le_bytes()); // LinkFlags
    h.extend_from_slice(&file_attrs.to_le_bytes()); // FileAttributes
    h.extend_from_slice(&filetime_bytes(1_600_000_000)); // CreationTime
    h.extend_from_slice(&filetime_bytes(1_600_000_100)); // AccessTime
    h.extend_from_slice(&filetime_bytes(1_600_000_200)); // WriteTime
    h.extend_from_slice(&123_456u32.to_le_bytes()); // FileSize
    h.extend_from_slice(&7i32.to_le_bytes()); // IconIndex
    h.extend_from_slice(&1u32.to_le_bytes()); // ShowCommand (SW_SHOWNORMAL)
    h.extend_from_slice(&0u16.to_le_bytes()); // HotKey
    h.extend_from_slice(&[0u8; 2]); // Reserved1
    h.extend_from_slice(&[0u8; 4]); // Reserved2
    h.extend_from_slice(&[0u8; 4]); // Reserved3
    assert_eq!(h.len(), 0x4C);
    h
}

/// A LinkInfo carrying a VolumeID (drive_type + serial + label) and a local base
/// path. Self-contained, LinkInfoSize-prefixed.
fn link_info_volume(drive_type: u32, serial: u32, label: &str, base_path: &str) -> Vec<u8> {
    // Build the VolumeID first.
    let mut vol = Vec::new();
    let mut label_z: Vec<u8> = label.bytes().collect();
    label_z.push(0);
    let vol_size = 0x10 + label_z.len();
    vol.extend_from_slice(&(vol_size as u32).to_le_bytes()); // VolumeIDSize
    vol.extend_from_slice(&drive_type.to_le_bytes()); // DriveType
    vol.extend_from_slice(&serial.to_le_bytes()); // DriveSerialNumber
    vol.extend_from_slice(&0x10u32.to_le_bytes()); // VolumeLabelOffset
    vol.extend_from_slice(&label_z); // Data (ANSI label)

    let mut base_z: Vec<u8> = base_path.bytes().collect();
    base_z.push(0);

    // LinkInfo header is 0x1C (no Unicode offsets).
    let header_size = 0x1Cu32;
    let volume_id_offset = header_size; // VolumeID immediately after header
    let local_base_path_offset = header_size + vol.len() as u32;
    let total = local_base_path_offset as usize + base_z.len();

    let mut li = Vec::new();
    li.extend_from_slice(&(total as u32).to_le_bytes()); // LinkInfoSize
    li.extend_from_slice(&header_size.to_le_bytes()); // LinkInfoHeaderSize
    li.extend_from_slice(&0x1u32.to_le_bytes()); // LinkInfoFlags: VolumeIDAndLocalBasePath
    li.extend_from_slice(&volume_id_offset.to_le_bytes()); // VolumeIDOffset
    li.extend_from_slice(&local_base_path_offset.to_le_bytes()); // LocalBasePathOffset
    li.extend_from_slice(&0u32.to_le_bytes()); // CommonNetworkRelativeLinkOffset
    li.extend_from_slice(&0u32.to_le_bytes()); // CommonPathSuffixOffset
    li.extend_from_slice(&vol);
    li.extend_from_slice(&base_z);
    assert_eq!(li.len(), total);
    li
}

/// A LinkInfo carrying a CommonNetworkRelativeLink (network share target).
fn link_info_network(net_name: &str, device_name: &str) -> Vec<u8> {
    let mut net_z: Vec<u8> = net_name.bytes().collect();
    net_z.push(0);
    let mut dev_z: Vec<u8> = device_name.bytes().collect();
    dev_z.push(0);

    // CNRL header 0x14, NetNameOffset right after, then DeviceNameOffset.
    let cnrl_header = 0x14u32;
    let net_name_offset = cnrl_header;
    let device_name_offset = cnrl_header + net_z.len() as u32;
    let cnrl_size = device_name_offset as usize + dev_z.len();

    let mut cnrl = Vec::new();
    cnrl.extend_from_slice(&(cnrl_size as u32).to_le_bytes()); // CommonNetworkRelativeLinkSize
    cnrl.extend_from_slice(&0x1u32.to_le_bytes()); // Flags: ValidDevice
    cnrl.extend_from_slice(&net_name_offset.to_le_bytes()); // NetNameOffset
    cnrl.extend_from_slice(&device_name_offset.to_le_bytes()); // DeviceNameOffset
    cnrl.extend_from_slice(&0u32.to_le_bytes()); // NetworkProviderType
    cnrl.extend_from_slice(&net_z);
    cnrl.extend_from_slice(&dev_z);

    let header_size = 0x1Cu32;
    let cnrl_offset = header_size; // CNRL right after the LinkInfo header
    // CommonPathSuffix is an empty NUL.
    let suffix_offset = cnrl_offset + cnrl.len() as u32;
    let total = suffix_offset as usize + 1;

    let mut li = Vec::new();
    li.extend_from_slice(&(total as u32).to_le_bytes()); // LinkInfoSize
    li.extend_from_slice(&header_size.to_le_bytes()); // LinkInfoHeaderSize
    li.extend_from_slice(&0x2u32.to_le_bytes()); // LinkInfoFlags: CommonNetworkRelativeLinkAndPathSuffix
    li.extend_from_slice(&0u32.to_le_bytes()); // VolumeIDOffset
    li.extend_from_slice(&0u32.to_le_bytes()); // LocalBasePathOffset
    li.extend_from_slice(&cnrl_offset.to_le_bytes()); // CommonNetworkRelativeLinkOffset
    li.extend_from_slice(&suffix_offset.to_le_bytes()); // CommonPathSuffixOffset
    li.extend_from_slice(&cnrl);
    li.push(0); // empty CommonPathSuffix
    assert_eq!(li.len(), total);
    li
}

fn guid_le_bytes(s: &str) -> Vec<u8> {
    // Build the 16 GUID bytes from canonical 8-4-4-4-12 (mixed-endian).
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    let raw: Vec<u8> = (0..16)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
        .collect();
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&[raw[3], raw[2], raw[1], raw[0]]); // Data1 LE
    out.extend_from_slice(&[raw[5], raw[4]]); // Data2 LE
    out.extend_from_slice(&[raw[7], raw[6]]); // Data3 LE
    out.extend_from_slice(&raw[8..16]); // Data4 BE
    out
}

/// A TrackerDataBlock with the given machine id and droid/birth GUIDs.
fn tracker_block(machine: &str, droid_vol: &str, droid_obj: &str) -> Vec<u8> {
    let mut b = Vec::new();
    let block_size = 0x60u32; // 96 bytes
    b.extend_from_slice(&block_size.to_le_bytes()); // BlockSize
    b.extend_from_slice(&shlink::EXTRA_TRACKER_DATA_BLOCK.to_le_bytes()); // Signature
    b.extend_from_slice(&0x58u32.to_le_bytes()); // Length
    b.extend_from_slice(&0u32.to_le_bytes()); // Version
    let mut machine_buf = [0u8; 16];
    for (i, c) in machine.bytes().take(15).enumerate() {
        machine_buf[i] = c;
    }
    b.extend_from_slice(&machine_buf); // MachineID[16]
    b.extend_from_slice(&guid_le_bytes(droid_vol)); // Droid volume
    b.extend_from_slice(&guid_le_bytes(droid_obj)); // Droid object
    b.extend_from_slice(&guid_le_bytes(droid_vol)); // DroidBirth volume
    b.extend_from_slice(&guid_le_bytes(droid_obj)); // DroidBirth object
    assert_eq!(b.len(), 0x60);
    b
}

const TERMINAL: [u8; 4] = [0, 0, 0, 0];

#[test]
fn rejects_wrong_header_size() {
    let mut data = header(0, 0);
    data[0] = 0x99; // corrupt HeaderSize
    assert!(parse_shell_link(&data).is_none());
}

#[test]
fn rejects_wrong_clsid() {
    let mut data = header(0, 0);
    data[4] = 0xFF; // corrupt LinkCLSID
    assert!(parse_shell_link(&data).is_none());
}

#[test]
fn rejects_empty_and_short_input() {
    assert!(parse_shell_link(&[]).is_none());
    assert!(parse_shell_link(&[0u8; 8]).is_none());
}

#[test]
fn parses_bare_header_fields() {
    let data = header(shlink::LINK_FLAG_HAS_NAME, shlink::FILE_ATTRIBUTE_ARCHIVE);
    let link = parse_shell_link(&data).unwrap();
    assert_eq!(link.header.file_size, 123_456);
    assert_eq!(link.header.icon_index, 7);
    assert_eq!(link.header.show_command, 1);
    assert_eq!(link.header.creation_time, 1_600_000_000);
    assert_eq!(link.header.access_time, 1_600_000_100);
    assert_eq!(link.header.write_time, 1_600_000_200);
    assert!(link.header.has_flag(shlink::LINK_FLAG_HAS_NAME));
    assert_eq!(link.header.file_attributes, shlink::FILE_ATTRIBUTE_ARCHIVE);
}

#[test]
fn zero_filetime_maps_to_zero_epoch() {
    let mut data = header(0, 0);
    // Zero the three FILETIMEs (offsets 28, 36, 44).
    for o in [28usize, 36, 44] {
        for i in 0..8 {
            data[o + i] = 0;
        }
    }
    let link = parse_shell_link(&data).unwrap();
    assert_eq!(link.header.creation_time, 0);
    assert_eq!(link.header.access_time, 0);
    assert_eq!(link.header.write_time, 0);
}

#[test]
fn parses_volume_id_with_drive_serial_and_local_base_path() {
    let mut data = header(shlink::LINK_FLAG_HAS_LINK_INFO, 0);
    data.extend_from_slice(&link_info_volume(
        drive_type::REMOVABLE,
        0xDEAD_BEEF,
        "USB STICK",
        "E:\\payload.exe",
    ));
    data.extend_from_slice(&TERMINAL);

    let link = parse_shell_link(&data).unwrap();
    let info = link.link_info.unwrap();
    let vol = info.volume_id.unwrap();
    assert_eq!(vol.drive_type, drive_type::REMOVABLE);
    assert_eq!(vol.drive_serial_number, 0xDEAD_BEEF);
    assert_eq!(vol.volume_label.as_deref(), Some("USB STICK"));
    assert_eq!(info.local_base_path.as_deref(), Some("E:\\payload.exe"));
}

#[test]
fn parses_network_relative_link() {
    let mut data = header(shlink::LINK_FLAG_HAS_LINK_INFO, 0);
    data.extend_from_slice(&link_info_network("\\\\SERVER\\share", "Z:"));
    data.extend_from_slice(&TERMINAL);

    let link = parse_shell_link(&data).unwrap();
    let cnrl = link
        .link_info
        .unwrap()
        .common_network_relative_link
        .unwrap();
    assert_eq!(cnrl.net_name.as_deref(), Some("\\\\SERVER\\share"));
    assert_eq!(cnrl.device_name.as_deref(), Some("Z:"));
}

#[test]
fn parses_string_data_ansi() {
    let flags = shlink::LINK_FLAG_HAS_NAME
        | shlink::LINK_FLAG_HAS_RELATIVE_PATH
        | shlink::LINK_FLAG_HAS_WORKING_DIR
        | shlink::LINK_FLAG_HAS_ARGUMENTS
        | shlink::LINK_FLAG_HAS_ICON_LOCATION;
    let mut data = header(flags, 0);
    for s in ["the name", "..\\rel", "C:\\wd", "-arg val", "icon.dll"] {
        data.extend_from_slice(&(s.len() as u16).to_le_bytes());
        data.extend_from_slice(s.as_bytes());
    }
    data.extend_from_slice(&TERMINAL);

    let link = parse_shell_link(&data).unwrap();
    assert_eq!(link.string_data.name.as_deref(), Some("the name"));
    assert_eq!(link.string_data.relative_path.as_deref(), Some("..\\rel"));
    assert_eq!(link.string_data.working_dir.as_deref(), Some("C:\\wd"));
    assert_eq!(link.string_data.arguments.as_deref(), Some("-arg val"));
    assert_eq!(link.string_data.icon_location.as_deref(), Some("icon.dll"));
}

#[test]
fn parses_string_data_unicode() {
    let flags = shlink::LINK_FLAG_HAS_NAME | shlink::LINK_FLAG_IS_UNICODE;
    let mut data = header(flags, 0);
    let s = "café"; // exercises a multi-byte UTF-16 path
    let units: Vec<u16> = s.encode_utf16().collect();
    data.extend_from_slice(&(units.len() as u16).to_le_bytes());
    for u in units {
        data.extend_from_slice(&u.to_le_bytes());
    }
    data.extend_from_slice(&TERMINAL);

    let link = parse_shell_link(&data).unwrap();
    assert_eq!(link.string_data.name.as_deref(), Some("café"));
}

#[test]
fn parses_link_target_idlist_raw() {
    let mut data = header(shlink::LINK_FLAG_HAS_LINK_TARGET_ID_LIST, 0);
    let pidl = [0xAAu8, 0xBB, 0xCC, 0xDD];
    data.extend_from_slice(&(pidl.len() as u16).to_le_bytes());
    data.extend_from_slice(&pidl);
    data.extend_from_slice(&TERMINAL);

    let link = parse_shell_link(&data).unwrap();
    assert_eq!(link.link_target_idlist.unwrap().raw, pidl.to_vec());
}

#[test]
fn parses_tracker_data_block() {
    let mut data = header(0, 0);
    data.extend_from_slice(&tracker_block(
        "ANALYST-PC",
        "11111111-2222-3333-4444-555555555555",
        "66666666-7777-8888-9999-aaaaaaaaaaaa",
    ));
    data.extend_from_slice(&TERMINAL);

    let link = parse_shell_link(&data).unwrap();
    let t = link.tracker.unwrap();
    assert_eq!(t.machine_id, "ANALYST-PC");
    assert_eq!(t.droid.volume, "11111111-2222-3333-4444-555555555555");
    assert_eq!(t.droid.object, "66666666-7777-8888-9999-AAAAAAAAAAAA");
    assert_eq!(t.birth_droid.volume, "11111111-2222-3333-4444-555555555555");
}

#[test]
fn skips_non_tracker_extra_block_then_finds_tracker() {
    let mut data = header(0, 0);
    // A ConsoleDataBlock-sized filler block (signature 0xA0000002) we must skip.
    let mut filler = Vec::new();
    filler.extend_from_slice(&0x0Cu32.to_le_bytes()); // BlockSize 12
    filler.extend_from_slice(&shlink::EXTRA_CONSOLE_DATA_BLOCK.to_le_bytes());
    filler.extend_from_slice(&[0u8; 4]);
    data.extend_from_slice(&filler);
    data.extend_from_slice(&tracker_block(
        "HOST2",
        "11111111-2222-3333-4444-555555555555",
        "66666666-7777-8888-9999-aaaaaaaaaaaa",
    ));
    data.extend_from_slice(&TERMINAL);

    let link = parse_shell_link(&data).unwrap();
    assert_eq!(link.tracker.unwrap().machine_id, "HOST2");
}

#[test]
fn truncated_link_info_does_not_panic() {
    let mut data = header(shlink::LINK_FLAG_HAS_LINK_INFO, 0);
    // Claim a LinkInfo but provide only a tiny, truncated body.
    data.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let _ = parse_shell_link(&data); // must not panic
}

#[test]
fn full_link_round_trips_all_sections() {
    let flags = shlink::LINK_FLAG_HAS_LINK_INFO | shlink::LINK_FLAG_HAS_NAME;
    let mut data = header(flags, shlink::FILE_ATTRIBUTE_ARCHIVE);
    data.extend_from_slice(&link_info_volume(
        drive_type::REMOVABLE,
        0x1234_5678,
        "KINGSTON",
        "F:\\tools\\nc.exe",
    ));
    let name = "Shortcut";
    data.extend_from_slice(&(name.len() as u16).to_le_bytes());
    data.extend_from_slice(name.as_bytes());
    data.extend_from_slice(&tracker_block(
        "DESKTOP-7",
        "11111111-2222-3333-4444-555555555555",
        "66666666-7777-8888-9999-aaaaaaaaaaaa",
    ));
    data.extend_from_slice(&TERMINAL);

    let link = parse_shell_link(&data).unwrap();
    assert_eq!(
        link.link_info.unwrap().volume_id.unwrap().drive_serial_number,
        0x1234_5678
    );
    assert_eq!(link.string_data.name.as_deref(), Some("Shortcut"));
    assert_eq!(link.tracker.unwrap().machine_id, "DESKTOP-7");
}

fn utf16le_z(s: &str) -> Vec<u8> {
    let mut v = Vec::new();
    for u in s.encode_utf16() {
        v.extend_from_slice(&u.to_le_bytes());
    }
    v.extend_from_slice(&[0, 0]);
    v
}

/// A LinkInfo with a 0x24 header carrying a *Unicode* LocalBasePathUnicode.
fn link_info_unicode_path(base_path: &str) -> Vec<u8> {
    let pz = utf16le_z(base_path);
    let header_size = 0x24u32; // includes the optional Unicode offsets
    let lbp_unicode_offset = header_size; // path right after the 0x24 header
    let total = lbp_unicode_offset as usize + pz.len();

    let mut li = Vec::new();
    li.extend_from_slice(&(total as u32).to_le_bytes()); // LinkInfoSize
    li.extend_from_slice(&header_size.to_le_bytes()); // LinkInfoHeaderSize (0x24)
    li.extend_from_slice(&0x1u32.to_le_bytes()); // VolumeIDAndLocalBasePath
    li.extend_from_slice(&0u32.to_le_bytes()); // VolumeIDOffset (none)
    li.extend_from_slice(&0u32.to_le_bytes()); // LocalBasePathOffset (ANSI, none)
    li.extend_from_slice(&0u32.to_le_bytes()); // CommonNetworkRelativeLinkOffset
    li.extend_from_slice(&0u32.to_le_bytes()); // CommonPathSuffixOffset
    li.extend_from_slice(&lbp_unicode_offset.to_le_bytes()); // LocalBasePathOffsetUnicode (+0x1C)
    li.extend_from_slice(&0u32.to_le_bytes()); // CommonPathSuffixOffsetUnicode (+0x20)
    li.extend_from_slice(&pz);
    assert_eq!(li.len(), total);
    li
}

#[test]
fn parses_unicode_local_base_path() {
    let mut data = header(shlink::LINK_FLAG_HAS_LINK_INFO, 0);
    data.extend_from_slice(&link_info_unicode_path("E:\\naïve\\café.exe"));
    data.extend_from_slice(&TERMINAL);
    let link = parse_shell_link(&data).unwrap();
    assert_eq!(
        link.link_info.unwrap().local_base_path.as_deref(),
        Some("E:\\naïve\\café.exe")
    );
}

/// A VolumeID whose label is Unicode (VolumeLabelOffset == 0x14).
fn volume_id_unicode_label(label: &str) -> Vec<u8> {
    let lz = utf16le_z(label);
    let uni_off = 0x14u32; // Unicode label data begins at VolumeID+0x14
    let size = uni_off as usize + lz.len();
    let mut vol = Vec::new();
    vol.extend_from_slice(&(size as u32).to_le_bytes()); // VolumeIDSize
    vol.extend_from_slice(&drive_type::FIXED.to_le_bytes()); // DriveType
    vol.extend_from_slice(&0xCAFE_F00Du32.to_le_bytes()); // DriveSerialNumber
    vol.extend_from_slice(&0x14u32.to_le_bytes()); // VolumeLabelOffset = 0x14 → Unicode
    vol.extend_from_slice(&uni_off.to_le_bytes()); // VolumeLabelOffsetUnicode
    vol.extend_from_slice(&lz);
    vol
}

#[test]
fn parses_unicode_volume_label() {
    let vol = volume_id_unicode_label("DISQUE É");
    let header_size = 0x1Cu32;
    let voff = header_size;
    let total = voff as usize + vol.len();
    let mut li = Vec::new();
    li.extend_from_slice(&(total as u32).to_le_bytes());
    li.extend_from_slice(&header_size.to_le_bytes());
    li.extend_from_slice(&0x1u32.to_le_bytes()); // VolumeIDAndLocalBasePath
    li.extend_from_slice(&voff.to_le_bytes()); // VolumeIDOffset
    li.extend_from_slice(&0u32.to_le_bytes()); // LocalBasePathOffset (none)
    li.extend_from_slice(&0u32.to_le_bytes()); // CNRLOffset
    li.extend_from_slice(&0u32.to_le_bytes()); // CommonPathSuffixOffset
    li.extend_from_slice(&vol);

    let mut data = header(shlink::LINK_FLAG_HAS_LINK_INFO, 0);
    data.extend_from_slice(&li);
    data.extend_from_slice(&TERMINAL);
    let link = parse_shell_link(&data).unwrap();
    let v = link.link_info.unwrap().volume_id.unwrap();
    assert_eq!(v.drive_serial_number, 0xCAFE_F00D);
    assert_eq!(v.volume_label.as_deref(), Some("DISQUE É"));
    // Local base path is absent (both ANSI and Unicode offsets are zero).
}

#[test]
fn link_info_too_small_yields_no_link_info() {
    // LinkInfoSize < 0x1C → parse_link_info returns None (header keeps parsing).
    let mut data = header(shlink::LINK_FLAG_HAS_LINK_INFO, 0);
    let mut li = Vec::new();
    li.extend_from_slice(&0x10u32.to_le_bytes()); // declared size 0x10 (< 0x1C)
    li.extend_from_slice(&[0u8; 0x0C]);
    data.extend_from_slice(&li);
    data.extend_from_slice(&TERMINAL);
    let link = parse_shell_link(&data).unwrap();
    assert!(link.link_info.is_none());
}

#[test]
fn undersize_volume_id_yields_no_volume() {
    // VolumeIDSize < 0x10 → parse_volume_id returns None.
    let header_size = 0x1Cu32;
    let voff = header_size;
    let mut vol = Vec::new();
    vol.extend_from_slice(&0x08u32.to_le_bytes()); // size 8 (< 0x10)
    vol.extend_from_slice(&[0u8; 4]);
    let total = voff as usize + vol.len();
    let mut li = Vec::new();
    li.extend_from_slice(&(total as u32).to_le_bytes());
    li.extend_from_slice(&header_size.to_le_bytes());
    li.extend_from_slice(&0x1u32.to_le_bytes());
    li.extend_from_slice(&voff.to_le_bytes());
    li.extend_from_slice(&0u32.to_le_bytes()); // LocalBasePathOffset 0 → None branch
    li.extend_from_slice(&0u32.to_le_bytes());
    li.extend_from_slice(&0u32.to_le_bytes());
    li.extend_from_slice(&vol);

    let mut data = header(shlink::LINK_FLAG_HAS_LINK_INFO, 0);
    data.extend_from_slice(&li);
    data.extend_from_slice(&TERMINAL);
    let link = parse_shell_link(&data).unwrap();
    let info = link.link_info.unwrap();
    assert!(info.volume_id.is_none());
    assert!(info.local_base_path.is_none());
}

#[test]
fn undersize_cnrl_yields_no_network_link() {
    // CommonNetworkRelativeLinkSize < 0x14 → parse_cnrl returns None.
    let header_size = 0x1Cu32;
    let coff = header_size;
    let mut cnrl = Vec::new();
    cnrl.extend_from_slice(&0x08u32.to_le_bytes()); // size 8 (< 0x14)
    cnrl.extend_from_slice(&[0u8; 4]);
    let total = coff as usize + cnrl.len();
    let mut li = Vec::new();
    li.extend_from_slice(&(total as u32).to_le_bytes());
    li.extend_from_slice(&header_size.to_le_bytes());
    li.extend_from_slice(&0x2u32.to_le_bytes()); // CNRLAndPathSuffix
    li.extend_from_slice(&0u32.to_le_bytes());
    li.extend_from_slice(&0u32.to_le_bytes());
    li.extend_from_slice(&coff.to_le_bytes());
    li.extend_from_slice(&0u32.to_le_bytes());
    li.extend_from_slice(&cnrl);

    let mut data = header(shlink::LINK_FLAG_HAS_LINK_INFO, 0);
    data.extend_from_slice(&li);
    data.extend_from_slice(&TERMINAL);
    let link = parse_shell_link(&data).unwrap();
    assert!(link
        .link_info
        .unwrap()
        .common_network_relative_link
        .is_none());
}

#[test]
fn cnrl_without_valid_device_omits_device_name() {
    // ValidDevice flag clear → device_name is None even with a non-zero offset.
    let header_size = 0x1Cu32;
    let coff = header_size;
    let mut nz: Vec<u8> = "\\\\HOST\\s".bytes().collect();
    nz.push(0);
    let cnrl_header = 0x14u32;
    let net_name_offset = cnrl_header;
    let device_name_offset = cnrl_header + nz.len() as u32; // set, but flag clear
    let cnrl_size = device_name_offset as usize + 2;
    let mut cnrl = Vec::new();
    cnrl.extend_from_slice(&(cnrl_size as u32).to_le_bytes());
    cnrl.extend_from_slice(&0u32.to_le_bytes()); // Flags: ValidDevice CLEAR
    cnrl.extend_from_slice(&net_name_offset.to_le_bytes());
    cnrl.extend_from_slice(&device_name_offset.to_le_bytes());
    cnrl.extend_from_slice(&0u32.to_le_bytes()); // NetworkProviderType
    cnrl.extend_from_slice(&nz);
    cnrl.extend_from_slice(&[0, 0]);

    let total = coff as usize + cnrl.len();
    let mut li = Vec::new();
    li.extend_from_slice(&(total as u32).to_le_bytes());
    li.extend_from_slice(&header_size.to_le_bytes());
    li.extend_from_slice(&0x2u32.to_le_bytes());
    li.extend_from_slice(&0u32.to_le_bytes());
    li.extend_from_slice(&0u32.to_le_bytes());
    li.extend_from_slice(&coff.to_le_bytes());
    li.extend_from_slice(&0u32.to_le_bytes());
    li.extend_from_slice(&cnrl);

    let mut data = header(shlink::LINK_FLAG_HAS_LINK_INFO, 0);
    data.extend_from_slice(&li);
    data.extend_from_slice(&TERMINAL);
    let link = parse_shell_link(&data).unwrap();
    let c = link
        .link_info
        .unwrap()
        .common_network_relative_link
        .unwrap();
    assert_eq!(c.net_name.as_deref(), Some("\\\\HOST\\s"));
    assert!(c.device_name.is_none());
}

#[test]
fn volume_id_with_zero_label_offset_has_no_label() {
    // VolumeLabelOffset == 0 → the label is None (line ~436).
    let header_size = 0x1Cu32;
    let voff = header_size;
    let mut vol = Vec::new();
    vol.extend_from_slice(&0x10u32.to_le_bytes()); // VolumeIDSize 0x10
    vol.extend_from_slice(&drive_type::FIXED.to_le_bytes());
    vol.extend_from_slice(&0xABCD_0123u32.to_le_bytes());
    vol.extend_from_slice(&0u32.to_le_bytes()); // VolumeLabelOffset = 0
    let total = voff as usize + vol.len();
    let mut li = Vec::new();
    li.extend_from_slice(&(total as u32).to_le_bytes());
    li.extend_from_slice(&header_size.to_le_bytes());
    li.extend_from_slice(&0x1u32.to_le_bytes());
    li.extend_from_slice(&voff.to_le_bytes());
    li.extend_from_slice(&0u32.to_le_bytes());
    li.extend_from_slice(&0u32.to_le_bytes());
    li.extend_from_slice(&0u32.to_le_bytes());
    li.extend_from_slice(&vol);

    let mut data = header(shlink::LINK_FLAG_HAS_LINK_INFO, 0);
    data.extend_from_slice(&li);
    data.extend_from_slice(&TERMINAL);
    let v = parse_shell_link(&data)
        .unwrap()
        .link_info
        .unwrap()
        .volume_id
        .unwrap();
    assert_eq!(v.drive_serial_number, 0xABCD_0123);
    assert!(v.volume_label.is_none());
}

#[test]
fn cnrl_with_zero_net_name_offset_has_no_net_name() {
    // NetNameOffset == 0 → net_name is None (line ~462).
    let header_size = 0x1Cu32;
    let coff = header_size;
    let mut cnrl = Vec::new();
    cnrl.extend_from_slice(&0x14u32.to_le_bytes()); // size exactly 0x14
    cnrl.extend_from_slice(&0u32.to_le_bytes()); // Flags: ValidDevice clear
    cnrl.extend_from_slice(&0u32.to_le_bytes()); // NetNameOffset = 0
    cnrl.extend_from_slice(&0u32.to_le_bytes()); // DeviceNameOffset = 0
    cnrl.extend_from_slice(&0u32.to_le_bytes()); // NetworkProviderType
    let total = coff as usize + cnrl.len();
    let mut li = Vec::new();
    li.extend_from_slice(&(total as u32).to_le_bytes());
    li.extend_from_slice(&header_size.to_le_bytes());
    li.extend_from_slice(&0x2u32.to_le_bytes());
    li.extend_from_slice(&0u32.to_le_bytes());
    li.extend_from_slice(&0u32.to_le_bytes());
    li.extend_from_slice(&coff.to_le_bytes());
    li.extend_from_slice(&0u32.to_le_bytes());
    li.extend_from_slice(&cnrl);

    let mut data = header(shlink::LINK_FLAG_HAS_LINK_INFO, 0);
    data.extend_from_slice(&li);
    data.extend_from_slice(&TERMINAL);
    let c = parse_shell_link(&data)
        .unwrap()
        .link_info
        .unwrap()
        .common_network_relative_link
        .unwrap();
    assert!(c.net_name.is_none());
    assert!(c.device_name.is_none());
}

#[test]
fn undersize_extra_block_terminates_walk() {
    // A non-tracker block with size < 0x4, followed by >= 8 trailing bytes, hits
    // the size-terminator break in the ExtraData walk (line ~512).
    let mut data = header(0, 0);
    data.extend_from_slice(&0x02u32.to_le_bytes()); // BlockSize 2 (< 0x4)
    data.extend_from_slice(&[0u8; 8]); // padding so off+8 <= len holds
    let link = parse_shell_link(&data).unwrap();
    assert!(link.tracker.is_none());
}
