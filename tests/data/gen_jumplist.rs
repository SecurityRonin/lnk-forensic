//! Generator for the spec-exact Jump List fixtures.
//!
//! Run from the repo root with the workspace's `cfb` available:
//!
//! ```sh
//! cargo run --example gen_jumplist -p lnk-core
//! ```
//!
//! (a copy is kept here under tests/data/ for provenance; the canonical, runnable
//! copy lives at core/examples/gen_jumplist.rs).
//!
//! Writes `pinned_removable.automaticDestinations-ms` (a real CFB compound file:
//! a DestList v2 stream with one pinned entry whose hostname is OTHER-PC + one
//! hex-named LNK sub-stream carrying a removable VolumeID with serial 0xDEADBEEF)
//! and `tasks.customDestinations-ms` (a flat user-tasks category with one
//! embedded LNK, terminated by the 0xBABFFBAB footer).
//!
//! No real user's Jump List is committed; every byte is hand-authored per the
//! libyal dtformats Jump-lists spec.

use std::io::Write;

const HEADER_SIZE: u32 = 0x4C;
const CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];
const FT_DELTA: i64 = 116_444_736_000_000_000;
const HAS_LINK_INFO: u32 = 1 << 1;
const FOOTER: u32 = 0xBABF_FBAB;

fn ft(unix: i64) -> [u8; 8] {
    (((unix * 10_000_000) + FT_DELTA) as u64).to_le_bytes()
}

fn header(flags: u32, attrs: u32) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(&HEADER_SIZE.to_le_bytes());
    h.extend_from_slice(&CLSID);
    h.extend_from_slice(&flags.to_le_bytes());
    h.extend_from_slice(&attrs.to_le_bytes());
    h.extend_from_slice(&ft(1_600_000_000));
    h.extend_from_slice(&ft(1_600_000_100));
    h.extend_from_slice(&ft(1_600_000_200));
    h.extend_from_slice(&0u32.to_le_bytes());
    h.extend_from_slice(&0i32.to_le_bytes());
    h.extend_from_slice(&1u32.to_le_bytes());
    h.extend_from_slice(&0u16.to_le_bytes());
    h.extend_from_slice(&[0u8; 2]);
    h.extend_from_slice(&[0u8; 4]);
    h.extend_from_slice(&[0u8; 4]);
    assert_eq!(h.len(), 0x4C);
    h
}

/// A removable-media LNK: LinkInfo + VolumeID(DRIVE_REMOVABLE, serial) + path.
fn removable_lnk(serial: u32, base: &str) -> Vec<u8> {
    let mut d = header(HAS_LINK_INFO, 1 << 5);
    let label = "KINGSTON USB";
    let mut lz: Vec<u8> = label.bytes().collect();
    lz.push(0);
    let mut vol = Vec::new();
    let vsize = 0x10 + lz.len();
    vol.extend_from_slice(&(vsize as u32).to_le_bytes());
    vol.extend_from_slice(&2u32.to_le_bytes()); // DRIVE_REMOVABLE
    vol.extend_from_slice(&serial.to_le_bytes());
    vol.extend_from_slice(&0x10u32.to_le_bytes());
    vol.extend_from_slice(&lz);
    let mut bz: Vec<u8> = base.bytes().collect();
    bz.push(0);
    let hs = 0x1Cu32;
    let voff = hs;
    let lbpoff = hs + vol.len() as u32;
    let total = lbpoff as usize + bz.len();
    let mut li = Vec::new();
    li.extend_from_slice(&(total as u32).to_le_bytes());
    li.extend_from_slice(&hs.to_le_bytes());
    li.extend_from_slice(&0x1u32.to_le_bytes());
    li.extend_from_slice(&voff.to_le_bytes());
    li.extend_from_slice(&lbpoff.to_le_bytes());
    li.extend_from_slice(&0u32.to_le_bytes());
    li.extend_from_slice(&0u32.to_le_bytes());
    li.extend_from_slice(&vol);
    li.extend_from_slice(&bz);
    d.extend_from_slice(&li);
    d.extend_from_slice(&[0, 0, 0, 0]); // ExtraData terminal
    d
}

fn guid_le(s: &str) -> Vec<u8> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    let raw: Vec<u8> = (0..16)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
        .collect();
    let mut o = Vec::new();
    o.extend_from_slice(&[raw[3], raw[2], raw[1], raw[0]]);
    o.extend_from_slice(&[raw[5], raw[4]]);
    o.extend_from_slice(&[raw[7], raw[6]]);
    o.extend_from_slice(&raw[8..16]);
    o
}

/// A DestList v2 (Windows 10) entry: pinned, hostname OTHER-PC, access count 7.
fn destlist_entry_v2(entry_number: u32, hostname: &str, pinned: bool, access: u32, path: &str) -> Vec<u8> {
    let mut e = vec![0u8; 8];
    e.extend_from_slice(&guid_le("11111111-2222-3333-4444-555555555555"));
    e.extend_from_slice(&guid_le("66666666-7777-8888-9999-aaaaaaaaaaaa"));
    e.extend_from_slice(&guid_le("11111111-2222-3333-4444-555555555555"));
    e.extend_from_slice(&guid_le("66666666-7777-8888-9999-aaaaaaaaaaaa"));
    let mut host = [0u8; 16];
    for (i, c) in hostname.bytes().take(15).enumerate() {
        host[i] = c;
    }
    e.extend_from_slice(&host);
    e.extend_from_slice(&entry_number.to_le_bytes());
    e.extend_from_slice(&0u32.to_le_bytes());
    e.extend_from_slice(&0u32.to_le_bytes());
    e.extend_from_slice(&ft(1_700_000_000));
    let pin: i32 = if pinned { 0 } else { -1 };
    e.extend_from_slice(&pin.to_le_bytes());
    e.extend_from_slice(&1u32.to_le_bytes()); // status
    e.extend_from_slice(&access.to_le_bytes()); // access count
    e.extend_from_slice(&[0u8; 8]); // unknown
    let units: Vec<u16> = path.encode_utf16().collect();
    e.extend_from_slice(&(units.len() as u16).to_le_bytes());
    for u in &units {
        e.extend_from_slice(&u.to_le_bytes());
    }
    e.extend_from_slice(&[0u8; 4]); // alignment
    e
}

fn destlist_stream(entry: &[u8]) -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(&3u32.to_le_bytes()); // format version 3 (Win10)
    s.extend_from_slice(&1u32.to_le_bytes()); // entry count
    s.extend_from_slice(&1u32.to_le_bytes()); // pinned count
    s.extend_from_slice(&0u32.to_le_bytes());
    s.extend_from_slice(&1u32.to_le_bytes()); // last entry number
    s.extend_from_slice(&0u32.to_le_bytes());
    s.extend_from_slice(&1u32.to_le_bytes()); // last revision
    s.extend_from_slice(&0u32.to_le_bytes());
    s.extend_from_slice(entry);
    s
}

fn build_automatic(dir: &str) {
    use std::io::Cursor;
    let lnk = removable_lnk(0xDEAD_BEEF, "E:\\report.docx");
    let entry = destlist_entry_v2(1, "OTHER-PC", true, 7, "E:\\report.docx");
    let destlist = destlist_stream(&entry);

    let mut comp = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
    comp.create_stream("DestList").unwrap().write_all(&destlist).unwrap();
    comp.create_stream("1").unwrap().write_all(&lnk).unwrap();
    comp.flush().unwrap();
    let bytes = comp.into_inner().into_inner();

    let path = format!("{dir}/pinned_removable.automaticDestinations-ms");
    std::fs::File::create(&path).unwrap().write_all(&bytes).unwrap();
    println!("{path}: {} bytes", bytes.len());
}

fn build_custom(dir: &str) {
    let lnk = removable_lnk(0xDEAD_BEEF, "E:\\report.docx");
    let mut data = Vec::new();
    data.extend_from_slice(&2u32.to_le_bytes()); // format version 2
    data.extend_from_slice(&1u32.to_le_bytes()); // category count
    data.extend_from_slice(&0u32.to_le_bytes()); // unknown
    data.extend_from_slice(&2u32.to_le_bytes()); // category type 2 (user tasks)
    data.extend_from_slice(&1u32.to_le_bytes()); // number of entries
    data.extend_from_slice(&CLSID); // shell-object CLSID prefix
    data.extend_from_slice(&lnk);
    data.extend_from_slice(&FOOTER.to_le_bytes()); // footer signature

    let path = format!("{dir}/tasks.customDestinations-ms");
    std::fs::File::create(&path).unwrap().write_all(&data).unwrap();
    println!("{path}: {} bytes", data.len());
}

fn main() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data");
    build_automatic(dir);
    build_custom(dir);
}
