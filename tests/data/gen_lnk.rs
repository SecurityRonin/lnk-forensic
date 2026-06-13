use std::io::Write;

const HEADER_SIZE: u32 = 0x4C;
const CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];
const FT_DELTA: i64 = 116_444_736_000_000_000;
const HAS_LINK_INFO: u32 = 1 << 1;
const HAS_NAME: u32 = 1 << 2;
const TRACKER_SIG: u32 = 0xA000_0003;

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
    h.extend_from_slice(&123_456u32.to_le_bytes());
    h.extend_from_slice(&7i32.to_le_bytes());
    h.extend_from_slice(&1u32.to_le_bytes());
    h.extend_from_slice(&0u16.to_le_bytes());
    h.extend_from_slice(&[0u8; 2]);
    h.extend_from_slice(&[0u8; 4]);
    h.extend_from_slice(&[0u8; 4]);
    assert_eq!(h.len(), 0x4C);
    h
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

fn tracker(machine: &str, vol: &str, obj: &str) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&0x60u32.to_le_bytes());
    b.extend_from_slice(&TRACKER_SIG.to_le_bytes());
    b.extend_from_slice(&0x58u32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    let mut m = [0u8; 16];
    for (i, c) in machine.bytes().take(15).enumerate() {
        m[i] = c;
    }
    b.extend_from_slice(&m);
    b.extend_from_slice(&guid_le(vol));
    b.extend_from_slice(&guid_le(obj));
    b.extend_from_slice(&guid_le(vol));
    b.extend_from_slice(&guid_le(obj));
    assert_eq!(b.len(), 0x60);
    b
}

fn removable() -> Vec<u8> {
    let mut d = header(HAS_LINK_INFO | HAS_NAME, 1 << 5);
    let label = "KINGSTON USB";
    let mut lz: Vec<u8> = label.bytes().collect();
    lz.push(0);
    let mut vol = Vec::new();
    let vsize = 0x10 + lz.len();
    vol.extend_from_slice(&(vsize as u32).to_le_bytes());
    vol.extend_from_slice(&2u32.to_le_bytes());
    vol.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    vol.extend_from_slice(&0x10u32.to_le_bytes());
    vol.extend_from_slice(&lz);
    let base = "E:\\payload.exe";
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
    let name = "Removable shortcut";
    d.extend_from_slice(&(name.len() as u16).to_le_bytes());
    d.extend_from_slice(name.as_bytes());
    d.extend_from_slice(&tracker(
        "ANALYST-PC",
        "11111111-2222-3333-4444-555555555555",
        "66666666-7777-8888-9999-aaaaaaaaaaaa",
    ));
    d.extend_from_slice(&[0, 0, 0, 0]);
    d
}

fn network() -> Vec<u8> {
    let mut d = header(HAS_LINK_INFO, 0);
    let net = "\\\\SERVER\\share";
    let mut nz: Vec<u8> = net.bytes().collect();
    nz.push(0);
    let dev = "Z:";
    let mut dz: Vec<u8> = dev.bytes().collect();
    dz.push(0);
    let ch = 0x14u32;
    let noff = ch;
    let doff = ch + nz.len() as u32;
    let csize = doff as usize + dz.len();
    let mut cnrl = Vec::new();
    cnrl.extend_from_slice(&(csize as u32).to_le_bytes());
    cnrl.extend_from_slice(&0x1u32.to_le_bytes());
    cnrl.extend_from_slice(&noff.to_le_bytes());
    cnrl.extend_from_slice(&doff.to_le_bytes());
    cnrl.extend_from_slice(&0u32.to_le_bytes());
    cnrl.extend_from_slice(&nz);
    cnrl.extend_from_slice(&dz);
    let hs = 0x1Cu32;
    let coff = hs;
    let soff = coff + cnrl.len() as u32;
    let total = soff as usize + 1;
    let mut li = Vec::new();
    li.extend_from_slice(&(total as u32).to_le_bytes());
    li.extend_from_slice(&hs.to_le_bytes());
    li.extend_from_slice(&0x2u32.to_le_bytes());
    li.extend_from_slice(&0u32.to_le_bytes());
    li.extend_from_slice(&0u32.to_le_bytes());
    li.extend_from_slice(&coff.to_le_bytes());
    li.extend_from_slice(&soff.to_le_bytes());
    li.extend_from_slice(&cnrl);
    li.push(0);
    d.extend_from_slice(&li);
    d.extend_from_slice(&[0, 0, 0, 0]);
    d
}

fn main() {
    let dir = "/Users/4n6h4x0r/src/lnk-forensic/tests/data";
    let r = removable();
    let n = network();
    std::fs::File::create(format!("{dir}/removable_media.lnk"))
        .unwrap()
        .write_all(&r)
        .unwrap();
    std::fs::File::create(format!("{dir}/network_share.lnk"))
        .unwrap()
        .write_all(&n)
        .unwrap();
    println!("removable_media.lnk: {} bytes", r.len());
    println!("network_share.lnk: {} bytes", n.len());
}
