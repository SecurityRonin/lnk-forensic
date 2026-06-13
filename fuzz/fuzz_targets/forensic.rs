#![no_main]
//! Full parse → audit pipeline over arbitrary bytes — must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(link) = lnk_core::parse_shell_link(data) {
        let _ = lnk_forensic::audit_findings(&link, "fuzz");
    }
});
