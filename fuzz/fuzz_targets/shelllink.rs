#![no_main]
//! Shell Link header/body parse over arbitrary bytes — must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = lnk_core::parse_shell_link(data);
});
