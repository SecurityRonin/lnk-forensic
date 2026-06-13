#![no_main]
//! Jump List parse → audit over arbitrary bytes — must never panic.
//!
//! Drives the CFB/DestList automatic-destinations parser and the flat
//! custom-destinations parser over hostile input, then audits any result. The
//! CFB layer (`cfb` crate) and every DestList read are attacker-controlled.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(jl) = lnk_core::parse_automatic_destinations(data, Some("ffff.automaticDestinations-ms")) {
        let _ = lnk_forensic::audit_jumplist(&jl, Some("HOST"), "fuzz");
    }
    if let Some(jl) = lnk_core::parse_custom_destinations(data, Some("ffff.customDestinations-ms")) {
        let _ = lnk_forensic::audit_jumplist(&jl, None, "fuzz");
    }
});
