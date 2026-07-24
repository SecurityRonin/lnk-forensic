# 7. Distrust declared sizes in Jump Lists; surface the structural failure reason

Date: 2026-07-24
Status: Accepted

## Context

Jump Lists are hostile to a happy-path parser in two ways:

1. **Declared shell-link sizes are unreliable.** A `*.customDestinations-ms` file
   is a flat run of concatenated `[MS-SHLLINK]` links; trusting a per-link length
   field to split them lets one lying or corrupt size desynchronize the whole
   remainder.
2. **`DestList` path strings carry invalid UTF-16.** Observed paths include
   unpaired surrogates, so a strict UTF-16 decode would reject or panic on real,
   benign evidence.

Separately, a silent `None` on a file that fails to parse throws away the one
datum an investigator needs — *why* it is not a valid Jump List (fleet robustness
rules: "Show the unrecognized value", fail loud with the offending bytes).

## Decision

- **Split by structure, not by declared size.** The custom-destinations splitter
  scans for the `[MS-SHLLINK]` `LinkCLSID` prefix and the `0xBABFFBAB` footer
  rather than trusting a length (`core/src/jumplist.rs` header:
  "declared shell-link sizes are treated as unreliable (the custom-destinations
  splitter scans for the CLSID/footer …)"; CHANGELOG 0.2.0).
- **Decode paths lossily.** `DestList` path strings are UTF-16 decoded lossily so
  unpaired surrogates yield a best-effort string, never a rejection or panic
  (`core/src/jumplist.rs` header; `DestListEntry`).
- **Offer a checked parse surface.** Alongside the `Option`-returning
  `parse_automatic_destinations` / `parse_custom_destinations`, add
  `parse_*_checked` returning a `JumplistError` whose variants each carry the
  offending value — `NotCompoundFile { found_magic: [u8; 8] }`,
  `MissingDestListStream`, `BadCustomFormatVersion { found: u32 }`
  (`core/src/jumplist.rs`; RED/GREEN commits `e0c8e75` / `bacb56a`).

## Consequences

- A corrupt or partially-overwritten Jump List still yields the entries that *do*
  parse, and the checked API tells the investigator exactly why a file was
  rejected instead of a bare `None`.
- The CLSID/footer scan is more work than reading a length, and it assumes the
  boundary markers are intact — a deliberately intact-marker-but-lying-size file
  is handled correctly, which the length-trusting approach would not be.
- Lossy decoding means a path with unpaired surrogates is shown with replacement
  characters; the raw bytes remain available upstream for byte-exact needs.
