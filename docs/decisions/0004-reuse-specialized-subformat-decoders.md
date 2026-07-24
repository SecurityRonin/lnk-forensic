# 4. Reuse specialized sub-format decoders (cfb, shellitem) rather than reinvent

Date: 2026-07-24
Status: Accepted

## Context

A `.lnk` and its Jump Lists embed two self-contained sub-formats that each have a
mature decoder already:

1. **OLE/CFB compound files.** `*.automaticDestinations-ms` Jump Lists are stored
   as a Microsoft Compound File Binary container (`D0 CF 11 E0 …`) holding the
   `DestList` MRU stream plus one hex-named embedded `.lnk` sub-stream per entry.
   Parsing CFB from scratch — FAT/mini-FAT, directory entries, sector chains — is
   a large, error-prone surface with nothing forensic about it.
2. **Shell items (PIDL / ITEMIDLIST).** The `LinkTargetIDList` (`[MS-SHLLINK]`
   §2.2) is an `ITEMIDLIST`; decoding it into a real target path is exactly the
   job of a shell-item parser, shared with shellbag work across the fleet.

The fleet law is "prefer our own crates", but with an explicit exception: reuse a
mature, better-scoped library rather than reinvent an inferior wheel (the `lznt1`
/ `lzfse` precedent). `unsafe` must never enter through such a dependency.

## Decision

- **`cfb` (third-party, MIT) for the OLE container** — `core/Cargo.toml`:
  `cfb = "0.14"`, with an inline note "the mature MIT OLE Compound-File reader …
  DRY, do not reinvent." This is a documented "prefer-our-own" exception, on the
  same footing as `lznt1` for NTFS (README "Third-party dependency note"). It is
  declared in `supply-chain/config.toml` (`[[exemptions.cfb]]`).
- **`shellitem` (fleet-own, 0.2) for the PIDL** — `core/Cargo.toml`:
  `shellitem = "0.2"`, "the reusable PIDL/ITEMIDLIST decoder primitive … decode
  it here rather than reinventing shell-item parsing." `LinkTargetIdList` now
  carries `items: Vec<shellitem::ShellItem>` and a reconstructed `path`
  (commit `78313bc`, CHANGELOG 0.3.0), resolving the real target even when
  `LinkInfo` is absent.

Both crates decode *sub-formats*; our own code stays `#![forbid(unsafe_code)]`.

## Consequences

- `lnk-core` reads real Jump Lists and reconstructs target paths without owning a
  CFB or shell-item parser — less code to fuzz and maintain, correctness inherited
  from the upstream decoders.
- The `cfb` exception is bounded and auditable: one third-party decoder for one
  well-defined container, license-checked in `deny.toml` and vet-exempted.
- The repo takes on `cfb`'s and `shellitem`'s release cadence; a CFB or shell-item
  fix arrives via a version bump rather than a local patch.
