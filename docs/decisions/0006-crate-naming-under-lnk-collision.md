# 6. Crate naming under the popular `lnk` collision

Date: 2026-07-24
Status: Accepted

## Context

The fleet Crate naming grammar reserves the two-crate pattern `<x>-core` (reader)
+ `<x>-forensic` (analyzer) for a single-format repo, and adds a rule for the
bare-name case: if the bare `<x>` crate name is taken on crates.io by a *popular*
third party, do **not** hijack the import path — keep the `<x>_core` import (the
`ntfs` precedent: Colin Finck's `ntfs` crate means `ntfs-core` imports as
`ntfs_core`, not `ntfs`).

The bare name `lnk` is already taken on crates.io (a general-purpose Shell Link
library). Hijacking `use lnk::…` for this reader would collide with it and
mislead consumers.

The observable choice is grounded in evidence: the crate is published as
`lnk-core` with no `[lib] name` override (default import `lnk_core`), which is
exactly the grammar's "popular incumbent → keep the `_core` import" branch. The
git history does not carry a commit that states this reasoning explicitly, so the
classification of `lnk` as the *incumbent to defer to* is reconstructed from the
naming grammar plus the crate structure, not from a recorded original intent.

## Decision

- The reader is published as **`lnk-core`** with the default library name
  `lnk_core` — `core/Cargo.toml` declares `name = "lnk-core"` and carries **no**
  `[lib] name = "lnk"` override, so consumers write `use lnk_core::…`. The bare
  `lnk` import is left to the incumbent crate.
- The analyzer is **`lnk-forensic`** (`forensic/Cargo.toml`), the headline crate
  the repo is named after.
- Reader = `lnk-core`, analyzer = `lnk-forensic`, always — matching the fleet
  grammar for a single-format repo.

## Consequences

- No import-path collision with the incumbent `lnk` crate; a consumer can even
  depend on both without ambiguity.
- The import path (`lnk_core`) is slightly longer than a hijacked `lnk` would be —
  the accepted cost of the naming grammar's "don't hijack a popular bare name"
  rule.
- Because the crate was named correctly before first publish, no crates.io
  72-hour rename window was needed.
