### Changed
- **The last `alias.*` read is gone.** The GORM fallback of the machine-credential lookup now lists the credential columns explicitly, and `TestNoStarSelectInProductionSQL` no longer has an allowlist entry for it, so the guard covers every production query.
