# internal/solewriter invariants

`storage.database.single_writer` (docs/specs/single-writer-cache.md, docs/single-writer.md): the
holder lock, the write fence, the write epoch and the lease. Read this before changing the package.

Format: `INV-SW-NN <rule>. Why: <source>. Guard: <test>` (new entries as slug IDs, `INV-SW-<kebab-slug>`).

Every invariant is a fragment in `INVARIANTS.d/` (one per file).
