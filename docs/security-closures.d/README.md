# docs/security-closures.d/ — one security closure per file

Each file is named `<claim_id>.tsv` and contains exactly one tab-separated row:
`claim_id  package  proving_test  verification  landed_commit  issue  note` —
the same row shape `docs/security-closures.tsv` has always used. See
the generated ledger's header (`HEADER.txt` here) for what each column means
and what `verification` values are valid.

`docs/security-closures.tsv` is a **generated, gitignored build artifact**, not
a committed file: this directory is the only source of truth.

## Adding a closure

Add a new `<claim_id>.tsv` file here and commit just that file. Nothing needs
regenerating: `scripts/check-closures.sh` builds the flat ledger from these
fragments itself on every run (and `scripts/check-adr-conformance.sh`, which
reuses it, is unaffected). To validate the fragments alone:

```
scripts/gen-security-closures-tsv.sh --check
```

To browse the flat ledger locally, `scripts/gen-security-closures-tsv.sh`
writes the (untracked) `docs/security-closures.tsv`.

**This is the whole point of the split**: a new closure is a new file, so two
PRs closing two different findings never touch the same line and never
conflict. Before this, every closure PR appended a line to one shared
`docs/security-closures.tsv`, and any two such PRs open at once were a
guaranteed merge conflict (`COMMON-RULES.md`'s "Shared-file rule") — this
directory replaces that with one-file-per-claim, mirroring
`scripts/fuzzing/targets.d/`'s fix for the identical problem with fuzz
targets.

`EXCLUDED.md` in this directory lists claims deliberately NOT represented as a
file here (a documented exception whose test doesn't yet exist) — the
generator does not read it; it is a human note only.
