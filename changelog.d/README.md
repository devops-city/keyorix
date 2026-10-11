# changelog.d/ — one fragment per PR

**Never edit `CHANGELOG.md` in a normal PR.** Every merged PR used to touch the
same `## Unreleased` section, so each merge conflicted with every other open PR.
Instead, add one file here.

## Naming

`<PR-number>-<short-slug>.md`, e.g. `3012-caddy-nonroot.md`. If the PR number is
not known yet, use `<branch-slug>.md` (e.g. `churn1-changelog-fragments.md`);
rename it when the number exists, or leave it — the name only sets the order of
bullets inside a section.

## Content

One or more `### <Section>` headings, each followed by the bullet(s) exactly as
they would have appeared under `## Unreleased`:

```markdown
### Security
- **Short bold lead.** Explanation, upgrade notes, where it is guarded.
```

Allowed sections (fixed output order): `Security`, `Added`, `Changed`,
`Deprecated`, `Removed`, `Fixed`, `Documentation`, `Testing`, `Internal`.
No `#` / `##` headings, no text before the first `###`, no empty sections.

## Checking

`scripts/changelog-assemble.sh --check` validates every fragment (CI runs it).

## Releasing

When cutting a release the maintainer runs
`scripts/changelog-assemble.sh vX.Y.Z [YYYY-MM-DD]`: it writes a
`## vX.Y.Z — <date>` section into `CHANGELOG.md` (fragments grouped by section),
keeps any legacy `## Unreleased` body under that heading, and deletes the
fragments. See `RELEASING.md`.
