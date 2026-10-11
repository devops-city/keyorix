# Releasing Keyorix

Releases are automated: pushing a `vX.Y.Z` git tag is the only manual step. The
tag fires three workflows that publish everything a user consumes.

## Cut a release

1. Make sure `main` is green, then assemble the changelog: run
   `scripts/changelog-assemble.sh vX.Y.Z` (optionally a second `YYYY-MM-DD`
   argument; default today). It merges every `changelog.d/*.md` fragment into
   `CHANGELOG.md` under a new `## vX.Y.Z — <date>` heading, keeps any legacy
   `## Unreleased` body under it, and deletes the fragments. Review the result
   and commit it. `scripts/changelog-assemble.sh --check` validates fragments
   without changing anything (CI runs it on every PR). Normal PRs never edit
   `CHANGELOG.md`; they add a fragment (`changelog.d/README.md`).
2. (If the chart changed) bump `version`/`appVersion` in
   `deploy/helm/keyorix/Chart.yaml`.
3. Bump the image pins in `docker-compose.yml` (`keyorix-server` and `keyorix-web`)
   to the new version (no leading `v`: release `v0.3.0` -> image `0.3.0`), in the
   same PR as the `CHANGELOG.md` entry. `go test ./deploy/` (`TestComposeImagePinsMatchLatestRelease`)
   fails if the pins don't match the newest `## vX.Y.Z` heading in `CHANGELOG.md`.
   The images only exist once the tag is pushed, so tag right after that PR merges.
   **The first release after v0.95.3 only:** in the same PR, fold
   `docker-compose.secure.yml` into `docker-compose.yml` and
   `keyorix.docker.secure.yaml` into `keyorix.docker.yaml`, delete both, and set
   the chart's `secureBaseline.enabled` default to `true` (SECURE-DEFAULT-1: the
   secure baseline needs an image newer than v0.95.3). `go test ./deploy/`
   (`TestComposeSecureBaselineFoldedAfterRelease`, `TestHelmSecureBaselineOnByDefaultAfterRelease`)
   fails until that is done.
4. Tag and push:

   ```sh
   git checkout main && git pull
   git tag v0.3.0
   git push origin v0.3.0
   ```

That's it. Watch the runs under the repo's **Actions** tab.

## What the tag publishes

| Workflow | Trigger | Output |
|----------|---------|--------|
| `release.yml` → `build-and-release` | `v*` tag | CLI + server + keyorix-migrate binaries for linux/darwin × amd64/arm64 (`keyorix_<os>_<arch>`, `keyorix-server_<os>_<arch>`, `keyorix-server-airgap_<os>_<arch>` linux-only, `keyorix-migrate_<os>_<arch>`), one CycloneDX SBOM per binary (`<binary_asset_name>_sbom.cdx.json`, 14 total) plus one shared, production-scope frontend SBOM (`keyorix-server_frontend_sbom.cdx.json`, linked from all six server/server-airgap SBOMs — ADR-073), `checksums.txt` covering all 29 files, and `checksums.txt.sig`/`.pem` (cosign keyless signature). All attached to the GitHub Release. `keyorix-server-airgap` replaces the old `keyorix-server-lean` (ADR-109 step 6 — see CHANGELOG.md). |
| `release.yml` → `publish-chart` | `v*` tag | Helm chart pushed to `oci://ghcr.io/keyorixhq/charts` (chart + app version = the tag without the `v`). |
| `docker-publish.yml` | `v*` tag (and `main`) | `ghcr.io/keyorixhq/keyorix-server` image tagged with the semver version. |
| `docker-publish.yml` | `v*` tag (and `main`) | `ghcr.io/keyorixhq/keyorix-server` AIR-GAPPED variant, tagged `<version>-airgap` (ADR-109 step 6) — same multi-arch platforms and Trivy gates as the full image. |
| `docker-publish.yml` | `v*` tag (and `main`) | `ghcr.io/keyorixhq/keyorix-web` image tagged with the same semver version — same workflow run, same tag (ADR-070). |

The asset names produced by `make release` are exactly what `install.sh`
downloads — keep `make release`, `install.sh`, and any image references in sync.

## SLSA build provenance (ADR-109 step 6)

`release.yml` and `docker-publish.yml` each run `actions/attest-build-provenance`
(SHA-pinned) for every binary and image they publish — a separate mechanism from the
cosign keyless signature above, verifiable with `gh attestation verify` and documented
for customers in [SECURITY.md](SECURITY.md). After cutting a release, confirm the
attestations actually landed:

```sh
gh attestation verify dist/keyorix-server_linux_amd64 --owner keyorixhq
gh attestation verify oci://ghcr.io/keyorixhq/keyorix-server:<tag> --owner keyorixhq
```

A missing or failed attestation on a freshly-cut release means the `attestations: write`
permission was dropped from the job, or `actions/attest-build-provenance`'s step was
skipped/failed silently — check the workflow run's own logs for that step before
assuming the release itself is otherwise fine.

## After the release — verify it's consumable

```sh
# CLI installer (latest)
curl -fsSL https://raw.githubusercontent.com/keyorixhq/keyorix/main/install.sh | sh
keyorix --version          # → the new version

# Helm chart from the OCI registry
helm show chart oci://ghcr.io/keyorixhq/charts/keyorix --version 0.3.0
```

## Versioning

Semantic Versioning. New user-facing features → minor; fixes → patch; breaking
changes → major. The CLI/server embed the version via `-ldflags` at build time
(`make release VERSION=<tag>`), so `keyorix --version` reports the tag.
