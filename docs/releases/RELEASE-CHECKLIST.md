# Release checklist (cut vX.Y.Z)

Written from RELEASE-DRYRUN-1 (2026-10-17): every command below was run for real
against `main` with nothing published, tagged or pushed, except the steps marked
**tag-time** and **after the tag**, which only the real release can exercise.
[RELEASING.md](../../RELEASING.md) says what the tag publishes; this page is the
order of work and the exact commands. Replace `X.Y.Z` / `PREV` (the last tag, for
example `v0.96.1`) throughout.

## 0. Before you start

- [ ] Every PR the release notes call *pending* is merged or dropped, and the notes
      are re-checked against `git log PREV..origin/main --first-parent` (a PR merged
      after the draft was written is not in it).
- [ ] `main` is green: `gh run list --branch main --limit 5`.
- [ ] If the release is meant to ship linux/arm (armv7): the Makefile `release`
      target and `_sbom-generate` have the targets (they did not at v0.97.0 prep;
      `make release` builds linux/darwin × amd64/arm64 only), `install.sh` maps
      `armv7l` to the asset name, and the 29-file count in SECURITY.md / RELEASING.md
      is updated.

## 1. The release PR (one PR, based on main)

```sh
git fetch origin --tags
git switch -c release/vX.Y.Z origin/main
scripts/preflight.sh
```

1. **Drop fragments a patch release already published.** A side-branch release
   (v0.96.1) has its CHANGELOG section only on its own tag, so the same fragments
   still sit on main and would print twice.

   ```sh
   scripts/changelog-dedupe.sh PREV            # lists "duplicate" / "partial"
   scripts/changelog-dedupe.sh --delete PREV   # git rm the duplicates; partial ones: edit by hand
   ```
2. **Assemble the changelog** and review `git diff CHANGELOG.md`:

   ```sh
   scripts/changelog-assemble.sh --check
   scripts/changelog-assemble.sh vX.Y.Z YYYY-MM-DD
   ```
3. **Bump the pins** to `X.Y.Z` (no `v`): the two `ghcr.io/keyorixhq/keyorix-{server,web}`
   lines in `docker-compose.yml`, and `version` / `appVersion` in
   `deploy/helm/keyorix/Chart.yaml` (the other two charts are versioned by the tag at
   publish time). Check that the guard goes green:

   ```sh
   go test ./deploy/ -count=1        # TestComposeImagePinsMatchLatestRelease is red until the pins match
   ```
   Also move `V=` in `QUICK_START.md` if the release changes what it describes.
4. **Refresh `server/default.pgo`** (`docs/pgo.md`, `scripts/pgo/refresh.sh`). Needs a
   load run: not done in the dry run (pending the bench host).
5. Move the finished draft to `docs/releases/vX.Y.Z.md` (or whatever the notes become)
   and check the links: `python3 scripts/check-doc-links.py`.
6. Open the PR, wait for CI, merge. The images only exist once the tag is pushed, so
   tag right after the merge.

## 2. Rehearse the build on your machine (nothing is published)

Needs Go 1.27.2, Node 22, pnpm 11, `cyclonedx-gomod` v1.10.0 and the lockfile-pinned
cdxgen (`npm ci --ignore-scripts`). About 15 minutes cold.

```sh
git switch --detach origin/main            # the commit you are about to tag
npm ci --ignore-scripts
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.10.0
PATH="$PWD/node_modules/.bin:$HOME/go/bin:$PATH" make release VERSION=vX.Y.Z
```

Expect 14 binaries, 14 SBOMs, `keyorix-server_frontend_sbom.cdx.json` and `checksums.txt`
(29 files in `dist/`, 29 lines in `checksums.txt`).

```sh
cd dist && sha256sum --check --quiet checksums.txt && cd ..   # macOS: shasum -a 256 --check --quiet
./dist/keyorix_$(go env GOOS)_$(go env GOARCH) --version       # keyorix version vX.Y.Z
./dist/keyorix-server_$(go env GOOS)_$(go env GOARCH) --version  # version, commit, build date (commit date), go
```

The server takes `--version` (there is no `version` subcommand). The CLI prints the
version only: commit and date are not stamped into it (by design, see the Makefile
`CLI_VERSION_LDFLAGS` comment).

**Reproducibility.** Two clones at different paths give bit-identical binaries; compare
with `diff a/dist/checksums.txt b/dist/checksums.txt`. Only `*_sbom.cdx.json` may differ
(random CycloneDX `serialNumber`, and a module hash of the replaced `../` directory for
the CLI and server SBOMs). A differing binary is a real finding.

**Signing rehearsal (no Sigstore, no Rekor).** The real signature is keyless and only
the tag-time job can make it. To rehearse verification with a throwaway key:

```sh
COSIGN_PASSWORD=x cosign generate-key-pair --output-key-prefix scratch-key
COSIGN_PASSWORD=x cosign sign-blob --yes --tlog-upload=false --key scratch-key.key \
  --output-signature checksums.txt.sig dist/checksums.txt
cosign verify-blob --key scratch-key.pub --signature checksums.txt.sig \
  --insecure-ignore-tlog=true dist/checksums.txt
```

`--tlog-upload=false` matters: without it `sign-blob --key` writes to the public Rekor log.

## 3. Tag

```sh
git switch main && git pull
git tag vX.Y.Z
git push origin vX.Y.Z      # fires release.yml, docker-publish.yml
```

(Andrei only: nothing in the dry run pushed a tag.)

## 4. After the tag

Watch the three workflows under Actions (`release`, `docker-publish`, and the chart job
in `release`). Then, from an empty directory with the release assets downloaded:

```sh
sha256sum --check --ignore-missing checksums.txt
cosign verify-blob \
  --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/keyorixhq/keyorix/\.github/workflows/release\.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
gh attestation verify keyorix-server_linux_amd64 --owner keyorixhq
cosign verify \
  --certificate-identity-regexp 'https://github.com/keyorixhq/keyorix/\.github/workflows/docker-publish\.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/keyorixhq/keyorix-server:X.Y.Z
helm show chart oci://ghcr.io/keyorixhq/charts/keyorix --version X.Y.Z
curl -fsSL https://raw.githubusercontent.com/keyorixhq/keyorix/main/install.sh | sh && keyorix --version
```

These are the commands SECURITY.md and RELEASING.md give users. In the dry run the
`cosign verify-blob` line was run unchanged except for two offline flags
(`--certificate-chain`, `--insecure-ignore-tlog`/`--insecure-ignore-sct`) against a
throwaway CA and a certificate carrying the release workflow's identity: it printed
`Verified OK`, failed on a modified `checksums.txt`, and failed on the
`docker-publish.yml` identity.

## 5. What a local rehearsal cannot show (pending e2e VM or the real tag)

- Container images (`keyorix-server`, `-airgap`, `keyorix-web`, `keyorix-operator`,
  k8s-sync): need Docker. CI's `release-dry-run` builds them without pushing.
- Keyless signing, SLSA attestations, the GHCR chart push and `install.sh` against the
  real release: tag-time.
- Helm install on a cluster, multi-replica rollout, the upgrade drill from PREV
  (`scripts/drills/upgrade.sh`): e2e VM.
- linux/arm (armv7) and linux/arm64 *running*: only compile-checked (`scripts/edge/cross-build.sh`).
- `keyorix-operator` has no version stamp and no SBOM, and is not in `make release`
  (it ships only as an image built by `docker-publish.yml`).
