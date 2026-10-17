// Package bundleverify implements Keyorix's air-gapped update bundles (ADR-064, ADR-062
// Phase 1a): building and signing a release bundle (BuildManifest/Sign/WriteBundle --
// maintainer-only, never wired into the thin CLI's command surface, see cli/cmd/bundle.go's
// own doc comment) and verifying/staging one someone else built (Verify/Extract -- the
// customer-facing half). It is a public leaf package (FINISH-SPLIT step 2,
// docs/cli-split-inventory.md §7 PR 10) so the thin CLI module (cli/) can call it directly
// without importing internal/core, internal/storage, internal/config, or any cloud SDK --
// the same reason pkg/trust exists. internal/bundle re-exports this package's API as
// aliases so the old CLI (internal/cli/bundle) keeps working unchanged.
//
// A bundle is a single gzip-compressed tar carrying a versioned set of release artifacts
// (images, charts, CRDs, binaries, migrations) plus a signed manifest that pins every
// component by sha256. An air-gapped operator carries the file across the gap and verifies
// it offline against an embedded, pinned ed25519 public key (pkg/trust) -- so trust follows a
// pinned chain (the key never travels with the bundle), not a self-described signature.
package bundleverify

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/keyorixhq/keyorix/pkg/trust"
)

// Reserved entry names that carry the manifest and its signature, not bundle components.
const (
	manifestName = "manifest.json"
	sigName      = "manifest.sig"
)

// maxManifestBytes caps the in-memory manifest/signature reads so a malformed bundle
// can't exhaust memory before the signature is even checked. A real manifest is a few KiB.
const maxManifestBytes = 4 << 20 // 4 MiB

// maxComponentBytes caps a single component tar entry's declared size, checked immediately
// after its header is parsed and BEFORE streamComponent ever calls io.Copy — so a corrupt or
// malicious entry can't force wasted decompression/read work merely by lying in its header.
// 2 GiB comfortably covers any single legitimate release artifact while still being a hard,
// finite ceiling rather than "whatever the archive claims."
const maxComponentBytes = 2 << 30 // 2 GiB

// maxComponentEntries caps the number of tar entries streamBundleComponents will iterate —
// matched, unlisted, or non-regular — before refusing the archive outright. A real bundle's
// entry count is 2 (manifest+sig) plus the pinned component count from its own size-bounded
// manifest — realistically dozens; 1000 is a generous ceiling above any legitimate release
// while bounding a pathological archive's total iteration cost.
const maxComponentEntries = 1000

var (
	// ErrNoManifest means the archive did not begin with manifest.json + manifest.sig.
	ErrNoManifest = errors.New("bundle: manifest.json/manifest.sig missing or out of order")
	// ErrDigestMismatch means a component's bytes did not match its pinned sha256.
	ErrDigestMismatch = errors.New("bundle: component digest mismatch")
	// ErrUnlistedComponent means the archive carried a file not pinned in the manifest.
	ErrUnlistedComponent = errors.New("bundle: file not listed in manifest")
	// ErrMissingComponent means the manifest pinned a file the archive did not contain.
	ErrMissingComponent = errors.New("bundle: manifest component missing from archive")
	// ErrNotUpgrade means the bundle version is not newer than what is installed.
	ErrNotUpgrade = errors.New("bundle: version is not an upgrade over the installed version")
	// ErrUpgradeSkipped means the installed version is older than the bundle's min_upgrade_from.
	ErrUpgradeSkipped = errors.New("bundle: installed version is below the bundle's minimum upgrade-from")
	// ErrEntryTooLarge means a tar entry declared a size exceeding the configured cap.
	ErrEntryTooLarge = errors.New("bundle: tar entry declares a size exceeding the maximum allowed")
	// ErrTooManyEntries means the archive contained more tar entries than the configured cap.
	ErrTooManyEntries = errors.New("bundle: archive contains more tar entries than allowed")
	// ErrDuplicateComponent means a component entry appeared more than once in the archive.
	ErrDuplicateComponent = errors.New("bundle: duplicate component entry")
)

// Component pins one file in the bundle by its digest and size. Path is a clean,
// forward-slash, relative path (e.g. "charts/keyorix-0.81.0.tgz").
type Component struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Manifest describes a bundle: what version it carries, the components it pins, the
// signing key-id, and the anti-skip floor. Signing the manifest transitively authenticates
// every component, because each is pinned by sha256.
type Manifest struct {
	Version        string      `json:"version"`
	ReleasedAt     time.Time   `json:"released_at"`
	MinUpgradeFrom string      `json:"min_upgrade_from,omitempty"`
	KeyID          string      `json:"key_id"`
	Components     []Component `json:"components"`
}

// MarshalCanonical renders the manifest deterministically (components sorted by path,
// indented) so the same inputs always produce byte-identical manifest.json — the bytes
// that get signed and, at verify time, re-checked against the signature.
func (m *Manifest) MarshalCanonical() ([]byte, error) {
	c := *m
	c.Components = append([]Component(nil), m.Components...)
	sort.Slice(c.Components, func(i, j int) bool { return c.Components[i].Path < c.Components[j].Path })
	return json.MarshalIndent(&c, "", "  ")
}

func (m *Manifest) byPath() map[string]Component {
	idx := make(map[string]Component, len(m.Components))
	for _, c := range m.Components {
		idx[c.Path] = c
	}
	return idx
}

// cleanComponentPath validates a component path is relative, normalized, and contained —
// no absolute paths, no "..", no leading slash. Returned in clean forward-slash form.
func cleanComponentPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", fmt.Errorf("bundle: empty component path")
	}
	if path.IsAbs(p) || strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("bundle: absolute component path %q", p)
	}
	clean := path.Clean(filepath.ToSlash(p))
	if isUnsafeCleanComponentPath(clean) {
		return "", fmt.Errorf("bundle: component path escapes the bundle: %q", p)
	}
	if clean == manifestName || clean == sigName {
		return "", fmt.Errorf("bundle: component path %q collides with a reserved name", p)
	}
	return clean, nil
}

// isUnsafeCleanComponentPath re-checks an already-cleaned, forward-slash path for
// escape/absolute shapes (Windows UNC-style paths become absolute-looking only after
// filepath.ToSlash + path.Clean run; this re-check catches that regardless of platform).
func isUnsafeCleanComponentPath(clean string) bool {
	return clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/")
}

// BuildManifest walks srcDir and pins every regular file (by relative path) with its
// sha256 and size. It refuses reserved names; manifest.json/manifest.sig are written by
// WriteBundle, not taken from srcDir. Maintainer-only (`keyorix bundle build`) -- see the
// package doc comment for why this stays out of the thin CLI's command surface even though
// it lives in the same public package as Verify/Extract.
func BuildManifest(srcDir, version, keyID, minUpgradeFrom string, releasedAt time.Time) (*Manifest, error) { // NOSONAR -- cognitive complexity 19, suppress go:S3776
	if strings.TrimSpace(version) == "" {
		return nil, fmt.Errorf("bundle: version is required")
	}
	if _, err := parseVersion(version); err != nil {
		return nil, fmt.Errorf("bundle: version %q: %w", version, err)
	}
	if strings.TrimSpace(keyID) == "" {
		return nil, fmt.Errorf("bundle: key-id is required")
	}
	if minUpgradeFrom != "" {
		if _, err := parseVersion(minUpgradeFrom); err != nil {
			return nil, fmt.Errorf("bundle: min-upgrade-from %q: %w", minUpgradeFrom, err)
		}
	}

	var components []Component
	err := filepath.WalkDir(srcDir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(srcDir, p)
		if err != nil {
			return err
		}
		clean, err := cleanComponentPath(rel)
		if err != nil {
			return err
		}
		sum, size, err := hashFile(p)
		if err != nil {
			return err
		}
		components = append(components, Component{Path: clean, SHA256: sum, Size: size})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(components) == 0 {
		return nil, fmt.Errorf("bundle: no files found under %q", srcDir)
	}
	sort.Slice(components, func(i, j int) bool { return components[i].Path < components[j].Path })
	return &Manifest{
		Version:        strings.TrimSpace(version),
		ReleasedAt:     releasedAt.UTC(),
		MinUpgradeFrom: strings.TrimSpace(minUpgradeFrom),
		KeyID:          strings.TrimSpace(keyID),
		Components:     components,
	}, nil
}

// WriteBundle writes the signed bundle to w: manifest.json first, then manifest.sig, then
// every component file (sorted by path). sig must be an ed25519 signature over the exact
// canonical manifest bytes (see Sign). Maintainer-only, see BuildManifest's doc comment.
func WriteBundle(w io.Writer, srcDir string, m *Manifest, sig []byte) error {
	manifestBytes, err := m.MarshalCanonical()
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)

	if err := writeTarBytes(tw, manifestName, manifestBytes); err != nil {
		return err
	}
	if err := writeTarBytes(tw, sigName, sig); err != nil {
		return err
	}
	for _, c := range m.Components {
		full := filepath.Join(srcDir, filepath.FromSlash(c.Path))
		f, err := os.Open(full) // #nosec G304 -- path validated by cleanComponentPath, rooted at srcDir
		if err != nil {
			return err
		}
		hdr := &tar.Header{Name: c.Path, Mode: 0o644, Size: c.Size, ModTime: m.ReleasedAt}
		if err := tw.WriteHeader(hdr); err != nil {
			_ = f.Close()
			return err
		}
		if _, err := io.Copy(tw, f); err != nil { // #nosec G110 -- size is pinned in the header
			_ = f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// Sign returns an ed25519 signature over the canonical manifest bytes. The private key is
// the offline signing secret; it never ships with the bundle. Maintainer-only.
func Sign(m *Manifest, priv ed25519.PrivateKey) ([]byte, error) {
	b, err := m.MarshalCanonical()
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, b), nil
}

func writeTarBytes(tw *tar.Writer, name string, b []byte) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(b))}); err != nil {
		return err
	}
	_, err := tw.Write(b)
	return err
}

func hashFile(p string) (string, int64, error) {
	f, err := os.Open(p) // #nosec G304 -- caller walks a trusted srcDir
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// ParsePrivateKeyPEM decodes a PKCS#8 PEM (as written by `keyorix trust keygen`) into an
// ed25519 private key for signing. Maintainer-only, see BuildManifest's doc comment.
func ParsePrivateKeyPEM(b []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("bundle: no PEM block in signing key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("bundle: parse signing key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("bundle: signing key is not ed25519 (%T)", key)
	}
	return priv, nil
}

// Verify streams a bundle from r, checking the manifest signature against the trusted,
// embedded key for its key-id, then every component's digest. It is memory-bounded (it
// hashes component bytes as they stream; it does not buffer images) and fails closed on
// any mismatch, unlisted file, or missing component. On success it returns the manifest.
// Verify only reads — it stages nothing; see Extract.
func Verify(r io.Reader, reg *trust.KeyRegistry) (*Manifest, error) {
	return process(r, reg, nil)
}

// Extract verifies a bundle (exactly as Verify) and, only after the signature and the
// no-downgrade gate pass, stages every verified component under destDir — preserving the
// component's relative path, contained within destDir, written atomically (temp + rename)
// so a digest failure never leaves a poisoned file in place. installedVersion enforces
// no-downgrade / min_upgrade_from *before* any component is written. Re-running it
// overwrites identical verified content, so import is idempotent.
func Extract(r io.Reader, reg *trust.KeyRegistry, destDir, installedVersion string) (*Manifest, error) {
	return process(r, reg, &extractOpts{destDir: destDir, installedVersion: installedVersion})
}

// ExtractAllowingStateReset is like Extract, but additionally accepts the operator's
// explicit acknowledgement that destDir's install state may have been intentionally
// reset (see ErrInstallStateReset). It does NOT disable the no-downgrade check itself — it
// only resolves which record to trust when the internal and external ones disagree, in
// favor of whatever destDir/its internal marker actually shows; CheckUpgrade still runs
// against that resolved value.
func ExtractAllowingStateReset(r io.Reader, reg *trust.KeyRegistry, destDir, installedVersion string, acknowledgeReset bool) (*Manifest, error) {
	return process(r, reg, &extractOpts{destDir: destDir, installedVersion: installedVersion, resetAcknowledged: acknowledgeReset})
}

// extractOpts is the staging configuration for process; nil means verify-only.
type extractOpts struct {
	destDir           string
	installedVersion  string
	resetAcknowledged bool
}

// process is the single streaming pass shared by Verify and Extract. It reads the manifest
// and signature first, verifies the signature against the embedded trusted key, optionally
// runs the no-downgrade gate, then streams each component — hashing it against its pinned
// digest and (when staging) writing it atomically. It fails closed on any mismatch.
func process(r io.Reader, reg *trust.KeyRegistry, opts *extractOpts) (*Manifest, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("bundle: gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)

	manifestBytes, err := readNamedEntry(tr, manifestName)
	if err != nil {
		return nil, err
	}
	sig, err := readNamedEntry(tr, sigName)
	if err != nil {
		return nil, err
	}

	var m Manifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return nil, fmt.Errorf("bundle: parse manifest: %w", err)
	}
	if strings.TrimSpace(m.KeyID) == "" {
		return nil, fmt.Errorf("bundle: manifest has no key-id")
	}
	// Verify the signature over the EXACT manifest.json bytes carried in the archive,
	// against the embedded trusted key named by the manifest's key-id. A forged key-id is
	// not in the embedded registry, so this fails closed.
	if err := reg.Verify(trust.PurposeUpdate, m.KeyID, manifestBytes, sig); err != nil {
		return nil, fmt.Errorf("bundle: manifest signature: %w", err)
	}

	// When staging, gate on no-downgrade BEFORE writing any component, and prepare destDir.
	if err := validateAndPrepareExtract(opts, &m); err != nil {
		return nil, err
	}

	if err := streamBundleComponents(tr, m.byPath(), optsDest(opts)); err != nil {
		return nil, err
	}

	// Record the just-staged version so a subsequent import enforces no-downgrade against
	// reality without the operator having to pass --installed-version.
	if opts != nil {
		if err := writeInstalledVersion(opts.destDir, m.Version); err != nil {
			return nil, err
		}
		if err := writeExternalInstallState(opts.destDir, m.Version); err != nil {
			return nil, err
		}
	}
	return &m, nil
}

// validateAndPrepareExtract gates extraction: validates the destination, enforces the
// no-downgrade check (reading the persisted marker as the authoritative installed version),
// and creates the destination directory. A nil opts means verify-only mode; returns nil.
func validateAndPrepareExtract(opts *extractOpts, m *Manifest) error {
	if opts == nil {
		return nil
	}
	if strings.TrimSpace(opts.destDir) == "" {
		return fmt.Errorf("bundle: extract destination is required")
	}
	installed, idempotent, err := resolveIdempotentInstall(opts, m)
	if err != nil {
		return err
	}
	if !idempotent {
		if err := m.CheckUpgrade(installed); err != nil {
			return err
		}
	}
	if err := mkdirAllNoSymlink(opts.destDir, opts.destDir); err != nil {
		return fmt.Errorf("bundle: create destination: %w", err)
	}
	return nil
}

// resolveIdempotentInstall reads the persisted version marker and determines whether
// re-importing the bundle's version is an idempotent re-stage (same version as marker).
func resolveIdempotentInstall(opts *extractOpts, m *Manifest) (installed string, idempotent bool, err error) {
	installed = strings.TrimSpace(opts.installedVersion)
	fromMarker := false
	if marker, ok, merr := reconcileInstallState(opts.destDir, opts.resetAcknowledged); merr != nil {
		return "", false, merr
	} else if ok {
		installed, fromMarker = marker, true
	}
	if fromMarker && installed != "" {
		if cmp, cerr := compareVersions(m.Version, installed); cerr == nil && cmp == 0 {
			return installed, true, nil
		}
	}
	return installed, false, nil
}

// streamBundleComponents iterates the tar stream, verifies each component against its
// pinned digest, writes it to dest (empty = verify-only), then checks that every pinned
// component was seen. Fails closed on any mismatch or missing component.
func streamBundleComponents(tr *tar.Reader, pinned map[string]Component, dest string) error {
	seen := make(map[string]bool, len(pinned))
	entries := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("bundle: read archive: %w", err)
		}
		entries++
		if entries > maxComponentEntries {
			return fmt.Errorf("%w: more than %d entries", ErrTooManyEntries, maxComponentEntries)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if hdr.Size > maxComponentBytes {
			return fmt.Errorf("%w: %s declares %d bytes (max %d)", ErrEntryTooLarge, hdr.Name, hdr.Size, int64(maxComponentBytes))
		}
		name, err := cleanComponentPath(hdr.Name)
		if err != nil {
			return err
		}
		comp, ok := pinned[name]
		if !ok {
			return fmt.Errorf("%w: %s", ErrUnlistedComponent, name)
		}
		if seen[name] {
			return fmt.Errorf("%w: %s", ErrDuplicateComponent, name)
		}
		if hdr.Size != comp.Size {
			return fmt.Errorf("%w: %s (header size %d, manifest size %d)", ErrDigestMismatch, name, hdr.Size, comp.Size)
		}
		if err := streamComponent(tr, comp, dest); err != nil {
			return err
		}
		seen[name] = true
	}
	return checkAllComponentsSeen(pinned, seen)
}

func checkAllComponentsSeen(pinned map[string]Component, seen map[string]bool) error {
	for p := range pinned {
		if !seen[p] {
			return fmt.Errorf("%w: %s", ErrMissingComponent, p)
		}
	}
	return nil
}

// installedVersionMarker is the file at the staging destination recording the version of
// the last successfully-imported bundle — the authoritative input to the no-downgrade gate.
const installedVersionMarker = ".keyorix-installed-version"

// PersistedInstalledVersion returns the version recorded by a previous successful `import`
// at destDir, reconciling the internal marker against the external install-state record
// (see reconcileInstallState, ErrInstallStateReset): ok is true and version is set when
// either record anchors the no-downgrade / anti-skip gate for this destination; ok is false
// when destDir is empty/nonexistent AND no external record exists (a genuine first import).
func PersistedInstalledVersion(destDir string) (version string, ok bool, err error) {
	return reconcileInstallState(destDir, false)
}

// PersistedInstalledVersionAllowingReset is like PersistedInstalledVersion, but takes the
// operator's explicit acknowledgement (acknowledgeReset) that destDir's install state may
// have been intentionally reset.
func PersistedInstalledVersionAllowingReset(destDir string, acknowledgeReset bool) (version string, ok bool, err error) {
	return reconcileInstallState(destDir, acknowledgeReset)
}

// readInstalledVersion returns the persisted installed version at destDir. ok is false
// when no marker exists (a first install); a present-but-unreadable marker is an error
// (fail closed). A missing marker in an OTHERWISE NON-EMPTY destDir is also refused rather
// than treated as a first install — see destDirHasContent's caller below for why.
func readInstalledVersion(destDir string) (string, bool, error) {
	if err := verifyNoSymlink(destDir, destDir); err != nil {
		return "", false, err
	}
	b, err := readFileNoFollow(destDir, installedVersionMarker)
	if err != nil {
		if os.IsNotExist(err) {
			hasContent, derr := destDirHasContent(destDir)
			if derr != nil {
				return "", false, fmt.Errorf("bundle: check destination for existing content: %w", derr)
			}
			if hasContent {
				return "", false, fmt.Errorf("bundle: destination %q already contains staged content but no installed-version marker — refusing to treat this as a first install (the marker may have been removed, or a prior import failed partway through); clear the destination first if this is intentional", destDir)
			}
			return "", false, nil
		}
		return "", false, fmt.Errorf("bundle: read installed-version marker: %w", err)
	}
	return strings.TrimSpace(string(b)), true, nil
}

// destDirHasContent reports whether destDir contains any entry at all. A
// nonexistent directory counts as empty (nothing has ever been staged there).
func destDirHasContent(destDir string) (bool, error) {
	entries, err := os.ReadDir(destDir)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return len(entries) > 0, nil
}

// writeInstalledVersion persists version as the installed-version marker at destDir.
func writeInstalledVersion(destDir, version string) error {
	if err := writeFileNoFollow(destDir, installedVersionMarker, []byte(version+"\n"), 0o600); err != nil {
		return fmt.Errorf("bundle: write installed-version marker: %w", err)
	}
	return nil
}

func optsDest(opts *extractOpts) string {
	if opts == nil {
		return ""
	}
	return opts.destDir
}

// streamComponent reads exactly comp.Size bytes of the current tar entry, verifying the
// sha256 digest. The read is bounded to size+1 (a decompression-bomb guard that also
// rejects an oversized entry before its digest is compared). If destDir is non-empty the
// bytes are written atomically to destDir/comp.Path (temp file + rename); on any digest
// failure the temp file is removed, so a failed component never lands on disk.
func streamComponent(tr io.Reader, comp Component, destDir string) error {
	h := sha256.New()
	dst := io.Writer(h)

	var tmpPath, finalPath string
	var tmp *os.File
	if destDir != "" {
		final, err := safeJoin(destDir, comp.Path)
		if err != nil {
			return err
		}
		finalPath = final
		if err := mkdirAllNoSymlink(destDir, filepath.Dir(finalPath)); err != nil {
			return fmt.Errorf("bundle: mkdir for %s: %w", comp.Path, err)
		}
		tmp, err = os.CreateTemp(filepath.Dir(finalPath), ".kxbundle-*")
		if err != nil {
			return fmt.Errorf("bundle: temp for %s: %w", comp.Path, err)
		}
		tmpPath = tmp.Name()
		dst = io.MultiWriter(h, tmp)
	}

	n, copyErr := io.Copy(dst, io.LimitReader(tr, comp.Size+1))
	if tmp != nil {
		_ = tmp.Close()
	}
	if copyErr != nil {
		removeBundleTemp(tmpPath)
		return fmt.Errorf("bundle: read %s: %w", comp.Path, copyErr)
	}
	if n != comp.Size {
		removeBundleTemp(tmpPath)
		return fmt.Errorf("%w: %s (size %d, want %d)", ErrDigestMismatch, comp.Path, n, comp.Size)
	}
	if hex.EncodeToString(h.Sum(nil)) != comp.SHA256 {
		removeBundleTemp(tmpPath)
		return fmt.Errorf("%w: %s", ErrDigestMismatch, comp.Path)
	}
	if tmpPath != "" {
		if err := os.Rename(tmpPath, finalPath); err != nil {
			removeBundleTemp(tmpPath)
			return fmt.Errorf("bundle: stage %s: %w", comp.Path, err)
		}
	}
	return nil
}

func removeBundleTemp(tmpPath string) {
	if tmpPath != "" {
		_ = os.Remove(tmpPath)
	}
}

// mkdirAllNoSymlink creates dir (and any missing parents, down to and including root
// itself) without ever traversing through an existing symlink. Unlike os.MkdirAll — which
// happily walks through a symlink at any path component and treats it as "the directory
// already exists" — this Lstats every component and refuses the moment one is a symlink.
// root is re-checked on every call (including when root == dir) so a pre-planted symlink AT
// the staging root's own path is caught too, not just symlinks nested underneath it.
func mkdirAllNoSymlink(root, dir string) error {
	return walkNoSymlink(root, dir, true)
}

// verifyNoSymlink is mkdirAllNoSymlink's read-only sibling: it walks the same root-to-dir
// path Lstat-checking every EXISTING component for a symlink, but never creates a missing
// one — a read-only check must not have a filesystem side effect. A missing component simply
// ends the walk (nothing beneath a directory that doesn't exist can exist either); the
// caller's own subsequent open/read fails with ENOENT exactly as it always did. Callers that
// read via readFileNoFollow but don't otherwise create dir first (readInstalledVersion,
// readExternalInstallState) call this so the "directory already verified symlink-free"
// guarantee readFileNoFollow's #nosec comment claims is actually true on the read path too,
// not just on the write path where mkdirAllNoSymlink already ran.
func verifyNoSymlink(root, dir string) error {
	return walkNoSymlink(root, dir, false)
}

// walkNoSymlink is the shared Lstat walk behind mkdirAllNoSymlink (create=true) and
// verifyNoSymlink (create=false).
func walkNoSymlink(root, dir string, create bool) error { // NOSONAR -- cognitive complexity, matches internal/bundle's original
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("bundle: resolve staging root: %w", err)
	}
	dirAbs, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("bundle: resolve target directory: %w", err)
	}
	rel, err := filepath.Rel(rootAbs, dirAbs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("bundle: refusing to touch directory %q outside staging root %q", dir, root)
	}

	var parts []string
	if rel != "." {
		parts = strings.Split(filepath.ToSlash(rel), "/")
	}
	segments := append([]string{filepath.Base(rootAbs)}, parts...)
	cur := filepath.Dir(rootAbs)
	for _, part := range segments {
		if part == "" {
			continue
		}
		cur = filepath.Join(cur, part)
		fi, statErr := os.Lstat(cur)
		switch {
		case statErr == nil:
			if fi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("bundle: refusing to follow pre-existing symlink at %q", cur)
			}
			if !fi.IsDir() {
				return fmt.Errorf("bundle: %q exists and is not a directory", cur)
			}
		case os.IsNotExist(statErr):
			if !create {
				return nil
			}
			if mkErr := os.Mkdir(cur, 0o750); mkErr != nil {
				return fmt.Errorf("bundle: mkdir %q: %w", cur, mkErr)
			}
		default:
			return fmt.Errorf("bundle: stat %q: %w", cur, statErr)
		}
	}
	return nil
}

// safeJoin joins a validated relative component path onto destDir and confirms the result
// stays within destDir (defence in depth atop cleanComponentPath).
func safeJoin(destDir, rel string) (string, error) {
	clean, err := cleanComponentPath(rel)
	if err != nil {
		return "", err
	}
	joined := filepath.Join(destDir, filepath.FromSlash(clean))
	rootAbs, err := filepath.Abs(destDir)
	if err != nil {
		return "", err
	}
	joinedAbs, err := filepath.Abs(joined)
	if err != nil {
		return "", err
	}
	if joinedAbs != rootAbs && !strings.HasPrefix(joinedAbs, rootAbs+string(os.PathSeparator)) {
		return "", fmt.Errorf("bundle: component %q escapes destination", rel)
	}
	return joined, nil
}

// CheckUpgrade enforces the no-downgrade and anti-skip rules against the installed
// version. An empty installed version (a first install) passes.
func (m *Manifest) CheckUpgrade(installed string) error {
	if strings.TrimSpace(installed) == "" {
		return nil
	}
	cmp, err := compareVersions(m.Version, installed)
	if err != nil {
		return err
	}
	if cmp <= 0 {
		return fmt.Errorf("%w: bundle %s <= installed %s", ErrNotUpgrade, m.Version, installed)
	}
	if m.MinUpgradeFrom != "" {
		floor, err := compareVersions(installed, m.MinUpgradeFrom)
		if err != nil {
			return err
		}
		if floor < 0 {
			return fmt.Errorf("%w: installed %s < required %s", ErrUpgradeSkipped, installed, m.MinUpgradeFrom)
		}
	}
	return nil
}

// readNamedEntry reads the next tar entry, requiring it to be the named regular file, and
// returns its bytes (bounded by maxManifestBytes).
func readNamedEntry(tr *tar.Reader, want string) ([]byte, error) {
	hdr, err := tr.Next()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoManifest, err)
	}
	if hdr.Name != want || hdr.Typeflag != tar.TypeReg {
		return nil, fmt.Errorf("%w: got %q, want %q", ErrNoManifest, hdr.Name, want)
	}
	if hdr.Size > maxManifestBytes {
		return nil, fmt.Errorf("%w: %s declares %d bytes (max %d)", ErrEntryTooLarge, want, hdr.Size, maxManifestBytes)
	}
	b, err := io.ReadAll(io.LimitReader(tr, maxManifestBytes))
	if err != nil {
		return nil, err
	}
	return b, nil
}

// parseVersion accepts a "vX.Y.Z" (or "X.Y.Z") release version, ignoring any pre-release
// or build metadata, and returns its numeric components.
func parseVersion(v string) ([3]int, error) {
	var out [3]int
	s := strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return out, fmt.Errorf("not a vMAJOR.MINOR.PATCH version")
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, fmt.Errorf("invalid version component %q", p)
		}
		out[i] = n
	}
	return out, nil
}

// compareVersions returns -1, 0, or 1 for a<b, a==b, a>b over vX.Y.Z versions.
func compareVersions(a, b string) (int, error) {
	pa, err := parseVersion(a)
	if err != nil {
		return 0, err
	}
	pb, err := parseVersion(b)
	if err != nil {
		return 0, err
	}
	for i := range 3 {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1, nil
			}
			return 1, nil
		}
	}
	return 0, nil
}

// --- minimal local file-safety helpers ---
//
// internal/securefiles provides the repo's general-purpose symlink-safe file I/O (a full
// per-path-component O_NOFOLLOW walk via SecureOpenBeneath), but this package deliberately
// does NOT import it: internal/securefiles is (a) internal to the main module, unreachable
// from the separate cli/ module without defeating the point of this split, and (b) under
// active change in a parallel PR. The two helpers below cover only what this package
// actually needs: writing/reading one small marker file in a directory whose FULL path was
// already verified symlink-free by mkdirAllNoSymlink (every call site here does that first).
// The remaining guarantee is narrower than SecureOpenBeneath's — O_NOFOLLOW on the final
// path component only, not a fresh per-component walk on every call — which is sufficient
// given the directory itself is freshly verified, and is stated here explicitly rather than
// silently assumed equivalent.

func writeFileNoFollow(dir, name string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_TRUNC|unix.O_NOFOLLOW, perm) // #nosec G304 -- dir verified symlink-free by mkdirAllNoSymlink/verifyNoSymlink at every call site; O_NOFOLLOW guards the final component
	if err != nil {
		return err
	}
	// O_CREATE only applies perm to a newly-created file -- overwriting a pre-existing file
	// (e.g. one left behind at a looser mode from an older version of this code) leaves its
	// mode untouched unless Chmod is called explicitly. Sync forces the write to durable
	// storage before Close, matching internal/securefiles.SecureWriteFileSync's original
	// durability guarantee: a crash right after this call must not lose or truncate the
	// record.
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func readFileNoFollow(dir, name string) ([]byte, error) {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_RDONLY|unix.O_NOFOLLOW, 0) // #nosec G304 -- dir verified symlink-free by mkdirAllNoSymlink; O_NOFOLLOW guards the final component
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}
