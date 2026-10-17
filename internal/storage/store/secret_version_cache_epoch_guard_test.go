package store

// Guards for secret_versions.cache_epoch (DEK-SWEEP-CACHE-1): the latest-version
// cache can only notice an in-place ciphertext rewrite if the rewriter raises
// cache_epoch, so (1) every non-test place that WRITES the ciphertext columns
// must be known, and (2) each known writer must raise cache_epoch in the same
// statement.
//
// What this recognises, stated explicitly: a non-test .go file under the
// repository root (outside vendor/.git/web/node_modules/.scratch/.gopath) in
// which an UPDATE statement or a GORM update call names the column
// "encrypted_value" / "encryption_metadata" of secret_versions. Recognised
// forms: a raw `UPDATE secret_versions SET ...` string, and a map/column
// literal key "encrypted_value" handed to Update/Updates/UpdateColumn(s)/Set.
// NOT recognised, and said so: a column name built at runtime, a struct Save of
// a models.SecretVersion (CREATE of a new version is not a rewrite; `Save` of a
// fetched row is — none exists today and the model field CacheEpoch is
// read-only to GORM so a Save cannot reset the epoch either), and SQL kept in a
// non-Go file (a migration script). Writers INSERTing a new version row are out
// of scope by design: a new row moves count and max(version_number).

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// ciphertextWriters lists, by repo-relative path, the only non-test files that
// rewrite secret_versions ciphertext in place. Add a file here only together
// with a cache_epoch bump in its statement.
var ciphertextWriters = map[string]bool{
	"internal/encryption/sweep.go": true,
}

var (
	rawVersionCiphertextUpdate = regexp.MustCompile(`(?is)UPDATE\s+secret_versions\s+SET[^"` + "`" + `]*\b(encrypted_value|encryption_metadata)\b`)
	mapKeyVersionCiphertext    = regexp.MustCompile(`"(encrypted_value|encryption_metadata)"\s*:`)
	updateCallVersionColumn    = regexp.MustCompile(`\.(Update|UpdateColumn)\(\s*"(encrypted_value|encryption_metadata)"`)
)

func repoRootFromStorePackage(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(root, "go.mod"))
	require.NoError(t, err, "repo root not found two levels above internal/storage/store")
	return root
}

func TestSecretVersionCiphertextWriters_AreOnlyTheSweep(t *testing.T) {
	t.Parallel()
	root := repoRootFromStorePackage(t)

	skipDir := map[string]bool{".git": true, "vendor": true, "node_modules": true, "web": true, ".scratch": true, ".gopath": true, "bin": true}
	found := map[string]string{}
	require.NoError(t, filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(path) //nolint:gosec // repo-local scan
		if rerr != nil {
			return rerr
		}
		src := string(b)
		if !strings.Contains(src, "encrypted_value") && !strings.Contains(src, "encryption_metadata") {
			return nil
		}
		// A map-key or Update("col") form only counts in a file that also talks
		// about the versions table or model, so other tables' encrypted columns
		// (api_tokens, mfa_secrets, ...) are not mistaken for secret_versions.
		versionsContext := strings.Contains(src, "secret_versions") || strings.Contains(src, "models.SecretVersion")
		hit := rawVersionCiphertextUpdate.MatchString(src) ||
			(versionsContext && (mapKeyVersionCiphertext.MatchString(src) || updateCallVersionColumn.MatchString(src)))
		if hit {
			rel, _ := filepath.Rel(root, path)
			found[filepath.ToSlash(rel)] = src
		}
		return nil
	}))

	var unexpected, missingBump []string
	for rel, src := range found {
		if !ciphertextWriters[rel] {
			unexpected = append(unexpected, rel)
			continue
		}
		if !strings.Contains(src, "cache_epoch = cache_epoch + 1") {
			missingBump = append(missingBump, rel)
		}
	}
	sort.Strings(unexpected)
	sort.Strings(missingBump)
	require.Empty(t, unexpected,
		"new writer of secret_versions ciphertext: it must raise secret_versions.cache_epoch in the same statement (the latest-version cache cannot see an in-place rewrite otherwise), then be added to ciphertextWriters")
	require.Empty(t, missingBump, "a known ciphertext writer no longer raises secret_versions.cache_epoch")

	// Calibration: a scanner that finds nothing passes vacuously.
	for rel := range ciphertextWriters {
		_, ok := found[rel]
		require.True(t, ok, "the scanner no longer recognises %s as a ciphertext writer; it has stopped matching the idiom, not the code stopped using it", rel)
	}
}
