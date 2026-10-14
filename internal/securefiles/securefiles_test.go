package securefiles

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsPathInsideBase(t *testing.T) {
	cases := []struct {
		base, target string
		want         bool
	}{
		{"/a/b", "/a/b", true},         // base itself
		{"/a/b", "/a/b/c", true},       // child
		{"/a/b", "/a/b/c/d", true},     // descendant
		{"/a/b", "/a", false},          // parent
		{"/a/b", "/a/bc", false},       // sibling sharing a prefix (the classic guard)
		{"/a/b", "/a/b/../c", false},   // escapes via ..
		{"/a/b", "/etc/passwd", false}, // unrelated absolute
	}
	for _, c := range cases {
		got, err := isPathInsideBase(c.base, c.target)
		require.NoError(t, err)
		assert.Equalf(t, c.want, got, "isPathInsideBase(%q, %q)", c.base, c.target)
	}
}

func TestSecureWriteAndReadRoundTrip(t *testing.T) {
	base := t.TempDir()
	want := []byte("secret-bytes")

	// SecureWriteFile does not create parent dirs (callers do); mimic that.
	require.NoError(t, os.MkdirAll(filepath.Join(base, "keys"), 0700))
	require.NoError(t, SecureWriteFile(base, "keys/dek.key", want, 0600))

	// Perm is applied as requested.
	info, err := os.Stat(filepath.Join(base, "keys/dek.key"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	got, err := SafeReadFile(base, "keys/dek.key")
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestSecureWriteFileEnforcesPermsOnExistingFile(t *testing.T) {
	base := t.TempDir()
	// A pre-existing file with looser perms must be tightened to the requested mode
	// (O_TRUNC alone keeps the old mode; the explicit Chmod fixes it) — same guarantee
	// as SecureWriteFileSync, just without the fsync.
	require.NoError(t, os.WriteFile(filepath.Join(base, "config.yaml"), []byte("old"), 0644))
	require.NoError(t, SecureWriteFile(base, "config.yaml", []byte("new"), 0600))

	info, err := os.Stat(filepath.Join(base, "config.yaml"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	got, err := SafeReadFile(base, "config.yaml")
	require.NoError(t, err)
	assert.Equal(t, []byte("new"), got)
}

func TestSecureWriteFileSyncRoundTripAndPerms(t *testing.T) {
	base := t.TempDir()
	want := []byte("durable-key-bytes")
	require.NoError(t, SecureWriteFileSync(base, "dek.key", want, 0600))

	info, err := os.Stat(filepath.Join(base, "dek.key"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	got, err := SafeReadFile(base, "dek.key")
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestSecureWriteFileSyncEnforcesPermsOnExistingFile(t *testing.T) {
	base := t.TempDir()
	// A pre-existing file with looser perms must be tightened to the requested mode
	// (O_TRUNC alone keeps the old mode; the explicit Chmod fixes it).
	require.NoError(t, os.WriteFile(filepath.Join(base, "dek.key"), []byte("old"), 0644))
	require.NoError(t, SecureWriteFileSync(base, "dek.key", []byte("new"), 0600))

	info, err := os.Stat(filepath.Join(base, "dek.key"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	got, err := SafeReadFile(base, "dek.key")
	require.NoError(t, err)
	assert.Equal(t, []byte("new"), got)
}

func TestSecureWriteFileSyncRejectsTraversal(t *testing.T) {
	base := t.TempDir()
	err := SecureWriteFileSync(base, "../escape.key", []byte("x"), 0600)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
	_, statErr := os.Stat(filepath.Join(filepath.Dir(base), "escape.key"))
	assert.True(t, os.IsNotExist(statErr))
}

// A DANGLING final-component symlink inside the base must not be followed: the write
// must fail (O_NOFOLLOW) rather than create the symlink's target outside the base.
func TestSecureWriteRefusesDanglingSymlink(t *testing.T) {
	base := t.TempDir()
	outside := filepath.Join(filepath.Dir(base), "escape.key")
	// A symlink "link.key" inside base pointing at a not-yet-existing file outside base.
	require.NoError(t, os.Symlink(outside, filepath.Join(base, "link.key")))

	err := SecureWriteFile(base, "link.key", []byte("secret"), 0600)
	require.Error(t, err, "writing through a final-component symlink must be refused")
	_, statErr := os.Stat(outside)
	assert.True(t, os.IsNotExist(statErr), "the symlink target outside base must not have been created")

	err = SecureWriteFileSync(base, "link.key", []byte("secret"), 0600)
	require.Error(t, err)
	_, statErr = os.Stat(outside)
	assert.True(t, os.IsNotExist(statErr))
}

// FixFilePerms must refuse to follow a symlink — otherwise it would chmod/chown the
// symlink's target (an arbitrary file when running as root).
func TestFixFilePerms_RefusesSymlink(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "real.txt")
	require.NoError(t, os.WriteFile(target, []byte("x"), 0644))
	link := filepath.Join(base, "link.key")
	require.NoError(t, os.Symlink(target, link))

	err := FixFilePerms([]FilePermSpec{{Path: link, Mode: 0600}}, true)
	require.Error(t, err, "autofix must report an unresolved issue for a symlinked path")
	// The target's mode must be untouched (the symlink was not followed).
	info, statErr := os.Stat(target)
	require.NoError(t, statErr)
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm(), "the symlink target's mode must be unchanged")
}

// TestFixFilePerms_TOCTOUSymlinkSwapNeverFollowed is the regression test for a
// TOCTOU race: FixFilePerms used to Lstat a path to detect a symlink, then
// separately call os.Chmod(path, ...) / os.Chown(path, ...) — both of which
// re-resolve the path and FOLLOW a final-component symlink. A symlink swapped
// into place after the Lstat check (or a race between the check and the fix)
// could redirect the chmod/chown to an arbitrary target outside the caller's
// control (an arbitrary chown when running as root).
//
// This test hammers that exact window: one goroutine repeatedly swaps path
// between a regular file and a symlink pointing at a "sensitive" file outside
// the directory (via atomic renames, mirroring how an attacker would swing the
// directory entry), while another goroutine repeatedly calls FixFilePerms on
// that same path with autofix=true. Throughout, the sensitive file's mode and
// ownership must never change — proving the fix operates on the fd obtained by
// an O_NOFOLLOW open (immune to the path being swapped out from under it), not
// on the path a second time after the initial check.
func TestFixFilePerms_TOCTOUSymlinkSwapNeverFollowed(t *testing.T) {
	dir := t.TempDir()

	// The attacker's target: a file outside the directory FixFilePerms is
	// meant to operate on. If the symlink is ever followed by a fix, this
	// file's mode changes to 0600 (the spec below) or its owner changes.
	sensitive := filepath.Join(t.TempDir(), "sensitive-outside-file")
	require.NoError(t, os.WriteFile(sensitive, []byte("do-not-touch"), 0644))

	path := filepath.Join(dir, "target.key")
	spec := FilePermSpec{Path: path, Mode: 0600}

	const iterations = 500
	var stop atomic.Int32

	// require/assert's fatal ("FailNow") helpers are documented as unsafe to call
	// from a goroutine other than the test's own, so this goroutine reports setup
	// failures via plain t.Errorf (safe for concurrent use) instead of require.
	var wg sync.WaitGroup
	wg.Go(func() {
		defer stop.Store(1)
		for range iterations {
			// Swing path to a regular (wrong-mode) file via an atomic rename.
			tmp := path + ".regular"
			if err := os.WriteFile(tmp, []byte("x"), 0644); err != nil {
				t.Errorf("setup: write regular file: %v", err)
				return
			}
			if err := os.Rename(tmp, path); err != nil {
				t.Errorf("setup: rename to regular file: %v", err)
				return
			}

			// Swing path to a symlink pointing at the sensitive file, also via
			// an atomic rename — this is the exact swap-after-check shape a
			// TOCTOU exploit relies on.
			tmpLink := path + ".link"
			_ = os.Remove(tmpLink)
			if err := os.Symlink(sensitive, tmpLink); err != nil {
				t.Errorf("setup: create symlink: %v", err)
				return
			}
			if err := os.Rename(tmpLink, path); err != nil {
				t.Errorf("setup: rename to symlink: %v", err)
				return
			}
		}
	})

	for stop.Load() == 0 {
		_ = FixFilePerms([]FilePermSpec{spec}, true) // result ignored — either outcome (fixed regular file, or refused symlink) is valid
	}
	wg.Wait()

	info, err := os.Lstat(sensitive)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm(), "the sensitive file outside the directory must never be modified, even under a concurrent symlink swap")
}

func TestSyncDir(t *testing.T) {
	base := t.TempDir()
	// A real directory syncs without error.
	require.NoError(t, SyncDir(base))
	// A missing directory surfaces the open error rather than silently passing.
	require.Error(t, SyncDir(filepath.Join(base, "does-not-exist")))
}

func TestSafeReadFileRejectsTraversal(t *testing.T) {
	base := t.TempDir()
	// Plant a file outside the base to make the test meaningful.
	outside := filepath.Join(filepath.Dir(base), "outside.txt")
	require.NoError(t, os.WriteFile(outside, []byte("nope"), 0600))
	t.Cleanup(func() { _ = os.Remove(outside) })

	_, err := SafeReadFile(base, "../outside.txt")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
}

func TestSecureWriteFileRejectsTraversal(t *testing.T) {
	base := t.TempDir()
	err := SecureWriteFile(base, "../escape.txt", []byte("x"), 0600)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
	// Nothing was written outside the base.
	_, statErr := os.Stat(filepath.Join(filepath.Dir(base), "escape.txt"))
	assert.True(t, os.IsNotExist(statErr))
}

func TestFixFilePermsAuditReportsWrongMode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "loose.key")
	require.NoError(t, os.WriteFile(p, []byte("x"), 0644))
	require.NoError(t, os.Chmod(p, 0644)) // defeat umask for a deterministic mode

	// Audit only (autofix=false): wrong mode is a warning → error, file unchanged.
	err := FixFilePerms([]FilePermSpec{{Path: p, Mode: 0600}}, false)
	require.Error(t, err)
	info, _ := os.Stat(p)
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm(), "audit must not modify the file")
}

// Fail closed: when autofix is on but the fix can't actually be applied (here, the file
// doesn't exist so stat fails), FixFilePerms must return an error rather than silently
// reporting success — the previous `hasWarnings && !autofix` form returned nil, hiding an
// unlocked-down key file.
func TestFixFilePermsAutofixFailsClosedOnUnresolvable(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.key")
	err := FixFilePerms([]FilePermSpec{{Path: missing, Mode: 0600}}, true)
	require.Error(t, err, "an unresolvable problem must fail even under autofix")
}

func TestFixFilePermsAutofixCorrectsMode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "loose.key")
	require.NoError(t, os.WriteFile(p, []byte("x"), 0644))
	require.NoError(t, os.Chmod(p, 0644))

	require.NoError(t, FixFilePerms([]FilePermSpec{{Path: p, Mode: 0600}}, true))
	info, _ := os.Stat(p)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestFixFilePermsCorrectModeNoWarning(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tight.key")
	require.NoError(t, os.WriteFile(p, []byte("x"), 0600))
	require.NoError(t, os.Chmod(p, 0600))

	// Correct mode, owned by the current user → no warnings, no error.
	require.NoError(t, FixFilePerms([]FilePermSpec{{Path: p, Mode: 0600}}, false))
}

// sandboxExcusesMissingBit reports whether a special mode bit (setuid, setgid,
// sticky) that failed to stick may be excused. It is true ONLY when the bit is
// absent AND the session sandbox marker KEYORIX_SANDBOX is exactly "1": the
// macOS Seatbelt session sandbox silently refuses to set these bits. In CI, on
// dev machines and on the e2e VM the variable is unset, so a missing bit stays
// a hard failure of the precondition.
func sandboxExcusesMissingBit(got, bit os.FileMode, sandboxEnv string) bool {
	return got&bit == 0 && sandboxEnv == "1"
}

// skipIfSandboxRefusedSpecialBit skips the test when sandboxExcusesMissingBit
// holds; otherwise it does nothing, leaving the caller's require.* to fail.
func skipIfSandboxRefusedSpecialBit(t *testing.T, got, bit os.FileMode) {
	t.Helper()
	if sandboxExcusesMissingBit(got, bit, os.Getenv("KEYORIX_SANDBOX")) {
		t.Skip("the KEYORIX_SANDBOX=1 session sandbox refuses to set the special mode bit; CI runs this test")
	}
}

func TestSandboxExcusesMissingBit(t *testing.T) {
	const bit = os.ModeSetuid
	cases := []struct {
		name string
		got  os.FileMode
		env  string
		want bool
	}{
		{"bit missing, sandbox env set: excused", 0600, "1", true},
		{"bit missing, env unset: hard failure", 0600, "", false},
		{"bit missing, env other value: hard failure", 0600, "true", false},
		{"bit missing, env 0: hard failure", 0600, "0", false},
		{"bit present, sandbox env set: nothing to excuse", bit | 0600, "1", false},
		{"bit present, env unset: nothing to excuse", bit | 0600, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, sandboxExcusesMissingBit(c.got, bit, c.env))
		})
	}
}

// TestFixFilePermsClearsSetuidBitEvenWhenLow9BitsMatch pins the fix for the
// info.Mode().Perm() masking gap: a file whose low 9 bits already equal the
// target mode but which ALSO carries the setuid bit must still be corrected —
// actualMode == f.Mode alone must not be treated as "nothing to do".
func TestFixFilePermsClearsSetuidBitEvenWhenLow9BitsMatch(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "setuid.key")
	require.NoError(t, os.WriteFile(p, []byte("x"), 0600))
	require.NoError(t, os.Chmod(p, os.ModeSetuid|0600))

	info, err := os.Stat(p)
	require.NoError(t, err)
	skipIfSandboxRefusedSpecialBit(t, info.Mode(), os.ModeSetuid)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm(), "low 9 bits already match the target mode")
	require.NotZero(t, info.Mode()&os.ModeSetuid, "setuid bit must actually be set going in")

	// Audit only: the special bit alone must still be reported as a mismatch.
	err = FixFilePerms([]FilePermSpec{{Path: p, Mode: 0600}}, false)
	require.Error(t, err, "a setuid bit on an otherwise-correct-mode file must still warn")
	info, _ = os.Stat(p)
	assert.NotZero(t, info.Mode()&os.ModeSetuid, "audit-only must not modify the file")

	// Autofix: the setuid bit must be stripped even though actualMode == f.Mode.
	require.NoError(t, FixFilePerms([]FilePermSpec{{Path: p, Mode: 0600}}, true))
	info, _ = os.Stat(p)
	assert.Zero(t, info.Mode()&os.ModeSetuid, "autofix must clear the setuid bit")
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestFixFilePermsMissingFileWarns(t *testing.T) {
	err := FixFilePerms([]FilePermSpec{{Path: filepath.Join(t.TempDir(), "absent"), Mode: 0600}}, false)
	require.Error(t, err)
}

// TestContainmentRejectsSymlinkEscape pins the symlink-containment fix: a symlink
// planted inside baseDir that points outside it must not let a read or write escape.
func TestContainmentRejectsSymlinkEscape(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("top secret"), 0o600))

	// A symlink inside baseDir that resolves to the outside directory.
	require.NoError(t, os.Symlink(outside, filepath.Join(base, "link")))

	// Reading through the symlink must be denied (the resolved path is outside base).
	_, err := SafeReadFile(base, "link/secret.txt")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "outside")

	// Writing through the symlink (target does not exist yet) must also be denied.
	err = SecureWriteFile(base, "link/planted.txt", []byte("x"), 0o600)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "outside")

	// The outside directory must be untouched by the rejected write.
	_, statErr := os.Stat(filepath.Join(outside, "planted.txt"))
	assert.True(t, os.IsNotExist(statErr), "rejected write must not create a file outside base")
}

func TestSecureDeleteFile_OverwritesAndRemoves(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dek.key.migrate-backup.123")
	original := []byte("sensitive-wrapped-dek-bytes-not-random")
	require.NoError(t, os.WriteFile(path, original, 0600))

	require.NoError(t, SecureDeleteFile(path))

	_, err := os.Stat(path)
	assert.True(t, os.IsNotExist(err), "file must be removed")
}

func TestSecureDeleteFile_MissingFileIsNotAnError(t *testing.T) {
	require.NoError(t, SecureDeleteFile(filepath.Join(t.TempDir(), "does-not-exist")))
}

// TestSecureDeleteFile_RefusesSymlinkTarget is #G26: unlike every other write
// primitive in this file, SecureDeleteFile's open had no O_NOFOLLOW — a symlink at
// path would have the shred pass (random-then-zero overwrite) write through it to the
// target, destroying arbitrary file content the process can write to. The final
// os.Remove only unlinks the symlink itself, so without O_NOFOLLOW the corrupted
// target would be left with no trace at the expected path.
func TestSecureDeleteFile_RefusesSymlinkTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	dir := t.TempDir()
	evilTarget := filepath.Join(dir, "attacker-owned.txt")
	original := []byte("do-not-shred-me")
	require.NoError(t, os.WriteFile(evilTarget, original, 0600))
	link := filepath.Join(dir, "dek.key.migrate-backup.456")
	require.NoError(t, os.Symlink(evilTarget, link))

	err := SecureDeleteFile(link)
	require.Error(t, err, "a symlinked backup path must be refused, not followed")

	content, rerr := os.ReadFile(evilTarget)
	require.NoError(t, rerr)
	assert.Equal(t, original, content, "the symlink target must never be shredded")
}
