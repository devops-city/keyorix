package securefiles

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/keyorixhq/keyorix/internal/secretenv"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

var FilePermsCmd = &cobra.Command{
	Use:   "fileperms",
	Short: "Manage critical file permissions",
}

// FilePermSpec describes a file and its required permissions and ownership
type FilePermSpec struct {
	Path string
	Mode os.FileMode // e.g., 0600
}

// isPathInsideBase ensures that targetPath is inside baseDir. It resolves symlinks on
// both sides before comparing, so a symlink planted inside baseDir cannot redirect the
// read/write to a location outside it (a purely lexical filepath.Clean check would miss
// that). The target file itself may not exist yet (writes), so its longest existing
// ancestor is resolved and the unresolved tail re-attached.
//
// This is a cheap pre-check only, used to fail fast with a clear "access denied" error
// on an obviously-escaping path (e.g. "../etc/passwd"). It is NOT sufficient on its own
// as a security boundary: it can only resolve symlinks up to the longest EXISTING
// ancestor at the moment it runs, so a not-yet-existing intermediate path component
// (e.g. baseDir/not-yet-created-dir/file) is passed through unresolved, and an attacker
// racing between this check and the later open could plant that component as a symlink
// pointing outside baseDir. Every caller that actually opens the file MUST use
// SecureOpenBeneath (below) to perform the open, which closes that gap by walking the
// path component-by-component with O_NOFOLLOW relative to already-open parent file
// descriptors — see its doc comment for why that eliminates the TOCTOU window that this
// function's path-string check alone cannot.
func isPathInsideBase(baseDir, targetPath string) (bool, error) {
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return false, err
	}
	if resolved, rerr := filepath.EvalSymlinks(absBase); rerr == nil {
		absBase = resolved
	} else if !os.IsNotExist(rerr) {
		return false, rerr
	}

	absTarget, err := filepath.Abs(targetPath)
	if err != nil {
		return false, err
	}
	absTarget = resolveExistingAncestor(absTarget)

	baseWithSlash := absBase + string(os.PathSeparator)
	return absTarget == absBase || strings.HasPrefix(absTarget, baseWithSlash), nil
}

// resolveExistingAncestor returns p with its longest existing prefix run through
// filepath.EvalSymlinks (collapsing any symlink in the real path) and the remaining
// non-existent suffix re-appended unchanged. This lets the containment check resolve
// symlinks even when the final target does not exist yet.
func resolveExistingAncestor(p string) string {
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved
	}
	dir, file := filepath.Split(p)
	dir = filepath.Clean(dir)
	if dir == p { // reached the filesystem root; nothing left to resolve
		return p
	}
	return filepath.Join(resolveExistingAncestor(dir), file)
}

// SafeReadFile reads a file at filepath.Join(baseDir, filePath), validating
// that the resolved path remains inside baseDir.
func SafeReadFile(baseDir, filePath string) ([]byte, error) {
	fullPath := filepath.Join(baseDir, filePath)
	cleanPath := filepath.Clean(fullPath)

	ok, err := isPathInsideBase(baseDir, cleanPath)
	if err != nil {
		return nil, fmt.Errorf("path validation error: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("access denied: file %q is outside of %q", cleanPath, baseDir)
	}

	// The actual open happens via SecureOpenBeneath, not os.ReadFile(cleanPath): the
	// isPathInsideBase check above only resolves symlinks up to the longest existing
	// ancestor, so it cannot see a symlink an attacker plants at a not-yet-existing (or
	// racily-replaced) intermediate component between this check and the open below.
	// SecureOpenBeneath closes that gap by walking every component with O_NOFOLLOW.
	//
	// O_NONBLOCK + a regular-file check on the opened fd: this reads the DEK, salt,
	// wrapped KEK and TPM blob, and a plain open of a FIFO planted at one of those
	// paths would block in open(2) until a writer appears, hanging boot or the CLI.
	f, err := SecureOpenBeneath(baseDir, filePath, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", filePath, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%q: %w", filePath, secretenv.ErrNotRegular)
	}
	return io.ReadAll(f)
}

// resolveInside joins and cleans baseDir/path and verifies the result stays
// inside baseDir, returning the validated absolute-ish clean path.
//
// The returned path is for error messages and logging only — callers that open the
// file MUST do so via SecureOpenBeneath, not by re-opening this returned string, for
// the same TOCTOU reason documented on isPathInsideBase.
func resolveInside(baseDir, path string) (string, error) {
	cleanPath := filepath.Clean(filepath.Join(baseDir, path))
	ok, err := isPathInsideBase(baseDir, cleanPath)
	if err != nil {
		return "", fmt.Errorf("path validation error: %w", err)
	}
	if !ok {
		return "", fmt.Errorf("access denied: file %q is outside of %q", cleanPath, baseDir)
	}
	return cleanPath, nil
}

// safeRelComponents cleans relPath and splits it into path components, rejecting
// anything absolute, empty, or containing a ".." component that could escape baseDir.
// This is a lexical check only — it never touches the filesystem. The actual
// containment guarantee against symlinks (including ones racily planted at an
// intermediate component) comes from SecureOpenBeneath's per-component O_NOFOLLOW
// walk below, not from this function.
func safeRelComponents(relPath string) ([]string, error) {
	if filepath.IsAbs(relPath) {
		return nil, fmt.Errorf("access denied: path %q must be relative", relPath)
	}
	clean := filepath.Clean(relPath)
	if clean == "." || clean == "" {
		return nil, fmt.Errorf("access denied: empty path")
	}
	parts := strings.Split(clean, string(os.PathSeparator))
	for _, p := range parts {
		if p == ".." || p == "" {
			return nil, fmt.Errorf("access denied: path %q escapes the base directory", relPath)
		}
	}
	return parts, nil
}

// SecureOpenBeneath opens (and, per flags, creates/truncates/appends) the file at
// baseDir/relPath, refusing to follow a symlink at ANY path component — not just the
// final one — with the actual open mode left to the caller.
//
// This is the shared WALK primitive underlying every write helper in this file
// (SecureWriteFile/SecureWriteFileSync use flags without O_EXCL; SecureCreateFile/
// SecureCreateFileSync/SecureCreateFileHandle add O_EXCL) — exported directly so a
// caller whose open-mode needs don't match either preset (a streaming writer that
// legitimately overwrites the same path on every run, an append-only log, an edit of a
// file that must already exist) still gets the full per-component symlink-safety walk
// instead of falling back to a plain os.OpenFile with only a final-component O_NOFOLLOW.
// internal/cli/secret/fix.go's applyFix/.env-append and internal/cli/encryption/
// migrate_provider.go's copyFile were originally downgraded to final-component-only
// protection specifically because O_EXCL didn't fit their semantics — conflating "which
// open flags" with "how much of the path gets walked safely" when the two are actually
// independent axes; all three now call this function directly with whatever flags fit
// them, rather than falling back to a weaker one-off.
//
// It walks relPath component-by-component using openat(2) (via golang.org/x/sys/unix)
// relative to the file descriptor of the directory opened for the PREVIOUS component,
// passing O_NOFOLLOW|O_DIRECTORY for every intermediate directory component and
// O_NOFOLLOW for the final (leaf) component. This closes the TOCTOU gap that a plain
// "validate path string, then os.OpenFile(path, ...O_NOFOLLOW)" leaves open:
//
//   - isPathInsideBase/resolveInside can only resolve symlinks up to the longest
//     EXISTING ancestor at the moment they run; a not-yet-existing intermediate
//     directory component is passed through unresolved.
//   - A plain O_NOFOLLOW on the final os.OpenFile call only protects the FINAL path
//     component — it does nothing to stop an attacker who, in the window between the
//     validation and that final open, plants a symlink at an INTERMEDIATE component
//     (one the containment check never resolved because it didn't exist yet).
//
// Once a component has been opened here, every subsequent step operates relative to
// that already-open file descriptor (openat), never by re-resolving the path string —
// so a symlink swapped in afterward at any already-traversed component cannot redirect
// anything: the fd is bound to the inode that was actually opened, not to a path. A
// symlink at a component not yet traversed is refused outright (ELOOP from O_NOFOLLOW)
// instead of being followed. This mirrors the O_NOFOLLOW-on-open pattern already used
// elsewhere in this file (SecureWriteFile, SecureWriteFileSync, FixFilePerms,
// SecureDeleteFile) and extends it to cover every path component, not just the last.
//
// It does not create missing intermediate directories (matching the pre-existing
// contract of SecureWriteFile/SecureWriteFileSync — callers create parent directories
// themselves); a missing intermediate component is simply an open error.
//
// Callers passing flags that include O_CREAT but not O_EXCL (e.g. a repeatable
// streaming write to a fixed path) still get the full walk but NOT the create-only
// guarantee — that tradeoff is the caller's to make explicitly, not a silent default.
func SecureOpenBeneath(baseDir, relPath string, flags int, perm os.FileMode) (*os.File, error) {
	parts, err := safeRelComponents(relPath)
	if err != nil {
		return nil, err
	}

	dirFd, err := unix.Open(baseDir, unix.O_DIRECTORY|unix.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("open base directory %q: %w", baseDir, err)
	}

	for _, component := range parts[:len(parts)-1] {
		childFd, oerr := unix.Openat(dirFd, component, unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_RDONLY, 0)
		_ = unix.Close(dirFd)
		if oerr != nil {
			if errors.Is(oerr, unix.ELOOP) {
				return nil, fmt.Errorf("access denied: path component %q of %q is a symlink", component, relPath)
			}
			return nil, fmt.Errorf("open path component %q of %q: %w", component, relPath, oerr)
		}
		dirFd = childFd
	}

	leaf := parts[len(parts)-1]
	fd, oerr := unix.Openat(dirFd, leaf, flags|unix.O_NOFOLLOW, uint32(perm))
	_ = unix.Close(dirFd)
	if oerr != nil {
		if errors.Is(oerr, unix.ELOOP) {
			return nil, fmt.Errorf("access denied: %q is a symlink", filepath.Join(baseDir, relPath))
		}
		return nil, oerr
	}

	return os.NewFile(uintptr(fd), filepath.Join(baseDir, relPath)), nil
}

// SecureWriteFile writes data to filepath.Join(baseDir, path), validating
// that the resolved path remains inside baseDir. The file mode is enforced
// even if the file pre-existed with a looser mode (O_CREATE|O_TRUNC alone
// only applies perm at creation time and leaves an existing file's mode
// untouched, so this Chmods explicitly after open — mirroring
// SecureWriteFileSync, minus the fsync). Callers writing durability-critical
// key material should prefer SecureWriteFileSync instead.
func SecureWriteFile(baseDir, path string, data []byte, perm os.FileMode) error {
	// resolveInside is a cheap pre-check that fails fast on an obviously-escaping path
	// (e.g. "../x") with a clear "access denied" error; the actual open — including the
	// symlink-safety guarantee — is performed by SecureOpenBeneath below. See both
	// functions' doc comments for why the pre-check alone is not sufficient.
	if _, err := resolveInside(baseDir, path); err != nil {
		return err
	}
	// SecureOpenBeneath refuses to traverse OR write THROUGH a symlink at any path
	// component, not just the final one (see its doc comment for the TOCTOU this
	// closes that a bare O_NOFOLLOW on the final open would miss).
	f, err := SecureOpenBeneath(baseDir, path, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC, perm) // #nosec G304 -- path validated inside baseDir by resolveInside + SecureOpenBeneath's per-component O_NOFOLLOW walk
	if err != nil {
		return err
	}
	// O_TRUNC keeps a pre-existing file's mode; force the intended perms.
	if cerr := f.Chmod(perm); cerr != nil {
		_ = f.Close()
		return cerr
	}
	if _, werr := f.Write(data); werr != nil {
		_ = f.Close()
		return werr
	}
	return f.Close()
}

// SecureWriteFileSync writes data like SecureWriteFile but fsyncs the file before
// returning, so the bytes are durable on disk rather than merely in the page
// cache. Use it for key material (DEK/KEK/salt) whose loss is unrecoverable: a
// non-durable write can be lost on power failure even after the call returns,
// which — combined with overwriting the previous key — risks orphaning all
// ciphertext. Pair it with SyncDir after any rename to make the rename durable
// too. The file mode is enforced even if the file pre-existed with a looser mode.
func SecureWriteFileSync(baseDir, path string, data []byte, perm os.FileMode) error {
	// See SecureWriteFile above: resolveInside is a fast lexical pre-check only; the
	// actual symlink-safe open (including intermediate path components, not just the
	// final one) is performed by SecureOpenBeneath.
	if _, err := resolveInside(baseDir, path); err != nil {
		return err
	}
	f, err := SecureOpenBeneath(baseDir, path, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC, perm) // #nosec G304 -- path validated inside baseDir by resolveInside + SecureOpenBeneath's per-component O_NOFOLLOW walk
	if err != nil {
		return err
	}
	// O_TRUNC keeps a pre-existing file's mode; force the intended perms.
	if cerr := f.Chmod(perm); cerr != nil {
		_ = f.Close()
		return cerr
	}
	if _, werr := f.Write(data); werr != nil {
		_ = f.Close()
		return werr
	}
	if serr := f.Sync(); serr != nil {
		_ = f.Close()
		return serr
	}
	return f.Close()
}

// SecureCreateFile writes data to a NEW file at filepath.Join(baseDir, path),
// combining the two strongest write protections found independently elsewhere in this
// codebase into one: SecureOpenBeneath's per-path-component O_NOFOLLOW walk (this
// package's existing SecureWriteFile/SecureWriteFileSync), plus O_EXCL (previously only
// in internal/cli/secret/export.go's createSecureOutputFile). O_EXCL makes the create
// atomic and refuses to write through — or truncate/overwrite — any pre-existing path,
// including one planted in the window between an earlier existence check and this call
// (the TOCTOU that a bare os.Stat-then-write leaves open). Unlike SecureWriteFile, this
// intentionally does NOT silently overwrite: it returns an error (wrapping O_EXCL's
// EEXIST) if path already exists. Callers that need overwrite-on-purpose (an explicit
// --force) should use SecureWriteFile/SecureWriteFileSync instead. The perm argument is
// Chmod'd explicitly after creation (in addition to being passed to the underlying
// open) so the intended mode is enforced even under a restrictive process umask.
func SecureCreateFile(baseDir, path string, data []byte, perm os.FileMode) error {
	f, err := secureCreateOpenBeneath(baseDir, path, perm)
	if err != nil {
		return err
	}
	if _, werr := f.Write(data); werr != nil {
		_ = f.Close()
		return werr
	}
	return f.Close()
}

// SecureCreateFileSync writes like SecureCreateFile but fsyncs before returning, for
// durability-critical material created for the first time (e.g. a freshly generated
// signing key) — mirroring SecureWriteFileSync's relationship to SecureWriteFile.
func SecureCreateFileSync(baseDir, path string, data []byte, perm os.FileMode) error {
	f, err := secureCreateOpenBeneath(baseDir, path, perm)
	if err != nil {
		return err
	}
	if _, werr := f.Write(data); werr != nil {
		_ = f.Close()
		return werr
	}
	if serr := f.Sync(); serr != nil {
		_ = f.Close()
		return serr
	}
	return f.Close()
}

// SecureCreateFileHandle opens a NEW file at baseDir/path for writing and returns the
// open *os.File, for callers that need to stream output (e.g. a CSV/JSON encoder or a
// tar writer) rather than write a single already-assembled []byte — see SecureCreateFile
// for the data-based variant this mirrors. The caller owns the returned file and must
// close it. Same O_EXCL + per-component-O_NOFOLLOW guarantee as SecureCreateFile: it
// refuses to create through a symlink at any path component and refuses to write
// through (or replace) a pre-existing path.
func SecureCreateFileHandle(baseDir, path string, perm os.FileMode) (*os.File, error) {
	return secureCreateOpenBeneath(baseDir, path, perm)
}

// secureCreateOpenBeneath is the shared implementation behind SecureCreateFile,
// SecureCreateFileSync, and SecureCreateFileHandle: resolveInside's fast lexical
// pre-check, then SecureOpenBeneath's per-component O_NOFOLLOW walk with O_EXCL added so
// the leaf open refuses a pre-existing path (regular file OR symlink) instead of
// silently truncating/following it. The explicit Chmod guards against a restrictive
// umask masking the requested perm at creation time (O_CREAT's mode argument is
// masked by umask, same reasoning SecureWriteFile documents for its own Chmod call).
func secureCreateOpenBeneath(baseDir, path string, perm os.FileMode) (*os.File, error) {
	if _, err := resolveInside(baseDir, path); err != nil {
		return nil, err
	}
	f, err := SecureOpenBeneath(baseDir, path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, perm) // #nosec G304 -- path validated inside baseDir by resolveInside + SecureOpenBeneath's per-component O_NOFOLLOW walk; O_EXCL refuses a pre-existing path
	if err != nil {
		return nil, err
	}
	if cerr := f.Chmod(perm); cerr != nil {
		_ = f.Close()
		return nil, cerr
	}
	return f, nil
}

// SyncDir fsyncs the directory dirPath so a preceding file create or rename
// within it is durable (the directory entry is flushed). On platforms where
// opening a directory for sync is unsupported the error is returned to the
// caller to decide; on Linux/macOS this is the standard create→fsync(file)→
// rename→fsync(dir) durability pattern.
func SyncDir(dirPath string) error {
	d, err := os.Open(dirPath) // #nosec G304 -- caller-controlled key directory, not network input
	if err != nil {
		return err
	}
	if serr := d.Sync(); serr != nil {
		_ = d.Close()
		return serr
	}
	return d.Close()
}

// SecureDeleteFile overwrites path with random bytes, then zeros, fsyncing after each
// pass, before unlinking it — a best-effort "shred" for key-material backups that
// should not linger recoverable on disk (e.g. a pre-migration wrapped-DEK backup, whose
// plaintext-after-unwrap is byte-identical to the DEK still in active use). This is NOT
// a guarantee on copy-on-write filesystems, SSDs with wear-leveling, or any snapshotted/
// replicated storage — those may retain the original blocks regardless of what gets
// written to the logical file — but it's strictly better than a plain unlink, and is the
// same caveat any shred(1)-style tool carries.
func SecureDeleteFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	size := info.Size()

	// #G26: every other write primitive in this file (SecureWriteFile,
	// SecureWriteFileSync, FixFilePerms) opens with O_NOFOLLOW; this one didn't — a
	// symlink at path (planted after the Stat above, or simply never checked for) would
	// have this shred-then-unlink through it to the symlink's target, overwriting an
	// arbitrary file the process can write to with random-then-zero bytes. os.Remove
	// below still only unlinks the symlink itself, never touching the shredded target —
	// so without O_NOFOLLOW this destroys arbitrary file content while leaving no trace
	// at the expected path.
	f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NOFOLLOW, 0) // #nosec G304 -- caller-controlled key-backup path, not network input
	if err != nil {
		return err
	}
	overwrite := func(pattern func([]byte) error) error {
		buf := make([]byte, size)
		if err := pattern(buf); err != nil {
			return err
		}
		if _, err := f.WriteAt(buf, 0); err != nil {
			return err
		}
		return f.Sync()
	}
	if err := overwrite(func(b []byte) error { _, err := rand.Read(b); return err }); err != nil {
		_ = f.Close()
		return fmt.Errorf("shred pass (random) failed: %w", err)
	}
	if err := overwrite(func(b []byte) error { return nil /* buf is already zero-valued */ }); err != nil {
		_ = f.Close()
		return fmt.Errorf("shred pass (zero) failed: %w", err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return SyncDir(filepath.Dir(path))
}

// unixOctalMode renders m in conventional Unix chmod notation (e.g. "4600" for
// setuid+rw-------), rather than Go's raw %o formatting of os.FileMode, which
// packs the special bits far above bit 8 and prints as a number no operator
// would recognize (e.g. "40000600").
func unixOctalMode(m os.FileMode) string {
	special := 0
	if m&os.ModeSetuid != 0 {
		special |= 4
	}
	if m&os.ModeSetgid != 0 {
		special |= 2
	}
	if m&os.ModeSticky != 0 {
		special |= 1
	}
	if special == 0 {
		return fmt.Sprintf("%o", m.Perm())
	}
	return fmt.Sprintf("%o%03o", special, m.Perm())
}

// FixFilePerms verifies file permissions and ownership.
// If autofix=true, it will attempt to correct any mismatches.
func FixFilePerms(files []FilePermSpec, autofix bool) error { // NOSONAR -- cognitive complexity 33, suppress go:S3776
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("cannot get current user: %w", err)
	}
	currentUID, _ := strconv.Atoi(currentUser.Uid)

	hasWarnings := false // a mismatch was found (fixed or not)
	unresolved := false  // a problem REMAINS — stat/chmod/chown failed, so autofix didn't help
	// issues is every problem that remains, in the words of the [WARN]/[ERROR] line
	// printed for it: the returned error carries them, so a caller that refuses on it
	// (server start-up) says WHY, not only that the audit failed (BOOT-REFUSALS-1).
	var issues []string

	for _, f := range files {
		// Open with O_NOFOLLOW so a symlink at the final path component is refused
		// (ELOOP) rather than followed. This replaces a prior Lstat-then-Chmod/Chown-
		// by-path design: Lstat correctly detected a symlink up front, but the
		// subsequent os.Chmod(f.Path, ...) / os.Chown(f.Path, ...) calls re-resolved
		// the path and FOLLOW a final-component symlink, leaving a TOCTOU window
		// between the check and the fix — a symlink swapped in after Lstat (or simply
		// never seen by it, e.g. a race with a concurrent attacker) would redirect the
		// chmod/chown to an arbitrary target (an arbitrary chown when running as
		// root). Operating on the returned *os.File's Chmod/Chown (fd-based, not
		// path-based) closes that window: the fd stays bound to the exact inode
		// opened here, immune to the path being swapped out from under us afterward —
		// mirrors SecureWriteFile/SecureWriteFileSync in this file.
		//
		// secretenv.OpenRegular adds O_NONBLOCK and refuses a non-regular file on the
		// opened fd: a FIFO planted at a key-file path must not hang startup here.
		file, info, err := secretenv.OpenRegular(f.Path, syscall.O_NOFOLLOW)
		if err != nil {
			if errors.Is(err, syscall.ELOOP) {
				fmt.Printf("[WARN] Refusing to fix %s: it is a symlink (won't follow it to an arbitrary target)\n", f.Path)
				issues = append(issues, fmt.Sprintf("%s is a symlink (not followed)", f.Path))
			} else {
				fmt.Printf("[WARN] Cannot open file %s: %v\n", f.Path, err)
				issues = append(issues, fmt.Sprintf("cannot open %s (%v)", f.Path, unwrapPathErr(err)))
			}
			hasWarnings = true
			unresolved = true
			continue
		}

		// Check permissions. info.Mode().Perm() masks to only the low 9 rwx bits,
		// silently dropping any setuid/setgid/sticky bits — a file whose low 9 bits
		// already match f.Mode but ALSO carries one of those special bits would
		// otherwise compare equal and never get chmod'd, leaving the special bit in
		// place through a pass whose entire purpose is to lock these files down.
		// Check for it explicitly so it's caught (and, via the unconditional
		// file.Chmod(f.Mode) below, cleared — f.Mode never carries these bits itself).
		actualMode := info.Mode().Perm()
		hasSpecialBits := info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0
		if actualMode != f.Mode || hasSpecialBits {
			msg := fmt.Sprintf("File %s has mode %s but expected %o", f.Path, unixOctalMode(info.Mode()), f.Mode)
			hasWarnings = true
			if autofix {
				if err := file.Chmod(f.Mode); err != nil {
					fmt.Printf("[ERROR] Failed to chmod %s: %v\n", f.Path, err)
					issues = append(issues, fmt.Sprintf("%s (chmod failed: %v)", msg, unwrapPathErr(err)))
					unresolved = true
				} else {
					fmt.Printf("[FIXED] %s\n", msg)
				}
			} else {
				fmt.Printf("[WARN] %s\n", msg)
				issues = append(issues, msg)
			}
		}

		// Check ownership
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			fmt.Printf("[WARN] Cannot get stat_t for %s\n", f.Path)
			issues = append(issues, fmt.Sprintf("cannot read the owner of %s", f.Path))
			hasWarnings = true
			unresolved = true
			_ = file.Close()
			continue
		}

		fileUID := int(stat.Uid)
		if fileUID != currentUID {
			msg := fmt.Sprintf("File %s is owned by uid %d, expected uid %d", f.Path, fileUID, currentUID)
			hasWarnings = true
			if autofix {
				if err := file.Chown(currentUID, int(stat.Gid)); err != nil {
					fmt.Printf("[ERROR] Failed to chown %s: %v\n", f.Path, err)
					issues = append(issues, fmt.Sprintf("%s (chown failed: %v)", msg, unwrapPathErr(err)))
					unresolved = true
				} else {
					fmt.Printf("[FIXED] %s\n", msg)
				}
			} else {
				fmt.Printf("[WARN] %s\n", msg)
				issues = append(issues, msg)
			}
		}

		_ = file.Close()
	}

	// Fail closed when a problem remains: either autofix was off and a mismatch exists,
	// or autofix was on but a chmod/chown/stat FAILED (so the insecure state persists).
	// The previous `hasWarnings && !autofix` form silently returned nil when autofix
	// couldn't actually lock a world-readable key file down.
	if unresolved || (hasWarnings && !autofix) {
		return fmt.Errorf("permissions or ownership audit found unresolved issues: %s", strings.Join(issues, "; "))
	}

	return nil
}

// unwrapPathErr drops the "op path:" prefix of an *os.PathError (the caller names
// the path already), leaving e.g. "no such file or directory".
func unwrapPathErr(err error) error {
	if pe, ok := errors.AsType[*os.PathError](err); ok {
		return pe.Err
	}
	return err
}
