// Package secretenv resolves a secret that may be supplied either directly in
// an environment variable (X) or as the path of a file holding it (X_FILE) --
// the Docker-secrets / Kubernetes-Secret-volume convention.
//
// Why: a value in the environment is visible in `docker inspect`, in
// /proc/<pid>/environ and in every child process. A file mounted from a
// secrets store is not.
//
// Rules (Andrei, DEPLOY-2 decision 1):
//   - X_FILE set  -> read the file, strip ONE trailing line terminator.
//   - X and X_FILE both set -> error. No silent precedence: an operator who
//     set both has a deployment in an unknown state.
//   - X_FILE set but unreadable / empty / not a regular file -> error. Never
//     fall back to X or to a config-file value.
//   - Neither the value nor the file contents appear in any error or log line;
//     errors name the variable and the path only.
//   - Permissions: Lookup leaves the policy to the caller (CheckPermissions plus
//     the warn-or-refuse matrix); LookupChecked -- used for key material -- judges
//     the mode on the opened descriptor and always refuses a file that is too open.
//
// An empty variable counts as unset (`X=${X:-}` passthrough in compose files
// is common, and the pre-existing resolvers already treated "" as unset).
package secretenv

import (
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

// FileSuffix is appended to a variable name to form its file-variant.
const FileSuffix = "_FILE"

// maxSecretFileSize bounds what Lookup will read. No legitimate secret in this
// product is larger; the cap stops a mis-pointed X_FILE (a log, a device) from
// being slurped into memory.
const maxSecretFileSize = 1 << 20

// Lookup resolves the secret called name.
//
//   - found=false, err=nil: neither name nor name_FILE is set; the caller may
//     use its own fallback (e.g. a config-file value).
//   - err != nil: the configuration is wrong; the caller must refuse to start
//     (or return an empty secret, never a fallback).
func Lookup(name string) (value string, found bool, err error) {
	return lookup(name, false)
}

// LookupChecked is Lookup for key material (master password, KEK, Shamir share,
// admin credentials): when the secret comes from a file, the file's permissions
// are judged by the same rule as CheckPermissions -- on the very descriptor that
// is then read, so the file cannot be swapped between the check and the read --
// and a file that is too open is an error, never a warning. There is no override:
// callers that need the warn-or-refuse matrix of security.enable_file_permission_check
// use Lookup and run CheckPermissions themselves.
func LookupChecked(name string) (value string, found bool, err error) {
	return lookup(name, true)
}

func lookup(name string, checkPerms bool) (value string, found bool, err error) {
	direct := os.Getenv(name)
	fileVar := name + FileSuffix
	path := os.Getenv(fileVar)

	switch {
	case direct != "" && path != "":
		return "", false, fmt.Errorf("both %s and %s are set; set exactly one (the secret may come from the environment or from a file, never both)", name, fileVar)
	case path != "":
		v, err := readSecretFile(path, checkPerms)
		if err != nil {
			return "", false, fmt.Errorf("%s=%q: %w", fileVar, path, err)
		}
		return v, true, nil
	case direct != "":
		return direct, true, nil
	}
	return "", false, nil
}

// FilePaths returns the paths named by the <name>_FILE variables that are set
// (non-empty), in argument order. Startup uses it to run the file-permission
// check over the secret files.
func FilePaths(names ...string) []string {
	var out []string
	for _, n := range names {
		if p := os.Getenv(n + FileSuffix); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ReadFile reads a secret file named by a config key (e.g.
// server.http.metrics_token_file) under the same rules as an X_FILE variable:
// regular file, size-capped, one trailing line terminator stripped, empty is an
// error, and errors never carry the contents. Like Lookup, it does not judge
// permissions itself: the file is listed in the config's SecretFilePaths and the
// startup check (security.enable_file_permission_check) covers it.
func ReadFile(path string) (string, error) {
	return readSecretFile(path, false)
}

func readSecretFile(path string, checkPerms bool) (string, error) {
	// Symlinks are followed on purpose: a Kubernetes Secret volume exposes each
	// key as a symlink into the kubelet's ..data/ directory. The permission
	// check (CheckPermissions) stats the target, so a symlink cannot be used to
	// launder a loose file.
	// #nosec G304 G703 -- path is the operator's own X_FILE setting (process environment,
	// not network input); the file must be a regular file and is size-capped below.
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("cannot open secret file: %w", unwrapPathError(err))
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("cannot stat secret file: %w", unwrapPathError(err))
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("secret file is not a regular file")
	}
	if checkPerms {
		if err := checkInfo(info); err != nil {
			return "", err
		}
	}
	if info.Size() > maxSecretFileSize {
		return "", fmt.Errorf("secret file is too large (%d bytes, limit %d)", info.Size(), maxSecretFileSize)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSecretFileSize+1))
	if err != nil {
		return "", fmt.Errorf("cannot read secret file: %w", unwrapPathError(err))
	}
	if len(data) > maxSecretFileSize {
		return "", fmt.Errorf("secret file is too large (limit %d bytes)", maxSecretFileSize)
	}
	v := trimOneTerminator(string(data))
	if v == "" {
		return "", fmt.Errorf("secret file is empty")
	}
	return v, nil
}

// trimOneTerminator strips one trailing "\n", then one trailing "\r": a "\n",
// "\r\n" or lone "\r" terminator. That is exactly what --passphrase-file strips
// (internal/crypto/passphrase.go), so KEYORIX_MASTER_PASSWORD_FILE and
// --passphrase-file derive the same KEK from the same file.
func trimOneTerminator(s string) string {
	return strings.TrimSuffix(strings.TrimSuffix(s, "\n"), "\r")
}

// unwrapPathError drops the path prefix os errors carry (the caller already
// names the path) so the message reads "...: permission denied".
func unwrapPathError(err error) error {
	if pe, ok := err.(*os.PathError); ok {
		return pe.Err
	}
	return err
}

// Test seams for the process identity the group rule compares against.
var (
	processUID    = os.Geteuid
	processGroups = func() []int {
		gs, _ := os.Getgroups()
		return append(gs, os.Getegid())
	}
)

// CheckPermissions applies the key-material permission policy to a secret
// file. The rule is the one the KEK file and --passphrase-file already follow
// (nothing for group or other: 0600 / 0400), with exactly one exception for
// orchestrator-mounted secrets: a file that is NOT owned by the running user
// may be group-readable (0440 / 0640 minus the write bit) when its group is one
// the process belongs to. That is what a Kubernetes Secret volume looks like
// with fsGroup set (the kubelet makes the files root-owned, group = fsGroup, and
// ORs in group-read even when defaultMode is 0400) and what a Docker secret
// looks like with group_add. A file owned by the running user must be exactly
// 0600 / 0400: nothing but the owner has a reason to read it.
//
// Always refused: any access for "other", group write, setuid/setgid/sticky.
// The path is stat'd through symlinks (the Kubernetes layout), so the target's
// mode is what is judged.
func CheckPermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("secret file %q: %w", path, unwrapPathError(err))
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("secret file %q is not a regular file", path)
	}
	if err := checkInfo(info); err != nil {
		return fmt.Errorf("secret file %q: %w", path, err)
	}
	return nil
}

func checkInfo(info os.FileInfo) error {
	mode := info.Mode()
	perm := mode.Perm()
	bad := func(why string) error {
		return fmt.Errorf("mode %04o is too open (%s) -- refusing to trust it; chmod 0600/0400, or mount it from the orchestrator owned by another user (e.g. root) with a group the process belongs to (fsGroup / group_add) and mode 0440", perm, why)
	}
	if mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return bad("setuid/setgid/sticky bit")
	}
	if perm&0o007 != 0 {
		return bad("accessible to other users")
	}
	if perm&0o020 != 0 {
		return bad("writable by its group")
	}
	if perm&0o050 == 0 {
		return nil
	}
	// Group-readable: only an orchestrator-owned file with a group we hold.
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return bad("group-readable and its owner cannot be determined")
	}
	if int(st.Uid) == processUID() {
		return bad("group-readable but owned by the running user")
	}
	for _, g := range processGroups() {
		if int(st.Gid) == g {
			return nil
		}
	}
	return bad("group-readable by a group the process does not belong to")
}
