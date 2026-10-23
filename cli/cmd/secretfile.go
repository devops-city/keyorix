// secretfile.go resolves a credential that may be given as NAME or as NAME_FILE
// (the Docker-secrets / Kubernetes-Secret-volume convention), for the two
// credentials `system init` takes from the environment.
//
// This is deliberately a small copy of internal/secretenv's rules, not an import:
// this module must not depend on the main module (ADR-108 Decision A, enforced by
// cli/internal/depguard). Keep the two in step:
//   - NAME_FILE set -> read the file, strip ONE trailing "\n", "\r\n" or "\r".
//   - NAME and NAME_FILE both set -> error (no precedence).
//   - unreadable / empty / not a regular file (a FIFO is refused, not waited on) /
//     over 1 MiB -> error; never a fallback to NAME or a prompt.
//   - the file's mode and owner are judged on the opened descriptor: owned by the
//     running user or root (#3393: any other owner can rewrite it), and 0600/0400,
//     or -- for a root-owned file an orchestrator mounted -- group-read (0440/0640)
//     when the file's group is one the process holds (fsGroup, group_add).
//     Anything for "other", group-write and setuid/setgid/sticky are always refused.
//   - internal/secretenv/testdata/permission-matrix.tsv is the rule as a table;
//     TestLookupSecretEnv_PermissionMatrix holds this copy to it.
//   - neither the value nor the contents ever appear in an error, and the path
//     only through describeSecretFile: a relative NAME_FILE is not shown, it may
//     be the secret itself (internal/secretenv.DescribeFile, SECRETENV-REVIEW-1 F4).
package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/keyorixhq/keyorix/cli/internal/regularfile"
)

const maxSecretFileSize = 1 << 20

// Test seams for the process identity the owner and group rules compare
// against, and for the owner a file reports (a test cannot chown to root).
var (
	secretFileProcessUID    = os.Geteuid
	secretFileProcessGroups = func() []int {
		gs, _ := os.Getgroups()
		return append(gs, os.Getegid())
	}
	secretFileOwner = func(info os.FileInfo) (uid, gid int, ok bool) {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return 0, 0, false
		}
		return int(st.Uid), int(st.Gid), true
	}
)

// lookupSecretEnv returns the value of name or of the file named by name_FILE;
// found is false when neither is set.
func lookupSecretEnv(name string) (value string, found bool, err error) {
	direct := os.Getenv(name)
	fileVar := name + "_FILE"
	path := os.Getenv(fileVar)
	switch {
	case direct != "" && path != "":
		return "", false, usageErrorf("both %s and %s are set; set exactly one", name, fileVar)
	case path != "":
		v, err := readCheckedSecretFile(path)
		if err != nil {
			return "", false, fmt.Errorf("%s: %w", describeSecretFile(fileVar, path), err)
		}
		return v, true, nil
	case direct != "":
		return direct, true, nil
	}
	return "", false, nil
}

func readCheckedSecretFile(path string) (string, error) {
	// regularfile.Open opens with O_NONBLOCK (a plain open(2) of a FIFO blocks until a
	// writer appears) and refuses a non-regular file on the opened descriptor.
	f, info, err := regularfile.Open("secret file", path)
	if err != nil {
		if errors.Is(err, regularfile.ErrNotRegular) {
			// regularfile's message carries the path; the caller names the file
			// through describeSecretFile instead (a relative path is not shown).
			return "", fmt.Errorf("secret file is %w", regularfile.ErrNotRegular)
		}
		return "", fmt.Errorf("cannot open secret file: %w", unwrapSecretPathError(err))
	}
	defer func() { _ = f.Close() }()
	if err := checkSecretFileMode(info); err != nil {
		return "", err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSecretFileSize+1))
	if err != nil {
		return "", fmt.Errorf("cannot read secret file: %w", unwrapSecretPathError(err))
	}
	if len(data) > maxSecretFileSize {
		return "", fmt.Errorf("secret file is too large (limit %d bytes)", maxSecretFileSize)
	}
	// One "\n", then one "\r": the server's rule (internal/secretenv) and
	// --passphrase-file's.
	v := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if v == "" {
		return "", fmt.Errorf("secret file is empty")
	}
	return v, nil
}

// relativeSecretPathNotShown and describeSecretFile copy
// internal/secretenv.RelativePathNotShown and DescribeFile for NAME_FILE labels;
// TestDescribeSecretFile_MatchesSecretenv holds the text to the server's.
const relativeSecretPathNotShown = "a relative path, not shown: it may be the secret itself"

// describeSecretFile names the file fileVar points at for an error: NAME_FILE="/abs"
// or, for a relative path, NAME_FILE (a relative path, not shown: ...). It is the
// only way lookupSecretEnv's errors name the path.
func describeSecretFile(fileVar, path string) string {
	if !filepath.IsAbs(path) {
		return fileVar + " (" + relativeSecretPathNotShown + ")"
	}
	return fmt.Sprintf("%s=%q", fileVar, path)
}

func unwrapSecretPathError(err error) error {
	if pe, ok := err.(*os.PathError); ok {
		return pe.Err
	}
	return err
}

func checkSecretFileMode(info os.FileInfo) error {
	mode := info.Mode()
	perm := mode.Perm()
	bad := func(why string) error {
		return fmt.Errorf("secret file mode %04o is too open (%s) -- refusing to trust it; chmod 0600/0400, or mount it owned by root with a group the process belongs to and mode 0440", perm, why)
	}
	switch {
	case mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0:
		return bad("setuid/setgid/sticky bit")
	case perm&0o007 != 0:
		return bad("accessible to other users")
	case perm&0o020 != 0:
		return bad("writable by its group")
	}
	// Owner (#3393, internal/secretenv.CheckOwner): whoever owns the file can chmod
	// and rewrite it, so it must be the running user or root, whatever the mode.
	uid, gid, ok := secretFileOwner(info)
	if !ok {
		return errors.New("secret file owner cannot be determined -- refusing to trust it")
	}
	euid := secretFileProcessUID()
	if uid != euid && uid != 0 {
		return fmt.Errorf("secret file is owned by uid %d, which is neither the running user (uid %d) nor root -- refusing to trust it (that account can replace the file); chown it to root, keeping the group the process reads it through, or to uid %d", uid, euid, euid)
	}
	if perm&0o050 == 0 {
		return nil
	}
	// Group-readable: only a root-owned (orchestrator) file with a group we hold.
	if uid == euid {
		return bad("group-readable but owned by the running user")
	}
	if slices.Contains(secretFileProcessGroups(), gid) {
		return nil
	}
	return bad("group-readable by a group the process does not belong to")
}
