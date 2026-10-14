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
//   - the file's mode is judged on the opened descriptor: 0600/0400, or -- for a
//     file an orchestrator mounted, i.e. not owned by the running user -- group-read
//     (0440/0640) when the file's group is one the process holds (fsGroup,
//     group_add). Anything for "other", group-write and setuid/setgid/sticky are
//     always refused.
//   - neither the value nor the contents ever appear in an error.
package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"syscall"

	"github.com/keyorixhq/keyorix/cli/internal/regularfile"
)

const maxSecretFileSize = 1 << 20

// Test seams for the process identity the group rule compares against.
var (
	secretFileProcessUID    = os.Geteuid
	secretFileProcessGroups = func() []int {
		gs, _ := os.Getgroups()
		return append(gs, os.Getegid())
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
		return "", false, fmt.Errorf("both %s and %s are set; set exactly one", name, fileVar)
	case path != "":
		v, err := readCheckedSecretFile(path)
		if err != nil {
			return "", false, fmt.Errorf("%s=%q: %w", fileVar, path, err)
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
			return "", err
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
		return fmt.Errorf("secret file mode %04o is too open (%s) -- refusing to trust it; chmod 0600/0400, or mount it owned by another user (e.g. root) with a group the process belongs to and mode 0440", perm, why)
	}
	switch {
	case mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0:
		return bad("setuid/setgid/sticky bit")
	case perm&0o007 != 0:
		return bad("accessible to other users")
	case perm&0o020 != 0:
		return bad("writable by its group")
	case perm&0o050 == 0:
		return nil
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return bad("group-readable and its owner cannot be determined")
	}
	if int(st.Uid) == secretFileProcessUID() {
		return bad("group-readable but owned by the running user")
	}
	if slices.Contains(secretFileProcessGroups(), int(st.Gid)) {
		return nil
	}
	return bad("group-readable by a group the process does not belong to")
}
