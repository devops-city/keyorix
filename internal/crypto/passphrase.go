package crypto

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/keyorixhq/keyorix/internal/secretenv"
)

// PassphraseSource selects where the master passphrase is read from. Exactly
// one of FD/FilePath/Stdin is normally set (callers that expose these as CLI
// flags should mark them mutually exclusive); if more than one is set, FD
// wins, then FilePath, then Stdin. If none are set, ResolvePassphrase falls
// back to the environment variable named by its envVarName argument.
//
// All three byte-based sources exist because a value handed to a process as
// an environment variable is structurally different from one read as bytes:
// an env var is a Go string from the moment os.Getenv returns it — strings
// are immutable in Go and cannot be wiped — and it persists in the process's
// own environment block for the process's whole lifetime, visible to
// anything that can read /proc/PID/environ. A value read from a file
// descriptor, file, or stdin arrives as a []byte that the caller can wipe
// once it has been consumed, and never touches the process environment at
// all.
type PassphraseSource struct {
	// FD is an already-open file descriptor to read the passphrase from
	// until EOF, honored only when FDSet is true. The strongest option: the
	// value never appears in argv, an env var, or a file on disk that this
	// process has to open by path. The usual answer for systemd's
	// LoadCredential= (the unit's ExecStart redirects the credential file to
	// an inherited fd; see docs/adr-099-master-passphrase-sourcing.md for a
	// worked example).
	FD int
	// FDSet reports whether FD was actually provided (e.g. --passphrase-fd
	// explicitly passed), as opposed to FD merely holding its zero value.
	// This distinction matters because 0 (stdin) is itself a legitimate,
	// deliberate fd choice — an earlier version of this check used `FD > 0`,
	// which silently treated an explicit `--passphrase-fd=0` identically to
	// "the flag was never passed" and fell through to the weakest source
	// (the environment variable) with no error or warning.
	FDSet bool
	// FilePath, if non-empty, is a file to read the passphrase from. Refused
	// if the file is group- or world-readable (mode & 0o077 != 0) — a
	// passphrase file readable by anyone but its owner defeats the point of
	// keeping the passphrase out of the environment.
	FilePath string
	// Stdin, if true, reads the passphrase from stdin: with no echo via
	// golang.org/x/term when stdin is an interactive terminal (matching
	// every other secret-value prompt in this CLI — see
	// internal/cli/secret/create.go and siblings), or a raw read until EOF
	// when stdin is piped/redirected.
	Stdin bool
}

// ResolvePassphrase returns the master passphrase as a byte slice the caller
// must wipe (WipeBytes) once it has been consumed, sourced per src's
// precedence (FD, then FilePath, then Stdin), or from the envVarName
// environment variable as the last-resort fallback -- the weakest option,
// documented on PassphraseSource, kept working for backward compatibility.
// A trailing newline is trimmed from file/fd/stdin sources and from
// <envVarName>_FILE (the common case of a passphrase file created with `echo` or
// `printf ... > file`); the environment variable itself is whitespace-trimmed,
// matching this codebase's pre-existing behavior.
func ResolvePassphrase(src PassphraseSource, envVarName string) ([]byte, error) {
	switch {
	case src.FDSet:
		return readPassphraseFD(src.FD)
	case src.FilePath != "":
		return readPassphraseFile(src.FilePath)
	case src.Stdin:
		return readPassphraseStdin()
	}
	// The environment fallback also accepts <envVarName>_FILE (a mounted secret
	// file); setting both, or an unreadable file, is an error, not a precedence.
	// The master passphrase is key material, so the file is held to the same rule
	// as --passphrase-file (secretenv.CheckPermissions: 0600/0400, with the one
	// orchestrator-mount exception) on every path that resolves it -- server, CLI
	// and admin commands alike -- and a file that is too open is refused outright.
	raw, found, err := secretenv.LookupChecked(envVarName)
	if err != nil {
		return nil, err
	}
	v := raw
	if os.Getenv(envVarName+secretenv.FileSuffix) == "" {
		// Environment value: whitespace-trimmed, as before. A file value is NOT
		// whitespace-trimmed -- exactly one trailing newline is stripped, the same
		// bytes --passphrase-file yields -- so both sources derive the same KEK.
		v = strings.TrimSpace(raw)
	}
	if !found || v == "" {
		return nil, fmt.Errorf("%s is not set (and no --passphrase-fd/--passphrase-file/--passphrase-stdin was given; %s%s works too)", envVarName, envVarName, secretenv.FileSuffix)
	}
	return []byte(v), nil
}

func readPassphraseFD(fd int) ([]byte, error) {
	f := os.NewFile(uintptr(fd), "passphrase-fd")
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("reading --passphrase-fd %d: %w", fd, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("--passphrase-fd %d produced no data", fd)
	}
	return trimTrailingNewline(data), nil
}

// readPassphraseFile mirrors internal/securefiles' TOCTOU-safe pattern: open
// with O_NOFOLLOW (refuse a symlink rather than follow it to an arbitrary
// target) and check permissions via fstat on the SAME fd used to read, so
// there is no window between the permission check and the read for the file
// to be swapped out from under it.
func readPassphraseFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) // #nosec G304 -- operator-configured trusted path (--passphrase-file), O_NOFOLLOW + permission-checked below
	if err != nil {
		return nil, fmt.Errorf("opening --passphrase-file %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat --passphrase-file %q: %w", path, err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("--passphrase-file %q is group- or world-readable (mode %04o) -- refusing to read it; chmod 600 the file", path, info.Mode().Perm())
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("reading --passphrase-file %q: %w", path, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("--passphrase-file %q is empty", path)
	}
	return trimTrailingNewline(data), nil
}

func readPassphraseStdin() ([]byte, error) {
	// os.Stdin.Fd(), not the hardcoded syscall.Stdin constant, so a caller
	// (or a test) that reassigns the os.Stdin package var gets consistent
	// behavior between the terminal check and the actual read below.
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, "Master passphrase: ")
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("reading passphrase from terminal: %w", err)
		}
		if len(b) == 0 {
			return nil, fmt.Errorf("no passphrase entered")
		}
		return b, nil
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("reading passphrase from stdin: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("stdin produced no data")
	}
	return trimTrailingNewline(data), nil
}

func trimTrailingNewline(b []byte) []byte {
	b = bytes.TrimSuffix(b, []byte("\n"))
	b = bytes.TrimSuffix(b, []byte("\r"))
	return b
}

// WipeBytes overwrites b with zeros in place. Exported for callers outside
// this package that resolve a passphrase via ResolvePassphrase and must wipe
// it once consumed (key derivation only reads a passphrase once; the byte
// slice itself has no reason to outlive that read).
func WipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
