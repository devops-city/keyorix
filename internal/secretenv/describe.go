package secretenv

import (
	"fmt"
	"path/filepath"
)

// RelativePathNotShown replaces a relative secret-file path in every error.
//
// Why (SECRETENV-REVIEW-1 F4, Andrei's decision secretenv-relative-file-path-echo,
// option a): an operator who puts the secret itself into X_FILE
// (KEYORIX_DB_PASSWORD_FILE=hunter2) gets "no such file" -- and the error used to
// print the value, so the secret landed in the boot log. A relative X_FILE keeps
// working (quickstarts use KEYORIX_TOKEN_FILE=./token); only its echo goes. An
// absolute path cannot be a mistyped secret in practice and stays visible, because
// it is what the operator needs to fix the mount.
const RelativePathNotShown = "a relative path, not shown: it may be the secret itself"

// DescribeFile names a secret file for an error message. It is the one formatter
// for a secret-file path: every error in this package that concerns an X_FILE
// value or a secret file goes through it, and so do the callers outside it
// (internal/config, internal/crypto, cmd/keyorix-k8s-sync). label is the variable
// (KEYORIX_DB_PASSWORD_FILE), a config key (server.http.metrics_token_file) or a
// noun ("secret file").
//
//	DescribeFile("KEYORIX_DB_PASSWORD_FILE", "/run/secrets/db") -> KEYORIX_DB_PASSWORD_FILE="/run/secrets/db"
//	DescribeFile("KEYORIX_DB_PASSWORD_FILE", "hunter2")         -> KEYORIX_DB_PASSWORD_FILE (a relative path, not shown: it may be the secret itself)
//	DescribeFile("secret file", "/run/secrets/db")              -> secret file "/run/secrets/db"
//
// The cli module (cli/cmd/secretfile.go describeSecretFile) and
// server/entrypoint.sh (_rs_describe) carry copies; TestDescribeFileCopiesAgree
// and the relative-sentinel tests hold them to the same text.
//
// Guards: TestSecretFileEnvReadsGoThroughSecretenv (no *_FILE value is read
// outside this package except to compare it with "") and
// TestRelativeFileValueNeverEchoed (every *_FILE variable, every failure mode).
func DescribeFile(label, path string) string {
	sep := " "
	if isEnvName(label) {
		sep = "="
	}
	if !filepath.IsAbs(path) {
		return label + " (" + RelativePathNotShown + ")"
	}
	return label + sep + fmt.Sprintf("%q", path)
}

// isEnvName reports whether label looks like an environment variable name
// (KEYORIX_DB_PASSWORD_FILE), which is written NAME="path" like a shell
// assignment; anything else is written label "path".
func isEnvName(label string) bool {
	if label == "" {
		return false
	}
	for _, r := range label {
		if (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

// FileError is a failure to use the secret file named by Label. Its message is
// DescribeFile(Label, path) + ": " + Err, so a relative path never appears in
// it; the path itself is unexported and only reachable through the formatter.
type FileError struct {
	Label string
	path  string
	Err   error
}

func (e *FileError) Error() string { return DescribeFile(e.Label, e.path) + ": " + e.Err.Error() }

func (e *FileError) Unwrap() error { return e.Err }

// NewFileError wraps err with the description of the secret file label/path.
func NewFileError(label, path string, err error) error {
	return &FileError{Label: label, path: path, Err: err}
}
