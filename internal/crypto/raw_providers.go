package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/keyorixhq/keyorix/internal/secretenv"
)

// decodeKeyMaterial accepts a 32-byte KEK supplied as raw bytes, hex, or base64
// (standard or raw, with or without padding) and returns the 32 raw bytes. This
// lets operators provide a KEK however their secret store emits it.
func decodeKeyMaterial(material []byte, providerName string) ([]byte, error) {
	// Already raw 32 bytes.
	if len(material) == KEKSize {
		return validateKEK(material, providerName)
	}
	s := strings.TrimSpace(string(material))
	// Hex (64 chars for 32 bytes). Decoded key material is validated (e.g. all-zero
	// rejected) exactly like the raw branch — the guard must not be skippable by
	// supplying the KEK in an encoded form (a zeroed/placeholder mounted secret can
	// arrive hex- or base64-encoded just as easily as raw).
	if b, err := hex.DecodeString(s); err == nil && len(b) == KEKSize {
		return validateKEK(b, providerName)
	}
	// Base64 — try standard then raw (unpadded), both URL-safe-tolerant.
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == KEKSize {
			return validateKEK(b, providerName)
		}
	}
	return nil, fmt.Errorf("%s key provider: key material must be 32 raw bytes, or hex/base64 encoding thereof (got %d bytes that did not decode to %d)", providerName, len(material), KEKSize)
}

// FileKeyProvider reads the KEK from a file — typically a path backed by a mounted
// Kubernetes/CSI secret, a sealed/SOPS-decrypted file, or a KMS sidecar. The path
// is operator-configured and trusted (read directly, not through the baseDir
// traversal guard, so absolute paths like /etc/keyorix/kek.key work).
type FileKeyProvider struct {
	path string
}

func NewFileKeyProvider(path string) *FileKeyProvider { return &FileKeyProvider{path: path} }

func (p *FileKeyProvider) Name() string { return "file" }

func (p *FileKeyProvider) KEK() ([]byte, error) {
	if p.path == "" {
		return nil, fmt.Errorf("file key provider: file_path is required")
	}
	// Reject a group-/world-readable (or -writable) KEK file before ever trusting its
	// contents. Mirrors the mode-bit threshold server/main.go's enforceKeyFilePermissions
	// already uses for the wrapped DEK / salt / TLS key files (perm&0o077 != 0). Unlike
	// that check — which only warns by default — the KEK is the root of the encryption
	// key hierarchy, so a bad permission here fails closed unconditionally: an
	// operator-fixable chmod, not a runtime toggle, is the correct remedy.
	//
	// Opened non-blocking and fstat'ed on the same descriptor that is read: a FIFO
	// (which passes the mode check at 0600) is refused instead of hanging the boot,
	// and the path cannot be swapped between the check and the read.
	f, info, err := secretenv.OpenRegular(p.path, 0)
	if err != nil {
		return nil, fmt.Errorf("file key provider: failed to read %s: %w", p.path, err)
	}
	defer func() { _ = f.Close() }()
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("file key provider: %s is readable/writable beyond its owner (mode %o) — refusing to trust it as key material; chmod it to 0600 (or 0400)", p.path, info.Mode().Perm())
	}
	// #3410: and owned by the running user or root (secretenv.CheckOwner): any other
	// owner could replace the KEK whatever its mode. Unconditional, like the mode.
	if err := secretenv.CheckOwner(info); err != nil {
		if foe, ok := errors.AsType[*secretenv.ForeignOwnerError](err); ok {
			return nil, fmt.Errorf("file key provider: %s is %w; chown it to uid %d (the user the server runs as) or to root", p.path, err, foe.ProcessUID)
		}
		return nil, fmt.Errorf("file key provider: %s: %w", p.path, err)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("file key provider: failed to read %s: %w", p.path, err)
	}
	// Trim a single trailing newline (common when a key file is `echo`-written),
	// but only for encoded forms — never mangle exactly-32 raw bytes.
	if len(data) != KEKSize {
		data = bytes.TrimRight(data, "\r\n")
	}
	return decodeKeyMaterial(data, "file")
}

// EnvKeyProvider reads the KEK directly from an environment variable's value
// (hex or base64). Suited to KMS/secret-manager injection that lands the key in
// the process environment.
type EnvKeyProvider struct {
	envVar string
}

func NewEnvKeyProvider(envVar string) *EnvKeyProvider { return &EnvKeyProvider{envVar: envVar} }

func (p *EnvKeyProvider) Name() string { return "env" }

func (p *EnvKeyProvider) KEK() ([]byte, error) {
	if p.envVar == "" {
		return nil, fmt.Errorf("env key provider: env_var is required")
	}
	val, found, err := secretenv.LookupChecked(p.envVar) // also honours <env_var>_FILE; a too-open file is refused (KEK = key material)
	if err != nil {
		return nil, fmt.Errorf("env key provider: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("env key provider: %s is not set or empty (or set %s%s to a file holding it)", p.envVar, p.envVar, secretenv.FileSuffix)
	}
	return decodeKeyMaterial([]byte(val), "env")
}
