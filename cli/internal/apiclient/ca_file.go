// ca_file.go -- hand-written, not part of client.gen.go. The CLI's custom-CA trust option
// (--ca-file / KEYORIX_CA_FILE / ca_file in the credentials file, resolved in cli/cmd).
//
// `keyorix-server admin init` generates a self-signed certificate for the server's TLS
// listener (SECURE-DEFAULT-1). No system trust store knows it, and SSL_CERT_FILE is not a
// portable answer: on macOS Go verifies through the platform verifier and ignores it. So
// the CLI builds its root pool with Go's own x509 from the named PEM file, which behaves
// the same on every platform.
package apiclient

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// maxCAFileBytes bounds how much of a CA file is read. A PEM bundle of every public root
// is well under 1 MiB; anything larger is not a CA file.
const maxCAFileBytes = 1 << 20

// LoadCAPool reads a PEM CA/certificate file into a new x509.CertPool. The pool holds ONLY
// the file's certificates (curl --cacert semantics): naming a CA file narrows trust to it,
// it never widens trust to "anything". It fails closed when the file is missing, larger
// than maxCAFileBytes, holds no certificate, holds a private key (the wrong file, and a key
// that should not sit in a trust path), or is writable by group or others (anyone who can
// write it can make this CLI trust their server).
func LoadCAPool(path string) (*x509.CertPool, error) {
	f, err := os.Open(path) // #nosec G304 -- the operator names their own CA file (flag/env/config)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("read CA file %s: not a regular file", path)
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return nil, fmt.Errorf("CA file %s has permissions %#o: writable by group or others, refusing to trust it; fix with chmod go-w %s", path, perm, path)
	}

	data, err := io.ReadAll(io.LimitReader(f, maxCAFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	if len(data) > maxCAFileBytes {
		return nil, fmt.Errorf("CA file %s is larger than %d bytes", path, maxCAFileBytes)
	}

	pool := x509.NewCertPool()
	certs := 0
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if strings.Contains(block.Type, "PRIVATE KEY") {
			return nil, fmt.Errorf("CA file %s contains a private key (%s): pass the certificate only", path, block.Type)
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("CA file %s: parse certificate: %w", path, err)
		}
		pool.AddCert(cert)
		certs++
	}
	if certs == 0 {
		return nil, fmt.Errorf("CA file %s: no PEM certificate found", path)
	}
	return pool, nil
}

// NewHardenedHTTPClientWithCAFile is NewHardenedHTTPClient with its TLS root pool built
// from caFile (see LoadCAPool). The timeout, response cap and redirect refusal are the same.
func NewHardenedHTTPClientWithCAFile(caFile string) (*http.Client, error) {
	if caFile == "" {
		return nil, errors.New("keyorix: empty CA file path")
	}
	pool, err := LoadCAPool(caFile)
	if err != nil {
		return nil, err
	}
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("keyorix: http.DefaultTransport is not an *http.Transport")
	}
	transport := base.Clone()
	transport.TLSClientConfig = &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}
	c := NewHardenedHTTPClient()
	c.Transport = &cappingTransport{base: transport}
	return c, nil
}
