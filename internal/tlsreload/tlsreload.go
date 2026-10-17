// Package tlsreload serves a TLS certificate from a cert/key file pair and picks up
// a rotated pair without a restart (cert-manager, ACME clients and operators
// replace the files in place; before this the HTTP and gRPC listeners kept the pair
// they loaded at start until the process restarted, and served an expired
// certificate in the meantime).
//
// The files are re-checked at most once per CheckInterval, from the TLS handshake
// itself (tls.Config.GetCertificate), so there is no goroutine and no file watcher.
// A changed pair is loaded and validated as a whole; if it does not load (a
// half-written rotation, a key that does not match the certificate) the previous
// pair keeps being served and the failure is logged, and the next check tries again.
package tlsreload

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// CheckInterval bounds how often a handshake re-stats the cert and key files.
// A rotated certificate is served within this long of being written.
var CheckInterval = 30 * time.Second

// Reloader holds the current certificate for one cert/key file pair.
type Reloader struct {
	certFile, keyFile string

	mu        sync.Mutex
	cert      *tls.Certificate
	certMod   time.Time
	keyMod    time.Time
	lastCheck time.Time
}

// New loads the pair once and fails if it does not load, so a broken
// configuration still stops the server at start.
func New(certFile, keyFile string) (*Reloader, error) {
	r := &Reloader{certFile: certFile, keyFile: keyFile}
	certMod, keyMod, err := r.modTimes()
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
	}
	r.cert, r.certMod, r.keyMod, r.lastCheck = &cert, certMod, keyMod, time.Now()
	return r, nil
}

// GetCertificate is the tls.Config.GetCertificate hook.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.lastCheck) >= CheckInterval {
		r.lastCheck = time.Now()
		r.reloadLocked()
	}
	return r.cert, nil
}

func (r *Reloader) reloadLocked() {
	certMod, keyMod, err := r.modTimes()
	if err != nil {
		log.Printf("TLS certificate reload: %v (still serving the previous certificate)", err)
		return
	}
	if certMod.Equal(r.certMod) && keyMod.Equal(r.keyMod) {
		return
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		// Leave certMod/keyMod unchanged so the next check retries: a rotation
		// that writes the cert and the key one after the other is caught on the
		// check after the second write.
		log.Printf("TLS certificate reload: %s changed but does not load: %v (still serving the previous certificate)", r.certFile, err)
		return
	}
	r.cert, r.certMod, r.keyMod = &cert, certMod, keyMod
	log.Printf("TLS certificate reloaded from %s", r.certFile)
}

func (r *Reloader) modTimes() (certMod, keyMod time.Time, err error) {
	ci, err := os.Stat(r.certFile)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("TLS certificate file: %w", err)
	}
	ki, err := os.Stat(r.keyFile)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("TLS key file: %w", err)
	}
	return ci.ModTime(), ki.ModTime(), nil
}
