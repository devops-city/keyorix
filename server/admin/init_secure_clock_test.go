package admin

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A board with no RTC battery and no NTP boots at the epoch. `admin init` must
// not stamp a certificate validity window from that clock: it would be valid
// from 1970 and expired the day the clock is corrected.
func TestEnsureSelfSignedCert_RefusesAnImplausibleClock(t *testing.T) {
	for name, when := range map[string]time.Time{
		"epoch":     time.Unix(0, 0),
		"year 2000": time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
	} {
		t.Run(name, func(t *testing.T) {
			defer func(old func() time.Time) { adminNow = old }(adminNow)
			adminNow = func() time.Time { return when }
			dir := t.TempDir()
			certPath, keyPath := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")

			err := ensureSelfSignedCert(certPath, keyPath, nil)
			if err == nil {
				t.Fatalf("a certificate was generated on a clock reading %s", when)
			}
			for _, want := range []string{"refusing to generate a TLS certificate", "Set the clock", certPath} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
			for _, p := range []string{certPath, keyPath} {
				if _, statErr := os.Stat(p); statErr == nil {
					t.Errorf("%s was written despite the refusal", p)
				}
			}
		})
	}
}

// Green control: on a plausible clock the certificate is generated and its
// validity window starts at (just before) that clock reading, not the real one.
func TestEnsureSelfSignedCert_StampsTheValidityFromTheClock(t *testing.T) {
	defer func(old func() time.Time) { adminNow = old }(adminNow)
	fixed := time.Now().Add(48 * time.Hour).Truncate(time.Second) // plausible, and distinguishable from the real now
	adminNow = func() time.Time { return fixed }
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")

	if err := ensureSelfSignedCert(certPath, keyPath, nil); err != nil {
		t.Fatalf("ensureSelfSignedCert on a plausible clock: %v", err)
	}
	raw, err := os.ReadFile(certPath) //nolint:gosec // test-generated path
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("no PEM block in the generated certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if want := fixed.Add(-5 * time.Minute); !cert.NotBefore.Equal(want) {
		t.Errorf("NotBefore = %s, want %s (the injected clock minus the 5 minute backdate)", cert.NotBefore, want)
	}
	if want := fixed.Add(selfSignedCertValidity); !cert.NotAfter.Equal(want) {
		t.Errorf("NotAfter = %s, want %s", cert.NotAfter, want)
	}
}
