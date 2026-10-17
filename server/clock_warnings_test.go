package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
)

func writeCertValidBetween(t *testing.T, notBefore, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "clock-test"}, NotBefore: notBefore, NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "server.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func collectWarnings(cfg *config.Config, now time.Time, buildDate string) string {
	var out []string
	logClockWarnings(cfg, now, buildDate, func(f string, a ...any) { out = append(out, fmt.Sprintf(f, a...)) })
	return strings.Join(out, "\n")
}

func tlsCfg(certPath string) *config.Config {
	cfg := &config.Config{}
	cfg.Server.HTTP.Enabled = true
	cfg.Server.HTTP.TLS.Enabled = true
	cfg.Server.HTTP.TLS.CertFile = certPath
	return cfg
}

func TestClockWarnings(t *testing.T) {
	const build = "2027-03-04T05:06:07Z"
	good := time.Date(2027, 6, 1, 12, 0, 0, 0, time.UTC)
	cert := writeCertValidBetween(t, good.Add(-time.Hour), good.Add(300*24*time.Hour))

	for _, c := range []struct {
		name string
		cfg  *config.Config
		now  time.Time
		want []string // substrings that must appear; none = silence
	}{
		{"good clock, valid certificate: silent", tlsCfg(cert), good, nil},
		{"epoch clock", tlsCfg(cert), time.Unix(0, 0), []string{"earlier than this build", "not valid until"}},
		{"clock after the certificate", tlsCfg(cert), good.Add(400 * 24 * time.Hour), []string{"expired on"}},
		{"certificate about to expire", tlsCfg(cert), good.Add(280 * 24 * time.Hour), []string{"expires on"}},
		{"stale clock from before the build, no TLS", &config.Config{}, time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), []string{"earlier than this build"}},
		{"TLS configured but the file is missing: the listener reports that, not this", tlsCfg(filepath.Join(t.TempDir(), "absent.crt")), good, nil},
		{"TLS listener disabled: its certificate is not looked at", func() *config.Config { c := tlsCfg(cert); c.Server.HTTP.Enabled = false; return c }(), time.Unix(0, 0), []string{"earlier than this build"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := collectWarnings(c.cfg, c.now, build)
			if len(c.want) == 0 && got != "" {
				t.Fatalf("expected silence, got:\n%s", got)
			}
			for _, w := range c.want {
				if !strings.Contains(got, w) {
					t.Errorf("warnings do not contain %q:\n%s", w, got)
				}
			}
			if strings.Contains(got, "TLS certificate") && !strings.Contains(got, cert) && c.cfg.Server.HTTP.TLS.CertFile == cert {
				t.Errorf("a certificate warning must name the file:\n%s", got)
			}
		})
	}
}

func TestClockStepWarning(t *testing.T) {
	before := time.Date(2027, 6, 1, 12, 0, 0, 0, time.UTC)
	after := before.Add(-2 * time.Hour)
	for _, c := range []struct {
		name string
		step time.Duration
		want string // substring; "" = silence
	}{
		{"no step", 0, ""},
		{"NTP slew, a few seconds back", -5 * time.Second, ""},
		{"29 s back is inside the guards' tolerance", -29 * time.Second, ""},
		{"30 s back", -30 * time.Second, "stepped BACKWARD by 30s"},
		{"two hours back", -2 * time.Hour, "refused by design"},
		{"31 s forward", 31 * time.Second, "stepped FORWARD"},
		{"a few seconds forward", 3 * time.Second, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := clockStepWarning(c.step, before, after)
			if c.want == "" && got != "" {
				t.Fatalf("expected silence, got %q", got)
			}
			if c.want != "" && !strings.Contains(got, c.want) {
				t.Fatalf("warning %q does not contain %q", got, c.want)
			}
		})
	}
}

// The watcher against a scripted clock: a steady clock is silent, a wall-clock
// jump with no matching monotonic jump is reported once, and the sample after
// the jump is the new baseline (no repeated report).
func TestWatchClockSteps_ReportsAJumpOnce(t *testing.T) {
	type sample struct {
		wall time.Time
		mono time.Duration
	}
	base := time.Date(2027, 6, 1, 12, 0, 0, 0, time.UTC)
	script := []sample{
		{base, 0},
		{base.Add(15 * time.Second), 15 * time.Second},                         // steady
		{base.Add(30 * time.Second), 30 * time.Second},                         // steady
		{base.Add(30*time.Second - 3*time.Hour), 45 * time.Second},             // wall clock 3 h back, 15 s really elapsed
		{base.Add(45*time.Second - 3*time.Hour), 60 * time.Second},             // steady again on the new baseline
		{base.Add(60*time.Second - 3*time.Hour + time.Hour), 75 * time.Second}, // 1 h forward
	}
	i := 0
	var mu sync.Mutex
	var got []string
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sampleFn := func() (time.Time, time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		s := script[min(i, len(script)-1)]
		i++
		if i > len(script) {
			select {
			case <-done:
			default:
				close(done)
			}
		}
		return s.wall, s.mono
	}
	go watchClockSteps(ctx, time.Millisecond, sampleFn, func(f string, a ...any) {
		mu.Lock()
		got = append(got, fmt.Sprintf(f, a...))
		mu.Unlock()
	})
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not consume the scripted samples")
	}
	cancel()
	time.Sleep(20 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 || !strings.Contains(got[0], "BACKWARD by 3h0m15s") || !strings.Contains(got[1], "FORWARD by 1h0m0s") {
		t.Fatalf("want exactly one backward (3h0m15s: the 3 h step plus the 15 s that really elapsed) then one forward (1h) report, got %d: %q", len(got), got)
	}
}
