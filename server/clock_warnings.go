package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/keyorixhq/keyorix/internal/clockcheck"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/version"
)

// certWarnWindow is how far ahead of NotAfter a TLS certificate starts being
// reported at start-up. The server does not renew a certificate itself.
const certWarnWindow = 30 * 24 * time.Hour

// warnClockAndCertificate logs, on every start, the two clock-related states an
// unattended device with no time source ends up in: a clock that cannot be
// right (before this build existed), and a TLS certificate that is not valid
// (yet, or any more) on this clock or is about to stop being. Warn only: the
// device must come back after a power cut even when its clock has not been set
// yet. docs/edge-deployment.md, "No NTP: what a bad clock does".
func warnClockAndCertificate(cfg *config.Config) {
	logClockWarnings(cfg, time.Now(), version.BuildDate, log.Printf)
}

// logClockWarnings is warnClockAndCertificate with its inputs injected.
func logClockWarnings(cfg *config.Config, now time.Time, buildDate string, warn func(format string, args ...any)) {
	if ok, floor := clockcheck.Plausible(now, buildDate); !ok {
		warn("WARNING: %s", clockcheck.ImplausibleMessage(now, floor))
	}
	seen := map[string]bool{}
	for _, inst := range []config.ServerInstanceConfig{cfg.Server.HTTP, cfg.Server.GRPC} {
		path := inst.TLS.CertFile
		if !inst.Enabled || !inst.TLS.Enabled || inst.TLS.AutoCert || path == "" || seen[path] {
			continue
		}
		seen[path] = true
		raw, err := os.ReadFile(path) //nolint:gosec // operator-configured certificate path, the same file the listener loads
		if err != nil {
			continue // the listener's own load reports an unreadable certificate
		}
		block, _ := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if issue := clockcheck.CertWindowIssue(cert, now, certWarnWindow); issue != "" {
			warn("WARNING: %s: %s", path, issue)
		}
	}
}

// clockStepThreshold is how far the wall clock must move relative to the
// monotonic clock before it is reported. 30 s is the tolerance the in-process
// backward-step guards allow (secretExpiryClockRegressionTolerance,
// consumeClockRegressionTolerance), so a smaller backward step never matters.
const clockStepThreshold = 30 * time.Second

// clockStepWarning classifies how far the wall clock moved beyond what the
// monotonic clock says elapsed: step = (wall delta) - (monotonic delta).
// "" when it is below the threshold. A step back past the threshold is the
// state in which the server, by design, refuses secret value reads and
// second-factor logins until the clock passes the latest time it has seen or
// the service restarts (internal/core versions.go, ADR-094): without this line
// the only symptom is every read answering "expired".
func clockStepWarning(step time.Duration, wallBefore, wallAfter time.Time) string {
	switch {
	case step <= -clockStepThreshold:
		return fmt.Sprintf("WARNING: the system clock stepped BACKWARD by %s (it read %s, now %s). "+
			"Until the clock passes about %s again, or this service restarts, secret value reads and second-factor logins are refused by design "+
			"(the server does not trust a clock that went back). Restart the service now if this correction is permanent; "+
			"to avoid this, make sure the clock is set before the service starts",
			(-step).Round(time.Second), wallBefore.UTC().Format(time.RFC3339), wallAfter.UTC().Format(time.RFC3339), wallBefore.UTC().Format(time.RFC3339))
	case step >= clockStepThreshold:
		return fmt.Sprintf("WARNING: the system clock stepped FORWARD by %s (it read %s, now %s). "+
			"Sessions, tokens and leases that expire inside that span have just expired, and TOTP codes must match the new time",
			step.Round(time.Second), wallBefore.UTC().Format(time.RFC3339), wallAfter.UTC().Format(time.RFC3339))
	}
	return ""
}

// clockSample returns the wall clock (monotonic reading stripped) and the
// monotonic time elapsed since some fixed start.
type clockSample func() (wall time.Time, mono time.Duration)

func realClockSample() clockSample {
	start := time.Now()
	return func() (time.Time, time.Duration) {
		n := time.Now()
		return n.Round(0), n.Sub(start) // Round(0) strips the monotonic reading from the wall value
	}
}

// watchClockSteps samples the clock every interval until ctx ends and logs a
// warning whenever the wall clock steps by clockStepThreshold or more against
// the monotonic clock. Cheap (one time.Now per tick), local, no network.
func watchClockSteps(ctx context.Context, interval time.Duration, sample clockSample, warn func(format string, args ...any)) {
	prevWall, prevMono := sample()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			wall, mono := sample()
			step := wall.Sub(prevWall) - (mono - prevMono)
			if msg := clockStepWarning(step, prevWall.Add(mono-prevMono), wall); msg != "" {
				warn("%s", msg)
			}
			prevWall, prevMono = wall, mono
		}
	}
}
