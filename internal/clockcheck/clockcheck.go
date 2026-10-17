// Package clockcheck answers two questions an unattended device with no
// reliable time source has to ask of its own clock, without any network:
//
//   - Is the clock plausible at all? A board without a battery-backed RTC and
//     without NTP boots at the epoch (1970) or at the time it was last shut down.
//     Anything earlier than the moment this binary was built cannot be right.
//   - Is a certificate valid on this clock, and is it about to stop being?
//
// Neither check changes behaviour by itself: callers decide whether to refuse
// (minting a certificate with a nonsense validity window) or to warn (starting
// the server). Pure functions of their arguments, so they are tested with
// injected instants, never the real clock.
package clockcheck

import (
	"crypto/x509"
	"fmt"
	"time"
)

// MinPlausible is the earliest instant a correctly-set clock can show for any
// build of this code: the date this check was written. A binary that knows its
// own (later) build date uses that instead; see Floor.
var MinPlausible = time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC)

// Floor is the earliest plausible instant: the later of MinPlausible and
// buildDate (RFC 3339, the format internal/version.BuildDate has; "" or
// "unknown" or anything unparseable falls back to MinPlausible). A clock
// before it is certainly wrong. A clock after it may still be wrong, in
// either direction; only an external time source can say.
func Floor(buildDate string) time.Time {
	floor := MinPlausible
	if t, err := time.Parse(time.RFC3339, buildDate); err == nil && t.After(floor) {
		floor = t.UTC()
	}
	return floor
}

// Plausible reports whether now is at or after Floor(buildDate), and the floor.
func Plausible(now time.Time, buildDate string) (bool, time.Time) {
	floor := Floor(buildDate)
	return !now.Before(floor), floor
}

// ImplausibleMessage is the operator-facing sentence for a clock that failed
// Plausible. It names what to do, not only what is wrong.
func ImplausibleMessage(now, floor time.Time) string {
	return fmt.Sprintf("the system clock reads %s, earlier than this build (%s): it was never set, or the device lost power with no battery-backed clock. "+
		"Timestamps, token and certificate expiry and TOTP codes depend on it. Set the clock (a local NTP server, `timedatectl set-time`, or an RTC battery) before relying on this device",
		now.UTC().Format(time.RFC3339), floor.Format("2006-01-02"))
}

// CertWindowIssue describes why cert is not good to serve with at now, or is
// close to ceasing to be, and returns "" when it is fine. warnWithin is how
// far ahead of NotAfter to start saying so (0 disables that case).
//
// A certificate that is "not yet valid" is the usual shadow of a clock that is
// behind: the certificate was minted when the clock was right (or ahead), and
// the device now thinks it is earlier. Clients with a correct clock accept it
// only after NotBefore passes in real time.
func CertWindowIssue(cert *x509.Certificate, now time.Time, warnWithin time.Duration) string {
	switch {
	case now.Before(cert.NotBefore):
		return fmt.Sprintf("TLS certificate is not valid until %s but the system clock reads %s: either the clock is behind (set it) or the certificate was issued with a wrong clock (replace it)",
			cert.NotBefore.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	case now.After(cert.NotAfter):
		return fmt.Sprintf("TLS certificate expired on %s (system clock reads %s): clients that check expiry will refuse this server; renew the certificate, or set the clock if it is wrong",
			cert.NotAfter.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	case warnWithin > 0 && cert.NotAfter.Sub(now) <= warnWithin:
		return fmt.Sprintf("TLS certificate expires on %s (within %d days): renew it; a self-signed certificate from `admin init` is not renewed automatically",
			cert.NotAfter.UTC().Format(time.RFC3339), int(warnWithin.Hours()/24))
	}
	return ""
}
