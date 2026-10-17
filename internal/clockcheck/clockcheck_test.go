package clockcheck

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"
)

func ts(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestFloor(t *testing.T) {
	for _, c := range []struct {
		name, build string
		want        time.Time
	}{
		{"no build date", "", MinPlausible},
		{"dev build", "unknown", MinPlausible},
		{"unparseable", "yesterday", MinPlausible},
		{"older than the constant: constant wins", "2026-01-02T03:04:05Z", MinPlausible},
		{"newer than the constant: build date wins", "2027-03-04T05:06:07Z", ts("2027-03-04T05:06:07Z")},
		{"offset is normalised to UTC", "2027-03-04T05:06:07+02:00", ts("2027-03-04T03:06:07Z")},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := Floor(c.build); !got.Equal(c.want) {
				t.Fatalf("Floor(%q) = %s, want %s", c.build, got, c.want)
			}
		})
	}
}

// The clocks an unattended board really shows after a power loss without an
// RTC: the epoch, a stale last-shutdown time, and (green control) a good time.
func TestPlausible(t *testing.T) {
	const build = "2027-03-04T05:06:07Z"
	for _, c := range []struct {
		name string
		now  time.Time
		want bool
	}{
		{"epoch (no RTC, no NTP)", time.Unix(0, 0), false},
		{"year 2000 RTC default", ts("2000-01-01T00:00:00Z"), false},
		{"stale time from before the build", ts("2027-03-04T05:06:06Z"), false},
		{"exactly the build instant", ts(build), true},
		{"a correct clock", ts("2027-06-01T12:00:00Z"), true},
		{"far future is NOT detectable here", ts("2099-01-01T00:00:00Z"), true},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, floor := Plausible(c.now, build)
			if got != c.want {
				t.Fatalf("Plausible(%s) = %v, want %v (floor %s)", c.now, got, c.want, floor)
			}
			if !got && !strings.Contains(ImplausibleMessage(c.now, floor), "Set the clock") {
				t.Fatalf("the message must tell the operator what to do: %s", ImplausibleMessage(c.now, floor))
			}
		})
	}
}

func TestCertWindowIssue(t *testing.T) {
	cert := &x509.Certificate{NotBefore: ts("2027-01-01T00:00:00Z"), NotAfter: ts("2028-02-01T00:00:00Z")}
	month := 30 * 24 * time.Hour
	for _, c := range []struct {
		name       string
		now        time.Time
		warnWithin time.Duration
		wantSubstr string // "" = no issue
	}{
		{"valid, far from expiry", ts("2027-06-01T00:00:00Z"), month, ""},
		{"clock behind the certificate (epoch)", time.Unix(0, 0), month, "not valid until"},
		{"one second before NotBefore", ts("2026-12-31T23:59:59Z"), month, "not valid until"},
		{"exactly NotBefore is valid", ts("2027-01-01T00:00:00Z"), month, ""},
		{"expired", ts("2028-02-01T00:00:01Z"), month, "expired on"},
		{"inside the warning window", ts("2028-01-15T00:00:00Z"), month, "expires on"},
		{"inside the window but warnings off", ts("2028-01-15T00:00:00Z"), 0, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := CertWindowIssue(cert, c.now, c.warnWithin)
			if c.wantSubstr == "" && got != "" {
				t.Fatalf("unexpected issue: %s", got)
			}
			if c.wantSubstr != "" && !strings.Contains(got, c.wantSubstr) {
				t.Fatalf("issue = %q, want it to contain %q", got, c.wantSubstr)
			}
		})
	}
}
