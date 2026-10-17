package apiclient

import (
	"net/http"
	"testing"
	"time"
)

func TestServerClockOffset(t *testing.T) {
	base := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	resp := func(date string) *http.Response {
		h := http.Header{}
		if date != "" {
			h.Set("Date", date)
		}
		return &http.Response{Header: h}
	}
	date := func(d time.Time) string { return d.UTC().Format(http.TimeFormat) }

	// Server in sync: its Date is the whole second the request fell in, so the +0.5s
	// correction makes the estimate land within a second of zero either way.
	off, ok := ServerClockOffset(resp(date(base)), base, base.Add(200*time.Millisecond))
	if !ok || off < -time.Second || off > time.Second {
		t.Errorf("in sync: offset %v ok=%v", off, ok)
	}
	// Server five minutes ahead / behind.
	off, ok = ServerClockOffset(resp(date(base.Add(5*time.Minute))), base, base)
	if !ok || off < 5*time.Minute-time.Second || off > 5*time.Minute+time.Second {
		t.Errorf("ahead: offset %v ok=%v", off, ok)
	}
	off, ok = ServerClockOffset(resp(date(base.Add(-5*time.Minute))), base, base)
	if !ok || off > -5*time.Minute+time.Second || off < -5*time.Minute-time.Second {
		t.Errorf("behind: offset %v ok=%v", off, ok)
	}
	// A slow round trip is split evenly, not charged to the clock.
	off, _ = ServerClockOffset(resp(date(base.Add(2*time.Second))), base, base.Add(4*time.Second))
	if off < -time.Second || off > time.Second {
		t.Errorf("round-trip midpoint: offset %v", off)
	}
	for _, bad := range []*http.Response{nil, resp(""), resp("not a date")} {
		if _, ok := ServerClockOffset(bad, base, base); ok {
			t.Errorf("%+v must report not-ok", bad)
		}
	}
}
