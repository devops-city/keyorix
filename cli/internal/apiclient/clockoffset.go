package apiclient

import (
	"net/http"
	"time"
)

// ServerClockOffset estimates how far the server's clock is ahead of this machine's
// (negative: behind) from the Date header of a response. sent and received are the local
// times just before the request and just after the response; the local time of the server's
// reading is taken as their midpoint. HTTP dates have one-second resolution, so the true
// server time lies in [Date, Date+1s): half a second is added. ok is false when the
// response has no usable Date header.
//
// It lives here because the clientguard sweep (INV-CLI-06) keeps net/http's surface out of
// cli/cmd.
func ServerClockOffset(resp *http.Response, sent, received time.Time) (offset time.Duration, ok bool) {
	if resp == nil {
		return 0, false
	}
	date := resp.Header.Get("Date")
	if date == "" {
		return 0, false
	}
	serverTime, err := http.ParseTime(date)
	if err != nil {
		return 0, false
	}
	local := sent.Add(received.Sub(sent) / 2)
	return serverTime.Add(500 * time.Millisecond).Sub(local), true
}
