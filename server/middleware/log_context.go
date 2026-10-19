package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/keyorixhq/keyorix/internal/logging"
)

// RequestIDHeader is the request header a caller (or a reverse proxy) may set to
// correlate its own logs with ours.
const RequestIDHeader = "X-Request-ID"

// LogContext puts a logging.Holder on the request context and fills in the request
// id: the caller's X-Request-ID when it sent a usable one (sanitised: printable
// ASCII, capped), otherwise a fresh random id. It writes the chosen id back into
// the request header so chi's RequestID middleware (registered after this one) adopts
// the same value instead of minting a second id.
//
// Register it FIRST, before Recovery, so a panic's log line can carry the id. The
// principal type starts as "anonymous" and is replaced once authentication has run
// (buildRequestContext); the route is filled in by the access logger once chi has
// matched.
func LogContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, h := logging.WithHolder(r.Context())
		id := logging.SanitizeID(r.Header.Get(RequestIDHeader))
		if id == "" {
			id = newRequestID()
		}
		r.Header.Set(RequestIDHeader, id)
		// Echoed so an operator can ask a client "what was the X-Request-ID of the
		// failing call" and grep the logs for it.
		w.Header().Set(RequestIDHeader, id)
		h.SetRequestID(id)
		h.SetPrincipalType(logging.PrincipalAnonymous)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func newRequestID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unavailable"
	}
	return hex.EncodeToString(b[:])
}
