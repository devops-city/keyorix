package middleware

import (
	"encoding/json"
	"net/http"
)

// MaxBodyBytes caps each request body at limit bytes. A limit <= 0 disables the cap
// (passthrough).
//
// Two layers, because a body's length may or may not be declared up front:
//   - A request whose Content-Length already exceeds the cap is answered 413 with the
//     standard JSON error body here, before any handler (or Authentication) runs and
//     before a byte of the body is read. The connection is closed rather than drained.
//   - Every body is also wrapped in http.MaxBytesReader, so a chunked body (no declared
//     length) still cannot be read past the cap: the handler's decode fails, and the
//     handler answers it (a 4xx: 413 where the handler maps *http.MaxBytesError,
//     400 where it reports a bad body generically).
func MaxBodyBytes(limit int64) func(http.Handler) http.Handler {
	return MaxBodyBytesFor(func(*http.Request) int64 { return limit })
}

// MaxBodyBytesFor is MaxBodyBytes with the cap chosen per request, so one middleware
// can give different route classes different caps (server/http's requestBodyLimit).
func MaxBodyBytesFor(limitFor func(*http.Request) int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if limit := limitFor(r); limit > 0 && r.Body != nil {
				if r.ContentLength > limit {
					writePayloadTooLarge(w)
					return
				}
				r.Body = http.MaxBytesReader(w, r.Body, limit)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// writePayloadTooLarge answers 413 in the API's JSON error shape. Connection: close
// tells net/http not to drain the unread body for keep-alive reuse.
func writePayloadTooLarge(w http.ResponseWriter) {
	w.Header().Set("Connection", "close")
	w.Header().Set(hdrContentType, mimeJSON)
	w.WriteHeader(http.StatusRequestEntityTooLarge)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": false,
		"error":   "PayloadTooLarge",
		"message": "request body too large",
		"code":    http.StatusRequestEntityTooLarge,
	})
}
