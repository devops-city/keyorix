package middleware

import (
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/keyorixhq/keyorix/internal/logging"
)

// sensitiveURIPattern matches request paths that carry a single-use bearer
// credential as a URL path segment — GET /auth/setup/{token} is the only such
// route in this router today (the token is sufficient, on its own, for full
// account takeover via the paired POST /auth/setup/consume), and every other
// sensitive identifier in the codebase travels in a POST body or a header, never
// a path segment. The pattern is written generally (…/setup/<tok>,
// …/invite/<tok>, …/password-reset/<tok>) so a future look-alike route is
// covered too, and is a no-op for paths that don't match (e.g. the no-token
// POST /auth/password-reset).
var sensitiveURIPattern = regexp.MustCompile(`(?i)^(/(?:api/v1/)?auth/(?:setup|invite|password-reset)/)[^/?]+`)

// sensitiveQueryPattern matches paths whose query-string parameters carry secret
// identifiers — /secrets/value and /secrets/by-name accept a ?ref= or ?name=
// query param that is the secret reference or name. Logging these verbatim would
// write secret names/references to the access log (container logs, log-aggregation
// SaaS, on-call terminal), leaking the secret catalogue to log readers.
//
// #G29: the OAuth/OIDC SSO callback (GET .../auth/sso/{provider}/callback) was
// never added here — its ?code=&state= query carries a single-use OAuth
// authorization code (redeemable for a session on its own) and a CSRF state
// nonce, so every SSO login used to write the authorization code to the log
// stream in plaintext.
var sensitiveQueryPattern = regexp.MustCompile(`(?i)/secrets/(?:value|by-name)\b|/auth/sso/[^/?]+/callback\b`)

// redactSensitiveURI replaces the credential segment of a known-sensitive path
// with a fixed placeholder, and strips the entire query string for paths that
// carry secret identifiers in query parameters. It returns the input unchanged
// when no sensitive pattern matches.
func redactSensitiveURI(uri string) string {
	// First redact path-segment credentials (setup/invite/password-reset tokens).
	uri = sensitiveURIPattern.ReplaceAllString(uri, "${1}[REDACTED]")
	// Then redact query strings for endpoints that accept secret ref/name params.
	if idx := strings.IndexByte(uri, '?'); idx != -1 {
		if sensitiveQueryPattern.MatchString(uri[:idx]) {
			uri = uri[:idx] + "?[redacted]"
		}
	}
	return uri
}

// decodedRequestURI reconstructs r.URL.Path + its query string as a single
// string, built from the already-percent-decoded .Path — NOT the raw
// r.RequestURI wire form redactSensitiveURI used to be applied to directly.
// #G29: a percent-encoded route character (e.g. %2F standing in for a literal
// '/') still routes to the same handler via chi's decoded-path matching, but
// left RequestURI's raw, still-encoded form unmatched by sensitiveURIPattern —
// a redaction bypass. Matching against the decoded path closes it.
func decodedRequestURI(r *http.Request) string {
	if r.URL.RawQuery == "" {
		return r.URL.Path
	}
	return r.URL.Path + "?" + r.URL.RawQuery
}

// logSafeRequestURI is the single canonicalizing function fix_shape (#G29)
// asks for: redact known-sensitive path/query content, then strip control
// characters (CR/LF, ANSI/C1 escapes, NUL) from whatever remains — applied
// uniformly here (the access log) and in recovery.go's panic-context log, so
// neither can independently drift out of sync with the other's coverage.
func logSafeRequestURI(r *http.Request) string {
	return stripControl(redactSensitiveURI(decodedRequestURI(r)))
}

// Logger returns a middleware that logs HTTP requests. It behaves like chi's
// middleware.RequestLogger(DefaultLogFormatter), except the request handed to the
// formatter has any known-sensitive path segment redacted first (see
// sensitiveURIPattern) — the original, unmodified request is still what reaches
// the route handler, so request handling is unaffected. Without this, a setup/
// password-reset token would be written to the log stream (container logs, a
// log-aggregation SaaS, an on-call terminal) in plaintext on every hit, and that
// token remains live (the describe GET does not consume it) — a log reader could
// use it for account takeover.
func Logger() func(next http.Handler) http.Handler {
	return LoggerDropOnSinkStall(false)
}

// LoggerDropOnSinkStall is Logger with the access-log stall mode chosen:
// drop=false is server.access_log.on_sink_stall "block" (the default: a full
// queue makes the request wait, no line is lost), drop=true is "drop" (the
// request proceeds, the line is counted and reported; see accessLogWriter).
func LoggerDropOnSinkStall(drop bool) func(next http.Handler) http.Handler {
	out := newAccessLogWriter(drop)
	var formatter middleware.LogFormatter = &middleware.DefaultLogFormatter{
		// Not log.Default(): its mutex is held across the write syscall, which
		// serialised every request at high concurrency. Same destination, prefix
		// and line format; see accessLogWriter.
		Logger: out,
		// #G29: server access logs are captured non-interactively (container
		// logs, a log-aggregation SaaS) where ANSI color codes are noise at
		// best and an unnecessary terminal-control byte stream at worst if
		// ever viewed raw — never emit them here.
		NoColor: true,
	}
	if logging.JSONMode() {
		// server.log.format: json — one JSON object per request, same fields as
		// every other log line. Read when the router is built, so logging.Setup must
		// run before NewRouter (server/main.go does).
		formatter = jsonLogFormatter{out: out}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logReq := r
			if redacted := logSafeRequestURI(r); redacted != r.RequestURI {
				clone := r.Clone(r.Context())
				clone.RequestURI = redacted
				logReq = clone
			}
			entry := formatter.NewLogEntry(logReq)
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			t1 := time.Now()
			defer func() {
				// #G55: without recover() here, a panicking handler still reaches this
				// defer (defers always run), but ww.Status() reads 0 at this point in the
				// unwind (Recovery's write happens later, further up the stack) — logging
				// a misleading status 0 instead of the 500 the client actually receives.
				// Recover, log the TRUE eventual status, then re-panic so Recovery (outer)
				// still gets to handle it.
				panicVal := recover()
				status := ww.Status()
				if panicVal != nil {
					status = http.StatusInternalServerError
				}
				entry.Write(status, ww.BytesWritten(), ww.Header(), time.Since(t1), nil)
				if panicVal != nil {
					panic(panicVal)
				}
			}()

			next.ServeHTTP(ww, middleware.WithLogEntry(r, entry))
		})
	}
}
