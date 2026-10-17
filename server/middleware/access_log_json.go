package middleware

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/keyorixhq/keyorix/internal/logging"
)

// jsonLogFormatter is the access-log formatter used when server.log.format is "json".
// It emits one JSON object per request with the same field names as every other log
// line (ts, level, msg, request_id, principal_type, route) plus method, uri, status,
// bytes, duration_ms and remote_addr. The text format keeps chi's DefaultLogFormatter.
//
// uri is the request URI after logSafeRequestURI's redaction (setup/reset tokens and
// secret-reference query strings never reach the log), exactly what the text format
// prints; route is the chi route pattern, which has bounded cardinality and is what
// dashboards should group by.
type jsonLogFormatter struct {
	out *accessLogWriter
}

func (f jsonLogFormatter) NewLogEntry(r *http.Request) chimw.LogEntry {
	return &jsonLogEntry{out: f.out, r: r}
}

type jsonLogEntry struct {
	out *accessLogWriter
	r   *http.Request
}

func (e *jsonLogEntry) Write(status, bytes int, _ http.Header, elapsed time.Duration, _ any) {
	ctx := e.r.Context()
	if h := logging.HolderFrom(ctx); h != nil {
		if rc := chi.RouteContext(ctx); rc != nil {
			if p := rc.RoutePattern(); p != "" {
				h.SetRoute(p)
			} else {
				h.SetRoute("unmatched")
			}
		}
	}
	level := logging.LevelInfo
	if status >= http.StatusInternalServerError {
		level = logging.LevelError
	}
	e.out.Print(logging.Line(ctx, level, "http request",
		"method", e.r.Method,
		"uri", e.r.RequestURI,
		"remote_addr", e.r.RemoteAddr,
		"status", status,
		"bytes", bytes,
		"duration_ms", float64(elapsed.Microseconds())/1000,
	))
}

// Panic is called by chi's Recoverer only; this router uses its own Recovery, which
// logs the panic itself, so there is nothing to record here.
func (e *jsonLogEntry) Panic(any, []byte) {}
