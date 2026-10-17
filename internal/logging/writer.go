package logging

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Format names for Setup.
const (
	FormatText = "text"
	FormatJSON = "json"
)

// Levels written to the "level" field.
const (
	LevelDebug = "debug"
	LevelInfo  = "info"
	LevelWarn  = "warn"
	LevelError = "error"
)

var jsonMode atomic.Bool

// lineMarker prefixes a line that Event/AccessEvent pre-formatted as JSON. It holds a
// per-process random nonce so no log text can forge it: a message that merely
// starts with `{"ts":...}` (a username, a header) is escaped like any other text,
// whereas passing a line through verbatim requires knowing the nonce.
var lineMarker = func() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("logging: no randomness for the line marker: " + err.Error())
	}
	return "\x1e" + hex.EncodeToString(b[:]) + "\x1f"
}()

// Setup chooses the log format. "" and "text" leave the standard logger exactly as it
// is. "json" sends every `log` line to dst as one JSON object ({"ts","level","msg"},
// plus request fields on lines emitted through Event) and clears the standard
// logger's prefix and timestamp flags, which the JSON object replaces.
func Setup(format string, dst io.Writer) error {
	switch format {
	case "", FormatText:
		jsonMode.Store(false)
		return nil
	case FormatJSON:
		log.SetOutput(NewJSONWriter(dst))
		log.SetFlags(0)
		log.SetPrefix("")
		jsonMode.Store(true)
		return nil
	default:
		return &FormatError{Format: format}
	}
}

// FormatError reports an unknown log format.
type FormatError struct{ Format string }

func (e *FormatError) Error() string {
	return "unknown log format " + `"` + e.Format + `"` + ` (want "text" or "json")`
}

// JSONMode reports whether Setup switched to JSON.
func JSONMode() bool { return jsonMode.Load() }

// NewJSONWriter returns an io.Writer for the standard logger that turns each line
// written to it into one JSON object on dst.
func NewJSONWriter(dst io.Writer) io.Writer { return &jsonWriter{dst: dst} }

type jsonWriter struct {
	mu  sync.Mutex
	dst io.Writer
}

type record struct {
	TS    string `json:"ts"`
	Level string `json:"level"`
	Msg   string `json:"msg"`
}

func (w *jsonWriter) Write(p []byte) (int, error) {
	var out bytes.Buffer
	for line := range strings.SplitSeq(strings.TrimRight(string(p), "\n"), "\n") {
		if line == "" {
			continue
		}
		if rest, ok := strings.CutPrefix(line, lineMarker); ok {
			out.WriteString(rest)
			out.WriteByte('\n')
			continue
		}
		msg := Redact(line)
		b, err := json.Marshal(record{TS: now(), Level: inferLevel(msg), Msg: msg})
		if err != nil {
			continue
		}
		out.Write(b)
		out.WriteByte('\n')
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.dst.Write(out.Bytes()); err != nil {
		return 0, err
	}
	return len(p), nil
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// inferLevel derives a level from the conventional prefixes this codebase already
// puts on its log lines. Anything unmarked is info.
func inferLevel(msg string) string {
	m := strings.TrimLeft(msg, " [")
	up := strings.ToUpper(m)
	switch {
	case hasAnyPrefix(up, "PANIC", "FATAL", "ERROR", "SECURITY"):
		return LevelError
	case hasAnyPrefix(up, "WARN"):
		return LevelWarn
	case hasAnyPrefix(up, "DEBUG"):
		return LevelDebug
	default:
		return LevelInfo
	}
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
