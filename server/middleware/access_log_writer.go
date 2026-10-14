package middleware

import (
	"fmt"
	"io"
	"log"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// maxPendingAccessLogBytes bounds the memory held by lines waiting for the
// current flusher. Past it the writer's stall mode decides: block (default) waits
// for the sink so no line is lost; drop discards and reports the line. The
// access log is not the audit trail, which is written separately either way.
const maxPendingAccessLogBytes = 1 << 20

// accessLogWarnInterval is the minimum gap between two "lines are being dropped"
// warnings.
const accessLogWarnInterval = 10 * time.Second

// accessLogDroppedTotal counts lines dropped by every drop-mode writer in this
// process; AccessLogDropped exposes it to the system-info posture surface.
var accessLogDroppedTotal atomic.Uint64

// AccessLogDropped reports how many access-log lines this process has dropped
// because the sink stalled (always 0 in the default block mode).
func AccessLogDropped() uint64 { return accessLogDroppedTotal.Load() }

// accessLogWriter is the access log's replacement for the global *log.Logger.
//
// log.Logger holds its mutex across the write syscall, so at high concurrency
// every request queued behind one another's write. Here the lock covers only an
// in-memory append. Whichever caller finds no flush in progress becomes the
// flusher and writes everything pending (its own line included) outside the
// lock; callers arriving meanwhile append and return without waiting.
//
// Properties kept from the std logger: lines are written whole, in the order
// they were appended, in the same "prefix + timestamp + message" format, and an
// uncontended Print has written its line to the sink before it returns.
type accessLogWriter struct {
	// useStd makes the destination, prefix and flags follow the std logger as it
	// is NOW: log.Writer() is read once per flushed batch, log.Prefix() and
	// log.Flags() (atomic loads) once per line. A later log.SetOutput, SetPrefix
	// or SetFlags therefore takes effect, as it would for log.Default(). When
	// false (tests), out, prefix and flags are used as given.
	useStd bool
	out    io.Writer
	prefix string
	flags  int

	// drop selects the stall mode: false (the zero value) blocks a caller while
	// the queue is full, true drops and reports its line.
	drop bool
	// logf and now are log.Printf and time.Now unless a test replaces them.
	logf func(format string, args ...any)
	now  func() time.Time

	mu       sync.Mutex
	cond     *sync.Cond // signalled when the flusher frees queue space; made lazily
	pending  []byte
	spare    []byte
	flushing bool

	// Drop-mode reporting, guarded by mu.
	episodeDrops uint64    // dropped since the last recovery line
	sinceWarn    uint64    // dropped since the last warning
	lastWarn     time.Time // zero until the first warning
	warnInFlight bool

	dropped atomic.Uint64
}

// newAccessLogWriter returns a writer that follows the std logger's destination,
// prefix and flags at write time, so output goes where log.Default() would send
// it right now (not where it pointed at construction: the router is usually built
// before log.SetOutput). drop selects server.access_log.on_sink_stall: "drop"
// (true) or "block" (false).
func newAccessLogWriter(drop bool) *accessLogWriter {
	return &accessLogWriter{useStd: true, drop: drop}
}

// sink is the destination for the batch about to be flushed.
func (w *accessLogWriter) sink() io.Writer {
	if w.useStd {
		return log.Writer()
	}
	return w.out
}

// layout is the prefix and flags for the line about to be formatted.
func (w *accessLogWriter) layout() (prefix string, flags int) {
	if w.useStd {
		return log.Prefix(), log.Flags()
	}
	return w.prefix, w.flags
}

// Dropped reports how many lines were discarded because the sink fell behind.
func (w *accessLogWriter) Dropped() uint64 { return w.dropped.Load() }

// Print implements chi's middleware.LoggerInterface.
func (w *accessLogWriter) Print(v ...any) {
	line := w.format(time.Now(), fmt.Sprint(v...))

	w.mu.Lock()
	for len(w.pending) >= maxPendingAccessLogBytes {
		if w.drop {
			n, total, warn := w.noteDropLocked()
			w.mu.Unlock()
			if warn {
				w.warnAsync(n, total)
			}
			return
		}
		// Block mode: a full queue means a flusher is mid-write; wait for it.
		w.condLocked().Wait()
	}
	w.pending = append(w.pending, line...)
	if w.flushing {
		w.mu.Unlock()
		return
	}
	w.flushing = true
	for len(w.pending) > 0 {
		batch := w.pending
		w.pending = w.spare[:0]
		w.condLocked().Broadcast() // the queue just emptied: wake blocked callers
		w.mu.Unlock()
		_, _ = w.sink().Write(batch) // a failing sink loses lines, as with log.Logger
		w.mu.Lock()
		w.spare = batch[:0]
	}
	w.flushing = false
	total, recovered := w.recoveredLocked()
	w.mu.Unlock()
	if recovered {
		go w.report("access log sink recovered, %d lines dropped in total", total)
	}
}

func (w *accessLogWriter) condLocked() *sync.Cond {
	if w.cond == nil {
		w.cond = sync.NewCond(&w.mu)
	}
	return w.cond
}

func (w *accessLogWriter) report(format string, args ...any) {
	if w.logf != nil {
		w.logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

func (w *accessLogWriter) clock() time.Time {
	if w.now != nil {
		return w.now()
	}
	return time.Now()
}

// noteDropLocked counts one dropped line and, at most once per
// accessLogWarnInterval, says a warning is due: warn is true with the number
// dropped since the last warning and the total. The caller holds w.mu and, after
// releasing it, calls warnAsync when warn is set.
func (w *accessLogWriter) noteDropLocked() (n, total uint64, warn bool) {
	w.dropped.Add(1)
	accessLogDroppedTotal.Add(1)
	w.episodeDrops++
	w.sinceWarn++
	now := w.clock()
	if w.warnInFlight || (!w.lastWarn.IsZero() && now.Sub(w.lastWarn) < accessLogWarnInterval) {
		return 0, 0, false
	}
	n, total = w.sinceWarn, w.dropped.Load()
	w.sinceWarn = 0
	w.lastWarn = now
	w.warnInFlight = true
	return n, total, true
}

// warnAsync writes the drop warning from its own goroutine: it goes to the same
// stalled sink, and the request being dropped must not wait on it. At most one
// such goroutine exists at a time (warnInFlight); counts keep accumulating meanwhile.
func (w *accessLogWriter) warnAsync(n, total uint64) {
	go func() {
		w.report("WARNING: access log sink is stalled (server.access_log.on_sink_stall=drop): "+
			"%d access-log lines dropped since the last warning, %d in total; the audit trail is unaffected", n, total)
		w.mu.Lock()
		w.warnInFlight = false
		w.mu.Unlock()
	}()
}

// recoveredLocked ends a drop episode once the sink has caught up (the flusher
// drained the queue) and returns the total to report. The caller holds w.mu.
func (w *accessLogWriter) recoveredLocked() (total uint64, recovered bool) {
	if w.episodeDrops == 0 {
		return 0, false
	}
	w.episodeDrops, w.sinceWarn = 0, 0
	w.lastWarn = time.Time{}
	return w.dropped.Load(), true
}

// format renders one line the way log.Logger does for the flags in use.
func (w *accessLogWriter) format(t time.Time, msg string) []byte {
	prefix, flags := w.layout()
	b := make([]byte, 0, len(prefix)+len(msg)+32)
	if flags&log.Lmsgprefix == 0 {
		b = append(b, prefix...)
	}
	if flags&(log.Ldate|log.Ltime|log.Lmicroseconds) != 0 {
		if flags&log.LUTC != 0 {
			t = t.UTC()
		}
		if flags&log.Ldate != 0 {
			y, m, d := t.Date()
			b = appendPadded(b, y, 4)
			b = append(b, '/')
			b = appendPadded(b, int(m), 2)
			b = append(b, '/')
			b = appendPadded(b, d, 2)
			b = append(b, ' ')
		}
		if flags&(log.Ltime|log.Lmicroseconds) != 0 {
			h, mi, s := t.Clock()
			b = appendPadded(b, h, 2)
			b = append(b, ':')
			b = appendPadded(b, mi, 2)
			b = append(b, ':')
			b = appendPadded(b, s, 2)
			if flags&log.Lmicroseconds != 0 {
				b = append(b, '.')
				b = appendPadded(b, t.Nanosecond()/1e3, 6)
			}
			b = append(b, ' ')
		}
	}
	if flags&log.Lmsgprefix != 0 {
		b = append(b, prefix...)
	}
	b = append(b, msg...)
	if len(msg) == 0 || msg[len(msg)-1] != '\n' {
		b = append(b, '\n')
	}
	return b
}

func appendPadded(b []byte, n, width int) []byte {
	s := strconv.Itoa(n)
	for i := len(s); i < width; i++ {
		b = append(b, '0')
	}
	return append(b, s...)
}
