package middleware

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLogger_AccessLineKeepsFields pins the shape of one access-log line: std
// logger timestamp, method, URI, protocol, remote address, status, byte count and
// elapsed time, exactly as chi's DefaultLogFormatter emits them.
func TestLogger_AccessLineKeepsFields(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)

	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("hello"))
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/things?x=1", nil)
	req.RemoteAddr = "192.0.2.7:4242"
	Logger()(h).ServeHTTP(httptest.NewRecorder(), req)

	line := buf.String()
	re := regexp.MustCompile(`^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} "POST http://example\.com/api/v1/things\?x=1 HTTP/1\.1" from 192\.0\.2\.7:4242 - 201 5B in \S+\n$`)
	assert.Regexp(t, re, line)
}

// TestLogger_FollowsSetOutputAfterConstruction: the router (and so Logger()) is
// built before a process or a test calls log.SetOutput/SetPrefix/SetFlags; the
// access log must still go to the std logger's CURRENT destination, prefix and
// flags. A construction-time snapshot blinded the canary log-leak fuzzers.
func TestLogger_FollowsSetOutputAfterConstruction(t *testing.T) {
	origW, origP, origF := log.Writer(), log.Prefix(), log.Flags()
	defer func() { log.SetOutput(origW); log.SetPrefix(origP); log.SetFlags(origF) }()

	mw := Logger() // constructed BEFORE the std logger is redirected
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetPrefix("late: ")
	log.SetFlags(0)

	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mw(h).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/ping", nil))

	assert.Regexp(t, `^late: "GET http://example\.com/api/v1/ping HTTP/1\.1" from \S+ - 200 0B in \S+\n$`, buf.String())
}

// TestAccessLogWriter_FormatMatchesStdLogger compares our line formatting with
// log.Logger for the flag combinations a process can set.
func TestAccessLogWriter_FormatMatchesStdLogger(t *testing.T) {
	ts := time.Date(2026, 10, 14, 9, 5, 3, 123456000, time.UTC)
	for _, flags := range []int{
		log.LstdFlags, log.LstdFlags | log.LUTC, log.Ldate, log.Ltime | log.Lmicroseconds,
		log.LstdFlags | log.Lmsgprefix, 0,
	} {
		var want bytes.Buffer
		l := log.New(&want, "pfx: ", flags)
		w := &accessLogWriter{prefix: "pfx: ", flags: flags}
		got := w.format(ts, "msg")
		// log.Logger stamps time.Now(), so compare with the timestamp
		// stripped; the layout around it must be identical.
		l.Print("msg")
		stamp := regexp.MustCompile(`\d{4}/\d{2}/\d{2} |\d{2}:\d{2}:\d{2}(\.\d{6})? `)
		assert.Equal(t, stamp.ReplaceAllString(want.String(), ""), stamp.ReplaceAllString(string(got), ""), "flags=%d", flags)
		assert.Equal(t, len(want.String()), len(got), "flags=%d", flags)
	}
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

// TestAccessLogWriter_ConcurrentLinesWholeAndOrdered runs under -race: every line
// arrives whole, none is lost, and each goroutine's lines keep their order.
func TestAccessLogWriter_ConcurrentLinesWholeAndOrdered(t *testing.T) {
	sink := &lockedBuf{}
	w := &accessLogWriter{out: sink}
	const goroutines, perG = 32, 200
	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := range perG {
				w.Print(fmt.Sprintf("g%d seq%d", g, i))
			}
		}(g)
	}
	wg.Wait()

	lines := strings.Split(strings.TrimSuffix(sink.b.String(), "\n"), "\n")
	require.Len(t, lines, goroutines*perG)
	next := make(map[int]int)
	for _, ln := range lines {
		var g, seq int
		_, err := fmt.Sscanf(ln, "g%d seq%d", &g, &seq)
		require.NoError(t, err, "torn line %q", ln)
		require.Equal(t, next[g], seq, "goroutine %d out of order", g)
		next[g]++
	}
	assert.Zero(t, w.Dropped())
}

type blockingSink struct {
	release chan struct{}
	started chan struct{}
	once    sync.Once
}

func (b *blockingSink) Write(p []byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	<-b.release
	return len(p), nil
}

// TestAccessLogWriter_DropsAreCountedNotBlocking: in drop mode, with a stalled
// sink, callers still return, and the overflow is counted rather than silent.
func TestAccessLogWriter_DropsAreCountedNotBlocking(t *testing.T) {
	sink := &blockingSink{release: make(chan struct{}), started: make(chan struct{})}
	w := &accessLogWriter{out: sink, drop: true, logf: func(string, ...any) {}}
	big := strings.Repeat("x", 64<<10)

	done := make(chan struct{})
	go func() { w.Print("first"); close(done) }() // becomes the flusher, stalls in Write
	<-sink.started

	for range 40 { // 40 x 64 KiB > the 1 MiB cap
		w.Print(big)
	}
	assert.NotZero(t, w.Dropped())
	close(sink.release)
	<-done
}

// TestAccessLogWriter_DefaultIsBlock: the zero value, newAccessLogWriter(false)
// and Logger() all select block mode.
func TestAccessLogWriter_DefaultIsBlock(t *testing.T) {
	assert.False(t, (&accessLogWriter{}).drop)
	assert.False(t, newAccessLogWriter(false).drop)
	assert.True(t, newAccessLogWriter(true).drop)
}

// TestAccessLogWriter_BlockModeLosesNothing: with the sink stalled and the queue
// full, a further Print waits (bounded by the sink release) instead of dropping,
// and every line reaches the sink afterwards.
func TestAccessLogWriter_BlockModeLosesNothing(t *testing.T) {
	sink := &stallThenBuf{release: make(chan struct{}), started: make(chan struct{})}
	w := &accessLogWriter{out: sink}
	big := strings.Repeat("x", 64<<10)

	var wg sync.WaitGroup
	wg.Go(func() { ; w.Print("first") }) // flusher, stalls in Write
	<-sink.started

	const lines = 40 // 40 x 64 KiB > the 1 MiB cap, so late callers must wait
	returned := make(chan struct{}, lines)
	for range lines {
		go func() { w.Print(big); returned <- struct{}{} }()
	}
	// Wait until the queue is full: from then on, with the sink stalled, no
	// further caller can return, so some must still be waiting.
	require.Eventually(t, func() bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		return len(w.pending) >= maxPendingAccessLogBytes
	}, 10*time.Second, time.Millisecond)
	assert.Less(t, len(returned), lines, "a full queue must make callers wait in block mode")
	assert.Zero(t, w.Dropped())

	close(sink.release)
	for i := range lines {
		select {
		case <-returned:
		case <-time.After(10 * time.Second):
			t.Fatalf("caller %d still blocked after the sink was released", i)
		}
	}
	wg.Wait()
	assert.Zero(t, w.Dropped())
	assert.Zero(t, AccessLogDropped()-sink.baseDropped)
	assert.Equal(t, 1+lines, strings.Count(sink.String(), "\n"), "every line must reach the sink")
}

// stallThenBuf blocks its first Write until released, then records everything.
type stallThenBuf struct {
	release     chan struct{}
	started     chan struct{}
	once        sync.Once
	baseDropped uint64
	lockedBuf
}

func (s *stallThenBuf) Write(p []byte) (int, error) {
	s.once.Do(func() { s.baseDropped = AccessLogDropped(); close(s.started) })
	<-s.release
	return s.lockedBuf.Write(p)
}

func (s *stallThenBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type logCapture struct {
	mu    sync.Mutex
	lines []string
}

func (c *logCapture) logf(format string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, fmt.Sprintf(format, args...))
}

func (c *logCapture) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.lines...)
}

// TestAccessLogWriter_DropModeReportsRateLimitedAndRecovers: drops are counted,
// at most one warning per accessLogWarnInterval carries the count since the
// previous one, and one "recovered" line follows once the sink catches up.
func TestAccessLogWriter_DropModeReportsRateLimitedAndRecovers(t *testing.T) {
	sink := &blockingSink{release: make(chan struct{}), started: make(chan struct{})}
	capt := &logCapture{}
	var clockMu sync.Mutex
	clock := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	w := &accessLogWriter{
		out: sink, drop: true, logf: capt.logf,
		now: func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return clock },
	}
	advance := func(d time.Duration) { clockMu.Lock(); clock = clock.Add(d); clockMu.Unlock() }
	waitLines := func(n int) []string {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if got := capt.snapshot(); len(got) >= n {
				return got
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("expected %d report lines, got %v", n, capt.snapshot())
		return nil
	}
	before := AccessLogDropped()

	done := make(chan struct{})
	go func() { w.Print("first"); close(done) }()
	<-sink.started
	big := strings.Repeat("x", 64<<10)
	for range 16 { // fill the 1 MiB queue
		w.Print(big)
	}
	require.Zero(t, w.Dropped())

	w.Print(big) // 1st drop: warns at once
	first := waitLines(1)
	assert.Contains(t, first[0], "1 access-log lines dropped since the last warning, 1 in total")

	require.Eventually(t, func() bool { // the first warning goroutine has finished
		w.mu.Lock()
		defer w.mu.Unlock()
		return !w.warnInFlight
	}, 5*time.Second, time.Millisecond)
	for range 5 { // same instant: counted, no new warning (decided inside Print)
		w.Print(big)
	}
	assert.Len(t, capt.snapshot(), 1, "no second warning inside the interval")

	advance(accessLogWarnInterval + time.Second)
	w.Print(big) // 7th drop: warns again with the 6 since the last warning
	second := waitLines(2)
	assert.Contains(t, second[1], "6 access-log lines dropped since the last warning, 7 in total")
	assert.Equal(t, uint64(7), w.Dropped())
	assert.Equal(t, uint64(7), AccessLogDropped()-before)

	close(sink.release) // the sink catches up
	<-done
	last := waitLines(3)
	assert.Contains(t, last[2], "recovered, 7 lines dropped in total")
	// <-done: the flusher has returned, so the single recovery goroutine exists.
	assert.Len(t, capt.snapshot(), 3, "exactly one recovery line")
}
