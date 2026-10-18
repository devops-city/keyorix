// Package fuzzutil holds small shared helpers for fuzz targets. It is imported
// only from _test.go files. It intentionally does not import "testing" — Guard
// takes a fatalf callback (pass t.Fatalf) — so nothing here can leak the testing
// dependency into a non-test build.
package fuzzutil

import (
	"runtime"
	"sync"
	"time"
)

// GuardTimeout is the per-input wall-clock budget for a guarded call. It is scaled
// up under the race detector (guardTimeoutScale, set in guard_race.go): -race
// instruments every memory access and slows execution ~10-20x, so the native 3s
// budget would false-trip on ordinary inputs during a `go test -race` pass.
var GuardTimeout = 3 * time.Second * time.Duration(guardTimeoutScale)

// Guard runs fn with a wall-clock deadline. If fn exceeds GuardTimeout — a hang,
// or a memory-amplification/decompression bomb that would otherwise balloon
// until the fuzz rig's cgroup OOM-kills the process (see the fuzz units'
// MemoryMax) — Guard reports it via fatalf (pass t.Fatalf) so the fuzzer saves
// the input as a reproducer, instead of the worker stalling or being killed with
// no attribution. A panic in fn propagates and is recorded by the fuzzer
// natively. label names the call under test, e.g. "timestamp.Parse".
//
// On timeout the goroutine running fn is left to finish on its own (it cannot be
// cancelled mid-call); the fuzzer stops at the recorded failure, and the rig's
// memory cap bounds any runaway allocation in the meantime.
//
// fn runs on a pooled runner goroutine and the deadline uses a pooled timer, so a
// call that finishes in time costs two channel handoffs instead of a goroutine,
// a channel and a 3s timer that stays live until it fires. fatalf is still called
// on the caller's goroutine, and a runner whose fn hung is never reused.
func Guard(fatalf func(format string, args ...any), label string, fn func()) {
	r := getRunner()
	r.work <- fn

	timeout := GuardTimeout
	t := getTimer(timeout)
	select {
	case <-r.done:
		putTimer(t)
		putRunner(r)
	case <-t.C:
		putTimer(t)
		// Abandon the runner: closing work ends its loop once the hung fn
		// returns (done is buffered, so its final send cannot block).
		r.stop()
		fatalf("%s exceeded %s — possible amplification or hang", label, timeout)
	}
}

// runnerCore is what the runner goroutine references; runner (the handle callers
// hold and the pool stores) is separate so that a handle dropped by the pool can
// be collected, which triggers a cleanup that ends the goroutine.
type runnerCore struct {
	work chan func()
	done chan struct{}
	once sync.Once
}

func (c *runnerCore) stop() { c.once.Do(func() { close(c.work) }) }

// runner executes guarded calls one at a time on a long-lived goroutine.
type runner struct{ *runnerCore }

var runnerPool sync.Pool

func getRunner() *runner {
	if r, ok := runnerPool.Get().(*runner); ok {
		return r
	}
	c := &runnerCore{work: make(chan func()), done: make(chan struct{}, 1)}
	go func() {
		for fn := range c.work {
			fn()
			c.done <- struct{}{}
		}
	}()
	r := &runner{c}
	runtime.AddCleanup(r, (*runnerCore).stop, c)
	return r
}

func putRunner(r *runner) { runnerPool.Put(r) }

var timerPool sync.Pool

func getTimer(d time.Duration) *time.Timer {
	if t, ok := timerPool.Get().(*time.Timer); ok {
		t.Reset(d)
		return t
	}
	return time.NewTimer(d)
}

func putTimer(t *time.Timer) {
	t.Stop()
	timerPool.Put(t)
}
