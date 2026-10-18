package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"
)

// startupParams describes one measurement: start bin in dir `runs` times, each
// time timing process start to the first HTTP 200 from url. The last run then
// idles for `idle` and is stopped, and its kernel-reported peak resident set
// size is the memory figure.
type startupParams struct {
	Bin     string
	Dir     string
	Env     []string
	URL     string
	Runs    int
	Idle    time.Duration
	Timeout time.Duration
}

type startupResult struct {
	ReadyMS   []int64 // one per run, process start to first 200
	PeakRSSKB int64   // peak RSS of the last run over its whole life (start, ready, idle)
}

func (r startupResult) medianMS() int64 {
	s := append([]int64{}, r.ReadyMS...)
	slices.Sort(s)
	if len(s) == 0 {
		return 0
	}
	return s[len(s)/2]
}

var probeClient = &http.Client{
	Timeout: 2 * time.Second,
	// The server's generated certificate is self-signed; this measures
	// readiness on loopback, it does not verify identity.
	Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}}, // #nosec G402 -- loopback readiness probe of a throwaway server; verifies nothing and sends no credentials nosemgrep: problem-based-packs.insecure-transport.go-stdlib.bypass-tls-verification.bypass-tls-verification -- same reason: loopback probe only
}

// probe GETs url. A url without a scheme is tried over https, then http: the
// baseline config of older releases serves cleartext, newer ones TLS.
func probe(url string) (*http.Response, error) {
	if strings.Contains(url, "://") {
		return probeClient.Get(url)
	}
	resp, err := probeClient.Get("https://" + url)
	if err == nil {
		return resp, nil
	}
	return probeClient.Get("http://" + url)
}

func measureStartup(p startupParams) (startupResult, error) {
	var res startupResult
	for i := 0; i < p.Runs; i++ {
		last := i == p.Runs-1
		ms, rss, err := oneStart(p, last)
		if err != nil {
			return res, fmt.Errorf("run %d of %d: %w", i+1, p.Runs, err)
		}
		fmt.Fprintf(os.Stderr, "  startup run %d/%d: %d ms\n", i+1, p.Runs, ms)
		res.ReadyMS = append(res.ReadyMS, ms)
		if last {
			res.PeakRSSKB = rss
		}
	}
	return res, nil
}

// oneStart runs the server once. With idleAfter it keeps the server idle for
// p.Idle after it is ready, stops it and returns its peak RSS in KiB.
func oneStart(p startupParams, idleAfter bool) (readyMS, peakKB int64, err error) {
	logPath := filepath.Join(p.Dir, "server.log")
	logf, err := os.Create(logPath) // #nosec G304 -- server.log under the throwaway state dir this tool created
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = logf.Close() }()
	cmd := exec.Command(p.Bin) // #nosec G204 -- p.Bin is the server binary the operator passed on this dev tool's own command line nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- measurement tool run by hand; no remote input reaches it
	cmd.Dir = p.Dir
	cmd.Env = p.Env
	cmd.Stdout, cmd.Stderr = logf, logf
	t0 := time.Now()
	if err := cmd.Start(); err != nil {
		return 0, 0, err
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	reaped := false
	// stop asks the server to exit and waits for it; safe to call once.
	stop := func() {
		if reaped {
			return
		}
		reaped = true
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-exited
		}
	}
	defer stop()

	deadline := t0.Add(p.Timeout)
	for {
		select {
		case werr := <-exited:
			reaped = true
			return 0, 0, fmt.Errorf("server exited before /health answered (%v); last log lines:\n%s", werr, tailFile(logPath, 15))
		default:
		}
		if resp, gerr := probe(p.URL); gerr == nil {
			ok := resp.StatusCode == http.StatusOK
			_ = resp.Body.Close()
			if ok {
				readyMS = time.Since(t0).Milliseconds()
				break
			}
		}
		if time.Now().After(deadline) {
			return 0, 0, fmt.Errorf("no HTTP 200 from %s within %s; last log lines:\n%s", p.URL, p.Timeout, tailFile(logPath, 15))
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !idleAfter {
		return readyMS, 0, nil
	}
	fmt.Fprintf(os.Stderr, "  idling %s to read peak memory...\n", p.Idle)
	select {
	case werr := <-exited:
		reaped = true
		return 0, 0, fmt.Errorf("server exited while idle (%v); last log lines:\n%s", werr, tailFile(logPath, 15))
	case <-time.After(p.Idle):
	}
	stop()
	kb, err := peakRSSKB(cmd.ProcessState)
	return readyMS, kb, err
}

// peakRSSKB returns the peak resident set size of an exited process in KiB.
// Getrusage reports bytes on macOS and KiB on Linux. The sandbox this tooling
// is developed in blocks ps, so the kernel's own accounting is used instead of
// sampling.
func peakRSSKB(ps *os.ProcessState) (int64, error) {
	if ps == nil {
		return 0, errors.New("process state unavailable")
	}
	ru, ok := ps.SysUsage().(*syscall.Rusage)
	if !ok || ru == nil {
		return 0, errors.New("no rusage for the exited process")
	}
	if runtime.GOOS == "darwin" {
		return int64(ru.Maxrss) / 1024, nil
	}
	return int64(ru.Maxrss), nil
}

func tailFile(path string, n int) string {
	b, err := os.ReadFile(path) // #nosec G304 -- the server.log this tool wrote under its own state dir
	if err != nil {
		return "(no log)"
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
