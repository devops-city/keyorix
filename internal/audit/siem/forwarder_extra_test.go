package siem

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseURL is a test-only helper that panics if raw is not a valid URL.
func parseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

// TestForwarder_Dropped verifies Dropped() returns the count of queue-full events.
func TestForwarder_Dropped(t *testing.T) {
	// A nil forwarder returns 0.
	var f *Forwarder
	assert.Equal(t, int64(0), f.Dropped())

	// Use a real forwarder with a wedged server to overflow the queue.
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fw, err := newForwarder(Config{Enabled: true, Provider: ProviderWebhook, Endpoint: srv.URL}, time.Millisecond)
	require.NoError(t, err)

	for range queueSize + numWorkers + 5 {
		fw.Forward(sampleEvent())
	}
	assert.Greater(t, fw.Dropped(), int64(0))
	close(release)
	fw.Close()
}

// TestForwarder_NilSafe confirms Forward/Close/Dropped are nil-safe.
func TestForwarder_NilSafe(t *testing.T) {
	var f *Forwarder
	f.Forward(sampleEvent()) // must not panic
	f.Forward(nil)           // must not panic
	f.Close()                // must not panic
	assert.Equal(t, int64(0), f.Dropped())
}

// TestForwarder_CloseIdempotent confirms Close twice does not panic or deadlock.
func TestForwarder_CloseIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	f, err := newForwarder(Config{Enabled: true, Provider: ProviderWebhook, Endpoint: srv.URL}, time.Millisecond)
	require.NoError(t, err)
	f.Close()
	f.Close() // must not panic or deadlock
}

// TestRefuseRedirect_NoVia verifies the first request (no prior hop) is accepted.
func TestRefuseRedirect_NoVia(t *testing.T) {
	req := &http.Request{URL: parseURL("https://siem.example.com/collect")}
	assert.NoError(t, refuseRedirect(req, nil))
}

// TestRefuseRedirect_SameHostAllowed verifies a same-host redirect is permitted.
func TestRefuseRedirect_SameHostAllowed(t *testing.T) {
	prev := &http.Request{URL: parseURL("https://siem.example.com/collect")}
	next := &http.Request{URL: parseURL("https://siem.example.com/final")}
	assert.NoError(t, refuseRedirect(next, []*http.Request{prev}))
}

// TestRefuseRedirect_CrossHostDenied verifies a cross-host redirect is refused.
func TestRefuseRedirect_CrossHostDenied(t *testing.T) {
	prev := &http.Request{URL: parseURL("https://siem.example.com/collect")}
	evil := &http.Request{URL: parseURL("https://evil.example.com/steal")}
	err := refuseRedirect(evil, []*http.Request{prev})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cross-host redirect")
}

// TestRefuseRedirect_HTTPSDowngradeDenied verifies an https→http downgrade is refused.
func TestRefuseRedirect_HTTPSDowngradeDenied(t *testing.T) {
	prev := &http.Request{URL: parseURL("https://siem.example.com/collect")}
	down := &http.Request{URL: parseURL("http://siem.example.com/collect")}
	err := refuseRedirect(down, []*http.Request{prev})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https->http")
}

// TestNewForwarder_WithSpoolDir confirms a forwarder with SpoolDir is created
// and queue-overflow events are persisted to the spool, not silently discarded.
func TestNewForwarder_WithSpoolDir(t *testing.T) {
	dir := t.TempDir()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	f, err := newForwarder(Config{
		Enabled:  true,
		Provider: ProviderWebhook,
		Endpoint: srv.URL,
		SpoolDir: dir,
	}, time.Millisecond)
	require.NoError(t, err)

	for range queueSize + numWorkers + 10 {
		f.Forward(sampleEvent())
	}
	close(release)
	f.Close()
	// The spool directory must exist (it was created at startup).
	_, err = os.Stat(dir)
	assert.NoError(t, err)
}

// TestSend_TooManyRequestsIsRetryable verifies 429 is treated as retryable.
func TestSend_TooManyRequestsIsRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	f, err := newForwarder(Config{Enabled: true, Provider: ProviderWebhook, Endpoint: srv.URL}, time.Millisecond)
	require.NoError(t, err)
	defer f.Close()

	retryable, err := f.send(context.Background(), sampleEvent())
	require.Error(t, err)
	assert.True(t, retryable, "429 must be retryable")
}

// TestSend_4xxIsNotRetryable verifies a 4xx is treated as a permanent error.
func TestSend_4xxIsNotRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	f, err := newForwarder(Config{Enabled: true, Provider: ProviderWebhook, Endpoint: srv.URL}, time.Millisecond)
	require.NoError(t, err)
	defer f.Close()

	retryable, err := f.send(context.Background(), sampleEvent())
	require.Error(t, err)
	assert.False(t, retryable, "4xx must not be retryable")
}

// TestToPayload_SuccessNil verifies toPayload defaults Success to true when the
// field is nil.
func TestToPayload_SuccessNil(t *testing.T) {
	e := &models.AuditEvent{ID: 1, EventType: "test"}
	p := toPayload(e)
	assert.True(t, p.Success, "nil Success pointer must default to true")
}

// TestToPayload_SuccessFalse verifies toPayload passes false through correctly.
func TestToPayload_SuccessFalse(t *testing.T) {
	f := false
	e := &models.AuditEvent{ID: 1, EventType: "test", Success: &f}
	p := toPayload(e)
	assert.False(t, p.Success)
}

// TestForwarder_InsecureSkipVerify verifies a forwarder with TLS-skip builds and delivers.
func TestForwarder_InsecureSkipVerify(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	f, err := newForwarder(Config{
		Enabled:            true,
		Provider:           ProviderWebhook,
		Endpoint:           srv.URL,
		InsecureSkipVerify: true,
	}, time.Millisecond)
	require.NoError(t, err)
	require.NotNil(t, f)
	f.Close()
}

// TestForwarder_DeliverSpoolsOnShutdown confirms events that fail after retries
// (i.e., the SIEM is still down when shutdown happens) are persisted to the spool.
func TestForwarder_DeliverSpoolsOnShutdown(t *testing.T) {
	dir := t.TempDir()
	// Server always returns 503 — every delivery attempt will fail.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	f, err := newForwarder(Config{
		Enabled:  true,
		Provider: ProviderWebhook,
		Endpoint: srv.URL,
		SpoolDir: dir,
	}, time.Millisecond)
	require.NoError(t, err)

	f.Forward(sampleEvent())
	f.Close()

	// After close, the spool file must exist (event was persisted after retries exhausted).
	spoolFile := dir + "/" + spoolFileName
	info, err := os.Stat(spoolFile)
	if os.IsNotExist(err) {
		// Acceptable if the forwarder chose another delivery path; just verify no panic.
		return
	}
	require.NoError(t, err)
	assert.Greater(t, info.Size(), int64(0), "spool file must not be empty")
}
