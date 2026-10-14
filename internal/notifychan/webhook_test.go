package notifychan

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebhookSink_DeliversJSONWithBearerAuth(t *testing.T) {
	var (
		mu    sync.Mutex
		body  []byte
		auth  string
		ctype string
		hits  int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		body, auth, ctype, hits = b, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), hits+1
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewWebhook(WebhookConfig{Endpoint: srv.URL, Token: "secret-tok"})
	require.NoError(t, err)

	pid := uint(3)
	sink.Deliver(core.NotificationEvent{
		UserID: 7, Email: "ada@x.io", Type: "access_request.approved",
		Title: "Approved", Message: "ok", ProjectID: &pid, Link: "/projects/3",
	})
	sink.Close() // drains the queue before returning

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1, hits)
	assert.Equal(t, "Bearer secret-tok", auth)
	assert.Equal(t, "application/json", ctype)

	var ev core.NotificationEvent
	require.NoError(t, json.Unmarshal(body, &ev))
	assert.Equal(t, uint(7), ev.UserID)
	assert.Equal(t, "ada@x.io", ev.Email)
	assert.Equal(t, "access_request.approved", ev.Type)
	require.NotNil(t, ev.ProjectID)
	assert.Equal(t, uint(3), *ev.ProjectID)
}

func TestWebhookSink_NoTokenOmitsAuthHeader(t *testing.T) {
	var (
		mu   sync.Mutex
		auth string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auth = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	sink, err := NewWebhook(WebhookConfig{Endpoint: srv.URL})
	require.NoError(t, err)
	sink.Deliver(core.NotificationEvent{UserID: 1, Type: "x"})
	sink.Close()

	mu.Lock()
	defer mu.Unlock()
	assert.Empty(t, auth)
}

// TestWebhookSink_SendRequestBuildErrorIsPermanent covers send's
// http.NewRequestWithContext error path. The endpoint is validated once at
// construction (newWebhook), so the only way to exercise a request-build failure at
// send time is to bypass the constructor and hand send() a URL that url.Parse itself
// rejects (a raw control character) — proving the documented contract ("a marshalling
// error is permanent" extends to any request-construction failure) actually holds,
// not merely that some error occurs.
func TestWebhookSink_SendRequestBuildErrorIsPermanent(t *testing.T) {
	s := &WebhookSink{
		cfg:    WebhookConfig{Endpoint: "https://example.com/\x7fbad"},
		client: &http.Client{},
	}
	retryable, err := s.send(context.Background(), core.NotificationEvent{UserID: 1, Type: "x"})
	require.Error(t, err)
	assert.False(t, retryable, "a malformed request must be treated as permanent, not retried")
}

func TestNewWebhook_RequiresEndpoint(t *testing.T) {
	_, err := NewWebhook(WebhookConfig{})
	require.Error(t, err)
}

func TestWebhookSink_RetriesTransientThenSucceeds(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable) // transient — should be retried
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	delivBefore := testutil.ToFloat64(notifyDeliveries.WithLabelValues("webhook", outcomeDelivered))
	retryBefore := testutil.ToFloat64(notifyRetries.WithLabelValues("webhook"))

	sink, err := newWebhook(WebhookConfig{Endpoint: srv.URL}, time.Millisecond)
	require.NoError(t, err)
	defer sink.Close()
	sink.Deliver(core.NotificationEvent{UserID: 1, Type: "x"})

	// Wait for the terminal "delivered" outcome before asserting — Close() would
	// abort an in-flight retry, so we must not race it against the backoff.
	require.Eventually(t, func() bool {
		return testutil.ToFloat64(notifyDeliveries.WithLabelValues("webhook", outcomeDelivered))-delivBefore == 1
	}, 2*time.Second, 5*time.Millisecond)

	assert.Equal(t, int32(3), hits.Load(), "should have taken 2 retries (3 attempts)")
	assert.Equal(t, 2.0, testutil.ToFloat64(notifyRetries.WithLabelValues("webhook"))-retryBefore)
}

func TestWebhookSink_PermanentErrorNotRetried(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusBadRequest) // 4xx — permanent, must not retry
	}))
	defer srv.Close()

	failedBefore := testutil.ToFloat64(notifyDeliveries.WithLabelValues("webhook", outcomeFailed))
	retryBefore := testutil.ToFloat64(notifyRetries.WithLabelValues("webhook"))

	sink, err := newWebhook(WebhookConfig{Endpoint: srv.URL}, time.Millisecond)
	require.NoError(t, err)
	sink.Deliver(core.NotificationEvent{UserID: 1, Type: "x"})
	sink.Close() // no retry backoff for a permanent error, so Close cleanly drains it

	assert.Equal(t, int32(1), hits.Load(), "a 4xx must not be retried")
	assert.Equal(t, 1.0, testutil.ToFloat64(notifyDeliveries.WithLabelValues("webhook", outcomeFailed))-failedBefore)
	assert.Equal(t, 0.0, testutil.ToFloat64(notifyRetries.WithLabelValues("webhook"))-retryBefore)
}

func TestWebhookSink_DropsAndCountsWhenQueueFull(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release // wedge the worker so the queue backs up
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	droppedBefore := testutil.ToFloat64(notifyDeliveries.WithLabelValues("webhook", outcomeDropped))

	sink, err := newWebhook(WebhookConfig{Endpoint: srv.URL}, time.Millisecond)
	require.NoError(t, err)

	// One event wedges the worker; the buffered queue holds webhookQueueSize more;
	// everything past that is dropped (and counted) rather than blocking the caller.
	for range webhookQueueSize + 5 {
		sink.Deliver(core.NotificationEvent{UserID: 1, Type: "x"})
	}
	dropped := testutil.ToFloat64(notifyDeliveries.WithLabelValues("webhook", outcomeDropped)) - droppedBefore
	assert.GreaterOrEqual(t, dropped, 1.0, "events past the queue capacity should be dropped and counted")

	close(release)
	sink.Close()
}

func TestWebhookSink_SignsPayloadWhenSecretSet(t *testing.T) {
	var (
		mu   sync.Mutex
		body []byte
		sig  string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		body, sig = b, r.Header.Get("X-Keyorix-Signature")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewWebhook(WebhookConfig{Endpoint: srv.URL, SigningSecret: "shh"})
	require.NoError(t, err)
	sink.Deliver(core.NotificationEvent{UserID: 1, Type: "x"})
	sink.Close()

	mu.Lock()
	defer mu.Unlock()
	mac := hmac.New(sha256.New, []byte("shh"))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	assert.Equal(t, want, sig, "payload must be HMAC-signed so the receiver can verify it")
}

func TestNewWebhook_RejectsNonHTTPSEndpoint(t *testing.T) {
	_, err := NewWebhook(WebhookConfig{Endpoint: "http://siem.example.com/hook"})
	require.Error(t, err, "a non-loopback http endpoint must be rejected (cleartext token)")
	assert.Contains(t, err.Error(), "https")

	// Loopback http is allowed (local testing).
	_, err = NewWebhook(WebhookConfig{Endpoint: "http://127.0.0.1:9000/hook"})
	require.NoError(t, err)

	// #130: InsecureSkipVerify (a TLS-certificate-trust decision) must NOT also
	// bypass the https/SSRF guard — that coupling was the bug. Only the dedicated
	// AllowInsecureTransport opt-in does (AllowPrivateNetworkTarget governs a
	// SEPARATE decision — whether a private/link-local resolved host is
	// permitted — and, since a later fix, no longer also implies this one).
	_, err = NewWebhook(WebhookConfig{Endpoint: "http://siem.example.com/hook", InsecureSkipVerify: true})
	require.Error(t, err, "InsecureSkipVerify alone must not bypass the https requirement")
	_, err = NewWebhook(WebhookConfig{Endpoint: "http://siem.example.com/hook", AllowPrivateNetworkTarget: true})
	require.Error(t, err, "AllowPrivateNetworkTarget alone must NOT also bypass the https requirement -- that conflation was a real bug, fixed by splitting the two decisions")

	// AllowInsecureTransport satisfies the scheme check, but the (separate,
	// still-active) private-network host check now runs for real -- mock the
	// resolver to a public IP so this test isolates the TLS/scheme axis alone,
	// rather than depending on siem.example.com's real DNS resolvability.
	origResolve := lookupIPAddr
	defer func() { lookupIPAddr = origResolve }()
	lookupIPAddr = func(_ string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.5")}}, nil // public TEST-NET-3
	}
	_, err = NewWebhook(WebhookConfig{Endpoint: "http://siem.example.com/hook", AllowInsecureTransport: true})
	require.NoError(t, err, "AllowInsecureTransport is the dedicated opt-in for a non-https target")
}

// TestNewWebhook_InsecureSkipVerifyWarningRedactsEndpoint is #G30: the endpoint
// URL is the bearer credential for this channel (the token lives in the path,
// not a header), so the InsecureSkipVerify startup warning must not log it
// verbatim — matching this package's own redactURLHost policy used elsewhere
// (delivery.go, TestChatSink_DeliveryFailureLogDoesNotLeakWebhookToken).
func TestNewWebhook_InsecureSkipVerifyWarningRedactsEndpoint(t *testing.T) {
	orig := lookupIPAddr
	defer func() { lookupIPAddr = orig }()
	lookupIPAddr = func(host string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.5")}}, nil // public TEST-NET-3
	}

	const token = "xoxb-topsecret-1234567890"

	var buf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(origOut)

	_, err := NewWebhook(WebhookConfig{
		Endpoint:           "https://siem.example.com/services/T000/B000/" + token,
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)

	logged := buf.String()
	assert.Contains(t, logged, "siem.example.com", "host should be kept for diagnostic value")
	assert.NotContains(t, logged, token, "the webhook's embedded bearer token must never reach the log stream")
	assert.NotContains(t, logged, "services/T000/B000", "the webhook's path (which carries the token) must never reach the log stream")
}

// TestNewWebhook_RejectsHostnameResolvingToPrivateIP pins #130: the SSRF guard
// previously only rejected a LITERAL private/link-local IP in the endpoint —
// a hostname (e.g. attacker-controlled DNS) resolving to one, such as the cloud
// metadata address, sailed straight through. The guard must resolve the
// hostname and check every address it returns.
func TestNewWebhook_RejectsHostnameResolvingToPrivateIP(t *testing.T) {
	orig := lookupIPAddr
	defer func() { lookupIPAddr = orig }()
	lookupIPAddr = func(host string) ([]net.IPAddr, error) {
		if host == "metadata.attacker.example" {
			return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
		}
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.5")}}, nil // a public TEST-NET-3 address
	}

	_, err := NewWebhook(WebhookConfig{Endpoint: "https://metadata.attacker.example/hook"})
	require.Error(t, err, "a hostname resolving to a link-local address must be rejected")
	assert.Contains(t, err.Error(), "private/link-local")

	_, err = NewWebhook(WebhookConfig{Endpoint: "https://normal.example.com/hook"})
	require.NoError(t, err, "a hostname resolving to a public address is unaffected")
}

// TestWebhookSink_DialTimeRefusesDNSRebind is the G48 regression: a hostname
// that resolves to a PUBLIC address at construction (so NewWebhook succeeds)
// but to a PRIVATE/link-local address by the time the webhook actually
// delivers (simulating a DNS-rebinding attacker) must have its delivery
// refused — the dial-time re-check, not just the one-time construction check,
// must catch it.
func TestWebhookSink_DialTimeRefusesDNSRebind(t *testing.T) {
	orig := lookupIPAddr
	defer func() { lookupIPAddr = orig }()

	const rebindHost = "rebind.notify.example"
	callCount := 0
	lookupIPAddr = func(host string) ([]net.IPAddr, error) {
		require.Equal(t, rebindHost, host)
		callCount++
		if callCount == 1 {
			// Construction-time validateEndpoint lookup: a public address.
			return []net.IPAddr{{IP: net.ParseIP("203.0.113.7")}}, nil
		}
		// Every subsequent (dial-time) lookup: the attacker's DNS now answers
		// with an RFC-1918 address.
		return []net.IPAddr{{IP: net.ParseIP("10.1.2.3")}}, nil
	}

	failedBefore := testutil.ToFloat64(notifyDeliveries.WithLabelValues("webhook", outcomeFailed))

	var buf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(origOut)

	sink, err := newWebhook(WebhookConfig{Endpoint: "https://" + rebindHost + "/hook"}, time.Millisecond)
	require.NoError(t, err, "construction sees a public address and must succeed")
	require.GreaterOrEqual(t, callCount, 1)

	sink.Deliver(core.NotificationEvent{UserID: 1, Type: "x"})
	sink.Close()

	assert.Equal(t, 1.0, testutil.ToFloat64(notifyDeliveries.WithLabelValues("webhook", outcomeFailed))-failedBefore,
		"delivery must be refused once dial-time resolution returns a private address, even though construction saw a public one")
	// Assert on the SPECIFIC failure reason, not merely that it failed — a
	// weaker assertion here would pass even without the dial-time guard,
	// since "rebind.notify.example" isn't a real, resolvable domain (a plain
	// DNS failure would also increment the failed counter for the wrong
	// reason).
	assert.Contains(t, buf.String(), "disallowed address", "the failure must come from the dial-time SSRF guard, not an unrelated DNS error")
}
