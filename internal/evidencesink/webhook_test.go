package evidencesink

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The evidence webhook must refuse a cleartext (non-loopback http) endpoint and an
// internal-target destination at construction, so the bearer token + compliance pack
// are never shipped in cleartext or to an internal host.
func TestWebhook_RejectsInsecureEndpoints(t *testing.T) {
	orig := lookupIPAddr
	defer func() { lookupIPAddr = orig }()
	lookupIPAddr = func(host string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.5")}}, nil // a public TEST-NET-3 address
	}

	// Cleartext http to a non-loopback host → rejected.
	_, err := NewWebhook(WebhookConfig{Endpoint: "http://collector.example.com/evidence", Token: "ev-tok"})
	require.ErrorContains(t, err, "must use https")

	// https to the cloud-metadata link-local address → rejected (SSRF/exfil).
	_, err = NewWebhook(WebhookConfig{Endpoint: "https://169.254.169.254/evidence"})
	require.ErrorContains(t, err, "private/link-local")

	// https to a normal host → accepted.
	_, err = NewWebhook(WebhookConfig{Endpoint: "https://collector.example.com/evidence"})
	require.NoError(t, err)

	// #130: InsecureSkipVerify (a TLS-certificate-trust decision) must NOT also
	// bypass the https/SSRF guard — that coupling was the bug. Only the dedicated
	// AllowInsecureTransport opt-in does (AllowPrivateNetworkTarget governs a
	// SEPARATE decision and, since a later fix, no longer also implies this one).
	_, err = NewWebhook(WebhookConfig{Endpoint: "http://collector.example.com/evidence", InsecureSkipVerify: true})
	require.Error(t, err, "InsecureSkipVerify alone must not bypass the https requirement")
	_, err = NewWebhook(WebhookConfig{Endpoint: "http://collector.example.com/evidence", AllowPrivateNetworkTarget: true})
	require.Error(t, err, "AllowPrivateNetworkTarget alone must NOT also bypass the https requirement -- that conflation was a real bug, fixed by splitting the two decisions")
	_, err = NewWebhook(WebhookConfig{Endpoint: "http://collector.example.com/evidence", AllowInsecureTransport: true})
	require.NoError(t, err, "AllowInsecureTransport is the dedicated opt-in for a non-https target")
}

func TestWebhook_PostsEvidenceWithAuth(t *testing.T) {
	var (
		mu       sync.Mutex
		body     []byte
		auth     string
		ctype    string
		sig      string
		filename string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		body, auth, ctype = b, r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		sig, filename = r.Header.Get("X-Keyorix-Evidence-Signature"), r.Header.Get("X-Keyorix-Evidence-Filename")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wh, err := NewWebhook(WebhookConfig{Endpoint: srv.URL, Token: "ev-tok"})
	require.NoError(t, err)
	require.NoError(t, wh.ForwardEvidence(context.Background(), "keyorix-evidence-20260615T100000Z.json", []byte(`{"generated_at":"x"}`), "v1:abc"))

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, `{"generated_at":"x"}`, string(body))
	assert.Equal(t, "Bearer ev-tok", auth)
	assert.Equal(t, "application/json", ctype)
	assert.Equal(t, "v1:abc", sig)
	assert.Equal(t, "keyorix-evidence-20260615T100000Z.json", filename)
	assert.Equal(t, "webhook", wh.Target())
}

// A cross-host redirect from the configured evidence endpoint must be refused, so the
// evidence pack (and its bearer token) can't be bounced to an attacker-controlled host.
func TestWebhook_RefusesCrossHostRedirect(t *testing.T) {
	var evilHits atomic.Int32
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		evilHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer evil.Close()
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, nil, evil.URL, http.StatusFound)
	}))
	defer primary.Close()

	wh, err := newWebhook(WebhookConfig{Endpoint: primary.URL, Token: "ev-tok"}, time.Millisecond)
	require.NoError(t, err)
	err = wh.ForwardEvidence(context.Background(), "pack.json", []byte(`{"x":1}`), "")
	require.Error(t, err, "a cross-host redirect must not be followed")
	assert.Equal(t, int32(0), evilHits.Load(), "redirect target must never be reached")
}

func TestWebhook_ErrorsOnNon2xxAfterRetries(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError) // transient — retried, then surfaced
	}))
	defer srv.Close()
	wh, err := newWebhook(WebhookConfig{Endpoint: srv.URL}, time.Millisecond)
	require.NoError(t, err)
	require.Error(t, wh.ForwardEvidence(context.Background(), "pack.json", []byte(`{}`), ""))
	assert.Equal(t, int32(maxAttempts), hits.Load(), "a 5xx should be retried up to maxAttempts")
}

func TestWebhook_RetriesTransientThenSucceeds(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	wh, err := newWebhook(WebhookConfig{Endpoint: srv.URL}, time.Millisecond)
	require.NoError(t, err)
	require.NoError(t, wh.ForwardEvidence(context.Background(), "pack.json", []byte(`{}`), ""))
	assert.Equal(t, int32(3), hits.Load(), "should retry the two 503s then succeed")
}

func TestWebhook_PermanentErrorNotRetried(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusBadRequest) // 4xx — permanent
	}))
	defer srv.Close()
	wh, err := newWebhook(WebhookConfig{Endpoint: srv.URL}, time.Millisecond)
	require.NoError(t, err)
	require.Error(t, wh.ForwardEvidence(context.Background(), "pack.json", []byte(`{}`), ""))
	assert.Equal(t, int32(1), hits.Load(), "a 4xx must not be retried")
}

func TestNewWebhook_RequiresEndpoint(t *testing.T) {
	_, err := NewWebhook(WebhookConfig{})
	require.Error(t, err)
}

// TestWebhook_DialTimeRefusesDNSRebind is the G48 regression: a hostname that
// resolves to a PUBLIC address at construction (so NewWebhook succeeds) but to
// a PRIVATE/link-local address by the time the webhook actually delivers
// (simulating a DNS-rebinding attacker) must have its delivery refused — the
// dial-time re-check, not just the one-time construction check, must catch it.
func TestWebhook_DialTimeRefusesDNSRebind(t *testing.T) {
	orig := lookupIPAddr
	defer func() { lookupIPAddr = orig }()

	const rebindHost = "rebind.evidence.example"
	callCount := 0
	lookupIPAddr = func(host string) ([]net.IPAddr, error) {
		require.Equal(t, rebindHost, host)
		callCount++
		if callCount == 1 {
			// Construction-time validateEndpoint lookup: answers with a public
			// address, so NewWebhook succeeds.
			return []net.IPAddr{{IP: net.ParseIP("203.0.113.7")}}, nil
		}
		// Every subsequent (dial-time) lookup: the attacker's DNS now answers
		// with the cloud-metadata address.
		return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
	}

	wh, err := newWebhook(WebhookConfig{Endpoint: "https://" + rebindHost + "/evidence", Token: "ev-tok"}, time.Millisecond)
	require.NoError(t, err, "construction sees a public address and must succeed")
	require.GreaterOrEqual(t, callCount, 1)

	err = wh.ForwardEvidence(context.Background(), "pack.json", []byte(`{}`), "")
	require.Error(t, err, "the actual delivery must be refused once dial-time resolution returns a private/link-local address")
	assert.Contains(t, err.Error(), "netutil")
}

// TestWebhook_DialTimePinsValidatedIP proves the dial actually connects to the
// specific IP address the dial-time check just validated (not the hostname
// again), which is what prevents a second, later DNS answer from mattering.
// Uses https + InsecureSkipVerify (self-signed test cert) with a hostname
// that resolves to loopback: isDisallowedIP explicitly permits loopback (for
// local testing), so the dial-time guard runs and passes without needing
// AllowPrivateNetworkTarget, which would otherwise disable the guard entirely.
func TestWebhook_DialTimePinsValidatedIP(t *testing.T) {
	orig := lookupIPAddr
	defer func() { lookupIPAddr = orig }()

	var gotHost string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	srvHost, srvPort, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", srvHost, "httptest.Server listens on 127.0.0.1 by default")

	lookupIPAddr = func(_ string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP(srvHost)}}, nil
	}

	wh, err := NewWebhook(WebhookConfig{
		Endpoint:           "https://dial-pin.evidence.example:" + srvPort + "/evidence",
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)
	require.NoError(t, wh.ForwardEvidence(context.Background(), "pack.json", []byte(`{}`), ""))
	assert.Equal(t, "dial-pin.evidence.example:"+srvPort, gotHost, "the HTTP request's Host header keeps the original hostname even though the TCP dial targeted the resolved IP")
}
