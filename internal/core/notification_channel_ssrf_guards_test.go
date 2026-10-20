package core

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// #3427: two SSRF guards had no test that goes red when the guard is removed.
//
//   - noEscalationRedirect: an attacker-controlled receiver must not bounce the
//     escalation POST to a second host with a 3xx.
//   - validateWebhookURL's resolve-and-check loop: a hostname that resolves to a
//     private address is refused on create AND update, and a resolve failure is
//     refused (fail closed), not waved through.

// TestPostJSONToURL_RefusesRedirectToSecondHost drives the production client
// that postJSONToURL builds when c.httpClient is nil. Only its dial target is
// swapped (escalationTransport, so two local TLS servers stand in for two
// hostnames); the client's CheckRedirect is the real one. Remove
// `CheckRedirect: noEscalationRedirect` from postJSONToURL and the second
// server receives the POST.
func TestPostJSONToURL_RefusesRedirectToSecondHost(t *testing.T) {
	const firstHost, secondHost = "hooks.first.test", "hooks.second.test"

	var firstHits, secondHits atomic.Int32
	second := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		secondHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer second.Close()
	first := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstHits.Add(1)
		http.Redirect(w, r, "https://"+secondHost+"/stolen", http.StatusFound)
	}))
	defer first.Close()

	pool := x509.NewCertPool()
	pool.AddCert(first.Certificate()) // httptest serves one shared cert from both servers
	backends := map[string]string{
		net.JoinHostPort(firstHost, "443"):  first.Listener.Addr().String(),
		net.JoinHostPort(secondHost, "443"): second.Listener.Addr().String(),
	}
	orig := escalationTransport
	defer func() { escalationTransport = orig }()
	escalationTransport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			backend, ok := backends[addr]
			if !ok {
				return nil, errors.New("test dialer: unexpected destination " + addr)
			}
			return (&net.Dialer{}).DialContext(ctx, network, backend)
		},
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com", MinVersion: tls.VersionTLS12},
	}

	c := NewKeyorixCore(new(MockStorage)) // c.httpClient nil: the production client
	err := c.postJSONToURL(context.Background(), "https://"+firstHost+"/hook", map[string]string{"k": "v"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "redirect refused", "the 302 must be refused by noEscalationRedirect")
	assert.EqualValues(t, 1, firstHits.Load(), "the first receiver is contacted once")
	assert.EqualValues(t, 0, secondHits.Load(), "the redirect target must receive nothing")
}

// resolverFor returns a channelLookupIPAddr stand-in answering with addrs (or
// err) and restores the real one on cleanup.
func resolverFor(t *testing.T, addrs []string, err error) {
	t.Helper()
	orig := channelLookupIPAddr
	t.Cleanup(func() { channelLookupIPAddr = orig })
	channelLookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
		if err != nil {
			return nil, err
		}
		out := make([]net.IPAddr, 0, len(addrs))
		for _, a := range addrs {
			out = append(out, net.IPAddr{IP: net.ParseIP(a)})
		}
		return out, nil
	}
}

// TestValidateWebhookURL_ResolveAndCheckLoop covers the loop in
// validateWebhookURL on its own: private, mixed (one public + one private
// answer) and failed resolutions are refused; an all-public answer passes.
func TestValidateWebhookURL_ResolveAndCheckLoop(t *testing.T) {
	const target = "https://hooks.internal.test/services/T/B/TOKEN"

	t.Run("private answer refused", func(t *testing.T) {
		resolverFor(t, []string{"10.0.0.5"}, nil)
		err := validateWebhookURL(target)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "private/link-local")
	})
	t.Run("one private answer among public ones refused", func(t *testing.T) {
		resolverFor(t, []string{"203.0.113.7", "10.0.0.5"}, nil)
		require.Error(t, validateWebhookURL(target))
	})
	t.Run("resolve error refused", func(t *testing.T) {
		resolverFor(t, nil, errors.New("no such host"))
		err := validateWebhookURL(target)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not resolve")
	})
	t.Run("all-public answer accepted", func(t *testing.T) {
		resolverFor(t, []string{"203.0.113.7", "198.51.100.9"}, nil)
		require.NoError(t, validateWebhookURL(target))
	})
}

// The same guard reached through the real create and update paths (no
// webhookURLValidator override): nothing is persisted when it refuses. The
// MockStorage has no expectations for the write calls, so a write would panic.
func TestNotificationChannel_CreateAndUpdateRefuseResolvedPrivateHost(t *testing.T) {
	const host = "https://hooks.internal.test/services/T/B/TOKEN"

	t.Run("create: 10.0.0.5 refused", func(t *testing.T) {
		resolverFor(t, []string{"10.0.0.5"}, nil)
		c := NewKeyorixCore(new(MockStorage))
		created, err := c.CreateNotificationChannel(context.Background(),
			&models.NotificationChannel{Name: "n", Type: "webhook", URL: host, Enabled: true}, "tester", 1)
		require.Error(t, err)
		assert.Nil(t, created)
		assert.Contains(t, err.Error(), "private/link-local")
	})

	t.Run("update: 10.0.0.5 refused", func(t *testing.T) {
		resolverFor(t, []string{"10.0.0.5"}, nil)
		store := new(MockStorage)
		store.On("GetNotificationChannel", mock.Anything, uint(7)).Return(&models.NotificationChannel{
			ID: 7, Name: "n", Type: "webhook", URLEnc: plaintextURLEnc("https://hooks.public.test/ok"), Enabled: true,
		}, nil)
		c := NewKeyorixCore(store)
		updated, err := c.UpdateNotificationChannel(context.Background(), 7, map[string]any{"url": host}, 1)
		require.Error(t, err)
		assert.Nil(t, updated)
		assert.Contains(t, err.Error(), "private/link-local")
		store.AssertNotCalled(t, "UpdateNotificationChannel", mock.Anything, mock.Anything)
	})

	t.Run("create: resolve error refused", func(t *testing.T) {
		resolverFor(t, nil, errors.New("no such host"))
		c := NewKeyorixCore(new(MockStorage))
		_, err := c.CreateNotificationChannel(context.Background(),
			&models.NotificationChannel{Name: "n", Type: "webhook", URL: host, Enabled: true}, "tester", 1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not resolve")
	})

	t.Run("update: resolve error refused", func(t *testing.T) {
		resolverFor(t, nil, errors.New("no such host"))
		store := new(MockStorage)
		store.On("GetNotificationChannel", mock.Anything, uint(7)).Return(&models.NotificationChannel{
			ID: 7, Name: "n", Type: "webhook", URLEnc: plaintextURLEnc("https://hooks.public.test/ok"), Enabled: true,
		}, nil)
		c := NewKeyorixCore(store)
		_, err := c.UpdateNotificationChannel(context.Background(), 7, map[string]any{"url": host}, 1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not resolve")
		store.AssertNotCalled(t, "UpdateNotificationChannel", mock.Anything, mock.Anything)
	})
}
