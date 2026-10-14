package connect

// proxy_target_guard_test.go — regression tests for targetGuardRoundTripper
// (hardened_client.go): with an HTTP proxy configured, connectGuardedDialer's
// per-dial netutil.Dialer only ever sees and validates the PROXY's own dial
// address, never the request's actual target — so a request whose TARGET host
// is a literal link-local IP (e.g. cloud IMDS) must still be refused, checked
// against the request URL itself, not the dial address.
import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConnectHardenedTransport_ProxyDoesNotBypassLinkLocalGuard is the
// no-proxy-bypass case: a request to http://169.254.169.254/... through a
// transport with a (real, listening) proxy configured must be refused BEFORE
// the proxy is ever contacted -- proving the check is keyed on the request's
// target, not the dial address (which, with a proxy, would be the proxy's
// own address, not 169.254.169.254 at all).
func TestConnectHardenedTransport_ProxyDoesNotBypassLinkLocalGuard(t *testing.T) {
	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	require.NoError(t, err)

	base := vaultBaseTransport()
	base.Proxy = http.ProxyURL(proxyURL) // force every request through this real, listening proxy
	rt := newConnectHardenedTransport(base)
	cl := &http.Client{Transport: rt}

	req, err := http.NewRequest(http.MethodGet, "http://169.254.169.254/latest/meta-data/", nil)
	require.NoError(t, err)
	_, err = cl.Do(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing")
	assert.Equal(t, int32(0), proxyHits.Load(), "the proxy must never be contacted for a link-local target -- if this is nonzero, the guard let the request through to be dialed via the proxy")
}

// TestConnectHardenedTransport_ProxyStillWorksForLegitimateTarget is the
// contrast case: the SAME proxy configuration must NOT block a legitimate
// (non-link-local) target -- confirms the fix didn't just refuse everything
// once a proxy is configured.
func TestConnectHardenedTransport_ProxyStillWorksForLegitimateTarget(t *testing.T) {
	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	require.NoError(t, err)

	base := vaultBaseTransport()
	base.Proxy = http.ProxyURL(proxyURL)
	rt := newConnectHardenedTransport(base)
	cl := &http.Client{Transport: rt}

	req, err := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	require.NoError(t, err)
	resp, err := cl.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, int32(1), proxyHits.Load())
}
