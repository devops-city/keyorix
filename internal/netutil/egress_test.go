package netutil

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ──────────────────────────── Guard.RequireTLS ─────────────────────────────

func TestGuard_RequireTLS_SatisfiedNoop(t *testing.T) {
	g := Guard{}
	require.NoError(t, g.RequireTLS(true, "test target", "example.net"))
}

func TestGuard_RequireTLS_UnsatisfiedRefusedByDefault(t *testing.T) {
	g := Guard{}
	err := g.RequireTLS(false, "test target", "example.net")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must use TLS")
	assert.Contains(t, err.Error(), "example.net")
}

func TestGuard_RequireTLS_UnsatisfiedAllowedWithOptOut(t *testing.T) {
	g := Guard{AllowInsecureTransport: true}
	require.NoError(t, g.RequireTLS(false, "test target", "example.net"), "the explicit opt-out must permit the plaintext connection")
}

// ──────────────────────────── RefuseScheme ─────────────────────────────────

func TestRefuseScheme_MatchingSchemeRefused(t *testing.T) {
	err := RefuseScheme("unix", "unix", "redis admin_dsn")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unix")
}

func TestRefuseScheme_DifferentSchemeAllowed(t *testing.T) {
	require.NoError(t, RefuseScheme("tcp", "unix", "redis admin_dsn"))
}

// ──────────────────────────── Guard.HTTPClient ─────────────────────────────

func TestGuard_HTTPClient_WiresDialContext(t *testing.T) {
	var dialed string
	g := Guard{
		Dial: Dialer{
			Resolve: noDNS(t),
			Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
				dialed = addr
				return &fakeConn{}, nil
			},
		},
	}
	client := g.HTTPClient(5*time.Second, nil, nil)
	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, transport.DialContext)
	_, err := transport.DialContext(testCtx(t), "tcp", "203.0.113.10:443")
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.10:443", dialed)
}

// ──────────────────────────── Guard.RedisDialer ────────────────────────────

func TestGuard_RedisDialer_NoTLS_ReturnsRawConn(t *testing.T) {
	g := Guard{
		Dial: Dialer{
			Resolve: noDNS(t),
			Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
				return &fakeConn{}, nil
			},
		},
	}
	dialer := g.RedisDialer(nil)
	conn, err := dialer(testCtx(t), "tcp", "203.0.113.10:6379")
	require.NoError(t, err)
	_, isTLS := conn.(*tls.Conn)
	assert.False(t, isTLS, "no tlsConfig means the raw conn must be returned unwrapped")
}

func TestGuard_RedisDialer_DialErrorPropagates(t *testing.T) {
	wantErr := errors.New("dial refused")
	g := Guard{
		Dial: Dialer{
			Resolve: noDNS(t),
			Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
				return nil, wantErr
			},
		},
	}
	dialer := g.RedisDialer(&tls.Config{})
	_, err := dialer(testCtx(t), "tcp", "203.0.113.10:6379")
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

func TestGuard_RedisDialer_TLSHandshakeFailurePropagates(t *testing.T) {
	// A real (non-TLS-speaking) local listener stands in for a server whose
	// TLS handshake fails immediately (it never sends a ServerHello), so
	// HandshakeContext returns an error rather than hanging.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	go func() {
		conn, aerr := ln.Accept()
		if aerr == nil {
			// Close immediately without speaking TLS -- the client's
			// handshake will fail with an EOF/reset rather than hang.
			_ = conn.Close()
		}
	}()

	g := Guard{Dial: Dialer{Resolve: noDNS(t)}}
	dialer := g.RedisDialer(&tls.Config{})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = dialer(ctx, "tcp", ln.Addr().String())
	require.Error(t, err, "a failed TLS handshake over a real (non-TLS) conn must surface as an error, not hang or silently downgrade")
	assert.Contains(t, err.Error(), "TLS handshake")
}

// TestGuard_RedisDialer_ServerNameDefaultsToOriginalHostname proves
// RedisDialer's ServerName-derivation logic against a REAL TLS handshake
// (not just that no panic occurs): the server's GetConfigForClient callback
// observes the SNI the client actually sent, then deliberately aborts the
// handshake (returning an error) so the test needs no real/self-signed
// certificate at all. The underlying (fake) Dial simulates what Dialer's own
// pinning does in production — it connects somewhere that is NOT the
// original hostname — so this proves RedisDialer derives ServerName from the
// addr IT was called with (the original hostname:port), never from whatever
// the inner Dial actually connected to.
func TestGuard_RedisDialer_ServerNameDefaultsToOriginalHostname(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	var gotServerName string
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		tlsConn := tls.Server(conn, &tls.Config{
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				gotServerName = hello.ServerName
				return nil, errors.New("deliberately abort handshake after capturing SNI")
			},
		})
		_ = tlsConn.Handshake() // expected to fail — that's fine, we only need the SNI
	}()

	g := Guard{Dial: Dialer{
		// A fake Resolve avoids a REAL (and, for a non-resolving name like
		// "db.example.net", potentially very slow or hanging) DNS lookup —
		// this test only cares what ServerName RedisDialer derives from
		// addr's hostname, not about actually resolving it.
		Resolve: func(_ context.Context, _ string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		},
		Dial: func(_ context.Context, network, _ string) (net.Conn, error) {
			// Simulate Dialer's own pinned-IP dial: connect to the real
			// listener regardless of what addr RedisDialer was told to dial.
			return net.Dial(network, ln.Addr().String())
		},
	}}
	dialer := g.RedisDialer(&tls.Config{InsecureSkipVerify: true})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _ = dialer(ctx, "tcp", "db.example.net:6380") // expected to fail post-handshake-abort
	<-serverDone
	assert.Equal(t, "db.example.net", gotServerName, "ServerName must be the ORIGINAL hostname, not a pinned IP")
}

// TestGuard_RedisDialer_ServerNameNotOverriddenWhenAlreadySet proves the
// caller's own explicit ServerName wins over the derived-from-addr default.
func TestGuard_RedisDialer_ServerNameNotOverriddenWhenAlreadySet(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	var gotServerName string
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		tlsConn := tls.Server(conn, &tls.Config{
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				gotServerName = hello.ServerName
				return nil, errors.New("deliberately abort handshake after capturing SNI")
			},
		})
		_ = tlsConn.Handshake()
	}()

	g := Guard{Dial: Dialer{
		// See TestGuard_RedisDialer_ServerNameDefaultsToOriginalHostname for
		// why Resolve is faked rather than left to hit real DNS.
		Resolve: func(_ context.Context, _ string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		},
		Dial: func(_ context.Context, network, _ string) (net.Conn, error) {
			return net.Dial(network, ln.Addr().String())
		},
	}}
	dialer := g.RedisDialer(&tls.Config{ServerName: "explicit.example.net", InsecureSkipVerify: true})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _ = dialer(ctx, "tcp", "db.example.net:6380")
	<-serverDone
	assert.Equal(t, "explicit.example.net", gotServerName)
}

// ──────────────────────────── Guard.ValidateSRVTargets ─────────────────────

func TestGuard_ValidateSRVTargets_AllTargetsValid(t *testing.T) {
	origLookup := srvLookup
	defer func() { srvLookup = origLookup }()
	srvLookup = func(_ context.Context, service, proto, name string) (string, []*net.SRV, error) {
		assert.Equal(t, "mongodb", service)
		assert.Equal(t, "tcp", proto)
		assert.Equal(t, "cluster0.example.net", name)
		return "", []*net.SRV{
			{Target: "shard00-00.cluster0.example.net.", Port: 27017},
			{Target: "shard00-01.cluster0.example.net.", Port: 27017},
		}, nil
	}
	g := Guard{Dial: Dialer{
		Disallow: IsPrivateOrLinkLocal,
		Resolve: func(_ context.Context, host string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}}, nil
		},
	}}
	require.NoError(t, g.ValidateSRVTargets(testCtx(t), "mongodb", "tcp", "cluster0.example.net"))
}

func TestGuard_ValidateSRVTargets_OneDisallowedTargetRefusesAll(t *testing.T) {
	origLookup := srvLookup
	defer func() { srvLookup = origLookup }()
	srvLookup = func(_ context.Context, _, _, _ string) (string, []*net.SRV, error) {
		return "", []*net.SRV{
			{Target: "shard00-00.cluster0.example.net.", Port: 27017},
			{Target: "shard00-01.cluster0.example.net.", Port: 27017},
		}, nil
	}
	g := Guard{Dial: Dialer{
		Disallow: IsPrivateOrLinkLocal,
		Resolve: func(_ context.Context, host string) ([]net.IPAddr, error) {
			if host == "shard00-01.cluster0.example.net" {
				return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
			}
			return []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}}, nil
		},
	}}
	err := g.ValidateSRVTargets(testCtx(t), "mongodb", "tcp", "cluster0.example.net")
	require.Error(t, err, "a DNS-rebinding-safe SRV pre-check must refuse the whole lookup if ANY target is disallowed")
	assert.Contains(t, err.Error(), "shard00-01.cluster0.example.net")
}

func TestGuard_ValidateSRVTargets_LookupErrorPropagates(t *testing.T) {
	origLookup := srvLookup
	defer func() { srvLookup = origLookup }()
	srvLookup = func(_ context.Context, _, _, _ string) (string, []*net.SRV, error) {
		return "", nil, errors.New("no such SRV record")
	}
	g := Guard{Dial: Dialer{Disallow: IsPrivateOrLinkLocal, Resolve: noDNS(t)}}
	err := g.ValidateSRVTargets(testCtx(t), "mongodb", "tcp", "cluster0.example.net")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no such SRV record")
}

func TestGuard_ValidateSRVTargets_EmptyResultRefused(t *testing.T) {
	origLookup := srvLookup
	defer func() { srvLookup = origLookup }()
	srvLookup = func(_ context.Context, _, _, _ string) (string, []*net.SRV, error) {
		return "", nil, nil
	}
	g := Guard{Dial: Dialer{Disallow: IsPrivateOrLinkLocal, Resolve: noDNS(t)}}
	err := g.ValidateSRVTargets(testCtx(t), "mongodb", "tcp", "cluster0.example.net")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no targets")
}

// The refusal and the warning must name the config key that set the opt-out at
// this construction site (the current insecure_ spelling), not a generic or
// deprecated one.
func TestGuard_RequireTLS_NamesTheConfiguredKey(t *testing.T) {
	const key = "audit.siem.insecure_allow_plaintext_siem_transport"
	err := Guard{InsecureTransportKey: key}.RequireTLS(false, "siem endpoint", "http://x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), key)
	assert.NotContains(t, err.Error(), "allow_insecure_transport")
}
