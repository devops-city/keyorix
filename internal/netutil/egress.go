package netutil

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// Guard is the single outbound-egress control point every backend that opens
// a connection to an operator-configured or secret-ref-derived address is
// expected to route through, rather than hand-rolling its own dial/http-
// client construction. Before this existed, that exact recipe (dial-time IP
// re-validation + TLS-by-default-with-a-logged-exception) was independently
// duplicated at every such call site (internal/dynamic/postgres.go,
// internal/dynamic/mysql.go, internal/notifychan's secure_transport.go,
// internal/evidencesink's webhook.go), while MongoDB, Redis, and the SIEM/
// audit forwarder had NO such guard at all. Guard wraps Dialer (the dial-
// time IP re-validation primitive, unchanged) with the transport- and
// scheme-level policy nearly every such backend also needs.
type Guard struct {
	// Dial is applied to every outbound connection this Guard makes. Its own
	// Disallow/Resolve fields carry the actual SSRF policy; the zero value
	// (nil Disallow) permits every address — the explicit "allow private
	// network target" opt-out, mirrored by leaving Dial unset entirely at
	// call sites that follow the existing postgres.go/mysql.go convention of
	// only wiring a Dialer when the opt-out is NOT set.
	Dial Dialer
	// AllowInsecureTransport permits a plaintext (non-TLS) connection when
	// true. False (the default) refuses one outright via RequireTLS. Every
	// construction site that sets this true logs the exception (2d) — see
	// RequireTLS.
	AllowInsecureTransport bool
	// InsecureTransportKey is the config key that sets AllowInsecureTransport for
	// this construction site (e.g. "audit.siem.insecure_allow_plaintext_siem_transport"),
	// so the refusal and the warning tell the operator the real key to change.
	InsecureTransportKey string
}

// RequireTLS enforces this Guard's TLS policy: tlsSatisfied must be true
// unless AllowInsecureTransport is set, in which case the plaintext
// connection is permitted but logged — an explicit, audited exception, never
// a silent fallback. context/target identify what connected without TLS
// (e.g. "mongodb admin_dsn", "cluster0.example.net"), so an operator can find
// and reconsider every insecure connection actually made, not just learn one
// exists somewhere.
func (g Guard) RequireTLS(tlsSatisfied bool, context, target string) error {
	if tlsSatisfied {
		return nil
	}
	key := g.InsecureTransportKey
	if key == "" {
		key = "the insecure_allow_plaintext_*_transport setting for this connection"
	}
	if !g.AllowInsecureTransport {
		return fmt.Errorf("netutil: %s %q must use TLS (set %s to permit a plaintext connection)", context, target, key)
	}
	log.Printf("WARNING: %s %q is using a plaintext (non-TLS) connection; %s is explicitly enabled", context, target, key)
	return nil
}

// RefuseScheme rejects addr's scheme when it equals disallowed — e.g. a
// Redis "unix" scheme pointing at a local domain-socket path, which carries
// no IP address for Dial to validate at all: a local-filesystem access
// vector, a different threat model than the network-egress SSRF guard this
// Guard exists to enforce, not something Dial (or any IP-based check) can
// meaningfully evaluate.
func RefuseScheme(scheme, disallowed, context string) error {
	if scheme == disallowed {
		return fmt.Errorf("netutil: %s scheme %q is refused: it names a local resource with no network "+
			"address for the egress guard to validate — a different threat model (local filesystem access) "+
			"than the network-SSRF guard this connector enforces", context, scheme)
	}
	return nil
}

// HTTPClient builds an *http.Client whose Transport dials exclusively
// through g.Dial, so every request this client makes — including a
// same-host redirect target checkRedirect allows through — gets the
// identical dial-time IP re-validation. Suitable for the SIEM/audit
// forwarder and any future outbound webhook-style client built on Guard.
func (g Guard) HTTPClient(timeout time.Duration, tlsConfig *tls.Config, checkRedirect func(*http.Request, []*http.Request) error) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: checkRedirect,
		Transport: &http.Transport{
			DialContext:     g.Dial.DialContext,
			TLSClientConfig: tlsConfig,
		},
	}
}

// RedisDialer adapts g.Dial to go-redis's Options.Dialer shape
// (func(ctx, network, addr) (net.Conn, error)). go-redis's own default
// dialer (NewDialer, in redis/go-redis's options.go) layers TLS itself atop
// the raw dial, but ONLY when Options.Dialer is left unset — setting a
// custom Dialer (required here to get the dial-time IP re-validation every
// other Guard-wired backend gets) takes over that responsibility entirely:
// without replicating the TLS layering here, every rediss:// admin DSN would
// silently downgrade to plaintext underneath a caller that configured TLS
// and has no way to notice it was dropped (confirmed by reading redis.go:
// the client calls nothing but c.opt.Dialer(ctx, network, addr) — there is
// no second, independent TLS step elsewhere in the library to fall back on).
//
// ServerName is derived from the ORIGINAL dial hostname (the addr this func
// receives), never the pinned IP g.Dial actually connects to underneath, so
// certificate verification still checks the real target name — the same
// hostname-for-TLS/IP-for-TCP split pgx and go-sql-driver/mysql already rely
// on for Postgres/MySQL (their own DialFunc only ever controls the raw TCP
// dial; each driver's TLS layer verifies against the original hostname
// independently).
func (g Guard) RedisDialer(tlsConfig *tls.Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := g.Dial.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		if tlsConfig == nil {
			return conn, nil
		}
		cfg := tlsConfig
		if cfg.ServerName == "" {
			if host, _, splitErr := net.SplitHostPort(addr); splitErr == nil && net.ParseIP(host) == nil {
				cloned := cfg.Clone()
				cloned.ServerName = host
				cfg = cloned
			}
		}
		tlsConn := tls.Client(conn, cfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("netutil: TLS handshake with %q: %w", addr, err)
		}
		return tlsConn, nil
	}
}

// srvLookup is net.DefaultResolver.LookupSRV's shape — a package-level var
// (not a Guard field) so it's overridable independently of any one Guard
// value, mirroring how internal/dynamic's dialResolve var lets tests
// substitute a fake DNS answer without a real query.
var srvLookup = net.DefaultResolver.LookupSRV

// ValidateSRVTargets pre-resolves the SRV record for name (service/proto,
// e.g. "mongodb"/"tcp") and validates every discovered target hostname
// against g.Dial's own resolve-and-validate policy (Dialer.ValidateHost) —
// closing a gap a bare TCP dial hook cannot see on its own.
//
// The MongoDB Go driver performs this exact SRV lookup internally, for a
// mongodb+srv:// URI, deep inside options.Client().ApplyURI — before any
// caller-supplied Dialer is ever invoked. Confirmed by reading the driver
// source (go.mongodb.org/mongo-driver/v2@v2.9.1): connstring.Parse's parser
// hardcodes dnsResolver to dns.DefaultResolver (x/mongo/driver/connstring/
// connstring.go:99), with no exported hook to override it, so a caller has
// no visibility into, or control over, which hostnames that internal step
// discovers. The actual per-server TCP dial for every server the driver ever
// connects to — SRV-discovered or not — DOES still funnel through whatever
// Dialer IS configured (x/mongo/driver/topology/connection.go:265,
// c.config.dialer.DialContext(ctx, c.addr.Network(), c.addr.String()),
// wired unconditionally from ClientOptions.Dialer regardless of discovery
// mode per x/mongo/driver/topology/topology_options.go), so g.Dial's own
// dial-time re-validation remains the authoritative, DNS-rebinding-safe
// check either way. This pre-check is defense-in-depth that turns a
// deep, less legible dial-time rejection (surfacing from inside the
// driver's connection pool, on whichever server it happens to try first)
// into one clear, fail-fast error before the URI is ever handed to the
// driver at all.
func (g Guard) ValidateSRVTargets(ctx context.Context, service, proto, name string) error {
	_, srvs, err := srvLookup(ctx, service, proto, name)
	if err != nil {
		return fmt.Errorf("netutil: resolve SRV record for %q: %w", name, err)
	}
	if len(srvs) == 0 {
		return fmt.Errorf("netutil: SRV record for %q returned no targets", name)
	}
	for _, srv := range srvs {
		target := strings.TrimSuffix(srv.Target, ".")
		if err := g.Dial.ValidateHost(ctx, target); err != nil {
			return fmt.Errorf("netutil: SRV target %q for %q: %w", target, name, err)
		}
	}
	return nil
}
