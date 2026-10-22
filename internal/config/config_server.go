package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/keyorixhq/keyorix/internal/secretenv"
)

type ServerConfig struct {
	HTTP      ServerInstanceConfig `yaml:"http"`
	GRPC      ServerInstanceConfig `yaml:"grpc"`
	AccessLog AccessLogConfig      `yaml:"access_log,omitempty"`
	Log       LogConfig            `yaml:"log,omitempty"`
}

// Values of server.log.format.
const (
	LogFormatText = "text"
	LogFormatJSON = "json"
)

// LogConfig configures the server's log output format (not the audit trail).
type LogConfig struct {
	// Format is "" or "text" (default: the existing human-readable lines) or "json"
	// (one JSON object per line with ts, level, msg and, where known, request_id,
	// principal_type and route; see docs/operations/logging.md). Any other value is
	// rejected by Validate.
	Format string `yaml:"format,omitempty"`
}

// EffectiveFormat returns the format in effect: "text" when unset.
func (l LogConfig) EffectiveFormat() string {
	if l.Format == "" {
		return LogFormatText
	}
	return l.Format
}

func validateLogFormat(v string) error {
	switch v {
	case "", LogFormatText, LogFormatJSON:
		return nil
	}
	return fmt.Errorf("server.log.format: unknown value %q (want %q or %q)", v, LogFormatText, LogFormatJSON)
}

// Values of server.access_log.on_sink_stall.
const (
	// AccessLogOnSinkStallBlock (the default) makes a request wait when the
	// access-log queue is full because the log sink has stalled: no line is ever
	// lost, but every request stalls with the sink.
	AccessLogOnSinkStallBlock = "block"
	// AccessLogOnSinkStallDrop keeps serving when the sink stalls; lines past the
	// 1 MiB queue are dropped, counted, and reported.
	AccessLogOnSinkStallDrop = "drop"
)

// AccessLogConfig configures the HTTP access log (not the audit trail).
type AccessLogConfig struct {
	// OnSinkStall is what a request does when the access-log sink (stdout, a
	// pipe to a log collector) has stalled and the 1 MiB in-memory queue is full.
	//
	//   - "" or "block" (default): wait for the sink. No access-log line is ever
	//     lost; requests stall while the sink does.
	//   - "drop": keep serving secrets. Lines past the queue are dropped, counted
	//     (GET /api/v1/system/info security.access_log_dropped), and reported by a
	//     rate-limited warning plus a recovery line. The audit trail is unaffected:
	//     it is written separately and never dropped.
	//
	// Config file only, like the fast audit mode, since "drop" trades log
	// completeness for availability. Any other value is rejected by Validate.
	OnSinkStall string `yaml:"on_sink_stall,omitempty"`
}

// EffectiveOnSinkStall returns the mode in effect: "block" when unset.
func (a AccessLogConfig) EffectiveOnSinkStall() string {
	if a.OnSinkStall == "" {
		return AccessLogOnSinkStallBlock
	}
	return a.OnSinkStall
}

func validateAccessLogOnSinkStall(v string) error {
	switch v {
	case "", AccessLogOnSinkStallBlock, AccessLogOnSinkStallDrop:
		return nil
	}
	return fmt.Errorf("server.access_log.on_sink_stall: unknown value %q (want %q or %q)",
		v, AccessLogOnSinkStallBlock, AccessLogOnSinkStallDrop)
}

// DefaultBindHost is the listen address used when server.http.host /
// server.grpc.host is unset: loopback only. Reaching the server from another
// machine (a container, a Kubernetes pod, a LAN demo) is an explicit opt-in,
// e.g. host: "0.0.0.0". (#2939: the listeners used to bind all interfaces
// while the startup log claimed 127.0.0.1.)
const DefaultBindHost = "127.0.0.1"

type ServerInstanceConfig struct {
	Enabled bool `yaml:"enabled"`
	// Host is the address the listener binds to. Empty means DefaultBindHost
	// (loopback only). Use "0.0.0.0" or "::" to listen on all interfaces.
	Host             string    `yaml:"host"`
	Port             string    `yaml:"port"`
	ProtocolVersions []string  `yaml:"protocol_versions"`
	TLS              TLSConfig `yaml:"tls"`
	// TLSMode switches the TLS posture from the default (TLS 1.2 floor,
	// restricted to the forward-secret AEAD suites in hardenedCipherSuites /
	// tls.allowed_ciphers) to "strict": TLS 1.3 only, nothing below it ever
	// accepted. ADR-112 §3 (decided 2026-10-02): TLS 1.2 with modern ciphers
	// stays compliant, not an insecure_ opt-out — NIST SP 800-52 Rev. 2
	// requires servers to support both 1.2 and 1.3, BSI TR-02102-2 prefers
	// 1.3 while planning 1.2's phase-out, and OT/legacy clients still need
	// 1.2 — so "strict" is an explicit UPGRADE an operator opts INTO, not a
	// downgrade to warn about. Empty ("") = the default (1.2 floor); any
	// other value is rejected at Validate() time. See applyTLSHardening
	// (server/main.go, server/grpc/server.go) for where this is wired in.
	TLSMode           string          `yaml:"tls_mode,omitempty"`
	RateLimit         RateLimitConfig `yaml:"ratelimit"`
	SwaggerEnabled    bool            `yaml:"swagger_enabled,omitempty"`
	ReflectionEnabled bool            `yaml:"reflection_enabled,omitempty"`
	// MaxRequestBodyBytes caps each request body to mitigate memory-exhaustion DoS from
	// an oversized payload. 0 uses a generous default (10 MiB — well above any normal
	// JSON request); a negative value disables the cap (for endpoints that legitimately
	// accept very large bodies).
	MaxRequestBodyBytes int64 `yaml:"max_request_body_bytes,omitempty"`
	// TrustedProxies is the set of reverse-proxy/load-balancer source addresses (CIDRs
	// or bare IPs) whose X-Forwarded-For / X-Real-IP header is honored when deriving the
	// client IP. When empty, those headers are IGNORED and the real TCP peer is used —
	// so a client cannot spoof its source IP (which would otherwise defeat the per-IP
	// login/MFA rate limiter) unless it actually connects from a trusted proxy. Set this
	// to your ingress/LB CIDR(s) when running behind a proxy. (HTTP only.)
	TrustedProxies []string `yaml:"trusted_proxies,omitempty"`
	// HSTSPreload adds the "preload" directive to the Strict-Transport-Security header
	// (sent when this listener serves TLS, or a trusted proxy reports
	// X-Forwarded-Proto: https). Off by default: submitting a domain to the browser
	// preload lists covers every subdomain and is slow to undo, so only the domain's
	// owner opts in. (HTTP only.)
	HSTSPreload bool `yaml:"hsts_preload,omitempty"`
	// Web dashboard specific settings (HTTP only)
	WebAssetsPath  string   `yaml:"web_assets_path,omitempty"`
	AllowedOrigins []string `yaml:"allowed_origins,omitempty"`
	Domain         string   `yaml:"domain,omitempty"`
	// MetricsToken, when non-empty, requires callers to present a matching
	// "Authorization: Bearer <token>" header to reach GET /metrics. When empty
	// (the default) /metrics is unauthenticated — restrict network access at the
	// perimeter. Set this to a long random token for any internet-facing deployment.
	MetricsToken string `yaml:"metrics_token,omitempty"`
	// MetricsTokenFile names a file holding the metrics token instead (same rules
	// as a KEYORIX_*_FILE secret file: regular file, one trailing newline
	// stripped, must not be empty, owner/group-readable only). `keyorix-server
	// admin init` generates one at 0600 and points both listeners at it. Setting
	// both metrics_token and metrics_token_file refuses to start.
	MetricsTokenFile string `yaml:"metrics_token_file,omitempty"`
	// Keepalive tunes server-side connection keepalive/idle-reclaim (#222/#435). GRPC
	// only — an authenticated credential holder can otherwise open many long-lived,
	// mostly-idle connections that the server has no way to detect and reclaim, a
	// slow-drip goroutine/fd exhaustion surface distinct from the per-principal
	// concurrency cap already applied to StreamAuditLogs.
	Keepalive GRPCKeepaliveConfig `yaml:"keepalive,omitempty"`
}

// GRPCKeepaliveConfig tunes the gRPC server's keepalive ping and enforcement policy
// (#222/#435). Every field is a Go duration string (e.g. "5m", "20s"); empty/unparseable
// values fall back to the documented default via the Get* accessors below.
type GRPCKeepaliveConfig struct {
	// Time is how long the server waits on an idle connection before sending a
	// keepalive ping to check it's still alive. Default 5m when unset/unparseable.
	Time string `yaml:"time,omitempty"`
	// Timeout is how long the server waits for a ping ack before closing the
	// connection as dead. Default 20s when unset/unparseable.
	Timeout string `yaml:"timeout,omitempty"`
	// MinTime is the minimum interval a client is allowed to send keepalive pings on;
	// a client pinging more often than this is judged abusive and sent GOAWAY
	// ENHANCE_YOUR_CALM. Default 5m when unset/unparseable.
	MinTime string `yaml:"min_time,omitempty"`
	// PermitWithoutStream, if true, lets a client send keepalive pings even with no
	// active RPC/stream open. No client in this codebase pings without an active
	// call (StreamAuditLogs keeps its stream open for the duration it needs pings),
	// so this defaults to false — rejecting streamless pings closes off a cheap
	// ping-flood vector from a valid credential holder that never opens an RPC.
	PermitWithoutStream bool `yaml:"permit_without_stream,omitempty"`
	// MaxConnectionAge is the maximum duration a connection may be kept open before
	// the server sends a GOAWAY and begins graceful shutdown of that connection.
	// Forces periodic reconnection so stream-slot-holding attacks (GRPC-008) cannot
	// pin audit-stream slots indefinitely. Default 1h when unset/unparseable.
	MaxConnectionAge string `yaml:"max_connection_age,omitempty"`
	// MaxConnectionAgeGrace is how long after MaxConnectionAge the server waits for
	// active RPCs to finish before force-closing. Default 30s when unset/unparseable.
	MaxConnectionAgeGrace string `yaml:"max_connection_age_grace,omitempty"`
	// MaxConnectionIdle closes a connection that has had no RPC in flight for this
	// long. Keepalive pings alone never reclaim it: a live client acks them, so an
	// authenticated caller could otherwise park idle connections until the server
	// runs out of descriptors. Default 15m when unset/unparseable.
	MaxConnectionIdle string `yaml:"max_connection_idle,omitempty"`
	// HandshakeTimeout bounds a new connection's TLS handshake plus HTTP/2 preface.
	// grpc-go's own default is 120s, which lets a client that opens TCP and sends
	// nothing hold a connection for two minutes. Default 10s when unset/unparseable.
	HandshakeTimeout string `yaml:"handshake_timeout,omitempty"`
}

// defaultGRPCKeepaliveTime/Timeout/MinTime are the server-side keepalive defaults
// applied when the operator hasn't configured server.grpc.keepalive.* (#222/#435).
const (
	defaultGRPCKeepaliveTime         = 5 * time.Minute
	defaultGRPCKeepaliveTimeout      = 20 * time.Second
	defaultGRPCKeepaliveMinTime      = 5 * time.Minute
	defaultGRPCMaxConnectionAge      = 1 * time.Hour
	defaultGRPCMaxConnectionAgeGrace = 30 * time.Second
	defaultGRPCMaxConnectionIdle     = 15 * time.Minute
	defaultGRPCHandshakeTimeout      = 10 * time.Second
)

// GetTime returns the idle-before-ping interval (default 5m).
func (c GRPCKeepaliveConfig) GetTime() time.Duration {
	return parseDurationDefault(c.Time, defaultGRPCKeepaliveTime)
}

// GetTimeout returns the ping-ack wait before the connection is closed as dead
// (default 20s).
func (c GRPCKeepaliveConfig) GetTimeout() time.Duration {
	return parseDurationDefault(c.Timeout, defaultGRPCKeepaliveTimeout)
}

// GetMinTime returns the minimum interval a client may send keepalive pings on
// before being treated as abusive (default 5m).
func (c GRPCKeepaliveConfig) GetMinTime() time.Duration {
	return parseDurationDefault(c.MinTime, defaultGRPCKeepaliveMinTime)
}

func (c GRPCKeepaliveConfig) GetMaxConnectionAge() time.Duration {
	return parseDurationDefault(c.MaxConnectionAge, defaultGRPCMaxConnectionAge)
}

func (c GRPCKeepaliveConfig) GetMaxConnectionAgeGrace() time.Duration {
	return parseDurationDefault(c.MaxConnectionAgeGrace, defaultGRPCMaxConnectionAgeGrace)
}

// GetMaxConnectionIdle returns how long a connection may sit with no RPC in flight
// before the server closes it (default 15m).
func (c GRPCKeepaliveConfig) GetMaxConnectionIdle() time.Duration {
	return parseDurationDefault(c.MaxConnectionIdle, defaultGRPCMaxConnectionIdle)
}

// GetHandshakeTimeout returns the bound on a new connection's TLS handshake and
// HTTP/2 preface (default 10s).
func (c GRPCKeepaliveConfig) GetHandshakeTimeout() time.Duration {
	return parseDurationDefault(c.HandshakeTimeout, defaultGRPCHandshakeTimeout)
}

// defaultMaxRequestBodyBytes is the request-body cap when none is configured.
const defaultMaxRequestBodyBytes = 10 << 20 // 10 MiB

// ResolveMetricsToken returns the token GET /metrics requires: metrics_token, or
// the contents of metrics_token_file. "" with a nil error means no token is
// configured. Both set, or an unreadable/empty file, is an error, and the
// caller must not fall back to serving /metrics unauthenticated:
// Config.Validate refuses to start on it.
func (s ServerInstanceConfig) ResolveMetricsToken() (string, error) {
	switch {
	case s.MetricsToken != "" && s.MetricsTokenFile != "":
		return "", fmt.Errorf("both metrics_token and metrics_token_file are set; set exactly one")
	case s.MetricsTokenFile != "":
		v, err := secretenv.ReadFile(s.MetricsTokenFile)
		if err != nil {
			return "", fmt.Errorf("metrics_token_file %q: %w", s.MetricsTokenFile, err)
		}
		return v, nil
	}
	return s.MetricsToken, nil
}

// metricsTokenMissing reports whether either listener serves /metrics without a
// token. An unresolvable metrics_token_file counts as missing (fail closed).
func (c *Config) metricsTokenMissing() bool {
	for _, s := range []ServerInstanceConfig{c.Server.HTTP, c.Server.GRPC} {
		if tok, err := s.ResolveMetricsToken(); err != nil || tok == "" {
			return true
		}
	}
	return false
}

// EffectiveMaxRequestBodyBytes returns the request-body cap to enforce: the configured
// value, or a 10 MiB default when unset (0). A negative value is returned as-is and
// disables the cap at the middleware.
func (s ServerInstanceConfig) EffectiveMaxRequestBodyBytes() int64 {
	if s.MaxRequestBodyBytes == 0 {
		return defaultMaxRequestBodyBytes
	}
	return s.MaxRequestBodyBytes
}

// ErrGRPCAutoCertUnsupported refuses server.grpc.tls.auto_cert: true. ACME
// (autocert) is wired only for the HTTP listener; on gRPC the flag used to build
// a TLS config with no certificate, so the server started and every handshake
// failed. Config.Validate returns it, and server/grpc's NewServer refuses the
// same flag for a caller that skipped Validate.
var ErrGRPCAutoCertUnsupported = errors.New("server.grpc.tls.auto_cert: true is not supported: " +
	"automatic (ACME) certificates are only available for the HTTP listener (server.http.tls.auto_cert). " +
	"Remove server.grpc.tls.auto_cert and set server.grpc.tls.cert_file and key_file, " +
	"or terminate gRPC TLS at a proxy")

type TLSConfig struct {
	Enabled  bool     `yaml:"enabled"`
	AutoCert bool     `yaml:"auto_cert,omitempty"`
	Domains  []string `yaml:"domains,omitempty"`
	// CertCacheDir is the directory autocert uses to persist ACME certificates
	// between restarts. Defaults to "certs" (relative to the working directory).
	// Use an absolute path in production to avoid ambiguity. The directory is
	// created with mode 0700 (owner-only) on startup if it does not exist.
	CertCacheDir string `yaml:"cert_cache_dir,omitempty"`
	CertFile     string `yaml:"cert_file"`
	KeyFile      string `yaml:"key_file"`
	// AllowedCiphers optionally restricts the TLS 1.2 cipher suites offered to
	// SecureCipherSuiteNames' names (e.g. "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384").
	// Left empty/unset, the caller's own hardcoded secure AEAD-only default applies
	// unchanged (see ResolveCipherSuites, and server/main.go's + server/grpc/server.go's
	// applyTLSHardening, which wire this in — #333). Any name outside
	// SecureCipherSuiteNames — including weak/deprecated suites (RC4, 3DES, CBC-mode)
	// and TLS 1.3 suite names, which don't apply to CipherSuites at all — is rejected
	// at startup rather than silently ignored or accepted.
	AllowedCiphers []string `yaml:"allowed_ciphers"`
}

type RateLimitConfig struct {
	Enabled           bool `yaml:"enabled"`
	RequestsPerSecond int  `yaml:"requests_per_second"`
	Burst             int  `yaml:"burst"`
}

// BindHost returns the host the listener binds to: Host, or DefaultBindHost
// when unset.
func (s ServerInstanceConfig) BindHost() string {
	if s.Host == "" {
		return DefaultBindHost
	}
	return s.Host
}

// ListenAddr returns the host:port the listener binds to (IPv6-safe).
func (s ServerInstanceConfig) ListenAddr() string {
	return net.JoinHostPort(s.BindHost(), s.Port)
}

func validateBindHost(field, host string) error {
	if host == "" || net.ParseIP(host) != nil || host == "localhost" {
		return nil
	}
	return fmt.Errorf("%s %q is not an IP address (use 127.0.0.1, 0.0.0.0, ::1, :: or a specific interface IP)", field, host)
}

// validateAllowedOrigins rejects a misconfigured CORS allowlist (server.http.
// allowed_origins) at startup rather than letting it sit silently until it's
// proven wrong in the field. A bare "*" — which matches every origin — must not
// be configurable here: the caller must list explicit origins. Every entry must
// also be a well-formed origin: an http(s) scheme, a host, and nothing else (no
// path, query, fragment, userinfo, or trailing slash) — the exact shape
// Access-Control-Allow-Origin expects an Origin header to have.
func validateAllowedOrigins(origins []string) error {
	for _, o := range origins {
		if o == "*" {
			return fmt.Errorf("server.http.allowed_origins must not contain \"*\" — list explicit origins (e.g. https://app.example.com); a wildcard origin defeats the CORS allowlist")
		}
		u, err := url.Parse(o)
		if err != nil || u.Scheme == "" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return fmt.Errorf("server.http.allowed_origins entry %q is not a valid origin (expected scheme://host[:port], e.g. https://app.example.com)", o)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("server.http.allowed_origins entry %q must use http or https", o)
		}
	}
	return nil
}

// isLoopbackConfigHost reports whether host is a loopback hostname/literal, for
// the http-only-on-loopback dev exception in validateWebAuthnRP. Kept as a plain
// string check (no net import) — the set of loopback spellings a browser origin
// can carry is small and fixed, and this is a config-hygiene check, not a network
// guard.
func isLoopbackConfigHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

// validateServerSection checks server.http / server.grpc: TLS modes, log formats, bind hosts, ports,
// ciphers, CORS origins and TLS material (Validate step).
func validateServerSection(c *Config) error {
	if err := validateTLSMode("server.http.tls_mode", c.Server.HTTP.TLSMode); err != nil {
		return err
	}
	if err := validateTLSMode("server.grpc.tls_mode", c.Server.GRPC.TLSMode); err != nil {
		return err
	}
	if err := validateLogFormat(c.Server.Log.Format); err != nil {
		return err
	}
	if err := validateAccessLogOnSinkStall(c.Server.AccessLog.OnSinkStall); err != nil {
		return err
	}
	if err := validateBindHost("server.http.host", c.Server.HTTP.Host); err != nil {
		return err
	}
	if err := validateBindHost("server.grpc.host", c.Server.GRPC.Host); err != nil {
		return err
	}
	if c.Server.HTTP.Enabled && c.Server.HTTP.Port == "" {
		return fmt.Errorf("HTTP server is enabled but no port is specified")
	}

	if c.Server.GRPC.Enabled && c.Server.GRPC.Port == "" {
		return fmt.Errorf("gRPC server is enabled but no port is specified")
	}

	// A misspelled or weak tls.allowed_ciphers name is a config error: refuse it here,
	// with the other config errors, not after start-up lines that read as readiness
	// ("Startup validation passed", "HTTP server will bind ...") (BOOT-REFUSALS-1 item 8).
	for _, l := range []struct {
		name string
		inst ServerInstanceConfig
	}{{"server.http", c.Server.HTTP}, {"server.grpc", c.Server.GRPC}} {
		if !l.inst.Enabled {
			continue
		}
		if _, err := l.inst.TLS.ResolveCipherSuites(nil); err != nil {
			return fmt.Errorf("%s.%w", l.name, err)
		}
	}

	if err := validateAllowedOrigins(c.Server.HTTP.AllowedOrigins); err != nil {
		return err
	}

	if err := validateAutoCertForProfile(c, airgapProfile); err != nil {
		return err
	}

	if c.Server.HTTP.TLS.Enabled {
		if c.Server.HTTP.TLS.AutoCert {
			if len(c.Server.HTTP.TLS.Domains) == 0 {
				return fmt.Errorf("autocert is enabled but no domains are specified")
			}
		} else {
			if c.Server.HTTP.TLS.CertFile == "" || c.Server.HTTP.TLS.KeyFile == "" {
				return fmt.Errorf("TLS is enabled but cert_file or key_file is missing")
			}
		}
	}

	// gRPC has no ACME integration: auto_cert would build a TLS config with no
	// certificate, so every handshake fails while start-up succeeds (a silent
	// outage). Refused whether or not tls.enabled is set: with it unset the
	// listener used to serve plaintext to an operator who had asked for
	// certificates (AUTH-2 item 3).
	if c.Server.GRPC.TLS.AutoCert {
		return ErrGRPCAutoCertUnsupported
	}
	if c.Server.GRPC.TLS.Enabled {
		if c.Server.GRPC.TLS.CertFile == "" || c.Server.GRPC.TLS.KeyFile == "" {
			return fmt.Errorf("gRPC TLS is enabled but cert_file or key_file is missing")
		}
	}
	return nil
}
