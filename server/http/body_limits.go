package http

import (
	"net/http"
	"strings"
)

// Request-body caps per route class. The router applies them through one global
// middleware (MaxBodyBytesFor(requestBodyLimit(...))), so a route added under /auth/
// is capped by its class without anyone remembering to wire it.
const (
	// publicAuthBodyLimit caps every unauthenticated credential route: /auth/*
	// (login, refresh, MFA, WebAuthn, setup, password reset, SSO) and /system/init.
	// Their largest legitimate body is a WebAuthn assertion, a few KiB. Anyone on
	// the network can send these, so they are never allowed the 10 MiB API default.
	publicAuthBodyLimit int64 = 64 << 10
	// samlACSBodyLimit caps the SAML Assertion Consumer Service POST: a base64
	// SAMLResponse with a signed assertion, certificates and group claims, which
	// for a large IdP directory can reach a few hundred KiB.
	samlACSBodyLimit int64 = 1 << 20
)

// requestBodyLimit returns the per-request body cap: the route class's cap for the
// public credential routes, server.http.max_request_body_bytes (global) for
// everything else. A class cap is never raised by global, and is applied even when
// an operator disables the global cap (global <= 0): unauthenticated routes are
// always capped. The secret-value routes add their own, tighter cap in router.go
// (secretBodyLimit).
func requestBodyLimit(global int64) func(*http.Request) int64 {
	classCap := func(class int64) int64 {
		if global > 0 && global < class {
			return global
		}
		return class
	}
	return func(r *http.Request) int64 {
		p := r.URL.Path
		switch {
		case strings.HasPrefix(p, "/auth/saml/") && strings.HasSuffix(p, "/acs"):
			return classCap(samlACSBodyLimit)
		case strings.HasPrefix(p, "/auth/"), p == "/system/init":
			return classCap(publicAuthBodyLimit)
		}
		return global
	}
}
