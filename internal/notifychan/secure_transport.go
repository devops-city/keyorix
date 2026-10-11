package notifychan

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
)

// validateEndpoint rejects a non-https notification endpoint — which would send the
// bearer token and payload in cleartext — allowing http only for a loopback target
// (local testing) or the explicit allowInsecureTransport opt-in. It also refuses a
// destination whose hostname RESOLVES to a private/link-local IP (e.g. cloud metadata
// 169.254.169.254 or an internal host) unless allowPrivateNetwork is set —
// SSRF/exfil hardening.
//
// allowPrivateNetwork and allowInsecureTransport are TWO INDEPENDENT knobs, not
// one (#130, plus a later fix closing a real conflation this file had until then):
// "I trust this endpoint's self-signed cert" (InsecureSkipVerify), "this endpoint
// is allowed to live on an internal network" (allowPrivateNetwork), and "this
// endpoint may be reached over plain, unencrypted HTTP" (allowInsecureTransport)
// are three different trust decisions. Before the split, a single
// allowPrivateNetwork bool gated BOTH the private/link-local-host check AND the
// https-required check — an operator opting in only to reach a legitimate
// on-prem receiver at a private address ALSO silently unlocked cleartext HTTP to
// any PUBLIC host, an unrelated and much broader exception nobody asked for.
// allowInsecureTransport defaults to false (deny), same as allowPrivateNetwork.
func validateEndpoint(raw string, allowPrivateNetwork, allowInsecureTransport bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("notifychan: invalid endpoint %q: %w", raw, err)
	}
	switch u.Scheme {
	case "https":
		// scheme OK; fall through to the destination-IP check
	case "http":
		if !allowInsecureTransport && !isLoopbackHost(u.Hostname()) {
			return fmt.Errorf("notifychan: endpoint %q must use https (set notifications.webhook.insecure_allow_plaintext_notify_transport only for a trusted internal or loopback target)", raw)
		}
	default:
		return fmt.Errorf("notifychan: endpoint %q must use https", raw)
	}
	if !allowPrivateNetwork {
		if err := refuseDisallowedHost(u.Hostname()); err != nil {
			return fmt.Errorf("notifychan: endpoint %q %w", raw, err)
		}
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// lookupIPAddr resolves a hostname to its IP addresses — a var so tests can
// substitute a fake resolver without a real DNS query.
var lookupIPAddr = func(host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(context.Background(), host)
}

// refuseDisallowedHost rejects host when it — or any address it RESOLVES to — is a
// private, link-local, or otherwise disallowed IP (loopback is permitted as a dev
// target). A literal-IP-only check lets a hostname like attacker.example (which
// resolves to 169.254.169.254 or an RFC 1918 address) straight through; this
// resolves the hostname and checks every returned address.
func refuseDisallowedHost(host string) error {
	if ip := net.ParseIP(host); ip != nil {
		if isDisallowedIP(ip) {
			return fmt.Errorf("targets a private/link-local address; refusing to send to an internal host")
		}
		return nil
	}
	addrs, err := lookupIPAddr(host)
	if err != nil {
		return fmt.Errorf("could not resolve hostname to verify it is not private/internal: %w", err)
	}
	for _, a := range addrs {
		if isDisallowedIP(a.IP) {
			return fmt.Errorf("resolves to a private/link-local address (%s); refusing to send to an internal host", a.IP)
		}
	}
	return nil
}

// isDisallowedIP reports whether ip is a private or link-local address (loopback is
// permitted as a dev target).
func isDisallowedIP(ip net.IP) bool {
	if ip.IsLoopback() {
		return false
	}
	return ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

// refuseRedirectDowngrade blocks a redirect to a different host or a downgrade from
// https to http, so a compromised/misbehaving endpoint cannot bounce the signed,
// token-bearing request to an internal or cleartext target (SSRF/exfil hardening).
func refuseRedirectDowngrade(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	prev := via[len(via)-1]
	if req.URL.Host != prev.URL.Host {
		return fmt.Errorf("notifychan: refusing cross-host redirect to %q", req.URL.Host)
	}
	if prev.URL.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("notifychan: refusing https->%s redirect", req.URL.Scheme)
	}
	return nil
}
