package dsn

import (
	"encoding/json"
	"net"
	"net/url"
	"strings"
)

// ParseDSNHosts extracts every host named by dsn, trying each recognized
// admin_dsn format in turn (Kubernetes JSON, URL, MySQL tcp()/() wrapper,
// PostgreSQL key-value). Every returned host is a candidate the connection
// may actually dial — a multi-host failover DSN can dial any of them, not
// just the first — so a caller validating hosts (e.g.
// core.validateAdminDSNHost) must check every one, not just the first.
//
// Returns nil when the format is unrecognised or no host can be extracted.
func ParseDSNHosts(dsn string) []string {
	// The kubernetes backend's admin_dsn is a JSON blob ({"api_server": "https://
	// host:port", ...}, see internal/dynamic/kubernetes.go), not a URL/wrapper/
	// key-value DSN string -- none of the checks below can extract a host from it
	// (a JSON blob embedding "https://" mid-string doesn't parse as a URL: url.Parse
	// requires the scheme at the start), so it fell through to the "unrecognised
	// format, skip validation" case, silently bypassing validateAdminDSNHost's
	// private-IP/IMDS guard for this one backend type. Try this first since it's
	// the most precise match for its exact shape.
	if h, ok := ParseDSNHostFromKubernetesConfig(dsn); ok {
		return []string{h}
	}
	// URL-form DSNs (any scheme that carries ://host), including a multi-host
	// comma-separated host list.
	if strings.Contains(dsn, "://") {
		if hosts, ok := ParseDSNHostsFromURL(dsn); ok {
			return hosts
		}
	}
	// MySQL tcp-wrapper: user:pass@tcp(host:port)/db
	if h, ok := ParseDSNHostFromWrapper(dsn, "@tcp("); ok {
		return []string{h}
	}
	// MySQL alternative wrapper: user:pass@(host:port)/db
	if h, ok := ParseDSNHostFromWrapper(dsn, "@("); ok {
		return []string{h}
	}
	// PostgreSQL key-value: scan for host=<value>, including a multi-host
	// comma-separated value.
	return ParseDSNHostsFromKeyValue(dsn)
}

// SplitDSNHostList splits a possibly comma-separated host (or host:port) list
// -- PostgreSQL's multi-host syntax, in either DSN form -- into individual
// hosts, stripping a per-entry port when present. A single, non-comma entry is
// the ordinary single-host case: it just comes back as a one-element list.
func SplitDSNHostList(field string) []string {
	var hosts []string
	for part := range strings.SplitSeq(field, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if h, _, err := net.SplitHostPort(part); err == nil && h != "" {
			hosts = append(hosts, h)
			continue
		}
		// net.SplitHostPort requires an explicit port, so a bracket-quoted
		// IPv6 literal with NO port (e.g. "[64:ff9b::8.8.8.8]" -- a legal
		// PostgreSQL multi-host URI entry that just uses the default port)
		// fails that call for want of one. Strip the brackets before giving
		// up, rather than carrying them into the "host" -- net.ParseIP (and
		// every guard downstream of it) rejects a bracket-wrapped literal
		// outright, which would otherwise fall through to net.LookupHost and
		// silently skip validation for exactly this shape.
		if strings.HasPrefix(part, "[") && strings.HasSuffix(part, "]") && len(part) > 1 {
			part = part[1 : len(part)-1]
		}
		hosts = append(hosts, part)
	}
	return hosts
}

// ParseDSNHostFromKubernetesConfig extracts the host from a kubernetes backend's
// JSON-shaped admin_dsn ({"api_server": "https://host:port", "token": "...",
// "ca_cert": "..."}, matching internal/dynamic.kubernetesConfig). A missing or
// empty api_server means in-cluster mode (KUBERNETES_SERVICE_HOST/PORT), which
// isn't attacker-influenceable, so there's nothing to validate.
func ParseDSNHostFromKubernetesConfig(dsn string) (string, bool) {
	var cfg struct {
		APIServer string `json:"api_server"`
	}
	if err := json.Unmarshal([]byte(dsn), &cfg); err != nil || strings.TrimSpace(cfg.APIServer) == "" {
		return "", false
	}
	hosts, ok := ParseDSNHostsFromURL(cfg.APIServer)
	if !ok || len(hosts) == 0 {
		return "", false
	}
	return hosts[0], true
}

// ParseDSNHostsFromURL extracts every host from a URL-form DSN's host
// component, splitting on comma first so a PostgreSQL multi-host URL
// (postgres://user@h1:5432,h2:5432,h3:5432/db) yields every host rather than
// failing net.SplitHostPort outright ("too many colons in address") and
// falling back to the whole unsplit string as a single bogus "host".
//
// url.Parse itself REJECTS a multi-host URL the moment any one host in the
// list is a bracket-quoted IPv6 literal (RFC 3986 requires the brackets, and
// PostgreSQL's own multi-host URI syntax permits mixing bracketed-IPv6 and
// plain-IPv4 hosts in one comma list) -- confirmed directly: url.Parse on
// "postgres://user@[64:ff9b::8.8.8.8]:5432,10.0.0.1:5432/db" fails with
// `invalid port ":5432,10.0.0.1:5432" after host`, because it treats
// everything after the closing bracket as a single port component and that
// text isn't pure digits. pgx.ParseConfig (the actual driver dialPostgres
// uses) parses and CONNECTS to this exact string without complaint. Before
// the ManualAuthorityHosts fallback below, that url.Parse error propagated
// all the way out of ParseDSNHosts (no other format matches either), and
// validateAdminDSNHost's "unrecognised format, can't extract host" branch
// treated the WHOLE DSN as unvalidatable -- a real, reachable SSRF bypass: an
// admin_dsn using this multi-host shape with a NAT64/6to4/Teredo/native-IPv6
// private or IMDS host anywhere in the list sailed through validation
// entirely while pgx happily dialed it.
func ParseDSNHostsFromURL(dsn string) ([]string, bool) {
	if u, err := url.Parse(dsn); err == nil && u.Host != "" {
		return SplitDSNHostList(u.Host), true
	}
	return ManualAuthorityHosts(dsn)
}

// ManualAuthorityHosts extracts a URL-form DSN's host-list authority segment
// (the text between "://" — or the last "@" before it, to skip userinfo —
// and the next "/", "?", or "#") by direct string scanning, bypassing
// url.Parse's authority grammar entirely. Only reached as a fallback when
// url.Parse itself rejects the DSN (see ParseDSNHostsFromURL's doc comment
// for the multi-host-plus-bracketed-IPv6 shape that triggers this).
// Deliberately simple and over-inclusive for a security check: extracting a
// spurious extra "host" candidate from a shape this doesn't fully understand
// is a safe failure (the candidate just gets validated too, and an
// unresolvable/malformed one is skipped exactly like any other unresolvable
// host); extracting too FEW hosts is not.
func ManualAuthorityHosts(dsn string) ([]string, bool) {
	_, after, ok := strings.Cut(dsn, "://")
	if !ok {
		return nil, false
	}
	rest := after
	end := len(rest)
	for i, c := range rest {
		if c == '/' || c == '?' || c == '#' {
			end = i
			break
		}
	}
	authority := rest[:end]
	if at := strings.LastIndex(authority, "@"); at != -1 {
		authority = authority[at+1:]
	}
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return nil, false
	}
	return SplitDSNHostList(authority), true
}

// ParseDSNHostFromWrapper extracts the host:port between marker and the next
// ')', used for both the MySQL "@tcp(" and "@(" wrapper forms.
func ParseDSNHostFromWrapper(dsn, marker string) (string, bool) {
	_, rest, ok := strings.Cut(dsn, marker)
	if !ok {
		return "", false
	}
	hostport, _, ok := strings.Cut(rest, ")")
	if !ok {
		return "", false
	}
	if h, _, _ := net.SplitHostPort(hostport); h != "" {
		return h, true
	}
	return hostport, true
}

// ParseDSNHostsFromKeyValue extracts every host from a PostgreSQL key-value
// DSN's host=<value>, splitting <value> on comma so a multi-host DSN
// (host=h1,h2,h3 port=p1,p2,p3 ...) yields every host rather than a single
// bogus comma-joined "host" that net.LookupHost will just fail to resolve.
func ParseDSNHostsFromKeyValue(dsn string) []string {
	for part := range strings.FieldsSeq(dsn) {
		if h, ok := strings.CutPrefix(part, "host="); ok {
			return SplitDSNHostList(h)
		}
	}
	return nil
}
