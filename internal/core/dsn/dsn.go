package dsn

import (
	"encoding/json"
	"net"
	"net/url"
	"slices"
	"strings"
)

// ParseDSNHosts extracts every host named by dsn under EVERY recognized
// admin_dsn reading (Kubernetes JSON, URL, libpq/mongo-style URI, MySQL
// tcp()/() wrapper, PostgreSQL key-value) and returns their union, first
// reading first. Every returned host is a candidate the connection may
// actually dial — a multi-host failover DSN can dial any of them, not just
// the first — so a caller validating hosts (e.g. core.validateAdminDSNHost)
// must check every one, not just the first.
//
// Union, not first match: this package does not know the backend type, and a
// first-match guess differed from what the driver does. pgx treats a string as
// a URL only when it starts with postgres:// or postgresql://, so
// "host=169.254.169.254 password=a://203.0.113.5" is key/value to pgx but was a
// URL naming 203.0.113.5 here; likewise a "@tcp(" inside a MySQL password, a
// repeated or quoted host=, a ?host= query override and a percent-encoded URL
// host (REVIEW-COVERAGE-1, TestParseDSNHosts_CoversWhatTheDriverDials). An
// extra candidate is a safe failure (it is validated too); a missing one is a
// register-time bypass. internal/dynamic's FuzzDSNHostsCoverDriverHosts checks
// the union against pgx, go-sql-driver/mysql and the mongo driver directly.
//
// Returns nil when no reading yields a host.
func ParseDSNHosts(dsn string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(hosts ...string) {
		for _, h := range hosts {
			if h != "" && !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	// The kubernetes backend's admin_dsn is a JSON blob ({"api_server": "https://
	// host:port", ...}, see internal/dynamic/kubernetes.go), not a URL/wrapper/
	// key-value DSN string -- a JSON blob embedding "https://" mid-string doesn't
	// parse as a URL (url.Parse requires the scheme at the start), so before this
	// reading existed it fell through to "unrecognised format, skip validation",
	// silently bypassing validateAdminDSNHost's private-IP/IMDS guard.
	add(parseKubernetesConfigHosts(dsn)...)
	// URL-form DSNs (any scheme that carries ://host), including a multi-host
	// comma-separated host list, read both the net/url way and the libpq/mongo
	// way (first '@' ends userinfo, percent-decoded host list, ?host= override).
	if strings.Contains(dsn, "://") {
		if hosts, ok := ParseDSNHostsFromURL(dsn); ok {
			add(hosts...)
		}
		add(uriStyleHosts(dsn)...)
	}
	// MySQL: the driver's own split (last '/', last '@' before it, first '('),
	// then the older marker scans, which also catch a DSN with no '/'.
	add(mysqlDriverHost(dsn))
	if h, ok := ParseDSNHostFromWrapper(dsn, "@tcp("); ok {
		add(h)
	}
	if h, ok := ParseDSNHostFromWrapper(dsn, "@("); ok {
		add(h)
	}
	// PostgreSQL key-value: every host= (and hostaddr=) value, libpq-tokenized.
	add(ParseDSNHostsFromKeyValue(dsn)...)
	if len(out) == 0 {
		return nil
	}
	return out
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
	hosts := parseKubernetesConfigHosts(dsn)
	if len(hosts) == 0 {
		return "", false
	}
	return hosts[0], true
}

// parseKubernetesConfigHosts is ParseDSNHostFromKubernetesConfig returning every
// host of api_server (both URL readings), not just the first.
func parseKubernetesConfigHosts(dsn string) []string {
	var cfg struct {
		APIServer string `json:"api_server"`
	}
	if err := json.Unmarshal([]byte(dsn), &cfg); err != nil || strings.TrimSpace(cfg.APIServer) == "" {
		return nil
	}
	hosts, _ := ParseDSNHostsFromURL(cfg.APIServer)
	for _, h := range uriStyleHosts(cfg.APIServer) {
		if !slices.Contains(hosts, h) {
			hosts = append(hosts, h)
		}
	}
	return hosts
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

// uriStyleHosts reads a URL-form DSN the way pgx (pgconn/parse_url.go, a port of
// libpq's URI parser) and the mongo driver (x/mongo/driver/connstring) do, which
// is not the net/url way:
//   - userinfo ends at the FIRST '@' that comes before any '/', even one inside
//     what looks like a query string;
//   - the authority runs to the next '/' or '?';
//   - the host list is percent-decoded: pgx decodes the joined list and then
//     splits on ',' (so %2C separates hosts), mongo splits and then decodes each
//     element; both readings are returned;
//   - pgx lets a ?host= query parameter override the authority's hosts.
//
// hostaddr= is returned too: libpq dials it instead of resolving host (pgx keeps
// it as a runtime parameter, so this is over-inclusive for pgx).
func uriStyleHosts(dsn string) []string {
	_, p, ok := strings.Cut(dsn, "://")
	if !ok {
		return nil
	}
	if i := strings.IndexAny(p, "@/"); i >= 0 && p[i] == '@' {
		p = p[i+1:]
	}
	// mongo reading: the authority up to '/' or '?', split on ',', each element
	// decoded, then host:port / [v6]:port split.
	end := strings.IndexAny(p, "/?")
	if end < 0 {
		end = len(p)
	}
	var hosts []string
	for part := range strings.SplitSeq(p[:end], ",") {
		// mongo uses url.QueryUnescape, which also reads '+' as a space.
		hosts = append(hosts, SplitDSNHostList(percentDecodeLenient(strings.ReplaceAll(part, "+", " ")))...)
		hosts = append(hosts, SplitDSNHostList(percentDecodeLenient(part))...)
	}
	// pgx reading (parse_url.go's netloc loop): '[' runs to ']', otherwise a host
	// runs to the next ':', '/', '?' or ','; a ':port' runs to '/', '?' or ','.
	// The joined host list is decoded once and then split on ','.
	var raw []string
	for {
		if strings.HasPrefix(p, "[") {
			rb := strings.IndexByte(p, ']')
			if rb < 0 {
				break // pgx: unterminated IPv6 literal, refused
			}
			raw = append(raw, p[1:rb])
			p = p[rb+1:]
		} else {
			i := strings.IndexAny(p, ":/?,")
			if i < 0 {
				i = len(p)
			}
			raw = append(raw, p[:i])
			p = p[i:]
		}
		if strings.HasPrefix(p, ":") {
			i := strings.IndexAny(p, "/?,")
			if i < 0 {
				i = len(p)
			}
			p = p[i:]
		}
		if !strings.HasPrefix(p, ",") {
			break
		}
		p = p[1:]
	}
	for h := range strings.SplitSeq(percentDecodeLenient(strings.Join(raw, ",")), ",") {
		hosts = append(hosts, strings.TrimSpace(h))
	}
	// pgx: a ?host= query parameter overrides the netloc hosts.
	if _, query, ok := strings.Cut(p, "?"); ok {
		for pair := range strings.SplitSeq(query, "&") {
			k, v, ok := strings.Cut(pair, "=")
			if !ok {
				continue
			}
			if k = percentDecodeLenient(k); k == "host" || k == "hostaddr" {
				hosts = append(hosts, SplitDSNHostList(percentDecodeLenient(v))...)
			}
		}
	}
	return hosts
}

// percentDecodeLenient decodes every valid %XX escape and leaves anything else
// as it is, after trimming surrounding ASCII spaces (pgx's uriDecode skips them).
// Lenient on purpose: a strict decoder that gives up on one bad escape would
// return no candidate for a string the driver itself may still accept.
func percentDecodeLenient(s string) string {
	s = strings.Trim(s, " ")
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi, ok1 := unhex(s[i+1])
			lo, ok2 := unhex(s[i+2])
			if ok1 && ok2 {
				b.WriteByte(hi<<4 | lo)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func unhex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// mysqlDriverHost extracts the address host exactly the way go-sql-driver/mysql's
// ParseDSN finds it: the LAST '/', then the last '@' before it (userinfo may hold
// any byte, "@tcp(" included), then the first '(' after that, with the address
// running to the ')' just before the '/'. Returns "" when that shape is absent.
// A bare "user:pass@tcp/db" (no address) dials the driver default 127.0.0.1:3306;
// that is not returned here, the dial-time guard refuses it.
func mysqlDriverHost(dsn string) string {
	i := strings.LastIndexByte(dsn, '/')
	if i <= 0 || dsn[i-1] != ')' {
		return ""
	}
	j := strings.LastIndexByte(dsn[:i], '@') // -1 when there is no userinfo
	k := strings.IndexByte(dsn[j+1:i], '(')
	if k < 0 {
		return ""
	}
	addr := dsn[j+1+k+1 : i-1]
	if h, _, err := net.SplitHostPort(addr); err == nil && h != "" {
		return h
	}
	return addr
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
// DSN, splitting each value on comma so a multi-host DSN (host=h1,h2,h3
// port=p1,p2,p3 ...) yields every host rather than a single bogus comma-joined
// "host" that net.LookupHost will just fail to resolve.
//
// It tokenizes the way libpq and pgx (pgconn parseKeywordValueSettings) do --
// whitespace allowed around '=', single-quoted values, backslash escapes -- and
// returns the value of EVERY host= and hostaddr= occurrence: pgx keeps the last
// repeated key, so returning only the first let "host=<public> host=<IMDS>"
// validate one host and dial the other. A plain whitespace-field scan for a
// "host=" prefix (the previous reading) is kept as a second reading for strings
// the tokenizer gives up on part-way.
func ParseDSNHostsFromKeyValue(dsn string) []string {
	var hosts []string
	for _, kv := range keywordValuePairs(dsn) {
		if kv[0] == "host" || kv[0] == "hostaddr" {
			hosts = append(hosts, SplitDSNHostList(kv[1])...)
		}
	}
	for part := range strings.FieldsSeq(dsn) {
		if h, ok := strings.CutPrefix(part, "host="); ok {
			for _, c := range SplitDSNHostList(h) {
				if !slices.Contains(hosts, c) {
					hosts = append(hosts, c)
				}
			}
		}
	}
	return hosts
}

// keywordValuePairs is pgx's keyword/value tokenizer (pgconn/config.go
// parseKeywordValueSettings, itself libpq's conninfo_parse): every (key, value)
// pair in order, repeats included. On input pgx would reject it returns the
// pairs read before the error -- pgx then refuses the whole string, so those are
// candidates at worst.
func keywordValuePairs(s string) [][2]string {
	const space = " \t\n\r\v\f"
	var out [][2]string
	s = strings.TrimLeft(s, space)
	for len(s) > 0 {
		eq := strings.IndexByte(s, '=')
		if eq < 0 {
			return out
		}
		key := strings.Trim(s[:eq], space)
		if key == "" || strings.ContainsAny(key, space) {
			return out
		}
		s = strings.TrimLeft(s[eq+1:], space)
		var val string
		switch {
		case len(s) == 0:
		case s[0] != '\'':
			end := 0
			for ; end < len(s) && !strings.ContainsRune(space, rune(s[end])); end++ {
				if s[end] == '\\' {
					end++
					if end == len(s) {
						break
					}
				}
			}
			val = unescapeKeywordValue(s[:end])
			s = strings.TrimLeft(s[end:], space)
		default:
			s = s[1:]
			end := 0
			for ; end < len(s) && s[end] != '\''; end++ {
				if s[end] == '\\' {
					end++
				}
			}
			if end >= len(s) {
				return out // unterminated quote: pgx refuses the string
			}
			val = unescapeKeywordValue(s[:end])
			s = strings.TrimLeft(s[end+1:], space)
		}
		out = append(out, [2]string{key, val})
	}
	return out
}

// unescapeKeywordValue drops each backslash and keeps the byte after it
// literally (libpq's rule; a trailing backslash is dropped).
func unescapeKeywordValue(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			if i == len(s) {
				break
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
