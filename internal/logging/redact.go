package logging

import (
	"regexp"
	"strings"
)

// Redaction is defence in depth, not the primary control. The primary control is
// that call sites never pass a secret to a log function (TestNoSecretValuesInServerLogs
// drives a real server with canary secrets and fails if any appears). This scrubber
// catches the shapes that are recognisable by their form if one slips through
// anyway: Keyorix credentials, bearer tokens, key=value pairs for credential-like
// names, PEM private keys, JWTs and URL passwords. It cannot catch an arbitrary
// secret value (a database password in free text has no recognisable shape), which
// is why the canary test exists.
const redacted = "[REDACTED]"

var (
	rePEM = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)`)
	// Keyorix credentials: personal access, machine, dynamic-secret, setup and session tokens.
	reKXToken = regexp.MustCompile(`\bkx_(?:pat|machine|dyn|setup|session|admin_session)_[A-Za-z0-9_\-]{6,}`)
	// Authorization header values.
	reBearer = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=\-]{8,}`)
	// JSON Web Tokens (three dot-separated base64url segments, the first a JSON header).
	reJWT = regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*`)
	// key=value / key: value / "key":"value" for credential-like names. Group 1 is the
	// key and separator, group 2 the value (up to whitespace, quote, comma or brace).
	reKV = regexp.MustCompile(`(?i)\b([a-z0-9_.-]*(?:password|passwd|passphrase|secret|token|api[_-]?key|private[_-]?key|authorization|credential)s?["']?\s*[:=]\s*["']?)([^\s"',}]+)`)
	// Passwords embedded in URLs: scheme://user:password@host.
	reURLPass = regexp.MustCompile(`([a-z][a-z0-9+.\-]*://[^/\s:@]+:)[^@\s/]+(@)`)
)

// Redact returns s with recognisable credentials replaced by [REDACTED].
func Redact(s string) string {
	s = rePEM.ReplaceAllString(s, redacted)
	s = reKXToken.ReplaceAllString(s, "kx_"+redacted)
	s = reBearer.ReplaceAllStringFunc(s, func(m string) string {
		parts := reBearer.FindStringSubmatch(m)
		// "allows bearer credentials over cleartext" is prose, not a credential: real
		// tokens contain a digit or are long. Redact only those.
		tok := strings.TrimSpace(m[len(parts[1]):])
		if !hasDigit(tok) && len(tok) < 20 {
			return m
		}
		return parts[1] + " " + redacted
	})
	s = reJWT.ReplaceAllString(s, redacted)
	s = reURLPass.ReplaceAllString(s, "${1}"+redacted+"${2}")
	s = reKV.ReplaceAllStringFunc(s, func(m string) string {
		parts := reKV.FindStringSubmatch(m)
		key, val := parts[1], parts[2]
		// Numeric ids ("secret=12", "token_id=7") and already-scrubbed values are not
		// credentials; keeping them keeps real log lines diagnosable.
		if isDigits(val) || strings.HasPrefix(val, "[REDACTED]") || strings.HasPrefix(val, "kx_[REDACTED]") {
			return m
		}
		return key + redacted
	})
	return s
}

func hasDigit(s string) bool {
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
