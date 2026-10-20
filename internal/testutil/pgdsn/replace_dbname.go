package pgdsn

import (
	"fmt"
	"net/url"
	"strings"
)

func isURLDSN(s string) bool {
	return strings.HasPrefix(s, "postgres://") || strings.HasPrefix(s, "postgresql://")
}

// replaceURLDBName swaps the database (URL path) of a postgres:// DSN through
// net/url, so the userinfo (including a percent-encoded password), the host
// list and every query parameter (sslmode, search_path, ...) survive.
func replaceURLDBName(base, newName string) string {
	u, err := url.Parse(base)
	if err != nil {
		// Never return base unchanged: that is exactly the silent no-op that
		// pointed "isolated" tests at the shared database.
		panic(fmt.Sprintf("pgdsn: cannot parse URL DSN: %v", err))
	}
	u.Path = "/" + newName
	u.RawPath = ""
	return u.String()
}

// kvToken is one key=value pair of a libpq keyword/value DSN, as byte offsets
// into the original string so unrelated pairs are preserved verbatim.
type kvToken struct {
	key        string
	start, end int // whole pair, including the value's quotes
}

// scanKeywordValue tokenizes a libpq keyword/value DSN: `key=value` pairs
// separated by whitespace, optional whitespace around '=', values either bare
// or single-quoted, backslash escaping the next byte.
func scanKeywordValue(s string) []kvToken {
	var toks []kvToken
	i := 0
	for i < len(s) {
		for i < len(s) && isSpace(s[i]) {
			i++
		}
		if i >= len(s) {
			break
		}
		start := i
		for i < len(s) && s[i] != '=' && !isSpace(s[i]) {
			i++
		}
		key := s[start:i]
		for i < len(s) && isSpace(s[i]) {
			i++
		}
		if i >= len(s) || s[i] != '=' {
			// malformed token; skip it rather than guess
			continue
		}
		i++ // '='
		for i < len(s) && isSpace(s[i]) {
			i++
		}
		if i < len(s) && s[i] == '\'' {
			i++
			for i < len(s) && s[i] != '\'' {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				i++
			}
			if i < len(s) {
				i++ // closing quote
			}
		} else {
			for i < len(s) && !isSpace(s[i]) {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				i++
			}
		}
		toks = append(toks, kvToken{key: key, start: start, end: i})
	}
	return toks
}

func isSpace(b byte) bool { return b == ' ' || b == '\t' || b == '\n' || b == '\r' }

func quoteKVValue(v string) string {
	if v != "" && !strings.ContainsAny(v, " \t\n\r'\\") {
		return v
	}
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(v) + "'"
}

// replaceKeywordValueDBName rewrites every dbname= pair (the last one wins in
// libpq) and appends one when there is none. Other pairs, quoted passwords
// included, are copied byte for byte.
func replaceKeywordValueDBName(base, newName string) string {
	repl := "dbname=" + quoteKVValue(newName)
	toks := scanKeywordValue(base)
	var b strings.Builder
	last := 0
	found := false
	for _, t := range toks {
		if t.key != "dbname" {
			continue
		}
		found = true
		b.WriteString(base[last:t.start])
		b.WriteString(repl)
		last = t.end
	}
	b.WriteString(base[last:])
	if found {
		return b.String()
	}
	out := strings.TrimRight(b.String(), " \t\n\r")
	if out == "" {
		return repl
	}
	return out + " " + repl
}
