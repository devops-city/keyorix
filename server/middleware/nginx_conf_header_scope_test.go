package middleware

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// addHeaderInLocation returns the add_header lines of an nginx config that sit
// inside a location block. nginx does not inherit server-scope add_header into
// a location that sets any add_header of its own, so one such line silently
// drops every security header for that location (Semgrep
// generic.nginx.security.header-redefinition, CodeQL #1224). web/nginx.conf
// keeps every add_header at server scope for that reason.
//
// It tracks { } nesting per line after stripping # comments and quoted strings
// (the CSP value is quoted); it understands the plain block syntax web/nginx.conf
// uses, not every nginx construct.
func addHeaderInLocation(conf string) []string {
	quoted := regexp.MustCompile(`"[^"]*"|'[^']*'`)
	var stack []string
	var bad []string
	for raw := range strings.SplitSeq(conf, "\n") {
		line := raw
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		line = quoted.ReplaceAllString(line, `""`)
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "add_header") {
			for _, blk := range stack {
				if strings.HasPrefix(blk, "location") {
					bad = append(bad, strings.TrimSpace(raw))
					break
				}
			}
		}
		for i := 0; i < len(line); i++ {
			switch line[i] {
			case '{':
				head := strings.TrimSpace(line[:i])
				stack = append(stack, head)
			case '}':
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
			}
		}
	}
	return bad
}

// TestNginxConfNoAddHeaderInsideLocation is the #1224 guard: green on the real
// config, red on a config that re-adds a header in a location.
func TestNginxConfNoAddHeaderInsideLocation(t *testing.T) {
	data, err := os.ReadFile("../../web/nginx.conf") // #nosec G304 -- fixed relative path to a repo file
	require.NoError(t, err)
	assert.Empty(t, addHeaderInLocation(string(data)),
		"web/nginx.conf must keep every add_header at server scope; one inside a location drops the server-scope security headers there")
	assert.Regexp(t, regexp.MustCompile(`(?m)^\s*add_header\s+X-Frame-Options\s`), string(data),
		"sanity: server-scope add_header lines must exist or the check above is vacuous")
}

func TestAddHeaderInLocation_DetectsRedefinition(t *testing.T) {
	bad := `http {
    server {
        add_header X-Frame-Options "DENY" always; # server scope: fine
        location /x {
            add_header Cache-Control "no-store";
        }
        location / { return 200; }
    }
}`
	assert.Equal(t, []string{`add_header Cache-Control "no-store";`}, addHeaderInLocation(bad))

	good := `http { server {
        add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'none';" always;
        location /x { proxy_hide_header X-Frame-Options; }
    } }`
	assert.Empty(t, addHeaderInLocation(good))
}
