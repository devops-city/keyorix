package configs

import (
	"bytes"
	"fmt"
)

// devBanner opens every config `keyorix-server admin init --dev` writes.
const devBanner = `# ============================================================================
# DEV-ONLY CONFIG — written by ` + "`keyorix-server admin init --dev`" + `.
# NOT FOR PRODUCTION OR ANY NETWORK-REACHABLE HOST.
#
# Relaxed on purpose so a local demo runs with no certificate and no token:
#   - TLS off and not required (security.insecure_allow_cleartext_transport)
#   - rate limiting off (server.insecure_disable_api_ratelimit)
#   - GET /metrics unauthenticated (server.insecure_allow_unauthenticated_metrics)
# ` + "`keyorix-server admin validate --posture`" + ` reports each of these as a
# deviation. For a real install run ` + "`keyorix-server admin init`" + ` without --dev.
# ============================================================================
`

// devReplacement turns one part of the secure template into its relaxed form.
// Each `from` must occur exactly `count` times in DefaultConfigTemplate.
type devReplacement struct {
	from, to string
	count    int
}

// devReplacements derive the --dev config from the one shipped template (do not
// duplicate the template: embed.go). TestDevConfigTemplate asserts every entry
// applies, so a template edit that breaks one fails the build's tests instead
// of silently leaving a secure value in (or a relaxed value out of) --dev.
var devReplacements = []devReplacement{
	{
		from: "# keyorix_template.yaml\n",
		to:   devBanner + "#\n# keyorix_template.yaml\n",
		// The file header still describes the secure template; the banner above
		// says which settings this file relaxes.
		count: 1,
	},
	{
		from:  "      enabled: true\n      cert_file: \"certs/server.crt\"",
		to:    "      enabled: false  # DEV-ONLY: cleartext\n      cert_file: \"certs/server.crt\"",
		count: 2, // server.http.tls, server.grpc.tls
	},
	{
		from:  "      # 10/20 throttled an ordinary CLI session (QUICK_START, scripts/smoke.sh) with 429s.\n      enabled: true\n",
		to:    "      # 10/20 throttled an ordinary CLI session (QUICK_START, scripts/smoke.sh) with 429s.\n      enabled: false  # DEV-ONLY\n",
		count: 1, // server.http.ratelimit
	},
	{
		from:  "    ratelimit:\n      enabled: true\n",
		to:    "    ratelimit:\n      enabled: false  # DEV-ONLY\n",
		count: 1, // server.grpc.ratelimit
	},
	{
		from:  "    metrics_token_file: \"secrets/metrics_token\"\n",
		to:    "    # DEV-ONLY: no metrics_token_file -- /metrics is unauthenticated\n",
		count: 2,
	},
	{
		from:  "  require_transport_tls: true\n",
		to:    "  require_transport_tls: false  # DEV-ONLY\n",
		count: 1,
	},
}

// DevConfigTemplate returns the relaxed, DEV-ONLY-labelled config that
// `admin init --dev` writes: DefaultConfigTemplate with devReplacements applied.
func DevConfigTemplate() ([]byte, error) {
	out := DefaultConfigTemplate
	for _, r := range devReplacements {
		if n := bytes.Count(out, []byte(r.from)); n != r.count {
			return nil, fmt.Errorf("configs: dev template: %q occurs %d times in keyorix.yaml.tpl, want %d", r.from, n, r.count)
		}
		out = bytes.ReplaceAll(out, []byte(r.from), []byte(r.to))
	}
	return out, nil
}
