package handlers

import (
	"net/http"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/version"
)

// VersionInfo is the response body of GET /api/v1/version (ADR-108 PR 0's version-skew
// mechanism, docs/cli-split-inventory.md §5). Deliberately narrow: unlike
// /api/v1/system/info (system.read-gated, authenticated), this endpoint is
// unauthenticated -- a thin CLI must be able to check compatibility before it has any
// credentials -- so it exposes ONLY the two fields a version-skew check needs, never the
// build version or commit (health.go's CVE-targeting rationale for that omission applies
// here just as much, arguably more, since this endpoint's whole purpose is to be probed
// by an unauthenticated caller before login).
type VersionInfo struct {
	// APIVersion is the server's REST API version (internal/version.APIVersion). The CLI
	// refuses outright on a different major/minimum-version number; see
	// docs/cli-split-inventory.md §5 for the full tiered rule.
	APIVersion int `json:"api_version"`
	// MinimumCLIVersion is config.Config.MinimumCLIVersion, or "" when unset (no floor
	// beyond the same-major-version rule).
	MinimumCLIVersion string `json:"minimum_cli_version"`
}

// MakeVersionHandler returns a handler for GET /api/v1/version. Registered outside any
// authenticated route group (server/http/router.go), alongside /health and /system/init --
// see this file's own VersionInfo doc comment for why it stays narrow rather than folding
// into /api/v1/system/info.
func MakeVersionHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info := VersionInfo{
			APIVersion:        version.APIVersion,
			MinimumCLIVersion: cfg.MinimumCLIVersion,
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache")

		if err := encodeJSONResponse(w, info); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	}
}
