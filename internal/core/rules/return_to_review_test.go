package rules

import (
	"net/url"
	"testing"
)

// TestSanitizeReturnTo_OpenRedirectShapes is the REVIEW-COVERAGE-1 table for
// the SSO returnTo sanitizer. The value is handed to the SPA in the login
// fragment and used with react-router navigate (web/src/utils/routing.ts
// isSafeReturnTo re-checks it), so "accepted" must mean "an in-app path a
// browser cannot read as another origin", including after the WHATWG URL
// parser strips tab/newline and turns '\' into '/'.
func TestSanitizeReturnTo_OpenRedirectShapes(t *testing.T) {
	rejected := []string{
		"", "app", " /app", "\t/app",
		"//evil.com", "///evil.com", "//evil.com/app",
		`\\evil.com`, `/\evil.com`, `\/evil.com`, `/ok/\/evil.com`, `/%2F/..\evil`,
		"/\t/evil.com", "/\n/evil.com", "/\r/evil.com", "/\x00/evil.com", "/\x7f",
		"javascript:alert(1)", "JaVaScRiPt:alert(1)", " javascript:alert(1)",
		"data:text/html,x", "vbscript:x", "http://evil.com", "https:evil.com", "https:/evil.com",
		"//%65vil.com",
	}
	for _, s := range rejected {
		if got := SanitizeReturnTo(s); got != "" {
			t.Errorf("SanitizeReturnTo(%q) = %q, want rejection", s, got)
		}
	}
	// Accepted: same-origin in-app paths. Percent-encoded slashes and
	// backslashes stay encoded in a path (browsers do not decode them there).
	accepted := []string{
		"/", "/app", "/app/secrets?project=1#tab", "/@evil.com", "/app/../../evil",
		"/%2F%2Fevil.com", "/%5Cevil.com", "/%09/evil.com", "/café", "/a//b",
	}
	for _, s := range accepted {
		if got := SanitizeReturnTo(s); got != s {
			t.Errorf("SanitizeReturnTo(%q) = %q, want it accepted unchanged", s, got)
		}
	}
}

// The browser-normalisation oracle in FuzzReturnToOpenRedirectDifferential must
// be able to go red: on the shapes SanitizeReturnTo refuses for exactly this
// reason, it reports an off-origin target (proved without weakening the
// sanitizer).
func TestWhatwgPreprocess_OracleSeesBrowserOnlyRedirects(t *testing.T) {
	base, _ := url.Parse("https://keyorix.example.test/app/")
	for _, s := range []string{`/\evil.com`, "/\t/evil.com", "\x01//evil.com"} {
		ref, err := url.Parse(whatwgPreprocess(s))
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		if got := base.ResolveReference(ref).Hostname(); got != "evil.com" {
			t.Errorf("oracle normalises %q to host %q, want evil.com (oracle blind to this shape)", s, got)
		}
	}
}
