// sso_session_trusted_proxy_ip_test.go — #2934 item 4(b), the behind-a-proxy half.
// sso_session_client_ip_test.go pins that the SSO handlers pass clientIP(r), not
// r.RemoteAddr. This file pins what that buys: with the production ClientIP
// middleware in front (router.go), an SSO session records the forwarded client
// address when the TCP peer is a trusted proxy, and ignores a forged
// X-Forwarded-For from an untrusted peer.
package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	samlpkg "github.com/keyorixhq/keyorix/internal/saml"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

// samlSessionIPBehind runs one SAML ACS through ClientIP(trusted) from the given
// TCP peer carrying the given X-Forwarded-For, and returns the stored session IP.
func samlSessionIPBehind(t *testing.T, trusted []string, peer, xff string) string {
	t.Helper()
	stub := &stubAssertionSAML{info: &samlpkg.AssertionInfo{Subject: "sub-tp", Email: "tp-saml@example.com", Name: "TP"}}
	cs, db := freshCoreS12WithAdmin(t)
	seedSSODefaultRoleS13(t, cs)
	cs.SetSSOProviders(map[string]*core.SSOProvider{
		"corp": {Name: "corp", Type: "saml", SAML: stub, CompleteURL: "https://app.example/auth/sso/complete", AutoProvision: true},
	}, nil)
	h := NewAuthHandler(cs, false)
	require.NoError(t, db.Create(&models.SSOLoginState{
		State: "relay-tp", Nonce: "nonce-tp", Provider: "corp",
		ExpiresAt: time.Now().Add(10 * time.Minute), CreatedAt: time.Now(),
	}).Error)

	req := withChiParam(httptest.NewRequest(http.MethodPost, "/auth/saml/corp/acs",
		strings.NewReader("RelayState=relay-tp&SAMLResponse=stub")), "provider", "corp")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = peer
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	w := httptest.NewRecorder()
	customMiddleware.ClientIP(trusted)(http.HandlerFunc(h.CompleteSAML)).ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	require.NotContains(t, w.Header().Get("Location"), "error=")
	return lastSessionIP(t, db)
}

func TestCompleteSAML_SessionRecordsForwardedClientIPBehindTrustedProxy(t *testing.T) {
	got := samlSessionIPBehind(t, []string{"10.0.0.0/8"}, "10.1.2.3:44444", "198.51.100.9")
	assert.Equal(t, "198.51.100.9", got,
		"a trusted proxy's forwarded client address must be what the SSO session records, not the proxy's")
}

func TestCompleteSAML_SessionIgnoresForwardedHeaderFromUntrustedPeer(t *testing.T) {
	got := samlSessionIPBehind(t, []string{"10.0.0.0/8"}, "203.0.113.7:51234", "198.51.100.9")
	assert.Equal(t, "203.0.113.7", got,
		"an X-Forwarded-For from a peer that is not a trusted proxy is attacker-controlled and must be ignored")
}
