// secrets_cert_inv_s13_test.go — coverage sweep targeting uncovered branches in:
//   - secret_certificate.go      (GetSecretCertificate): suspended (400),
//     not-a-parseable-cert (400), permission denied (403), internal error (500)
//   - secrets_name_conformance.go (SecretNameConformance): bad project ID (400),
//     core error (500)
//   - secrets_name_conformance_deployment.go (DeploymentSecretNameConformance):
//     core error (500)
//   - secrets_inventory_csv.go       (SecretsInventoryCSV): bad project ID (400),
//     core error (500)
//   - secrets_inventory_deployment_csv.go (DeploymentSecretsInventoryCSV):
//     core error (500)
package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// selfSignedCertPEMS13 mints a self-signed P-256 cert and returns its PEM bytes.
func selfSignedCertPEMS13(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	notAfter := time.Now().Add(90 * 24 * time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "s13.example.com"},
		NotBefore:    notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{"s13.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// ── GetSecretCertificate: suspended secret → 400 ─────────────────────────────

// TestGetSecretCertificate_Suspended_S13 seeds a suspended secret that has a
// valid certificate value, then calls GetSecretCertificate.  InspectCertificate
// returns "secret is suspended" which the handler maps to 400.
func TestGetSecretCertificate_Suspended_S13(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	certPEM := selfSignedCertPEMS13(t)
	// Seed a suspended certificate-typed secret owned by user 1 (the test actor)
	// so EnforceSecretReadPermission passes via ownership, but InspectCertificate
	// still returns "secret is suspended".
	sec := &models.SecretNode{
		Name:      "suspended-cert-s13",
		IsSecret:  true,
		Status:    "suspended",
		Type:      "certificate",
		OwnerID:   1,
		ProjectID: 1,
	}
	require.NoError(t, db.Create(sec).Error)
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID:   sec.ID,
		VersionNumber:  1,
		EncryptedValue: certPEM,
	}).Error)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", fmt.Sprintf("%d", sec.ID),
	))
	w := httptest.NewRecorder()
	h.GetSecretCertificate(w, req)

	// ERRMAP-1 follow-up: a suspended secret is 409 SecretSuspended, as on the
	// value routes (it was 400 by string matching).
	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Equal(t, "SecretSuspended", wireOf(t, w).Error)
}

// ── GetSecretCertificate: non-parseable value → 400 ─────────────────────────

// TestGetSecretCertificate_NotParseable_S13 seeds an active certificate-typed
// secret whose value is not a valid X.509 cert.  InspectCertificate returns
// a message containing "not a parseable" which the handler maps to 400.
func TestGetSecretCertificate_NotParseable_S13(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	sec := &models.SecretNode{
		Name:      "bad-cert-s13",
		IsSecret:  true,
		Status:    "active",
		Type:      "certificate",
		OwnerID:   1,
		ProjectID: 1,
	}
	require.NoError(t, db.Create(sec).Error)
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID:   sec.ID,
		VersionNumber:  1,
		EncryptedValue: []byte("this-is-not-a-certificate"),
	}).Error)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", fmt.Sprintf("%d", sec.ID),
	))
	w := httptest.NewRecorder()
	h.GetSecretCertificate(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── GetSecretCertificate: permission denied → 403 ────────────────────────────

// TestGetSecretCertificate_PermissionDenied_S13 seeds a certificate-typed secret
// owned by a different user (999) so that the actor (UserID=1) has no ownership
// or share grant.  InspectCertificate returns "insufficient permissions" which
// contains "permission", mapping to 403 in the handler.
func TestGetSecretCertificate_PermissionDenied_S13(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	certPEM := selfSignedCertPEMS13(t)
	sec := &models.SecretNode{
		Name:      "foreign-cert-s13",
		IsSecret:  true,
		Status:    "active",
		Type:      "certificate",
		OwnerID:   999, // actor is UserID=1; no ownership or share
		ProjectID: 1,
	}
	require.NoError(t, db.Create(sec).Error)
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID:   sec.ID,
		VersionNumber:  1,
		EncryptedValue: certPEM,
	}).Error)

	// Use a non-admin UserID (99) with no project roles, ownership, or shares.
	// UserID=1 is the global admin seeded by freshCoreS12WithAdmin; the RBAC
	// fallback added in #r124 now grants admins access to all secrets, so we
	// must use an unprivileged actor to keep this "permission denied" branch
	// exercised.
	req := withUserCtxID2(withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", fmt.Sprintf("%d", sec.ID),
	), 99, "noperm-user")
	w := httptest.NewRecorder()
	h.GetSecretCertificate(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ── GetSecretCertificate: closed DB → non-401/non-400 ────────────────────────

// TestGetSecretCertificate_InternalError_S13 triggers a genuine DB-layer failure
// by closing the underlying *sql.DB before the handler runs.
func TestGetSecretCertificate_InternalError_S13(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", "1",
	))
	w := httptest.NewRecorder()
	h.GetSecretCertificate(w, req)

	// DB failure produces an error that doesn't match any special substring,
	// so the handler returns 500 (or possibly 404 if "not found" appears).
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)

	// G50: the raw driver error ("sql: database is closed") must never reach
	// the client — GetSecretCertificate's default branch must route through
	// clientSafe() instead of forwarding err.Error() verbatim.
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NotContains(t, w.Body.String(), "sql:")
	assert.NotContains(t, w.Body.String(), "database is closed")
	assert.Contains(t, w.Body.String(), "an internal error occurred")
}

// ── SecretNameConformance: bad project ID → 400 ──────────────────────────────

// TestSecretNameConformance_BadProjectID_S13 sends a non-numeric "id" param.
// The handler's strconv.ParseUint call fails and returns 400.
func TestSecretNameConformance_BadProjectID_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", "not-a-number",
	))
	w := httptest.NewRecorder()
	h.SecretNameConformance(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── SecretNameConformance: core error → 500 ──────────────────────────────────

// TestSecretNameConformance_CoreError_S13 enables a naming policy so that
// SecretNameConformance proceeds past the early-return, then closes the DB so
// the storage call fails and the handler returns 500.
func TestSecretNameConformance_CoreError_S13(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	// Must enable a policy before closing the DB: without a policy the function
	// early-returns (report, nil) before ever reaching storage.
	require.NoError(t, cs.SetSecretNamePolicy(core.SecretNamePolicy{
		Enabled: true,
		Pattern: "^[A-Z][A-Z0-9_]*$",
	}))
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", "1",
	))
	w := httptest.NewRecorder()
	h.SecretNameConformance(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── DeploymentSecretNameConformance: core error → 500 ────────────────────────

// TestDeploymentSecretNameConformance_CoreError_S13 enables the naming policy
// then closes the DB so that DeploymentSecretNameConformance fails on the
// ListProjects storage call and the handler returns 500.
func TestDeploymentSecretNameConformance_CoreError_S13(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	require.NoError(t, cs.SetSecretNamePolicy(core.SecretNamePolicy{
		Enabled: true,
		Pattern: "^[A-Z][A-Z0-9_]*$",
	}))
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.DeploymentSecretNameConformance(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── SecretsInventoryCSV: bad project ID → 400 ────────────────────────────────

// TestSecretsInventoryCSV_BadProjectID_S13 sends a non-numeric "id" param.
// The handler's strconv.ParseUint call fails and returns 400.
func TestSecretsInventoryCSV_BadProjectID_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", "bad",
	))
	w := httptest.NewRecorder()
	h.SecretsInventoryCSV(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── SecretsInventoryCSV: core error → 500 ────────────────────────────────────

// TestSecretsInventoryCSV_CoreError_S13 closes the DB before the call to
// h.coreService.SecretsInventory, exercising the 500 branch.
func TestSecretsInventoryCSV_CoreError_S13(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", "1",
	))
	w := httptest.NewRecorder()
	h.SecretsInventoryCSV(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── DeploymentSecretsInventoryCSV: core error → 500 ─────────────────────────

// TestDeploymentSecretsInventoryCSV_CoreError_S13 closes the DB before the call
// to h.coreService.DeploymentSecretsInventory, exercising the 500 branch.
func TestDeploymentSecretsInventoryCSV_CoreError_S13(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.DeploymentSecretsInventoryCSV(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
