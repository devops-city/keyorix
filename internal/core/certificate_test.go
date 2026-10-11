package core

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// selfSignedPEM mints a self-signed P-256 cert valid until notAfter and returns its
// PEM, plus the PEM of its private key (to prove the key is never surfaced).
func selfSignedPEM(t *testing.T, cn string, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{cn, "www." + cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// caCertPEM mints a self-signed CA certificate valid until notAfter (IsCA=true),
// used to build leaf-last / CA-first chains.
func caCertPEM(t *testing.T, cn string, notAfter time.Time) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(9999),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notAfter.Add(-3650 * 24 * time.Hour),
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestParseLeafCertificate_OrderIndependent proves the expiry monitor can't be
// defeated by chain ordering or a corrupt leading block: parseLeafCertificate always
// surfaces the soonest-expiring end-entity (non-CA) leaf regardless of position.
func TestParseLeafCertificate_OrderIndependent(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	leafPEM, _ := selfSignedPEM(t, "leaf.example.com", base.Add(30*24*time.Hour)) // short-lived leaf
	caPEM := caCertPEM(t, "Root CA", base.Add(3650*24*time.Hour))                 // long-lived CA
	leafNotAfter := base.Add(30 * 24 * time.Hour)

	t.Run("CA-first bundle still yields the leaf's expiry", func(t *testing.T) {
		bundle := append(append([]byte{}, caPEM...), leafPEM...)
		cert, err := parseLeafCertificate(bundle)
		require.NoError(t, err)
		assert.False(t, cert.IsCA, "must select the end-entity leaf, not the CA")
		assert.WithinDuration(t, leafNotAfter, cert.NotAfter, time.Second)
	})

	t.Run("corrupt leading CERTIFICATE block does not hide the valid leaf", func(t *testing.T) {
		garbage := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a real der cert")})
		bundle := append(append([]byte{}, garbage...), leafPEM...)
		cert, err := parseLeafCertificate(bundle)
		require.NoError(t, err)
		assert.WithinDuration(t, leafNotAfter, cert.NotAfter, time.Second)
	})

	t.Run("all-CA bundle falls back to soonest-expiring CA", func(t *testing.T) {
		soonCA := caCertPEM(t, "Intermediate", base.Add(100*24*time.Hour))
		bundle := append(append([]byte{}, caPEM...), soonCA...)
		cert, err := parseLeafCertificate(bundle)
		require.NoError(t, err)
		assert.WithinDuration(t, base.Add(100*24*time.Hour), cert.NotAfter, time.Second)
	})
}

func newCertCore(t *testing.T, now time.Time) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.AuditEvent{},
		&models.ShareRecord{}, &models.Group{}, &models.UserGroup{}, &models.UserRole{},
		&models.SecretAccessSchedule{},
	))
	// CheckSecretPermission gates the owner path on IsProjectMember (RBAC-001): user 9
	// (the standard cert-test actor) must be a member of project 1 so the read succeeds.
	require.NoError(t, db.Create(&models.UserRole{UserID: 9, RoleID: 1, ProjectID: 1}).Error)
	return &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}, db
}

// mkCertSecret stores a secret (no encryption → value lives in the version row), owned
// by user 9 in project 1 — the actor ID every InspectCertificate call in this file uses.
func mkCertSecret(t *testing.T, db *gorm.DB, id uint, name, status string, value []byte) {
	t.Helper()
	require.NoError(t, db.Create(&models.SecretNode{ID: id, Name: name, IsSecret: true, Status: status, Type: "certificate", OwnerID: 9, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{SecretNodeID: id, VersionNumber: 1, EncryptedValue: value}).Error)
}

// TestParseLeafCertificate_AttemptBound pins that maxCertBlocks bounds the number
// of pem.Decode ATTEMPTS, not the number of successfully-parsed CERTIFICATE
// blocks: a value packed with maxCertBlocks non-CERTIFICATE blocks ahead of the
// real leaf exhausts the budget before ever reaching it, so the leaf is not
// found. One fewer padding block and it IS found — proving the bound is exact.
func TestParseLeafCertificate_AttemptBound(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	leafPEM, _ := selfSignedPEM(t, "leaf.example.com", base.Add(30*24*time.Hour))
	padding := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("dummy-key-bytes-not-a-real-key")})

	t.Run("real cert beyond the attempt budget is not found", func(t *testing.T) {
		var buf bytes.Buffer
		for i := 0; i < maxCertBlocks; i++ {
			buf.Write(padding)
		}
		buf.Write(leafPEM)
		_, err := parseLeafCertificate(buf.Bytes())
		require.Error(t, err, "the real cert sits at attempt maxCertBlocks+1 and must not be reached")
	})

	t.Run("real cert within the attempt budget is found", func(t *testing.T) {
		var buf bytes.Buffer
		for i := 0; i < maxCertBlocks-1; i++ {
			buf.Write(padding)
		}
		buf.Write(leafPEM)
		cert, err := parseLeafCertificate(buf.Bytes())
		require.NoError(t, err)
		assert.Equal(t, "leaf.example.com", cert.Subject.CommonName)
	})
}

func TestInspectCertificate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	c, db := newCertCore(t, now)
	certPEM, _ := selfSignedPEM(t, "example.com", now.Add(90*24*time.Hour))
	mkCertSecret(t, db, 1, "tls-cert", "active", certPEM)

	info, err := c.InspectCertificate(ctx, 9, 1)
	require.NoError(t, err)
	assert.Contains(t, info.Subject, "example.com")
	assert.Contains(t, info.Issuer, "example.com")
	assert.True(t, info.SelfSigned)
	assert.False(t, info.IsExpired)
	assert.Equal(t, 90, info.DaysUntilExpiry)
	assert.ElementsMatch(t, []string{"example.com", "www.example.com"}, info.DNSNames)
	assert.NotEmpty(t, info.SignatureAlgorithm)
	assert.Equal(t, "4242", info.SerialNumber)
}

// TestInspectCertificateCAIssuedWithMatchingSubjectIssuerString guards #CORE-CERT-003:
// SelfSigned used to be `cert.Subject.String() == cert.Issuer.String()`, a naive RDN
// string comparison. Here the CA and the leaf are given the IDENTICAL pkix.Name, so
// their rendered Subject/Issuer strings are byte-for-byte equal — exactly what the old
// check looked at — but the leaf is signed with the CA's private key, not its own: it is
// genuinely CA-issued, not self-signed. The cryptographic check (signature verified
// against the leaf's OWN public key) must correctly report SelfSigned:false, where the
// old string comparison would have wrongly reported true.
func TestInspectCertificateCAIssuedWithMatchingSubjectIssuerString(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	c, db := newCertCore(t, now)

	sharedName := pkix.Name{CommonName: "shared-name.example.com"}

	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               sharedName,
		NotBefore:             now.Add(-365 * 24 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caPriv.PublicKey, caPriv)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      sharedName, // identical to the CA's Subject → rendered strings match
		NotBefore:    now.Add(-30 * 24 * time.Hour),
		NotAfter:     now.Add(60 * 24 * time.Hour),
	}
	// Signed by the CA's key (caPriv), NOT the leaf's own key — genuinely CA-issued.
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafPriv.PublicKey, caPriv)
	require.NoError(t, err)

	// Sanity check the test setup actually exercises the regression: the old naive
	// check's inputs really must be equal, or this test proves nothing.
	parsedLeaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)
	require.Equal(t, parsedLeaf.Issuer.String(), parsedLeaf.Subject.String(),
		"test setup: Subject/Issuer strings must render identically")

	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	mkCertSecret(t, db, 1, "ca-issued-matching-strings", "active", leafPEM)

	info, err := c.InspectCertificate(ctx, 9, 1)
	require.NoError(t, err)
	assert.False(t, info.SelfSigned,
		"signature does not verify against the leaf's own key — must not be reported self-signed despite matching Subject/Issuer strings")
}

func TestInspectCertificateExpired(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	c, db := newCertCore(t, now)
	certPEM, _ := selfSignedPEM(t, "old.example.com", now.Add(-10*24*time.Hour)) // expired 10 days ago
	mkCertSecret(t, db, 1, "expired-cert", "active", certPEM)

	info, err := c.InspectCertificate(ctx, 9, 1)
	require.NoError(t, err)
	assert.True(t, info.IsExpired)
	assert.Less(t, info.DaysUntilExpiry, 0)
}

// A value that bundles the cert AND its private key (the common TLS layout) still
// parses to the cert, and the response never carries the key.
func TestInspectCertificateWithBundledKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	c, db := newCertCore(t, now)
	certPEM, keyPEM := selfSignedPEM(t, "bundle.example.com", now.Add(30*24*time.Hour))
	bundle := append(append([]byte{}, certPEM...), keyPEM...)
	mkCertSecret(t, db, 1, "tls-bundle", "active", bundle)

	info, err := c.InspectCertificate(ctx, 9, 1)
	require.NoError(t, err)
	assert.Contains(t, info.Subject, "bundle.example.com")
	// CertificateInfo has no field that could carry key material — public metadata only.
}

func TestInspectCertificateNotACert(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	c, db := newCertCore(t, now)
	mkCertSecret(t, db, 1, "db-password", "active", []byte("hunter2-not-a-cert"))

	_, err := c.InspectCertificate(ctx, 9, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certificate")
}

func TestInspectCertificateSuspended(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	c, db := newCertCore(t, now)
	certPEM, _ := selfSignedPEM(t, "frozen.example.com", now.Add(30*24*time.Hour))
	mkCertSecret(t, db, 1, "frozen", SecretStatusSuspended, certPEM)

	_, err := c.InspectCertificate(ctx, 9, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "suspended")
}

// TestInspectCertificateEnforcesPerSecretPermission guards #239: InspectCertificate
// used to call storage.GetSecret directly and rely solely on the caller's HTTP route
// being gated by scoped secrets.read, skipping the ownership/share-aware permission
// check every other per-secret value-derived read goes through (GetSecretWithPermissionCheck,
// GetSecretTags, GetSecretAccessStats, …). That let any actor holding project-wide
// secrets.read see a certificate's Subject/Issuer/SANs/serial number, even for a
// certificate they neither own nor were shared — a real information disclosure. This
// proves both directions: a non-owner/non-shared actor is now refused, and a share
// recipient still succeeds — no regression for the legitimate path.
func TestInspectCertificateEnforcesPerSecretPermission(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.AuditEvent{}, &models.ShareRecord{}, &models.Group{}, &models.UserGroup{}, &models.SecretAccessSchedule{}, &models.UserRole{}))
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}

	certPEM, _ := selfSignedPEM(t, "restricted.example.com", now.Add(30*24*time.Hour))
	require.NoError(t, db.Create(&models.SecretNode{ID: 1, Name: "restricted-cert", IsSecret: true, Status: "active", Type: "certificate", OwnerID: 9, ProjectID: 1}).Error)
	// #2941: a share applies only to a live member of the secret's project, so the
	// share recipient (7) is a member through a project-scoped grant of a role that
	// carries no permissions.
	require.NoError(t, db.Create(&models.UserRole{UserID: 7, RoleID: 999, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{SecretNodeID: 1, VersionNumber: 1, EncryptedValue: certPEM}).Error)

	t.Run("actor with no ownership/share is refused, despite the HTTP route already gating project-scoped secrets.read", func(t *testing.T) {
		_, err := c.InspectCertificate(ctx, 42, 1) // actor 42: no owner/share grant on secret 1
		require.Error(t, err)
		assert.Contains(t, err.Error(), "insufficient permissions")
	})

	t.Run("actor with an active share on the secret still succeeds — no regression", func(t *testing.T) {
		require.NoError(t, db.Create(&models.ShareRecord{ID: 1, SecretID: 1, OwnerID: 9, RecipientID: 7, IsGroup: false, Permission: "read"}).Error)
		info, err := c.InspectCertificate(ctx, 7, 1)
		require.NoError(t, err)
		assert.Contains(t, info.Subject, "restricted.example.com")
	})
}
