// encryption_s23_test.go — coverage uplift for internal/encryption (s23 round).
//
// Focus areas (functions with <80% coverage not already exercised elsewhere):
//   - EncryptChunked: default chunk size (chunkSize=0)
//   - DecryptChunked: inconsistent TotalChunks, duplicate index, invalid index
//   - DecryptWithAAD: bad base64 nonce path
//   - sweep_auth.go: dryRun=true (does not persist) for sessions, password resets,
//     api_clients, api_tokens; AAD-bound and legacy paths for dynamic_secret_configs
//     and dynamic_secret_leases; skip (empty field) path for api_clients
//   - keymanager_lifecycle: unwrapDEK bad DEK-size path (wrap/unwrap roundtrip)
//   - Service.RewrapDEKWithProvider (not-initialized guard)
//   - Service.AcquireSharedKeyLock idempotent-when-already-held path
//   - UpgradeAuthAAD with AAD-bound and legacy rows for DynamicSecretConfig/Lease
//   - GenerateKEK: zero iterations uses DefaultKEKIterations
//   - AAD helper format assertions
package encryption

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ─── local helpers ────────────────────────────────────────────────────────────

func s23ES(t *testing.T) *EncryptionService {
	t.Helper()
	es, err := NewEncryptionService(make([]byte, 32))
	require.NoError(t, err)
	return es
}

func s23DB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Session{},
		&models.APIToken{},
		&models.APIClient{},
		&models.PasswordReset{},
		&models.MFASecret{},
		&models.DynamicSecretConfig{},
		&models.DynamicSecretLease{},
		&models.SecretNode{},
		&models.SecretVersion{},
	))
	return db
}

func s23Svc(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "kek.salt",
	}
	svc := NewService(cfg, dir)
	require.NoError(t, svc.Initialize("s23-passphrase"))
	return svc
}

// ─── EncryptChunked: chunkSize=0 uses default 64 KB ─────────────────────────

func TestEncryptChunked_ZeroChunkSizeUsesDefault(t *testing.T) {
	es := s23ES(t)
	// 100 bytes → fits in one 64 KB default chunk
	data := bytes.Repeat([]byte("z"), 100)
	chunks, err := es.EncryptChunked(data, 0, "v1")
	require.NoError(t, err)
	assert.Len(t, chunks, 1)
	// Verify round-trip
	result, err := es.DecryptChunked(chunks)
	require.NoError(t, err)
	assert.Equal(t, data, result)
}

// ─── DecryptChunked: inconsistent TotalChunks across chunks ──────────────────

func TestDecryptChunked_InconsistentTotalChunks(t *testing.T) {
	es := s23ES(t)
	data := bytes.Repeat([]byte("a"), 20)
	chunks, err := es.EncryptChunked(data, 10, "v1")
	require.NoError(t, err)
	require.Len(t, chunks, 2)
	// Tamper: chunk[1] claims a different total count
	chunks[1].Metadata.TotalChunks = 99
	_, err = es.DecryptChunked(chunks)
	require.Error(t, err)
}

// ─── DecryptChunked: duplicate chunk index ───────────────────────────────────

func TestDecryptChunked_DuplicateIndex(t *testing.T) {
	es := s23ES(t)
	data := bytes.Repeat([]byte("b"), 20)
	chunks, err := es.EncryptChunked(data, 10, "v1")
	require.NoError(t, err)
	require.Len(t, chunks, 2)
	// Both chunks claim index 0
	chunks[1].Metadata.ChunkIndex = 0
	_, err = es.DecryptChunked(chunks)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate chunk index")
}

// ─── DecryptChunked: out-of-range chunk index ────────────────────────────────

func TestDecryptChunked_OutOfRangeIndex(t *testing.T) {
	es := s23ES(t)
	data := bytes.Repeat([]byte("c"), 20)
	chunks, err := es.EncryptChunked(data, 10, "v1")
	require.NoError(t, err)
	require.Len(t, chunks, 2)
	// index beyond the range [0, totalChunks)
	chunks[1].Metadata.ChunkIndex = 99
	_, err = es.DecryptChunked(chunks)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid chunk index")
}

// ─── DecryptWithAAD: bad base64 nonce ────────────────────────────────────────

func TestDecryptWithAAD_BadBase64Nonce(t *testing.T) {
	es := s23ES(t)
	enc := &EncryptedData{
		Data: []byte("some-data"),
		Metadata: EncryptionMetadata{
			Algorithm: aesCipherSuite,
			Nonce:     "not!valid!base64!!!",
		},
	}
	_, err := es.DecryptWithAAD(enc, []byte("aad"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode nonce")
}

// ─── DecryptWithAAD: wrong AAD causes tag failure ────────────────────────────

func TestDecryptWithAAD_WrongAADCausesFailure(t *testing.T) {
	es := s23ES(t)
	enc, err := es.EncryptWithAAD([]byte("payload"), "v1", []byte("correct-aad"))
	require.NoError(t, err)
	_, err = es.DecryptWithAAD(enc, []byte("wrong-aad"))
	require.Error(t, err)
}

// ─── GenerateKEK: zero iterations → DefaultKEKIterations ─────────────────────

func TestGenerateKEK_ZeroIterations(t *testing.T) {
	salt := make([]byte, 32)
	kek0 := GenerateKEK("pw", salt, 0)
	kekD := GenerateKEK("pw", salt, DefaultKEKIterations)
	assert.Equal(t, kekD, kek0)
	assert.Len(t, kek0, 32)
}

// ─── wrapKey / unwrapKey: short wrapped bytes ─────────────────────────────────

func TestUnwrapKey_TooShort(t *testing.T) {
	kek := make([]byte, 32)
	// GCM nonce is 12 bytes; 2-byte input is always too short
	_, err := unwrapKey([]byte{0x01, 0x02}, kek)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestWrapKey_ThenUnwrapKey_RoundTrip(t *testing.T) {
	kek := make([]byte, 32)
	plain := make([]byte, 32)
	for i := range plain {
		plain[i] = byte(i)
	}
	wrapped, err := wrapKey(plain, kek)
	require.NoError(t, err)
	assert.Greater(t, len(wrapped), 12)

	got, err := unwrapKey(wrapped, kek)
	require.NoError(t, err)
	assert.Equal(t, plain, got)
}

// ─── unwrapDEK: DEK wrong size ───────────────────────────────────────────────

// TestKeyManager_UnwrapDEK_WrongSize exercises the post-unwrap size guard in
// unwrapDEK by writing a valid AES-GCM-wrapped 16-byte payload (not 32) to
// disk so unwrapKey succeeds but the size check fires.
func TestKeyManager_UnwrapDEK_WrongSize(t *testing.T) {
	dir := t.TempDir()

	// Use a non-zero KEK so the FileKeyProvider's placeholder-rejection guard doesn't fire.
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i + 1)
	}

	// Wrap a 16-byte DEK (not 32) using the same AES-GCM scheme
	fakeDEK := make([]byte, 16) // wrong size
	wrapped, err := wrapKey(fakeDEK, kek)
	require.NoError(t, err)

	// Write it as the DEK file
	require.NoError(t, os.WriteFile(dir+"/dek.key", wrapped, 0600))
	// Write a valid 32-byte salt so ensureSaltExists is happy
	require.NoError(t, os.WriteFile(dir+"/kek.salt", make([]byte, 32), 0600))

	// Write the KEK as hex so FileKeyProvider can read it
	hexKEK := make([]byte, 64)
	for i, b := range kek {
		const hexDigits = "0123456789abcdef"
		hexKEK[i*2] = hexDigits[b>>4]
		hexKEK[i*2+1] = hexDigits[b&0xf]
	}
	kekPath := dir + "/test.kek"
	require.NoError(t, os.WriteFile(kekPath, hexKEK, 0600))

	km := NewKeyManager(dir, "dek.key", "kek.salt")
	km.SetKeyProvider(crypto.NewFileKeyProvider(kekPath))
	err = km.Initialize("")
	require.Error(t, err)
	// Error should mention invalid size or unwrap failure
	t.Logf("got expected error: %v", err)
}

// ─── Service.RewrapDEKWithProvider: not initialized ──────────────────────────

func TestService_RewrapDEKWithProvider_NotInitialized(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	svc := NewService(cfg, dir)
	err := svc.RewrapDEKWithProvider(crypto.NewPasswordKeyProvider("x", dir, "kek.salt"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

// ─── Service.AcquireSharedKeyLock: idempotent when already held ──────────────

func TestService_AcquireSharedKeyLock_IdempotentWhenAlreadyHeld(t *testing.T) {
	svc := s23Svc(t)
	// First acquisition
	require.NoError(t, svc.AcquireSharedKeyLock())
	// Second call while lock is held → no-op (serverLock != nil branch)
	require.NoError(t, svc.AcquireSharedKeyLock())
	svc.Shutdown()
}

// ─── Service.GetKeyVersion: initialized returns non-"unknown" ────────────────

func TestService_GetKeyVersion_Initialized(t *testing.T) {
	svc := s23Svc(t)
	v := svc.GetKeyVersion()
	assert.NotEmpty(t, v)
	assert.NotEqual(t, "unknown", v)
	svc.Shutdown()
}

// ─── Service.EncryptLargeSecret → DecryptLargeSecret round-trip ──────────────

func TestService_EncryptLargeSecret_RoundTrip(t *testing.T) {
	svc := s23Svc(t)
	// 200 KB → multiple 64 KB chunks
	plain := bytes.Repeat([]byte("x"), 200*1024)
	encChunks, _, err := svc.EncryptLargeSecret(plain, 64)
	require.NoError(t, err)
	assert.Greater(t, len(encChunks), 1)

	result, err := svc.DecryptLargeSecret(encChunks)
	require.NoError(t, err)
	assert.Equal(t, plain, result)
}

func TestService_DecryptLargeSecret_InvalidChunk(t *testing.T) {
	svc := s23Svc(t)
	// Pass a chunk that cannot be deserialized
	_, err := svc.DecryptLargeSecret([][]byte{[]byte("not-json")})
	require.Error(t, err)
}

// ─── UpgradeAuthAAD: DynamicSecretConfig with legacy row ─────────────────────

func TestUpgradeAuthAAD_DynamicSecretConfig_LegacyRow(t *testing.T) {
	svc := s23Svc(t)
	db := s23DB(t)
	es := svc.encryptionService
	kv := svc.keyManager.GetKeyVersion()

	// Legacy row (no AAD) — sweepDynamicSecretConfigs decrypts via Decrypt (no AAD)
	encLegacy, err := es.Encrypt([]byte("admin-dsn-legacy"), kv)
	require.NoError(t, err)
	legacyBytes, err := SerializeEncryptedData(encLegacy)
	require.NoError(t, err)
	legacyMeta, err := json.Marshal(encLegacy.Metadata)
	require.NoError(t, err)
	rowLegacy := &models.DynamicSecretConfig{
		Name:          "legacy-cfg",
		ProjectID:     1,
		EnvironmentID: 2,
		AdminDSNEnc:   legacyBytes,
		AdminDSNMeta:  legacyMeta,
	}
	require.NoError(t, db.Create(rowLegacy).Error)

	result, err := svc.UpgradeAuthAAD(db)
	require.NoError(t, err)
	assert.Equal(t, 1, result.DynamicSecretConfigsSwept)
	assert.Equal(t, 1, result.LegacyAADUpgraded)
}

// ─── sweepDynamicSecretLeases: dryRun=true does not persist ─────────────────

func TestSweepDynamicSecretLeases_DryRun_DoesNotPersist(t *testing.T) {
	db := s23DB(t)
	es := s23ES(t)

	leaseID := "dry-run-lease-01"
	configID := uint(5)
	aad := DynamicSecretLeaseAAD(leaseID, configID)
	enc, err := es.EncryptWithAAD([]byte("cred"), "v1", aad)
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	origBytes := make([]byte, len(encBytes))
	copy(origBytes, encBytes)

	row := &models.DynamicSecretLease{
		LeaseID:        leaseID,
		ConfigID:       configID,
		Status:         "active",
		CredentialEnc:  encBytes,
		CredentialMeta: metaBytes,
	}
	require.NoError(t, db.Create(row).Error)

	swept, _, err := sweepDynamicSecretLeases(db, es, es, "v2", true /* dryRun */)
	require.NoError(t, err)
	assert.Equal(t, 1, swept)

	// Row in DB must not have changed
	var updated models.DynamicSecretLease
	require.NoError(t, db.First(&updated, row.ID).Error)
	assert.Equal(t, origBytes, []byte(updated.CredentialEnc))
}

// ─── sweepDynamicSecretConfigs: dryRun=true does not persist ─────────────────

func TestSweepDynamicSecretConfigs_DryRun_DoesNotPersist(t *testing.T) {
	db := s23DB(t)
	es := s23ES(t)

	// Legacy row (no AAD) — decrypt path goes through oldSvc.Decrypt
	enc, err := es.Encrypt([]byte("dsn"), "v1")
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	orig := make([]byte, len(encBytes))
	copy(orig, encBytes)

	row := &models.DynamicSecretConfig{Name: "dry-cfg", ProjectID: 2, AdminDSNEnc: encBytes}
	require.NoError(t, db.Create(row).Error)

	swept, _, err := sweepDynamicSecretConfigs(db, es, es, "v2", true)
	require.NoError(t, err)
	assert.Equal(t, 1, swept)

	var updated models.DynamicSecretConfig
	require.NoError(t, db.First(&updated, row.ID).Error)
	assert.Equal(t, orig, []byte(updated.AdminDSNEnc))
}

// ─── sweepPasswordResets: dryRun=true does not persist ───────────────────────

func TestSweepPasswordResets_DryRun_DoesNotPersist(t *testing.T) {
	db := s23DB(t)
	es := s23ES(t)
	enc, err := es.Encrypt([]byte("reset-tok"), "v1")
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	orig := make([]byte, len(encBytes))
	copy(orig, encBytes)

	row := &models.PasswordReset{UserID: 20, Token: "hash20", EncryptedToken: encBytes}
	require.NoError(t, db.Create(row).Error)

	swept, _, err := sweepPasswordResets(db, es, es, "v2", true)
	require.NoError(t, err)
	assert.Equal(t, 1, swept)

	var updated models.PasswordReset
	require.NoError(t, db.First(&updated, row.ID).Error)
	assert.Equal(t, orig, []byte(updated.EncryptedToken))
}

// ─── sweepAPIClients: dryRun=true does not persist ──────────────────────────

func TestSweepAPIClients_DryRun_DoesNotPersist(t *testing.T) {
	db := s23DB(t)
	es := s23ES(t)
	enc, err := es.Encrypt([]byte("client-secret"), "v1")
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)
	orig := make([]byte, len(encBytes))
	copy(orig, encBytes)

	row := &models.APIClient{
		Name:                  "dry-client",
		ClientID:              "cid-dry",
		ClientSecret:          "hsh",
		EncryptedClientSecret: encBytes,
		ClientSecretMetadata:  models.JSON(metaBytes),
	}
	require.NoError(t, db.Create(row).Error)

	swept, err := sweepAPIClients(db, es, es, "v2", true)
	require.NoError(t, err)
	assert.Equal(t, 1, swept)

	var updated models.APIClient
	require.NoError(t, db.First(&updated, row.ID).Error)
	assert.Equal(t, orig, []byte(updated.EncryptedClientSecret))
}

// ─── sweepAPITokens: dryRun=true does not persist ───────────────────────────

func TestSweepAPITokens_DryRun_DoesNotPersist(t *testing.T) {
	db := s23DB(t)
	es := s23ES(t)
	enc, err := es.Encrypt([]byte("api-tok"), "v1")
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)
	orig := make([]byte, len(encBytes))
	copy(orig, encBytes)

	row := &models.APIToken{
		Token:          "hsh-tok",
		EncryptedToken: encBytes,
		TokenMetadata:  models.JSON(metaBytes),
	}
	require.NoError(t, db.Create(row).Error)

	swept, _, err := sweepAPITokens(db, es, es, "v2", true)
	require.NoError(t, err)
	assert.Equal(t, 1, swept)

	var updated models.APIToken
	require.NoError(t, db.First(&updated, row.ID).Error)
	assert.Equal(t, orig, []byte(updated.EncryptedToken))
}

// ─── sweepMFASecrets: dryRun=true does not persist ───────────────────────────

func TestSweepMFASecrets_DryRun_DoesNotPersist(t *testing.T) {
	db := s23DB(t)
	es := s23ES(t)
	// AAD-bound row
	userID := uint(77)
	aad := MFASecretAAD(userID)
	enc, err := es.EncryptWithAAD([]byte("totp-seed"), "v1", aad)
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)
	orig := make([]byte, len(encBytes))
	copy(orig, encBytes)

	row := &models.MFASecret{UserID: userID, SecretEnc: encBytes, SecretMeta: metaBytes}
	require.NoError(t, db.Create(row).Error)

	swept, _, err := sweepMFASecrets(db, es, es, "v2", true)
	require.NoError(t, err)
	assert.Equal(t, 1, swept)

	var updated models.MFASecret
	require.NoError(t, db.First(&updated, row.ID).Error)
	assert.Equal(t, orig, []byte(updated.SecretEnc))
}

// ─── sweepDynamicSecretLeases: legacy row is upgraded (not dry-run) ──────────

func TestSweepDynamicSecretLeases_LegacyBecomesAADBound(t *testing.T) {
	db := s23DB(t)
	es := s23ES(t)

	// Encrypt without AAD (legacy, no AADVersion in metadata)
	enc, err := es.Encrypt([]byte("old-cred"), "v1")
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	row := &models.DynamicSecretLease{
		LeaseID:        "legacy-001",
		ConfigID:       3,
		Status:         "active",
		CredentialEnc:  encBytes,
		CredentialMeta: metaBytes,
	}
	require.NoError(t, db.Create(row).Error)

	swept, legacyUpgraded, err := sweepDynamicSecretLeases(db, es, es, "v1", false)
	require.NoError(t, err)
	assert.Equal(t, 1, swept)
	assert.Equal(t, 1, legacyUpgraded)
}

// ─── sweepDynamicSecretLeases: skip row with empty CredentialEnc ─────────────

func TestSweepDynamicSecretLeases_SkipsEmptyCredential(t *testing.T) {
	db := s23DB(t)
	es := s23ES(t)
	row := &models.DynamicSecretLease{LeaseID: "no-cred", ConfigID: 1, Status: "active"}
	require.NoError(t, db.Create(row).Error)

	swept, _, err := sweepDynamicSecretLeases(db, es, es, "v1", false)
	require.NoError(t, err)
	assert.Equal(t, 0, swept)
}

// ─── sweepDynamicSecretConfigs: AAD-bound row is re-encrypted ────────────────

func TestSweepDynamicSecretConfigs_AADBoundRow(t *testing.T) {
	db := s23DB(t)
	es := s23ES(t)

	// Insert placeholder first to learn the ID
	row := &models.DynamicSecretConfig{Name: "aad-cfg", ProjectID: 3, EnvironmentID: 4}
	require.NoError(t, db.Create(row).Error)

	// Now encrypt with matching AAD
	aad := DynamicSecretConfigAAD(row.ID, row.ProjectID, row.EnvironmentID)
	enc, err := es.EncryptWithAAD([]byte("real-dsn"), "v1", aad)
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	require.NoError(t, db.Model(row).Updates(map[string]any{
		"admin_dsn_enc":  encBytes,
		"admin_dsn_meta": metaBytes,
	}).Error)

	swept, legacyUpgraded, err := sweepDynamicSecretConfigs(db, es, es, "v1", false)
	require.NoError(t, err)
	assert.Equal(t, 1, swept)
	assert.Equal(t, 0, legacyUpgraded) // already AAD-bound
}

// ─── sweepAPIClients: skip row with empty EncryptedClientSecret ──────────────

func TestSweepAPIClients_SkipsEmptySecret(t *testing.T) {
	db := s23DB(t)
	es := s23ES(t)
	row := &models.APIClient{Name: "no-enc", ClientID: "cid-skip", ClientSecret: "h"}
	require.NoError(t, db.Create(row).Error)

	swept, err := sweepAPIClients(db, es, es, "v1", false)
	require.NoError(t, err)
	assert.Equal(t, 0, swept)
}

// ─── AAD helper string format checks ─────────────────────────────────────────

func TestDynamicSecretConfigAAD_Format(t *testing.T) {
	aad := DynamicSecretConfigAAD(1, 2, 3)
	assert.True(t, strings.HasPrefix(string(aad), "keyorix:dynsecret-config:v1:"))
	assert.Contains(t, string(aad), ":1:2:3")
}

func TestDynamicSecretLeaseAAD_Format(t *testing.T) {
	aad := DynamicSecretLeaseAAD("lease-xyz", 7)
	assert.True(t, strings.HasPrefix(string(aad), "keyorix:dynsecret-lease:v1:"))
	assert.Contains(t, string(aad), "lease-xyz:7")
}

func TestMFASecretAAD_Format(t *testing.T) {
	aad := MFASecretAAD(42)
	assert.Equal(t, "keyorix:mfa:v1:42", string(aad))
}

// ─── EncryptionService: DecryptWithAAD mismatch vs missing AAD ───────────────

func TestEncryptWithAAD_ThenDecryptWithAAD_Success(t *testing.T) {
	es := s23ES(t)
	aad := []byte("bind-me")
	enc, err := es.EncryptWithAAD([]byte("plaintext"), "v1", aad)
	require.NoError(t, err)
	assert.Equal(t, "v2", enc.Metadata.AADVersion)

	got, err := es.DecryptWithAAD(enc, aad)
	require.NoError(t, err)
	assert.Equal(t, []byte("plaintext"), got)
}

// ─── keyFileLock.release: nil safe ───────────────────────────────────────────

func TestKeyFileLock_Release_Nil(t *testing.T) {
	// Calling release on a nil *keyFileLock must not panic
	var l *keyFileLock
	l.release() // should be a no-op
}

func TestKeyFileLock_Release_NilFile(t *testing.T) {
	l := &keyFileLock{f: nil}
	l.release() // should be a no-op
}

// ─── UpgradeAuthAAD: error path when sweepMFASecrets fails ───────────────────

func TestUpgradeAuthAAD_MFADecryptFails_ReturnsError(t *testing.T) {
	svc := s23Svc(t)
	db := s23DB(t)

	// Encrypt with a DIFFERENT key → decrypt will fail inside sweepMFASecrets
	otherKey := make([]byte, 32)
	for i := range otherKey {
		otherKey[i] = byte(i + 1)
	}
	otherES, err := NewEncryptionService(otherKey)
	require.NoError(t, err)
	enc, err := otherES.Encrypt([]byte("totp"), "v1")
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	row := &models.MFASecret{UserID: 55, SecretEnc: encBytes, SecretMeta: metaBytes}
	require.NoError(t, db.Create(row).Error)

	_, err = svc.UpgradeAuthAAD(db)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mfa_secrets AAD upgrade failed")
}

// ─── UpgradeAuthAAD: error when sweepDynamicSecretConfigs fails ──────────────

func TestUpgradeAuthAAD_DynConfigDecryptFails_ReturnsError(t *testing.T) {
	svc := s23Svc(t)
	db := s23DB(t)

	// No MFA secrets → sweepMFASecrets succeeds (returns 0).
	// Corrupt DynamicSecretConfig → sweepDynamicSecretConfigs fails.
	otherKey := make([]byte, 32)
	for i := range otherKey {
		otherKey[i] = byte(i + 2)
	}
	otherES, err := NewEncryptionService(otherKey)
	require.NoError(t, err)
	enc, err := otherES.Encrypt([]byte("dsn"), "v1")
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)

	row := &models.DynamicSecretConfig{Name: "bad-cfg", ProjectID: 1, AdminDSNEnc: encBytes}
	require.NoError(t, db.Create(row).Error)

	_, err = svc.UpgradeAuthAAD(db)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dynamic_secret_configs AAD upgrade failed")
}

// ─── UpgradeAuthAAD: error when sweepDynamicSecretLeases fails ───────────────

func TestUpgradeAuthAAD_DynLeaseDecryptFails_ReturnsError(t *testing.T) {
	svc := s23Svc(t)
	db := s23DB(t)

	// No MFA secrets, no DynamicSecretConfigs → both succeed.
	// Corrupt DynamicSecretLease → sweepDynamicSecretLeases fails.
	otherKey := make([]byte, 32)
	for i := range otherKey {
		otherKey[i] = byte(i + 3)
	}
	otherES, err := NewEncryptionService(otherKey)
	require.NoError(t, err)
	enc, err := otherES.Encrypt([]byte("cred"), "v1")
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	row := &models.DynamicSecretLease{
		LeaseID:        "bad-lease-01",
		ConfigID:       1,
		Status:         "active",
		CredentialEnc:  encBytes,
		CredentialMeta: metaBytes,
	}
	require.NoError(t, db.Create(row).Error)

	_, err = svc.UpgradeAuthAAD(db)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dynamic_secret_leases AAD upgrade failed")
}

// ─── sweepAPITokens: deserialize-corrupt row fails ───────────────────────────

func TestSweepAPITokens_CorruptJSON_FailsDeserialize(t *testing.T) {
	db := s23DB(t)
	es := s23ES(t)
	row := &models.APIToken{Token: "tok99", EncryptedToken: []byte("bad-json")}
	require.NoError(t, db.Create(row).Error)

	_, _, err := sweepAPITokens(db, es, es, "v1", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "deserialize")
}

// ─── sweepAPIClients: deserialize-corrupt row fails ──────────────────────────

func TestSweepAPIClients_CorruptJSON_FailsDeserialize(t *testing.T) {
	db := s23DB(t)
	es := s23ES(t)
	row := &models.APIClient{
		Name:                  "bad-client",
		ClientID:              "cid-bad",
		ClientSecret:          "hsh",
		EncryptedClientSecret: []byte("bad-json"),
	}
	require.NoError(t, db.Create(row).Error)

	_, err := sweepAPIClients(db, es, es, "v1", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "deserialize")
}

// ─── sweepPasswordResets: deserialize-corrupt row fails ──────────────────────

func TestSweepPasswordResets_CorruptJSON_FailsDeserialize(t *testing.T) {
	db := s23DB(t)
	es := s23ES(t)
	row := &models.PasswordReset{UserID: 88, Token: "hsh88", EncryptedToken: []byte("bad-json")}
	require.NoError(t, db.Create(row).Error)

	_, _, err := sweepPasswordResets(db, es, es, "v1", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "deserialize")
}

// ─── sweepMFASecrets: deserialize-corrupt row fails ─────────────────────────

func TestSweepMFASecrets_CorruptJSON_FailsDeserialize(t *testing.T) {
	db := s23DB(t)
	es := s23ES(t)
	row := &models.MFASecret{UserID: 77, SecretEnc: []byte("bad-json")}
	require.NoError(t, db.Create(row).Error)

	_, _, err := sweepMFASecrets(db, es, es, "v1", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "deserialize")
}

// ─── sweepDynamicSecretConfigs: deserialize-corrupt row fails ────────────────

func TestSweepDynamicSecretConfigs_CorruptJSON_FailsDeserialize(t *testing.T) {
	db := s23DB(t)
	es := s23ES(t)
	row := &models.DynamicSecretConfig{Name: "bad-dsn", ProjectID: 9, AdminDSNEnc: []byte("bad-json")}
	require.NoError(t, db.Create(row).Error)

	_, _, err := sweepDynamicSecretConfigs(db, es, es, "v1", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "deserialize")
}

// ─── sweepDynamicSecretLeases: deserialize-corrupt row fails ─────────────────

func TestSweepDynamicSecretLeases_CorruptJSON_FailsDeserialize(t *testing.T) {
	db := s23DB(t)
	es := s23ES(t)
	row := &models.DynamicSecretLease{
		LeaseID:       "bad-json-lease",
		ConfigID:      9,
		Status:        "active",
		CredentialEnc: []byte("bad-json"),
	}
	require.NoError(t, db.Create(row).Error)

	_, _, err := sweepDynamicSecretLeases(db, es, es, "v1", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "deserialize")
}

// ─── sweepAPIClients: decrypt error ──────────────────────────────────────────

func TestSweepAPIClients_DecryptError(t *testing.T) {
	db := s23DB(t)
	es := s23ES(t)

	// Encrypt with a different key so decrypt fails
	otherKey := make([]byte, 32)
	for i := range otherKey {
		otherKey[i] = byte(i + 5)
	}
	otherES, err := NewEncryptionService(otherKey)
	require.NoError(t, err)
	enc, err := otherES.Encrypt([]byte("secret"), "v1")
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	row := &models.APIClient{
		Name:                  "bad-enc-client",
		ClientID:              "cid-bad-enc",
		ClientSecret:          "hsh",
		EncryptedClientSecret: encBytes,
		ClientSecretMetadata:  models.JSON(metaBytes),
	}
	require.NoError(t, db.Create(row).Error)

	_, err = sweepAPIClients(db, es, es, "v1", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt api_client")
}

// ─── sweepAPITokens: decrypt error ───────────────────────────────────────────

func TestSweepAPITokens_DecryptError(t *testing.T) {
	db := s23DB(t)
	es := s23ES(t)

	otherKey := make([]byte, 32)
	for i := range otherKey {
		otherKey[i] = byte(i + 6)
	}
	otherES, err := NewEncryptionService(otherKey)
	require.NoError(t, err)
	enc, err := otherES.Encrypt([]byte("token"), "v1")
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	row := &models.APIToken{
		Token:          "bad-enc-tok",
		EncryptedToken: encBytes,
		TokenMetadata:  models.JSON(metaBytes),
	}
	require.NoError(t, db.Create(row).Error)

	_, _, err = sweepAPITokens(db, es, es, "v1", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt api_token")
}

// ─── sweepPasswordResets: happy path ─────────────────────────────────────────

func TestSweepPasswordResets_HappyPath_Persists(t *testing.T) {
	db := s23DB(t)
	es := s23ES(t)
	enc, err := es.Encrypt([]byte("reset-value"), "v1")
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	row := &models.PasswordReset{
		UserID:         60,
		Token:          "hash60",
		EncryptedToken: encBytes,
		TokenMetadata:  models.JSON(metaBytes),
	}
	require.NoError(t, db.Create(row).Error)

	swept, _, err := sweepPasswordResets(db, es, es, "v2", false)
	require.NoError(t, err)
	assert.Equal(t, 1, swept)
}

// ─── wrapKey bad KEK size ─────────────────────────────────────────────────────

func TestWrapKey_BadKEKSize_Error(t *testing.T) {
	// AES requires 16, 24, or 32 bytes; 10-byte key is invalid
	_, err := wrapKey(make([]byte, 32), make([]byte, 10))
	require.Error(t, err)
}

// ─── Service.Initialize: buildKeyProvider error ───────────────────────────────

func TestService_Initialize_UnknownProvider_Error(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "kek.salt",
		KeyProvider: config.KeyProviderConfig{
			Type: "totally-unknown-provider",
		},
	}
	svc := NewService(cfg, dir)
	err := svc.Initialize("any-pass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown")
}

// ─── PreviewRotationSweep: not initialized returns error ─────────────────────

func TestPreviewRotationSweep_NotInitialized_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	svc := NewService(cfg, dir)
	_, err := svc.PreviewRotationSweep(s23DB(t))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

// ─── sweepMFASecrets: AAD-bound row (DecryptWithAAD path) ────────────────────

func TestSweepMFASecrets_AADBoundRow(t *testing.T) {
	db := s23DB(t)
	es := s23ES(t)

	// Insert with known UserID first
	row := &models.MFASecret{UserID: 200}
	require.NoError(t, db.Create(row).Error)

	aad := MFASecretAAD(row.UserID)
	enc, err := es.EncryptWithAAD([]byte("totp-bound"), "v1", aad)
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	require.NoError(t, db.Model(row).Updates(map[string]any{
		"secret_enc":  encBytes,
		"secret_meta": metaBytes,
	}).Error)

	swept, legacyUpgraded, err := sweepMFASecrets(db, es, es, "v1", false)
	require.NoError(t, err)
	assert.Equal(t, 1, swept)
	assert.Equal(t, 0, legacyUpgraded) // already AAD-bound
}

// ─── EncryptSecret: service happy path ───────────────────────────────────────

func TestService_EncryptSecret_HappyPath(t *testing.T) {
	svc := s23Svc(t)
	enc, meta, err := svc.EncryptSecret([]byte("my-secret"))
	require.NoError(t, err)
	assert.NotEmpty(t, enc)
	assert.NotEmpty(t, meta)

	// Verify decrypt works
	plain, err := svc.DecryptSecret(enc)
	require.NoError(t, err)
	assert.Equal(t, []byte("my-secret"), plain)
}

// ─── DecryptChunked: stream ID mismatch ──────────────────────────────────────

func TestDecryptChunked_StreamIDMismatch_Fails(t *testing.T) {
	es := s23ES(t)
	data1 := bytes.Repeat([]byte("a"), 20)
	data2 := bytes.Repeat([]byte("b"), 20)

	chunks1, err := es.EncryptChunked(data1, 10, "v1")
	require.NoError(t, err)
	chunks2, err := es.EncryptChunked(data2, 10, "v1")
	require.NoError(t, err)

	// Put chunk from different stream, but fix all metadata to look consistent
	mixed := []*EncryptedData{
		chunks1[0],
		chunks2[1],
	}
	// Fix mixed[1] to pretend to be from stream 1
	mixed[1].Metadata.ChunkStreamID = chunks1[0].Metadata.ChunkStreamID
	// Now the GCM open will fail because AAD won't match (different stream ID was used during encryption)
	_, err = es.DecryptChunked(mixed)
	require.Error(t, err)
}
