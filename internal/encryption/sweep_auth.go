// sweep_auth.go — Re-encryption sweep for auth tables (API tokens, clients,
// password resets, MFA secrets, dynamic-secret configs/leases).
//
// sweepAPITokens/sweepPasswordResets use per-row AAD, matching the live write path's
// AAD helpers (APITokenAAD/PasswordResetTokenAAD). Legacy rows (AADVersion == "") are
// decrypted via the no-AAD fallback and re-encrypted WITH AAD, upgrading them in
// place — same pattern as sweepMFASecrets. Re-encrypting without AAD would strip
// transplant protection and widen any stolen ciphertext's scope.
//
// sweepAPITokens/sweepAPIClients re-encrypt legacy already-deployed rows only: no
// live write path populates APIToken.EncryptedToken or APIClient.EncryptedClientSecret
// today (server/http/router.go: the admin-managed API-client/API-token issuance
// routes were removed per finding #131 — their tokens were never accepted by any
// auth path). These two sweeps stay so a DEK rotation still re-encrypts any such row
// surviving from before that removal, rather than stranding it permanently
// undecryptable (#1641). Session had no equivalent legacy population ever (the live
// write path always hashed session tokens, never encrypted them) — its now-dead
// EncryptedSessionToken/SessionTokenMetadata columns and sweepSessions were deleted
// outright, not kept for legacy data.
//
// sweepAPIClients re-encrypts without AAD: EncryptClientSecret does not bind to a
// user identity (client secrets have no owner AAD).
//
// sweepMFASecrets/sweepDynamicSecretConfigs/sweepDynamicSecretLeases (#94) ARE
// live-path AAD-bound categories: they reconstruct each row's AAD from its own
// identity (mirroring sweepSecretVersions in sweep.go) and, like it, decrypt via
// either the legacy no-AAD path or the AAD-aware path depending on the row's stored
// AADVersion, then ALWAYS re-encrypt with AAD — upgrading legacy rows in place.
package encryption

import (
	"encoding/json"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

const (
	sqlWhereID = "id = ?"
)

// dryRun skips the final Updates() write only; every other step still runs.
// Returns (rowsSwept, legacyRowsUpgraded, error).
func sweepAPITokens(tx *gorm.DB, oldSvc *EncryptionService, newSvc *EncryptionService, newKeyVersion string, dryRun bool) (int, int, error) { // NOSONAR -- cognitive complexity 24, suppress go:S3776
	var tokens []models.APIToken
	if err := tx.Find(&tokens).Error; err != nil {
		return 0, 0, fmt.Errorf("failed to fetch api_tokens: %w", err)
	}
	swept, legacyUpgraded := 0, 0
	for _, token := range tokens {
		if len(token.EncryptedToken) == 0 {
			continue
		}
		encrypted, err := DeserializeEncryptedData(token.EncryptedToken)
		if err != nil {
			return swept, legacyUpgraded, fmt.Errorf("failed to deserialize api_token id=%d: %w", token.ID, err)
		}
		var tokenUserID uint
		if token.UserID != nil {
			tokenUserID = *token.UserID
		}
		aad := APITokenAAD(tokenUserID)
		isLegacy := encrypted.Metadata.AADVersion == ""
		var plaintext []byte
		if isLegacy {
			plaintext, err = oldSvc.Decrypt(encrypted)
		} else {
			plaintext, err = oldSvc.DecryptWithAAD(encrypted, aad)
		}
		if err != nil {
			return swept, legacyUpgraded, fmt.Errorf("failed to decrypt api_token id=%d: %w", token.ID, err)
		}
		newEncrypted, err := newSvc.EncryptWithAAD(plaintext, newKeyVersion, aad)
		wipeBytes(plaintext)
		if err != nil {
			return swept, legacyUpgraded, fmt.Errorf("failed to re-encrypt api_token id=%d: %w", token.ID, err)
		}
		newBytes, err := SerializeEncryptedData(newEncrypted)
		if err != nil {
			return swept, legacyUpgraded, fmt.Errorf("failed to serialize api_token id=%d: %w", token.ID, err)
		}
		metaBytes, err := json.Marshal(newEncrypted.Metadata)
		if err != nil {
			return swept, legacyUpgraded, fmt.Errorf("failed to marshal api_token metadata id=%d: %w", token.ID, err)
		}
		if !dryRun {
			if err := tx.Model(&models.APIToken{}).Where(sqlWhereID, token.ID).Updates(map[string]any{
				"encrypted_token": newBytes,
				"token_metadata":  models.JSON(metaBytes),
			}).Error; err != nil {
				return swept, legacyUpgraded, fmt.Errorf("failed to update api_token id=%d: %w", token.ID, err)
			}
		}
		swept++
		if isLegacy {
			legacyUpgraded++
		}
	}
	return swept, legacyUpgraded, nil
}

// dryRun skips the final Updates() write only; every other step still runs.
func sweepAPIClients(tx *gorm.DB, oldSvc *EncryptionService, newSvc *EncryptionService, newKeyVersion string, dryRun bool) (int, error) { // NOSONAR -- cognitive complexity 19, suppress go:S3776
	var clients []models.APIClient
	if err := tx.Find(&clients).Error; err != nil {
		return 0, fmt.Errorf("failed to fetch api_clients: %w", err)
	}
	swept := 0
	for _, client := range clients {
		if len(client.EncryptedClientSecret) == 0 {
			continue
		}
		encrypted, err := DeserializeEncryptedData(client.EncryptedClientSecret)
		if err != nil {
			return swept, fmt.Errorf("failed to deserialize api_client id=%d: %w", client.ID, err)
		}
		plaintext, err := oldSvc.Decrypt(encrypted)
		if err != nil {
			return swept, fmt.Errorf("failed to decrypt api_client id=%d: %w", client.ID, err)
		}
		newEncrypted, err := newSvc.Encrypt(plaintext, newKeyVersion)
		wipeBytes(plaintext)
		if err != nil {
			return swept, fmt.Errorf("failed to re-encrypt api_client id=%d: %w", client.ID, err)
		}
		newBytes, err := SerializeEncryptedData(newEncrypted)
		if err != nil {
			return swept, fmt.Errorf("failed to serialize api_client id=%d: %w", client.ID, err)
		}
		metaBytes, err := json.Marshal(newEncrypted.Metadata)
		if err != nil {
			return swept, fmt.Errorf("failed to marshal api_client metadata id=%d: %w", client.ID, err)
		}
		if !dryRun {
			if err := tx.Model(&models.APIClient{}).Where(sqlWhereID, client.ID).Updates(map[string]any{
				"encrypted_client_secret": newBytes,
				"client_secret_metadata":  models.JSON(metaBytes),
			}).Error; err != nil {
				return swept, fmt.Errorf("failed to update api_client id=%d: %w", client.ID, err)
			}
		}
		swept++
	}
	return swept, nil
}

// sweepMFASecrets re-encrypts TOTP secrets (mfa_secrets.secret_enc), bound to
// MFASecretAAD(UserID) (#94). Legacy (pre-#94) rows are decrypted via the no-AAD
// path and always re-encrypted WITH AAD, upgrading them in place — mirrors
// sweepSecretVersions's legacy-branch pattern. Missing this sweeper's re-encryption
// step entirely (the original gap, ADR-010) meant a DEK rotation left every enrolled
// TOTP secret encrypted under the wiped old DEK — permanently breaking MFA login.
// dryRun skips the final Updates() write only; every other step still runs.
// Returns (rowsSwept, legacyRowsUpgraded, error).
func sweepMFASecrets(tx *gorm.DB, oldSvc *EncryptionService, newSvc *EncryptionService, newKeyVersion string, dryRun bool) (int, int, error) { // NOSONAR -- cognitive complexity 24, suppress go:S3776
	var rows []models.MFASecret
	if err := tx.Find(&rows).Error; err != nil {
		return 0, 0, fmt.Errorf("failed to fetch mfa_secrets: %w", err)
	}
	swept, legacyUpgraded := 0, 0
	for _, row := range rows {
		if len(row.SecretEnc) == 0 {
			continue
		}
		encrypted, err := DeserializeEncryptedData(row.SecretEnc)
		if err != nil {
			return swept, legacyUpgraded, fmt.Errorf("failed to deserialize mfa_secret id=%d: %w", row.ID, err)
		}
		aad := MFASecretAAD(row.UserID)
		isLegacy := encrypted.Metadata.AADVersion == ""
		var plaintext []byte
		if isLegacy {
			plaintext, err = oldSvc.Decrypt(encrypted)
		} else {
			plaintext, err = oldSvc.DecryptWithAAD(encrypted, aad)
		}
		if err != nil {
			return swept, legacyUpgraded, fmt.Errorf("failed to decrypt mfa_secret id=%d: %w", row.ID, err)
		}
		newEncrypted, err := newSvc.EncryptWithAAD(plaintext, newKeyVersion, aad)
		wipeBytes(plaintext)
		if err != nil {
			return swept, legacyUpgraded, fmt.Errorf("failed to re-encrypt mfa_secret id=%d: %w", row.ID, err)
		}
		newBytes, err := SerializeEncryptedData(newEncrypted)
		if err != nil {
			return swept, legacyUpgraded, fmt.Errorf("failed to serialize mfa_secret id=%d: %w", row.ID, err)
		}
		metaBytes, err := json.Marshal(newEncrypted.Metadata)
		if err != nil {
			return swept, legacyUpgraded, fmt.Errorf("failed to marshal mfa_secret metadata id=%d: %w", row.ID, err)
		}
		if !dryRun {
			if err := tx.Model(&models.MFASecret{}).Where(sqlWhereID, row.ID).Updates(map[string]any{
				"secret_enc":  newBytes,
				"secret_meta": metaBytes,
			}).Error; err != nil {
				return swept, legacyUpgraded, fmt.Errorf("failed to update mfa_secret id=%d: %w", row.ID, err)
			}
		}
		swept++
		if isLegacy {
			legacyUpgraded++
		}
	}
	return swept, legacyUpgraded, nil
}

// sweepDynamicSecretConfigs re-encrypts dynamic-secret admin DSNs
// (dynamic_secret_configs.admin_dsn_enc), bound to
// DynamicSecretConfigAAD(ID, ProjectID, EnvironmentID) (#94). Legacy rows are
// upgraded to AAD in place — see sweepMFASecrets. Missing this sweeper's
// re-encryption step entirely (the original gap, ADR-010) left the admin connection
// string undecryptable after a DEK rotation — the backend could no longer be reached
// or its leases revoked. dryRun skips the final Updates() write only; every other
// step still runs. Returns (rowsSwept, legacyRowsUpgraded, error).
func sweepDynamicSecretConfigs(tx *gorm.DB, oldSvc *EncryptionService, newSvc *EncryptionService, newKeyVersion string, dryRun bool) (int, int, error) { // NOSONAR -- cognitive complexity 24, suppress go:S3776
	var rows []models.DynamicSecretConfig
	if err := tx.Find(&rows).Error; err != nil {
		return 0, 0, fmt.Errorf("failed to fetch dynamic_secret_configs: %w", err)
	}
	swept, legacyUpgraded := 0, 0
	for _, row := range rows {
		if len(row.AdminDSNEnc) == 0 {
			continue
		}
		encrypted, err := DeserializeEncryptedData(row.AdminDSNEnc)
		if err != nil {
			return swept, legacyUpgraded, fmt.Errorf("failed to deserialize dynamic_secret_config id=%d: %w", row.ID, err)
		}
		aad := DynamicSecretConfigAAD(row.ID, row.ProjectID, row.EnvironmentID)
		isLegacy := encrypted.Metadata.AADVersion == ""
		var plaintext []byte
		if isLegacy {
			plaintext, err = oldSvc.Decrypt(encrypted)
		} else {
			plaintext, err = oldSvc.DecryptWithAAD(encrypted, aad)
		}
		if err != nil {
			return swept, legacyUpgraded, fmt.Errorf("failed to decrypt dynamic_secret_config id=%d: %w", row.ID, err)
		}
		newEncrypted, err := newSvc.EncryptWithAAD(plaintext, newKeyVersion, aad)
		wipeBytes(plaintext)
		if err != nil {
			return swept, legacyUpgraded, fmt.Errorf("failed to re-encrypt dynamic_secret_config id=%d: %w", row.ID, err)
		}
		newBytes, err := SerializeEncryptedData(newEncrypted)
		if err != nil {
			return swept, legacyUpgraded, fmt.Errorf("failed to serialize dynamic_secret_config id=%d: %w", row.ID, err)
		}
		metaBytes, err := json.Marshal(newEncrypted.Metadata)
		if err != nil {
			return swept, legacyUpgraded, fmt.Errorf("failed to marshal dynamic_secret_config metadata id=%d: %w", row.ID, err)
		}
		if !dryRun {
			if err := tx.Model(&models.DynamicSecretConfig{}).Where(sqlWhereID, row.ID).Updates(map[string]any{
				"admin_dsn_enc":  newBytes,
				"admin_dsn_meta": metaBytes,
			}).Error; err != nil {
				return swept, legacyUpgraded, fmt.Errorf("failed to update dynamic_secret_config id=%d: %w", row.ID, err)
			}
		}
		swept++
		if isLegacy {
			legacyUpgraded++
		}
	}
	return swept, legacyUpgraded, nil
}

// sweepDynamicSecretLeases re-encrypts issued dynamic-secret credentials
// (dynamic_secret_leases.credential_enc), bound to
// DynamicSecretLeaseAAD(LeaseID, ConfigID) (#94). Legacy rows are upgraded to AAD in
// place — see sweepMFASecrets. Missing this sweeper's re-encryption step entirely
// (the original gap, ADR-010) left active lease credentials undecryptable after a DEK
// rotation. dryRun skips the final Updates() write only; every other step still
// runs. Returns (rowsSwept, legacyRowsUpgraded, error).
func sweepDynamicSecretLeases(tx *gorm.DB, oldSvc *EncryptionService, newSvc *EncryptionService, newKeyVersion string, dryRun bool) (int, int, error) { // NOSONAR -- cognitive complexity 24, suppress go:S3776
	var rows []models.DynamicSecretLease
	if err := tx.Find(&rows).Error; err != nil {
		return 0, 0, fmt.Errorf("failed to fetch dynamic_secret_leases: %w", err)
	}
	swept, legacyUpgraded := 0, 0
	for _, row := range rows {
		if len(row.CredentialEnc) == 0 {
			continue
		}
		encrypted, err := DeserializeEncryptedData(row.CredentialEnc)
		if err != nil {
			return swept, legacyUpgraded, fmt.Errorf("failed to deserialize dynamic_secret_lease id=%d: %w", row.ID, err)
		}
		aad := DynamicSecretLeaseAAD(row.LeaseID, row.ConfigID)
		isLegacy := encrypted.Metadata.AADVersion == ""
		var plaintext []byte
		if isLegacy {
			plaintext, err = oldSvc.Decrypt(encrypted)
		} else {
			plaintext, err = oldSvc.DecryptWithAAD(encrypted, aad)
		}
		if err != nil {
			return swept, legacyUpgraded, fmt.Errorf("failed to decrypt dynamic_secret_lease id=%d: %w", row.ID, err)
		}
		newEncrypted, err := newSvc.EncryptWithAAD(plaintext, newKeyVersion, aad)
		wipeBytes(plaintext)
		if err != nil {
			return swept, legacyUpgraded, fmt.Errorf("failed to re-encrypt dynamic_secret_lease id=%d: %w", row.ID, err)
		}
		newBytes, err := SerializeEncryptedData(newEncrypted)
		if err != nil {
			return swept, legacyUpgraded, fmt.Errorf("failed to serialize dynamic_secret_lease id=%d: %w", row.ID, err)
		}
		metaBytes, err := json.Marshal(newEncrypted.Metadata)
		if err != nil {
			return swept, legacyUpgraded, fmt.Errorf("failed to marshal dynamic_secret_lease metadata id=%d: %w", row.ID, err)
		}
		if !dryRun {
			if err := tx.Model(&models.DynamicSecretLease{}).Where(sqlWhereID, row.ID).Updates(map[string]any{
				"credential_enc":  newBytes,
				"credential_meta": metaBytes,
			}).Error; err != nil {
				return swept, legacyUpgraded, fmt.Errorf("failed to update dynamic_secret_lease id=%d: %w", row.ID, err)
			}
		}
		swept++
		if isLegacy {
			legacyUpgraded++
		}
	}
	return swept, legacyUpgraded, nil
}

// sweepNotificationChannels re-encrypts notification channel destination URLs
// (notification_channels.url_enc), bound to NotificationChannelURLAAD(ID)
// (#2433). Legacy rows are upgraded to AAD in place -- see sweepMFASecrets.
// Missing this sweeper's re-encryption step entirely would leave the webhook/
// Slack/Teams bearer credential undecryptable after a DEK rotation, silently
// breaking every outbound alert escalation until each channel's URL was
// manually re-entered. dryRun skips the final Updates() write only; every
// other step still runs. Returns (rowsSwept, legacyRowsUpgraded, error).
func sweepNotificationChannels(tx *gorm.DB, oldSvc *EncryptionService, newSvc *EncryptionService, newKeyVersion string, dryRun bool) (int, int, error) { // NOSONAR -- cognitive complexity 24, suppress go:S3776
	var rows []models.NotificationChannel
	if err := tx.Find(&rows).Error; err != nil {
		return 0, 0, fmt.Errorf("failed to fetch notification_channels: %w", err)
	}
	swept, legacyUpgraded := 0, 0
	for _, row := range rows {
		// url_enc is self-describing (#2468). Unlike the sibling sweeps above,
		// this column can legitimately hold a PLAINTEXT passthrough value --
		// notification channels, alone among the encrypted auth-secret columns,
		// have no write path that refuses when encryption is off, because they
		// predate encryption here. The format tag is what tells the two apart;
		// before it existed, this loop handed those plaintext bytes to
		// DeserializeEncryptedData and returned an error, which SweepAllTables
		// propagates -- hard-failing the DEK rotation for every table, not just
		// this one, on an install that had ever run with encryption off.
		tag, payload, err := NotificationChannelURLUnwrap(row.URLEnc)
		if err != nil {
			return swept, legacyUpgraded, fmt.Errorf("notification_channel id=%d: %w", row.ID, err)
		}
		aad := NotificationChannelURLAAD(row.ID)
		var plaintext []byte
		isLegacy := false
		switch tag {
		case NotificationChannelURLTagAbsent:
			continue
		case NotificationChannelURLTagPlaintext:
			// A row still awaiting the startup backfill's off->on upgrade. A
			// rotation only happens with encryption ON, so encrypting it here
			// under the NEW key is both correct and the stronger outcome: the
			// sweep's contract is that every row is under newKeyVersion
			// afterwards, and leaving this one in plaintext would break that
			// silently.
			plaintext = append([]byte(nil), payload...)
		default: // NotificationChannelURLTagEncrypted
			encrypted, derr := DeserializeEncryptedData(payload)
			if derr != nil {
				return swept, legacyUpgraded, fmt.Errorf("failed to deserialize notification_channel id=%d: %w", row.ID, derr)
			}
			// NO legacy no-AAD fallback for this column, unlike every sibling
			// sweep above (#2468 round 2). Those tables have real rows that
			// predate #94 and must still be re-keyable; url_enc was introduced
			// by #2468 itself, so an envelope here declaring no aad_version
			// cannot be legitimate — it is ciphertext somebody copied in from
			// elsewhere in the database. Decrypting it without AAD would make
			// the rotation sweep the same decryption oracle the read path just
			// stopped being (internal/core's decryptNotificationChannelURL),
			// and would then RE-ENCRYPT the result as a properly AAD-bound
			// channel URL, laundering it. Refuse instead: a rotation that
			// cannot account for a row must stop, not normalise it.
			if encrypted.Metadata.AADVersion == "" {
				return swept, legacyUpgraded, fmt.Errorf("notification_channel id=%d: URL envelope declares no AAD version; this column has no legitimate pre-AAD rows, so refusing to re-encrypt it (manual investigation required: the row was written by something other than the notification-channel CRUD path)", row.ID)
			}
			plaintext, derr = oldSvc.DecryptWithAAD(encrypted, aad)
			if derr != nil {
				return swept, legacyUpgraded, fmt.Errorf("failed to decrypt notification_channel id=%d: %w", row.ID, derr)
			}
		}
		newEncrypted, err := newSvc.EncryptWithAAD(plaintext, newKeyVersion, aad)
		wipeBytes(plaintext)
		if err != nil {
			return swept, legacyUpgraded, fmt.Errorf("failed to re-encrypt notification_channel id=%d: %w", row.ID, err)
		}
		newBytes, err := SerializeEncryptedData(newEncrypted)
		if err != nil {
			return swept, legacyUpgraded, fmt.Errorf("failed to serialize notification_channel id=%d: %w", row.ID, err)
		}
		metaBytes, err := json.Marshal(newEncrypted.Metadata)
		if err != nil {
			return swept, legacyUpgraded, fmt.Errorf("failed to marshal notification_channel metadata id=%d: %w", row.ID, err)
		}
		if !dryRun {
			if err := tx.Model(&models.NotificationChannel{}).Where(sqlWhereID, row.ID).Updates(map[string]any{
				"url_enc":  NotificationChannelURLWrap(NotificationChannelURLTagEncrypted, newBytes),
				"url_meta": metaBytes,
			}).Error; err != nil {
				return swept, legacyUpgraded, fmt.Errorf("failed to update notification_channel id=%d: %w", row.ID, err)
			}
		}
		swept++
		if isLegacy {
			legacyUpgraded++
		}
	}
	return swept, legacyUpgraded, nil
}

// dryRun skips the final Updates() write only; every other step still runs.
// Returns (rowsSwept, legacyRowsUpgraded, error).
func sweepPasswordResets(tx *gorm.DB, oldSvc *EncryptionService, newSvc *EncryptionService, newKeyVersion string, dryRun bool) (int, int, error) { // NOSONAR -- cognitive complexity 24, suppress go:S3776
	var resets []models.PasswordReset
	if err := tx.Find(&resets).Error; err != nil {
		return 0, 0, fmt.Errorf("failed to fetch password_resets: %w", err)
	}
	swept, legacyUpgraded := 0, 0
	for _, reset := range resets {
		if len(reset.EncryptedToken) == 0 {
			continue
		}
		encrypted, err := DeserializeEncryptedData(reset.EncryptedToken)
		if err != nil {
			return swept, legacyUpgraded, fmt.Errorf("failed to deserialize password_reset id=%d: %w", reset.ID, err)
		}
		aad := PasswordResetTokenAAD(reset.UserID)
		isLegacy := encrypted.Metadata.AADVersion == ""
		var plaintext []byte
		if isLegacy {
			plaintext, err = oldSvc.Decrypt(encrypted)
		} else {
			plaintext, err = oldSvc.DecryptWithAAD(encrypted, aad)
		}
		if err != nil {
			return swept, legacyUpgraded, fmt.Errorf("failed to decrypt password_reset id=%d: %w", reset.ID, err)
		}
		newEncrypted, err := newSvc.EncryptWithAAD(plaintext, newKeyVersion, aad)
		wipeBytes(plaintext)
		if err != nil {
			return swept, legacyUpgraded, fmt.Errorf("failed to re-encrypt password_reset id=%d: %w", reset.ID, err)
		}
		newBytes, err := SerializeEncryptedData(newEncrypted)
		if err != nil {
			return swept, legacyUpgraded, fmt.Errorf("failed to serialize password_reset id=%d: %w", reset.ID, err)
		}
		metaBytes, err := json.Marshal(newEncrypted.Metadata)
		if err != nil {
			return swept, legacyUpgraded, fmt.Errorf("failed to marshal password_reset metadata id=%d: %w", reset.ID, err)
		}
		if !dryRun {
			if err := tx.Model(&models.PasswordReset{}).Where(sqlWhereID, reset.ID).Updates(map[string]any{
				"encrypted_token": newBytes,
				"token_metadata":  models.JSON(metaBytes),
			}).Error; err != nil {
				return swept, legacyUpgraded, fmt.Errorf("failed to update password_reset id=%d: %w", reset.ID, err)
			}
		}
		swept++
		if isLegacy {
			legacyUpgraded++
		}
	}
	return swept, legacyUpgraded, nil
}
