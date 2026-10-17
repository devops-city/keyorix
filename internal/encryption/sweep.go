// sweep.go — SweepAllTables orchestrator and sweepSecretVersions (AAD-aware).
//
// Called by RotateDEKWithSweep inside a DB transaction. Re-encrypts every
// DEK-encrypted row so no ciphertext remains under the old DEK.
//
// sweepSecretVersions is here because it requires AAD reconstruction logic
// (project lookup, SecretAAD, legacy-vs-bound path). The simpler auth-table
// sweepers (API tokens, clients, password resets) live in sweep_auth.go.
// Sessions have no sweeper: the live write path only ever hashes session
// tokens, never encrypts them, so there is nothing to re-encrypt (#1641).
//
// Invariant: on nil return, every row holds ciphertext under the new DEK.
// Secret values are transient in memory only — never logged or returned.
package encryption

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// sweepBatchSize is how many secret_versions rows are re-encrypted per batch.
// A var (not const) so tests can shrink it to exercise multi-batch pagination.
var sweepBatchSize = 500

// SweepResult holds statistics from a completed sweep.
type SweepResult struct {
	SecretVersionsSwept       int
	APITokensSwept            int
	APIClientsSwept           int
	AccountResetsSwept        int
	MFASecretsSwept           int
	DynamicSecretConfigsSwept int
	DynamicSecretLeasesSwept  int
	NotificationChannelsSwept int
	LegacyAADUpgraded         int
}

// SweepAllTables re-encrypts every DEK-encrypted row within a single DB transaction.
// oldSvc decrypts; newSvc re-encrypts. Called while both DEK services are live in memory.
//
// dryRun gates ONLY the final per-row write (tx.Model(...).Updates(...)) in each
// sweeper: every SELECT, decrypt, re-encrypt, and count still runs exactly as a real
// sweep would, so the returned SweepResult is an accurate preview of what a real
// rotation would touch (including catching any row that would fail to decrypt), but
// nothing here is ever persisted — the caller is expected to always roll back the
// transaction when dryRun is true (see Service.PreviewRotationSweep).
func SweepAllTables(tx *gorm.DB, oldSvc *EncryptionService, newSvc *EncryptionService, newKeyVersion string, dryRun bool) (*SweepResult, error) {
	result := &SweepResult{}

	sweptVersions, legacyUpgraded, err := sweepSecretVersions(tx, oldSvc, newSvc, newKeyVersion, dryRun)
	if err != nil {
		return nil, fmt.Errorf("secret_versions sweep failed: %w", err)
	}
	result.SecretVersionsSwept = sweptVersions
	result.LegacyAADUpgraded = legacyUpgraded

	sweptAPITokens, legacyAPITokens, err := sweepAPITokens(tx, oldSvc, newSvc, newKeyVersion, dryRun)
	if err != nil {
		return nil, fmt.Errorf("api_tokens sweep failed: %w", err)
	}
	result.APITokensSwept = sweptAPITokens
	result.LegacyAADUpgraded += legacyAPITokens

	sweptClients, err := sweepAPIClients(tx, oldSvc, newSvc, newKeyVersion, dryRun)
	if err != nil {
		return nil, fmt.Errorf("api_clients sweep failed: %w", err)
	}
	result.APIClientsSwept = sweptClients

	sweptResets, legacyResets, err := sweepPasswordResets(tx, oldSvc, newSvc, newKeyVersion, dryRun)
	if err != nil {
		return nil, fmt.Errorf("password_resets sweep failed: %w", err)
	}
	result.AccountResetsSwept = sweptResets
	result.LegacyAADUpgraded += legacyResets

	// These three tables are also DEK-encrypted but were previously omitted from the
	// sweep entirely — so a DEK rotation orphaned their ciphertext under the wiped old
	// key (TOTP secrets, dynamic-secret admin DSNs and lease credentials), breaking
	// MFA login and dynamic-secret access irrecoverably. They are also AAD-bound
	// (#94) as of this fix, so — like sweepSecretVersions — each also upgrades any
	// still-legacy (no-AAD) row it encounters, contributing to LegacyAADUpgraded.
	sweptMFA, legacyMFA, err := sweepMFASecrets(tx, oldSvc, newSvc, newKeyVersion, dryRun)
	if err != nil {
		return nil, fmt.Errorf("mfa_secrets sweep failed: %w", err)
	}
	result.MFASecretsSwept = sweptMFA
	result.LegacyAADUpgraded += legacyMFA

	sweptDynConfigs, legacyDynConfigs, err := sweepDynamicSecretConfigs(tx, oldSvc, newSvc, newKeyVersion, dryRun)
	if err != nil {
		return nil, fmt.Errorf("dynamic_secret_configs sweep failed: %w", err)
	}
	result.DynamicSecretConfigsSwept = sweptDynConfigs
	result.LegacyAADUpgraded += legacyDynConfigs

	sweptDynLeases, legacyDynLeases, err := sweepDynamicSecretLeases(tx, oldSvc, newSvc, newKeyVersion, dryRun)
	if err != nil {
		return nil, fmt.Errorf("dynamic_secret_leases sweep failed: %w", err)
	}
	result.DynamicSecretLeasesSwept = sweptDynLeases
	result.LegacyAADUpgraded += legacyDynLeases

	// #2433: notification_channels.url_enc (the webhook/Slack/Teams bearer
	// credential) is also DEK-encrypted and AAD-bound -- same reason as the
	// three sweeps above, same upgrade-in-place shape for still-legacy rows.
	sweptNotifChannels, legacyNotifChannels, err := sweepNotificationChannels(tx, oldSvc, newSvc, newKeyVersion, dryRun)
	if err != nil {
		return nil, fmt.Errorf("notification_channels sweep failed: %w", err)
	}
	result.NotificationChannelsSwept = sweptNotifChannels
	result.LegacyAADUpgraded += legacyNotifChannels

	return result, nil
}

// sweepSecretVersions re-encrypts all secret_versions rows in batches.
//
// Two cases:
//   - AAD-bound rows (aad_version="v2"): reconstruct AAD, decrypt with old
//     AAD-aware path, re-encrypt with new DEK + same AAD.
//   - Legacy rows (no aad_version): decrypt without AAD, re-encrypt with new
//     DEK + correct AAD (completes the M2 AAD migration).
//
// dryRun skips the final Updates() write only — every other step (fetch, decrypt,
// re-encrypt, counting) still runs, so callers get an accurate preview.
// Returns (rowsSwept, legacyRowsUpgraded, error).
func sweepSecretVersions(tx *gorm.DB, oldSvc *EncryptionService, newSvc *EncryptionService, newKeyVersion string, dryRun bool) (int, int, error) { // NOSONAR -- cognitive complexity 44, suppress go:S3776
	var offset int
	var totalSwept, totalLegacyUpgraded int

	// Pre-fetch secretNodeID → projectID to avoid N+1 queries. Unscoped: a
	// soft-deleted (recycle-bin) secret keeps its ciphertext-bearing version rows
	// (SecretVersion has no deleted_at; ADR-033 secrets are restorable), and those
	// rows still must be re-encrypted under the new DEK. Without Unscoped the map
	// excludes soft-deleted nodes, so a version of a trashed secret hits "no project
	// found" and aborts the entire rotation — blocking key rotation whenever anything
	// sits in the recycle bin.
	nodeProjectMap := make(map[uint]uint)
	var nodes []models.SecretNode
	if err := tx.Unscoped().Select("id, project_id").Find(&nodes).Error; err != nil {
		return 0, 0, fmt.Errorf("failed to fetch secret nodes for AAD reconstruction: %w", err)
	}
	for _, n := range nodes {
		nodeProjectMap[n.ID] = n.ProjectID
	}

	for {
		var batch []models.SecretVersion
		// Order by the immutable primary key: this batch loop re-encrypts (updates)
		// rows in place, and without a stable ORDER BY, offset pagination could skip
		// or double-visit rows as the engine re-orders the unupdated result set —
		// silently leaving some versions under the old DEK. id is never updated.
		if err := tx.Order("id").Offset(offset).Limit(sweepBatchSize).Find(&batch).Error; err != nil {
			return totalSwept, totalLegacyUpgraded, fmt.Errorf("failed to fetch secret_versions batch at offset %d: %w", offset, err)
		}
		if len(batch) == 0 {
			break
		}

		for _, version := range batch {
			if len(version.EncryptedValue) == 0 {
				continue
			}

			encrypted, err := DeserializeEncryptedData(version.EncryptedValue)
			if err != nil {
				return totalSwept, totalLegacyUpgraded, fmt.Errorf("failed to deserialize secret_version id=%d: %w", version.ID, err)
			}

			projectID, ok := nodeProjectMap[version.SecretNodeID]
			if !ok {
				return totalSwept, totalLegacyUpgraded, fmt.Errorf("no project found for secret_node_id=%d (version id=%d)", version.SecretNodeID, version.ID)
			}
			aad := SecretAAD(version.SecretNodeID, projectID, version.VersionNumber)

			isLegacy := encrypted.Metadata.AADVersion == ""
			var plaintext []byte
			if isLegacy {
				plaintext, err = oldSvc.Decrypt(encrypted)
			} else {
				plaintext, err = oldSvc.DecryptWithAAD(encrypted, aad)
			}
			if err != nil {
				return totalSwept, totalLegacyUpgraded, fmt.Errorf("failed to decrypt secret_version id=%d: %w", version.ID, err)
			}

			newEncrypted, err := newSvc.EncryptWithAAD(plaintext, newKeyVersion, aad)
			if err != nil {
				wipeBytes(plaintext)
				return totalSwept, totalLegacyUpgraded, fmt.Errorf("failed to re-encrypt secret_version id=%d: %w", version.ID, err)
			}
			wipeBytes(plaintext)

			newEncryptedBytes, err := SerializeEncryptedData(newEncrypted)
			if err != nil {
				return totalSwept, totalLegacyUpgraded, fmt.Errorf("failed to serialize re-encrypted secret_version id=%d: %w", version.ID, err)
			}
			metadataBytes, err := json.Marshal(newEncrypted.Metadata)
			if err != nil {
				return totalSwept, totalLegacyUpgraded, fmt.Errorf("failed to marshal metadata for secret_version id=%d: %w", version.ID, err)
			}

			if !dryRun {
				if err := tx.Model(&models.SecretVersion{}).Where("id = ?", version.ID).Updates(map[string]any{
					"encrypted_value":     newEncryptedBytes,
					"encryption_metadata": models.JSON(metadataBytes),
				}).Error; err != nil {
					return totalSwept, totalLegacyUpgraded, fmt.Errorf("failed to update re-encrypted secret_version id=%d: %w", version.ID, err)
				}
				// Raise cache_epoch in the same transaction as the rewrite: it is the term
				// of the read-path latest-version cache's generation that moves when a
				// row is rewritten in place (count, max(version_number) and
				// sum(read_count) do not), so every cache, on every replica, misses on
				// its next hit instead of serving the pre-sweep ciphertext.
				// store.TestSecretVersionCiphertextWriters_AreOnlyTheSweep fails if this
				// statement goes away. Explicit SQL, not part of the Updates above: the
				// model field is read-only to GORM (`<-:false`, so a struct Save can
				// never reset it) and GORM silently drops such a column from any update,
				// map and UpdateColumn included.
				if err := tx.Exec("UPDATE secret_versions SET cache_epoch = cache_epoch + 1 WHERE id = ?", version.ID).Error; err != nil {
					return totalSwept, totalLegacyUpgraded, fmt.Errorf("failed to raise cache_epoch of re-encrypted secret_version id=%d: %w", version.ID, err)
				}
			}

			totalSwept++
			if isLegacy {
				totalLegacyUpgraded++
			}
		}

		offset += sweepBatchSize
		log.Printf("[sweep] secret_versions: %d rows processed", totalSwept)
	}

	return totalSwept, totalLegacyUpgraded, nil
}
