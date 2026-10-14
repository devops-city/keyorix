// local_dynamic.go — dynamic-secrets persistence (ADR-035): configs and the
// issued leases whose expiry drives the auto-revoke sweep.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// CreateDynamicSecretConfig inserts a config and, in the same transaction, re-reads
// its project with lockLiveParent (FOR SHARE on Postgres), rolling back if the project
// is gone (#2651, INV-STORE-21). DeleteProject's #369 cascade row-locks the project
// before it disables the project's configs, so it either disables this config or this
// insert fails; without the re-check a config inserted after the cascade's disable
// committed enabled under the deleted project and minted again once it was restored.
func (ls *LocalStorage) CreateDynamicSecretConfig(ctx context.Context, c *models.DynamicSecretConfig) (*models.DynamicSecretConfig, error) {
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(c).Error; err != nil {
			if isUniqueViolation(err) {
				// The unique index uniq_dynamic_secret_configs_project_env_name (#462) caught a
				// duplicate (project, environment, name) tuple — the only unique constraint on
				// this table, so a bare driver-message match (isUniqueViolation, shared with
				// CreateProjectMembership) is unambiguous here. Translate to the sentinel so
				// callers (CreateDynamicSecretConfig in internal/core) can surface a clean
				// validation error instead of a raw constraint-violation message. Returning
				// it rolls the transaction back, so no aborted-transaction COMMIT follows.
				return fmt.Errorf("%w: %v", storage.ErrDuplicateDynamicSecretConfig, err)
			}
			return err
		}
		live, err := lockLiveParent(tx, &models.Project{}, "id = ?", c.ProjectID)
		if err != nil {
			return err
		}
		if !live {
			return fmt.Errorf("project not found")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (ls *LocalStorage) GetDynamicSecretConfig(ctx context.Context, id uint) (*models.DynamicSecretConfig, error) {
	var c models.DynamicSecretConfig
	if err := ls.db.WithContext(ctx).First(&c, id).Error; err != nil {
		return nil, err
	}
	return &c, nil
}

func (ls *LocalStorage) ListDynamicSecretConfigs(ctx context.Context, projectID, environmentID uint) ([]*models.DynamicSecretConfig, error) {
	var cs []*models.DynamicSecretConfig
	q := ls.db.WithContext(ctx).Where("project_id = ?", projectID)
	if environmentID != 0 {
		q = q.Where("environment_id = ?", environmentID)
	}
	if err := q.Order("name").Find(&cs).Error; err != nil {
		return nil, err
	}
	return cs, nil
}

func (ls *LocalStorage) UpdateDynamicSecretConfig(ctx context.Context, c *models.DynamicSecretConfig) error {
	return ls.db.WithContext(ctx).Save(c).Error
}

// SetDynamicSecretConfigAdminDSN writes only the encrypted admin DSN columns and
// updated_at (#2651): a targeted UPDATE, so a concurrent writer's columns
// (DeleteProject's #369 disabled=true above all) are never overwritten.
func (ls *LocalStorage) SetDynamicSecretConfigAdminDSN(ctx context.Context, id uint, enc, meta []byte) error {
	res := ls.db.WithContext(ctx).Model(&models.DynamicSecretConfig{}).Where("id = ?", id).
		Updates(map[string]any{"admin_dsn_enc": enc, "admin_dsn_meta": meta, "updated_at": time.Now()})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("dynamic-secret config not found")
	}
	return nil
}

// SetDynamicSecretConfigClassification persists ONLY the classification column
// (plus updated_at), conditional on the row's current classification still being
// fromClassification — see the storage.Storage interface doc for why
// ClassifyDynamicSecretConfig cannot use the full-row UpdateDynamicSecretConfig
// (#2698: its Save wrote `disabled=false` back over the incident kill switch).
//
// COALESCE so a NULL column (a row written before Classification existed) is
// matched by fromClassification "", the value GORM reads it back as.
func (ls *LocalStorage) SetDynamicSecretConfigClassification(ctx context.Context, id uint, fromClassification, toClassification string, updatedAt time.Time) (bool, error) {
	res := ls.db.WithContext(ctx).Model(&models.DynamicSecretConfig{}).
		Where("id = ? AND COALESCE(classification, '') = ?", id, fromClassification).
		Updates(map[string]any{"classification": toClassification, "updated_at": updatedAt})
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}

// ExtendDynamicSecretLeaseExpiry persists ONLY expires_at, and only for a lease
// that is STILL active — see the storage.Storage interface doc (#2698: the
// full-row Save it replaces wrote the stale Status/RevokeError/RevokedAt back
// over a concurrent RevokeLease, turning a successful revoke into an `active`
// lease with a later expiry).
//
// expires_at is normalised to UTC here because this raw UPDATE bypasses
// DynamicSecretLease.BeforeSave, which exists precisely to keep this column
// canonical for ListExpiredActiveLeases' SQL range query (G81, INV-STORE-19).
// Dropping that normalisation would let the auto-revoke sweep misjudge expiry
// on a non-UTC server.
func (ls *LocalStorage) ExtendDynamicSecretLeaseExpiry(ctx context.Context, leaseID string, newExpiry time.Time) (bool, error) {
	res := ls.db.WithContext(ctx).Model(&models.DynamicSecretLease{}).
		Where("lease_id = ? AND status = ?", leaseID, "active").
		Updates(map[string]any{"expires_at": newExpiry.UTC()})
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}

// RecordDynamicSecretLeaseRevocation persists ONLY the revocation columns of a
// lease: status, revoke_reason, revoke_error and revoked_at. Not conditional on
// the current status — unlike the two methods above, this write records what
// already happened to the credential at the backend, and it must land whatever
// else moved meanwhile (a lease whose target drop failed must not be left
// reading `active` because some other writer touched the row first).
//
// What it must NOT do is carry the rest of the caller's pre-read row with it:
// the former full-row Save also rewrote expires_at, so a revoke could revert a
// concurrent renewal's extension (harmless on a dead credential, but it is the
// same lost-update shape, and leaving one full-row writer alive is how the class
// comes back — #2698).
func (ls *LocalStorage) RecordDynamicSecretLeaseRevocation(ctx context.Context, leaseID, status, revokeReason, revokeError string, revokedAt *time.Time) (bool, error) {
	res := ls.db.WithContext(ctx).Model(&models.DynamicSecretLease{}).
		Where("lease_id = ?", leaseID).
		Updates(map[string]any{
			"status":        status,
			"revoke_reason": revokeReason,
			"revoke_error":  revokeError,
			"revoked_at":    revokedAt,
		})
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}

// TransitionDynamicSecretConfigDisabled persists c's full row via a conditional
// UPDATE gated on the row's CURRENT disabled value still being fromDisabled (see
// the interface doc in internal/core/storage/interface.go for why this exists
// alongside — not instead of — GetDynamicSecretConfig/UpdateDynamicSecretConfig).
// Mirrors TransitionMachineIdentityState's `WHERE id = ? AND state = ?` +
// `Select("*")` shape exactly, so every field the caller mutated on c (Disabled,
// UpdatedAt, ...) is persisted in the same statement, not just a hardcoded
// column subset.
func (ls *LocalStorage) TransitionDynamicSecretConfigDisabled(ctx context.Context, c *models.DynamicSecretConfig, fromDisabled bool) (bool, error) {
	// #G42: the guard only checks `disabled`, so a concurrent DSN rotation or
	// classification change (UpdateDynamicSecretConfig, an unconditional Save
	// that doesn't touch `disabled`) still matches this WHERE clause. A
	// Select("*") here would silently revert that concurrent edit back to
	// this call's stale copy even though the enable/disable toggle itself is
	// legitimate. Whitelist only the columns this transition actually owns.
	res := ls.db.WithContext(ctx).Model(&models.DynamicSecretConfig{}).
		Where("id = ? AND disabled = ?", c.ID, fromDisabled).
		Select("Disabled", "UpdatedAt").
		Updates(c)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}

// CountDynamicSecretConfigsByClassification returns config counts keyed by
// classification label ("" = unclassified), install-wide, via a GROUP BY.
func (ls *LocalStorage) CountDynamicSecretConfigsByClassification(ctx context.Context) (map[string]int, error) {
	return countByClassification(ctx, ls.db, &models.DynamicSecretConfig{})
}

// CreateDynamicSecretLease inserts a lease row. An ACTIVE lease (a live credential
// handed to a caller) is inserted in one transaction with a lockLiveParent re-read of
// its config, still enabled, and rolls back with ErrDynamicSecretConfigDisabled if the
// config was disabled meanwhile (#2652, INV-STORE-21). DeleteProject's #369 cascade and
// the config disable kill switch both UPDATE (row-lock) the config row and list leases
// to revoke only after they commit, so either they see this lease, or this insert sees
// the disable and the caller revokes the just-minted credential. Any other status
// (revoke_failed: the tracking row for a credential that could not be dropped) is
// always recorded, disabled config or not: refusing it would hide a live credential.
func (ls *LocalStorage) CreateDynamicSecretLease(ctx context.Context, l *models.DynamicSecretLease) (*models.DynamicSecretLease, error) {
	if l.Status != "active" {
		if err := ls.db.WithContext(ctx).Create(l).Error; err != nil {
			return nil, err
		}
		return l, nil
	}
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(l).Error; err != nil {
			return err
		}
		live, err := lockLiveParent(tx, &models.DynamicSecretConfig{}, "id = ? AND disabled = ?", l.ConfigID, false)
		if err != nil {
			return err
		}
		if !live {
			return storage.ErrDynamicSecretConfigDisabled
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return l, nil
}

func (ls *LocalStorage) GetDynamicSecretLease(ctx context.Context, leaseID string) (*models.DynamicSecretLease, error) {
	var l models.DynamicSecretLease
	if err := ls.db.WithContext(ctx).Where("lease_id = ?", leaseID).First(&l).Error; err != nil {
		return nil, err
	}
	return &l, nil
}

func (ls *LocalStorage) ListDynamicSecretLeases(ctx context.Context, configID uint) ([]*models.DynamicSecretLease, error) {
	var ls2 []*models.DynamicSecretLease
	if err := ls.db.WithContext(ctx).Where("config_id = ?", configID).Order("issued_at desc").Limit(maxUnboundedListRows).Find(&ls2).Error; err != nil {
		return nil, err
	}
	return ls2, nil
}

func (ls *LocalStorage) UpdateDynamicSecretLease(ctx context.Context, l *models.DynamicSecretLease) error {
	return ls.db.WithContext(ctx).Save(l).Error
}

// CountActiveLeases returns the number of leases for a config that still hold a live
// credential upstream — status "active" AND "revoke_failed" (#411: a revoke_failed
// lease's earlier revoke attempt failed on the target, so its credential is still live,
// exactly the same "still live" reasoning ListExpiredActiveLeases documents above). An
// active-only count would let an attacker (or ordinary backend flakiness) force revokes
// to fail at issue time and silently exceed MaxActiveLeases forever, since every
// subsequent ceiling check would undercount the leftover live credentials.
func (ls *LocalStorage) CountActiveLeases(ctx context.Context, configID uint) (int64, error) {
	var n int64
	err := ls.db.WithContext(ctx).Model(&models.DynamicSecretLease{}).
		Where("config_id = ? AND status IN ?", configID, []string{"active", "revoke_failed"}).Count(&n).Error
	return n, err
}

// ListExpiredActiveLeases returns leases whose ExpiresAt is past `before` that still need
// their target credential dropped — active leases AND revoke_failed ones (whose earlier
// revoke failed, so their credential is still live). Ordered by id (stable) for the sweep.
// Without the revoke_failed inclusion such a credential would stay live past TTL forever,
// excluded from both the sweep and a manual retry.
//
// before is normalised to UTC here (G81), not left to the caller: DynamicSecretLease's
// BeforeSave hook already stores expires_at as UTC, but the caller-supplied cutoff
// (server/main.go's sweep passes time.Now(), local system time) previously wasn't —
// SQLite compares time.Time values as strings, so a local-time cutoff compared against
// a UTC-normalised expires_at column could silently misjudge which leases are actually
// past expiry, letting the auto-revoke sweep skip a genuinely-expired credential (or
// revoke one prematurely) depending on the sign of the local/UTC offset. Normalising
// here — the single place this comparison happens — means every caller gets a correct
// comparison regardless of whether it remembers to pass UTC itself.
func (ls *LocalStorage) ListExpiredActiveLeases(ctx context.Context, before time.Time) ([]*models.DynamicSecretLease, error) {
	var leases []*models.DynamicSecretLease
	if err := ls.db.WithContext(ctx).
		Where("status IN ? AND expires_at < ?", []string{"active", "revoke_failed"}, before.UTC()).
		Order("id").Limit(maxUnboundedListRows).Find(&leases).Error; err != nil {
		return nil, err
	}
	return leases, nil
}
