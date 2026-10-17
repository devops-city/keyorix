// secrets_versions.go — storeSecretVersion: shared helper used by Create, Update, and Rotate.
//
// Full version query/retrieval functions live in versions.go.
// For CRUD operations see secrets.go. For validation see secrets_validation.go.
package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// storeSecretVersion writes a new version row for the given secret. The value is
// encrypted at rest (AAD-bound AES-256-GCM) when a secret-value encryptor is wired,
// otherwise stored as plaintext (encryption disabled — dev/test). Either way the row
// is persisted through the storage backend, so this works uniformly for local,
// Postgres, and remote (ADR-049) storage. Fail-closed: an encryption error aborts the
// write; the value is never silently downgraded to plaintext. Used by CreateSecret,
// UpdateSecret, and RotateSecret.
//
// db is the storage handle to write through — c.storage for callers running outside a
// transaction, or a tx-scoped storage.Storage for a caller that needs the version write
// to commit or roll back together with an earlier call in the same operation (CreateSecret,
// fix/create-ops-atomicity: the secret row and its version 1 now share one WithTransaction).
func (c *KeyorixCore) storeSecretVersion(ctx context.Context, db storage.Storage, secret *models.SecretNode, value []byte, versionNumber int) error {
	storedValue, metadata, err := c.encryptVersionValue(secret, value, versionNumber)
	if err != nil {
		return err
	}
	if metadata == nil {
		metadata = []byte("{}") // plaintext row marker (encryption disabled)
	}
	version := &models.SecretVersion{
		SecretNodeID:       secret.ID,
		VersionNumber:      versionNumber,
		EncryptedValue:     storedValue,
		EncryptionMetadata: metadata,
		ReadCount:          0,
		CreatedAt:          time.Now(),
	}
	_, err = db.CreateSecretVersion(ctx, version)
	return err
}

// maxRotateVersionAttempts bounds updateSecretWithNewVersion's retry loop — a safety
// valve, not an expected outcome. Even under the empirically-reproduced #121 contention
// (15 concurrent rotations of one secret), a handful of retries always suffices; if this
// bound is ever hit it indicates something is wrong beyond ordinary concurrent rotation
// traffic.
const maxRotateVersionAttempts = 20

// ErrSecretVersionContentionExhausted is returned when storeNextSecretVersion or
// updateSecretWithNewVersion exhausts maxRotateVersionAttempts racing OTHER
// concurrent writers for the same secret's next version number (W3, Session W,
// 2026-09-29: reproduced at ~54% of writes failing at concurrency 50 against one
// secret on Postgres, ~1% on SQLite — a real, load-bearing outcome under sustained
// heavy contention, not a hypothetical). The retry loop itself is working as
// designed (see maxRotateVersionAttempts's doc comment) — this signals "the whole
// operation should be retried," the same as a database serialization-failure
// class, not "something is broken." Callers (HTTP/gRPC) must map this to 409/
// Aborted with a retry hint, never a generic 500 — see secrets_crud.go's
// sendUpdateSecretError and secrets_versions.go's RotateSecret handler.
var ErrSecretVersionContentionExhausted = errors.New("exceeded retry attempts resolving the next secret version number under concurrent writes to this secret")

// isVersionConflict reports whether err is the sentinel storage.ErrDuplicateSecretVersion
// (which storeSecretVersion's storage write wraps explicitly) or looks like a raw
// unique-constraint violation from either backing DB driver (matched directly too, as
// defense-in-depth against a backend that surfaces the raw driver error, mirroring
// store.isUniqueViolation).
func isVersionConflict(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, storage.ErrDuplicateSecretVersion) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") || // SQLite
		strings.Contains(msg, "duplicate key value violates unique constraint") // Postgres
}

// storeNextSecretVersion resolves the next version number for secret and stores value
// under it, retrying on a lost race rather than failing the rotation outright (#121).
// GetLatestSecretVersion -> +1 -> storeSecretVersion is inherently a read-then-write
// sequence; the uniq_secret_versions_node_version DB index (storage.
// ensureSecretVersionIndex) is what actually makes concurrent rotations of the same
// secret safe — this retry loop is what lets a rotation that lost the race succeed anyway
// instead of surfacing a spurious "rotation failed" to an ordinary concurrent caller (an
// operational timing coincidence, not a conflict either caller did anything wrong to
// cause).
//
// Used ONLY by RotateSecret, deliberately NOT wrapped in a transaction with the
// row-update write that follows it — see RotateSecret's call site comment for why a
// partial commit here (version stored, row update fails) must be preserved rather than
// rolled back. UpdateSecret has the same-shaped write but no such consideration and
// uses updateSecretWithNewVersion below instead, which makes the two writes atomic.
//
// inTx, when non-nil, runs last in the version write's transaction (AUDIT-MUTATION-TX-1):
// the rotation's audit row, and for a rotation that changed nothing upstream (no
// rotation backend, or a rollback) the timestamp write too, so only a backend-bound
// rotation still keeps the split described above. A version is never stored without
// its audit row and a failed inTx stores nothing.
func (c *KeyorixCore) storeNextSecretVersion(ctx context.Context, secret *models.SecretNode, value []byte, inTx func(tx storage.Storage) error) error {
	var lastErr error
	for range maxRotateVersionAttempts {
		latestVersion, err := c.storage.GetLatestSecretVersion(ctx, secret.ID)
		nextVersionNumber := 1
		switch {
		case err == nil:
			nextVersionNumber = latestVersion.VersionNumber + 1
		case storage.IsSecretVersionNotFound(err):
			// No versions yet - version 1 is correct.
		default:
			// A real read failure, not "no versions yet" - don't guess.
			return err
		}
		if inTx == nil {
			lastErr = c.storeSecretVersion(ctx, c.storage, secret, value, nextVersionNumber)
		} else {
			lastErr = c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
				if err := c.storeSecretVersion(ctx, tx, secret, value, nextVersionNumber); err != nil {
					return err
				}
				return inTx(tx)
			})
		}
		if lastErr == nil {
			return nil
		}
		if !isVersionConflict(lastErr) {
			return lastErr
		}
		// Lost the race to another concurrent rotation of the same secret — re-read the
		// now-current latest version and retry.
	}
	return fmt.Errorf("%w (exceeded %d attempts): %v", ErrSecretVersionContentionExhausted, maxRotateVersionAttempts, lastErr)
}

// updateSecretWithNewVersion resolves the next version number, then stores that
// version and persists secret's own row (already mutated in place by the caller) as
// one atomic unit via storage.WithTransaction — the same fix/create-ops-atomicity
// pattern CreateSecret uses above, applied to UpdateSecret's identical two-write
// shape. Used ONLY by UpdateSecret: RotateSecret's write has the same shape but a
// different correctness requirement (see storeNextSecretVersion's doc comment and
// RotateSecret's call site) and deliberately stays non-transactional. The
// version-number READ stays outside the transaction here too (mirroring CreateSecret's
// duplicate-name pre-check, which reads via c.storage before its own WithTransaction)
// so a lost race (#121) can be retried by re-reading and reattempting the whole
// transaction; only the two WRITES need to commit or roll back together.
//
// A fault-fuzz run (2026-09-24) found the gap this closes: storing the version and
// then persisting the row as two independent c.storage calls left a real
// partial-commit window open — if the version write succeeded and the row update
// then failed, the caller was told the whole operation failed while a new version
// it was never told exists was already live and would be served by any
// GetLatestSecretVersion read. Unlike CreateSecret's documented ambiguous-commit gap
// (multiStepAmbiguousCommitExceptions, fuzz_storage_fault_operations_test.go), this
// was not ambiguous: the version write's success was certain, not a network-blip
// guess, so there was a concrete row to roll back — and unlike RotateSecret, there is
// no external upstream credential whose already-applied change that version would be
// the only record of, so rolling it back loses nothing.
//
// inTx, when non-nil, runs last inside each attempt's transaction: the caller's
// audit row (AUDIT-MUTATION-TX-1), so a failed audit write rolls the version and
// the row update back with it.
func (c *KeyorixCore) updateSecretWithNewVersion(ctx context.Context, secret *models.SecretNode, value []byte, fields storage.SecretFieldUpdate, inTx func(tx storage.Storage) error) (*models.SecretNode, error) {
	var updated *models.SecretNode
	var lastErr error
	for range maxRotateVersionAttempts {
		latestVersion, err := c.storage.GetLatestSecretVersion(ctx, secret.ID)
		nextVersionNumber := 1
		switch {
		case err == nil:
			nextVersionNumber = latestVersion.VersionNumber + 1
		case storage.IsSecretVersionNotFound(err):
			// No versions yet - version 1 is correct.
		default:
			// A real read failure, not "no versions yet" - don't guess.
			return nil, err
		}
		txErr := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
			if err := c.storeSecretVersion(ctx, tx, secret, value, nextVersionNumber); err != nil {
				return err
			}
			// #2695: the row write inside this transaction is column-scoped
			// too, to the same field set the caller derived from its request.
			// A full-row Save here had the extra sting that it ran in the SAME
			// transaction as the version insert, so a resurrection or a
			// reverted suspend committed atomically with a new version — the
			// row looked entirely self-consistent afterwards.
			matched, uerr := tx.UpdateSecretFields(ctx, secret.ID, fields)
			if uerr != nil {
				return uerr
			}
			if !matched {
				return fmt.Errorf("%s", i18n.T("ErrorSecretNotFound", nil))
			}
			if inTx != nil {
				if err := inTx(tx); err != nil {
					return err
				}
			}
			updated = secret
			return nil
		})
		if txErr == nil {
			return updated, nil
		}
		lastErr = txErr
		if !isVersionConflict(txErr) {
			return nil, txErr
		}
		// Lost the race to another concurrent rotation of the same secret — re-read the
		// now-current latest version and retry.
	}
	return nil, fmt.Errorf("%w (exceeded %d attempts): %v", ErrSecretVersionContentionExhausted, maxRotateVersionAttempts, lastErr)
}
