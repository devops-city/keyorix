// local_notification_channel_url_migration.go — the startup backfill that
// brings every NotificationChannel row's destination URL into the encrypted,
// self-describing url_enc/url_meta columns (#2433/#2468).
package store

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// legacyNotificationChannelURLRow reads the three columns this migration needs.
// URL is read via the raw "url" column name — models.NotificationChannel.URL is
// gorm:"-" (not persisted) as of #2433, so a normal Find into that model would
// never see the legacy plaintext value at all.
type legacyNotificationChannelURLRow struct {
	ID     uint
	URL    string `gorm:"column:url"`
	URLEnc []byte `gorm:"column:url_enc"`
}

// MigrateNotificationChannelURLsToEncrypted brings every NotificationChannel
// row into the current url_enc format and returns how many rows it rewrote.
//
// It runs on every startup, not only the first one after an upgrade, because it
// has two jobs:
//
//  1. Backfill a row that has no url_enc at all. That is every row on an
//     install upgrading from a pre-#2433 binary, whose URL still sits in the
//     legacy plaintext `url` column — INCLUDING a row whose legacy URL is the
//     empty string. #2468: the original version of this migration filtered
//     those out with `url != ”`, so an `email` channel (which legitimately
//     has no URL) kept an empty url_enc; the fail-closed read path then failed
//     the ENTIRE channel list over it, taking the channel UI, the CRUD API and
//     RunRecoverAdminAlerting down together. Every row gets a url_enc here,
//     even when the URL it describes is empty.
//  2. Upgrade a row stored as a plaintext passthrough once encryption becomes
//     available. A row written while `storage.encryption.enabled` was off is
//     tagged NotificationChannelURLTagPlaintext (see
//     ports.UnwrapNotificationChannelURL); turning encryption on later must
//     re-encrypt it, or it stays in plaintext at rest forever — invisibly,
//     since it still reads back fine.
//
// Idempotent in both roles: a row already in the target format for the current
// encryptor state is not selected, so a steady-state restart rewrites nothing
// and returns 0.
//
// Deliberately ROW-BY-ROW and NOT transactional (#2468 round 2, stated because
// a reviewer will otherwise and reasonably ask). Each row's UPDATE commits on
// its own, so a failure partway through leaves a mix of migrated and
// unmigrated rows. That is safe here for two specific reasons, and only
// because both hold:
//
//  1. Every row is independent — nothing reads two of them together, and
//     per-row state is self-describing via the format tag, so a half-finished
//     run has no inconsistent intermediate to observe.
//  2. A failure is FATAL to startup (its caller in server/main.go returns the
//     error), so no request is ever served against a half-migrated table; the
//     next boot resumes from wherever it stopped.
//
// Wrapping the whole thing in one transaction would be worse, not better: on
// an install with many channels it would hold a long write transaction over a
// table the scheduler also touches, to protect against an intermediate state
// nothing can see.
//
// Fails LOUDLY rather than logging and continuing (its caller in server/main.go
// refuses to start on an error). The cheap-looking alternative — "it is
// idempotent, a later restart will retry" — is wrong for job (2) specifically:
// a permanently-failing backfill leaves webhook bearer credentials in plaintext
// at rest on an install that has explicitly configured encryption, in exactly
// the state that still looks and behaves correct. That is the same reasoning,
// and the same remedy, as the SecretValueEncryptionActive fail-closed check
// immediately above the call site.
func (ls *LocalStorage) MigrateNotificationChannelURLsToEncrypted(ctx context.Context, encryptor ports.EncryptionProvider) (int, error) {
	// A fresh install never had a `url` column at all --
	// models.NotificationChannel.URL is gorm:"-", so AutoMigrate never creates
	// it from scratch there. Only an install upgrading from a pre-#2433 binary
	// has one, and selecting a nonexistent column would error rather than
	// return zero rows. Checked via ColumnTypes (portable across
	// SQLite/Postgres), not HasColumn, which resolves by STRUCT FIELD name and
	// "url" is no longer one.
	//
	// Note this is NOT an early return any more (#2468): job (2) above applies
	// to a fresh install too, which has rows but no legacy column.
	cols, err := ls.db.WithContext(ctx).Migrator().ColumnTypes(&models.NotificationChannel{})
	if err != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	hasLegacyColumn := false
	for _, c := range cols {
		if c.Name() == "url" {
			hasLegacyColumn = true
			break
		}
	}

	selectCols := "id, url_enc"
	if hasLegacyColumn {
		selectCols = "id, url, url_enc"
	}
	var rows []legacyNotificationChannelURLRow
	if err := ls.db.WithContext(ctx).Model(&models.NotificationChannel{}).
		Select(selectCols).Find(&rows).Error; err != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	encryptionOn := encryptor != nil && encryptor.IsEnabled()
	migrated := 0
	for _, r := range rows {
		plain, needsRewrite, err := notificationChannelURLRewritePlan(r, encryptionOn)
		if err != nil {
			return migrated, err
		}
		if !needsRewrite {
			continue
		}
		urlEnc, urlMeta, err := encodeNotificationChannelURL(plain, r.ID, encryptor, encryptionOn)
		if err != nil {
			return migrated, err
		}
		updates := map[string]any{"url_enc": urlEnc, "url_meta": urlMeta}
		if hasLegacyColumn {
			// Clear the legacy plaintext once its replacement is durable, so
			// the bytes don't linger in the ROW.
			//
			// Not in the FILE, though, and that limit is worth stating rather
			// than implying (#2468 round 2): an UPDATE to "" overwrites the
			// logical value, but the old bytes survive in SQLite free pages and
			// the WAL, and in PostgreSQL dead tuples, until a VACUUM (or
			// VACUUM FULL / pg_repack) reclaims them. So this clears the
			// plaintext from anything that reads the database, not from
			// forensic recovery of its storage. An operator upgrading an
			// install whose webhook URLs are treated as credentials should
			// VACUUM after the first post-upgrade boot. Deliberately NOT done
			// here: VACUUM is a long, exclusive, whole-database operation on
			// both backends and must not be fired implicitly from a startup
			// path -- see docs/CONFIGURATION.md's break-glass/notification
			// section for the operator-facing note.
			updates["url"] = ""
		}
		res := ls.db.WithContext(ctx).Model(&models.NotificationChannel{}).Where("id = ?", r.ID).Updates(updates)
		if res.Error != nil {
			return migrated, fmt.Errorf("%s: failed to persist migrated URL for notification channel %d: %w", i18n.T("ErrorStorageFailed", nil), r.ID, res.Error)
		}
		migrated++
	}

	if err := ls.verifyNoPlaintextNotificationChannelURLs(ctx, encryptionOn); err != nil {
		return migrated, err
	}
	return migrated, nil
}

// verifyNoPlaintextNotificationChannelURLs is the postcondition the core read
// path's tag-downgrade refusal rests on (#2468 round 2).
//
// internal/core's decryptNotificationChannelURL refuses a plaintext-tagged
// url_enc whenever encryption is active, which is only safe to do if a
// legitimate install can never BE in that state while serving. This is the
// check that makes that true rather than assumed: with encryption on, the loop
// above has re-encrypted every plaintext row, so finding one here means a write
// landed outside the CRUD path (or the loop's own logic regressed). Either way
// the server must not come up — its caller in server/main.go treats this error
// as fatal.
//
// Guarding the CONDITION, not the conclusion: without it, "the read path can
// refuse plaintext because startup leaves none" would be a claim in a comment,
// and a reader of decryptNotificationChannelURL would have no way to check it.
func (ls *LocalStorage) verifyNoPlaintextNotificationChannelURLs(ctx context.Context, encryptionOn bool) error {
	if !encryptionOn {
		return nil
	}
	var rows []legacyNotificationChannelURLRow
	if err := ls.db.WithContext(ctx).Model(&models.NotificationChannel{}).
		Select("id, url_enc").Find(&rows).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, r := range rows {
		tag, _, err := ports.UnwrapNotificationChannelURL(r.URLEnc)
		if err != nil {
			return fmt.Errorf("notification channel %d: %w", r.ID, err)
		}
		if tag == ports.NotificationChannelURLTagPlaintext {
			return fmt.Errorf("notification channel %d still holds an unencrypted URL after the backfill: refusing to continue, because the read path is entitled to assume encryption-active implies no plaintext rows (investigate how this row was written -- the CRUD path cannot produce it)", r.ID)
		}
	}
	return nil
}

// notificationChannelURLRewritePlan decides what, if anything, row r still
// needs. Returns the plaintext URL to (re-)encode and whether a rewrite is due.
//
// An unrecognised format tag is an error, not a row to skip: skipping it would
// leave a row the read path also refuses, with nothing anywhere saying so.
func notificationChannelURLRewritePlan(r legacyNotificationChannelURLRow, encryptionOn bool) (plain string, needsRewrite bool, err error) {
	tag, payload, err := ports.UnwrapNotificationChannelURL(r.URLEnc)
	if err != nil {
		return "", false, fmt.Errorf("notification channel %d: %w", r.ID, err)
	}
	switch tag {
	case ports.NotificationChannelURLTagAbsent:
		// Never written: an upgrading install's row. Its URL (possibly empty)
		// is in the legacy column, which is "" when that column is gone.
		return r.URL, true, nil
	case ports.NotificationChannelURLTagPlaintext:
		// Written while encryption was off. Due for upgrade only now that an
		// encryptor exists.
		return string(payload), encryptionOn, nil
	default: // ports.NotificationChannelURLTagEncrypted
		// Already an envelope. Re-keying it is the DEK-rotation sweep's job
		// (internal/encryption.sweepNotificationChannels), not this backfill's.
		return "", false, nil
	}
}

// encodeNotificationChannelURL mirrors internal/core's
// encryptNotificationChannelURL: a tagged envelope when encryption is on, a
// tagged plaintext passthrough when it is off. Kept in step with that function
// by TestNotificationChannelURLFormat_MigrationAndCoreAgree.
func encodeNotificationChannelURL(plain string, channelID uint, encryptor ports.EncryptionProvider, encryptionOn bool) (urlEnc, urlMeta []byte, err error) {
	if !encryptionOn {
		return ports.WrapNotificationChannelURL(ports.NotificationChannelURLTagPlaintext, []byte(plain)), nil, nil
	}
	envelope, meta, err := encryptor.EncryptSecretWithAAD([]byte(plain), ports.NotificationChannelURLAAD(channelID))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt notification channel %d URL during migration: %w", channelID, err)
	}
	return ports.WrapNotificationChannelURL(ports.NotificationChannelURLTagEncrypted, envelope), meta, nil
}
