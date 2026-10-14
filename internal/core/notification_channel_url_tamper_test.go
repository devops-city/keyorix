// notification_channel_url_tamper_test.go — round-2 coordinator review of
// #2468: two ways a DB-write attacker could still steer or abuse
// notification_channels.url_enc after the format tag landed.
//
// Both assume the same attacker the AAD binding already assumes: someone who
// can write the row but not hold the DEK (a compromised replica, a restored
// backup, SQL injection elsewhere, a DBA). Neither needs the key.
//
//  1. TAG DOWNGRADE. The format tag made url_enc self-describing, but the read
//     path accepted a 0x01 (plaintext) tag unconditionally — including on an
//     install with encryption ON. So an attacker could replace a channel's
//     encrypted URL with a plaintext one of their choosing, redirecting every
//     alert for that channel to a host they control, with no AAD to stop them
//     (plaintext carries no binding to the channel ID at all). Worse, the next
//     startup backfill would then ENCRYPT that planted URL, laundering it into
//     a properly-bound envelope and erasing the evidence.
//
//  2. NO-AAD DECRYPTION ORACLE. Service.DecryptSecretWithAAD falls back to a
//     no-AAD decrypt when the envelope's aad_version is empty, for the sake of
//     rows written before #94. url_enc is brand new in this very PR, so it has
//     NO legitimate pre-AAD rows — and that fallback let an attacker paste ANY
//     old non-AAD ciphertext from anywhere in the DB (a secret_versions row,
//     say) into url_enc and read the plaintext straight back out of
//     GET /notification-channels. The AAD binding was doing nothing, because
//     the attacker chooses the metadata that decides whether AAD is checked.
package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// newEncryptedChannelWorld builds a core with encryption ON plus one channel
// created through the normal CRUD path, and returns the raw DB so a test can
// tamper with the stored row the way an attacker with DB write would.
func newEncryptedChannelWorld(t *testing.T) (*KeyorixCore, *gorm.DB, *encryption.Service, uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.NotificationChannel{}, &models.AuditEvent{}))

	ls := store.NewLocalStorage(db)
	enc := newTestEncryptionService(t)
	c := NewKeyorixCore(ls)
	c.webhookURLValidator = noopWebhookURLValidator
	c.SetAuthEncryptor(enc)

	created, err := c.CreateNotificationChannel(context.Background(),
		&models.NotificationChannel{Name: "ops-hook", Type: "webhook", URL: "https://hooks.example.com/real"},
		"admin", 1)
	require.NoError(t, err)
	return c, db, enc, created.ID
}

// setURLEnc writes url_enc/url_meta straight through GORM, bypassing every
// core-layer encrypt step — the DB-write attacker's capability.
func setURLEnc(t *testing.T, db *gorm.DB, id uint, urlEnc, urlMeta []byte) {
	t.Helper()
	require.NoError(t, db.Model(&models.NotificationChannel{}).Where("id = ?", id).
		Updates(map[string]any{"url_enc": urlEnc, "url_meta": urlMeta}).Error)
}

// TestGetNotificationChannel_PlaintextTagRefusedWhenEncryptionActive is the
// regression test for the tag downgrade. With encryption on, a plaintext tag
// is not a legitimate state: CreateNotificationChannel/UpdateNotificationChannel
// only ever write an envelope, and the startup backfill refuses to finish (and
// so refuses to start the server) while any plaintext row remains. The only way
// to observe one at runtime is that somebody wrote it directly.
func TestGetNotificationChannel_PlaintextTagRefusedWhenEncryptionActive(t *testing.T) {
	t.Parallel()
	c, db, _, id := newEncryptedChannelWorld(t)
	ctx := context.Background()

	// The attacker plants their own URL, unencrypted and unbound.
	setURLEnc(t, db, id,
		ports.WrapNotificationChannelURL(ports.NotificationChannelURLTagPlaintext, []byte("https://attacker.example.com/collect")),
		nil)

	_, err := c.GetNotificationChannel(ctx, id)
	require.Error(t, err, "a plaintext-tagged URL must be refused while encryption is active -- accepting it lets a DB writer redirect every alert for this channel")
	assert.NotContains(t, errString(err), "attacker.example.com", "the refusal must not echo the planted URL back")

	// And the fail-closed list must refuse too, not quietly skip the row.
	_, lerr := c.ListNotificationChannels(ctx)
	require.Error(t, lerr)
}

// TestGetNotificationChannel_NonAADEnvelopeRefused is the regression test for
// the decryption oracle. The envelope below is a perfectly valid encryption
// under the install's own DEK — it simply has no aad_version, which is what
// made DecryptSecretWithAAD skip the AAD check entirely. Its plaintext is
// deliberately something that was never a URL, standing in for ciphertext
// lifted from another table.
func TestGetNotificationChannel_NonAADEnvelopeRefused(t *testing.T) {
	t.Parallel()
	c, db, enc, id := newEncryptedChannelWorld(t)
	ctx := context.Background()

	stolen, meta, err := enc.EncryptSecret([]byte("super-secret-value-from-another-table"))
	require.NoError(t, err)
	setURLEnc(t, db, id, ports.WrapNotificationChannelURL(ports.NotificationChannelURLTagEncrypted, stolen), meta)

	got, err := c.GetNotificationChannel(ctx, id)
	require.Error(t, err, "an envelope with no aad_version must be refused for this column: url_enc has no legitimate pre-AAD rows, so the no-AAD fallback is purely an attacker's decryption oracle")
	if got != nil {
		assert.NotEqual(t, "super-secret-value-from-another-table", got.URL,
			"the stolen plaintext must never be returned")
	}
	assert.NotContains(t, errString(err), "super-secret-value-from-another-table",
		"the refusal must not leak the decrypted plaintext either")
}

// TestGetNotificationChannel_CrossRowCiphertextSwapRefused is the AAD binding
// doing its actual job: channel A's own, properly AAD-bound envelope must not
// decrypt when moved onto channel B's row. This one is expected to pass before
// the fix as well as after — it is here because the oracle above proves the
// binding can be SIDESTEPPED, and a reader needs to see that the binding
// itself is sound when it is not being bypassed.
func TestGetNotificationChannel_CrossRowCiphertextSwapRefused(t *testing.T) {
	t.Parallel()
	c, db, _, idA := newEncryptedChannelWorld(t)
	ctx := context.Background()

	chB, err := c.CreateNotificationChannel(ctx,
		&models.NotificationChannel{Name: "other-hook", Type: "webhook", URL: "https://hooks.example.com/other"},
		"admin", 1)
	require.NoError(t, err)

	// Lift A's stored envelope verbatim onto B's row.
	var rowA models.NotificationChannel
	require.NoError(t, db.First(&rowA, idA).Error)
	setURLEnc(t, db, chB.ID, rowA.URLEnc, rowA.URLMeta)

	got, err := c.GetNotificationChannel(ctx, chB.ID)
	require.Error(t, err, "channel A's ciphertext must not decrypt under channel B's id -- that is what NotificationChannelURLAAD binds")
	if got != nil {
		assert.NotEqual(t, "https://hooks.example.com/real", got.URL)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
