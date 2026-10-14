package store

// The raw credential lookup scans its three time columns through sql.NullTime
// (assignCredentialTimes). Golden check: the result is reflect.DeepEqual to the
// previous scan straight into the model's *time.Time / time.Time fields, for
// every NULL/non-NULL combination, on SQLite and (KEYORIX_TEST_PG_DSN) Postgres.

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// directTimeCredentialScan is the scan as it was before assignCredentialTimes:
// times straight into the model's fields.
func directTimeCredentialScan(ctx context.Context, t *testing.T, ls *LocalStorage, hash string) (*models.MachineIdentityCredential, string) {
	t.Helper()
	sqlDB, err := ls.db.DB()
	require.NoError(t, err)
	var c models.MachineIdentityCredential
	var identityState string
	require.NoError(t, sqlDB.QueryRowContext(ctx, rebindForDialect(ls.db.Dialector.Name(), credentialLookupRawQuery), hash).Scan(
		&c.ID, &c.MachineIdentityID, &c.Name, &c.TokenHash, &c.TokenPrefix,
		&c.AllowedCIDRs, &c.LastUsedAt, &c.ExpiresAt, &c.Revoked, &c.CreatedAt,
		&c.Classification, &identityState,
	))
	return &c, identityState
}

func TestCredentialLookupRaw_TimesMatchDirectScan(t *testing.T) {
	for _, backend := range principalPermBackends(t) {
		t.Run(backend, func(t *testing.T) {
			ls, _ := newPrincipalPermStorage(t, backend)
			require.NoError(t, ls.db.AutoMigrate(&models.MachineIdentityCredential{}))
			w := ppWorld{t: t, ls: ls}
			ctx := context.Background()
			mid := w.machine(w.project())
			at := time.Date(2026, 3, 4, 5, 6, 7, 891011000, time.FixedZone("x", 2*3600))
			for i, shape := range []struct{ lastUsed, expires bool }{{false, false}, {true, false}, {false, true}, {true, true}} {
				hash := w.name("times-hash")
				cred := &models.MachineIdentityCredential{
					MachineIdentityID: mid, Name: hash, TokenHash: hash, TokenPrefix: "kx_",
					AllowedCIDRs: strings.Repeat(`["10.0.0.0/8"]`, i%2), Revoked: i == 3,
					CreatedAt: at.Add(time.Duration(i) * time.Hour), Classification: "internal",
				}
				if shape.lastUsed {
					lu := at.Add(time.Minute)
					cred.LastUsedAt = &lu
				}
				if shape.expires {
					ex := at.Add(48 * time.Hour)
					cred.ExpiresAt = &ex
				}
				require.NoError(t, ls.db.Create(cred).Error)

				want, wantState := directTimeCredentialScan(ctx, t, ls, hash)
				got, gotState, handled, err := ls.getMachineIdentityCredentialWithIdentityStateByHashRaw(ctx, hash)
				require.True(t, handled)
				require.NoError(t, err)
				require.Equal(t, wantState, gotState)
				require.Equal(t, want, got, "shape %+v", shape)
				require.Equal(t, shape.lastUsed, got.LastUsedAt != nil)
				require.Equal(t, shape.expires, got.ExpiresAt != nil)
			}
		})
	}
}

// A NULL created_at stays an error, as it was when scanned into a time.Time.
func TestAssignCredentialTimes_NullCreatedAtIsAnError(t *testing.T) {
	var c models.MachineIdentityCredential
	require.ErrorIs(t, assignCredentialTimes(&c, sql.NullTime{}, sql.NullTime{}, sql.NullTime{}), errCredentialCreatedAtNull)
	now := time.Now()
	require.NoError(t, assignCredentialTimes(&c, sql.NullTime{}, sql.NullTime{Time: now, Valid: true}, sql.NullTime{Time: now, Valid: true}))
	require.Nil(t, c.LastUsedAt)
	require.Equal(t, now, *c.ExpiresAt)
	require.Equal(t, now, c.CreatedAt)
}
