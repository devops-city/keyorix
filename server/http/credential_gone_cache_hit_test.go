package http

// credential_gone_cache_hit_test.go — CRED-CACHE-REVOKE-1.
//
// A machine token or PAT that authenticated once is served from the
// process's auth cache (validTokenTTL) and re-checked live on every hit
// (serveAuthCacheHit -> CurrentMachineTokenRestriction / CurrentPATRestriction,
// INV-MW-02/05). The replica that ends the credential evicts its own cache;
// every OTHER replica relies on that live re-check alone.
//
// Each case below fills replica B's cache with one successful request, ends
// the credential through replica A (own pool, own core, no cache invalidator
// wired, so nothing evicts B's entry: B stands in for every other replica),
// then authenticates on B again immediately. Expected: refused with exactly
// the response an unknown token of the same kind gets, so a client cannot tell
// "deleted" from "never existed".
//
// The "row deleted" cases have no API path today (machine credentials and
// identities are only ever revoked/transitioned, never hard-deleted; PAT rows
// are hard-deleted only by the user purge, after DeleteUser has already
// revoked them). They delete the row directly to pin the contract for when a
// path appears (manual DB cleanup, a future purge, a restore): before the fix
// a vanished credential row was read as "lookup failed, can't tell" and B
// kept serving the cached login until the entry expired.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// cgGet authenticates one request on r and returns "status body".
func cgGet(r *svReplica, token, url string) string {
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	r.router.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		return "200"
	}
	return fmt.Sprintf("%d %s", rec.Code, svNormalizeBody(rec.Body.String()))
}

func cgSHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

type cgCase struct {
	name string
	end  func(t *testing.T, w *svWorld, ids cgIDs)
}

type cgIDs struct {
	machineID, credID uint // machine-token cases
	userID, patID     uint // PAT cases
}

func cgBackends(t *testing.T, run func(t *testing.T, backend string)) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) { run(t, backend) })
	}
}

func TestCredentialEnded_MachineToken_RefusedOnOtherReplicaCacheHit(t *testing.T) {
	cases := []cgCase{
		{"credential-revoked", func(t *testing.T, w *svWorld, ids cgIDs) {
			_, err := w.a.c.RevokeMachineToken(context.Background(), w.projID, ids.machineID, ids.credID, w.adminID)
			require.NoError(t, err)
		}},
		{"identity-suspended", func(t *testing.T, w *svWorld, ids cgIDs) {
			_, err := w.a.c.TransitionMachineIdentity(context.Background(), w.projID, ids.machineID, "suspended", w.adminID)
			require.NoError(t, err)
		}},
		{"identity-revoked", func(t *testing.T, w *svWorld, ids cgIDs) {
			_, err := w.a.c.TransitionMachineIdentity(context.Background(), w.projID, ids.machineID, "revoked", w.adminID)
			require.NoError(t, err)
		}},
		{"credential-row-deleted", func(t *testing.T, w *svWorld, ids cgIDs) {
			require.NoError(t, w.a.db.Delete(&models.MachineIdentityCredential{}, ids.credID).Error)
		}},
		{"identity-row-deleted", func(t *testing.T, w *svWorld, ids cgIDs) {
			require.NoError(t, w.a.db.Delete(&models.MachineIdentity{}, ids.machineID).Error)
		}},
	}
	cgBackends(t, func(t *testing.T, backend string) {
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				w := newSVWorld(t, backend, 2)
				sec, _ := w.newSecret(t, nil)
				url := fmt.Sprintf("/api/v1/secrets/%d", sec.ID)
				token := w.tokens["machine"]
				var cred models.MachineIdentityCredential
				require.NoError(t, w.a.db.Where("token_hash = ?", cgSHA256Hex(token)).First(&cred).Error)

				require.Equal(t, "200", cgGet(w.b, token, url), "fill B's cache")
				require.Equal(t, "200", cgGet(w.b, token, url), "B serves the cache hit")
				tc.end(t, w, cgIDs{machineID: cred.MachineIdentityID, credID: cred.ID})

				unknown := cgGet(w.b, "kx_machine_"+fmt.Sprintf("%064d", w.seq.Add(1)), url)
				require.Contains(t, unknown, "401")
				require.Equal(t, unknown, cgGet(w.b, token, url),
					"after %s via A, B must refuse the cached machine token at once, exactly like an unknown token", tc.name)
				require.Equal(t, unknown, cgGet(w.b, token, url), "and keep refusing it (evicted, slow path)")
			})
		}
	})
}

func TestCredentialEnded_PAT_RefusedOnOtherReplicaCacheHit(t *testing.T) {
	cases := []cgCase{
		{"pat-revoked", func(t *testing.T, w *svWorld, ids cgIDs) {
			_, err := w.a.c.RevokeOwnPAT(context.Background(), ids.userID, ids.patID)
			require.NoError(t, err)
		}},
		{"user-deleted", func(t *testing.T, w *svWorld, ids cgIDs) {
			require.NoError(t, w.a.c.DeleteUser(context.Background(), w.adminID, ids.userID))
		}},
		{"scim-deprovisioned", func(t *testing.T, w *svWorld, ids cgIDs) {
			require.NoError(t, w.a.db.Model(&models.User{}).Where("id = ?", ids.userID).Update("external_id", "ext-cg").Error)
			require.NoError(t, w.a.c.DeprovisionSCIMUser(context.Background(), w.adminID, ids.userID))
		}},
		{"user-deleted-and-purged", func(t *testing.T, w *svWorld, ids cgIDs) {
			ctx := context.Background()
			require.NoError(t, w.a.c.DeleteUser(ctx, w.adminID, ids.userID))
			res, err := w.a.c.PurgeExpiredSoftDeletes(ctx, time.Now().Add(time.Hour))
			require.NoError(t, err)
			require.EqualValues(t, 1, res.Users)
		}},
		{"pat-row-deleted", func(t *testing.T, w *svWorld, ids cgIDs) {
			require.NoError(t, w.a.db.Delete(&models.PersonalAccessToken{}, ids.patID).Error)
		}},
	}
	cgBackends(t, func(t *testing.T, backend string) {
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				w := newSVWorld(t, backend, 2)
				ctx := context.Background()
				sec, _ := w.newSecret(t, nil)
				url := fmt.Sprintf("/api/v1/secrets/%d", sec.ID)
				u, err := w.a.c.CreateUser(ctx, &core.CreateUserRequest{Username: "cguser", Email: "cguser@x.io", Password: svPassword})
				require.NoError(t, err)
				var role models.Role
				require.NoError(t, w.a.db.Where("name = ?", "sv-reader").First(&role).Error)
				require.NoError(t, w.a.c.AssignUserRole(ctx, 0, u.ID, role.ID, core.Scope{ProjectID: w.projID}, false))
				pat, err := w.a.c.CreateOwnPAT(ctx, u.ID, "cg", nil, nil, 0, 0, nil)
				require.NoError(t, err)

				require.Equal(t, "200", cgGet(w.b, pat.PlainToken, url), "fill B's cache")
				require.Equal(t, "200", cgGet(w.b, pat.PlainToken, url), "B serves the cache hit")
				tc.end(t, w, cgIDs{userID: u.ID, patID: pat.Token.ID})

				unknown := cgGet(w.b, "kx_pat_"+fmt.Sprintf("%064d", w.seq.Add(1)), url)
				require.Contains(t, unknown, "401")
				require.Equal(t, unknown, cgGet(w.b, pat.PlainToken, url),
					"after %s via A, B must refuse the cached PAT at once, exactly like an unknown token", tc.name)
				require.Equal(t, unknown, cgGet(w.b, pat.PlainToken, url), "and keep refusing it (evicted, slow path)")
			})
		}
	})
}
