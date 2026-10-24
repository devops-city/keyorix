package http

// folded_credential_test.go — PERF-LEVER2.
//
// On a machine-token cache hit for GET /api/v1/secrets/{id}, the live
// credential re-check (INV-MW-02) also reads the node stamp, the machine's
// roles and the schedule/version state of that secret, in the same statement,
// once this replica has served this machine that secret before. The verdict on
// the credential is the same code at the same middleware position; the node
// answers are only parked for the secret read that follows.
//
// Every test runs on SQLite and Postgres through the production storage
// factory. "Folded" is observed directly: the folded statement is the only
// GORM statement that reads machine_identity_credentials and secret_nodes
// together (the plain credential re-check is a database/sql prepared statement
// and never shows up in the GORM callbacks).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

// fcRead is one machine value read on r: "status value" on success, "status
// body" otherwise.
func fcRead(r *svReplica, token string, id uint) string {
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d?include_value=true", id), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	r.router.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		var resp struct {
			Data struct {
				Value string `json:"value"`
			} `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return fmt.Sprintf("200 %s", resp.Data.Value)
	}
	return fmt.Sprintf("%d %s", rec.Code, svNormalizeBody(rec.Body.String()))
}

// fcStatements runs fn on r and returns the GORM statements r issued.
func fcStatements(r *svReplica, fn func()) []string {
	r.mu.Lock()
	r.counting, r.stmts = true, nil
	r.mu.Unlock()
	fn()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counting = false
	return append([]string(nil), r.stmts...)
}

func fcIsFolded(stmts []string) bool {
	for _, s := range stmts {
		if strings.Contains(s, "machine_identity_credentials c") && strings.Contains(s, "secret_nodes n") {
			return true
		}
	}
	return false
}

// fcReadObserved is fcRead plus whether r issued the folded statement.
func fcReadObserved(r *svReplica, token string, id uint) (string, bool) {
	var got string
	stmts := fcStatements(r, func() { got = fcRead(r, token, id) })
	return got, fcIsFolded(stmts)
}

func newFCWorld(t *testing.T, backend string, replicas int) *svWorld {
	t.Helper()
	customMiddleware.ResetCredentialReadFoldMarksForTest()
	t.Cleanup(customMiddleware.ResetCredentialReadFoldMarksForTest)
	return newSVWorld(t, backend, replicas)
}

// fcWarm: the slow path fills the token cache, the first cache hit marks
// (machine, secret) on r, the second cache hit is folded (when folding is on).
func fcWarm(t *testing.T, w *svWorld, r *svReplica, sec *models.SecretNode, v1 string, wantFolded bool) {
	t.Helper()
	tok := w.tokens["machine"]
	require.Equal(t, "200 "+v1, fcRead(r, tok, sec.ID), "slow path")
	require.Equal(t, "200 "+v1, fcRead(r, tok, sec.ID), "first cache hit")
	got, folded := fcReadObserved(r, tok, sec.ID)
	require.Equal(t, "200 "+v1, got, "warm cache hit")
	require.Equal(t, wantFolded, folded, "warm cache hit folded")
}

func fcMachineCred(t *testing.T, w *svWorld) models.MachineIdentityCredential {
	t.Helper()
	var cred models.MachineIdentityCredential
	require.NoError(t, w.a.db.Where("token_hash = ?", cgSHA256Hex(w.tokens["machine"])).First(&cred).Error)
	return cred
}

func fcAuditRows(t *testing.T, w *svWorld) int64 {
	t.Helper()
	var n int64
	require.NoError(t, w.a.db.Model(&models.AuditEvent{}).Count(&n).Error)
	return n
}

type fcCase struct {
	name string
	end  func(t *testing.T, w *svWorld, sec *models.SecretNode, cred models.MachineIdentityCredential)
}

func fcCredentialCases() []fcCase {
	return []fcCase{
		{"token-revoked", func(t *testing.T, w *svWorld, _ *models.SecretNode, cred models.MachineIdentityCredential) {
			_, err := w.a.c.RevokeMachineToken(context.Background(), w.projID, cred.MachineIdentityID, cred.ID, w.adminID)
			require.NoError(t, err)
		}},
		{"token-expired", func(t *testing.T, w *svWorld, _ *models.SecretNode, cred models.MachineIdentityCredential) {
			// Through Save so the model's BeforeSave hook canonicalizes the time.
			past := time.Now().Add(-time.Minute)
			cred.ExpiresAt = &past
			require.NoError(t, w.a.db.Save(&cred).Error)
		}},
		{"identity-suspended", func(t *testing.T, w *svWorld, _ *models.SecretNode, cred models.MachineIdentityCredential) {
			_, err := w.a.c.TransitionMachineIdentity(context.Background(), w.projID, cred.MachineIdentityID, "suspended", w.adminID)
			require.NoError(t, err)
		}},
		{"identity-revoked", func(t *testing.T, w *svWorld, _ *models.SecretNode, cred models.MachineIdentityCredential) {
			_, err := w.a.c.TransitionMachineIdentity(context.Background(), w.projID, cred.MachineIdentityID, "revoked", w.adminID)
			require.NoError(t, err)
		}},
		{"credential-row-deleted", func(t *testing.T, w *svWorld, _ *models.SecretNode, cred models.MachineIdentityCredential) {
			require.NoError(t, w.a.db.Delete(&models.MachineIdentityCredential{}, cred.ID).Error)
		}},
		{"cidr-narrowed", func(t *testing.T, w *svWorld, _ *models.SecretNode, cred models.MachineIdentityCredential) {
			require.NoError(t, w.a.db.Model(&models.MachineIdentityCredential{}).Where("id = ?", cred.ID).
				Update("allowed_c_id_rs", `["10.0.0.0/8"]`).Error)
		}},
	}
}

// TestFoldedCredentialCheck_RefusesExactlyAsUnfolded: every way a cached
// machine token stops being good, ended on replica A, then used on replica B,
// once with the fold armed and once with it off. Status, body, the follow-up
// request (eviction) and the audit row count must be identical. The last case
// makes the folded statement itself fail: it must fall back to the plain
// credential statement, never to the cached snapshot.
func TestFoldedCredentialCheck_RefusesExactlyAsUnfolded(t *testing.T) {
	cases := append(fcCredentialCases(), fcCase{"folded-statement-errors", func(t *testing.T, w *svWorld, _ *models.SecretNode, cred models.MachineIdentityCredential) {
		// system_metadata is read only by the folded statement on this path;
		// renaming it makes that statement fail on this database.
		require.NoError(t, w.a.db.Exec("ALTER TABLE system_metadata RENAME TO system_metadata_fc_off").Error)
		_, err := w.a.c.RevokeMachineToken(context.Background(), w.projID, cred.MachineIdentityID, cred.ID, w.adminID)
		require.NoError(t, err)
	}})
	type outcome struct {
		first, second string
		audit         int64
	}
	cgBackends(t, func(t *testing.T, backend string) {
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				run := func(fold bool) outcome {
					restore := customMiddleware.SetCredentialReadFoldForTest(fold)
					defer restore()
					w := newFCWorld(t, backend, 2)
					sec, v1 := w.newSecret(t, nil)
					fcWarm(t, w, w.b, sec, v1, fold)
					cred := fcMachineCred(t, w)
					tc.end(t, w, sec, cred)
					before := fcAuditRows(t, w)
					tok := w.tokens["machine"]
					first, folded := fcReadObserved(w.b, tok, sec.ID)
					if tc.name != "folded-statement-errors" {
						require.Equal(t, fold, folded, "the refused read folded")
					}
					second := fcRead(w.b, tok, sec.ID)
					return outcome{first: first, second: second, audit: fcAuditRows(t, w) - before}
				}
				folded, plain := run(true), run(false)
				require.NotEqual(t, "200", folded.first[:3], "%s must be refused", tc.name)
				require.Equal(t, plain, folded, "%s: the folded check must refuse exactly as the plain one", tc.name)
			})
		}
	})
}

// TestFoldedCredentialCheck_ShapeIndependentOfSecret: for a revoked token on a
// cache hit, what the credential re-check runs does not depend on whether the
// requested secret exists or is cached on this replica; only on whether this
// machine has itself read that secret on this replica before.
func TestFoldedCredentialCheck_ShapeIndependentOfSecret(t *testing.T) {
	type result struct {
		resp  string
		stmts []string
	}
	cgBackends(t, func(t *testing.T, backend string) {
		variant := func(t *testing.T, target string) result {
			w := newFCWorld(t, backend, 1)
			tok := w.tokens["machine"]
			z, vz := w.newSecret(t, nil)
			x, vx := w.newSecret(t, nil)
			require.Equal(t, "200 "+vz, fcRead(w.a, tok, z.ID), "fill the token cache")
			require.Equal(t, "200 "+vz, fcRead(w.a, tok, z.ID), "cache hit, marks z only")
			var id uint
			switch target {
			case "cached-by-another-principal":
				require.Equal(t, "200 "+vx, fcRead(w.a, w.tokens["human"], x.ID), "warm x's node entry")
				id = x.ID
			case "exists-cold":
				id = x.ID
			case "does-not-exist":
				id = x.ID + 1000
			case "marked":
				require.Equal(t, "200 "+vx, fcRead(w.a, tok, x.ID))
				id = x.ID
			}
			require.NoError(t, w.a.db.Model(&models.MachineIdentityCredential{}).
				Where("token_hash = ?", cgSHA256Hex(tok)).Update("revoked", true).Error)
			var r result
			r.stmts = fcStatements(w.a, func() { r.resp = fcRead(w.a, tok, id) })
			return r
		}
		base := variant(t, "exists-cold")
		require.Contains(t, base.resp, "401")
		require.False(t, fcIsFolded(base.stmts), "%q", base.stmts)
		for _, target := range []string{"cached-by-another-principal", "does-not-exist"} {
			got := variant(t, target)
			require.Equal(t, base.resp, got.resp, target)
			require.Equal(t, base.stmts, got.stmts, "%s: the revoked token's statements must not depend on the secret", target)
		}
		marked := variant(t, "marked")
		require.Equal(t, base.resp, marked.resp)
		require.True(t, fcIsFolded(marked.stmts), "only a secret this machine already read here is folded")
	})
}

// TestFoldedCredential_CrossReplicaInvalidation: replica B is warm and folded;
// each change is made through replica A (own pool, own caches). B's very next
// read must answer exactly what replica C, which has never served this
// secret, answers, and differently from before the change. Adapted from
// VALUE-CACHE-1's deferred-read invalidation cases.
func TestFoldedCredential_CrossReplicaInvalidation(t *testing.T) {
	cases := append(fcCredentialCases()[:4:4], fcCredentialCases()[5],
		fcCase{"rotation", func(t *testing.T, w *svWorld, sec *models.SecretNode, _ models.MachineIdentityCredential) {
			w.rotate(t, w.a.c, sec, "fc-rotated")
		}},
		fcCase{"node-suspended", func(t *testing.T, w *svWorld, sec *models.SecretNode, _ models.MachineIdentityCredential) {
			require.NoError(t, w.a.db.Exec("UPDATE secret_nodes SET status = 'suspended' WHERE id = ?", sec.ID).Error)
		}},
		fcCase{"node-deleted", func(t *testing.T, w *svWorld, sec *models.SecretNode, _ models.MachineIdentityCredential) {
			require.NoError(t, w.a.db.Exec("UPDATE secret_nodes SET deleted_at = ? WHERE id = ?", time.Now(), sec.ID).Error)
		}},
		fcCase{"schedule-closed", func(t *testing.T, w *svWorld, sec *models.SecretNode, _ models.MachineIdentityCredential) {
			start, end := svDenyHours(time.Now().UTC().Hour())
			w.putSchedule(t, w.a.db, sec.ID, "*", start, end, "UTC")
		}},
		fcCase{"machine-role-removed", func(t *testing.T, w *svWorld, _ *models.SecretNode, cred models.MachineIdentityCredential) {
			require.NoError(t, w.a.db.Exec("DELETE FROM machine_identity_roles WHERE machine_identity_id = ?", cred.MachineIdentityID).Error)
		}},
		fcCase{"role-permission-removed", func(t *testing.T, w *svWorld, _ *models.SecretNode, _ models.MachineIdentityCredential) {
			var role models.Role
			require.NoError(t, w.a.db.Where("name = ?", "sv-reader").First(&role).Error)
			require.NoError(t, w.a.db.Exec("DELETE FROM role_permissions WHERE role_id = ?", role.ID).Error)
			require.NoError(t, w.a.db.Exec("UPDATE system_metadata SET value = value || 'x' WHERE key = 'role_permissions_generation'").Error)
		}},
		// #3259: a direct database change to role_permissions / permissions,
		// with nothing bumping the generation by hand (the case above does,
		// which is what hid the gap): the triggers must move it.
		fcCase{"role-permission-removed-direct-sql", func(t *testing.T, w *svWorld, _ *models.SecretNode, _ models.MachineIdentityCredential) {
			var role models.Role
			require.NoError(t, w.a.db.Where("name = ?", "sv-reader").First(&role).Error)
			require.NoError(t, w.a.db.Exec("DELETE FROM role_permissions WHERE role_id = ?", role.ID).Error)
		}},
		fcCase{"permission-renamed-direct-sql", func(t *testing.T, w *svWorld, _ *models.SecretNode, _ models.MachineIdentityCredential) {
			require.NoError(t, w.a.db.Exec("UPDATE permissions SET name = name || '.renamed' WHERE name = 'secrets.read'").Error)
		}},
		// REVIEW-LEVER2: a classification change on the node the fold parks. The
		// restricted-read gate is off by default (a classification is then only a
		// label and the read is unchanged), so every replica runs with it armed;
		// the secret is unclassified while B warms and folds, and turns "restricted"
		// on A. A machine read of a restricted secret is always denied under the
		// gate, so B (folded) must refuse exactly as C (cold) does.
		fcCase{"classification-restricted-direct-sql", func(t *testing.T, w *svWorld, sec *models.SecretNode, _ models.MachineIdentityCredential) {
			for _, r := range []*svReplica{w.a, w.b, w.c} {
				r.c.SetClassificationRestrictedRequiresPermission(true)
			}
			require.NoError(t, w.a.db.Exec("UPDATE secret_nodes SET classification = ? WHERE id = ?", "restricted", sec.ID).Error)
		}},
		fcCase{"epoch-trigger-dropped-then-write", func(t *testing.T, w *svWorld, sec *models.SecretNode, _ models.MachineIdentityCredential) {
			drop := "DROP TRIGGER trg_secret_nodes_cache_epoch"
			if w.backend == "postgres" {
				drop += " ON secret_nodes"
			}
			require.NoError(t, w.a.db.Exec(drop).Error)
			require.NoError(t, w.a.db.Exec("UPDATE secret_nodes SET status = 'suspended' WHERE id = ?", sec.ID).Error)
		}},
	)
	cgBackends(t, func(t *testing.T, backend string) {
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				svAvoidHourBoundary(t)
				w := newFCWorld(t, backend, 3)
				sec, v1 := w.newSecret(t, nil)
				fcWarm(t, w, w.b, sec, v1, true)
				tc.end(t, w, sec, fcMachineCred(t, w))
				tok := w.tokens["machine"]
				got, folded := fcReadObserved(w.b, tok, sec.ID)
				require.True(t, folded, "B's read after the change must take the folded path")
				require.NotEqual(t, "200 "+v1, got, "B must see %s made on A", tc.name)
				require.Equal(t, fcRead(w.c, tok, sec.ID), got, "B (warm, folded) must answer as C (cold) after %s", tc.name)
			})
		}
	})
}
