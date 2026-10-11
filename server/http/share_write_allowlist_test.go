// share_write_allowlist_test.go — #3001 follow-up (Andrei, 2026-10-10 19:33): a WRITE
// share elevates a project member for exactly three things on that one secret: update
// its value, update its metadata, rotate it. Everything else a secrets.write route can
// do (suspend/resume, move, transfer ownership, re-share, revoke others' shares,
// rollback, dependencies, classification, auto-rotate, restore, anything project-level)
// still needs a real project role. A READ share is unchanged.
//
// The route list is DERIVED, not hand-picked: TestWriteShareMatrix_EverySecretsWriteRoute
// walks router.go's AST inventory (buildRouteInventory) and sends one request to EVERY
// route gated on permSecretsWrite. A secrets.write route missing from
// writeShareRouteMatrix fails the test, so a new route cannot land without an explicit
// "does a write share elevate this?" decision recorded here (the code-side half of that
// guard is TestShareAwareWriteRoutes_NameTheirAction).
//
// Audit (same decision): share_access_elevated is written when an elevated action is
// PERFORMED (2xx), naming the action, secret, share id and actor; never on a refusal,
// never when the request fails after the gate, never when the role alone allowed it.
package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// shareNotElevatedPhrase is part of the fixed reason a share-aware gate gives when the
// caller's share covers secrets.write but the action is not on the allowlist.
const shareNotElevatedPhrase = "only lets you update its value and metadata or rotate it"

// writeShareCase is one secrets.write route's decision.
type writeShareCase struct {
	// elevated: a write share alone (project_viewer + write share) may perform it.
	elevated bool
	// shareAware: the route's gate consults shares (RequireScopedSecretPermission),
	// so a refusal must carry the share reason. Role-only gates answer the generic 403.
	shareAware bool
	body       string
}

// writeShareRouteMatrix: every route router.go gates on permSecretsWrite. Keyed
// "<METHOD> <pattern>". Exactly three are elevated (plus PUT /secrets/{id} carrying
// both value and metadata).
var writeShareRouteMatrix = map[string]writeShareCase{
	// --- the allowlist ---
	"PUT /api/v1/secrets/{id}":               {elevated: true, shareAware: true, body: `{"value":"matrix-updated-value"}`},
	"PUT /api/v1/secrets/{id}/tags":          {elevated: true, shareAware: true, body: `{"tags":["matrix"]}`},
	"PATCH /api/v1/secrets/{id}/description": {elevated: true, shareAware: true, body: `{"description":"set by a write share"}`},
	"POST /api/v1/secrets/{id}/rotate":       {elevated: true, shareAware: true, body: `{"new_value":"matrix-rotated-value"}`},

	// --- per-secret, share-aware gate, NOT elevated ---
	"PATCH /api/v1/secrets/{id}/auto-rotate":                  {shareAware: true, body: `{"enabled":false}`},
	"PATCH /api/v1/secrets/{id}/classification":               {shareAware: true, body: `{"classification":"public"}`},
	"POST /api/v1/secrets/{id}/dependencies":                  {shareAware: true, body: `{"depends_on_id":1}`},
	"DELETE /api/v1/secrets/{id}/dependencies/{depId}":        {shareAware: true},
	"POST /api/v1/secrets/{id}/move":                          {shareAware: true, body: `{"environment_id":1}`},
	"POST /api/v1/secrets/{id}/resume":                        {shareAware: true, body: `{}`},
	"POST /api/v1/secrets/{id}/rollback":                      {shareAware: true, body: `{"version":1}`},
	"POST /api/v1/secrets/{id}/share":                         {shareAware: true, body: `{"recipient_id":1,"is_group":false,"permission":"read"}`},
	"POST /api/v1/secrets/{id}/suspend":                       {shareAware: true, body: `{"reason":"deny service"}`},
	"POST /api/v1/secrets/{id}/transfer-ownership":            {shareAware: true, body: `{"new_owner_id":1}`},
	"POST /api/v1/secrets/{id}/versions/{versionId}/comments": {shareAware: true, body: `{"comment":"x"}`},

	// --- role-only gates: a share is never consulted ---
	"POST /api/v1/secrets/{id}/restore":                            {body: `{}`},
	"PUT /api/v1/shares/{id}":                                      {body: `{"permission":"write"}`},
	"DELETE /api/v1/shares/{id}":                                   {},
	"GET /api/v1/projects/{id}/share-recipients":                   {},
	"POST /api/v1/projects":                                        {body: `{"name":"matrix-project"}`},
	"PUT /api/v1/projects/{id}":                                    {body: `{"description":"x"}`},
	"POST /api/v1/projects/{id}/environments":                      {body: `{"name":"matrix-env"}`},
	"POST /api/v1/projects/{id}/environments/{envId}/clone":        {body: `{"name":"matrix-clone"}`},
	"POST /api/v1/projects/{id}/environments/{envId}/copy-secrets": {body: `{}`},
	"POST /api/v1/projects/{id}/secrets/bulk-rename":               {body: `{}`},
	"POST /api/v1/projects/{id}/secrets/bulk-rotate":               {body: `{}`},
	"POST /api/v1/projects/{id}/secrets/extend-expiring":           {body: `{}`},
	"POST /api/v1/projects/{id}/secrets/resume-all":                {body: `{}`},
	"POST /api/v1/projects/{id}/secrets/suspend-all":               {body: `{}`},
	"PUT /api/v1/rotation-policies/{id}":                           {body: `{}`},
	"DELETE /api/v1/rotation-policies/{id}":                        {},
	"POST /api/v1/secret-templates":                                {body: `{}`},
	"PUT /api/v1/secret-templates/{id}":                            {body: `{}`},
	"DELETE /api/v1/secret-templates/{id}":                         {},
	"PATCH /api/v1/dynamic-secrets/configs/{id}/classification":    {body: `{}`},
	"PATCH /api/v1/dynamic-secrets/configs/{id}/enabled":           {body: `{}`},
	"POST /api/v1/dynamic-secrets/configs/{id}/issue":              {body: `{}`},
	"POST /api/v1/dynamic-secrets/configs/{id}/revoke-all":         {body: `{}`},
	"POST /api/v1/dynamic-secrets/leases/{leaseID}/renew":          {body: `{}`},
	"POST /api/v1/dynamic-secrets/leases/{leaseID}/revoke":         {body: `{}`},
}

// writeShareFixture extends the demo seed: alice (project_viewer) holds a share on
// db-password; carol (project_viewer) holds another share on it (the "others' share"
// alice must not touch); a second secret alice also holds a write share on is
// soft-deleted (restore target).
type writeShareFixture struct {
	*shareDemo
	aliceShareID    uint
	carolID         uint
	carolTok        string
	carolShareID    uint
	deletedSecretID uint
	envID           uint
}

func newWriteShareFixture(t *testing.T, alicePermission string) *writeShareFixture {
	t.Helper()
	d := newShareDemo(t)
	d.makeAdminMember(t)
	ctx := context.Background()

	secret, err := d.c.Storage().GetSecret(ctx, d.secretID)
	require.NoError(t, err)

	carol, err := d.c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "carol", Email: "carol@keyorix.demo", DisplayName: "Carol", Password: shareDemoPassword,
	})
	require.NoError(t, err)
	require.NoError(t, d.c.AddProjectMember(ctx, d.adminID, d.projectID, carol.ID, "project_viewer", false))
	sess, _, err := d.c.Login(ctx, &core.LoginRequest{Username: "carol", Password: shareDemoPassword})
	require.NoError(t, err)

	f := &writeShareFixture{shareDemo: d, carolID: carol.ID, carolTok: sess.SessionToken, envID: secret.EnvironmentID}
	f.aliceShareID = d.shareOK(t, d.aliceID, alicePermission)
	f.carolShareID = d.shareOK(t, carol.ID, "read")

	doomed, err := d.c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "doomed", Value: []byte("doomed-v1"), ProjectID: d.projectID, EnvironmentID: secret.EnvironmentID,
		Type: "generic", CreatedBy: "admin", OwnerID: d.adminID,
	})
	require.NoError(t, err)
	_, err = d.c.ShareSecret(ctx, &core.ShareSecretRequest{
		SecretID: doomed.ID, RecipientID: d.aliceID, Permission: alicePermission, SharedBy: d.adminID,
	})
	require.NoError(t, err)
	code, raw := doMachineRequest(t, d.srv, d.adminTok, http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d", doomed.ID), nil)
	require.Equal(t, http.StatusNoContent, code, "soft-delete the restore target: %s", raw)
	f.deletedSecretID = doomed.ID
	return f
}

// concretePath fills a route pattern's parameters with the fixture's ids.
func (f *writeShareFixture) concretePath(pattern string) string {
	id := "1"
	switch {
	case pattern == "/api/v1/secrets/{id}/restore":
		id = strconv.FormatUint(uint64(f.deletedSecretID), 10)
	case strings.HasPrefix(pattern, "/api/v1/secrets/"):
		id = strconv.FormatUint(uint64(f.secretID), 10)
	case strings.HasPrefix(pattern, "/api/v1/shares/"):
		id = strconv.FormatUint(uint64(f.carolShareID), 10)
	case strings.HasPrefix(pattern, "/api/v1/projects/"):
		id = strconv.FormatUint(uint64(f.projectID), 10)
	}
	r := strings.NewReplacer(
		"{id}", id,
		"{envId}", strconv.FormatUint(uint64(f.envID), 10),
		"{depId}", "1", "{versionId}", "1", "{leaseID}", "1",
	)
	return r.Replace(pattern)
}

// secretsWriteRoutes returns router.go's routes gated on permSecretsWrite, elevated
// ones first (so a wrongly-allowed suspend cannot mask a later update result).
func secretsWriteRoutes(t *testing.T) []routeInventoryEntry {
	t.Helper()
	entries := buildRouteInventory(t, filepath.Join(permissionSweepRepoRoot(t), "server", "http", "router.go"))
	var out []routeInventoryEntry
	for _, e := range entries {
		for _, p := range e.GatePerms {
			if p == "permSecretsWrite" {
				out = append(out, e)
				break
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return writeShareRouteMatrix[out[i].key()].elevated && !writeShareRouteMatrix[out[j].key()].elevated
	})
	return out
}

func messageOf(raw string) string {
	var out map[string]interface{}
	if json.Unmarshal([]byte(raw), &out) != nil {
		return raw
	}
	msg, _ := out["message"].(string)
	return msg
}

// TestWriteShareMatrix_EverySecretsWriteRoute is the per-route matrix: alice holds
// project_viewer (secrets.read, no secrets.write) plus a WRITE share on db-password.
func TestWriteShareMatrix_EverySecretsWriteRoute(t *testing.T) {
	f := newWriteShareFixture(t, "write")
	routes := secretsWriteRoutes(t)
	require.Greater(t, len(routes), 30, "calibration: the inventory walk must find the secrets.write family")

	seen := map[string]bool{}
	for _, e := range routes {
		key := e.key()
		seen[key] = true
		tc, ok := writeShareRouteMatrix[key]
		if !assert.True(t, ok, "%s (router.go:%d) is gated on secrets.write but has no writeShareRouteMatrix entry: "+
			"decide whether a write share elevates it (core.secretActionShareElevates) and record it here", key, e.Line) {
			continue
		}
		var body []byte
		if tc.body != "" {
			body = []byte(tc.body)
		}
		code, raw := doMachineRequest(t, f.srv, f.aliceTok, e.Method, f.concretePath(e.Pattern), body)
		if tc.elevated {
			assert.True(t, code >= 200 && code < 300, "%s: a write share must elevate this action, got %d: %s", key, code, raw)
			continue
		}
		if assert.Equal(t, http.StatusForbidden, code, "%s: a write share must NOT elevate this action: %s", key, raw) && tc.shareAware {
			assert.Contains(t, messageOf(raw), shareNotElevatedPhrase,
				"%s: the 403 must say what a share covers and that this needs a project role", key)
		}
	}
	for key := range writeShareRouteMatrix {
		assert.True(t, seen[key], "stale writeShareRouteMatrix entry %q: no such secrets.write route in router.go", key)
	}

	// The refusals changed nothing: the secret is still active, in its project,
	// owned by the admin, and carol's share is intact.
	ctx := context.Background()
	sec, err := f.c.Storage().GetSecret(ctx, f.secretID)
	require.NoError(t, err)
	assert.Equal(t, "active", sec.Status, "suspend must not have landed")
	assert.Equal(t, f.adminID, sec.OwnerID, "ownership must not have moved")
	assert.Equal(t, f.projectID, sec.ProjectID)
	_, err = f.c.Storage().GetShareRecord(ctx, f.carolShareID)
	assert.NoError(t, err, "alice must not be able to revoke carol's share")
}

// TestWriteShareMatrix_ReadShareUnchanged: a READ share elevates no secrets.write
// route at all, and reading still works.
func TestWriteShareMatrix_ReadShareUnchanged(t *testing.T) {
	f := newWriteShareFixture(t, "read")
	for _, e := range secretsWriteRoutes(t) {
		tc := writeShareRouteMatrix[e.key()]
		var body []byte
		if tc.body != "" {
			body = []byte(tc.body)
		}
		code, raw := doMachineRequest(t, f.srv, f.aliceTok, e.Method, f.concretePath(e.Pattern), body)
		assert.Equal(t, http.StatusForbidden, code, "%s: a read share never grants secrets.write: %s", e.key(), raw)
	}
	code, raw := doMachineRequest(t, f.srv, f.aliceTok, http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d", f.secretID), nil)
	assert.Equal(t, http.StatusOK, code, "a read share's holder still reads: %s", raw)
}

// TestWriteShareMatrix_RoleHolderUnaffected: a project_developer (secrets.write by
// role) who ALSO holds a write share keeps every action the role grants, including
// the ones a share does not elevate, and no share_access_elevated row is written for
// any of them: the role allowed it.
func TestWriteShareMatrix_RoleHolderUnaffected(t *testing.T) {
	f := newWriteShareFixture(t, "write")
	ctx := context.Background()
	dev, err := f.c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "dave", Email: "dave@keyorix.demo", DisplayName: "Dave", Password: shareDemoPassword,
	})
	require.NoError(t, err)
	require.NoError(t, f.c.AddProjectMember(ctx, f.adminID, f.projectID, dev.ID, "project_developer", false))
	f.shareOK(t, dev.ID, "write")
	sess, _, err := f.c.Login(ctx, &core.LoginRequest{Username: "dave", Password: shareDemoPassword})
	require.NoError(t, err)
	before := countAuditEvents(t, f.c, f.secretID, string(core.ShareAuditEventAccessElevated))

	for _, step := range []struct{ method, path, body string }{
		{http.MethodPut, "", `{"value":"dev-updated"}`},
		{http.MethodPut, "/tags", `{"tags":["dev"]}`},
		{http.MethodPatch, "/description", `{"description":"dev"}`},
		{http.MethodPost, "/rotate", `{"new_value":"dev-rotated"}`},
		{http.MethodPut, "", `{"expiration":"` + time.Now().Add(48*time.Hour).UTC().Format(time.RFC3339) + `"}`},
		{http.MethodPatch, "/classification", `{"classification":"internal"}`},
		{http.MethodPatch, "/auto-rotate", `{"enabled":false}`},
		{http.MethodPost, "/suspend", `{"reason":"incident"}`},
		{http.MethodPost, "/resume", `{}`},
	} {
		code, raw := doMachineRequest(t, f.srv, sess.SessionToken, step.method,
			fmt.Sprintf("/api/v1/secrets/%d%s", f.secretID, step.path), []byte(step.body))
		assert.True(t, code >= 200 && code < 300, "%s %s: the role grants this; a share must not get in the way, got %d: %s",
			step.method, step.path, code, raw)
	}
	assert.Equal(t, before, countAuditEvents(t, f.c, f.secretID, string(core.ShareAuditEventAccessElevated)),
		"the role allowed every action: no share_access_elevated row")
}

// TestWriteShare_LifecycleFieldsAreNotMetadata: an elevated update may change the
// value and metadata, but not the expiry or read limit (setting either is a way to
// take the secret away from everyone else — the same denial of service as suspend).
// Re-sending the stored values unchanged is not a change.
func TestWriteShare_LifecycleFieldsAreNotMetadata(t *testing.T) {
	f := newWriteShareFixture(t, "write")
	path := fmt.Sprintf("/api/v1/secrets/%d", f.secretID)
	soon := time.Now().Add(time.Minute).UTC().Format(time.RFC3339)

	for _, body := range []string{
		`{"value":"v-with-expiry","expiration":"` + soon + `"}`,
		`{"max_reads":1}`,
	} {
		code, raw := doMachineRequest(t, f.srv, f.aliceTok, http.MethodPut, path, []byte(body))
		if assert.Equal(t, http.StatusForbidden, code, "%s: %s", body, raw) {
			assert.Contains(t, messageOf(raw), shareNotElevatedPhrase, body)
		}
	}
	sec, err := f.c.Storage().GetSecret(context.Background(), f.secretID)
	require.NoError(t, err)
	assert.Nil(t, sec.Expiration, "the refused update must not have set an expiry")
	assert.Nil(t, sec.MaxReads)

	code, raw := doMachineRequest(t, f.srv, f.aliceTok, http.MethodPut, path, []byte(`{"value":"v2","type":"password"}`))
	assert.Equal(t, http.StatusOK, code, "value + type (metadata) is the allowlisted update: %s", raw)
}

// TestWriteShareAudit_OnPerformedActionOnly pins the audit half of the decision.
func TestWriteShareAudit_OnPerformedActionOnly(t *testing.T) {
	f := newWriteShareFixture(t, "write")
	elevated := string(core.ShareAuditEventAccessElevated)
	path := fmt.Sprintf("/api/v1/secrets/%d", f.secretID)

	// Refused (not on the allowlist): no row.
	code, raw := doMachineRequest(t, f.srv, f.aliceTok, http.MethodPost, path+"/suspend", []byte(`{"reason":"x"}`))
	require.Equal(t, http.StatusForbidden, code, raw)
	assert.Zero(t, countAuditEvents(t, f.c, f.secretID, elevated), "a refused action is not an elevation")

	// Authorized by the share at the gate but failed in the handler: not performed, no row.
	code, raw = doMachineRequest(t, f.srv, f.aliceTok, http.MethodPut, path, []byte(`{not json`))
	require.Equal(t, http.StatusBadRequest, code, raw)
	assert.Zero(t, countAuditEvents(t, f.c, f.secretID, elevated),
		"the gate's decision alone must not write the row: the update never happened")

	// Performed: exactly one row naming action, secret, share and actor.
	code, raw = doMachineRequest(t, f.srv, f.aliceTok, http.MethodPut, path, []byte(`{"value":"alice-v2"}`))
	require.Equal(t, http.StatusOK, code, raw)
	rows := auditEventsOfType(t, f.c, f.secretID, elevated)
	require.Len(t, rows, 1, "one performed elevated action, one row")
	ev := rows[0]
	require.NotNil(t, ev.UserID)
	assert.Equal(t, f.aliceID, *ev.UserID, "actor")
	require.NotNil(t, ev.SecretNodeID)
	assert.Equal(t, f.secretID, *ev.SecretNodeID, "secret")
	assert.Contains(t, ev.Description, string(core.SecretActionUpdate), "the row names the action")
	assert.Contains(t, ev.Description, fmt.Sprintf("share %d", f.aliceShareID), "the row names the share")

	// A second performed action is a second row; a rotate names its own action.
	code, raw = doMachineRequest(t, f.srv, f.aliceTok, http.MethodPost, path+"/rotate", []byte(`{"new_value":"alice-v3"}`))
	require.Equal(t, http.StatusOK, code, raw)
	rows = auditEventsOfType(t, f.c, f.secretID, elevated)
	require.Len(t, rows, 2)
	var actions []string
	for _, r := range rows {
		actions = append(actions, r.Description)
	}
	assert.Contains(t, strings.Join(actions, "\n"), string(core.SecretActionRotate))
}

func auditEventsOfType(t *testing.T, c *core.KeyorixCore, secretID uint, eventType string) []*eventRow {
	t.Helper()
	rows, _, err := c.Storage().GetAuditLogs(context.Background(), &storage.AuditFilter{SecretID: &secretID, Page: 1, PageSize: 1000})
	require.NoError(t, err)
	var out []*eventRow
	for _, r := range rows {
		if r.EventType == eventType {
			out = append(out, &eventRow{UserID: r.UserID, SecretNodeID: r.SecretNodeID, Description: r.Description})
		}
	}
	return out
}

type eventRow struct {
	UserID       *uint
	SecretNodeID *uint
	Description  string
}

func countAuditEvents(t *testing.T, c *core.KeyorixCore, secretID uint, eventType string) int {
	t.Helper()
	return len(auditEventsOfType(t, c, secretID, eventType))
}
