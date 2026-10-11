// share_action_allowlist_guard_test.go — the core half of the #3001 follow-up guard
// (Andrei, 2026-10-10 19:33: a write share elevates ONLY update value, update metadata,
// rotate). The allowlist is secretActionShareElevates (share_authz.go) and nothing
// else. These tests fail when:
//   - a SecretAction constant is declared without an explicit allowlist entry (or an
//     entry names no declared constant): every new action needs a decision;
//   - the elevated set drifts from the decision (changing it means editing this test,
//     which a reviewer sees);
//   - something other than the share term reaches the un-allowlisted share lookup
//     (activeShareGrant), which would be a second, unguarded share path.
//
// The transport halves (every secrets.write route/RPC names its action) are
// server/http/share_authz_route_guard_test.go and
// server/grpc/services/share_authz_rpc_guard_test.go; the behavioural matrices are
// server/http/share_write_allowlist_test.go and its gRPC sibling.
package core

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// declaredSecretActions returns the names of the SecretAction-typed constants in
// share_authz.go.
func declaredSecretActions(t *testing.T) map[string]SecretAction {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "share_authz.go", nil, 0)
	require.NoError(t, err)
	out := map[string]SecretAction{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			typ, ok := vs.Type.(*ast.Ident)
			if !ok || typ.Name != "SecretAction" {
				continue
			}
			for i, n := range vs.Names {
				lit, ok := vs.Values[i].(*ast.BasicLit)
				require.True(t, ok, "SecretAction %s must be a string literal", n.Name)
				out[n.Name] = SecretAction(strings.Trim(lit.Value, `"`))
			}
		}
	}
	return out
}

func TestSecretActionAllowlist_EveryActionHasAnExplicitDecision(t *testing.T) {
	declared := declaredSecretActions(t)
	require.Greater(t, len(declared), 10, "calibration: the scan must find the SecretAction constants")
	values := map[SecretAction]string{}
	for name, v := range declared {
		_, ok := secretActionShareElevates[v]
		assert.True(t, ok, "SecretAction %s (%q) has no entry in secretActionShareElevates: decide whether a write share elevates it", name, v)
		prev, dup := values[v]
		assert.False(t, dup, "SecretAction %s and %s share the value %q", name, prev, v)
		values[v] = name
	}
	for v := range secretActionShareElevates {
		_, ok := values[v]
		assert.True(t, ok, "secretActionShareElevates has an entry %q that is not a declared SecretAction constant", v)
	}
	assert.False(t, IsKnownSecretAction(""), "the empty action is never known")
	assert.False(t, ShareElevatesAction(""), "the empty action is never elevated")
}

func TestSecretActionAllowlist_ElevatedSetIsExactlyTheDecision(t *testing.T) {
	var got []string
	for a, elevated := range secretActionShareElevates {
		if elevated {
			got = append(got, string(a))
		}
	}
	sort.Strings(got)
	assert.Equal(t, []string{string(SecretActionRotate), string(SecretActionUpdate), string(SecretActionUpdateMetadata)}, got,
		"Andrei 2026-10-10 19:33: a write share elevates ONLY update value, update metadata and rotate. Widening this "+
			"is a product decision, not a code change")
}

func TestSecretActionAllowlist_OnlyTheShareTermReachesTheRawShareLookup(t *testing.T) {
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	callers := map[string]bool{}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		src, rerr := os.ReadFile(file) // #nosec G304 -- this package's own source files
		require.NoError(t, rerr)
		f, perr := parser.ParseFile(token.NewFileSet(), file, src, 0)
		require.NoError(t, perr)
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil && bodyCalls(fd.Body, "activeShareGrant") {
				callers[fd.Name.Name] = true
			}
		}
	}
	assert.Equal(t, map[string]bool{"sharePermissionFor": true, "shareCoversButNotElevated": true}, callers,
		"activeShareGrant ignores the action allowlist: only the share term (and the refusal explainer) may call it")
}

// TestSecretActionAllowlist_ShareTermDecidesPerAction: behavioural, real storage. A
// member with a no-permission role and a write share.
func TestSecretActionAllowlist_ShareTermDecidesPerAction(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	c, db, secretID := shareTermRig(t)
	ctx, _ := WithShareElevationRecorder(context.Background())
	require.NoError(t, db.Create(&models.ShareRecord{SecretID: secretID, OwnerID: 9, RecipientID: 2, Permission: "write"}).Error)

	for a, elevated := range secretActionShareElevates {
		d, err := c.AuthorizeSecretAction(ctx, 2, secretID, permSecretsWrite, a)
		require.NoError(t, err)
		assert.Equal(t, elevated, d.Allowed, "AuthorizeSecretAction(%s)", a)
		assert.Equal(t, !elevated, d.ShareNotElevated, "a refused %s must report that the share does not cover it", a)

		_, err = c.EnforceSecretActionPermission(ctx, secretID, 2, a)
		if elevated {
			assert.NoError(t, err, "EnforceSecretActionPermission(%s)", a)
		} else {
			assert.ErrorIs(t, err, ErrShareActionNotElevated, "EnforceSecretActionPermission(%s)", a)
		}
	}
	d, err := c.AuthorizeSecretAction(ctx, 2, secretID, permSecretsWrite, "secret.not_a_real_action")
	require.NoError(t, err)
	assert.False(t, d.Allowed, "an unknown action is not elevated (fail closed)")

	// Read is unchanged: no action needed.
	ok, err := c.AuthorizeSecret(ctx, 2, secretID, permSecretsRead)
	require.NoError(t, err)
	assert.True(t, ok, "a write share still grants read")

	// No share at all: the refusal does not claim one.
	d, err = c.AuthorizeSecretAction(ctx, 3, secretID, permSecretsWrite, SecretActionSuspend)
	require.NoError(t, err)
	assert.False(t, d.Allowed)
	assert.False(t, d.ShareNotElevated, "a caller without a share gets the plain refusal")
}

// TestShareElevationAudit_RecordedThenCommitted: a share-made grant writes nothing at
// decision time; CommitShareElevations writes exactly one row per elevation (the
// gate and the handler deciding the same thing count once); a write elevation with
// no recorder is refused.
func TestShareElevationAudit_RecordedThenCommitted(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	c, db, secretID := shareTermRig(t)
	require.NoError(t, db.Create(&models.ShareRecord{SecretID: secretID, OwnerID: 9, RecipientID: 2, Permission: "write"}).Error)
	count := func() int64 {
		var n int64
		require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", string(ShareAuditEventAccessElevated)).Count(&n).Error)
		return n
	}

	ctx, rec := WithShareElevationRecorder(context.Background())
	for i := 0; i < 2; i++ { // the gate, then the handler's own check
		d, err := c.AuthorizeSecretAction(ctx, 2, secretID, permSecretsWrite, SecretActionUpdate)
		require.NoError(t, err)
		require.True(t, d.Allowed)
	}
	assert.Zero(t, count(), "nothing is written when the elevation is decided")
	c.CommitShareElevations(ctx, rec)
	assert.Equal(t, int64(1), count(), "one performed action, one row")
	c.CommitShareElevations(ctx, rec)
	assert.Equal(t, int64(1), count(), "committing twice does not duplicate")

	d, err := c.AuthorizeSecretAction(context.Background(), 2, secretID, permSecretsWrite, SecretActionUpdate)
	require.NoError(t, err)
	assert.False(t, d.Allowed, "without a recorder an elevated write cannot be audited when performed: refused")
}
