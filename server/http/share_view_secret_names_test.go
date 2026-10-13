// share_view_secret_names_test.go — #3153: the Sharing Management list names the secret
// (and its project) instead of "Secret #N", and never names a secret the caller may not
// read. Real router + session tokens for the wire shape; core with a PAT restriction for
// the negative case (the share lists do not filter received/owned shares by PAT, so the
// name is the only thing the read check withholds).
package http

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func viewBySecretName(views []core.ShareView, secretID uint) (core.ShareView, bool) {
	for _, v := range views {
		if v.SecretID == secretID {
			return v, true
		}
	}
	return core.ShareView{}, false
}

func TestOwnedShares_NameTheSecretAndProject(t *testing.T) {
	f := newOwnedShareFixture(t)
	code, out, raw := f.owned(t, f.ownerTok, "")
	require.Equal(t, http.StatusOK, code, raw)
	require.Len(t, out.Data.Data, 2, raw)

	byShare := map[uint]core.ShareView{}
	for _, v := range out.Data.Data {
		byShare[v.ID] = v
	}
	assert.Equal(t, "olga-p", byShare[f.olgaShareP].SecretName, raw)
	assert.Equal(t, f.d.projectID, byShare[f.olgaShareP].ProjectID, raw)
	assert.NotEmpty(t, byShare[f.olgaShareP].ProjectName, raw)
	assert.Equal(t, "olga-pay", byShare[f.olgaSharePayments].SecretName, raw)
	assert.Equal(t, f.otherProjectID, byShare[f.olgaSharePayments].ProjectID, raw)
	assert.Contains(t, raw, `"secretName":"olga-p"`)
}

func TestGlobalShareList_NamesTheSecret(t *testing.T) {
	f := newOwnedShareFixture(t)
	f.d.makeAdminMember(t)
	adminShare := f.d.shareOK(t, f.ids["carol"], "read")

	code, raw := doMachineRequest(t, f.d.srv, f.d.adminTok, http.MethodGet, "/api/v1/shares", nil)
	require.Equal(t, http.StatusOK, code, raw)
	var global ownedShareResponse
	require.NoError(t, json.Unmarshal([]byte(raw), &global))
	require.Len(t, global.Data.Data, 1, raw)
	assert.Equal(t, adminShare, global.Data.Data[0].ID)
	assert.NotEmpty(t, global.Data.Data[0].SecretName, "GET /shares must name the secret: %s", raw)
	assert.NotEmpty(t, global.Data.Data[0].ProjectName, raw)
}

// A caller whose token may not read a secret still lists the share (the list is not
// filtered by PAT) but must not learn the secret's name or project.
func TestShareList_DoesNotNameSecretsTheCallerCannotRead(t *testing.T) {
	f := newOwnedShareFixture(t)
	ctx := context.Background()
	c := f.d.c
	pSecretID := mustShareSecretID(t, f, f.olgaShareP)
	paySecretID := mustShareSecretID(t, f, f.olgaSharePayments)

	cases := []struct {
		name      string
		r         *core.PATRestriction
		wantP     bool
		wantOther bool
	}{
		{"unrestricted (control)", nil, true, true},
		{"confined to P", &core.PATRestriction{ProjectID: f.d.projectID}, true, false},
		{"confined to payments", &core.PATRestriction{ProjectID: f.otherProjectID}, false, true},
		{"no secrets.read", &core.PATRestriction{Permissions: []string{"secrets.write"}}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			views, err := c.ListUserShareViews(core.WithPATRestriction(ctx, tc.r), f.ownerID)
			require.NoError(t, err)
			for _, want := range []struct {
				id      uint
				name    string
				project string
				named   bool
			}{
				{pSecretID, "olga-p", "", tc.wantP},
				{paySecretID, "olga-pay", "", tc.wantOther},
			} {
				v, ok := viewBySecretName(views, want.id)
				require.True(t, ok, "the share is still listed")
				if want.named {
					assert.Equal(t, want.name, v.SecretName)
					assert.NotZero(t, v.ProjectID)
					assert.NotEmpty(t, v.ProjectName)
				} else {
					assert.Empty(t, v.SecretName, "name of a secret the caller cannot read leaked")
					assert.Zero(t, v.ProjectID)
					assert.Empty(t, v.ProjectName)
				}
			}
			raw, err := json.Marshal(views)
			require.NoError(t, err)
			if !tc.wantP {
				assert.NotContains(t, string(raw), "olga-p\"")
			}
			if !tc.wantOther {
				assert.NotContains(t, string(raw), "olga-pay")
			}
		})
	}
}
