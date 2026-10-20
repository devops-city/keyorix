package handlers

// AUTH-2 item 1 (#3298) through the real handler: a setup consume that fails
// after the token was validated answers the generic setup failure AND leaves
// the link usable, because core commits the consume, the password, the PAT
// revocation and the session (or MFA challenge) in one transaction. Before,
// the token was spent first: the retry got "already used" over a changed
// password.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func postConsumeSetupToken(t *testing.T, h *AuthHandler, token string) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(`{"token":%q,"password":%q}`, token, undeliveredSetupPassword+"x")
	w := httptest.NewRecorder()
	h.ConsumeSetup(w, httptest.NewRequest(http.MethodPost, "/auth/setup/consume", strings.NewReader(body)))
	return w
}

func TestConsumeSetup_FailedConsumeLeavesTheLinkUsable(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mfa    bool
		method string
	}{
		{"session/identity read", false, "GetUserPermissions"},
		{"session/insert", false, "CreateSession"},
		{"session/PAT revocation", false, "RevokeAllPersonalAccessTokensForUser"},
		{"mfa/challenge insert", true, "CreateMFAChallenge"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, c, fs, st, adminID := newUndeliveredSetupFixture(t)
			name := "atomic" + strings.ReplaceAll(strings.ReplaceAll(tc.name, "/", ""), " ", "")
			token := issueSetupTokenForUserS11(t, c, adminID, name+"@example.com", name)
			u, err := c.GetUserByUsername(context.Background(), name)
			require.NoError(t, err)
			if tc.mfa {
				require.NoError(t, st.DB().Model(&models.User{}).Where("id = ?", u.ID).Update("mfa_enabled", true).Error)
			}

			fs.Arm(&faultstorage.FaultSpec{Method: tc.method, NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("injected: " + tc.method)})
			w := postConsumeSetupToken(t, h, token)
			require.True(t, fs.Fired(), "the %s fault must fire", tc.method)
			require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			require.Contains(t, w.Body.String(), "This setup link could not be completed")
			require.Zero(t, countSessions(t, st, u.ID))

			fs.Arm(nil)
			w = postConsumeSetupToken(t, h, token)
			require.Equal(t, http.StatusOK, w.Code, "the same link must still work after a failed consume: %s", w.Body.String())
			if tc.mfa {
				require.Contains(t, w.Body.String(), `"mfa_required":true`)
			} else {
				require.Equal(t, 1, countSessions(t, st, u.ID))
			}
		})
	}
}
