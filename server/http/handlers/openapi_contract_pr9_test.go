// openapi_contract_pr9_test.go — ADR-074 registry population for the operations
// docs/cli-split-inventory.md §7 PR 9 (share) added response schemas for. Each test
// below drives the real handler through a happy path and calls
// contracttest.AssertOpenAPIResponse so the operation moves from "pending" to
// genuinely enforced -- see CLAUDE.md's "a mechanism must be validated against a
// failure that actually happened" and openapi_contract_pr3_test.go's identical
// precedent. Each test is self-contained (its own fixture), not grafted onto an
// existing test. Fixture shape (project + live-owner UserRole + recipient
// membership) mirrors shares_s13_test.go's TestShareSecret_Success_S13 and
// TestRevokeShare_Success_S13, which already establish what ShareSecret's
// requireLiveOwnerAuthority / IsProjectMember gates need.
package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/http/handlers/contracttest"
)

func TestContractPR9_ShareSecret(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	require.NoError(t, db.Create(&models.Project{Name: "contract-pr9-share-proj"}).Error)
	u := &models.User{Username: "contract-pr9-recip", Email: "contract-pr9-recip@example.test", DisplayName: "R"}
	require.NoError(t, db.Create(u).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: u.ID, RoleID: 1, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1}).Error)
	secret := &models.SecretNode{Name: "contract-pr9-share-secret", IsSecret: true, OwnerID: 1, ProjectID: 1}
	require.NoError(t, db.Create(secret).Error)

	h, err := NewShareHandler(cs)
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]any{"recipient_id": u.ID, "permission": "read"})
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPost, "/api/v1/secrets/1/share", bytes.NewReader(body)),
		"id", fmt.Sprintf("%d", secret.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ShareSecret(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusCreated, w.Code)
}

func TestContractPR9_ListSecretShares(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	require.NoError(t, db.Create(&models.Project{Name: "contract-pr9-list-shares-proj"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1}).Error)
	secret := &models.SecretNode{Name: "contract-pr9-list-shares-secret", IsSecret: true, OwnerID: 1, ProjectID: 1}
	require.NoError(t, db.Create(secret).Error)
	require.NoError(t, db.Create(&models.ShareRecord{SecretID: secret.ID, OwnerID: 1, RecipientID: 2, IsGroup: false, Permission: "read"}).Error)

	h, err := NewShareHandler(cs)
	require.NoError(t, err)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1/shares", nil),
		"id", fmt.Sprintf("%d", secret.ID),
	))
	w := httptest.NewRecorder()
	h.ListSecretShares(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR9_UpdateSharePermission(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	require.NoError(t, db.Create(&models.Project{Name: "contract-pr9-update-proj"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1}).Error)
	secret := &models.SecretNode{Name: "contract-pr9-update-secret", IsSecret: true, OwnerID: 1, ProjectID: 1}
	require.NoError(t, db.Create(secret).Error)
	share := &models.ShareRecord{SecretID: secret.ID, OwnerID: 1, RecipientID: 2, IsGroup: false, Permission: "read"}
	require.NoError(t, db.Create(share).Error)

	h, err := NewShareHandler(cs)
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]any{"permission": "write"})
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPut, "/api/v1/shares/1", bytes.NewReader(body)),
		"id", fmt.Sprintf("%d", share.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.UpdateSharePermission(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR9_RemoveSelfFromShare(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	require.NoError(t, db.Create(&models.Project{Name: "contract-pr9-self-remove-proj"}).Error)
	secret := &models.SecretNode{Name: "contract-pr9-self-remove-secret", IsSecret: true, OwnerID: 2, ProjectID: 1}
	require.NoError(t, db.Create(secret).Error)
	// Caller (UserID=1, from withUserCtx) is the RECIPIENT here -- self-remove acts
	// on the caller's own share, not one they own.
	require.NoError(t, db.Create(&models.ShareRecord{SecretID: secret.ID, OwnerID: 2, RecipientID: 1, IsGroup: false, Permission: "read"}).Error)

	h, err := NewShareHandler(cs)
	require.NoError(t, err)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodDelete, "/api/v1/secrets/1/self-share", nil),
		"id", fmt.Sprintf("%d", secret.ID),
	))
	w := httptest.NewRecorder()
	h.RemoveSelfFromShare(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusNoContent, w.Code)
}

func TestContractPR9_ListSharedSecrets(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	require.NoError(t, db.Create(&models.Project{Name: "contract-pr9-shared-secrets-proj"}).Error)
	secret := &models.SecretNode{Name: "contract-pr9-shared-secrets-secret", IsSecret: true, OwnerID: 2, ProjectID: 1}
	require.NoError(t, db.Create(secret).Error)
	require.NoError(t, db.Create(&models.ShareRecord{SecretID: secret.ID, OwnerID: 2, RecipientID: 1, IsGroup: false, Permission: "read"}).Error)

	h, err := NewShareHandler(cs)
	require.NoError(t, err)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/shared-secrets", nil))
	w := httptest.NewRecorder()
	h.ListSharedSecrets(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR9_ListSharedSecretsForUser(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	require.NoError(t, db.Create(&models.Project{Name: "contract-pr9-shared-secrets-user-proj"}).Error)
	secret := &models.SecretNode{Name: "contract-pr9-shared-secrets-user-secret", IsSecret: true, OwnerID: 2, ProjectID: 1}
	require.NoError(t, db.Create(secret).Error)
	// Target the caller's own ID (1): the self-target branch skips the admin-rank
	// ceiling check entirely, keeping this fixture focused on the route/schema, not
	// core.ListSharedSecretsForUser's separate admin-ceiling behavior.
	require.NoError(t, db.Create(&models.ShareRecord{SecretID: secret.ID, OwnerID: 2, RecipientID: 1, IsGroup: false, Permission: "read"}).Error)

	h, err := NewShareHandler(cs)
	require.NoError(t, err)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/users/1/shared-secrets", nil),
		"id", "1",
	))
	w := httptest.NewRecorder()
	h.ListSharedSecretsForUser(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR9_ListGroupShares(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	require.NoError(t, db.Create(&models.Project{Name: "contract-pr9-group-shares-proj"}).Error)
	g := &models.Group{Name: "contract-pr9-group-shares-group"}
	require.NoError(t, db.Create(g).Error)
	secret := &models.SecretNode{Name: "contract-pr9-group-shares-secret", IsSecret: true, OwnerID: 1, ProjectID: 1}
	require.NoError(t, db.Create(secret).Error)
	require.NoError(t, db.Create(&models.ShareRecord{SecretID: secret.ID, OwnerID: 1, RecipientID: g.ID, IsGroup: true, Permission: "read"}).Error)

	h, err := NewShareHandler(cs)
	require.NoError(t, err)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/groups/1/shares", nil),
		"id", fmt.Sprintf("%d", g.ID),
	))
	w := httptest.NewRecorder()
	h.ListGroupShares(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

// TestContractShare2_SearchShareRecipients validates GET
// /api/v1/projects/{id}/share-recipients (SHARE-2) against its response schema,
// which forbids any field beyond id, username, display_name and email.
func TestContractShare2_SearchShareRecipients(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	require.NoError(t, db.Create(&models.Project{Name: "contract-share2-proj"}).Error)
	u := &models.User{Username: "contract-share2-recip", Email: "contract-share2-recip@example.test", DisplayName: "R", AccountState: "active"}
	require.NoError(t, db.Create(u).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: u.ID, RoleID: 1, ProjectID: 1}).Error)

	h, err := NewShareHandler(cs)
	require.NoError(t, err)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/share-recipients?q=contract&page_size=5", nil),
		"id", "1",
	))
	w := httptest.NewRecorder()
	h.SearchShareRecipients(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"username":"contract-share2-recip"`)
}
