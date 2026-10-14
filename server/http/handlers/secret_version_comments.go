// secret_version_comments.go — HTTP handlers for secret version comments.
//
// Three endpoints:
//
//	POST   /api/v1/secrets/{id}/versions/{versionId}/comments
//	GET    /api/v1/secrets/{id}/versions/{versionId}/comments
//	DELETE /api/v1/secrets/{id}/versions/{versionId}/comments/{commentId}
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core"
)

// SecretVersionCommentHandler handles secret version comment requests.
type SecretVersionCommentHandler struct {
	coreService *core.KeyorixCore
}

// NewSecretVersionCommentHandler creates a new SecretVersionCommentHandler.
func NewSecretVersionCommentHandler(coreService *core.KeyorixCore) *SecretVersionCommentHandler {
	return &SecretVersionCommentHandler{coreService: coreService}
}

const errInvalidVersionID = "Invalid version ID"

// createVersionCommentRequest is the JSON body for POST .../comments.
type createVersionCommentRequest struct {
	Comment string `json:"comment"`
}

// CreateComment handles POST /api/v1/secrets/{id}/versions/{versionId}/comments.
func (h *SecretVersionCommentHandler) CreateComment(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	secretID, ok := mustParseUintParam(w, r, "id", "InvalidParameter", errInvalidSecretID)
	if !ok {
		return
	}
	versionID, ok := mustParseUintParam(w, r, "versionId", "InvalidParameter", errInvalidVersionID)
	if !ok {
		return
	}

	var body createVersionCommentRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", errInvalidJSON, http.StatusBadRequest, nil)
		return
	}

	if body.Comment == "" {
		sendError(w, "ValidationError", "comment is required", http.StatusBadRequest, nil)
		return
	}

	comment, err := h.coreService.CreateSecretVersionComment(r.Context(), core.CreateVersionCommentRequest{
		SecretID:  secretID,
		VersionID: versionID,
		Comment:   body.Comment,
		UserID:    userCtx.UserID,
		Username:  userCtx.Username,
	})
	if err != nil {
		sendVersionCommentError(w, "creating", secretID, versionID, err)
		return
	}

	sendCreated(w, map[string]any{"comment": comment}, "Comment created successfully")
}

// ListComments handles GET /api/v1/secrets/{id}/versions/{versionId}/comments.
func (h *SecretVersionCommentHandler) ListComments(w http.ResponseWriter, r *http.Request) {
	_, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	secretID, ok := mustParseUintParam(w, r, "id", "InvalidParameter", errInvalidSecretID)
	if !ok {
		return
	}
	versionID, ok := mustParseUintParam(w, r, "versionId", "InvalidParameter", errInvalidVersionID)
	if !ok {
		return
	}

	comments, err := h.coreService.ListSecretVersionComments(r.Context(), secretID, versionID)
	if err != nil {
		sendVersionCommentError(w, "listing", secretID, versionID, err)
		return
	}

	sendSuccess(w, map[string]any{"comments": comments, "total": len(comments)}, "")
}

// DeleteComment handles DELETE /api/v1/secrets/{id}/versions/{versionId}/comments/{commentId}.
func (h *SecretVersionCommentHandler) DeleteComment(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	secretID, ok := mustParseUintParam(w, r, "id", "InvalidParameter", errInvalidSecretID)
	if !ok {
		return
	}
	versionID, ok := mustParseUintParam(w, r, "versionId", "InvalidParameter", errInvalidVersionID)
	if !ok {
		return
	}
	commentID, ok := mustParseUintParam(w, r, "commentId", "InvalidParameter", "Invalid comment ID")
	if !ok {
		return
	}

	if err := h.coreService.DeleteSecretVersionComment(r.Context(), secretID, versionID, commentID); err != nil {
		sendVersionCommentError(w, "deleting", secretID, versionID, err)
		return
	}
	h.coreService.LogSecretVersionCommentDeleted(r.Context(), userCtx.UserID, secretID, versionID, commentID)

	w.WriteHeader(http.StatusNoContent)
}

// sendVersionCommentError classifies an error from the three
// SecretVersionComment core calls above and responds with the right status
// code, instead of blanket-mapping every failure (including the ordinary,
// expected "this version doesn't belong to this secret" case
// versionBelongsToSecret returns -- internal/core/secret_version_comments.go)
// to 500. Matches the errNotFound-substring-check convention already used
// throughout this package (e.g. machine_identities.go's changeMachineRole/
// TransitionMachineIdentity) -- CreateSecretVersionComment/
// ListSecretVersionComments/DeleteSecretVersionComment were the one file in
// this package that never adopted it, so every caller who referenced a
// stale or mistyped version ID got an opaque 500 instead of a 404. Found by
// SESSION-I's fresh-install API smoke driver (scripts/e2e).
func sendVersionCommentError(w http.ResponseWriter, verb string, secretID, versionID uint, err error) {
	status := http.StatusInternalServerError
	msg := err.Error()
	switch {
	case strings.Contains(msg, errNotFound):
		status = http.StatusNotFound
	default:
		log.Printf("Error %s version comment (secret %d, version %d): %v", verb, secretID, versionID, err)
		msg = clientSafe(err)
	}
	sendError(w, "Error", msg, status, nil)
}
