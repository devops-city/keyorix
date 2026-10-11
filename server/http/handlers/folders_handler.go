// folders_handler.go — FolderHandler: create, list, and delete folder nodes.
//
// Routes (under /api/v1/folders):
//
//	POST   /              — create a folder (body: {name, project_id, environment_id, parent_id?})
//	GET    /              — list folders (?project_id=N&parent_id=M)
//	DELETE /{id}          — soft-delete a folder
package handlers

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/keyorixhq/keyorix/server/validation"
)

// FolderHandler handles folder-node HTTP requests.
type FolderHandler struct {
	coreService *core.KeyorixCore
	validator   *validation.Validator
}

// NewFolderHandler creates a new FolderHandler.
func NewFolderHandler(coreService *core.KeyorixCore) *FolderHandler {
	return &FolderHandler{
		coreService: coreService,
		validator:   validation.NewValidator(),
	}
}

func (h *FolderHandler) sendSuccess(w http.ResponseWriter, data interface{}, message string) {
	w.Header().Set(hdrContentType, mimeApplicationJSON)
	w.Header().Set(hdrXContentTypeOptions, "nosniff")
	if err := encodeJSONResponse(w, SuccessResponse{Success: true, Data: data, Message: message}); err != nil {
		log.Printf("Error encoding folder JSON response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *FolderHandler) sendError(w http.ResponseWriter, errorType, message string, statusCode int, details interface{}) {
	w.Header().Set(hdrContentType, mimeApplicationJSON)
	w.Header().Set(hdrXContentTypeOptions, "nosniff")
	w.WriteHeader(statusCode)
	if err := encodeJSONResponse(w, ErrorResponse{
		Error:   errorType,
		Message: message,
		Code:    statusCode,
		Details: details,
	}); err != nil {
		log.Printf("Error encoding folder JSON error response: %v", err)
	}
}

// CreateFolder handles POST /api/v1/folders.
// Authorization is done in-handler (same pattern as CreateSecret) because the
// create route carries no path scope — scope comes from the request body.
func (h *FolderHandler) CreateFolder(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	var reqBody struct {
		Name          string `json:"name"`
		ProjectID     uint   `json:"project_id"`
		EnvironmentID uint   `json:"environment_id"`
		ParentID      *uint  `json:"parent_id,omitempty"`
	}
	if !mustDecodeBody(w, r, &reqBody) {
		return
	}

	if reqBody.Name == "" {
		h.sendError(w, "ValidationError", "name is required", http.StatusBadRequest, nil)
		return
	}
	if reqBody.ProjectID == 0 {
		h.sendError(w, "ValidationError", "project_id is required", http.StatusBadRequest, nil)
		return
	}
	if reqBody.EnvironmentID == 0 {
		h.sendError(w, "ValidationError", "environment_id is required", http.StatusBadRequest, nil)
		return
	}

	// Authorize at the project/environment scope from the body.
	scope := core.Scope{ProjectID: reqBody.ProjectID, EnvironmentID: reqBody.EnvironmentID}
	if allowed, err := h.coreService.AuthorizePrincipal(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), permSecretsWrite, scope); err != nil || !allowed {
		h.sendError(w, "Forbidden", "Insufficient permissions", http.StatusForbidden, nil)
		return
	}
	// Per-project MFA policy (ADR-037).
	if middleware.ProjectMFABlocked(r, h.coreService, scope.ProjectID) {
		middleware.WriteProjectMFARequired(w)
		return
	}

	folder, err := h.coreService.CreateFolder(r.Context(), userCtx.UserID, reqBody.Name, reqBody.ProjectID, reqBody.EnvironmentID, reqBody.ParentID)
	if err != nil {
		log.Printf("Error creating folder: %v", err)
		msg := err.Error()
		status := http.StatusInternalServerError
		errType := "InternalError"
		respMsg := "Failed to create folder"
		switch {
		case strings.Contains(msg, "not found"):
			status = http.StatusNotFound
			errType = "NotFound"
			respMsg = "Parent folder not found"
		case strings.Contains(msg, "validation") ||
			strings.Contains(msg, "not a folder") ||
			strings.Contains(msg, "does not belong to the same project"):
			status = http.StatusBadRequest
			errType = "ValidationError"
			respMsg = msg
		}
		h.sendError(w, errType, respMsg, status, nil)
		return
	}

	w.Header().Set(hdrContentType, mimeApplicationJSON)
	w.Header().Set(hdrXContentTypeOptions, "nosniff")
	w.WriteHeader(http.StatusCreated)
	if err := encodeJSONResponse(w, SuccessResponse{Success: true, Data: newSecretNodeWire(folder), Message: "Folder created"}); err != nil {
		log.Printf("Error encoding created folder: %v", err)
	}
}

// ListFolders handles GET /api/v1/folders.
// Scope is enforced via the RequireScopedPermission middleware using the
// project_id query parameter (same convention as ListSecrets).
func (h *FolderHandler) ListFolders(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	var projectID uint
	if pidStr := r.URL.Query().Get("project_id"); pidStr != "" {
		v, err := strconv.ParseUint(pidStr, 10, 32)
		if err != nil {
			h.sendError(w, "ValidationError", "invalid project_id", http.StatusBadRequest, nil)
			return
		}
		projectID = uint(v)
	}

	var parentID *uint
	if pidStr := r.URL.Query().Get("parent_id"); pidStr != "" {
		v, err := strconv.ParseUint(pidStr, 10, 32)
		if err != nil {
			h.sendError(w, "ValidationError", "invalid parent_id", http.StatusBadRequest, nil)
			return
		}
		pid := uint(v)
		parentID = &pid
	}

	page := 1
	pageSize := 20
	if p, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && p > 0 {
		page = p
	}
	if ps, err := strconv.Atoi(r.URL.Query().Get("page_size")); err == nil && ps > 0 && ps <= 100 {
		pageSize = ps
	}

	folders, total, err := h.coreService.ListFolders(r.Context(), projectID, parentID, page, pageSize)
	if err != nil {
		log.Printf("Error listing folders: %v", err)
		h.sendError(w, "InternalError", "Failed to list folders", http.StatusInternalServerError, nil)
		return
	}

	w.Header().Set("X-Total-Count", fmt.Sprintf("%d", total))
	h.sendSuccess(w, newSecretNodeWireList(folders), "")
}

// DeleteFolder handles DELETE /api/v1/folders/{id}.
// Authorization is performed by the RequireScopedPermission middleware using
// the folder node's own project/environment scope.
func (h *FolderHandler) DeleteFolder(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "invalid folder ID", http.StatusBadRequest, nil)
		return
	}

	// Verify the node is actually a folder before deleting.
	node, err := h.coreService.GetSecret(r.Context(), uint(id))
	if err != nil {
		h.sendError(w, "NotFound", "Folder not found", http.StatusNotFound, nil)
		return
	}
	if node.IsSecret {
		h.sendError(w, "ValidationError", "node is a secret, not a folder", http.StatusBadRequest, nil)
		return
	}

	if err := h.coreService.DeleteSecretWithPermissionCheck(r.Context(), uint(id), userCtx.UserID); err != nil {
		log.Printf("Error deleting folder %d: %v", id, err)
		h.sendError(w, "InternalError", "Failed to delete folder", http.StatusInternalServerError, nil)
		return
	}

	// DeleteSecretWithPermissionCheck/DeleteSecret write no secret.deleted event
	// of their own (by design — see DeleteSecret's own comment); the real
	// /secrets/{id} DELETE handler calls LogSecretDeletedWithProject explicitly
	// afterward, and folders (IsSecret=false SecretNode rows deleted via the
	// same core call) need the identical call (F3, audit-completeness campaign).
	uid, fID, uname := userCtx.UserID, uint(id), userCtx.Username
	ip, ua := r.RemoteAddr, r.Header.Get(hdrUserAgent)
	auditCtx := core.DetachedAuditContext(r.Context())
	goSafe(func() {
		h.coreService.LogSecretDeletedWithProject(auditCtx, uid, fID, node.ProjectID, uname, node.Name, ip, ua)
	}) // #nosec G118

	w.WriteHeader(http.StatusNoContent)
}
