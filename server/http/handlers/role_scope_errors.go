package handlers

import (
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
)

// sendRoleScopeError answers a core role-scope refusal (core.ErrRoleScopeInvalid,
// #3546: e.g. a project-tier role granted with no project_id) with 400 and the
// refusal's client-safe message, and reports whether it did. Every grant handler
// checks it before its own error mapping, which would otherwise fall through to
// 500 for an error the caller can fix.
func sendRoleScopeError(w http.ResponseWriter, err error) bool {
	msg, ok := core.RoleScopeClientMessage(err)
	if !ok {
		return false
	}
	sendError(w, "ValidationError", msg, http.StatusBadRequest, nil)
	return true
}
