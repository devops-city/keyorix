package http

// machine_notifications_forbidden_test.go — AUTHZ-WALKS-HTTP-1 triage.
//
// POST /notifications/read-all and POST /notifications/{id}/read are user-only
// writes: a notification belongs to a user, and a machine identity authenticates
// with UserID 0 (ADR-030). read-all answered a machine token 200 {"all_read":true}
// for a feed that cannot exist, and {id}/read answered 404. Found by
// TestEveryWriteRouteRefusesAndChangesNothing (zero-grant machine persona). Both
// now answer 403 like the other user-only routes.

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNotificationsMarkRead_MachineToken_Forbidden(t *testing.T) {
	w := newAWWorld(t, "sqlite", 1)
	for _, rt := range []awRoute{
		{http.MethodPost, "/api/v1/notifications/read-all"},
		{http.MethodPost, "/api/v1/notifications/1/read"},
	} {
		code, body := awDo(w.a, rt.Method, w.tokens["machine_zero"], rt.Path, nil)
		assert.Equal(t, http.StatusForbidden, code, "%s %s: %s", rt.Method, rt.Path, body)
	}
	// Control: a human still gets 200 on read-all.
	code, body := awDo(w.a, http.MethodPost, w.tokens["awviewer"], "/api/v1/notifications/read-all", nil)
	assert.Equal(t, http.StatusOK, code, body)
}
