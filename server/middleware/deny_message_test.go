package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestDenyMessage_SameBodyForBothDenialShapes: a route's DenyMessage replaces
// "Insufficient permissions" in BOTH denials RequireScopedPermission produces (not
// authorized, and target not found for a caller without the permission globally),
// so the two stay byte-identical and the custom text is no existence oracle
// (INV-HTTP-08). A global holder still gets the 404, and the default stays as is.
func TestDenyMessage_SameBodyForBothDenialShapes(t *testing.T) {
	db := newScopedTestDB(t)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "nobody", AccountState: "active"}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj"}).Error)
	seedAdmin(t, db, 1)
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))

	const reason = "You need a role in this project."
	found := func(_ *http.Request, _ *core.KeyorixCore) (core.Scope, error) { return core.Scope{ProjectID: 1}, nil }
	missing := func(_ *http.Request, _ *core.KeyorixCore) (core.Scope, error) { return core.Scope{}, errTargetNotFound }
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	run := func(userID uint, resolve ScopeResolver, opts ...ScopedGateOption) *httptest.ResponseRecorder {
		req := makeRequest(t, http.MethodGet, "/test", nil, &UserContext{UserID: userID, ActorType: core.ActorTypeUser}, cs)
		rec := httptest.NewRecorder()
		RequireScopedPermission("secrets.write", resolve, opts...)(next).ServeHTTP(rec, req)
		return rec
	}

	denied := run(2, found, DenyMessage(reason))
	notFound := run(2, missing, DenyMessage(reason))
	assert.Equal(t, http.StatusForbidden, denied.Code)
	assert.Contains(t, denied.Body.String(), reason)
	assert.Equal(t, denied.Code, notFound.Code)
	assert.Equal(t, denied.Body.String(), notFound.Body.String(), "both denial shapes must be identical")

	assert.Equal(t, http.StatusNotFound, run(1, missing, DenyMessage(reason)).Code, "a global holder still learns not-found")
	assert.Contains(t, run(2, found).Body.String(), "Insufficient permissions", "the default message is unchanged")
}
