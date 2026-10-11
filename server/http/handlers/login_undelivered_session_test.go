package handlers

// #2844: ConsumeSetup still reads the response identity after core has minted
// the session (completeLogin), and compensates by revoking it. That
// compensation used to run only for an ERROR from the read; a PANIC unwound
// past it to the recovery middleware's 500 and left the session live. Setup
// consume is not in the faultops op catalog, so its oracle (f) coverage is here.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

const undeliveredSetupPassword = "Kx#Vr9$Mn2!Zp4@Qw"

func newUndeliveredSetupFixture(t *testing.T) (*AuthHandler, *core.KeyorixCore, *faultstorage.FaultyStorage, *store.LocalStorage, uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxundeliveredsetup")
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))
	real := store.NewLocalStorage(db)
	fs := faultstorage.NewFaultyStorage(real, nil)
	c := core.NewKeyorixCore(fs)
	c.SetBootstrapToken("undelivered-boot")
	_, err := c.BootstrapSystem(context.Background(), &core.BootstrapRequest{
		Username: "undeliveredadmin", Email: "undeliveredadmin@example.com",
		Password: undeliveredSetupPassword, Token: "undelivered-boot",
	})
	require.NoError(t, err)
	admin, err := c.GetUserByUsername(context.Background(), "undeliveredadmin")
	require.NoError(t, err)
	return NewAuthHandler(c, false), c, fs, real, admin.ID
}

func consumeSetupFor(t *testing.T, h *AuthHandler, c *core.KeyorixCore, adminID uint, name string) (*httptest.ResponseRecorder, uint, any) {
	t.Helper()
	token := issueSetupTokenForUserS11(t, c, adminID, name+"@example.com", name)
	u, err := c.GetUserByUsername(context.Background(), name)
	require.NoError(t, err)
	body := fmt.Sprintf(`{"token":%q,"password":%q}`, token, undeliveredSetupPassword+"x")
	req := httptest.NewRequest(http.MethodPost, "/auth/setup/consume", strings.NewReader(body))
	w := httptest.NewRecorder()
	var panicked any
	func() {
		defer func() { panicked = recover() }()
		h.ConsumeSetup(w, req)
	}()
	return w, u.ID, panicked
}

func countSessions(t *testing.T, st *store.LocalStorage, userID uint) int {
	t.Helper()
	rows, err := st.ListSessionsByUser(context.Background(), userID)
	require.NoError(t, err)
	return len(rows)
}

// lastIdentityReadNth returns how many GetUserPermissions calls a fault-free
// ConsumeSetup makes: the last one is completeLogin's identity read, after the
// session is minted. Measured rather than hard-coded so a change in how many
// times core reads permissions earlier cannot silently move the fault onto a
// pre-mint read and make the test pass for the wrong reason.
func lastIdentityReadNth(t *testing.T, h *AuthHandler, c *core.KeyorixCore, fs *faultstorage.FaultyStorage, st *store.LocalStorage, adminID uint) int {
	t.Helper()
	start := len(fs.Calls())
	w, uid, p := consumeSetupFor(t, h, c, adminID, "undeliveredcalib")
	require.Nil(t, p)
	require.Equal(t, http.StatusOK, w.Code, "calibration: a fault-free setup consume logs the user in: %s", w.Body.String())
	require.Equal(t, 1, countSessions(t, st, uid), "calibration: the fault-free consume delivers exactly one session")
	n := 0
	for _, call := range fs.Calls()[start:] {
		if call.Method == "GetUserPermissions" {
			n++
		}
	}
	require.NotZero(t, n, "calibration: the response identity read must call GetUserPermissions")
	return n
}

func TestConsumeSetup_IdentityReadPanic_LeavesNoSession(t *testing.T) {
	h, c, fs, st, adminID := newUndeliveredSetupFixture(t)
	nth := lastIdentityReadNth(t, h, c, fs, st, adminID)

	fs.Arm(&faultstorage.FaultSpec{Method: "GetUserPermissions", NthCall: nth, Kind: faultstorage.KindPanic, Err: errors.New("injected")})
	_, uid, panicked := consumeSetupFor(t, h, c, adminID, "undeliveredpanic")
	require.True(t, fs.Fired(), "the armed fault must fire on the post-mint identity read")
	assert.NotNil(t, panicked, "the panic still propagates to the recovery middleware (unchanged 500)")
	assert.Zero(t, countSessions(t, st, uid), "a setup consume that reported failure left a live session the client never received")
}

func TestConsumeSetup_IdentityReadError_StillLeavesNoSession(t *testing.T) {
	h, c, fs, st, adminID := newUndeliveredSetupFixture(t)
	nth := lastIdentityReadNth(t, h, c, fs, st, adminID)

	fs.Arm(&faultstorage.FaultSpec{Method: "GetUserPermissions", NthCall: nth, Kind: faultstorage.KindError, Err: errors.New("injected")})
	w, uid, panicked := consumeSetupFor(t, h, c, adminID, "undeliverederr")
	require.True(t, fs.Fired())
	require.Nil(t, panicked)
	// #2894/#2888: the token was already accepted, so this failure answers
	// exactly like the endpoint's generic setup failure, not a distinguishable
	// 500 "Login could not be completed".
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "This setup link could not be completed", "same response as the generic setup failure")
	assert.NotContains(t, w.Body.String(), errLoginIncomplete)
	assert.Zero(t, countSessions(t, st, uid))
}
