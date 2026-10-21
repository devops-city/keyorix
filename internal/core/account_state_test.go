package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestAccountStateHelpers(t *testing.T) {
	t.Parallel()
	assert.Equal(t, AccountActive, NormalizeAccountState(""))
	assert.Equal(t, AccountSuspended, NormalizeAccountState(AccountSuspended))

	assert.True(t, AccountRestricted(AccountPendingFirstLogin))
	assert.True(t, AccountRestricted(AccountPasswordResetRequired))
	assert.False(t, AccountRestricted(AccountActive))
	assert.False(t, AccountRestricted("")) // legacy → active

	assert.True(t, AccountLoginBlocked(1, AccountSuspended))
	assert.False(t, AccountLoginBlocked(1, AccountActive))

	// A restricted state clears to active on password change; others unchanged.
	assert.Equal(t, AccountActive, clearRestrictionOnPasswordChange(AccountPasswordResetRequired))
	assert.Equal(t, AccountActive, clearRestrictionOnPasswordChange(AccountPendingFirstLogin))
	assert.Equal(t, AccountSuspended, clearRestrictionOnPasswordChange(AccountSuspended))
	assert.Equal(t, AccountActive, clearRestrictionOnPasswordChange(""))
}

// TestIsValidAccountState proves #334's write-path validation: the empty string
// and every canonical ADR-025 value are valid, and nothing else is.
func TestIsValidAccountState(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"", AccountActive, AccountPendingFirstLogin, AccountPasswordResetRequired, AccountSuspended, AccountDeprovisioned} {
		assert.True(t, IsValidAccountState(s), "expected %q to be valid", s)
	}
	for _, s := range []string{"SUSPENDED", "suspend", "Active", "not-a-real-state", " "} {
		assert.False(t, IsValidAccountState(s), "expected %q to be invalid", s)
	}
}

// TestAccountState_UnrecognizedValueFailsClosed proves #334's defense-in-depth
// backstop (AccountRestricted) AND AccountLoginBlocked's own fail-closed
// posture (see that function's doc for the asymmetry reasoning): an
// unrecognized account_state value is treated as restricted by
// AccountRestricted (never as fully active/unrestricted), AND refused
// outright by AccountLoginBlocked — both fail closed, just to different
// degrees of severity, matching what each function protects.
func TestAccountState_UnrecognizedValueFailsClosed(t *testing.T) {
	t.Parallel()
	garbage := "not-a-real-state"

	assert.True(t, AccountRestricted(garbage), "unrecognized state must fail closed to restricted")
	assert.True(t, AccountLoginBlocked(1, garbage), "unrecognized state must also fail closed to login-blocked")

	// An unrecognized-but-restricted state still self-heals to active on the
	// next password change, exactly like the canonical restricted states.
	// (Moot in practice for login itself, since AccountLoginBlocked now refuses
	// it before a session is ever minted -- but clearRestrictionOnPasswordChange
	// is also called from paths that already hold an authenticated session, e.g.
	// an admin-initiated password change, so this must still self-heal.)
	assert.Equal(t, AccountActive, clearRestrictionOnPasswordChange(garbage))

	// The canonical, previously-tested behaviors are unchanged.
	assert.True(t, AccountRestricted(AccountPendingFirstLogin))
	assert.True(t, AccountRestricted(AccountPasswordResetRequired))
	assert.False(t, AccountRestricted(AccountActive))
	assert.False(t, AccountRestricted(AccountSuspended))
	assert.False(t, AccountRestricted(AccountDeprovisioned))
	// AccountRestricted's behavior for blank is genuinely unchanged by this fix:
	// NormalizeAccountState still maps "" to AccountActive (write-time-defaulting
	// semantics used elsewhere, e.g. CreateUser's "no state specified" path --
	// see AccountLoginBlocked's own doc for why that function deliberately does
	// NOT route through NormalizeAccountState instead), so AccountRestricted("")
	// still resolves to AccountActive's case (not restricted) exactly as before.
	// This is moot in practice: AccountLoginBlocked now refuses a blank state
	// outright, so restriction-checking is never reached for it at all.
	assert.False(t, AccountRestricted(""))

	assert.True(t, AccountLoginBlocked(1, AccountSuspended))
	assert.True(t, AccountLoginBlocked(1, AccountDeprovisioned))
	assert.False(t, AccountLoginBlocked(1, AccountActive))
	assert.False(t, AccountLoginBlocked(1, AccountPendingFirstLogin))
	assert.False(t, AccountLoginBlocked(1, AccountPasswordResetRequired))
}

// TestAccountLoginBlocked_FailsClosedOnBlankAndWhitespace is the regression
// test for the actual vulnerability this fix closes: a blank or whitespace-
// only account_state (the shape a full-row storage overwrite silently
// produced in a real, confirmed incident) must be refused, not read as "not
// blocked" the way this function's original fail-open default did.
func TestAccountLoginBlocked_FailsClosedOnBlankAndWhitespace(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"", " ", "\t", "   "} {
		assert.True(t, AccountLoginBlocked(1, s), "blank/whitespace state %q must block login", s)
	}
}

// TestAccountLoginBlocked_MetricAndLogOnFailClosed proves P3's "loud, never
// silent" requirement: hitting the fail-closed default increments the
// unrecognized-state counter (the routine Suspended/Deprovisioned path must
// NOT increment it -- that's expected, not anomalous).
//
// Deliberately NOT t.Parallel(): accountStateUnrecognizedTotal is a package-
// global counter, and this test asserts exact deltas on it. Sibling tests in
// this file (TestAccountState_UnrecognizedValueFailsClosed,
// TestAccountLoginBlocked_FailsClosedOnBlankAndWhitespace) also drive garbage/
// blank states through the same counter and DO run in parallel with each
// other -- if this test parallelized too, their increments could land between
// this test's "before" read and its delta assertions, flaking the count.
// Running serially guarantees this test completes before any t.Parallel()
// test in the package starts.
func TestAccountLoginBlocked_MetricAndLogOnFailClosed(t *testing.T) {
	before := testutil.ToFloat64(accountStateUnrecognizedTotal)

	assert.True(t, AccountLoginBlocked(1, AccountSuspended))
	assert.True(t, AccountLoginBlocked(1, AccountDeprovisioned))
	assert.False(t, AccountLoginBlocked(1, AccountActive))
	assert.Equal(t, before, testutil.ToFloat64(accountStateUnrecognizedTotal),
		"routine suspended/deprovisioned/active checks must not touch the anomalous-state counter")

	assert.True(t, AccountLoginBlocked(1, ""))
	assert.Equal(t, before+1, testutil.ToFloat64(accountStateUnrecognizedTotal))

	assert.True(t, AccountLoginBlocked(1, "some-garbage-value"))
	assert.Equal(t, before+2, testutil.ToFloat64(accountStateUnrecognizedTotal))
}

func newAccountCore(store *MockStorage) *KeyorixCore {
	fixed := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	return &KeyorixCore{storage: store, now: func() time.Time { return fixed }, passwordPolicy: DefaultPasswordPolicy()}
}

func TestAdminAccountTransitions(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		call      func(c *KeyorixCore, ctx context.Context) error
		wantState string
		event     string
	}{
		{"suspend", func(c *KeyorixCore, ctx context.Context) error { return c.SuspendUser(ctx, 1, 2) }, AccountSuspended, "account.suspended"},
		{"reactivate", func(c *KeyorixCore, ctx context.Context) error { return c.ReactivateUser(ctx, 1, 2) }, AccountActive, "account.reactivated"},
		{"require reset", func(c *KeyorixCore, ctx context.Context) error { return c.RequirePasswordReset(ctx, 1, 2) }, AccountPasswordResetRequired, "account.password_reset_required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := new(MockStorage)
			c := newAccountCore(store)
			ctx := context.Background()
			store.On("GetUser", ctx, uint(2)).Return(&models.User{ID: 2, AccountState: AccountActive}, nil)
			// S1 (CLI-split inventory #2012): setAccountState now calls the
			// admin-rank ceiling first (actor 1 != target 2) for all three
			// transitions — the fixture target holds no role scopes, so it
			// passes trivially.
			store.On("GetUserRoleScopes", ctx, uint(2)).Return([]Scope{}, nil)
			store.On("SetAccountState", ctx, uint(2), tc.wantState, mock.Anything).Return(nil)
			store.On("LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
				return e.EventType == tc.event
			})).Return(nil)
			store.On("CreatePendingAuditEvent", mock.Anything, mock.Anything).Return(nil).Maybe() // AUDIT-TX-3: a revocation owes its audit row
			// A transition INTO a blocked or restricted state EVICTS the user's cached
			// session tokens AND PAT hashes from the auth cache, tombstoning them
			// (#r125-H2: password_reset_required previously skipped PAT eviction). A
			// transition TO plain active (reactivate) CLEARS instead of tombstoning —
			// see setAccountState's own doc comment and
			// TestReactivateUser_DoesNotTombstoneNeverCachedPAT
			// (server/http/account_state_reactivation_cache_test.go) for the real
			// auth-cache/DB divergence that distinction fixes. #2402 (G5 follow-up):
			// the collection step itself (listing session/PAT hashes to act on) runs
			// for BOTH branches now — a stale negative cache entry left over from
			// BEFORE the account went active must still be cleared on reactivate, so
			// skipping collection there left that stale-tombstone bug open. Unlike the
			// eviction/clear choice below, this mock expectation is unconditional for
			// every case.
			store.On("ListSessionTokenHashesForUser", ctx, uint(2)).Return([]string{}, nil)
			store.On("ListPersonalAccessTokensByUser", ctx, uint(2)).Return([]*models.PersonalAccessToken{}, nil)
			// A login-blocking transition (suspend) must purge the user's sessions AND PATs.
			if AccountLoginBlocked(1, tc.wantState) {
				store.On("DeleteSessionsForUserExcept", ctx, uint(2), uint(0)).Return(nil)
				store.On("RevokeAllPersonalAccessTokensForUser", ctx, uint(2)).Return([]string{}, nil)
			}
			// SuspendUser now runs guardLastAdminDeactivation first (#G02) — the
			// fixture user holds no roles, so IsGlobalAdmin resolves false and the
			// guard is a no-op; only the "suspend" case reaches this check.
			if tc.name == "suspend" {
				store.On("GetUserRoleIDsAt", ctx, uint(2), Scope{}).Return([]uint{}, nil)
				store.On("GetUserGroupRoleIDsAt", ctx, uint(2), Scope{}).Return([]uint{}, nil)
			}

			require.NoError(t, tc.call(c, ctx))
			store.AssertExpectations(t)
			if !AccountLoginBlocked(1, tc.wantState) {
				store.AssertNotCalled(t, "DeleteSessionsForUserExcept", mock.Anything, mock.Anything, mock.Anything)
			}
		})
	}
}

func TestLogin_BlocksSuspended(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newAccountCore(store)
	ctx := context.Background()
	hash, _ := bcrypt.GenerateFromPassword([]byte("Secret#Passw0rd!"), int(bcryptCost.Load()))
	// A suspended account keeps IsActive=true (SuspendUser changes only account_state),
	// so the state-based gate — not the IsActive gate — is what refuses the login.
	store.On("GetUserByUsername", ctx, "bob").
		Return(&models.User{ID: 2, Username: "bob", PasswordHash: string(hash), IsActive: true, AccountState: AccountSuspended}, nil)

	_, _, err := c.Login(ctx, &LoginRequest{Username: "bob", Password: "Secret#Passw0rd!"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "suspended")
	store.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
}

// A deactivated account (IsActive=false, e.g. admin deactivation via UpdateUser or a
// SCIM/IdP deactivation) must be refused login even with the correct password and an
// otherwise-active account_state — the state gate alone does not cover IsActive.
func TestLogin_BlocksDeactivated(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newAccountCore(store)
	ctx := context.Background()
	hash, _ := bcrypt.GenerateFromPassword([]byte("Secret#Passw0rd!"), int(bcryptCost.Load()))
	store.On("GetUserByUsername", ctx, "bob").
		Return(&models.User{ID: 2, Username: "bob", PasswordHash: string(hash), IsActive: false, AccountState: AccountActive}, nil)

	_, _, err := c.Login(ctx, &LoginRequest{Username: "bob", Password: "Secret#Passw0rd!"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not active")
	store.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
}

// A suspended or deactivated account must not authenticate via an existing,
// not-yet-expired session token (the suspend/deactivate revocation gap).
func TestValidateSessionToken_RejectsBlockedOrInactive(t *testing.T) {
	t.Parallel()
	future := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC) // after newAccountCore's fixed now
	cases := []struct {
		name string
		user *models.User
	}{
		{"suspended", &models.User{ID: 2, IsActive: true, AccountState: AccountSuspended}},
		{"inactive", &models.User{ID: 2, IsActive: false, AccountState: AccountActive}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := new(MockStorage)
			c := newAccountCore(store)
			ctx := context.Background()
			store.On("GetSession", ctx, "tok").Return(&models.Session{ID: 7, UserID: 2, ExpiresAt: &future}, nil)
			store.On("GetUser", ctx, uint(2)).Return(tc.user, nil)

			_, _, err := c.ValidateSessionToken(ctx, "tok")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not active")
			store.AssertNotCalled(t, "GetUserRoles", mock.Anything, mock.Anything)
			// Must reject before stamping last-seen — a blocked/inactive account's
			// request is not "used" and must not refresh the sessions view (matching
			// ValidatePATToken's touch-after-gate ordering).
			c.FlushLastUsed(ctx) // the stamp is coalesced: flush so a recorded touch would reach the mock
			store.AssertNotCalled(t, "TouchSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// An impersonation session (target active) must be rejected once the IMPERSONATING
// admin is suspended/deactivated — the session is keyed to the target's user_id, so
// the target-state gate alone would let a revoked admin keep acting as the target.
func TestValidateSessionToken_RejectsWhenImpersonatorBlocked(t *testing.T) {
	t.Parallel()
	future := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	store := new(MockStorage)
	c := newAccountCore(store)
	ctx := context.Background()
	admin := uint(1)
	store.On("GetSession", ctx, "tok").Return(&models.Session{ID: 7, UserID: 2, ImpersonatedBy: &admin, ExpiresAt: &future}, nil)
	store.On("GetUser", ctx, uint(2)).Return(&models.User{ID: 2, IsActive: true, AccountState: AccountActive}, nil)
	store.On("GetUser", ctx, uint(1)).Return(&models.User{ID: 1, IsActive: true, AccountState: AccountSuspended}, nil)

	_, _, err := c.ValidateSessionToken(ctx, "tok")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "impersonating account is not active")
	c.FlushLastUsed(ctx) // the stamp is coalesced: flush so a recorded touch would reach the mock
	store.AssertNotCalled(t, "TouchSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestValidateSessionToken_AllowsActive(t *testing.T) {
	t.Parallel()
	future := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	store := new(MockStorage)
	c := newAccountCore(store)
	ctx := context.Background()
	store.On("GetSession", ctx, "tok").Return(&models.Session{ID: 7, UserID: 2, ExpiresAt: &future}, nil)
	store.On("TouchSession", ctx, uint(7), mock.Anything, mock.Anything).Return(nil)
	store.On("GetUser", ctx, uint(2)).Return(&models.User{ID: 2, IsActive: true, AccountState: AccountActive}, nil)
	store.On("GetUserRoles", ctx, uint(2)).Return([]*models.Role{{Name: "viewer"}}, nil)

	user, roles, err := c.ValidateSessionToken(ctx, "tok")
	require.NoError(t, err)
	assert.Equal(t, uint(2), user.ID)
	assert.Equal(t, []string{"viewer"}, roles)
	// The accepted request's last-seen stamp is coalesced, not written inline;
	// it reaches storage on the next flush with staleness 0 (GREATEST semantics).
	store.AssertNotCalled(t, "TouchSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	c.FlushLastUsed(ctx)
	store.AssertCalled(t, "TouchSession", ctx, uint(7), mock.Anything, time.Duration(0))
}

func TestChangePassword_ClearsRestriction(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newAccountCore(store)
	ctx := context.Background()
	oldHash, _ := bcrypt.GenerateFromPassword([]byte("oldpassword"), int(bcryptCost.Load()))
	user := &models.User{ID: 1, Username: "alice", PasswordHash: string(oldHash), AccountState: AccountPasswordResetRequired}

	store.On("GetUser", ctx, uint(1)).Return(user, nil)
	store.On("RecentPasswordHashes", ctx, uint(1), 5).Return([]string{}, nil)
	store.On("SetPasswordHash", ctx, uint(1), mock.AnythingOfType("string"), mock.Anything).Return(nil)
	store.On("SetAccountState", ctx, uint(1), AccountActive, mock.Anything).Return(nil) // restriction cleared
	store.On("AddPasswordHistory", ctx, uint(1), mock.AnythingOfType("string"), mock.Anything).Return(nil)
	store.On("PrunePasswordHistory", ctx, uint(1), 5).Return(nil)
	store.On("GetSession", ctx, "tok").Return(&models.Session{ID: 7, UserID: 1}, nil)
	store.On("ListSessionTokenHashesForUser", ctx, uint(1)).Return([]string{}, nil)
	store.On("DeleteSessionsForUserExcept", ctx, uint(1), uint(7)).Return(nil)
	store.On("RevokeAllPersonalAccessTokensForUser", mock.Anything, mock.Anything).Return(nil, nil)

	err := c.ChangePassword(ctx, 1, "oldpassword", "Brandnew#Passw0rd!", "tok")
	require.NoError(t, err)
	store.AssertExpectations(t)
}

// TestRequirePasswordReset_EvictsPATCache verifies that RequirePasswordReset evicts
// PAT token hashes from the auth cache, not only session hashes (#r125-H2). Without
// this eviction, a cached PAT request would bypass the password_reset_required
// restriction for up to validTokenTTL (30 s) — the cache fast-path returns the
// old, unrestricted identity without re-reading the DB.
func TestRequirePasswordReset_EvictsPATCache(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newAccountCore(store)
	ctx := context.Background()

	const userID = uint(5)
	patHash := "sha256-pat-hash-abc"

	// LockUserForUpdate delegates to GetUser inside the mock.
	store.On("GetUser", ctx, userID).Return(&models.User{ID: userID, AccountState: AccountActive}, nil)
	// S1 (CLI-split inventory #2012): actor 1 != target 5 — the admin-rank
	// ceiling runs first; the fixture target holds no role scopes.
	store.On("GetUserRoleScopes", ctx, userID).Return([]Scope{}, nil)
	store.On("ListSessionTokenHashesForUser", ctx, userID).Return([]string{}, nil)
	store.On("ListPersonalAccessTokensByUser", ctx, userID).Return([]*models.PersonalAccessToken{
		{ID: 1, UserID: userID, TokenHash: patHash, Revoked: false},
	}, nil)
	store.On("SetAccountState", ctx, userID, AccountPasswordResetRequired, mock.Anything).Return(nil)
	store.On("LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == "account.password_reset_required"
	})).Return(nil)
	store.On("CreatePendingAuditEvent", mock.Anything, mock.Anything).Return(nil).Maybe() // AUDIT-TX-3: a revocation owes its audit row

	var evicted []string
	c.SetTokenCacheInvalidator(func(h string) { evicted = append(evicted, h) })

	require.NoError(t, c.RequirePasswordReset(ctx, 1, userID))

	// The PAT hash must have been evicted so the next PAT request re-reads the DB
	// and observes the new password_reset_required restriction.
	assert.Contains(t, evicted, patHash, "RequirePasswordReset must evict PAT hashes from auth cache")
	store.AssertExpectations(t)
}
