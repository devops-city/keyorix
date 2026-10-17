package middleware

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const (
	validToken = "valid-token"
	testToken  = "test-token"
)

const wrongKey contextKey = "wrong-key"

// fakeValidator is a test double for sessionValidator. It returns a fixed
// admin user for validToken, a viewer user for testToken, and an error for
// anything else.
type fakeValidator struct{}

func (fakeValidator) ValidateSessionToken(_ context.Context, token string) (*models.User, []string, error) {
	switch token {
	case validToken:
		return &models.User{
			ID:       1,
			Username: "admin",
			Email:    "admin@example.com",
		}, []string{"admin", "user"}, nil
	case testToken:
		return &models.User{
			ID:       2,
			Username: "testuser",
			Email:    "test@example.com",
		}, []string{"viewer"}, nil
	default:
		return nil, nil, fmt.Errorf("session not found")
	}
}

// ValidatePATToken accepts a single fixed PAT and resolves it to a user, mirroring
// the shape of ValidateSessionToken so the prefix-routing in validateToken can be
// exercised. Anything else is rejected.
func (fakeValidator) ValidatePATToken(_ context.Context, token string) (*models.User, []string, *core.PATRestriction, uint, error) {
	if token == "kx_pat_validtoken" {
		return &models.User{
			ID:       3,
			Username: "patuser",
			Email:    "pat@example.com",
		}, []string{"system_viewer"}, nil, 0, nil
	}
	if token == "kx_pat_scopedtoken" {
		// A least-privilege token confined to secrets.read in project 5 (ADR-042).
		return &models.User{ID: 3, Username: "patuser", Email: "pat@example.com"},
			[]string{"system_viewer"},
			&core.PATRestriction{Permissions: []string{"secrets.read"}, ProjectID: 5},
			0,
			nil
	}
	if token == "kx_pat_cidrtoken" {
		// A token restricted to the 10.0.0.0/8 network. patID is 0 (fake, not a real
		// storage-backed PAT), so handleAuthRequest's post-check TouchPATLastUsed is a
		// harmless no-op in tests exercising this fake.
		return &models.User{ID: 3, Username: "patuser", Email: "pat@example.com"},
			[]string{"system_viewer"},
			&core.PATRestriction{AllowedCIDRs: []string{"10.0.0.0/8"}},
			0,
			nil
	}
	return nil, nil, nil, 0, fmt.Errorf("invalid token")
}

func (fakeValidator) ValidateMachineToken(_ context.Context, token string) (*models.MachineIdentity, []string, *core.MachineTokenRestriction, uint, error) {
	if token == "kx_machine_validtoken" {
		return &models.MachineIdentity{
			ID:    9,
			Name:  "ci-bot",
			State: "active",
		}, []string{"project_viewer"}, nil, 0, nil
	}
	return nil, nil, nil, 0, fmt.Errorf("invalid token")
}

func (fakeValidator) OIDCEnabled() bool { return true }

func (fakeValidator) ValidateOIDCToken(_ context.Context, token string) (*models.MachineIdentity, []string, time.Time, error) {
	// A three-segment dotted token whose middle segment marks it valid.
	if token == "header.valid.sig" {
		return &models.MachineIdentity{ID: 11, Name: "k8s-sa", State: "active"}, []string{"project_viewer"}, time.Now().Add(time.Hour), nil
	}
	return nil, nil, time.Time{}, fmt.Errorf("invalid token")
}

// newTestAuthMiddleware builds the Authentication middleware with the fake
// validator. The coreService passed to authenticationWithValidator is nil here
// because none of these tests exercise downstream handlers that pull the core
// service out of context.
func newTestAuthMiddleware() func(next http.Handler) http.Handler {
	return authenticationWithValidator(fakeValidator{}, nil)
}

func TestAuthentication(t *testing.T) {
	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
		expectUserCtx  bool
	}{
		{
			name:           "valid token",
			authHeader:     "Bearer valid-token",
			expectedStatus: http.StatusOK,
			expectUserCtx:  true,
		},
		{
			name:           "valid test token",
			authHeader:     "Bearer test-token",
			expectedStatus: http.StatusOK,
			expectUserCtx:  true,
		},
		{
			name:           "invalid token",
			authHeader:     "Bearer invalid-token",
			expectedStatus: http.StatusUnauthorized,
			expectUserCtx:  false,
		},
		{
			// kx_pat_ prefix routes to ValidatePATToken and resolves to a user,
			// producing the same UserContext shape as a session.
			name:           "valid personal access token",
			authHeader:     "Bearer kx_pat_validtoken",
			expectedStatus: http.StatusOK,
			expectUserCtx:  true,
		},
		{
			name:           "invalid personal access token",
			authHeader:     "Bearer kx_pat_bogus",
			expectedStatus: http.StatusUnauthorized,
			expectUserCtx:  false,
		},
		{
			name:           "missing authorization header",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
			expectUserCtx:  false,
		},
		{
			name:           "malformed authorization header",
			authHeader:     "InvalidFormat token",
			expectedStatus: http.StatusUnauthorized,
			expectUserCtx:  false,
		},
		{
			name:           "bearer without token",
			authHeader:     "Bearer ",
			expectedStatus: http.StatusUnauthorized,
			expectUserCtx:  false,
		},
		{
			name:           "only bearer",
			authHeader:     "Bearer",
			expectedStatus: http.StatusUnauthorized,
			expectUserCtx:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test handler that checks for user context
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				userCtx := GetUserFromContext(r.Context())
				if tt.expectUserCtx {
					assert.NotNil(t, userCtx)
					assert.NotEmpty(t, userCtx.Username)
					assert.NotEmpty(t, userCtx.Email)
				} else {
					assert.Nil(t, userCtx)
				}
				w.WriteHeader(http.StatusOK)
			})

			// Wrap with authentication middleware
			authMiddleware := newTestAuthMiddleware()
			handler := authMiddleware(testHandler)

			// Create request
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler
			handler.ServeHTTP(w, req)

			// Check status code
			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestRequireRole(t *testing.T) {
	tests := []struct {
		name           string
		token          string
		role           string
		expectedStatus int
	}{
		{
			name:           "admin has admin role",
			token:          validToken,
			role:           "admin",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "admin has user role",
			token:          validToken,
			role:           "user",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "test user has viewer role",
			token:          testToken,
			role:           "viewer",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "test user lacks admin role",
			token:          testToken,
			role:           "admin",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "nonexistent role",
			token:          validToken,
			role:           "nonexistent",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test handler
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			// Create user context based on token
			var userCtx *UserContext
			switch tt.token {
			case validToken:
				userCtx = &UserContext{
					UserID:   1,
					Username: "admin",
					Email:    "admin@example.com",
					Roles:    []string{"admin", "user"},
				}
			case testToken:
				userCtx = &UserContext{
					UserID:   2,
					Username: "testuser",
					Email:    "test@example.com",
					Roles:    []string{"viewer"},
				}
			}

			// Wrap with role middleware
			roleMiddleware := RequireRole(tt.role)
			handler := roleMiddleware(testHandler)

			// Create request with user context
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if userCtx != nil {
				ctx := context.WithValue(req.Context(), userContextKey, userCtx)
				req = req.WithContext(ctx)
			}

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler
			handler.ServeHTTP(w, req)

			// Check status code
			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

// A PAT carrying a least-privilege restriction (ADR-042) must not satisfy a role
// gate, even when its owner holds the role — RequireRole does not funnel through
// core.Authorize, so the restriction is enforced here directly (fail-closed).
func TestRequireRole_DeniesScopedPAT(t *testing.T) {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := RequireRole("admin")(testHandler)

	t.Run("scoped PAT on an admin owner is forbidden", func(t *testing.T) {
		userCtx := &UserContext{
			UserID:         1,
			Username:       "admin",
			Roles:          []string{"admin", "user"},
			PATRestriction: &core.PATRestriction{Permissions: []string{"secrets.read"}},
		}
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req = req.WithContext(context.WithValue(req.Context(), userContextKey, userCtx))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("same owner via a full session still passes", func(t *testing.T) {
		userCtx := &UserContext{UserID: 1, Username: "admin", Roles: []string{"admin", "user"}}
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req = req.WithContext(context.WithValue(req.Context(), userContextKey, userCtx))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// TestRequireRole_DeniesMachinePrincipal reproduces the exact #308 landmine
// scenario: a machine identity holds "deployer" only via a grant scoped to
// Project A (10), but store.GetMachineRoles is intentionally unscoped and
// flattens that grant into a bare role name with no project attached —
// precisely what ValidateMachineToken/machineUserContext feed into
// userCtx.Roles for every machine-token-authenticated request. If RequireRole
// were ever wired onto an authorization-gating route, an unscoped name match
// against that role list would wrongly authorize the same machine identity on
// a request for a DIFFERENT project (B, 99) that its grant was never scoped
// to — silently bypassing project scoping entirely for machine principals.
//
// Before the #308 fix, RequireRole only checked the role name against
// userCtx.Roles and had no machine-principal guard, so this exact request
// would have incorrectly succeeded (StatusOK). After the fix, RequireRole
// unconditionally refuses to gate on any machine principal, so it is
// rejected — regardless of which project the route targets — closing the
// landmine at the consumer rather than depending on GetMachineRoles (or any
// other future unscoped data source) never being wired in.
func TestRequireRole_DeniesMachinePrincipal(t *testing.T) {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := RequireRole("deployer")(testHandler)

	// Mirrors machineUserContext(m, roleNames) exactly as validateToken builds
	// it for a machine-token request: roleNames is store.GetMachineRoles's
	// unscoped output ("deployer" appears with no indication it was granted
	// only at project A/10) for a machine whose real grant is scoped to
	// project A alone.
	machineID := uint(42)
	userCtx := machineUserContext(
		&models.MachineIdentity{ID: machineID, Name: "ci-deployer"},
		[]string{"deployer"}, // GetMachineRoles' unscoped flattening of a project-A-only grant
		nil,
		0,
	)
	require.NotNil(t, userCtx.MachineIdentityID)
	require.Equal(t, machineID, *userCtx.MachineIdentityID)

	// The request targets project B (99) — a project the machine's grant was
	// never scoped to.
	req := httptest.NewRequest(http.MethodGet, "/projects/99/deploy", nil)
	req = req.WithContext(context.WithValue(req.Context(), userContextKey, userCtx))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "a machine principal must never satisfy RequireRole's unscoped name match (#308)")
}

func TestGetUserFromContext(t *testing.T) {
	tests := []struct {
		name         string
		setupCtx     func() context.Context
		expectUser   bool
		expectedID   uint
		expectedName string
	}{
		{
			name: "valid user context",
			setupCtx: func() context.Context {
				userCtx := &UserContext{
					UserID:   123,
					Username: "testuser",
					Email:    "test@example.com",
					Roles:    []string{"user"},
				}
				return context.WithValue(context.Background(), userContextKey, userCtx)
			},
			expectUser:   true,
			expectedID:   123,
			expectedName: "testuser",
		},
		{
			name: "empty context",
			setupCtx: func() context.Context {
				return context.Background()
			},
			expectUser: false,
		},
		{
			name: "wrong context key",
			setupCtx: func() context.Context {
				userCtx := &UserContext{
					UserID:   123,
					Username: "testuser",
				}
				return context.WithValue(context.Background(), wrongKey, userCtx)
			},
			expectUser: false,
		},
		{
			name: "wrong context value type",
			setupCtx: func() context.Context {
				return context.WithValue(context.Background(), userContextKey, "not-a-user-context")
			},
			expectUser: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupCtx()
			userCtx := GetUserFromContext(ctx)

			if tt.expectUser {
				require.NotNil(t, userCtx)
				assert.Equal(t, tt.expectedID, userCtx.UserID)
				assert.Equal(t, tt.expectedName, userCtx.Username)
			} else {
				assert.Nil(t, userCtx)
			}
		})
	}
}

func TestValidateToken(t *testing.T) {
	tests := []struct {
		name         string
		token        string
		expectError  bool
		expectedUser *UserContext
	}{
		{
			name:        "valid admin token",
			token:       validToken,
			expectError: false,
			expectedUser: &UserContext{
				UserID:   1,
				Username: "admin",
				Email:    "admin@example.com",
				Roles:    []string{"admin", "user"},
			},
		},
		{
			name:        "valid test token",
			token:       testToken,
			expectError: false,
			expectedUser: &UserContext{
				UserID:   2,
				Username: "testuser",
				Email:    "test@example.com",
				Roles:    []string{"viewer"},
			},
		},
		{
			name:        "invalid token",
			token:       "invalid-token",
			expectError: true,
		},
		{
			name:        "empty token",
			token:       "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userCtx, err := validateToken(context.Background(), fakeValidator{}, tt.token)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, userCtx)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, userCtx)
				assert.Equal(t, tt.expectedUser.UserID, userCtx.UserID)
				assert.Equal(t, tt.expectedUser.Username, userCtx.Username)
				assert.Equal(t, tt.expectedUser.Email, userCtx.Email)
				assert.Equal(t, tt.expectedUser.Roles, userCtx.Roles)
			}
		})
	}
}

// makeTestJWT builds a real, correctly-signed three-segment JWT with the given
// issuer/kid, for testing oidcDiagnosticFields's unverified best-effort parse.
// fakeValidator.ValidateOIDCToken never checks the signature (it just string-
// matches "header.valid.sig"), so any properly-shaped JWT here exercises the
// failure path.
func makeTestJWT(t *testing.T, issuer, kid string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		Issuer:  issuer,
		Subject: "test-subject",
	})
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(key)
	require.NoError(t, err)
	return signed
}

// TestValidateToken_OIDCFailureLogsDiagnostics confirms a failed federated-JWT
// verification is logged server-side (previously discarded entirely, leaving
// zero operator signal — see server/middleware/auth.go's oidcDiagnosticFields)
// with the token's issuer/kid, without changing validateToken's returned error.
func TestValidateToken_OIDCFailureLogsDiagnostics(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)

	badToken := makeTestJWT(t, "https://unreachable-issuer.example", "kid-123")
	userCtx, err := validateToken(context.Background(), fakeValidator{}, badToken)

	require.Error(t, err)
	assert.Nil(t, userCtx)

	logged := buf.String()
	assert.Contains(t, logged, "WARNING: OIDC federation verification failed")
	assert.Contains(t, logged, "https://unreachable-issuer.example")
	assert.Contains(t, logged, "kid-123")
}

// TestValidateToken_OIDCFailureLogIsBoundedAndSafe confirms boundedForLog does
// its job: an attacker-controlled claim (this runs on an UNVERIFIED token)
// can't forge a fake log field via an embedded quote, and can't bloat the log
// line via an oversized value.
func TestValidateToken_OIDCFailureLogIsBoundedAndSafe(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)

	maliciousIssuer := `evil" forged_field="injected` + strings.Repeat("A", 1000)
	badToken := makeTestJWT(t, maliciousIssuer, "k1")
	_, err := validateToken(context.Background(), fakeValidator{}, badToken)
	require.Error(t, err)

	logged := buf.String()
	// %q escapes an embedded quote (-> \") rather than letting it close the
	// field early and forge a fake key=value pair after it.
	assert.NotContains(t, logged, `forged_field="injected`, "an embedded quote must not forge a fake log field")
	assert.Less(t, len(logged), 2000, "an oversized claim must not bloat the log line unbounded")
}

// TestAuthentication_OIDCFailureResponseUnchanged confirms the server-side
// logging added for OIDC verification failures does not change what an
// unauthenticated caller sees: still a generic, detail-free 401 — config
// topology (issuer identity, reachability) must never leak into the response.
func TestAuthentication_OIDCFailureResponseUnchanged(t *testing.T) {
	badToken := makeTestJWT(t, "https://some-internal-issuer.example", "k1")
	mw := newTestAuthMiddleware()
	handler := mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler must not be reached on auth failure")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+badToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "Invalid or expired token")
	assert.NotContains(t, rec.Body.String(), "some-internal-issuer.example", "issuer must never leak into the client-facing response")
}

// TestValidateToken_PATRestriction asserts the ADR-042 least-privilege wiring:
// a scoped PAT surfaces its restriction on the UserContext, an unrestricted PAT
// and a session carry none, and buildRequestContext propagates the restriction so
// core.Authorize can enforce it downstream.
func TestValidateToken_PATRestriction(t *testing.T) {
	t.Run("scoped PAT carries its restriction and propagates to context", func(t *testing.T) {
		userCtx, err := validateToken(context.Background(), fakeValidator{}, "kx_pat_scopedtoken")
		require.NoError(t, err)
		require.NotNil(t, userCtx.PATRestriction)
		assert.Equal(t, []string{"secrets.read"}, userCtx.PATRestriction.Permissions)
		assert.Equal(t, uint(5), userCtx.PATRestriction.ProjectID)
		assert.False(t, userCtx.SessionAuth, "a PAT is not an interactive session")

		// The restriction filters as expected: the listed permission within the
		// token's project passes; a different permission or project is denied.
		assert.True(t, userCtx.PATRestriction.Allows("secrets.read", core.Scope{ProjectID: 5}))
		assert.False(t, userCtx.PATRestriction.Allows("secrets.write", core.Scope{ProjectID: 5}))
		assert.False(t, userCtx.PATRestriction.Allows("secrets.read", core.Scope{ProjectID: 6}))

		// buildRequestContext must not panic and must return a context carrying the
		// identity, so downstream core.Authorize reads the restriction off ctx.
		ctx := buildRequestContext(context.Background(), userCtx, nil)
		require.NotNil(t, ctx)
		assert.Equal(t, userCtx, GetUserFromContext(ctx))
	})

	t.Run("unrestricted PAT carries no restriction", func(t *testing.T) {
		userCtx, err := validateToken(context.Background(), fakeValidator{}, "kx_pat_validtoken")
		require.NoError(t, err)
		assert.Nil(t, userCtx.PATRestriction)
	})

	t.Run("session token carries no restriction", func(t *testing.T) {
		userCtx, err := validateToken(context.Background(), fakeValidator{}, "valid-token")
		require.NoError(t, err)
		assert.Nil(t, userCtx.PATRestriction)
		assert.True(t, userCtx.SessionAuth)
	})
}

// Benchmark tests
func BenchmarkAuthentication(b *testing.B) {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	authMiddleware := newTestAuthMiddleware()
	handler := authMiddleware(testHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

// Test concurrent access
func TestAuthenticationConcurrency(t *testing.T) {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userCtx := GetUserFromContext(r.Context())
		assert.NotNil(t, userCtx)
		w.WriteHeader(http.StatusOK)
	})

	authMiddleware := newTestAuthMiddleware()
	handler := authMiddleware(testHandler)

	const numGoroutines = 100
	results := make(chan int, numGoroutines)

	for range numGoroutines {
		go func() {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Authorization", "Bearer valid-token")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			results <- w.Code
		}()
	}

	successCount := 0
	for range numGoroutines {
		code := <-results
		if code == http.StatusOK {
			successCount++
		}
	}

	assert.Equal(t, numGoroutines, successCount)
}

// A PAT with a CIDR allowlist is honored per-request: accepted from an in-range source IP
// and denied (403) from outside — and the denial holds on the cached fast path too.
func TestAuthentication_PATNetworkAllowlist(t *testing.T) {
	mw := newTestAuthMiddleware()
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	serve := func(remoteAddr string) int {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer kx_pat_cidrtoken")
		req.RemoteAddr = remoteAddr
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Code
	}

	assert.Equal(t, http.StatusOK, serve("10.1.2.3:5555"), "in-range source IP is allowed")
	// Second request caches the (valid) identity but must still be denied from off-network.
	assert.Equal(t, http.StatusForbidden, serve("203.0.113.9:5555"), "off-network source IP is forbidden")
	// And an in-range request after the cached deny still passes (per-request evaluation).
	assert.Equal(t, http.StatusOK, serve("10.9.9.9:443"), "in-range again after a deny")
}

// #146: a PAT's CIDR allowlist narrowed AFTER the first request (which cached the
// identity) must be enforced on the very next request — a cache HIT must not keep
// permitting a source IP the allowlist no longer allows, even within validTokenTTL.
func TestAuthentication_PATNetworkAllowlist_RefreshesOnCacheHit(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.PersonalAccessToken{}))
	require.NoError(t, db.Create(&models.User{ID: 3, Username: "patuser", Email: "pat@example.com", IsActive: true}).Error)

	const raw = "kx_pat_cidrtoken"
	sum := sha256.Sum256([]byte(raw))
	hash := hex.EncodeToString(sum[:])
	cidrsJSON := `["10.0.0.0/8"]`
	pat := &models.PersonalAccessToken{ID: 1, UserID: 3, Name: "ci", TokenHash: hash, AllowedCIDRs: cidrsJSON}
	require.NoError(t, db.Create(pat).Error)

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	mw := authenticationWithValidator(fakeValidator{}, coreService)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	serve := func(remoteAddr string) int {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer "+raw)
		req.RemoteAddr = remoteAddr
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Code
	}

	// First request (slow path, via fakeValidator): in-range, cached.
	require.Equal(t, http.StatusOK, serve("10.1.2.3:5555"))

	// An admin narrows the allowlist directly in storage — simulating a live
	// mid-incident restriction change on the SAME token the cache already holds.
	pat.AllowedCIDRs = `["192.0.2.0/24"]`
	require.NoError(t, db.Save(pat).Error)

	// The SAME source IP that was allowed a moment ago must now be denied — on the
	// cache-HIT path, not after the 30s TTL expires.
	assert.Equal(t, http.StatusForbidden, serve("10.1.2.3:5555"),
		"a narrowed allowlist must take effect on the very next request, not after the cache TTL")
	// And the newly-allowed network is now honored, also on a cache hit.
	assert.Equal(t, http.StatusOK, serve("192.0.2.7:5555"))
}

// #G60 regression: a CIDR-restricted PAT presented from a disallowed source IP
// must be rejected WITHOUT stamping last_used_at — the touch must only fire
// once the network-restriction check has actually passed, not merely because
// the token itself resolved. This exercises the real core.KeyorixCore (not
// fakeValidator) as the sessionValidator so ValidatePATToken's real PAT-id
// plumbing and handleAuthRequest's post-check TouchPATLastUsed both run.
func TestAuthentication_PATNetworkAllowlist_DeniedRequestDoesNotTouchLastUsed(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	// Role/UserRole are needed by ValidatePATToken's GetUserRoles call on the real
	// (non-fake) storage path this test exercises.
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.PersonalAccessToken{}, &models.Role{}, &models.UserRole{}))
	require.NoError(t, db.Create(&models.User{ID: 4, Username: "cidruser", Email: "cidr@example.com", IsActive: true}).Error)

	hashOf := func(raw string) string {
		sum := sha256.Sum256([]byte(raw))
		return hex.EncodeToString(sum[:])
	}

	// Two DISTINCT tokens, each used exactly once, so neither request can be
	// served from the auth cache (a cache HIT deliberately never re-touches
	// last_used_at at all — see TestAuthentication_PATNetworkAllowlist_RefreshesOnCacheHit
	// above — which would make the second assertion below vacuously true if
	// this test instead reused the SAME token for both calls).
	const deniedRaw = "kx_pat_touchcidr_denied"
	deniedPAT := &models.PersonalAccessToken{ID: 1, UserID: 4, Name: "ci-denied", TokenHash: hashOf(deniedRaw), AllowedCIDRs: `["10.0.0.0/8"]`}
	require.NoError(t, db.Create(deniedPAT).Error)

	const allowedRaw = "kx_pat_touchcidr_allowed"
	allowedPAT := &models.PersonalAccessToken{ID: 2, UserID: 4, Name: "ci-allowed", TokenHash: hashOf(allowedRaw), AllowedCIDRs: `["10.0.0.0/8"]`}
	require.NoError(t, db.Create(allowedPAT).Error)

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	mw := Authentication(coreService)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	serve := func(raw, remoteAddr string) int {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer "+raw)
		req.RemoteAddr = remoteAddr
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Code
	}

	// A PAT presented from a disallowed network is rejected...
	require.Equal(t, http.StatusForbidden, serve(deniedRaw, "203.0.113.9:5555"))

	var reloadedDenied models.PersonalAccessToken
	require.NoError(t, db.First(&reloadedDenied, 1).Error)
	assert.Nil(t, reloadedDenied.LastUsedAt, "a request rejected for its source network must not stamp last_used_at")

	// ...but a different token, from an allowed network, succeeds and DOES stamp
	// it — confirming the assertion above isn't just "never touched at all".
	require.Equal(t, http.StatusOK, serve(allowedRaw, "10.1.2.3:5555"))

	var reloadedAllowed models.PersonalAccessToken
	require.NoError(t, db.First(&reloadedAllowed, 2).Error)
	assert.NotNil(t, reloadedAllowed.LastUsedAt, "a request accepted from an allowed network stamps last_used_at")
}

// A token revoked WHILE a slow-path validation was in flight must not be resurrected by
// that validation's positive cache write (the revocation-resurrection race).
func TestCacheSetValidated_DropsResurrectionAfterRevoke(t *testing.T) {
	key := tokenKey("race-token")
	tokenCacheMu.Lock()
	delete(tokenCache, key)
	tokenCacheMu.Unlock()

	validatedAt := time.Now()        // slow path began (before its DB read)
	time.Sleep(2 * time.Millisecond) //
	InvalidateTokenCacheByHash(key)  // token revoked during validation
	// The in-flight positive write must be refused (revoke is newer than validatedAt).
	cacheSetValidated(key, &UserContext{UserID: 1}, validatedAt, time.Now().Add(validTokenTTL))

	entry, ok := cacheGet(key)
	if !ok {
		return // tombstone may have already expired in CI; the key point is no positive entry
	}
	if entry.userCtx != nil {
		t.Error("a token revoked mid-validation must NOT be resurrected as a positive cache entry")
	}
}

// #2423 coordinator follow-up: a role removal evicts via ClearTokenCacheIfCached,
// not InvalidateTokenCacheByHash's tombstone (ClearTokenCacheIfCached must never
// negative-cache a credential it never saw -- see its own doc comment). But a
// slow-path validation that read the user's OLD (pre-removal) permissions from the
// DB before the clear ran, and writes its positive cache entry AFTER the clear,
// must still be refused -- otherwise the removed role's grant is resurrected in
// the cache for up to validTokenTTL, a genuine privilege-bypass window, not merely
// a wrong status code. Mirrors TestCacheSetValidated_DropsResurrectionAfterRevoke
// above, using ClearTokenCacheIfCached as the eviction instead of
// InvalidateTokenCacheByHash. This is the no-interleaving-read case; see
// TestCacheSetValidated_DropsResurrectionAfterClear_SurvivesInterveningCacheGet
// below for the harder case a first version of this fix missed (coordinator
// review): an intervening cacheGet on the same key between the clear and the
// stale write.
func TestCacheSetValidated_DropsResurrectionAfterClear(t *testing.T) {
	key := tokenKey("clear-race-token")
	tokenCacheMu.Lock()
	delete(tokenCache, key)
	delete(clearedAt, key)
	tokenCacheMu.Unlock()

	validatedAt := time.Now() // slow path began (before its DB read saw the still-held role)
	time.Sleep(2 * time.Millisecond)
	ClearTokenCacheIfCached(key) // role removed; cache cleared during validation

	// The in-flight positive write (built from the stale, pre-removal permission
	// read) must be refused -- the clear is newer than validatedAt.
	cacheSetValidated(key, &UserContext{UserID: 1}, validatedAt, time.Now().Add(validTokenTTL))

	entry, ok := cacheGet(key)
	if !ok {
		return // no entry at all is also a pass; the key point is no positive entry
	}
	if entry.userCtx != nil {
		t.Error("a token cleared mid-validation must NOT be resurrected as a positive cache entry carrying the removed role's permissions")
	}
}

// TestCacheSetValidated_DropsResurrectionAfterClear_SurvivesInterveningCacheGet is
// the exact race the coordinator's review on the first version of this fix
// identified: that version's guard was a tokenCacheEntry marker with
// expiresAt=now, written into tokenCache by ClearTokenCacheIfCached. cacheGet
// deletes any entry whose expiresAt has passed on its very next read -- so a
// SECOND, unrelated request for the same key, landing between the clear and the
// slow-path's positive write, deleted the marker before cacheSetValidatedGen ever
// got to check its revokedAt, and the resurrection succeeded anyway. The fix
// (a separate clearedAt map, checked directly by cacheSetValidatedGen,
// independent of whatever cacheGet did to tokenCache) must survive exactly this
// interleaving:
//
//  1. slow-path validation starts (captures validatedAt, reads the OLD permissions)
//  2. role removed -> ClearTokenCacheIfCached(key)
//  3. an intervening cacheGet(key) -- simulates a second, unrelated request for
//     the same token landing right after the clear
//  4. the slow-path validation finishes -> cacheSetValidatedGen(key, ...)
//  5. assert: the stale positive was NOT cached
func TestCacheSetValidated_DropsResurrectionAfterClear_SurvivesInterveningCacheGet(t *testing.T) {
	key := tokenKey("clear-race-interleaved-token")
	tokenCacheMu.Lock()
	delete(tokenCache, key)
	delete(clearedAt, key)
	tokenCacheMu.Unlock()

	// 1. Slow-path validation begins -- reads the user's OLD (still-held) role.
	validatedAt := time.Now()
	time.Sleep(2 * time.Millisecond)

	// 2. Role removed concurrently.
	ClearTokenCacheIfCached(key)

	// 3. An intervening read for the SAME key -- a different, unrelated request.
	// With the original tokenCacheEntry-marker design this call would delete the
	// marker (its expiresAt already passed) before step 4 ever gets to check it.
	if _, ok := cacheGet(key); ok {
		t.Fatalf("expected a miss immediately after ClearTokenCacheIfCached, got a cached entry")
	}

	// 4. The slow-path validation (started in step 1, before the clear) now
	// finishes and tries to cache its stale, pre-removal result.
	cacheSetValidated(key, &UserContext{UserID: 1}, validatedAt, time.Now().Add(validTokenTTL))

	// 5. The stale positive must NOT have been cached, despite the intervening
	// cacheGet in step 3.
	entry, ok := cacheGet(key)
	if ok && entry.userCtx != nil {
		t.Error("the stale positive write must be refused even after an intervening cacheGet deleted the clear's own tokenCache marker -- " +
			"the removed role's permissions must not be resurrected via this interleaving")
	}
}

// ClearTokenCacheIfCached must not create an observable negative-cache window
// for a hash that was never cached before -- the #2402 bug this function exists
// to avoid. A plain cacheGet immediately after the clear (same as any ordinary
// request would do) must see a miss, not a lingering negative entry.
func TestClearTokenCacheIfCached_NeverCachedHashHasNoObservableNegativeWindow(t *testing.T) {
	key := tokenKey("never-cached-token")
	tokenCacheMu.Lock()
	delete(tokenCache, key)
	delete(clearedAt, key)
	tokenCacheMu.Unlock()

	ClearTokenCacheIfCached(key)

	_, ok := cacheGet(key)
	if ok {
		t.Error("a hash that was never cached must read as a miss immediately after ClearTokenCacheIfCached, not a lingering entry")
	}
}

// A positive write with no intervening revoke is cached normally.
func TestCacheSetValidated_CachesWhenNotRevoked(t *testing.T) {
	key := tokenKey("ok-token")
	tokenCacheMu.Lock()
	delete(tokenCache, key)
	tokenCacheMu.Unlock()

	cacheSetValidated(key, &UserContext{UserID: 7}, time.Now(), time.Now().Add(validTokenTTL))
	entry, ok := cacheGet(key)
	if !ok || entry.userCtx == nil || entry.userCtx.UserID != 7 {
		t.Errorf("a non-revoked validation must be cached; got ok=%v entry=%+v", ok, entry)
	}
}

// pruneLocked hard-caps the cache so a flood of distinct tokens can't grow it unbounded.
func TestPruneLocked_EnforcesSizeCap(t *testing.T) {
	// Clear the shared cache before and after so the bulk insert doesn't bleed into other
	// tests that share the process-wide map.
	t.Cleanup(func() {
		tokenCacheMu.Lock()
		for k := range tokenCache {
			delete(tokenCache, k)
		}
		tokenCacheMu.Unlock()
	})
	tokenCacheMu.Lock()
	for k := range tokenCache {
		delete(tokenCache, k)
	}
	far := time.Now().Add(time.Hour)
	for i := range maxTokenCacheEntries + 1000 {
		tokenCache[tokenKey(string(rune(i))+"-x-"+time.Now().String()+string(rune(i)))] = tokenCacheEntry{expiresAt: far}
	}
	pruneLocked()
	n := len(tokenCache)
	tokenCacheMu.Unlock()
	if n > maxTokenCacheEntries {
		t.Errorf("cache size %d exceeds cap %d after prune", n, maxTokenCacheEntries)
	}
}
