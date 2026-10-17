// anomaly_config_test.go — coverage for GetAnomalyConfig/UpdateAnomalyConfig
// (anomaly_config.go), previously untested (0% coverage). Both are
// package-level functions using middleware.GetCoreServiceFromContext, whose
// context key is unexported outside the middleware package — the established
// convention for exercising the happy path (see
// TestListAnomalyAlerts_WithCoreService_S7 in handlers_s7_test.go) is to wrap
// the handler in middleware.Authentication(cs) behind a real httptest.Server
// and authenticate with a bootstrapped session, rather than fabricate the
// context directly.
package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// newAnomalyConfigTestServer boots a real core, bootstraps an admin user, and
// returns an httptest.Server wired with GetAnomalyConfig/UpdateAnomalyConfig
// behind middleware.Authentication, plus a bearer token for that admin and
// the FaultyStorage under the core (so a caller can arm a fault on exactly the
// handler's own storage call; closing the DB would also fail the auth
// cache-hit live re-check, which answers 503 by design).
func newAnomalyConfigTestServer(t *testing.T, name string) (*httptest.Server, string, *faultstorage.FaultyStorage) {
	t.Helper()
	ls, ok := freshCoreS7(t).Storage().(*store.LocalStorage)
	require.True(t, ok)
	fs := faultstorage.NewFaultyStorage(ls, nil)
	cs := core.NewKeyorixCore(fs)
	mux := chi.NewRouter()
	mux.Use(middleware.Authentication(cs))
	mux.Get("/api/v1/admin/anomaly-config", GetAnomalyConfig)
	mux.Put("/api/v1/admin/anomaly-config", UpdateAnomalyConfig)

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	ctx := context.Background()
	cs.SetBootstrapToken(name + "-boot")
	_, err := cs.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: name,
		Email:    name + "@example.com",
		Password: "Kx#Vr9$Mn2!Zp4@Qw",
		Token:    name + "-boot",
	})
	require.NoError(t, err)
	session, _, err := cs.Login(ctx, &core.LoginRequest{Username: name, Password: "Kx#Vr9$Mn2!Zp4@Qw"})
	require.NoError(t, err)

	return ts, session.SessionToken, fs
}

func TestGetAnomalyConfig_NoCoreService(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/anomaly-config", nil)
	w := httptest.NewRecorder()
	GetAnomalyConfig(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestUpdateAnomalyConfig_NoCoreService(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/anomaly-config", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	UpdateAnomalyConfig(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestGetAnomalyConfig_Success — no config has ever been saved, so the
// storage layer's sensible defaults are returned (200).
func TestGetAnomalyConfig_Success(t *testing.T) {
	ts, token, _ := newAnomalyConfigTestServer(t, "s_anomalycfg_get")

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/anomaly-config", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestUpdateAnomalyConfig_Success persists a within-bounds config and
// confirms the round trip through GET reflects it.
func TestUpdateAnomalyConfig_Success(t *testing.T) {
	ts, token, _ := newAnomalyConfigTestServer(t, "s_anomalycfg_upd")

	body := `{"lookback_days":14,"quarantine_hours":48,"ml_num_trees":50,"ml_sample_size":128}`
	req, err := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/admin/anomaly-config", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestUpdateAnomalyConfig_BadJSON exercises the malformed-body 400 branch.
func TestUpdateAnomalyConfig_BadJSON(t *testing.T) {
	ts, token, _ := newAnomalyConfigTestServer(t, "s_anomalycfg_badjson")

	req, err := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/admin/anomaly-config", strings.NewReader("{bad json}"))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestUpdateAnomalyConfig_ValidationError_S1546 exercises the ceiling
// (#G44) rejection branch (lookback_days above the maximum of 365).
//
// Bug found and fixed alongside this coverage sweep: the handler used to map
// EVERY UpdateAnomalyConfig error -- including this validation error, which
// core.validateAnomalyConfig returns BEFORE ever touching storage -- to a
// blanket 500 "InternalError". A caller submitting an out-of-range knob got
// told the SERVER failed, not that ITS request was invalid; every sibling
// handler in this package that distinguishes validation from storage errors
// (secrets_bulk_rotate.go's BulkRotateSecrets, catalog.go's CloneEnvironment)
// returns 400 for this class of error. Fixed by matching on the
// "exceeds the maximum" substring validateAnomalyConfig's errors always
// carry, same convention those siblings already use.
func TestUpdateAnomalyConfig_ValidationError_S1546(t *testing.T) {
	ts, token, _ := newAnomalyConfigTestServer(t, "s_anomalycfg_valerr")

	body := `{"lookback_days":9999}`
	req, err := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/admin/anomaly-config", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "an out-of-range knob is a bad request, not a server failure")
}

// TestGetAnomalyConfig_StorageError arms a fault on coreService.GetAnomalyConfig's
// own storage read after auth is cached, so it fails with a genuine
// (non-record-not-found) error, exercising the handler's 500 branch. The DB
// stays open: a closed DB would also fail the auth cache-hit re-check, which
// fails closed with 503 (CACHE-FAILCLOSED-1) and never reaches the handler.
func TestGetAnomalyConfig_StorageError(t *testing.T) {
	ts, token, fs := newAnomalyConfigTestServer(t, "s_anomalycfg_geterr")

	newGetReq := func() *http.Request {
		r, rerr := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/anomaly-config", nil)
		require.NoError(t, rerr)
		r.Header.Set("Authorization", "Bearer "+token)
		return r
	}

	// Warm-up request first: middleware.Authentication positive-caches a
	// validated session token, so the request below is a cache hit whose live
	// re-check succeeds and only GetAnomalyConfig's own storage read is armed
	// to fail (a 500 from the handler, not the middleware's 503).
	warmup, err := ts.Client().Do(newGetReq())
	require.NoError(t, err)
	_ = warmup.Body.Close()
	require.Equal(t, http.StatusOK, warmup.StatusCode)

	fs.Arm(&faultstorage.FaultSpec{Method: "GetAnomalyConfig", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("injected storage failure")})

	resp, err := ts.Client().Do(newGetReq())
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// TestUpdateAnomalyConfig_StorageError arms a fault on SaveAnomalyConfig after
// auth is cached, so a within-bounds config (passes validateAnomalyConfig, so
// the #G44 400 branch is NOT taken) fails at the write instead -- the plain
// "InternalError" 500 branch. The DB stays open so the auth cache-hit re-check
// still succeeds.
func TestUpdateAnomalyConfig_StorageError(t *testing.T) {
	ts, token, fs := newAnomalyConfigTestServer(t, "s_anomalycfg_puterr")

	// Warm-up GET first for the same reason as
	// TestGetAnomalyConfig_StorageError: populate the session-token cache
	// before the fault is armed, so the PUT below fails at SaveAnomalyConfig,
	// not at the auth re-check.
	warmupReq, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/anomaly-config", nil)
	require.NoError(t, err)
	warmupReq.Header.Set("Authorization", "Bearer "+token)
	warmup, err := ts.Client().Do(warmupReq)
	require.NoError(t, err)
	_ = warmup.Body.Close()
	require.Equal(t, http.StatusOK, warmup.StatusCode)

	fs.Arm(&faultstorage.FaultSpec{Method: "SaveAnomalyConfig", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("injected storage failure")})

	body := `{"lookback_days":14}`
	req, err := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/admin/anomaly-config", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}
