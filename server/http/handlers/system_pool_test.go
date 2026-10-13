package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
)

func systemInfoPool(t *testing.T, cfg *config.Config, cs *core.KeyorixCore) PoolInfo {
	t.Helper()
	req := userCtxForTest(httptest.NewRequest(http.MethodGet, "/api/v1/system/info", nil))
	rr := httptest.NewRecorder()
	MakeSystemInfoHandler(cfg, cs)(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	var resp struct {
		Data SystemInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	return resp.Data.Database.Pool
}

// #3037: GET /system/info reported the raw config values (0 / 0 on every install that does
// not set max_open_conns, which is every compose and Helm install) and a hard-coded "2 active
// connections". It must report the pool the server is actually running.
func TestMakeSystemInfoHandler_PoolIsTheLivePool(t *testing.T) {
	ls := freshLocalStorageS12(t)
	sqlDB, err := ls.DB().DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(7)
	cs := core.NewKeyorixCore(ls)

	// Config says nothing about the pool (the common case): the answer is still the real cap.
	cfg := &config.Config{}
	cfg.Storage.Type = "sqlite"

	pool := systemInfoPool(t, cfg, cs)
	assert.Equal(t, 7, pool.MaxConnections, "the cap the pool really has, not the unset config value")
	assert.Equal(t, 0, pool.ActiveConnections, "no connection is held: not the old constant 2")

	// Hold two connections: the report follows.
	c1, err := sqlDB.Conn(context.Background())
	require.NoError(t, err)
	c2, err := sqlDB.Conn(context.Background())
	require.NoError(t, err)
	pool = systemInfoPool(t, cfg, cs)
	assert.Equal(t, 2, pool.ActiveConnections)
	assert.Equal(t, 7, pool.MaxConnections)
	require.NoError(t, c1.Close())
	pool = systemInfoPool(t, cfg, cs)
	assert.Equal(t, 1, pool.ActiveConnections)
	require.NoError(t, c2.Close())

	// A config value that disagrees with the pool does not win over the pool.
	cfg.Storage.Database.MaxOpenConns = 99
	cfg.Storage.Database.MaxIdleConns = 99
	pool = systemInfoPool(t, cfg, cs)
	assert.Equal(t, 7, pool.MaxConnections)
	assert.LessOrEqual(t, pool.IdleConnections, 7)
}
