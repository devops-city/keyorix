package handlers

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// POST /system/init is reachable unauthenticated. When bootstrapping fails for a
// server-side reason the client gets the standard 500 body; the detail (here a
// database error naming a host and role) goes to the log only (HARDEN-HTTP-1 finding).
func TestInitSystem_ServerFaultReturnsStandardBodyAndLogsDetail(t *testing.T) {
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	secretDetail := errors.New("pq: password authentication failed for user \"keyorix_prod\" at db-primary.internal:5432")
	faulty.Arm(&faultstorage.FaultSpec{
		Method: "GetSystemMetadata", NthCall: 1, Kind: faultstorage.KindError, Err: secretDetail,
	})
	h := NewAuthHandler(core.NewKeyorixCore(faulty), false)

	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(log.Writer()) })

	body := `{"username":"admin","email":"admin@example.com","password":"Admin1234!"}`
	req := httptest.NewRequest(http.MethodPost, "/system/init", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.InitSystem(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	for _, leak := range []string{"keyorix_prod", "db-primary", "5432", "password authentication"} {
		assert.NotContains(t, w.Body.String(), leak, "the response must not carry the error text")
	}
	assert.Contains(t, w.Body.String(), "InternalError", "the standard error body")
	assert.Contains(t, logs.String(), "db-primary.internal", "the detail is logged")
}
