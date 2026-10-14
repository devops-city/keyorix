package handlers

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func setupNotificationTest(t *testing.T) (*NotificationHandler, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Notification{}))
	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	return NewNotificationHandler(coreService), db
}

func TestNotificationHandler_ListMarkReadMarkAll(t *testing.T) {
	h, db := setupNotificationTest(t)

	// withUserCtx authenticates as user 1. Seed 2 for user 1 (one read) + 1 for user 2.
	require.NoError(t, db.Create(&models.Notification{UserID: 1, Type: "a", Title: "A", Message: "m1"}).Error)
	require.NoError(t, db.Create(&models.Notification{UserID: 1, Type: "b", Title: "B", Message: "m2", IsRead: true}).Error)
	require.NoError(t, db.Create(&models.Notification{UserID: 2, Type: "c", Title: "C", Message: "m3"}).Error)

	// List all for user 1 → 2 items, unread_count 1.
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/notifications", nil))
	w := httptest.NewRecorder()
	h.List(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	data := decodeData(t, w)
	assert.Len(t, data["notifications"].([]any), 2)
	assert.Equal(t, float64(1), data["unread_count"])

	// List unread only → 1 item.
	reqU := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/notifications?unread=true", nil))
	wu := httptest.NewRecorder()
	h.List(wu, reqU)
	require.Equal(t, http.StatusOK, wu.Code)
	assert.Len(t, decodeData(t, wu)["notifications"].([]any), 1)

	// Mark the unread one read → unread_count drops to 0.
	var unread models.Notification
	require.NoError(t, db.Where("user_id = ? AND is_read = ?", 1, false).First(&unread).Error)
	mr := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPost, "/x", nil)), "id", itoa(unread.ID))
	wmr := httptest.NewRecorder()
	h.MarkRead(wmr, mr)
	require.Equal(t, http.StatusOK, wmr.Code)

	wc := httptest.NewRecorder()
	h.List(wc, withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/notifications", nil)))
	assert.Equal(t, float64(0), decodeData(t, wc)["unread_count"])

	// Marking another user's notification → 404 (ownership).
	var others models.Notification
	require.NoError(t, db.Where("user_id = ?", 2).First(&others).Error)
	w404 := httptest.NewRecorder()
	h.MarkRead(w404, withChiParam(withUserCtx(httptest.NewRequest(http.MethodPost, "/x", nil)), "id", itoa(others.ID)))
	assert.Equal(t, http.StatusNotFound, w404.Code)

	// Mark-all-read is a clean 200.
	wall := httptest.NewRecorder()
	h.MarkAllRead(wall, withUserCtx(httptest.NewRequest(http.MethodPost, "/x", nil)))
	assert.Equal(t, http.StatusOK, wall.Code)
}

func itoa(u uint) string {
	return strconv.FormatUint(uint64(u), 10)
}
