package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestEnforceSessionLimit(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.Session{}))
	ls := NewLocalStorage(db)

	base := time.Now()
	for i := range 30 {
		require.NoError(t, db.Create(&models.Session{
			UserID: 1, SessionToken: fmt.Sprintf("t%d", i),
			CreatedAt: base.Add(time.Duration(i) * time.Minute),
		}).Error)
	}
	require.NoError(t, db.Create(&models.Session{UserID: 2, SessionToken: "other"}).Error)

	require.NoError(t, ls.EnforceSessionLimit(context.Background(), 1, 25))

	var count int64
	db.Model(&models.Session{}).Where("user_id = ?", 1).Count(&count)
	assert.EqualValues(t, 25, count, "keeps exactly the cap")

	// The 5 oldest are reaped; the newest survives.
	var oldest, newest int64
	db.Model(&models.Session{}).Where("session_token = ?", "t0").Count(&oldest)
	db.Model(&models.Session{}).Where("session_token = ?", "t29").Count(&newest)
	assert.EqualValues(t, 0, oldest, "oldest session reaped")
	assert.EqualValues(t, 1, newest, "most-recent session retained")

	// Another user's sessions are untouched.
	var u2 int64
	db.Model(&models.Session{}).Where("user_id = ?", 2).Count(&u2)
	assert.EqualValues(t, 1, u2)

	// Under the cap is a no-op.
	require.NoError(t, ls.EnforceSessionLimit(context.Background(), 2, 25))
	db.Model(&models.Session{}).Where("user_id = ?", 2).Count(&u2)
	assert.EqualValues(t, 1, u2)
}
