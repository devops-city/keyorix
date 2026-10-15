package core

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// #2951 item 2: the dashboard activity feed must not hand the UI raw event
// types ("secret.dependency_invalidated") or an empty name for events that do
// have a subject secret, and must keep the raw type available.
func TestMapAuditEventToActivity_ReadableLabelAndRawTypeKept(t *testing.T) {
	for _, raw := range []string{
		"secret.dependency_invalidated", "secret.restored", "role.removed", "break_glass.revoked",
		"some.future_event_type",
	} {
		item := mapAuditEventToActivity(&models.AuditEvent{ID: 1, EventType: raw, EventTime: time.Now()}, "alice")
		assert.Equal(t, raw, item.EventType, "raw type stays available")
		assert.NotEmpty(t, item.Label, raw)
		assert.False(t, strings.ContainsAny(item.Label, "._"), "label for %s must not look like a raw type: %q", raw, item.Label)
	}
	assert.Equal(t, "revoked break-glass access", ActivityLabel("break_glass.revoked"))
	assert.Equal(t, "some future event type", ActivityLabel("some.future_event_type"))
	// A version-history listing is not a value read (#2970): it gets its own phrase.
	assert.Equal(t, "listed versions of secret", ActivityLabel(EventSecretVersionsListed))
}

func TestGetActivityFeed_ResolvesSubjectSecretAndEventActor(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	sid, uid := uint(9), uint(3)
	events := []*models.AuditEvent{
		{ID: 1, EventType: "secret.dependency_invalidated", SecretNodeID: &sid, UserID: &uid,
			Description: `dependency of secret 9 on "db" (id 2) invalidated due to secret lifecycle event`, EventTime: time.Now()},
		{ID: 2, EventType: "secret.restored", SecretNodeID: &sid, Description: "secret 9 restored", EventTime: time.Now()},
		{ID: 3, EventType: "role.removed", Description: "role removed", EventTime: time.Now()},
	}
	ms.On("GetAuditLogs", mock.Anything, mock.Anything).Return(events, int64(3), nil)
	ms.On("GetSecretsByIDs", mock.Anything, []uint{9}).Return([]*models.SecretNode{{ID: 9, Name: "api-key"}}, nil)
	ms.On("GetUsernamesByIDs", mock.Anything, []uint{uid}).Return(map[uint]string{uid: "bob"}, nil)
	c := NewKeyorixCore(ms)

	feed, err := c.GetActivityFeed(context.Background(), 1, "alice-the-viewer", 1, 10)
	require.NoError(t, err)
	require.Len(t, feed.Items, 3)
	assert.Equal(t, "api-key", feed.Items[0].SecretName, "name comes from the event's secret, not parsed from the description")
	assert.Equal(t, "api-key", feed.Items[1].SecretName)
	assert.Equal(t, "", feed.Items[2].SecretName, "role events have no secret")
	assert.Equal(t, "bob", feed.Items[0].Actor, "actor is who did it, not the viewer")
	assert.Equal(t, "system", feed.Items[2].Actor)
}
