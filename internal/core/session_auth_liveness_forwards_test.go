package core

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// PERF-FIX-7: these test Storage wrappers override GetUser. Each forwards the
// combined session cache-hit read to storage.ComposeSessionAuthLiveness over
// itself so its GetUser override is what that read meets too
// (TestSessionAuthReadWrappersForwardTheCombinedRead).

func (s *userReadFaultStub) GetSessionAuthLiveness(ctx context.Context, userID, sessionID uint) (*storage.SessionAuthLiveness, error) {
	return storage.ComposeSessionAuthLiveness(ctx, s, userID, sessionID), nil
}

func (f *failingUserLookup) GetSessionAuthLiveness(ctx context.Context, userID, sessionID uint) (*storage.SessionAuthLiveness, error) {
	return storage.ComposeSessionAuthLiveness(ctx, f, userID, sessionID), nil
}

func (t *transientOwnerLookup) GetSessionAuthLiveness(ctx context.Context, userID, sessionID uint) (*storage.SessionAuthLiveness, error) {
	return storage.ComposeSessionAuthLiveness(ctx, t, userID, sessionID), nil
}

func (s *breakGlassNotifyPanicSpy) GetSessionAuthLiveness(ctx context.Context, userID, sessionID uint) (*storage.SessionAuthLiveness, error) {
	return storage.ComposeSessionAuthLiveness(ctx, s, userID, sessionID), nil
}

func (s *reviewReminderNotifySpy) GetSessionAuthLiveness(ctx context.Context, userID, sessionID uint) (*storage.SessionAuthLiveness, error) {
	return storage.ComposeSessionAuthLiveness(ctx, s, userID, sessionID), nil
}
