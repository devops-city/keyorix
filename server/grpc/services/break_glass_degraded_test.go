package services

// BREAKGLASS-OWED-1: an activation that could be recorded neither in the audit log
// nor as owed is refused; gRPC says Unavailable with fixed text naming the offline
// recover-admin procedure and never the storage error underneath.

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestBreakGlassError_UnrecordableIsUnavailableNamingRecoverAdmin(t *testing.T) {
	err := breakGlassError(fmt.Errorf("pq: relation pending_audit_events is read-only: %w", core.ErrBreakGlassUnrecordable))
	st := status.Convert(err)
	assert.Equal(t, codes.Unavailable, st.Code())
	assert.Contains(t, st.Message(), "recover-admin")
	assert.NotContains(t, st.Message(), "pq:", "no storage text reaches the client")
}

func TestBreakGlassToProto_CarriesDegradedAndSettled(t *testing.T) {
	now := time.Now()
	out := breakGlassToProto(&models.BreakGlassActivation{ID: 7, Degraded: true, AuditSettledAt: &now})
	assert.True(t, out.GetDegraded())
	assert.Equal(t, now.Unix(), out.GetAuditSettledAt().AsTime().Unix())
	plain := breakGlassToProto(&models.BreakGlassActivation{ID: 8})
	assert.False(t, plain.GetDegraded())
	assert.Nil(t, plain.AuditSettledAt)
}
