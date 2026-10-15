package services

// audit_keyset_test.go — gRPC GetAuditLogs follows the same page contract as
// REST GET /audit/logs (docs/specs/audit-list-keyset.md §3): next_cursor walk,
// capped total with total_exact, InvalidArgument for the offset cap and a bad
// cursor.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

func TestAuditService_GetAuditLogs_CursorWalk(t *testing.T) {
	svc, db := newAuditServiceDB(t)
	base := time.Now().UTC().Add(-time.Hour)
	for i := range 24 {
		require.NoError(t, db.Create(&models.AuditEvent{EventType: "secret.read", EventTime: base.Add(time.Duration(i/3) * time.Second)}).Error)
	}
	req := &pb.GetAuditLogsRequest{PageSize: 10}
	first, err := svc.GetAuditLogs(auditCtx(), req)
	require.NoError(t, err)
	require.Equal(t, uint32(25), first.GetTotal(), "24 seeded + newAuditService's one")
	require.True(t, first.GetTotalExact())
	require.NotEmpty(t, first.GetNextCursor())

	seen := map[uint32]bool{}
	resp := first
	for {
		for _, l := range resp.GetLogs() {
			require.False(t, seen[l.GetId()], "id %d returned twice", l.GetId())
			seen[l.GetId()] = true
		}
		if resp.NextCursor == nil {
			break
		}
		resp, err = svc.GetAuditLogs(auditCtx(), &pb.GetAuditLogsRequest{PageSize: 10, Cursor: resp.NextCursor})
		require.NoError(t, err)
		require.Zero(t, resp.GetTotal(), "a cursor page runs no count unless include_total")
	}
	require.Len(t, seen, 25)
}

func TestAuditService_GetAuditLogs_OffsetCapAndBadCursor(t *testing.T) {
	svc := newAuditService(t)
	_, err := svc.GetAuditLogs(auditCtx(), &pb.GetAuditLogsRequest{Page: 100, PageSize: 100})
	require.NoError(t, err, "the last page inside the cap")
	_, err = svc.GetAuditLogs(auditCtx(), &pb.GetAuditLogsRequest{Page: 101, PageSize: 100})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Contains(t, status.Convert(err).Message(), "cursor")
	bad := "not-a-cursor"
	_, err = svc.GetAuditLogs(auditCtx(), &pb.GetAuditLogsRequest{Cursor: &bad})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}
