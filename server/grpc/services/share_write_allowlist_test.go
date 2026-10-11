// share_write_allowlist_test.go — the gRPC half of the #3001 follow-up (Andrei,
// 2026-10-10 19:33): a WRITE share elevates only updating a secret's value/metadata
// and rotating it. Over gRPC the only elevated RPC is SecretService.UpdateSecret;
// every other RPC gated on secrets.write still needs a real role
// (server/http/share_write_allowlist_test.go is the REST half).
//
// The RPC list is derived: TestWriteShareRPCMatrix_CoversEverySecretsWriteRPC parses
// every non-test file in this package and fails on any RPC method whose body names
// secrets.write but has no grpcWriteShareMatrix entry. Calls go through the real
// ShareElevationAuditInterceptor, as in the server's chain.
package services

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// viaShareAudit runs fn behind the real ShareElevationAuditInterceptor.
func viaShareAudit(c *core.KeyorixCore, ctx context.Context, fn func(context.Context) error) error {
	_, err := interceptors.ShareElevationAuditInterceptor(c)(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test"},
		func(ctx context.Context, _ interface{}) (interface{}, error) { return nil, fn(ctx) })
	return err
}

type grpcWriteShareFixture struct {
	r            *secretTestRig
	c            *core.KeyorixCore
	secretID     uint32
	aliceShareID uint
	carolShareID uint
	share        *ShareGRPCService
	project      *ProjectGRPCService
	dynamic      *DynamicSecretGRPCService
}

// newGRPCWriteShareFixture: alice (user 2) and carol (user 3) are secrets.read-only
// members of project 1; alice holds a share at alicePermission on the owner's secret,
// carol a read share on it.
func newGRPCWriteShareFixture(t *testing.T, alicePermission string) *grpcWriteShareFixture {
	t.Helper()
	r := newSecretTestRig(t)
	require.NoError(t, r.db.AutoMigrate(&models.AuditEvent{}))
	seedProjectReader(t, r)
	require.NoError(t, r.db.Create(&models.User{ID: 3, Username: "carol", Email: "carol@example.com"}).Error)
	require.NoError(t, r.db.Create(&models.UserRole{UserID: 3, RoleID: readerRoleID, ProjectID: 1}).Error)
	sec := r.createSecret(t, authCtx(1, "owner"), "db-password", "v1")
	aliceShare := &models.ShareRecord{SecretID: uint(sec.GetId()), OwnerID: 1, RecipientID: 2, Permission: alicePermission}
	require.NoError(t, r.db.Create(aliceShare).Error)
	carolShare := &models.ShareRecord{SecretID: uint(sec.GetId()), OwnerID: 1, RecipientID: 3, Permission: "read"}
	require.NoError(t, r.db.Create(carolShare).Error)
	c := r.svc.core
	return &grpcWriteShareFixture{
		r: r, c: c, secretID: sec.GetId(), aliceShareID: aliceShare.ID, carolShareID: carolShare.ID,
		share: NewShareService(c), project: NewProjectService(c), dynamic: NewDynamicSecretService(c),
	}
}

type grpcWriteShareCase struct {
	elevated   bool
	shareAware bool // the gate consults shares, so the refusal carries the share reason
	call       func(f *grpcWriteShareFixture, ctx context.Context) error
}

// grpcWriteShareMatrix: every RPC in this package gated on secrets.write.
var grpcWriteShareMatrix = map[string]grpcWriteShareCase{
	"SecretGRPCService.UpdateSecret": {elevated: true, shareAware: true, call: func(f *grpcWriteShareFixture, ctx context.Context) error {
		v := "alice-via-write-share"
		_, err := f.r.svc.UpdateSecret(ctx, &pb.UpdateSecretRequest{Id: f.secretID, Value: &v})
		return err
	}},
	"SecretGRPCService.SetSecretAutoRotate": {shareAware: true, call: func(f *grpcWriteShareFixture, ctx context.Context) error {
		_, err := f.r.svc.SetSecretAutoRotate(ctx, &pb.SetSecretAutoRotateRequest{Id: f.secretID, Enabled: false})
		return err
	}},
	"SecretGRPCService.CreateSecret": {call: func(f *grpcWriteShareFixture, ctx context.Context) error {
		_, err := f.r.svc.CreateSecret(ctx, &pb.CreateSecretRequest{Name: "x", Value: "y", ProjectId: 1, EnvironmentId: 1, Type: "password"})
		return err
	}},
	"ShareGRPCService.ShareSecret": {shareAware: true, call: func(f *grpcWriteShareFixture, ctx context.Context) error {
		_, err := f.share.ShareSecret(ctx, &pb.ShareSecretRequest{SecretId: f.secretID, RecipientId: 3, Permission: "write"})
		return err
	}},
	"ShareGRPCService.UpdateSharePermission": {call: func(f *grpcWriteShareFixture, ctx context.Context) error {
		_, err := f.share.UpdateSharePermission(ctx, &pb.UpdateSharePermissionRequest{ShareId: uint32(f.carolShareID), Permission: "write"})
		return err
	}},
	"ShareGRPCService.RevokeShare": {call: func(f *grpcWriteShareFixture, ctx context.Context) error {
		_, err := f.share.RevokeShare(ctx, &pb.RevokeShareRequest{ShareId: uint32(f.carolShareID)})
		return err
	}},
	"ProjectGRPCService.CreateProject": {call: func(f *grpcWriteShareFixture, ctx context.Context) error {
		_, err := f.project.CreateProject(ctx, &pb.CreateProjectRequest{Name: "matrix"})
		return err
	}},
	"ProjectGRPCService.UpdateProject": {call: func(f *grpcWriteShareFixture, ctx context.Context) error {
		_, err := f.project.UpdateProject(ctx, &pb.UpdateProjectRequest{Id: 1, Description: "x"})
		return err
	}},
	"DynamicSecretGRPCService.CreateConfig": {call: func(f *grpcWriteShareFixture, ctx context.Context) error {
		_, err := f.dynamic.CreateConfig(ctx, &pb.CreateDynamicConfigRequest{Name: "x", ProjectId: 1, EnvironmentId: 1, BackendType: "postgres", AdminDsn: "postgres://u:p@h/db"})
		return err
	}},
	"DynamicSecretGRPCService.ClassifyConfig": {call: func(f *grpcWriteShareFixture, ctx context.Context) error {
		_, err := f.dynamic.ClassifyConfig(ctx, &pb.ClassifyDynamicConfigRequest{Id: 1, Classification: "public"})
		return err
	}},
	"DynamicSecretGRPCService.IssueLease": {call: func(f *grpcWriteShareFixture, ctx context.Context) error {
		_, err := f.dynamic.IssueLease(ctx, &pb.IssueLeaseRequest{ConfigId: 1})
		return err
	}},
	"DynamicSecretGRPCService.RevokeLease": {call: func(f *grpcWriteShareFixture, ctx context.Context) error {
		_, err := f.dynamic.RevokeLease(ctx, &pb.RevokeLeaseRequest{LeaseId: "1"})
		return err
	}},
	"DynamicSecretGRPCService.RenewLease": {call: func(f *grpcWriteShareFixture, ctx context.Context) error {
		_, err := f.dynamic.RenewLease(ctx, &pb.RenewLeaseRequest{LeaseId: "1"})
		return err
	}},
	"DynamicSecretGRPCService.RevokeAllLeases": {call: func(f *grpcWriteShareFixture, ctx context.Context) error {
		_, err := f.dynamic.RevokeAllLeases(ctx, &pb.RevokeAllLeasesRequest{ConfigId: 1})
		return err
	}},
}

func sortedMatrixKeys() []string {
	keys := make([]string, 0, len(grpcWriteShareMatrix))
	for k := range grpcWriteShareMatrix {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { // elevated first
		ei, ej := grpcWriteShareMatrix[keys[i]].elevated, grpcWriteShareMatrix[keys[j]].elevated
		if ei != ej {
			return ei
		}
		return keys[i] < keys[j]
	})
	return keys
}

func TestWriteShareRPCMatrix_WriteShareElevatesOnlyUpdate(t *testing.T) {
	f := newGRPCWriteShareFixture(t, "write")
	alice := authCtx(2, "alice")
	for _, name := range sortedMatrixKeys() {
		tc := grpcWriteShareMatrix[name]
		err := viaShareAudit(f.c, alice, func(ctx context.Context) error { return tc.call(f, ctx) })
		if tc.elevated {
			assert.NoError(t, err, "%s: a write share must elevate this RPC", name)
			continue
		}
		if assert.Error(t, err, "%s: a write share must NOT elevate this RPC", name) {
			assert.Equal(t, codes.PermissionDenied, status.Code(err), "%s: %v", name, err)
			if tc.shareAware {
				assert.Contains(t, status.Convert(err).Message(), "only lets you update its value and metadata or rotate it",
					"%s: the refusal must say what a share covers", name)
			}
		}
	}
	var carol models.ShareRecord
	require.NoError(t, f.r.db.First(&carol, f.carolShareID).Error, "alice must not be able to revoke carol's share")
	assert.Equal(t, "read", carol.Permission, "alice must not be able to change carol's share")
}

func TestWriteShareRPCMatrix_ReadShareUnchanged(t *testing.T) {
	f := newGRPCWriteShareFixture(t, "read")
	alice := authCtx(2, "alice")
	for _, name := range sortedMatrixKeys() {
		err := viaShareAudit(f.c, alice, func(ctx context.Context) error { return grpcWriteShareMatrix[name].call(f, ctx) })
		if assert.Error(t, err, "%s: a read share never grants secrets.write", name) {
			assert.Equal(t, codes.PermissionDenied, status.Code(err), "%s", name)
		}
	}
	_, err := f.r.svc.GetSecret(alice, &pb.GetSecretRequest{Id: f.secretID})
	assert.NoError(t, err, "reading is unchanged")
}

// TestWriteShareRPC_ElevationNeedsTheAuditRecorder: without the interceptor's recorder
// nobody can audit the action when performed, so core refuses the elevation.
func TestWriteShareRPC_ElevationNeedsTheAuditRecorder(t *testing.T) {
	f := newGRPCWriteShareFixture(t, "write")
	err := grpcWriteShareMatrix["SecretGRPCService.UpdateSecret"].call(f, authCtx(2, "alice"))
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestWriteShareRPC_AuditOnPerformedActionOnly(t *testing.T) {
	f := newGRPCWriteShareFixture(t, "write")
	elevated := func() []models.AuditEvent {
		var rows []models.AuditEvent
		require.NoError(t, f.r.db.Where("event_type = ?", string(core.ShareAuditEventAccessElevated)).Find(&rows).Error)
		return rows
	}
	alice := authCtx(2, "alice")

	err := viaShareAudit(f.c, alice, func(ctx context.Context) error {
		return grpcWriteShareMatrix["SecretGRPCService.SetSecretAutoRotate"].call(f, ctx)
	})
	require.Error(t, err)
	assert.Empty(t, elevated(), "a refused RPC is not an elevation")

	// Authorized by the share at the gate, then refused by the size cap: not performed.
	f.c.SetMaxSecretSize(100)
	err = viaShareAudit(f.c, alice, func(ctx context.Context) error {
		big := strings.Repeat("a", 101)
		_, uerr := f.r.svc.UpdateSecret(ctx, &pb.UpdateSecretRequest{Id: f.secretID, Value: &big})
		return uerr
	})
	require.Error(t, err, "the oversized value must fail after the gate")
	assert.Equal(t, codes.ResourceExhausted, status.Code(err), "%v", err)
	assert.Empty(t, elevated(), "an RPC that failed after the gate performed nothing")

	require.NoError(t, viaShareAudit(f.c, alice, func(ctx context.Context) error {
		return grpcWriteShareMatrix["SecretGRPCService.UpdateSecret"].call(f, ctx)
	}))
	rows := elevated()
	require.Len(t, rows, 1)
	require.NotNil(t, rows[0].UserID)
	assert.Equal(t, uint(2), *rows[0].UserID)
	require.NotNil(t, rows[0].SecretNodeID)
	assert.Equal(t, uint(f.secretID), *rows[0].SecretNodeID)
	assert.Contains(t, rows[0].Description, string(core.SecretActionUpdate))
	assert.Contains(t, rows[0].Description, "share ")

	// The owner (role holder) updating writes no elevation row.
	require.NoError(t, viaShareAudit(f.c, authCtx(1, "owner"), func(ctx context.Context) error {
		v := "owner-update"
		_, uerr := f.r.svc.UpdateSecret(ctx, &pb.UpdateSecretRequest{Id: f.secretID, Value: &v})
		return uerr
	}))
	assert.Len(t, elevated(), 1, "the role allowed it: no share_access_elevated row")
}

// TestWriteShareRPCMatrix_CoversEverySecretsWriteRPC: any exported method on a
// *XxxGRPCService in this package whose body names secrets.write (permSecretsWrite or
// the literal) must have a matrix entry, so a new secrets.write RPC needs an explicit
// write-share decision.
func TestWriteShareRPCMatrix_CoversEverySecretsWriteRPC(t *testing.T) {
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	found := map[string]bool{}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		src, rerr := os.ReadFile(file) // #nosec G304 -- this package's own source files
		require.NoError(t, rerr)
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, file, src, 0)
		require.NoError(t, perr)
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || fd.Body == nil || !fd.Name.IsExported() {
				continue
			}
			star, ok := fd.Recv.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			recv, ok := star.X.(*ast.Ident)
			if !ok || !strings.HasSuffix(recv.Name, "GRPCService") {
				continue
			}
			namesWrite := false
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.Ident:
					namesWrite = namesWrite || x.Name == "permSecretsWrite"
				case *ast.BasicLit:
					namesWrite = namesWrite || x.Value == `"secrets.write"`
				}
				return !namesWrite
			})
			if namesWrite {
				found[recv.Name+"."+fd.Name.Name] = true
			}
		}
	}
	require.Greater(t, len(found), 8, "calibration: the scan must find the secrets.write RPC family")
	for name := range found {
		_, ok := grpcWriteShareMatrix[name]
		assert.True(t, ok, "%s names secrets.write but has no grpcWriteShareMatrix entry: decide whether a write share "+
			"elevates it (core.secretActionShareElevates) and add it", name)
	}
	for name := range grpcWriteShareMatrix {
		assert.True(t, found[name], "stale grpcWriteShareMatrix entry %q", name)
	}
}
