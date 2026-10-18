package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	"github.com/keyorixhq/keyorix/server/grpc/services"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// TestAuthzParity_HTTPvsGRPC_ShareCreate pins the SAME authorization decision across
// HTTP and gRPC for creating a secret share — a two-layer gate: both surfaces require
// secrets.write at the secret's project (route/method) AND core enforces owner-only
// sharing. The standout case is a project-WRITER (secrets.write on the project) who
// does NOT own the secret: it must NOT be able to re-share it (an escalation/IDOR
// vector) — on either surface. A divergence here is exploitable.
func TestAuthzParity_HTTPvsGRPC_ShareCreate(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())

	db := sqlitetest.OpenWithConfig(t, "kxtest_", &gorm.Config{})
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.SecretVersion{},
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Session{}, &models.AuditEvent{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.SystemMetadata{},
	))
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	c.SetBootstrapToken("test-bootstrap-token")
	_, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "Qr7#Kp2$Lm5@Vn9!", Token: "test-bootstrap-token",
	})
	require.NoError(t, err)

	var editorRole models.Role // editor = secrets.read + secrets.write
	require.NoError(t, db.Where("name = ?", "editor").First(&editorRole).Error)

	login := func(username, password string) string {
		s, _, lerr := c.Login(ctx, &core.LoginRequest{Username: username, Password: password})
		require.NoError(t, lerr)
		return s.SessionToken
	}

	// owner — has secrets.write on p1 AND owns the secret (can share).
	owner, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: "owner", Email: "owner@example.com", Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.UserRole{UserID: owner.ID, RoleID: editorRole.ID, ProjectID: 1}).Error)
	ownerToken := login("owner", "Qr7#Kp2$Lm5@Vn9!")

	// writer — has secrets.write on p1 but does NOT own the secret (must not re-share).
	writer, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: "writer", Email: "writer@example.com", Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.UserRole{UserID: writer.ID, RoleID: editorRole.ID, ProjectID: 1}).Error)
	writerToken := login("writer", "Qr7#Kp2$Lm5@Vn9!")

	// Recipients just need to exist. Distinct ones for the allow case so the HTTP and
	// gRPC shares don't collide as duplicates. Each must be a project member (#1185
	// added an IsProjectMember gate in ShareSecret).
	require.NoError(t, db.Create(&models.User{ID: 500, Username: "rcpt-http", Email: "rh@example.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 501, Username: "rcpt-grpc", Email: "rg@example.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 502, Username: "rcpt-deny", Email: "rd@example.com"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 500, RoleID: editorRole.ID, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 501, RoleID: editorRole.ID, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 502, RoleID: editorRole.ID, ProjectID: 1}).Error)

	// The secret, owned by owner in project 1.
	sec, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "shared-sec", Value: []byte("v"), ProjectID: 1, EnvironmentID: 1,
		Type: "password", Classification: "internal", OwnerID: owner.ID, CreatedBy: "owner",
	})
	require.NoError(t, err)

	shareSvc := services.NewShareService(c)
	gctx := func(userID uint, name string) context.Context {
		return context.WithValue(ctx, interceptors.GetUserContextKey(),
			&interceptors.UserContext{UserID: userID, Username: name})
	}

	cfg := &config.Config{Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"}}}
	router, err := NewRouter(cfg, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := srv.Client()

	httpShare := func(token string, secretID, recipientID uint) bool {
		body, _ := json.Marshal(map[string]any{"recipient_id": recipientID, "is_group": false, "permission": "read"})
		r, _ := http.NewRequest("POST", srv.URL+fmt.Sprintf("/api/v1/secrets/%d/share", secretID), bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+token)
		resp, derr := client.Do(r)
		require.NoError(t, derr)
		_ = resp.Body.Close()
		return resp.StatusCode >= 200 && resp.StatusCode < 300
	}
	grpcShare := func(ctx context.Context, secretID, recipientID uint) bool {
		_, gerr := shareSvc.ShareSecret(ctx, &pb.ShareSecretRequest{
			SecretId: uint32(secretID), RecipientId: uint32(recipientID), Permission: "read", IsGroup: false,
		})
		return gerr == nil
	}

	cases := []struct {
		name        string
		httpAllowed bool
		grpcAllowed bool
		wantAllowed bool
	}{
		{
			name:        "owner shares its own secret (has secrets.write + ownership)",
			httpAllowed: httpShare(ownerToken, sec.ID, 500),
			grpcAllowed: grpcShare(gctx(owner.ID, "owner"), sec.ID, 501),
			wantAllowed: true,
		},
		{
			name:        "project-writer re-shares a secret it does NOT own",
			httpAllowed: httpShare(writerToken, sec.ID, 502),
			grpcAllowed: grpcShare(gctx(writer.ID, "writer"), sec.ID, 502),
			wantAllowed: false,
		},
	}

	for _, tc := range cases {
		require.Equal(t, tc.wantAllowed, tc.httpAllowed, "%s: HTTP decision", tc.name)
		require.Equal(t, tc.wantAllowed, tc.grpcAllowed, "%s: gRPC decision", tc.name)
		require.Equal(t, tc.httpAllowed, tc.grpcAllowed, "%s: HTTP and gRPC must agree", tc.name)
	}
}

// TestAuthzParity_HTTPvsGRPC_ShareList pins the SAME authorization decision across HTTP
// and gRPC for LISTING a secret's shares (GET /secrets/{id}/shares vs
// ShareService.ListSecretShares). The share graph (who has access, at what tier) is
// owner-only by the code's own documented design — a project-WRITER (secrets.write, and
// therefore also secrets.read, on the project) who does NOT own the secret must NOT be
// able to enumerate its shares on either surface, even though the route-level RBAC gate
// (secrets.read) alone would let it through. A divergence here is the #246 regression:
// HTTP called the raw, ownership-blind ListSecretShares while gRPC already required
// ownership via ListSecretSharesWithPermissionCheck.
func TestAuthzParity_HTTPvsGRPC_ShareList(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())

	db := sqlitetest.OpenWithConfig(t, "kxtest_", &gorm.Config{})
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.SecretVersion{},
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Session{}, &models.AuditEvent{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.SystemMetadata{},
	))
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	c.SetBootstrapToken("test-bootstrap-token")
	_, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "Qr7#Kp2$Lm5@Vn9!", Token: "test-bootstrap-token",
	})
	require.NoError(t, err)

	var editorRole models.Role // editor = secrets.read + secrets.write
	require.NoError(t, db.Where("name = ?", "editor").First(&editorRole).Error)

	login := func(username, password string) string {
		s, _, lerr := c.Login(ctx, &core.LoginRequest{Username: username, Password: password})
		require.NoError(t, lerr)
		return s.SessionToken
	}

	// owner — has secrets.write/read on p1 AND owns the secret (can list its shares).
	owner, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: "owner2", Email: "owner2@example.com", Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.UserRole{UserID: owner.ID, RoleID: editorRole.ID, ProjectID: 1}).Error)
	ownerToken := login("owner2", "Qr7#Kp2$Lm5@Vn9!")

	// writer — has secrets.write/read on p1 but does NOT own the secret (must not
	// enumerate its shares — the #246 exploit shape).
	writer, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: "writer2", Email: "writer2@example.com", Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.UserRole{UserID: writer.ID, RoleID: editorRole.ID, ProjectID: 1}).Error)
	writerToken := login("writer2", "Qr7#Kp2$Lm5@Vn9!")

	recipient, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: "recipient2", Email: "recipient2@example.com", Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)
	// IsProjectMember gate (#1185): recipient must be a project member to receive a share.
	require.NoError(t, db.Create(&models.UserRole{UserID: recipient.ID, RoleID: editorRole.ID, ProjectID: 1}).Error)

	// The secret, owned by owner in project 1, shared once with recipient so the list
	// isn't trivially empty.
	sec, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "shared-sec-list", Value: []byte("v"), ProjectID: 1, EnvironmentID: 1,
		Type: "password", Classification: "internal", OwnerID: owner.ID, CreatedBy: "owner2",
	})
	require.NoError(t, err)
	_, err = c.ShareSecret(ctx, &core.ShareSecretRequest{
		SecretID: sec.ID, RecipientID: recipient.ID, IsGroup: false, Permission: "read", SharedBy: owner.ID,
	})
	require.NoError(t, err)

	shareSvc := services.NewShareService(c)
	gctx := func(userID uint, name string) context.Context {
		return context.WithValue(ctx, interceptors.GetUserContextKey(),
			&interceptors.UserContext{UserID: userID, Username: name})
	}

	cfg := &config.Config{Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"}}}
	router, err := NewRouter(cfg, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := srv.Client()

	httpListAllowed := func(token string, secretID uint) bool {
		r, _ := http.NewRequest("GET", srv.URL+fmt.Sprintf("/api/v1/secrets/%d/shares", secretID), nil)
		r.Header.Set("Authorization", "Bearer "+token)
		resp, derr := client.Do(r)
		require.NoError(t, derr)
		_ = resp.Body.Close()
		return resp.StatusCode >= 200 && resp.StatusCode < 300
	}
	grpcListAllowed := func(ctx context.Context, secretID uint) bool {
		_, gerr := shareSvc.ListSecretShares(ctx, &pb.ListSecretSharesRequest{SecretId: uint32(secretID)})
		return gerr == nil
	}

	cases := []struct {
		name        string
		httpAllowed bool
		grpcAllowed bool
		wantAllowed bool
	}{
		{
			name:        "owner lists shares on its own secret (has secrets.read + ownership)",
			httpAllowed: httpListAllowed(ownerToken, sec.ID),
			grpcAllowed: grpcListAllowed(gctx(owner.ID, "owner2"), sec.ID),
			wantAllowed: true,
		},
		{
			name:        "project-writer lists shares on a secret it does NOT own",
			httpAllowed: httpListAllowed(writerToken, sec.ID),
			grpcAllowed: grpcListAllowed(gctx(writer.ID, "writer2"), sec.ID),
			wantAllowed: false,
		},
	}

	for _, tc := range cases {
		require.Equal(t, tc.wantAllowed, tc.httpAllowed, "%s: HTTP decision", tc.name)
		require.Equal(t, tc.wantAllowed, tc.grpcAllowed, "%s: gRPC decision", tc.name)
		require.Equal(t, tc.httpAllowed, tc.grpcAllowed, "%s: HTTP and gRPC must agree", tc.name)
	}
}
