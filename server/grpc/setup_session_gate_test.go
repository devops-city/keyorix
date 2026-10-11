package grpc_test

// setup_session_gate_test.go — #3041 review, finding 2: the gRPC auth
// interceptor never looked at models.Session.SetupOnly (#3024). A setup-only
// session whose revocation had not landed (or failed: EndSetupSessionIfComplete
// used to discard the error) owed nothing any more and passed every gRPC gate
// with full access, while HTTP refused it with ReauthenticationRequired.
//
// TestEveryGRPCMethod_RefusesSetupOnlySession is the gRPC counterpart of the
// HTTP route-registry guard (server/http TestAccountSetupGate_EveryOtherRouteDenied).
// The method set is read from the real server NewServer builds
// (grpc.Server.GetServiceInfo), the same enumeration INV-GRPC-07's
// auth_interceptor_completeness_test.go uses, so a new service or RPC is
// covered without editing this file. Every RPC is invoked with a setup-only
// session and must be refused by the interceptor's setup gate (its own status
// message, not a service-level error), both while setup steps are owed and
// after they are done. The RPCs a setup step may reach over gRPC are pinned in
// expectedSetupGRPCMethods (empty: gRPC has no password-change, enrolment or
// profile RPC); opening one needs a deliberate edit there and in the
// interceptor. What this does NOT cover: an ordinary session owing one step
// (enforceGRPCAccessPolicy, interceptors_s22_test.go) and the per-step HTTP
// allowlist (server/http).

import (
	"context"
	"errors"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	keyorixgrpc "github.com/keyorixhq/keyorix/server/grpc"
	"gorm.io/gorm"
)

// expectedSetupGRPCMethods are the RPCs a setup-only session may reach. Empty:
// the setup steps (change password, enrol a second factor) and the profile
// read exist only on REST. Adding one is a security decision.
var expectedSetupGRPCMethods = map[string]bool{}

// The interceptor's setup-gate status messages (server/grpc/interceptors
// grpcSetupOnlyMsg / grpcSetupCompleteMsg), pinned here so a refusal from any
// other layer does not satisfy the guard.
const (
	setupOnlyRefusedMsg = "a setup-only session can only change the password and enrol a second factor, which are not available over gRPC: finish account setup over the REST API or the CLI"
	setupCompleteMsg    = "account setup is complete: sign in again with your new password and second factor"
)

const setupGateGRPCOTP = "Temp#Otp-Passw0rd-91"

// faultySessionReads fails every GetSession after the first while armed: the
// store goes away right after token validation.
type faultySessionReads struct {
	storage.Storage
	mu    sync.Mutex
	armed bool
	reads int
}

func (f *faultySessionReads) GetSession(ctx context.Context, token string) (*models.Session, error) {
	f.mu.Lock()
	f.reads++
	fail := f.armed && f.reads > 1
	f.mu.Unlock()
	if fail {
		return nil, errors.New("injected: session read failed")
	}
	return f.Storage.GetSession(ctx, token)
}

func (f *faultySessionReads) arm(on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.armed, f.reads = on, 0
}

type setupGRPCEnv struct {
	core  *core.KeyorixCore
	conn  *grpc.ClientConn
	srv   *grpc.Server
	fault *faultySessionReads
}

// newSetupGRPCEnv serves every service over bufconn with require_mfa on,
// backed by a fully-migrated core over a session-read fault wrapper, with the
// bootstrap admin "testadmin".
func newSetupGRPCEnv(t *testing.T) *setupGRPCEnv {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	db := sqlitetest.OpenWithConfig(t, "kxgrpc_setup_", &gorm.Config{})
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))
	require.NoError(t, db.AutoMigrate(&models.SecretAccessLog{}))
	f := &faultySessionReads{Storage: store.NewLocalStorage(db)}
	c := core.NewKeyorixCore(f)
	c.SetRequireMFA(true)
	c.SetBootstrapToken("test-bootstrap-token")
	_, err := c.BootstrapSystem(context.Background(), &core.BootstrapRequest{
		Username: "testadmin", Email: "testadmin@example.com",
		Password: "TestPassword123!", Token: "test-bootstrap-token",
	})
	require.NoError(t, err)

	cfg := &config.Config{}
	cfg.Security.RequireMFA = true
	srv, err := keyorixgrpc.NewServer(cfg, c)
	require.NoError(t, err)
	lis := bufconn.Listen(1024 * 1024)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return &setupGRPCEnv{core: c, conn: conn, srv: srv, fault: f}
}

// recoverAdmin leaves testadmin as `keyorix-server admin recover-admin` does
// (password_reset_required, a one-time password, no second factor, no
// sessions) and logs in with the one-time password: a setup-only session.
func (e *setupGRPCEnv) recoverAdmin(t *testing.T) (token string, userID uint) {
	t.Helper()
	ctx := context.Background()
	st := e.core.Storage()
	admin, err := st.GetUserByUsername(ctx, "testadmin")
	require.NoError(t, err)
	hash, err := bcrypt.GenerateFromPassword([]byte(setupGateGRPCOTP), bcrypt.MinCost)
	require.NoError(t, err)
	now := time.Now()
	require.NoError(t, st.SetAccountState(ctx, admin.ID, core.AccountPasswordResetRequired, now))
	require.NoError(t, st.SetPasswordHash(ctx, admin.ID, string(hash), now))
	require.NoError(t, st.SetUserMFAEnabled(ctx, admin.ID, false))
	require.NoError(t, st.DeleteSessionsForUserExcept(ctx, admin.ID, 0))
	sess, _, err := e.core.Login(ctx, &core.LoginRequest{Username: "testadmin", Password: setupGateGRPCOTP})
	require.NoError(t, err)
	stored, err := st.GetSession(ctx, sess.SessionToken)
	require.NoError(t, err)
	require.True(t, stored.SetupOnly, "precondition: a recovered admin under require_mfa gets a setup-only session")
	return sess.SessionToken, admin.ID
}

type grpcRPC struct {
	full   string
	stream bool
	client bool
}

func (e *setupGRPCEnv) rpcs(t *testing.T) []grpcRPC {
	t.Helper()
	var out []grpcRPC
	for svc, info := range e.srv.GetServiceInfo() {
		for _, m := range info.Methods {
			out = append(out, grpcRPC{full: "/" + svc + "/" + m.Name, stream: m.IsServerStream || m.IsClientStream, client: m.IsClientStream})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].full < out[j].full })
	require.GreaterOrEqual(t, len(out), 80, "enumeration found implausibly few RPCs")
	return out
}

func (e *setupGRPCEnv) call(r grpcRPC, token string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	if !r.stream {
		return e.conn.Invoke(ctx, r.full, &emptypb.Empty{}, &emptypb.Empty{})
	}
	st, err := e.conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true, ClientStreams: r.client}, r.full)
	if err != nil {
		return err
	}
	if err := st.SendMsg(&emptypb.Empty{}); err != nil {
		return st.RecvMsg(&emptypb.Empty{})
	}
	_ = st.CloseSend()
	return st.RecvMsg(&emptypb.Empty{})
}

// walk invokes every non-public RPC with token and asserts the setup gate's
// refusal (code, msg) on each one outside expectedSetupGRPCMethods.
func (e *setupGRPCEnv) walk(t *testing.T, token string, code codes.Code, msg string) {
	t.Helper()
	var refused int
	for _, r := range e.rpcs(t) {
		if expectedPublicGRPCMethods[r.full] {
			continue
		}
		st := status.Convert(e.call(r, token))
		if expectedSetupGRPCMethods[r.full] {
			assert.NotEqualf(t, msg, st.Message(), "%s is allowlisted for setup but the setup gate refused it", r.full)
			continue
		}
		if assert.Equalf(t, code, st.Code(), "%s (stream=%v): %s", r.full, r.stream, st.Message()) {
			assert.Equalf(t, msg, st.Message(), "%s must be refused by the interceptor's setup gate", r.full)
		}
		refused++
	}
	assert.Greater(t, refused, 80, "sanity: the walk must cover the gRPC surface")
}

func TestEveryGRPCMethod_RefusesSetupOnlySession(t *testing.T) {
	e := newSetupGRPCEnv(t)
	token, userID := e.recoverAdmin(t)

	t.Run("steps owed", func(t *testing.T) {
		e.walk(t, token, codes.PermissionDenied, setupOnlyRefusedMsg)
	})

	// Both steps done (a password set, a second factor enrolled) but the
	// setup-only session was not revoked: the state EndSetupSessionIfComplete's
	// failed or not-yet-landed revocation leaves behind.
	ctx := context.Background()
	require.NoError(t, e.core.Storage().SetAccountState(ctx, userID, core.AccountActive, time.Now()))
	require.NoError(t, e.core.Storage().SetUserMFAEnabled(ctx, userID, true))
	t.Run("steps done, session not revoked", func(t *testing.T) {
		e.walk(t, token, codes.Unauthenticated, setupCompleteMsg)
	})
	for m := range expectedSetupGRPCMethods {
		var registered bool
		for _, r := range e.rpcs(t) {
			registered = registered || r.full == m
		}
		assert.Truef(t, registered, "allowlisted setup RPC %s is not registered: drop it", m)
	}
}

// TestGRPCSessionFactsReadFailure_FailsClosed: the session read after token
// validation fails. The interceptor must refuse (Unavailable, the generic
// retry answer) rather than serve the RPC with the session's restrictions
// defaulted away, and the refusal is audited.
func TestGRPCSessionFactsReadFailure_FailsClosed(t *testing.T) {
	e := newSetupGRPCEnv(t)
	ctx := context.Background()
	sess, user, err := e.core.Login(ctx, &core.LoginRequest{Username: "testadmin", Password: "TestPassword123!"})
	require.NoError(t, err)
	require.NoError(t, e.core.Storage().SetUserMFAEnabled(ctx, user.ID, true)) // nothing owed: an ordinary session

	listSecrets := grpcRPC{full: "/keyorix.v1.SecretService/ListSecrets"}
	require.NoError(t, e.call(listSecrets, sess.SessionToken), "precondition: the session works")

	e.fault.arm(true)
	err = e.call(listSecrets, sess.SessionToken)
	e.fault.arm(false)
	st := status.Convert(err)
	assert.Equal(t, codes.Unavailable, st.Code(), st.Message())
	assert.Equal(t, "authentication temporarily unavailable, please retry", st.Message())

	action := core.EventSessionFactsUnavailable
	events, _, err := e.core.Storage().GetAuditLogs(ctx, &storage.AuditFilter{Action: &action})
	require.NoError(t, err)
	require.Len(t, events, 1, "the refusal must be audited")
	assert.Contains(t, events[0].Description, "grpc request")
	require.NoError(t, e.call(listSecrets, sess.SessionToken), "the recovered store serves the session again")
}
