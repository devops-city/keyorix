package grpc_test

// pat_restriction_read_family_test.go — PAT-GUARD-1, the gRPC half of
// server/http/pat_restriction_read_family_test.go: every read RPC honours the
// caller's PAT restriction (ADR-042), including reads whose visibility is decided
// outside Authorize/AuthorizeSecret.
//
// Same oracle as the HTTP sweep. A canary project holds data whose every name
// carries patGuardCanary; the PAT owner is project_admin there and in a decoy
// project, owns a canary secret, shares it, and has one shared with them. Every
// registered unary READ RPC (derived from the live server via
// discoverUnaryMethods, not listed) is called with every *_id / id field bound to
// each canary object's id in turn, as the owner's restricted PATs. An OK response
// whose wire bytes contain the canary is a violation. The owner's unrestricted PAT
// is the positive control: it must see the canary through at least
// grpcPATGuardMinControlHits methods, including ListSecrets, GetSecret and
// ListSharedSecrets. There are two owners, as in the HTTP sweep: a project-only
// user and the global admin, whose restricted tokens must be narrowed below the
// admin bypass.
//
// Read vs write is decided by the method's leading verb. Write RPCs are not called
// (a restricted token reaching one would mutate the fixture mid-sweep) — they are
// gated by Authorize at their target scope, and their authorization is the
// protoreflect fuzzer's AUTHZ oracle's job. A method whose verb is in neither list
// FAILS the test, so a new verb ("Describe", "Peek") cannot silently drop a read RPC
// out of the sweep.
//
// What it does NOT cover: streaming RPCs (StreamAuditLogs — gated on global
// audit.read, which every restricted persona here is denied); request fields other
// than ids; data the fixture does not create.

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	keyorixgrpc "github.com/keyorixhq/keyorix/server/grpc"
)

const patGuardCanary = "pgcanary"

// grpcPATGuardMinControlHits: measured 8 when this was written. Below that so route
// churn does not trip it, above zero so a broken fixture does.
const grpcPATGuardMinControlHits = 6

// grpcReadVerbs / grpcWriteVerbs classify every unary RPC by its leading verb.
var (
	grpcReadVerbs  = []string{"List", "Get", "Search", "Count", "Export", "Check", "Validate", "Verify", "Read", "Health"}
	grpcWriteVerbs = []string{
		"Create", "Update", "Delete", "Remove", "Add", "Assign", "Grant", "Revoke", "Issue", "Renew",
		"Activate", "Restore", "Transition", "Classify", "Share", "Set", "Write", "Rotate", "Reissue",
	}
)

// grpcPATRestrictionReadExempt maps "service/method" to the reason a restricted
// PAT may legitimately see canary data through it. Empty: the sweep found none.
var grpcPATRestrictionReadExempt = map[string]string{}

func hasVerb(method string, verbs []string) bool {
	for _, v := range verbs {
		if strings.HasPrefix(method, v) {
			return true
		}
	}
	return false
}

type grpcPATGuardWorld struct {
	conn      *grpc.ClientConn
	srv       *grpc.Server
	canaryPID uint64
	canaryEID uint64
	ids       []uint64
	tokens    map[string]string
	core      *core.KeyorixCore
}

func newGRPCPATGuardWorld(t *testing.T) *grpcPATGuardWorld {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	gormDB := sqlitetest.Open(t, "kxpatguard_")
	require.NoError(t, gormDB.AutoMigrate(models.AllTestModels()...))
	c := core.NewKeyorixCore(store.NewLocalStorage(gormDB))
	ctx := context.Background()
	c.SetBootstrapToken("test-bootstrap-token")
	_, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "testadmin", Email: "testadmin@example.com", Password: "TestPassword123!", Token: "test-bootstrap-token",
	})
	require.NoError(t, err)

	canary, err := c.CreateProject(ctx, patGuardCanary+"-proj", patGuardCanary+" project")
	require.NoError(t, err)
	canaryEnv, err := c.CreateEnvironment(ctx, canary.ID, patGuardCanary+"-env")
	require.NoError(t, err)
	decoy, err := c.CreateProject(ctx, "decoyproj", "decoy project")
	require.NoError(t, err)
	decoyEnv, err := c.CreateEnvironment(ctx, decoy.ID, "decoyenv")
	require.NoError(t, err)
	mkUser := func(name string) uint {
		u, uerr := c.CreateUser(ctx, &core.CreateUserRequest{Username: name, Email: name + "@example.com", Password: "Qr7#Kp2$Lm5@Vn9!"})
		require.NoError(t, uerr)
		return u.ID
	}
	owner, peer := mkUser("pgowner"), mkUser("pgpeer")
	const adminID = 1 // BootstrapSystem's admin
	for _, u := range []uint{owner, peer, adminID} {
		require.NoError(t, c.AddProjectMember(ctx, adminID, canary.ID, u, "project_admin", false))
		require.NoError(t, c.AddProjectMember(ctx, adminID, decoy.ID, u, "project_admin", false))
	}

	ids := []uint64{uint64(canary.ID), uint64(canaryEnv.ID), uint64(owner), uint64(peer), adminID}
	tokens := map[string]string{}
	// Two PAT owners, as in the HTTP sweep: a project-only owner and the global
	// admin (whose restricted tokens must be narrowed below the admin bypass).
	for _, o := range []struct {
		prefix, username string
		id               uint
	}{{"", "pgowner", owner}, {"admin_", "testadmin", adminID}} {
		owned, serr := c.CreateSecret(ctx, &core.CreateSecretRequest{
			Name: patGuardCanary + "-" + o.username + "-secret", Value: []byte("v"), ProjectID: canary.ID,
			EnvironmentID: canaryEnv.ID, Type: "password", CreatedBy: o.username, OwnerID: o.id,
		})
		require.NoError(t, serr)
		sharedTo, serr := c.CreateSecret(ctx, &core.CreateSecretRequest{
			Name: patGuardCanary + "-to-" + o.username, Value: []byte("v"), ProjectID: canary.ID,
			EnvironmentID: canaryEnv.ID, Type: "password", CreatedBy: "pgpeer", OwnerID: peer,
		})
		require.NoError(t, serr)
		share, serr := c.ShareSecret(ctx, &core.ShareSecretRequest{SecretID: owned.ID, RecipientID: peer, Permission: "read", SharedBy: o.id})
		require.NoError(t, serr)
		_, serr = c.ShareSecret(ctx, &core.ShareSecretRequest{SecretID: sharedTo.ID, RecipientID: o.id, Permission: "read", SharedBy: peer})
		require.NoError(t, serr)
		ids = append(ids, uint64(owned.ID), uint64(sharedTo.ID), uint64(share.ID))

		mint := func(name string, scopes []string, pid, eid uint) {
			res, merr := c.CreateOwnPAT(ctx, o.id, name, nil, scopes, pid, eid, nil)
			require.NoError(t, merr)
			tokens[o.prefix+name] = res.PlainToken
		}
		mint("pat_unrestricted", nil, 0, 0)
		mint("pat_decoy_project", nil, decoy.ID, 0)
		mint("pat_decoy_env", nil, decoy.ID, decoyEnv.ID)
		mint("pat_users_read_only", []string{"users.read"}, 0, 0)
		mint("pat_secrets_read_decoy", []string{"secrets.read"}, decoy.ID, 0)
		mint("pat_system_read_only", []string{"system.read"}, 0, 0)
	}

	srv, err := keyorixgrpc.NewServer(&config.Config{}, c)
	require.NoError(t, err)
	lis := bufconn.Listen(1 << 20)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return &grpcPATGuardWorld{
		conn: conn, srv: srv, canaryPID: uint64(canary.ID), canaryEID: uint64(canaryEnv.ID),
		ids: ids, tokens: tokens, core: c,
	}
}

// requestWithIDs builds an input message with every top-level id / *_id scalar
// field set to id — except, when pinScope is set, project_id and environment_id,
// which are pinned to the canary scope so an RPC that needs a coherent
// (project, environment, object) triple can be reached. id == 0 with pinScope
// sets only the scope (a list RPC whose other id fields, e.g. parent_id, narrow).
func (w *grpcPATGuardWorld) requestWithIDs(desc protoreflect.MessageDescriptor, id uint64, pinScope bool) *dynamicpb.Message {
	req := dynamicpb.NewMessage(desc)
	fs := desc.Fields()
	for i := 0; i < fs.Len(); i++ {
		fd := fs.Get(i)
		name := string(fd.Name())
		if fd.IsList() || fd.IsMap() || (name != "id" && !strings.HasSuffix(name, "_id")) {
			continue
		}
		v := id
		if pinScope && name == "project_id" {
			v = w.canaryPID
		}
		if pinScope && name == "environment_id" {
			v = w.canaryEID
		}
		if v == 0 {
			continue
		}
		switch fd.Kind() {
		case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
			req.Set(fd, protoreflect.ValueOfUint64(v))
		case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
			req.Set(fd, protoreflect.ValueOfUint32(uint32(v))) //nolint:gosec // fixture ids are tiny
		case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
			req.Set(fd, protoreflect.ValueOfInt64(int64(v))) //nolint:gosec // fixture ids are tiny
		case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
			req.Set(fd, protoreflect.ValueOfInt32(int32(v))) //nolint:gosec // fixture ids are tiny
		}
	}
	return req
}

func (w *grpcPATGuardWorld) leaks(t *testing.T, m grpcMethod, token string, req *dynamicpb.Message) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(
		metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token)), 10*time.Second)
	defer cancel()
	resp := dynamicpb.NewMessage(m.output)
	if err := w.conn.Invoke(ctx, m.fullMethod(), req, resp); err != nil {
		return false
	}
	b, err := proto.Marshal(resp)
	require.NoError(t, err)
	return bytes.Contains(b, []byte(patGuardCanary))
}

// TestEveryGRPCReadHonoursPATRestriction is the gRPC family-wide guard.
func TestEveryGRPCReadHonoursPATRestriction(t *testing.T) {
	w := newGRPCPATGuardWorld(t)
	methods := discoverUnaryMethods(w.srv)
	require.Greater(t, len(methods), 50, "sanity: the server should register the whole unary surface")

	var restricted []string
	for _, owner := range []string{"", "admin_"} {
		for _, p := range []string{"pat_decoy_project", "pat_decoy_env", "pat_users_read_only", "pat_secrets_read_decoy", "pat_system_read_only"} {
			restricted = append(restricted, owner+p)
		}
	}
	controlHits := map[string]bool{}
	reported := map[string]bool{}
	reads := 0
	for _, m := range methods {
		isRead, isWrite := hasVerb(m.methodName, grpcReadVerbs), hasVerb(m.methodName, grpcWriteVerbs)
		if isRead == isWrite {
			t.Errorf("%s: cannot classify as read or write by its verb — add the verb to grpcReadVerbs or grpcWriteVerbs", m.key())
			continue
		}
		if isWrite {
			continue
		}
		reads++
		_, exempt := grpcPATRestrictionReadExempt[m.key()]
		reqs := []*dynamicpb.Message{dynamicpb.NewMessage(m.input), w.requestWithIDs(m.input, 0, true)}
		for _, id := range w.ids {
			reqs = append(reqs, w.requestWithIDs(m.input, id, false), w.requestWithIDs(m.input, id, true))
		}
		for _, req := range reqs {
			for _, ctrl := range []string{"pat_unrestricted", "admin_pat_unrestricted"} {
				if w.leaks(t, m, w.tokens[ctrl], req) {
					controlHits[m.key()] = true
				}
			}
			if exempt {
				continue
			}
			for _, persona := range restricted {
				if reported[m.key()+persona] {
					continue
				}
				if w.leaks(t, m, w.tokens[persona], req) {
					reported[m.key()+persona] = true
					t.Errorf("%s disclosed canary-project data to %s (request %v): its visibility is decided outside "+
						"Authorize/AuthorizeSecret — apply the PAT restriction to its rows, or add a reasoned entry to "+
						"grpcPATRestrictionReadExempt", m.key(), persona, req)
				}
			}
		}
	}
	assert.Greater(t, reads, 25, "sanity: many read RPCs")
	assert.GreaterOrEqual(t, len(controlHits), grpcPATGuardMinControlHits,
		"the unrestricted owner saw canary data through too few RPCs: the fixture is not exercising the surface")
	// ListUserShares is not one: a ShareRecord carries ids, never a name, so it
	// cannot show the canary to anyone.
	for _, mustSee := range []string{
		"keyorix.v1.SecretService/ListSecrets", "keyorix.v1.SecretService/GetSecret", "keyorix.v1.ShareService/ListSharedSecrets",
	} {
		assert.True(t, controlHits[mustSee], "positive control: the unrestricted owner must see canary data via %s", mustSee)
	}
	for key, reason := range grpcPATRestrictionReadExempt {
		assert.NotEmpty(t, strings.TrimSpace(reason), "grpcPATRestrictionReadExempt entry %q needs a reason", key)
	}
}
