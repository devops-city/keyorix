package grpc_test

// authz_walk_fixture_test.go — shared machinery for the gRPC authorization
// walks (AUTHZ-WALKS-GRPC-1): authz_walk_lowpriv_test.go (item 1),
// authz_walk_dead_credential_test.go (item 2) and
// authz_walk_rest_parity_test.go (item 3).
//
// The method set is never listed here: walkMethods reads it from the live
// *grpc.Server (GetServiceInfo) and resolves each descriptor from the global
// registry, streaming RPCs included (discoverUnaryMethods skips them), and
// fails if any registered method cannot be resolved so a descriptor lookup miss
// cannot silently shrink the walk.
//
// The world runs on SQLite and, when KEYORIX_TEST_PG_DSN is set, on Postgres
// (fuzzworld.Worlds). State change is detected with a backend-neutral content
// digest (digestDB) rather than the SQLite-only write-count triggers the
// protoreflect fuzzer installs.
//
// What the fixture does NOT do: it does not fuzz values (the protoreflect fuzzer
// does); it fills every non-id field with a fixed plausible value so a request
// gets PAST field validation and reaches the authorization decision.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	keyorixgrpc "github.com/keyorixhq/keyorix/server/grpc"
	grpcservices "github.com/keyorixhq/keyorix/server/grpc/services"
)

// walkCanary is the substring every canary object's name (and the canary
// secret's plaintext) carries. No request the walks send contains it, so
// seeing it in a response means the response disclosed canary data.
const walkCanary = "kxwalkcanary"

const walkPassword = "Qr7#Kp2$Lm5@Vn9!"

// walkMethod is one registered RPC, unary or streaming.
type walkMethod struct {
	service      string // "keyorix.v1.SecretService"
	name         string // "GetSecret"
	input        protoreflect.MessageDescriptor
	output       protoreflect.MessageDescriptor
	clientStream bool
	serverStream bool
}

func (m walkMethod) full() string   { return "/" + m.service + "/" + m.name }
func (m walkMethod) key() string    { return m.service + "/" + m.name }
func (m walkMethod) stream() bool   { return m.clientStream || m.serverStream }
func (m walkMethod) String() string { return m.key() }

// walkMethods enumerates every RPC the server registers.
func walkMethods(t testing.TB, srv *grpc.Server) []walkMethod {
	t.Helper()
	var out []walkMethod
	registered := 0
	for svcName, info := range srv.GetServiceInfo() {
		d, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(svcName))
		require.NoErrorf(t, err, "service %s is registered but has no descriptor in the global registry", svcName)
		sd, ok := d.(protoreflect.ServiceDescriptor)
		require.Truef(t, ok, "%s is not a service descriptor", svcName)
		for _, mi := range info.Methods {
			registered++
			md := sd.Methods().ByName(protoreflect.Name(mi.Name))
			require.NotNilf(t, md, "%s/%s is registered but missing from its service descriptor", svcName, mi.Name)
			out = append(out, walkMethod{
				service: svcName, name: mi.Name, input: md.Input(), output: md.Output(),
				clientStream: md.IsStreamingClient(), serverStream: md.IsStreamingServer(),
			})
		}
	}
	require.Len(t, out, registered)
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}

// walkReadVerbs / walkWriteVerbs classify a method by its leading verb. The
// unary lists are shared with the PAT read-family sweep; "Stream" covers the
// one streaming RPC. A method in neither list fails the walk: a new verb must
// be classified deliberately.
var (
	walkReadVerbs  = append(append([]string{}, grpcReadVerbs...), "Stream")
	walkWriteVerbs = grpcWriteVerbs
)

func (m walkMethod) isRead() bool  { return hasVerb(m.name, walkReadVerbs) }
func (m walkMethod) isWrite() bool { return hasVerb(m.name, walkWriteVerbs) }

// --- fake peer addresses ---------------------------------------------------
//
// interceptors.grpcIPFailureLimiter is process-global, keyed by peer IP, and
// allows only 10 invalid-token attempts per IP. Every bufconn peer is the same
// "bufconn" key, so a walk that sends hundreds of bad credentials would be
// answered ResourceExhausted instead of Unauthenticated. Each connection the
// walks open is therefore accepted with its own distinct fake RemoteAddr.

type peerAddrConn struct {
	net.Conn
	addr net.Addr
}

func (c peerAddrConn) RemoteAddr() net.Addr { return c.addr }

type uniquePeerListener struct {
	net.Listener
	seq *atomic.Uint32
}

func (l uniquePeerListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	n := l.seq.Add(1)
	// 10.0.0.0/8, derived from a process-wide counter shared by every world.
	ip := net.IPv4(10, byte(n>>16), byte(n>>8), byte(n))
	return peerAddrConn{Conn: c, addr: &net.TCPAddr{IP: ip, Port: 40000}}, nil
}

var walkPeerSeq atomic.Uint32

// --- the world -------------------------------------------------------------

type walkIDs struct {
	canaryProject, canaryEnv, canarySecret, canaryVictim uint
	canaryMachine, canaryGroup, canaryShare              uint
	decoyProject, decoyEnv                               uint
	builtinRole                                          uint
}

type walkWorld struct {
	backend string
	db      *gorm.DB
	sqlDB   *sql.DB
	core    *core.KeyorixCore
	srv     *grpc.Server
	lis     *bufconn.Listener
	methods []walkMethod
	ids     walkIDs
	adminID uint
	admin   string   // admin session token (positive control)
	tables  []string // tables the digest covers (cached on first use)
}

// forEachWalkBackend runs fn once per available backend: SQLite always,
// Postgres when KEYORIX_TEST_PG_DSN is set.
func forEachWalkBackend(t *testing.T, fn func(t *testing.T, w *walkWorld)) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	for _, fw := range fuzzworld.Worlds(t, "kxgrpcwalk", sqlitetest.DSN("kxgrpcwalk_"), 1) {
		t.Run(fw.Backend, func(t *testing.T) {
			fn(t, buildWalkWorld(t, fw))
		})
	}
}

func buildWalkWorld(t *testing.T, fw *fuzzworld.World) *walkWorld {
	t.Helper()
	require.NoError(t, fw.DB.AutoMigrate(models.AllTestModels()...))
	sqlDB, err := fw.DB.DB()
	require.NoError(t, err)

	c := core.NewKeyorixCore(store.NewLocalStorage(fw.DB))
	ctx := context.Background()
	c.SetBootstrapToken("test-bootstrap-token")
	_, err = c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "testadmin", Email: "testadmin@example.com", Password: "TestPassword123!", Token: "test-bootstrap-token",
	})
	require.NoError(t, err)
	adminSess, _, err := c.Login(ctx, &core.LoginRequest{Username: "testadmin", Password: "TestPassword123!"})
	require.NoError(t, err)
	const adminID = 1 // BootstrapSystem's admin

	var ids walkIDs
	canary, err := c.CreateProject(ctx, walkCanary+"-proj", walkCanary+" project")
	require.NoError(t, err)
	canaryEnv, err := c.CreateEnvironment(ctx, canary.ID, walkCanary+"-env")
	require.NoError(t, err)
	decoy, err := c.CreateProject(ctx, "walkdecoy", "decoy project")
	require.NoError(t, err)
	decoyEnv, err := c.CreateEnvironment(ctx, decoy.ID, "walkdecoyenv")
	require.NoError(t, err)
	ids.canaryProject, ids.canaryEnv, ids.decoyProject, ids.decoyEnv = canary.ID, canaryEnv.ID, decoy.ID, decoyEnv.ID
	for _, pid := range []uint{canary.ID, decoy.ID} {
		require.NoError(t, c.AddProjectMember(ctx, adminID, pid, adminID, "project_admin", false))
	}

	victim, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: walkCanary + "-victim", Email: walkCanary + "-victim@example.com", Password: walkPassword})
	require.NoError(t, err)
	ids.canaryVictim = victim.ID
	require.NoError(t, c.AddProjectMember(ctx, adminID, canary.ID, victim.ID, "project_admin", false))

	secret, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: walkCanary + "-secret", Value: []byte(walkCanary + "-plaintext"), ProjectID: canary.ID,
		EnvironmentID: canaryEnv.ID, Type: "password", CreatedBy: "testadmin", OwnerID: adminID,
	})
	require.NoError(t, err)
	ids.canarySecret = secret.ID
	share, err := c.ShareSecret(ctx, &core.ShareSecretRequest{SecretID: secret.ID, RecipientID: victim.ID, Permission: "read", SharedBy: adminID})
	require.NoError(t, err)
	ids.canaryShare = share.ID

	mi, err := c.CreateMachineIdentity(ctx, canary.ID, walkCanary+"-machine", "ci", "", "", adminID, 0)
	require.NoError(t, err)
	ids.canaryMachine = mi.ID
	grp, err := c.CreateGroup(ctx, adminID, &core.CreateGroupRequest{Name: walkCanary + "-group", Description: walkCanary})
	require.NoError(t, err)
	ids.canaryGroup = grp.ID

	role, err := store.NewLocalStorage(fw.DB).GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)
	require.NotNil(t, role)
	ids.builtinRole = role.ID

	srv, err := keyorixgrpc.NewServer(&config.Config{}, c)
	require.NoError(t, err)
	lis := bufconn.Listen(1 << 20)
	go func() { _ = srv.Serve(uniquePeerListener{Listener: lis, seq: &walkPeerSeq}) }()
	t.Cleanup(func() {
		srv.Stop()
		core.DrainBackgroundGoroutines()
		grpcservices.DrainBackgroundGoroutines()
	})

	w := &walkWorld{
		backend: fw.Backend, db: fw.DB, sqlDB: sqlDB, core: c, srv: srv, lis: lis,
		methods: walkMethods(t, srv), ids: ids, adminID: adminID, admin: adminSess.SessionToken,
	}
	require.GreaterOrEqual(t, len(w.methods), 80, "enumeration found implausibly few RPCs")
	return w
}

// dial opens a fresh connection (hence a fresh fake peer IP, see above).
func (w *walkWorld) dial(t testing.TB) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return w.lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	return conn
}

// --- request builder -------------------------------------------------------

// requestFor builds m's input message: every string/number/bool field gets a
// fixed plausible non-canary value (so validation passes and the call reaches
// its authorization decision), nested messages and one-element repeateds are
// filled recursively, and every id-shaped field is bound by bind(msgName,
// fieldName). A nil bind result of 0 leaves the field unset.
func requestFor(desc protoreflect.MessageDescriptor, bind func(msg, field string) uint64) *dynamicpb.Message {
	return fillMessage(desc, bind, 0)
}

const walkMaxDepth = 3

func fillMessage(desc protoreflect.MessageDescriptor, bind func(msg, field string) uint64, depth int) *dynamicpb.Message {
	msg := dynamicpb.NewMessage(desc)
	if depth >= walkMaxDepth {
		return msg
	}
	fields := desc.Fields()
	seenOneof := map[protoreflect.Name]bool{}
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if oo := fd.ContainingOneof(); oo != nil && !oo.IsSynthetic() {
			if seenOneof[oo.Name()] {
				continue
			}
			seenOneof[oo.Name()] = true
		}
		name := string(fd.Name())
		switch {
		case fd.IsMap():
			continue
		case fd.IsList():
			lst := msg.Mutable(fd).List()
			lst.Append(walkValue(fd, desc, name, bind, depth+1))
		case fd.HasOptionalKeyword() && fd.Kind() == protoreflect.StringKind:
			// proto3 "optional string" fields are list filters (search, type, ...):
			// filling one would narrow a list to nothing and hide what the walk
			// is looking for.
			continue
		default:
			if v := walkValue(fd, desc, name, bind, depth); v.IsValid() {
				msg.Set(fd, v)
			}
		}
	}
	return msg
}

func isIDField(name string) bool { return name == "id" || strings.HasSuffix(name, "_id") }

func walkValue(fd protoreflect.FieldDescriptor, owner protoreflect.MessageDescriptor, name string, bind func(msg, field string) uint64, depth int) protoreflect.Value {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return protoreflect.ValueOfBool(false)
	case protoreflect.EnumKind:
		vals := fd.Enum().Values()
		if vals.Len() > 1 {
			return protoreflect.ValueOfEnum(vals.Get(1).Number())
		}
		return protoreflect.ValueOfEnum(0)
	case protoreflect.StringKind:
		switch name {
		case "email":
			return protoreflect.ValueOfString("walk-probe@example.com")
		case "password":
			return protoreflect.ValueOfString(walkPassword)
		case "permission":
			return protoreflect.ValueOfString("read")
		}
		return protoreflect.ValueOfString("walk-" + strings.ReplaceAll(name, "_", "-"))
	case protoreflect.BytesKind:
		return protoreflect.ValueOfBytes([]byte("walk-bytes"))
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return protoreflect.ValueOfMessage(fillMessage(fd.Message(), bind, depth))
	}
	var v uint64
	if isIDField(name) {
		v = bind(string(owner.Name()), name)
		if v == 0 && fd.HasOptionalKeyword() {
			return protoreflect.Value{} // leave an optional id unbound rather than "set to 0"
		}
	}
	switch fd.Kind() {
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return protoreflect.ValueOfUint64(v)
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return protoreflect.ValueOfUint32(uint32(v)) //nolint:gosec // fixture ids are tiny
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return protoreflect.ValueOfInt64(int64(v)) //nolint:gosec // fixture ids are tiny
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return protoreflect.ValueOfInt32(int32(v)) //nolint:gosec // fixture ids are tiny
	}
	return fd.Default()
}

// walkVariant is one way of binding the id fields of a request.
type walkVariant struct {
	label string
	bind  func(msg, field string) uint64
}

// variants returns the request bindings the walks try for every method: one
// "semantic" binding (each id field gets the canary object its name or its
// request type names) plus one uniform binding per canary object (every id
// field of the request, scope fields aside, is that object's id — the shape
// the PAT read-family sweep uses to reach RPCs whose id field is generic).
func (ids walkIDs) variants() []walkVariant {
	semantic := func(msg, field string) uint64 {
		switch field {
		case "project_id":
			return uint64(ids.canaryProject)
		case "environment_id":
			return uint64(ids.canaryEnv)
		case "secret_id", "secret_node_id":
			return uint64(ids.canarySecret)
		case "user_id", "recipient_id", "owner_id", "target_user_id":
			return uint64(ids.canaryVictim)
		case "machine_id", "machine_identity_id":
			return uint64(ids.canaryMachine)
		case "group_id":
			return uint64(ids.canaryGroup)
		case "share_id":
			return uint64(ids.canaryShare)
		case "parent_id":
			return 0 // a folder node id: setting it would narrow a list to that folder's children
		case "role_id":
			return uint64(ids.builtinRole)
		case "id":
			switch {
			case strings.Contains(msg, "Secret") && !strings.Contains(msg, "Share"):
				return uint64(ids.canarySecret)
			case strings.Contains(msg, "Share"):
				return uint64(ids.canaryShare)
			case strings.Contains(msg, "User"):
				return uint64(ids.canaryVictim)
			case strings.Contains(msg, "Role"):
				return uint64(ids.builtinRole)
			case strings.Contains(msg, "Group"):
				return uint64(ids.canaryGroup)
			case strings.Contains(msg, "Machine"):
				return uint64(ids.canaryMachine)
			}
			return uint64(ids.canaryProject)
		}
		return uint64(ids.canaryProject)
	}
	uniform := func(label string, id uint) walkVariant {
		return walkVariant{label: "all-ids=" + label, bind: func(_, field string) uint64 {
			switch field {
			case "project_id":
				return uint64(ids.canaryProject)
			case "environment_id":
				return uint64(ids.canaryEnv)
			case "parent_id":
				return 0
			}
			return uint64(id)
		}}
	}
	return []walkVariant{
		{label: "semantic", bind: semantic},
		uniform("canary-secret", ids.canarySecret),
		uniform("canary-victim", ids.canaryVictim),
		uniform("canary-machine", ids.canaryMachine),
		uniform("canary-group", ids.canaryGroup),
	}
}

// --- invocation ------------------------------------------------------------

// walkStreamOpenWindow is how long a stream may stay open before the walk
// concludes the server accepted it.
const walkStreamOpenWindow = 750 * time.Millisecond

// walkResult is the outcome of one RPC.
type walkResult struct {
	err  error
	resp []byte // wire bytes of the response (every message, for a stream)
	msgs int
}

func (r walkResult) leaksCanary() bool { return bytes.Contains(r.resp, []byte(walkCanary)) }

// call invokes m with req on conn, bearer-authenticated when token != "".
func call(t testing.TB, conn *grpc.ClientConn, m walkMethod, token string, req *dynamicpb.Message) walkResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if token != "" {
		ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+token))
	}
	if !m.stream() {
		resp := dynamicpb.NewMessage(m.output)
		err := conn.Invoke(ctx, m.full(), req, resp)
		b, merr := proto.Marshal(resp)
		require.NoError(t, merr)
		return walkResult{err: err, resp: b, msgs: 1}
	}
	// A stream the server ACCEPTED may stay open indefinitely (StreamAuditLogs
	// follows the log): a short deadline that fires on an established stream means
	// "accepted, nothing more to say", i.e. OK; a refusal arrives immediately.
	sctx, scancel := context.WithTimeout(ctx, walkStreamOpenWindow)
	defer scancel()
	st, err := conn.NewStream(sctx, &grpc.StreamDesc{ServerStreams: m.serverStream, ClientStreams: m.clientStream}, m.full())
	if err != nil {
		return walkResult{err: err}
	}
	if err := st.SendMsg(req); err != nil {
		return walkResult{err: recvErr(st, err)}
	}
	defer func() { _ = st.CloseSend() }()
	_ = st.CloseSend()
	var res walkResult
	for res.msgs < 50 {
		resp := dynamicpb.NewMessage(m.output)
		if err := st.RecvMsg(resp); err != nil {
			if err != io.EOF && status.Code(err) != codes.DeadlineExceeded {
				res.err = err
			}
			return res
		}
		b, merr := proto.Marshal(resp)
		require.NoError(t, merr)
		res.resp = append(res.resp, b...)
		res.msgs++
	}
	return res
}

func recvErr(st grpc.ClientStream, sendErr error) error {
	if err := st.RecvMsg(&dynamicpb.Message{}); err != nil && err != io.EOF {
		return err
	}
	return sendErr
}

// --- state digest ----------------------------------------------------------

// auditTables are counted, not digested: every authenticated RPC may append
// audit/access-log rows (documented best-effort writes), and the walks assert
// on them separately.
var auditTables = map[string]bool{"audit_events": true, "secret_access_logs": true}

// digestExemptTables are tables a rejected call may legitimately touch.
//
//   - compliance_posture_snapshots: GetCompliancePosture persists a trend
//     snapshot best-effort (internal/core/compliance_posture.go); the protoreflect
//     fuzzer names the same exemption (bestEffortSideEffectTables).
var digestExemptTables = map[string]bool{"compliance_posture_snapshots": true}

// digestVolatileColumns are last-touched stamps ValidateSessionToken /
// TouchPATLastUsed / TouchMachineTokenLastUsed write on every successful
// authentication (documented best-effort, bookkeeping only).
var digestVolatileColumns = map[string]bool{"last_seen_at": true, "last_used_at": true}

type dbDigest struct {
	tables map[string]string // table -> content hash
	audit  map[string]int64  // audit table -> row count
}

// digest hashes the full content of every table (volatile columns removed),
// so any INSERT/UPDATE/DELETE outside the exemptions changes the digest, on
// either backend.
func (w *walkWorld) digest(t testing.TB) dbDigest {
	t.Helper()
	if w.tables == nil {
		tables, err := w.db.Migrator().GetTables()
		require.NoError(t, err)
		for _, tbl := range tables {
			// sqlite_sequence & co are the engine's own bookkeeping, not data.
			if !strings.HasPrefix(tbl, "sqlite_") && !digestExemptTables[tbl] {
				w.tables = append(w.tables, tbl)
			}
		}
		require.NotEmpty(t, w.tables)
	}
	d := dbDigest{tables: map[string]string{}, audit: map[string]int64{}}
	for _, tbl := range w.tables {
		if auditTables[tbl] {
			var n int64
			require.NoError(t, w.sqlDB.QueryRow(`SELECT COUNT(*) FROM "`+tbl+`"`).Scan(&n)) // #nosec G202 -- tbl comes from the schema catalogue
			d.audit[tbl] = n
			continue
		}
		rows, err := w.sqlDB.Query(`SELECT * FROM "` + tbl + `"`) // #nosec G202 -- tbl comes from the schema catalogue
		require.NoErrorf(t, err, "digest %s", tbl)
		cols, err := rows.Columns()
		require.NoError(t, err)
		var lines []string
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			require.NoError(t, rows.Scan(ptrs...))
			var sb strings.Builder
			for i, c := range cols {
				if digestVolatileColumns[c] {
					continue
				}
				fmt.Fprintf(&sb, "%s=%v|", c, vals[i])
			}
			lines = append(lines, sb.String())
		}
		require.NoError(t, rows.Err())
		require.NoError(t, rows.Close())
		sort.Strings(lines)
		sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
		d.tables[tbl] = hex.EncodeToString(sum[:])
	}
	return d
}

// changedTables names the tables whose content differs between two digests.
func (before dbDigest) changedTables(after dbDigest) []string {
	var out []string
	for tbl, h := range after.tables {
		if before.tables[tbl] != h {
			out = append(out, tbl)
		}
	}
	sort.Strings(out)
	return out
}

func (before dbDigest) auditDelta(after dbDigest) map[string]int64 {
	out := map[string]int64{}
	for tbl, n := range after.audit {
		if n != before.audit[tbl] {
			out[tbl] = n - before.audit[tbl]
		}
	}
	return out
}
