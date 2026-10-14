package http

// connect_ref_scoping_grpc_fuzz_test.go — FuzzConnectRefScopingGRPC.
//
// internal/connect/ref_scoping_fuzz_test.go fuzzes prefixAllowed, the connector-level
// static allowed_refs guardrail (ADR-043), as a PURE FUNCTION -- no transport involved.
// The SEPARATE, RBAC-driven per-reference scoping layer (ADR-045 ConnectRefGrant,
// enforced by core.KeyorixCore.ReadFederatedSecret -> connectRefAllowed -> refMatches)
// is reached IDENTICALLY by both transports keyorix serves for a federated secret
// read: the HTTP handler (server/http/handlers/connect.go ConnectHandler.ReadSecret)
// and the gRPC service (server/grpc/services/connect_service.go
// ConnectGRPCService.ReadSecret) both call the exact same core.ReadFederatedSecret
// with the caller's actor identity, connector name, and ref. Neither transport had
// fuzz coverage of this path before.
//
// SAME generated world as api_sequence_fuzz_test.go's buildAPIFuzzWorlds (same core,
// same bootstrap admin, same project A) -- extended here with one fake connector
// ("svcA", owned by project A) and one role ("crs-fuzz-scoped-<backend>") holding a
// single ConnectRefGrant scoping it to ref-prefix "allowed/prefix". A second gRPC
// server is wired onto the IDENTICAL *core.KeyorixCore the REST router already uses
// (mirroring multitenant_isolation_grpc_fuzz_test.go's FuzzMultiTenantIsolationGRPC),
// so the grant created below is visible to both surfaces instantly -- not a parallel
// world.
//
// Oracle:
//   - (a) NEVER RESOLVES OUTSIDE SCOPE, via gRPC exactly like via REST: whenever the
//     fuzzed ref is NOT segment-contained in "allowed/prefix" (an INDEPENDENT
//     segment-slice check -- crsRefWithinPrefixIndependent below -- not the
//     ports.RefWithinPrefix implementation refMatches itself calls) OR contains a
//     "."/".." path segment (crsHasDotSegmentIndependent, not ports.RefHasDotSegment),
//     BOTH transports must deny the read. The converse direction is checked too (a
//     non-vacuous positive control): an in-scope ref must be ALLOWED on both.
//   - (b) REST-vs-gRPC PARITY: for the identical world + identical (actor, connector,
//     ref), the allow/deny decision REST returns must equal what gRPC returns; when
//     both allow, the returned plaintext value must match too.
//
// A second, grant-less principal (holding connect.read but no ConnectRefGrant of its
// own) is checked once per iteration as a structural control: once a connector has
// ANY grant configured, an unmatched caller must never resolve, on either transport,
// regardless of ref content -- proves ADR-045's deny-by-default-once-scoped rule is
// actually reached here, not vacuously bypassed by project/global ownership.

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/connect"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	keyorixgrpc "github.com/keyorixhq/keyorix/server/grpc"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// crsFakeConnector is a minimal ports.Connector double: it ignores ref entirely (the
// connector-level allowed_refs check -- internal/connect's prefixAllowed -- already
// has its own pure-function fuzz coverage in ref_scoping_fuzz_test.go) and always
// returns a fixed value, so the ONLY gate a read can be denied by here is the RBAC
// ref-grant layer this fuzzer targets.
type crsFakeConnector struct{ nameV, val string }

func (f crsFakeConnector) Name() string { return f.nameV }
func (f crsFakeConnector) Type() string { return "fake" }
func (f crsFakeConnector) GetSecret(_ context.Context, _ string) (string, error) {
	return f.val, nil
}

const crsConnectorValue = "FEDERATED-VALUE-9f21a"
const crsGrantPrefix = "allowed/prefix"

// crsRefWithinPrefixIndependent is an INDEPENDENT oracle for "ref is within prefix p
// on a path-segment boundary", implemented via "/"-split segment-slice comparison --
// deliberately NOT calling ports.RefWithinPrefix, the implementation refMatches (the
// code under test) itself calls. Mirrors ref_scoping_fuzz_test.go's
// segContainsBySegments.
func crsRefWithinPrefixIndependent(p, ref string) bool {
	if p == "" {
		return false
	}
	pSegs := strings.Split(strings.TrimSuffix(p, "/"), "/")
	refSegs := strings.Split(ref, "/")
	if len(refSegs) < len(pSegs) {
		return false
	}
	for i := range pSegs {
		if refSegs[i] != pSegs[i] {
			return false
		}
	}
	return true
}

// crsHasDotSegmentIndependent is an INDEPENDENT oracle for "ref contains a '.' or '..'
// path segment" -- deliberately NOT calling ports.RefHasDotSegment, the implementation
// under test.
func crsHasDotSegmentIndependent(ref string) bool {
	for seg := range strings.SplitSeq(ref, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

type crsWorld struct {
	w         *apiFuzzWorld
	scopedTok string // holds connect.read + the ConnectRefGrant scoping it to crsGrantPrefix
	plainTok  string // holds connect.read, NO matching grant -- must always deny once the connector has ANY grant
	grpc      pb.ConnectServiceClient
}

// buildCRSWorlds extends buildAPIFuzzWorlds (api_sequence_fuzz_test.go) with the
// Connect ref-scoping fixtures and a second gRPC server wired onto the same core,
// exactly as FuzzMultiTenantIsolationGRPC extends buildAPIFuzzWorlds for tenant
// isolation.
func buildCRSWorlds(f *testing.F) []crsWorld {
	f.Helper()
	apiWorlds := buildAPIFuzzWorlds(f, "connectrefscopegrpc")
	f.Cleanup(i18n.ResetForTesting)
	ctx := context.Background()

	out := make([]crsWorld, 0, len(apiWorlds))
	for _, w := range apiWorlds {
		c := w.c

		conn := crsFakeConnector{nameV: "svcA", val: crsConnectorValue}
		c.SetConnectManager(connect.NewManager([]connect.Connector{conn}))
		c.SetConnectOwnership(map[string]core.ConnectOwnership{
			"svcA": {Scope: "project", ProjectID: w.projAID},
		})

		var permConnRead models.Permission
		if e := w.db.Where("name = ?", "connect.read").First(&permConnRead).Error; e != nil {
			permConnRead = models.Permission{Name: "connect.read", Resource: "connect", Action: "read"}
			if e2 := w.db.Create(&permConnRead).Error; e2 != nil {
				f.Fatalf("[%s] seed connect.read permission: %v", w.backend, e2)
			}
		}

		roleScoped := models.Role{Name: "crs-fuzz-scoped-" + w.backend, NameFolded: "crs-fuzz-scoped-" + w.backend}
		if e := w.db.Create(&roleScoped).Error; e != nil {
			f.Fatalf("[%s] seed roleScoped: %v", w.backend, e)
		}
		if e := w.db.Create(&models.RolePermission{RoleID: roleScoped.ID, PermissionID: permConnRead.ID}).Error; e != nil {
			f.Fatalf("[%s] seed roleScoped permission: %v", w.backend, e)
		}
		rolePlain := models.Role{Name: "crs-fuzz-plain-" + w.backend, NameFolded: "crs-fuzz-plain-" + w.backend}
		if e := w.db.Create(&rolePlain).Error; e != nil {
			f.Fatalf("[%s] seed rolePlain: %v", w.backend, e)
		}
		if e := w.db.Create(&models.RolePermission{RoleID: rolePlain.ID, PermissionID: permConnRead.ID}).Error; e != nil {
			f.Fatalf("[%s] seed rolePlain permission: %v", w.backend, e)
		}

		// The single ConnectRefGrant configured on "svcA": once created, ANY caller
		// (owned or delegated) must match a grant by role+ref-prefix to read -- see
		// connectRefAllowed's doc comment (internal/core/connect.go).
		if _, err := c.CreateConnectRefGrant(ctx, 0, roleScoped.ID, "svcA", crsGrantPrefix, nil); err != nil {
			f.Fatalf("[%s] create ref grant: %v", w.backend, err)
		}

		mk := func(uname string) (uint, string) {
			u, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: uname, Email: uname + "@x.io", Password: apiFuzzPrincipalPassword})
			if err != nil || u == nil {
				f.Fatalf("[%s] create user %s: %v", w.backend, uname, err)
			}
			sess, _, err := c.Login(ctx, &core.LoginRequest{Username: uname, Password: apiFuzzPrincipalPassword})
			if err != nil || sess == nil {
				f.Fatalf("[%s] login %s: %v", w.backend, uname, err)
			}
			return u.ID, sess.SessionToken
		}
		scopedID, scopedTok := mk("crsscoped" + w.backend)
		plainID, plainTok := mk("crsplain" + w.backend)

		// Both roles carry connect.read at GLOBAL scope -- required by both
		// transports' front gate (RequirePermission("connect.read") == Scope{} on
		// REST; authorizeGlobal == Scope{} on gRPC). Global scope also satisfies
		// connectOwnershipSatisfied's ConnectOwnershipReasonGlobalScope branch for
		// BOTH users, so the only remaining gate that can differ between them is
		// ADR-045's ConnectRefGrant match -- exactly the layer under test.
		if err := c.AssignUserRole(ctx, 0, scopedID, roleScoped.ID, core.Scope{}, false); err != nil {
			f.Fatalf("[%s] assign roleScoped: %v", w.backend, err)
		}
		if err := c.AssignUserRole(ctx, 0, plainID, rolePlain.ID, core.Scope{}, false); err != nil {
			f.Fatalf("[%s] assign rolePlain: %v", w.backend, err)
		}

		srv, err := keyorixgrpc.NewServer(&config.Config{}, c)
		if err != nil {
			f.Fatalf("[%s] grpc server: %v", w.backend, err)
		}
		lis := bufconn.Listen(1 << 20)
		go func() { _ = srv.Serve(lis) }()
		f.Cleanup(srv.Stop)
		gconn, err := grpc.NewClient(
			"passthrough:///bufnet",
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err != nil {
			f.Fatalf("[%s] grpc dial: %v", w.backend, err)
		}
		f.Cleanup(func() { _ = gconn.Close() })

		out = append(out, crsWorld{w: w, scopedTok: scopedTok, plainTok: plainTok, grpc: pb.NewConnectServiceClient(gconn)})
	}
	return out
}

type crsRespEnvelope struct {
	Data struct {
		Value string `json:"value"`
	} `json:"data"`
}

func FuzzConnectRefScopingGRPC(f *testing.F) {
	worlds := buildCRSWorlds(f)

	seeds := []string{
		"allowed/prefix",
		"allowed/prefix/x",
		"allowed/prefixEXTRA",   // byte-prefix but not segment boundary -- must deny
		"allowed/prefix/../etc", // traversal -- must deny
		"allowed/./prefix/x",    // dot segment -- must deny
		"other/ref",             // outside scope entirely -- must deny
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, ref string) {
		for _, cw := range worlds {
			runCRSIteration(t, cw, ref)
		}
	})
}

func runCRSIteration(t *testing.T, cw crsWorld, ref string) {
	t.Helper()
	w := cw.w

	// Honest scope note: an invalid-UTF-8 ref is not representable identically on
	// both transports -- encoding/json.Marshal silently replaces invalid sequences
	// with U+FFFD (REST never sees the real bytes), while the gRPC/protobuf wire
	// format rejects invalid UTF-8 in a string field outright (the RPC itself fails
	// before ReadSecret ever runs). Neither behavior is a scope-escape or a
	// parity bug -- it's the two transports disagreeing about what a "ref" even IS
	// once it isn't valid text, not about who may read it. Skip rather than assert.
	if !utf8.ValidString(ref) {
		return
	}

	doREST := func(tok string) (bool, string) {
		body, _ := json.Marshal(map[string]string{"ref": ref})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/connect/svcA/secret:read", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		rec := httptest.NewRecorder()
		w.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			return false, ""
		}
		var env crsRespEnvelope
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("[%s] REST 200 response is not valid JSON: %v (body=%q)", w.backend, err, rec.Body.String())
		}
		return true, env.Data.Value
	}

	doGRPC := func(tok string) (bool, string) {
		gctx := context.Background()
		if tok != "" {
			gctx = metadata.NewOutgoingContext(gctx, metadata.Pairs("authorization", "Bearer "+tok))
		}
		resp, err := cw.grpc.ReadSecret(gctx, &pb.ReadFederatedSecretRequest{Connector: "svcA", Ref: ref})
		if err != nil {
			return false, ""
		}
		return true, resp.GetValue()
	}

	// Structural control: a connect.read holder with NO matching ConnectRefGrant on a
	// connector that now has ANY grant configured must never resolve, on either
	// transport -- regardless of ref content.
	if ok, _ := doREST(cw.plainTok); ok {
		t.Fatalf("[%s] NO-GRANT BYPASS(REST): ungranted principal read ref %q", w.backend, ref)
	}
	if ok, _ := doGRPC(cw.plainTok); ok {
		t.Fatalf("[%s] NO-GRANT BYPASS(gRPC): ungranted principal read ref %q", w.backend, ref)
	}

	restOK, restVal := doREST(cw.scopedTok)
	grpcOK, grpcVal := doGRPC(cw.scopedTok)

	withinScope := crsRefWithinPrefixIndependent(crsGrantPrefix, ref) && !crsHasDotSegmentIndependent(ref)

	if !withinScope {
		if restOK {
			t.Fatalf("[%s] OVER-GRANT/TRAVERSAL(REST): ref %q resolved outside grant prefix %q", w.backend, ref, crsGrantPrefix)
		}
		if grpcOK {
			t.Fatalf("[%s] OVER-GRANT/TRAVERSAL(gRPC): ref %q resolved outside grant prefix %q", w.backend, ref, crsGrantPrefix)
		}
	} else {
		// Positive control (non-vacuous): an in-scope ref must actually be allowed on
		// both transports -- a harness that denied everything could not pass this.
		if !restOK {
			t.Fatalf("[%s] POSITIVE-CONTROL(REST): in-scope ref %q was denied", w.backend, ref)
		}
		if !grpcOK {
			t.Fatalf("[%s] POSITIVE-CONTROL(gRPC): in-scope ref %q was denied", w.backend, ref)
		}
	}

	if restOK != grpcOK {
		t.Fatalf("[%s] REST/gRPC PARITY VIOLATION reading %q: REST allow=%v, gRPC allow=%v", w.backend, ref, restOK, grpcOK)
	}
	if restOK && grpcOK {
		if restVal != crsConnectorValue || grpcVal != crsConnectorValue {
			t.Fatalf("[%s] VALUE MISMATCH reading %q: REST=%q gRPC=%q want %q", w.backend, ref, restVal, grpcVal, crsConnectorValue)
		}
	}
}
