package http

// secret_value_read_refusal_family_test.go — ERRMAP-1.
//
// Once a caller may read a secret, the secret's own state can still refuse the
// value read: outside its access schedule, expired, suspended, or out of
// max-reads budget. Before ERRMAP-1 those answered 500 / Internal on most value
// paths (only the human include_value path gave 403, and only for the
// schedule). The contract now, on every value-read route of both transports and
// for both principal kinds:
//
//	refusal                REST  error code                    gRPC
//	outside schedule       403   SecretAccessOutsideSchedule   PermissionDenied
//	expired                409   SecretExpired                 FailedPrecondition
//	suspended              409   SecretSuspended               FailedPrecondition
//	max reads exhausted    409   SecretMaxReadsExhausted       FailedPrecondition
//
// with a fixed message (never internal error text) and, on gRPC, the same code
// as an ErrorInfo detail's Reason. Two properties that must NOT change ride
// along: a caller who cannot read the secret gets exactly the answer it got
// before the secret entered the refused state (no existence or state oracle),
// and a refused read writes no audit or access-log row (as before).
//
// TestValueReadRouteFamily_IsCovered keeps the route table honest: it derives
// the value-read routes from the source instead of trusting this list.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// refusalCase is one refusal: how to put a secret into it, and the expected
// answer, written out here rather than taken from the code under test.
type refusalCase struct {
	sentinel   error
	name       string
	apply      func(t *testing.T, w *guardParityWorld, sec *models.SecretNode)
	restStatus int
	code       string
	message    string
	grpcCode   codes.Code
}

func refusalCases() []refusalCase {
	return []refusalCase{
		{core.ErrAccessOutsideSchedule, "outside access schedule", func(t *testing.T, w *guardParityWorld, sec *models.SecretNode) {
			// Closed at every hour (StartHour == EndHour), so wall-clock independent.
			require.NoError(t, w.db.Create(&models.SecretAccessSchedule{
				SecretNodeID: sec.ID, AllowedDays: "*", StartHour: 0, EndHour: 0, Timezone: "UTC",
			}).Error)
		}, http.StatusForbidden, "SecretAccessOutsideSchedule",
			"secret access is not permitted outside the configured time window", codes.PermissionDenied},
		{core.ErrSecretExpired, "expired", func(t *testing.T, w *guardParityWorld, sec *models.SecretNode) {
			// Through Save(), so SecretNode's BeforeSave hook runs (G1619).
			var row models.SecretNode
			require.NoError(t, w.db.First(&row, sec.ID).Error)
			past := time.Now().UTC().Add(-time.Hour)
			row.Expiration = &past
			require.NoError(t, w.db.Save(&row).Error)
		}, http.StatusConflict, "SecretExpired",
			"secret has expired; its value can no longer be read", codes.FailedPrecondition},
		{core.ErrSecretSuspended, "suspended", func(t *testing.T, w *guardParityWorld, sec *models.SecretNode) {
			require.NoError(t, w.db.Model(&models.SecretNode{}).Where("id = ?", sec.ID).Update("status", core.SecretStatusSuspended).Error)
		}, http.StatusConflict, "SecretSuspended",
			"secret is suspended; its value cannot be read until it is resumed", codes.FailedPrecondition},
		{core.ErrSecretMaxReadsExhausted, "max reads exhausted", func(t *testing.T, w *guardParityWorld, sec *models.SecretNode) {
			require.NoError(t, w.db.Model(&models.SecretNode{}).Where("id = ?", sec.ID).
				Updates(map[string]interface{}{"max_reads": 1, "read_count": 1}).Error)
		}, http.StatusConflict, "SecretMaxReadsExhausted",
			"secret has reached its maximum number of reads", codes.FailedPrecondition},
	}
}

// valueReadOutcome is one call's observable answer.
type valueReadOutcome struct {
	ok        bool
	value     string
	restCode  int
	restBody  string
	errCode   string // REST envelope `error`
	errMsg    string // REST envelope `message`
	grpcCode  codes.Code
	grpcMsg   string
	grpcInfo  string // ErrorInfo "domain/reason", "" if none
	transport string
}

// valueReadRoute is one value-read route. handler names the transport function
// serving it (Recv.Method), which TestValueReadRouteFamily_IsCovered matches
// against the source-derived family.
type valueReadRoute struct {
	name       string
	handler    string
	method     string // REST only: router method + path as registered in router.go
	path       string
	principals []string
	read       func(w *guardParityWorld, token string, sec *models.SecretNode) valueReadOutcome
}

func restValueRead(w *guardParityWorld, method, url, token string, body []byte, extract func(map[string]json.RawMessage) string) valueReadOutcome {
	var rdr *bytes.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, url, rdr)
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	w.router.ServeHTTP(rec, req)
	out := valueReadOutcome{transport: "rest", restCode: rec.Code, restBody: rec.Body.String()}
	var env struct {
		Data    map[string]json.RawMessage `json:"data"`
		Error   string                     `json:"error"`
		Message string                     `json:"message"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	out.errCode, out.errMsg = env.Error, env.Message
	if rec.Code >= 200 && rec.Code < 300 {
		out.ok = true
		out.value = extract(env.Data)
	}
	return out
}

func rawString(m map[string]json.RawMessage, key string) string {
	var s string
	_ = json.Unmarshal(m[key], &s)
	return s
}

func valueReadRoutes(projectName, envName string, projID uint) []valueReadRoute {
	return []valueReadRoute{
		{
			name: "REST GET /secrets/{id}?include_value=true", handler: "SecretHandler.GetSecret",
			method: "GET", path: "/api/v1/secrets/{id}", principals: []string{"session", "machine"},
			read: func(w *guardParityWorld, token string, sec *models.SecretNode) valueReadOutcome {
				return restValueRead(w, http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d?include_value=true", sec.ID), token, nil,
					func(d map[string]json.RawMessage) string { return rawString(d, "value") })
			},
		},
		{
			name: "REST GET /secrets/value?ref=", handler: "SecretHandler.GetSecretValueByRef",
			method: "GET", path: "/api/v1/secrets/value", principals: []string{"session", "machine"},
			read: func(w *guardParityWorld, token string, sec *models.SecretNode) valueReadOutcome {
				return restValueRead(w, http.MethodGet, "/api/v1/secrets/value?ref="+projectName+"/"+envName+"/"+sec.Name, token, nil,
					func(d map[string]json.RawMessage) string { return rawString(d, "value") })
			},
		},
		{
			// Human only: a render resolves every reference under the caller's own
			// per-user read permission, which a machine principal has no user for.
			name: "REST POST /projects/{id}/secrets/render", handler: "SecretHandler.RenderTemplate",
			method: "POST", path: "/api/v1/projects/{id}/secrets/render", principals: []string{"session"},
			read: func(w *guardParityWorld, token string, sec *models.SecretNode) valueReadOutcome {
				body, _ := json.Marshal(map[string]string{"template": "${secret:" + envName + "/" + sec.Name + "}"})
				return restValueRead(w, http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/secrets/render", projID), token, body,
					func(d map[string]json.RawMessage) string { return rawString(d, "rendered") })
			},
		},
		{
			name: "gRPC SecretService/GetSecretValue", handler: "SecretGRPCService.GetSecretValue",
			principals: []string{"session", "machine"},
			read: func(w *guardParityWorld, token string, sec *models.SecretNode) valueReadOutcome {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+token))
				resp, err := w.grpc.GetSecretValue(ctx, &pb.GetSecretRequest{Id: uint32(sec.ID), IncludeValue: true})
				out := valueReadOutcome{transport: "grpc"}
				if err == nil {
					out.ok, out.value = true, resp.GetValue()
					return out
				}
				st := status.Convert(err)
				out.grpcCode, out.grpcMsg = st.Code(), st.Message()
				for _, d := range st.Details() {
					if info, ok := d.(*errdetails.ErrorInfo); ok {
						out.grpcInfo = info.GetDomain() + "/" + info.GetReason()
					}
				}
				return out
			},
		},
	}
}

// refusalFamilyWorld is the guard-parity world plus two principals that may
// NOT read its project's secrets: a human with no grant and a machine identity
// holding secrets.read only in another project.
func buildRefusalFamilyWorld(t *testing.T) *guardParityWorld {
	t.Helper()
	w := buildGuardParityWorld(t)
	ctx := context.Background()
	ls := store.NewLocalStorage(w.db)

	const pw = "Xk7#Qp2$Rn5@Wv9!"
	_, err := w.c.CreateUser(ctx, &core.CreateUserRequest{Username: "refusal-outsider", Email: "refusal-outsider@x.io", Password: pw})
	require.NoError(t, err)
	sess, _, err := w.c.Login(ctx, &core.LoginRequest{Username: "refusal-outsider", Password: pw})
	require.NoError(t, err)
	w.tokens["outsider-session"] = sess.SessionToken

	other, err := ls.CreateProject(ctx, &models.Project{Name: "otherproj"})
	require.NoError(t, err)
	var role models.Role
	require.NoError(t, w.db.Where("name = ?", "guard-reader").First(&role).Error)
	m, err := w.c.CreateMachineIdentity(ctx, other.ID, "other-bot", "service", "", "", w.adminID, 0)
	require.NoError(t, err)
	require.NoError(t, w.c.AssignMachineRole(ctx, m.ID, role.ID, core.Scope{ProjectID: other.ID}, w.adminID, false))
	mtok, err := w.c.IssueMachineToken(ctx, other.ID, m.ID, w.adminID, core.IssueMachineTokenParams{Name: "other"})
	require.NoError(t, err)
	w.tokens["outsider-machine"] = mtok.PlainToken
	return w
}

func refusalRowCounts(t *testing.T, w *guardParityWorld, secretID uint) (audit, access int64) {
	t.Helper()
	require.NoError(t, w.db.Model(&models.AuditEvent{}).Where("secret_node_id = ?", secretID).Count(&audit).Error)
	require.NoError(t, w.db.Model(&models.SecretAccessLog{}).Where("secret_node_id = ?", secretID).Count(&access).Error)
	return audit, access
}

func TestSecretValueReadRefusals_MapToClientErrorsOnEveryRoute(t *testing.T) {
	w := buildRefusalFamilyWorld(t)
	ctx := context.Background()
	cases := refusalCases()

	// The table above must cover the whole refusal family core defines.
	family := core.SecretReadRefusalFamily()
	require.Len(t, cases, len(family), "refusalCases must have one row per core refusal")
	for _, rc := range cases {
		ref, ok := family[rc.sentinel]
		require.Truef(t, ok, "%s: sentinel is not in core's refusal family", rc.name)
		require.Equalf(t, rc.code, ref.Code, "%s: the stable wire code changed — it is API contract", rc.name)
	}

	n := 0
	for _, route := range valueReadRoutes("guardproj", "prod", w.projID) {
		for _, rc := range cases {
			for _, principal := range route.principals {
				t.Run(route.name+"/"+rc.name+"/"+principal, func(t *testing.T) {
					n++
					plaintext := fmt.Sprintf("REFUSAL-FAMILY-%d-4d2a", n)
					sec, err := w.c.CreateSecret(ctx, &core.CreateSecretRequest{
						Name: fmt.Sprintf("refused%d", n), Value: []byte(plaintext),
						ProjectID: w.projID, EnvironmentID: w.envID,
						Type: "password", CreatedBy: "guardadmin", OwnerID: w.adminID,
					})
					require.NoError(t, err)
					token := w.tokens[principal]

					before := route.read(w, token, sec)
					require.Truef(t, before.ok, "precondition: the unrefused secret must be readable (got %+v)", before)
					require.Equal(t, plaintext, before.value, "precondition: the read must return the plaintext")
					outsiderBefore := map[string]valueReadOutcome{}
					for _, o := range []string{"outsider-session", "outsider-machine"} {
						outsiderBefore[o] = route.read(w, w.tokens[o], sec)
						require.Falsef(t, outsiderBefore[o].ok, "precondition: %s must not read the secret", o)
					}

					rc.apply(t, w, sec)
					audit0, access0 := refusalRowCounts(t, w, sec.ID)

					got := route.read(w, token, sec)
					assert.False(t, got.ok, "the refused read succeeded")
					assert.NotContains(t, got.restBody, plaintext, "a refused read disclosed the plaintext")
					switch got.transport {
					case "rest":
						assert.Equal(t, rc.restStatus, got.restCode, "HTTP status (body: %s)", got.restBody)
						assert.Equal(t, rc.code, got.errCode, "stable error code (body: %s)", got.restBody)
						assert.Equal(t, rc.message, got.errMsg, "fixed client-safe message (body: %s)", got.restBody)
					case "grpc":
						assert.Equal(t, rc.grpcCode, got.grpcCode, "gRPC code (message: %s)", got.grpcMsg)
						assert.Equal(t, rc.message, got.grpcMsg, "fixed client-safe message")
						assert.Equal(t, "keyorix.secrets/"+rc.code, got.grpcInfo, "ErrorInfo carries the stable code")
					}

					audit1, access1 := refusalRowCounts(t, w, sec.ID)
					assert.Equal(t, audit0, audit1, "a refused read must not add audit rows (unchanged behaviour)")
					assert.Equal(t, access0, access1, "a refused read must not add access-log rows (unchanged behaviour)")

					// A caller who cannot read the secret learns nothing from its state:
					// the same answer, byte for byte, as before the refusal applied.
					for _, o := range []string{"outsider-session", "outsider-machine"} {
						after := route.read(w, w.tokens[o], sec)
						assert.Equalf(t, outsiderBefore[o], after, "%s: the refusal changed what an unauthorized caller sees", o)
						assert.NotEqualf(t, http.StatusConflict, after.restCode, "%s got a secret-state answer", o)
						assert.NotEqualf(t, codes.FailedPrecondition, after.grpcCode, "%s got a secret-state answer", o)
					}
				})
			}
		}
	}
}

// TestValueReadRouteFamily_IsCovered derives the value-read family from the
// source and fails when a transport function reads a secret value without
// being in valueReadRoutes (or valueReadRouteExclusions, with a reason).
//
// Derivation. A value read is a call that charges a secret's max-reads budget:
// in internal/core, readVersionValue and commitStagedSecretRead. Every
// *KeyorixCore method that reaches one of them through calls on its receiver
// (c.X(...), closures included) is a value-read entry point. Every function in
// server/ (non-test, non-generated) that calls an exported entry point by name
// (anything.X(...)) is a value-read transport function.
//
// What it does not see, stated so its silence is not over-read: a call through
// a function value or an interface method of a different name, a core helper
// that is a plain function rather than a method, and value reads outside
// server/ (the embedded CLI, the operator). For each REST function it also
// requires every router.go registration of that handler to be the route the
// table names.
func TestValueReadRouteFamily_IsCovered(t *testing.T) {
	entry := valueReadCoreEntryPoints(t, filepath.Join("..", "..", "internal", "core"))
	for _, want := range []string{"GetSecretValue", "GetPermittedSecretValue", "RenderSecretTemplate"} {
		require.Truef(t, entry[want], "derivation sanity: %s must be a value-read entry point (got %v)", want, sortedKeys(entry))
	}

	callers := valueReadTransportFunctions(t, "..", entry)
	covered := map[string]valueReadRoute{}
	for _, r := range valueReadRoutes("", "", 0) {
		covered[r.handler] = r
	}
	for fn, calls := range callers {
		if _, ok := covered[fn]; ok {
			continue
		}
		if reason, ok := valueReadRouteExclusions[fn]; ok && reason != "" {
			continue
		}
		t.Errorf("%s reads a secret value (calls %v) but is not in valueReadRoutes: add its route to "+
			"TestSecretValueReadRefusals_MapToClientErrorsOnEveryRoute and map refusals with "+
			"sendSecretReadRefusal / mapSecretReadError", fn, calls)
	}
	for fn := range covered {
		if _, ok := callers[fn]; !ok {
			t.Errorf("valueReadRoutes names %s, which no longer reads a secret value: remove or rename it", fn)
		}
	}
	for fn := range valueReadRouteExclusions {
		if _, ok := callers[fn]; !ok {
			t.Errorf("valueReadRouteExclusions names %s, which no longer reads a secret value: remove it", fn)
		}
	}

	byHandler := map[string][]routerRoute{}
	for _, rr := range extractAllRouterRoutes(t, "router.go") {
		byHandler[rr.Handler] = append(byHandler[rr.Handler], rr)
	}
	for fn, r := range covered {
		if r.method == "" {
			continue // gRPC
		}
		method := strings.TrimPrefix(fn, "SecretHandler.")
		regs := byHandler[method]
		require.NotEmptyf(t, regs, "%s is not registered in router.go", fn)
		for _, rr := range regs {
			assert.Equalf(t, r.method+" "+r.path, rr.Method+" "+normalizeRouterPath(rr.Path),
				"%s is also served at a route the family test does not exercise", fn)
		}
	}
}

// valueReadRouteExclusions are value-reading transport functions deliberately
// outside this family, each with the reason.
var valueReadRouteExclusions = map[string]string{
	"SecretHandler.CopySecret": "a write that copies a value into a new secret: its source is resolved " +
		"before authorization and collapsed to not-found on purpose (core.CopySecret), so naming a " +
		"refusal there needs its own reordering; tracked as an ERRMAP-1 follow-up",
	"SecretHandler.CopyEnvironmentSecrets": "bulk copy through core.CopySecret: a source whose state refuses " +
		"the read is skipped and counted, not answered as an error",
	"CatalogHandler.CloneEnvironment": "bulk clone through core.CopySecret: a source whose state refuses " +
		"the read is skipped, not answered as an error",
}

func valueReadCoreEntryPoints(t *testing.T, dir string) map[string]bool {
	t.Helper()
	calls := map[string]map[string]bool{} // method -> receiver-method callees
	exported := map[string]bool{}
	for _, f := range parseGoDir(t, dir) {
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || len(fd.Recv.List) != 1 || fd.Body == nil {
				continue
			}
			star, ok := fd.Recv.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			if id, ok := star.X.(*ast.Ident); !ok || id.Name != "KeyorixCore" {
				continue
			}
			recv := ""
			if len(fd.Recv.List[0].Names) == 1 {
				recv = fd.Recv.List[0].Names[0].Name
			}
			name := fd.Name.Name
			exported[name] = ast.IsExported(name)
			if calls[name] == nil {
				calls[name] = map[string]bool{}
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := ce.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if x, ok := sel.X.(*ast.Ident); ok && recv != "" && x.Name == recv {
					calls[name][sel.Sel.Name] = true
				}
				return true
			})
		}
	}
	reaches := map[string]bool{"readVersionValue": true, "commitStagedSecretRead": true}
	for changed := true; changed; {
		changed = false
		for m, callees := range calls {
			if reaches[m] {
				continue
			}
			for c := range callees {
				if reaches[c] {
					reaches[m], changed = true, true
					break
				}
			}
		}
	}
	out := map[string]bool{}
	for m := range reaches {
		if exported[m] {
			out[m] = true
		}
	}
	return out
}

// valueReadTransportFunctions walks every non-test, non-generated Go file under
// root and returns "Recv.Func" (or "Func") -> the entry points it calls.
func valueReadTransportFunctions(t *testing.T, root string, entry map[string]bool) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "pb" || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if perr != nil {
			return perr
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			name := fd.Name.Name
			if fd.Recv != nil && len(fd.Recv.List) == 1 {
				typ := fd.Recv.List[0].Type
				if st, ok := typ.(*ast.StarExpr); ok {
					typ = st.X
				}
				if id, ok := typ.(*ast.Ident); ok {
					name = id.Name + "." + name
				}
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := ce.Fun.(*ast.SelectorExpr); ok && entry[sel.Sel.Name] {
					out[name] = append(out[name], sel.Sel.Name)
				}
				return true
			})
		}
		return nil
	})
	require.NoError(t, err)
	return out
}

func parseGoDir(t *testing.T, dir string) []*ast.File {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var files []*ast.File
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, e.Name()), nil, 0)
		require.NoError(t, err)
		files = append(files, f)
	}
	return files
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
