package http

// secret_value_read_denial_audit_test.go -- #3273, ADR-112 Amendment 4:
// "denied reads stay audited, so probing still leaves a trace".
//
// Against the real router and the real gRPC server, at BOTH
// insecure_audit_skip_reads settings, every refused native value read writes
// exactly one secret.read row with Success=false and its reason class, on
// every value-disclosing path: REST GET /secrets/{id}?include_value=true,
// GET /secrets/value?ref=, POST /projects/{id}/secrets/render,
// POST /secrets/{id}/copy, the environment copy and clone, and gRPC
// GetSecretValue. A refusal before authorization (forbidden, not_found)
// answers the caller identically and leaves a row that names neither the
// secret nor its project on any column. TestValueReadRoutes_AuditTheirRefusals
// derives the value-read routes from the source and requires the audit hook on
// each, so a new route cannot skip it. The aggregation bounds are in
// internal/core/secret_read_denial_test.go.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// refusedReadRow is one secret.read Success=false row as the test reads it.
type refusedReadRow struct {
	row  models.AuditEvent
	diff struct {
		Outcome  string `json:"outcome"`
		Reason   string `json:"reason"`
		Path     string `json:"path"`
		Target   string `json:"target"`
		SecretID uint   `json:"secret_id"`
		Count    int    `json:"count"`
	}
}

func refusedReadRowsAfter(t *testing.T, w *guardParityWorld, afterID uint) []refusedReadRow {
	t.Helper()
	var rows []models.AuditEvent
	require.NoError(t, w.db.Where("event_type = ? AND success = ? AND id > ?", "secret.read", false, afterID).Order("id").Find(&rows).Error)
	out := make([]refusedReadRow, len(rows))
	for i, r := range rows {
		out[i].row = r
		require.NoError(t, json.Unmarshal([]byte(r.Diff), &out[i].diff), "diff: %s", r.Diff)
	}
	return out
}

func lastAuditID(t *testing.T, w *guardParityWorld) uint {
	t.Helper()
	var id uint
	require.NoError(t, w.db.Model(&models.AuditEvent{}).Select("COALESCE(MAX(id), 0)").Scan(&id).Error)
	return id
}

func readAccessLogCount(t *testing.T, w *guardParityWorld, secretID uint) int64 {
	t.Helper()
	var n int64
	require.NoError(t, w.db.Model(&models.SecretAccessLog{}).Where("secret_node_id = ? AND action = ?", secretID, "read").Count(&n).Error)
	return n
}

// denialWorld is the refusal-family world plus a second environment (copy
// target) and the skip-reads setting under test.
type denialWorld struct {
	*guardParityWorld
	stagingID uint
}

func buildDenialWorld(t *testing.T, skipReads bool) *denialWorld {
	t.Helper()
	w := buildRefusalFamilyWorld(t)
	w.c.SetInsecureAuditSkipReads(skipReads)
	staging, err := store.NewLocalStorage(w.db).CreateEnvironment(context.Background(), &models.Environment{Name: "staging", ProjectID: w.projID})
	require.NoError(t, err)
	return &denialWorld{guardParityWorld: w, stagingID: staging.ID}
}

func (w *denialWorld) newSecret(t *testing.T, name, plaintext string, envID uint) *models.SecretNode {
	t.Helper()
	sec, err := w.c.CreateSecret(context.Background(), &core.CreateSecretRequest{
		Name: name, Value: []byte(plaintext), ProjectID: w.projID, EnvironmentID: envID,
		Type: "password", CreatedBy: "guardadmin", OwnerID: w.adminID,
	})
	require.NoError(t, err)
	return sec
}

// copyValueReadRoute is POST /secrets/{id}/copy into the staging environment.
func (w *denialWorld) copyValueReadRoute() valueReadRoute {
	return valueReadRoute{
		name: "REST POST /secrets/{id}/copy", handler: "SecretHandler.CopySecret", principals: []string{"session"},
		read: func(gw *guardParityWorld, token string, sec *models.SecretNode) valueReadOutcome {
			body, _ := json.Marshal(map[string]any{"environment_id": w.stagingID, "name": fmt.Sprintf("%s-copy-%d", sec.Name, time.Now().UnixNano())})
			return restValueRead(gw, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/copy", sec.ID), token, body,
				func(map[string]json.RawMessage) string { return "" })
		},
	}
}

// routePath is the Diff.path each route records.
var routePath = map[string]string{
	"SecretHandler.GetSecret":           core.SecretReadPathRESTGet,
	"SecretHandler.GetSecretValueByRef": core.SecretReadPathRESTByRef,
	"SecretHandler.RenderTemplate":      core.SecretReadPathRESTRender,
	"SecretGRPCService.GetSecretValue":  core.SecretReadPathGRPCGetValue,
	"SecretHandler.CopySecret":          core.SecretReadPathRESTCopy,
}

// stateRefusal is a refusal past authorization, with its expected reason.
type stateRefusal struct {
	name   string
	reason core.SecretReadDenialReason
	apply  func(t *testing.T, w *guardParityWorld, sec *models.SecretNode)
}

func stateRefusals() []stateRefusal {
	cases := refusalCases()
	byName := map[string]refusalCase{}
	for _, rc := range cases {
		byName[rc.name] = rc
	}
	return []stateRefusal{
		{"outside access schedule", core.SecretReadDeniedOutsideSchedule, byName["outside access schedule"].apply},
		{"expired", core.SecretReadDeniedExpired, byName["expired"].apply},
		{"suspended", core.SecretReadDeniedSuspended, byName["suspended"].apply},
		{"max reads exhausted", core.SecretReadDeniedMaxReadsExhausted, byName["max reads exhausted"].apply},
		{"restricted, MFA step-up required", core.SecretReadDeniedClassificationGate, func(t *testing.T, w *guardParityWorld, sec *models.SecretNode) {
			require.NoError(t, w.db.Model(&models.SecretNode{}).Where("id = ?", sec.ID).Update("classification", core.ClassificationRestricted).Error)
		}},
	}
}

// Every refusal past authorization, on every value-read route and for both
// principal kinds, at both insecure_audit_skip_reads settings: exactly one new
// secret.read Success=false row, with the reason class, the route's path and
// the secret named; no access-log "read" row.
func TestSecretValueReadDenials_StateRefusalsAuditedOnEveryRoute(t *testing.T) {
	for _, skip := range []bool{false, true} {
		t.Run(fmt.Sprintf("insecure_audit_skip_reads=%v", skip), func(t *testing.T) {
			w := buildDenialWorld(t, skip)
			routes := append(valueReadRoutes("guardproj", "prod", w.projID), w.copyValueReadRoute())
			n := 0
			for _, route := range routes {
				for _, sr := range stateRefusals() {
					for _, principal := range route.principals {
						t.Run(route.name+"/"+sr.name+"/"+principal, func(t *testing.T) {
							n++
							plaintext := fmt.Sprintf("DENIAL-AUDIT-%d-9f3b", n)
							sec := w.newSecret(t, fmt.Sprintf("denied%d", n), plaintext, w.envID)
							token := w.tokens[principal]
							before := route.read(w.guardParityWorld, token, sec)
							require.Truef(t, before.ok, "precondition: the unrefused secret must be readable (got %+v)", before)

							sr.apply(t, w.guardParityWorld, sec)
							mark, logs0 := lastAuditID(t, w.guardParityWorld), readAccessLogCount(t, w.guardParityWorld, sec.ID)
							got := route.read(w.guardParityWorld, token, sec)
							require.False(t, got.ok, "the refused read succeeded")
							assert.NotContains(t, got.restBody, plaintext)

							rows := refusedReadRowsAfter(t, w.guardParityWorld, mark)
							require.Lenf(t, rows, 1, "a refused read must write exactly one secret.read Success=false row (answer: %+v)", got)
							r := rows[0]
							want := sr.reason
							if route.handler == "SecretHandler.CopySecret" && sr.reason == core.SecretReadDeniedExpired {
								// core.CopySecret resolves its source before authorization and
								// answers an expired source as not found (#G14); the row follows.
								want = core.SecretReadDeniedNotFound
							}
							assert.Equal(t, string(want), r.diff.Reason, "reason class (%s)", r.row.Description)
							assert.Contains(t, r.row.Description, "reason="+string(want))
							assert.Equal(t, routePath[route.handler], r.diff.Path)
							assert.Equal(t, "denied", r.diff.Outcome)
							if !want.IsBeforeAuthorization() {
								require.NotNil(t, r.row.SecretNodeID, "a refusal past authorization names the secret")
								assert.Equal(t, sec.ID, *r.row.SecretNodeID)
								require.NotNil(t, r.row.ProjectID)
								assert.Equal(t, w.projID, *r.row.ProjectID)
							}
							if principal == "machine" {
								assert.Equal(t, core.ActorTypeMachine, r.row.ActorType)
								assert.NotNil(t, r.row.MachineIdentityID)
								assert.Nil(t, r.row.UserID)
							} else {
								require.NotNil(t, r.row.UserID)
								assert.Equal(t, w.adminID, *r.row.UserID)
							}
							assert.Equal(t, logs0, readAccessLogCount(t, w.guardParityWorld, sec.ID), "a refused read writes no access-log read row")
						})
					}
				}
			}
		})
	}
}

// outsiderRoute is one value-read path, read by a caller who may not read
// anything in the project, against an existing target and a missing one.
type outsiderRoute struct {
	name string
	path string
	// missingReason is what the row of the missing target says. A project or
	// environment gate authorizes against the scope without resolving it, so
	// for those routes a missing target is, as far as the server looked, a
	// forbidden one.
	missingReason core.SecretReadDenialReason
	principals    []string
	existing      func(t *testing.T, w *denialWorld, token string) valueReadOutcome
	missing       func(t *testing.T, w *denialWorld, token string) valueReadOutcome
}

func outsiderRoutes() []outsiderRoute {
	// A distinct missing ID per route, so no two routes share an aggregation key.
	nextMissing := uint(987650)
	missing := func() uint { nextMissing++; return nextMissing }
	byID := func(r valueReadRoute) func(w *denialWorld, token string, id uint, name string) valueReadOutcome {
		return func(w *denialWorld, token string, id uint, name string) valueReadOutcome {
			return r.read(w.guardParityWorld, token, &models.SecretNode{ID: id, Name: name})
		}
	}
	envPost := func(path string, body func(w *denialWorld) []byte) func(w *denialWorld, token string, envID uint) valueReadOutcome {
		return func(w *denialWorld, token string, envID uint) valueReadOutcome {
			return restValueRead(w.guardParityWorld, http.MethodPost, fmt.Sprintf(path, w.projID, envID), token, body(w),
				func(map[string]json.RawMessage) string { return "" })
		}
	}
	var out []outsiderRoute
	for _, r := range valueReadRoutes("guardproj", "prod", 0) {
		read := byID(r)
		route := outsiderRoute{name: r.name, path: routePath[r.handler], missingReason: core.SecretReadDeniedNotFound,
			principals: []string{"outsider-session", "outsider-machine"}}
		if r.handler == "SecretHandler.RenderTemplate" {
			// The project gate refuses an outsider before any reference is looked
			// at, so the target is the project: an existing one versus a missing one.
			route.principals = []string{"outsider-session"}
			route.missingReason = core.SecretReadDeniedForbidden
			missingProject := missing()
			render := func(w *denialWorld, token string, projID uint) valueReadOutcome {
				body, _ := json.Marshal(map[string]string{"template": "${secret:prod/whatever}"})
				return restValueRead(w.guardParityWorld, http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/secrets/render", projID), token, body,
					func(map[string]json.RawMessage) string { return "" })
			}
			route.existing = func(t *testing.T, w *denialWorld, token string) valueReadOutcome { return render(w, token, w.projID) }
			route.missing = func(t *testing.T, w *denialWorld, token string) valueReadOutcome {
				return render(w, token, missingProject)
			}
		} else {
			route.existing = func(t *testing.T, w *denialWorld, token string) valueReadOutcome {
				sec := w.newSecret(t, fmt.Sprintf("outsider-target-%d", time.Now().UnixNano()), "OUTSIDER-PLAINTEXT", w.envID)
				return read(w, token, sec.ID, sec.Name)
			}
			missingSecret := missing()
			route.missing = func(t *testing.T, w *denialWorld, token string) valueReadOutcome {
				return read(w, token, missingSecret, fmt.Sprintf("no-such-secret-%d", time.Now().UnixNano()))
			}
		}
		out = append(out, route)
	}
	cp := outsiderRoute{name: "REST POST /secrets/{id}/copy", path: core.SecretReadPathRESTCopy, missingReason: core.SecretReadDeniedNotFound, principals: []string{"outsider-session"}}
	copyRead := func(w *denialWorld, token string, id uint) valueReadOutcome {
		body, _ := json.Marshal(map[string]any{"environment_id": w.stagingID})
		return restValueRead(w.guardParityWorld, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/copy", id), token, body,
			func(map[string]json.RawMessage) string { return "" })
	}
	cp.existing = func(t *testing.T, w *denialWorld, token string) valueReadOutcome {
		return copyRead(w, token, w.newSecret(t, fmt.Sprintf("copy-target-%d", time.Now().UnixNano()), "x", w.envID).ID)
	}
	missingCopy := missing()
	cp.missing = func(t *testing.T, w *denialWorld, token string) valueReadOutcome {
		return copyRead(w, token, missingCopy)
	}
	out = append(out, cp)

	copyEnv := envPost("/api/v1/projects/%d/environments/%d/copy-secrets", func(w *denialWorld) []byte {
		b, _ := json.Marshal(map[string]any{"target_environment_id": w.stagingID})
		return b
	})
	clone := envPost("/api/v1/projects/%d/environments/%d/clone", func(w *denialWorld) []byte {
		b, _ := json.Marshal(map[string]any{"destination_environment_id": w.stagingID})
		return b
	})
	missingEnvCopy, missingEnvClone := missing(), missing()
	out = append(out,
		outsiderRoute{name: "REST POST /projects/{id}/environments/{envId}/copy-secrets", path: core.SecretReadPathRESTCopyEnv,
			missingReason: core.SecretReadDeniedForbidden, principals: []string{"outsider-session"},
			existing: func(t *testing.T, w *denialWorld, token string) valueReadOutcome { return copyEnv(w, token, w.envID) },
			missing: func(t *testing.T, w *denialWorld, token string) valueReadOutcome {
				return copyEnv(w, token, missingEnvCopy)
			}},
		outsiderRoute{name: "REST POST /projects/{id}/environments/{envId}/clone", path: core.SecretReadPathRESTCloneEnv,
			missingReason: core.SecretReadDeniedForbidden, principals: []string{"outsider-session"},
			existing: func(t *testing.T, w *denialWorld, token string) valueReadOutcome { return clone(w, token, w.envID) },
			missing: func(t *testing.T, w *denialWorld, token string) valueReadOutcome {
				return clone(w, token, missingEnvClone)
			}},
	)
	return out
}

// A caller who may not read the target: the existing target (forbidden) and a
// missing one (not_found) get the SAME answer, each writes one row with its
// reason, and neither row names a secret or project on a column the caller
// could see (their own dashboard activity, a project-filtered view).
func TestSecretValueReadDenials_ForbiddenAndNotFoundAuditedWithoutAnOracle(t *testing.T) {
	for _, skip := range []bool{false, true} {
		t.Run(fmt.Sprintf("insecure_audit_skip_reads=%v", skip), func(t *testing.T) {
			w := buildDenialWorld(t, skip)
			for _, route := range outsiderRoutes() {
				for _, principal := range route.principals {
					t.Run(route.name+"/"+principal, func(t *testing.T) {
						token := w.tokens[principal]
						mark := lastAuditID(t, w.guardParityWorld)
						forbidden := route.existing(t, w, token)
						missing := route.missing(t, w, token)
						require.False(t, forbidden.ok)
						require.False(t, missing.ok)
						assert.Equal(t, forbidden.restCode, missing.restCode, "status must not tell missing from forbidden")
						assert.Equal(t, forbidden.errCode, missing.errCode)
						assert.Equal(t, forbidden.errMsg, missing.errMsg)
						assert.Equal(t, forbidden.grpcCode, missing.grpcCode)
						assert.Equal(t, forbidden.grpcMsg, missing.grpcMsg)
						assert.NotEqual(t, codes.FailedPrecondition, forbidden.grpcCode)

						rows := refusedReadRowsAfter(t, w.guardParityWorld, mark)
						require.Len(t, rows, 2, "one row per refusal")
						assert.Equal(t, string(core.SecretReadDeniedForbidden), rows[0].diff.Reason, rows[0].row.Description)
						assert.Equal(t, string(route.missingReason), rows[1].diff.Reason, rows[1].row.Description)
						for _, r := range rows {
							assert.Equal(t, route.path, r.diff.Path)
							assert.Nil(t, r.row.SecretNodeID, "a refusal before authorization must not name the secret on a column")
							assert.Nil(t, r.row.ProjectID, "a refusal before authorization must not name the project on a column")
							if principal == "outsider-machine" {
								assert.NotNil(t, r.row.MachineIdentityID)
							} else {
								assert.NotNil(t, r.row.UserID)
							}
						}
					})
				}
			}
		})
	}
}

// The full ERRMAP-1 refusal table above is complete for the denial audit too:
// every reason class a transport can produce has a test here or in core.
func TestSecretValueReadDenials_ReasonClassesCovered(t *testing.T) {
	covered := map[core.SecretReadDenialReason]string{
		core.SecretReadDeniedForbidden: "TestSecretValueReadDenials_ForbiddenAndNotFoundAuditedWithoutAnOracle",
		core.SecretReadDeniedNotFound:  "TestSecretValueReadDenials_ForbiddenAndNotFoundAuditedWithoutAnOracle",
		// mfa_required needs a project MFA policy and an interactive session
		// without a second factor; internal_error a storage/decrypt fault.
		core.SecretReadDeniedMFARequired:   "TestSecretValueReadDenials_MFARequiredAudited",
		core.SecretReadDeniedInternalError: "core TestClassifySecretReadDenial + TestSecretReadDenial_WrittenAtBothSkipReadsSettings",
	}
	for _, sr := range stateRefusals() {
		covered[sr.reason] = "TestSecretValueReadDenials_StateRefusalsAuditedOnEveryRoute"
	}
	for _, r := range core.SecretReadDenialReasons() {
		assert.NotEmptyf(t, covered[r], "reason class %q has no transport-level test", r)
	}
}

// The project MFA policy (ADR-037) refusing an interactive session without a
// second factor is audited as mfa_required.
func TestSecretValueReadDenials_MFARequiredAudited(t *testing.T) {
	w := buildDenialWorld(t, false)
	sec := w.newSecret(t, "mfa-guarded", "MFA-PLAINTEXT", w.envID)
	require.NoError(t, w.db.Model(&models.Project{}).Where("id = ?", w.projID).Update("require_mfa", true).Error)
	mark := lastAuditID(t, w.guardParityWorld)
	got := restValueRead(w.guardParityWorld, http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d?include_value=true", sec.ID), w.tokens["session"], nil,
		func(d map[string]json.RawMessage) string { return rawString(d, "value") })
	require.False(t, got.ok, "precondition: the project MFA policy must refuse a session without a second factor (%+v)", got)
	rows := refusedReadRowsAfter(t, w.guardParityWorld, mark)
	require.Len(t, rows, 1)
	assert.Equal(t, string(core.SecretReadDeniedMFARequired), rows[0].diff.Reason)
}

// TestValueReadRoutes_AuditTheirRefusals: every transport function that reads
// a secret value (derived from the source the same way
// TestValueReadRouteFamily_IsCovered derives it, so its blind spots are the
// same and stated there) must audit its refusals. A REST handler: every
// router.go registration of it carries middleware.AuditSecretValueReadDenials
// as the FIRST middleware (outermost, so the gate's own refusals are seen). A
// gRPC method: its body calls core.WithSecretReadDenialNote.
func TestValueReadRoutes_AuditTheirRefusals(t *testing.T) {
	entry := valueReadCoreEntryPoints(t, filepath.Join("..", "..", "internal", "core"))
	callers := valueReadTransportFunctions(t, "..", entry)
	require.Contains(t, callers, "SecretHandler.GetSecret", "derivation sanity")
	require.Contains(t, callers, "SecretGRPCService.GetSecretValue", "derivation sanity")

	handlers := map[string]bool{}
	for fn := range callers {
		if recv, method, ok := strings.Cut(fn, "."); ok && strings.HasSuffix(recv, "Handler") {
			handlers[method] = true
		}
	}
	regs := routerRegistrationsWithMiddleware(t, "router.go")
	seen := map[string]int{}
	for _, reg := range regs {
		if !handlers[reg.handler] {
			continue
		}
		seen[reg.handler]++
		assert.Truef(t, reg.firstMiddleware == "AuditSecretValueReadDenials",
			"router.go:%d registers value-read handler %s without customMiddleware.AuditSecretValueReadDenials as its first middleware (got %q): its refusals would not be audited (#3273)",
			reg.line, reg.handler, reg.firstMiddleware)
	}
	for h := range handlers {
		assert.Positivef(t, seen[h], "value-read handler %s has no router.go registration the guard can see", h)
	}

	grpcBodies := functionBodiesCalling(t, filepath.Join("..", "grpc"), "WithSecretReadDenialNote")
	for fn := range callers {
		if recv, _, ok := strings.Cut(fn, "."); ok && strings.HasSuffix(recv, "GRPCService") {
			assert.Truef(t, grpcBodies[fn], "gRPC value read %s does not call core.WithSecretReadDenialNote: its refusals would not be audited (#3273)", fn)
		}
	}
}

type routerRegistration struct {
	handler         string
	firstMiddleware string
	line            int
}

// routerRegistrationsWithMiddleware finds every r.With(mw...).Method(path, x.Handler)
// and plain r.Method(path, x.Handler) in router.go, with the first middleware's
// function name ("" when none).
func routerRegistrationsWithMiddleware(t *testing.T, path string) []routerRegistration {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	require.NoError(t, err)
	methods := map[string]bool{"Get": true, "Post": true, "Put": true, "Patch": true, "Delete": true, "Head": true, "Options": true, "Method": true}
	var out []routerRegistration
	ast.Inspect(f, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := ce.Fun.(*ast.SelectorExpr)
		if !ok || !methods[sel.Sel.Name] || len(ce.Args) < 2 {
			return true
		}
		h, ok := ce.Args[len(ce.Args)-1].(*ast.SelectorExpr)
		if !ok {
			return true
		}
		reg := routerRegistration{handler: h.Sel.Name, line: fset.Position(ce.Pos()).Line}
		if with, ok := sel.X.(*ast.CallExpr); ok {
			if ws, ok := with.Fun.(*ast.SelectorExpr); ok && ws.Sel.Name == "With" && len(with.Args) > 0 {
				if mw, ok := with.Args[0].(*ast.CallExpr); ok {
					if ms, ok := mw.Fun.(*ast.SelectorExpr); ok {
						reg.firstMiddleware = ms.Sel.Name
					}
				}
			}
		}
		out = append(out, reg)
		return true
	})
	return out
}

// functionBodiesCalling returns "Recv.Func" for every non-test function under
// root whose body calls a function or method named name.
func functionBodiesCalling(t *testing.T, root, name string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, rerr := os.ReadFile(path)
		if rerr != nil || !bytes.Contains(src, []byte(name)) {
			return rerr
		}
		f, perr := parser.ParseFile(token.NewFileSet(), path, src, 0)
		if perr != nil {
			return perr
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			fn := fd.Name.Name
			if fd.Recv != nil && len(fd.Recv.List) == 1 {
				typ := fd.Recv.List[0].Type
				if st, ok := typ.(*ast.StarExpr); ok {
					typ = st.X
				}
				if id, ok := typ.(*ast.Ident); ok {
					fn = id.Name + "." + fn
				}
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if ce, ok := n.(*ast.CallExpr); ok {
					if s, ok := ce.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == name {
						out[fn] = true
					}
				}
				return true
			})
		}
		return nil
	})
	require.NoError(t, err)
	return out
}
