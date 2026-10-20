// owed_audit_split_ops_test.go -- the owed-audit rule for the SPLIT ops (MERGE-FIX-3482G;
// Andrei 2026-10-20, ask 3482-mixed-request-rule (a)).
//
// WHAT HAPPENS. A request that narrows access and also widens it is applied as two
// commits (internal/core/audit_split.go): the narrowing first, its row owed (never
// blocked by the audit log), then the rest fail closed. If the second commit fails, the
// first stands and the transport answers 503 / SCIM 503 / gRPC Unavailable with a body
// that says machine-readably which half was applied. No opCatalog op sends a mixed
// request (the catalog scenarios each change one thing), so the fuzzer never reaches
// this shape; the scenarios below drive it through the real HTTP, SCIM and gRPC stack.
// They are not opCatalog entries on purpose: appending ops re-points legacy seeds
// (opcatalog_order_golden_test.go).
//
// THE RULE (owedAuditSplitVerdict), for one run of a mixed request with one fault on
// LogAuditEvent:
//
//   - SUCCESS: the non-audit tables equal the fault-free MIXED reference; every owed
//     row (owedAuditSplitExpectedOwedTypes) is written or queued exactly once; nothing
//     else is queued; after the backfill nothing is pending and the state still equals
//     the mixed reference.
//   - PARTIAL (the second commit failed): the body must carry code
//     mutation_partially_applied, revocation_applied=true, remainder_applied=false,
//     retry_safe=true. The non-audit tables must equal the fault-free NARROW-ONLY
//     reference (the narrowing applied, none of the rest) and differ from the
//     pre-request state; the second commit's row must be absent; every owed row is
//     written or queued exactly once (a missing one is the "NOT queued" gap: a
//     violation, Andrei 2026-10-20). After the backfill nothing is pending; a retry
//     of the same request then succeeds and reaches the mixed reference.
//   - Any other failure must have changed nothing and queued nothing.
//
// The calibration (TestOwedAuditSplit_Calibration) shows the verdict red on each way a
// partial apply can be wrong, built from a real partial run: the owed row neither
// written nor queued (both audit writes failed), the second commit's effect present,
// the narrowing missing, and a body that does not say which half was applied.
package faultops

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// splitOutcome is a mixed request's transport-level answer.
type splitOutcome struct {
	success bool
	partial bool              // 503 / Unavailable with the partial-apply marker
	details map[string]string // the machine-readable fields, as strings
	detail  string
}

// splitScenario is one mixed request, plus the narrowing part sent alone (the
// reference a partial apply must equal).
type splitScenario struct {
	key   string
	setup func(ctx context.Context, w *faultWorld) (any, error)
	mixed func(ctx context.Context, w *faultWorld, state any) (splitOutcome, error)
	// narrow sends only the narrowing part; it must succeed unfaulted.
	narrow func(ctx context.Context, w *faultWorld, state any) (opResult, error)
	// rest identifies the second commit's audit row (event type + description fragment).
	restType, restDesc string
	// refIgnore lists tables a second world can never equal (a random one-time password).
	refIgnore []string
	// retryRefusedBy, when set, is the error type with which a retry after a partial
	// apply is REFUSED by design, changing nothing: the narrowing itself gates the
	// actor (a project that now requires MFA refuses a rename from an admin without a
	// second factor: ProjectMFARequired). Any other retry must succeed.
	retryRefusedBy string
}

// owedAuditSplitExpectedOwedTypes is the split ops' PINNED owed table (as
// owedAuditExpectedOwedTypes for the plain revocations): the rows the narrowing commit
// owes. Changing an entry is a decision about what a revocation owes the audit log.
var owedAuditSplitExpectedOwedTypes = map[string]map[string]int{
	"REST PUT /api/v1/users/{id} [deactivate+email]":                 {"user.updated": 1},
	"GRPC keyorix.v1.UserService.UpdateUser [deactivate+username]":   {"user.updated": 1},
	"REST PUT /scim/v2/Users/{id} [active=false+email]":              {"scim.user_updated": 1},
	"REST PATCH /scim/v2/Groups/{id} [remove+add]":                   {"scim.group_updated": 1},
	"REST PUT /scim/v2/Groups/{id} [remove+rename]":                  {"scim.group_updated": 1},
	"REST PUT /api/v1/projects/{id} [mfa-on+rename]":                 {"project.mfa_requirement_enabled": 1},
	"GRPC keyorix.v1.ProjectService.UpdateProject [mfa-on+rename]":   {"project.mfa_requirement_enabled": 1},
	"REST POST /api/v1/users/{id}/reissue-one-time-password [split]": {"user.one_time_password_reissue_restricted": 1},
	// Item 3: the rotation's revoke of the old credential.
	"REST POST /api/v1/projects/{id}/machine-identities/{machineId}/tokens [rotate]": {"machine_identity.token_revoked": 1},
}

func splitHTTPOutcome(st int, body []byte) splitOutcome {
	out := splitOutcome{success: st/100 == 2, detail: fmt.Sprintf("HTTP %d: %s", st, body)}
	if st != http.StatusServiceUnavailable {
		return out
	}
	var b struct {
		Error   string         `json:"error"`
		Details map[string]any `json:"details"`
	}
	if json.Unmarshal(body, &b) == nil && b.Error == core.PartialMutationErrorType {
		out.partial, out.details = true, stringify(b.Details)
	}
	return out
}

func splitSCIMOutcome(st int, body []byte) splitOutcome {
	out := splitOutcome{success: st/100 == 2, detail: fmt.Sprintf("HTTP %d: %s", st, body)}
	if st != http.StatusServiceUnavailable {
		return out
	}
	const ext = "urn:keyorix:params:scim:api:messages:2.0:PartialMutation"
	var b map[string]json.RawMessage
	if json.Unmarshal(body, &b) != nil {
		return out
	}
	var schemas []string
	var d map[string]any
	if json.Unmarshal(b["schemas"], &schemas) == nil && json.Unmarshal(b[ext], &d) == nil &&
		len(schemas) == 2 && schemas[0] == "urn:ietf:params:scim:api:messages:2.0:Error" && schemas[1] == ext {
		out.partial, out.details = true, stringify(d)
	}
	return out
}

func splitGRPCOutcome(err error) splitOutcome {
	if err == nil {
		return splitOutcome{success: true, detail: codes.OK.String()}
	}
	st := status.Convert(err)
	out := splitOutcome{detail: st.Code().String() + ": " + st.Message()}
	if st.Code() != codes.Unavailable {
		return out
	}
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetReason() == core.PartialMutationErrorType {
			out.partial, out.details = true, info.GetMetadata()
		}
	}
	return out
}

func stringify(m map[string]any) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		out[k] = fmt.Sprint(v)
	}
	return out
}

// splitDetailsOK reports whether a partial answer says machine-readably which half was applied.
func splitDetailsOK(d map[string]string) bool {
	return d["code"] == core.PartialMutationErrorCode && d["revocation_applied"] == "true" &&
		d["remainder_applied"] == "false" && d["retry_safe"] == "true" && d["applied"] != "" && d["not_applied"] != ""
}

func splitScenarios() []splitScenario {
	type ids struct{ a, b uint }
	scimPatch := func(ops ...map[string]any) map[string]any {
		return map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"}, "Operations": ops}
	}
	scimGroupWithMember := func(ctx context.Context, w *faultWorld, name string) (any, error) {
		g, err := createGroupForFuzz(ctx, w, name)
		if err != nil {
			return nil, err
		}
		a, err := createSCIMUserForFuzz(ctx, w, name+"-a")
		if err != nil {
			return nil, err
		}
		b, err := createSCIMUserForFuzz(ctx, w, name+"-b")
		if err != nil {
			return nil, err
		}
		st, body, err := scimJSON(ctx, w, http.MethodPatch, fmt.Sprintf("/scim/v2/Groups/%d", g), scimPatch(
			map[string]any{"op": "add", "path": "members", "value": []map[string]any{{"value": fmt.Sprint(a)}}}))
		if err != nil {
			return nil, err
		}
		if st/100 != 2 {
			return nil, fmt.Errorf("setup SCIM add member: HTTP %d: %s", st, body)
		}
		return [2]any{g, ids{a, b}}, nil
	}
	userPut := func(body map[string]any) func(ctx context.Context, w *faultWorld, state any) (int, []byte, error) {
		return func(ctx context.Context, w *faultWorld, state any) (int, []byte, error) {
			return httpJSON(ctx, w, http.MethodPut, fmt.Sprintf("/api/v1/users/%d", state.(uint)), body)
		}
	}
	projectPut := func(name string) func(ctx context.Context, w *faultWorld, state any) (int, []byte, error) {
		return func(ctx context.Context, w *faultWorld, state any) (int, []byte, error) {
			return httpJSON(ctx, w, http.MethodPut, fmt.Sprintf("/api/v1/projects/%d", state.(uint)), map[string]any{
				"name": name, "description": "", "require_mfa": true,
			})
		}
	}
	asOutcome := func(f func(ctx context.Context, w *faultWorld, state any) (int, []byte, error), scim bool) func(ctx context.Context, w *faultWorld, state any) (splitOutcome, error) {
		return func(ctx context.Context, w *faultWorld, state any) (splitOutcome, error) {
			st, body, err := f(ctx, w, state)
			if err != nil {
				return splitOutcome{}, err
			}
			if scim {
				return splitSCIMOutcome(st, body), nil
			}
			return splitHTTPOutcome(st, body), nil
		}
	}
	asResult := func(f func(ctx context.Context, w *faultWorld, state any) (int, []byte, error)) func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
		return func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
			st, body, err := f(ctx, w, state)
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		}
	}
	grpcUpdateUser := func(username string) func(ctx context.Context, w *faultWorld, state any) error {
		return func(ctx context.Context, w *faultWorld, state any) error {
			off := false
			req := &pb.UpdateUserRequest{Id: uint32(state.(uint)), Active: &off}
			if username != "" {
				req.Username = &username
			}
			_, err := pb.NewUserServiceClient(w.grpcConn).UpdateUser(w.grpcCtx, req)
			return err
		}
	}
	grpcUpdateProject := func(name string) func(ctx context.Context, w *faultWorld, state any) error {
		return func(ctx context.Context, w *faultWorld, state any) error {
			on := true
			_, err := pb.NewProjectServiceClient(w.grpcConn).UpdateProject(w.grpcCtx, &pb.UpdateProjectRequest{
				Id: uint32(state.(uint)), Name: name, RequireMfa: &on,
			})
			return err
		}
	}
	grpcResult := func(err error) opResult {
		if err != nil {
			return opResult{Detail: status.Convert(err).Code().String() + ": " + err.Error()}
		}
		return opResult{Success: true, Detail: codes.OK.String()}
	}
	scimGroupPath := func(state any) string { return fmt.Sprintf("/scim/v2/Groups/%d", state.([2]any)[0].(uint)) }
	member := func(id uint) []map[string]any { return []map[string]any{{"value": fmt.Sprint(id)}} }

	return []splitScenario{
		{
			key: "REST PUT /api/v1/users/{id} [deactivate+email]",
			setup: func(ctx context.Context, w *faultWorld) (any, error) {
				return createUserForFuzz(ctx, w, "fuzz-split-user")
			},
			mixed:    asOutcome(userPut(map[string]any{"active": false, "email": "fuzz-split-user-new@example.com"}), false),
			narrow:   asResult(userPut(map[string]any{"active": false})),
			restType: "user.updated", restDesc: "updated user",
		},
		{
			key: "GRPC keyorix.v1.UserService.UpdateUser [deactivate+username]",
			setup: func(ctx context.Context, w *faultWorld) (any, error) {
				return createUserForFuzz(ctx, w, "fuzz-split-grpc-user")
			},
			mixed: func(ctx context.Context, w *faultWorld, state any) (splitOutcome, error) {
				return splitGRPCOutcome(grpcUpdateUser("fuzz-split-grpc-renamed")(ctx, w, state)), nil
			},
			narrow: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
				return grpcResult(grpcUpdateUser("")(ctx, w, state)), nil
			},
			restType: "user.updated", restDesc: "updated user",
		},
		{
			key: "REST PUT /scim/v2/Users/{id} [active=false+email]",
			setup: func(ctx context.Context, w *faultWorld) (any, error) {
				return createSCIMUserForFuzz(ctx, w, "fuzz-split-scim-user")
			},
			mixed: asOutcome(func(ctx context.Context, w *faultWorld, state any) (int, []byte, error) {
				return scimJSON(ctx, w, http.MethodPut, fmt.Sprintf("/scim/v2/Users/%d", state.(uint)), map[string]any{
					"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
					"userName": "fuzz-split-scim-user-new@example.com", "active": false,
					"emails": []map[string]any{{"value": "fuzz-split-scim-user-new@example.com", "primary": true}},
				})
			}, true),
			narrow: asResult(func(ctx context.Context, w *faultWorld, state any) (int, []byte, error) {
				return scimJSON(ctx, w, http.MethodPatch, fmt.Sprintf("/scim/v2/Users/%d", state.(uint)),
					scimPatch(map[string]any{"op": "replace", "path": "active", "value": false}))
			}),
			restType: "scim.user_updated", restDesc: "SCIM updated user",
		},
		{
			key: "REST PATCH /scim/v2/Groups/{id} [remove+add]",
			setup: func(ctx context.Context, w *faultWorld) (any, error) {
				return scimGroupWithMember(ctx, w, "fuzz-split-patch")
			},
			mixed: asOutcome(func(ctx context.Context, w *faultWorld, state any) (int, []byte, error) {
				m := state.([2]any)[1].(ids)
				return scimJSON(ctx, w, http.MethodPatch, scimGroupPath(state), scimPatch(
					map[string]any{"op": "remove", "path": "members", "value": member(m.a)},
					map[string]any{"op": "add", "path": "members", "value": member(m.b)}))
			}, true),
			narrow: asResult(func(ctx context.Context, w *faultWorld, state any) (int, []byte, error) {
				m := state.([2]any)[1].(ids)
				return scimJSON(ctx, w, http.MethodPatch, scimGroupPath(state), scimPatch(
					map[string]any{"op": "remove", "path": "members", "value": member(m.a)}))
			}),
			restType: "scim.group_updated", restDesc: "(+1",
		},
		{
			key: "REST PUT /scim/v2/Groups/{id} [remove+rename]",
			setup: func(ctx context.Context, w *faultWorld) (any, error) {
				return scimGroupWithMember(ctx, w, "fuzz-split-put")
			},
			mixed: asOutcome(func(ctx context.Context, w *faultWorld, state any) (int, []byte, error) {
				return scimJSON(ctx, w, http.MethodPut, scimGroupPath(state), map[string]any{
					"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Group"}, "displayName": "fuzz-split-put-renamed", "members": []map[string]any{},
				})
			}, true),
			narrow: asResult(func(ctx context.Context, w *faultWorld, state any) (int, []byte, error) {
				return scimJSON(ctx, w, http.MethodPut, scimGroupPath(state), map[string]any{
					"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Group"}, "displayName": "fuzz-split-put", "members": []map[string]any{},
				})
			}),
			restType: "scim.group_updated", restDesc: "(members=",
		},
		{
			key: "REST PUT /api/v1/projects/{id} [mfa-on+rename]",
			setup: func(ctx context.Context, w *faultWorld) (any, error) {
				return createProjectForFuzz(ctx, w, "fuzz-split-project")
			},
			mixed:          asOutcome(projectPut("fuzz-split-project-renamed"), false),
			narrow:         asResult(projectPut("fuzz-split-project")),
			restType:       "project.updated",
			retryRefusedBy: "ProjectMFARequired",
		},
		{
			key: "GRPC keyorix.v1.ProjectService.UpdateProject [mfa-on+rename]",
			setup: func(ctx context.Context, w *faultWorld) (any, error) {
				return createProjectForFuzz(ctx, w, "fuzz-split-grpc-project")
			},
			mixed: func(ctx context.Context, w *faultWorld, state any) (splitOutcome, error) {
				return splitGRPCOutcome(grpcUpdateProject("fuzz-split-grpc-project-renamed")(ctx, w, state)), nil
			},
			narrow: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
				return grpcResult(grpcUpdateProject("fuzz-split-grpc-project")(ctx, w, state)), nil
			},
			restType:       "project.updated",
			retryRefusedBy: "multi-factor authentication",
		},
		{
			key: "REST POST /api/v1/users/{id}/reissue-one-time-password [split]",
			setup: func(ctx context.Context, w *faultWorld) (any, error) {
				return createUserForFuzz(ctx, w, "fuzz-split-otp")
			},
			mixed: asOutcome(func(ctx context.Context, w *faultWorld, state any) (int, []byte, error) {
				return httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/reissue-one-time-password", state.(uint)), nil)
			}, false),
			narrow: asResult(func(ctx context.Context, w *faultWorld, state any) (int, []byte, error) {
				return httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/users/%d/require-password-reset", state.(uint)), nil)
			}),
			restType: "user.one_time_password_reissued",
			// The one-time password is random: no second world has the same hash, expiry
			// or history row. The user's account state is still compared (narrow case).
			refIgnore: []string{"User", "PasswordHistory"},
		},
		{
			// Item 3 (ask perf-cred-lookup-1-rotation-audit-gated (b)): rotation revokes the
			// old credential (owed) and issues the new one (fail closed). The narrow-only
			// reference is the plain revoke.
			key: "REST POST /api/v1/projects/{id}/machine-identities/{machineId}/tokens [rotate]",
			setup: func(ctx context.Context, w *faultWorld) (any, error) {
				m, err := createMachineIdentityForFuzz(ctx, w, 1)
				if err != nil {
					return nil, err
				}
				cred, err := issueMachineTokenForFuzz(ctx, w, 1, m)
				if err != nil {
					return nil, err
				}
				return [2]uint{m, cred}, nil
			},
			mixed: asOutcome(func(ctx context.Context, w *faultWorld, state any) (int, []byte, error) {
				ids := state.([2]uint)
				return httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/projects/1/machine-identities/%d/tokens", ids[0]), map[string]any{
					"name": "fuzz-rotated", "expires_in_days": 90, "replace_credential_id": ids[1],
				})
			}, false),
			narrow: asResult(func(ctx context.Context, w *faultWorld, state any) (int, []byte, error) {
				ids := state.([2]uint)
				return httpJSON(ctx, w, http.MethodDelete, fmt.Sprintf("/api/v1/projects/1/machine-identities/%d/tokens/%d", ids[0], ids[1]), nil)
			}),
			restType: "machine_identity.token_rotated",
			// The new token is random, so its credential row never equals another world's.
			// The partial case still compares it (the narrow-only state has no new row).
			refIgnore: []string{"MachineIdentityCredential"},
		},
	}
}

// splitRows is the audit and pending rows a run added, keyed by event type, with the
// second commit's rows counted apart.
type splitRows struct {
	owedAudit, owedPending map[string]int
	restAudit, restPending int
}

func splitRowsOf(before, after dbSnapshot, sc splitScenario) (splitRows, error) {
	out := splitRows{owedAudit: map[string]int{}, owedPending: map[string]int{}}
	isRest := func(eventType, desc string) bool {
		return eventType == sc.restType && strings.Contains(desc, sc.restDesc)
	}
	seen := map[string]int{}
	for _, r := range before.Tables[owedAuditAuditTable].Rows {
		seen[r]++
	}
	for _, r := range after.Tables[owedAuditAuditTable].Rows {
		if seen[r] > 0 {
			seen[r]--
			continue
		}
		var e struct{ EventType, Description string }
		if err := json.Unmarshal([]byte(r), &e); err != nil {
			return out, err
		}
		if isRest(e.EventType, e.Description) {
			out.restAudit++
		} else {
			out.owedAudit[e.EventType]++
		}
	}
	for _, r := range after.Tables[owedAuditPendingTable].Rows {
		var rec struct{ Event string }
		if err := json.Unmarshal([]byte(r), &rec); err != nil {
			return out, err
		}
		var ev models.AuditEvent
		if err := json.Unmarshal([]byte(rec.Event), &ev); err != nil {
			return out, err
		}
		if isRest(ev.EventType, ev.Description) {
			out.restPending++
		} else {
			out.owedPending[ev.EventType]++
		}
	}
	return out, nil
}

// splitInput is one judged run.
type splitInput struct {
	sc                                splitScenario
	owed                              map[string]int
	before, after, refNarrow, refMixd dbSnapshot
	out                               splitOutcome
	// converge removes the fault and backfills (nil: not run, which fails the rule closed).
	converge func() (dbSnapshot, error)
	// retry sends the same mixed request again, unfaulted, and snapshots (nil: not run).
	retry func() (splitOutcome, dbSnapshot, error)
}

// owedAuditSplitVerdict applies the split rule (file comment). Empty means accepted.
func owedAuditSplitVerdict(in splitInput) string {
	nonAudit := func(s dbSnapshot, extra ...string) string {
		return hashExcluding(s, append([]string{owedAuditAuditTable, owedAuditPendingTable}, extra...)...)
	}
	rows, err := splitRowsOf(in.before, in.after, in.sc)
	if err != nil {
		return fmt.Sprintf("audit/pending rows cannot be decoded: %v", err)
	}
	// Owed rows: each one exactly once, written or queued; nothing else queued.
	owedOnce := func() string {
		for t, n := range in.owed {
			if got := rows.owedAudit[t] + rows.owedPending[t]; got != n {
				return fmt.Sprintf("owed %q: %d written + %d queued, the narrowing owes %d (a missing one is the NOT-queued gap)",
					t, rows.owedAudit[t], rows.owedPending[t], n)
			}
		}
		for t, n := range rows.owedPending {
			if in.owed[t] == 0 && n > 0 {
				return fmt.Sprintf("%d pending row(s) of %q, which the narrowing does not owe", n, t)
			}
		}
		return ""
	}
	switch {
	case in.out.success:
		if nonAudit(in.after, in.sc.refIgnore...) != nonAudit(in.refMixd, in.sc.refIgnore...) {
			return fmt.Sprintf("success, but the state differs from the mixed reference in %v", diffTables(in.refMixd, in.after))
		}
		if v := owedOnce(); v != "" {
			return "success: " + v
		}
		if rows.restAudit != 1 || rows.restPending != 0 {
			return fmt.Sprintf("success: the second commit's row must be written once in its transaction (written %d, queued %d)", rows.restAudit, rows.restPending)
		}
	case in.out.partial:
		if !splitDetailsOK(in.out.details) {
			return fmt.Sprintf("partial apply, but the answer does not say machine-readably which half was applied: %v", in.out.details)
		}
		if nonAudit(in.after) != nonAudit(in.refNarrow) {
			return fmt.Sprintf("partial apply, but the state is not the narrowing alone (differs from the narrow-only reference in %v)", diffTables(in.refNarrow, in.after))
		}
		if nonAudit(in.after) == nonAudit(in.before) {
			return "partial apply reported, but the narrowing is not visible in the state"
		}
		if rows.restAudit+rows.restPending != 0 {
			return fmt.Sprintf("partial apply, but the second commit's row exists (written %d, queued %d)", rows.restAudit, rows.restPending)
		}
		if v := owedOnce(); v != "" {
			return "partial apply: " + v
		}
	default:
		if nonAudit(in.after) != nonAudit(in.before) || len(in.after.Tables[owedAuditPendingTable].Rows) != len(in.before.Tables[owedAuditPendingTable].Rows) {
			return fmt.Sprintf("failed without a partial-apply answer (%s) but changed state in %v", in.out.detail, diffTables(in.before, in.after))
		}
		return ""
	}
	if in.converge == nil {
		return "the backfill was not run, so convergence is unproven"
	}
	got, err := in.converge()
	if err != nil {
		return fmt.Sprintf("the backfill did not complete: %v", err)
	}
	if n := len(got.Tables[owedAuditPendingTable].Rows); n != 0 {
		return fmt.Sprintf("%d pending row(s) left after the backfill", n)
	}
	if !in.out.partial {
		return ""
	}
	if in.retry == nil {
		return "the retry was not run, so retry safety is unproven"
	}
	out, snap, err := in.retry()
	if err != nil {
		return fmt.Sprintf("the retry failed to run: %v", err)
	}
	if !out.success && in.sc.retryRefusedBy != "" && strings.Contains(out.detail, in.sc.retryRefusedBy) {
		// Refused by the narrowing's own gate: safe only if it changed nothing.
		if hashExcluding(snap, owedAuditAuditTable, owedAuditPendingTable) != hashExcluding(got, owedAuditAuditTable, owedAuditPendingTable) {
			return fmt.Sprintf("the retry was refused (%s) but changed state in %v", out.detail, diffTables(got, snap))
		}
		return ""
	}
	if !out.success {
		return fmt.Sprintf("a retry of the same request after a partial apply must succeed: %s", out.detail)
	}
	if nonAudit(snap, in.sc.refIgnore...) != nonAudit(in.refMixd, in.sc.refIgnore...) {
		return fmt.Sprintf("after the retry the state differs from the mixed reference in %v", diffTables(in.refMixd, snap))
	}
	return ""
}

// splitRun is one faulted run of a scenario and what the verdict needs.
type splitRun struct {
	w     *faultWorld
	state any
	in    splitInput
	fired bool
}

func splitReference(t *testing.T, sc splitScenario, narrowOnly bool) dbSnapshot {
	t.Helper()
	ctx := context.Background()
	w := newFaultWorld(t, nil)
	state, err := sc.setup(ctx, w)
	require.NoError(t, err, "setup (reference)")
	drainAllBackgroundGoroutines()
	if narrowOnly {
		res, err := sc.narrow(ctx, w, state)
		require.NoError(t, err)
		require.True(t, res.Success, "narrow-only reference of %s failed: %s", sc.key, res.Detail)
	} else {
		out, err := sc.mixed(ctx, w, state)
		require.NoError(t, err)
		require.True(t, out.success, "mixed reference of %s failed: %s", sc.key, out.detail)
	}
	drainAllBackgroundGoroutines()
	snap, err := snapshotDB(w.db)
	require.NoError(t, err)
	return snap
}

func runSplitFaulted(t *testing.T, sc splitScenario, spec *faultstorage.FaultSpec, refNarrow, refMixed dbSnapshot) splitRun {
	t.Helper()
	ctx := context.Background()
	w := newFaultWorld(t, nil)
	state, err := sc.setup(ctx, w)
	require.NoError(t, err, "setup")
	drainAllBackgroundGoroutines()
	before, err := snapshotDB(w.db)
	require.NoError(t, err)
	w.faulty.Arm(spec)
	out, err := sc.mixed(ctx, w, state)
	fired := w.faulty.Fired()
	w.faulty.Arm(nil)
	drainAllBackgroundGoroutines()
	require.NoError(t, err, "transport error")
	after, err := snapshotDB(w.db)
	require.NoError(t, err)
	return splitRun{w: w, state: state, fired: fired, in: splitInput{
		sc: sc, owed: owedAuditSplitExpectedOwedTypes[sc.key], before: before, after: after,
		refNarrow: refNarrow, refMixd: refMixed, out: out,
		converge: owedAuditConvergeFor(w),
		retry: func() (splitOutcome, dbSnapshot, error) {
			o, rerr := sc.mixed(ctx, w, state)
			if rerr != nil {
				return o, dbSnapshot{}, rerr
			}
			drainAllBackgroundGoroutines()
			s, serr := snapshotDB(w.db)
			return o, s, serr
		},
	}}
}

// TestOwedAuditSplit_SweepEverySplitOp refuses LogAuditEvent#1, #2, ... (until the
// fault no longer fires) on every split scenario and judges each run. Each scenario
// must show both shapes (an owed row queued after a success, and a partial apply), and
// the union of what got queued must equal the pinned owed table.
func TestOwedAuditSplit_SweepEverySplitOp(t *testing.T) {
	scs := splitScenarios()
	require.Len(t, owedAuditSplitExpectedOwedTypes, len(scs), "every split scenario has a pinned owed-types entry and vice versa")
	for _, sc := range scs {
		t.Run(sc.key, func(t *testing.T) {
			require.Contains(t, owedAuditSplitExpectedOwedTypes, sc.key)
			refNarrow, refMixed := splitReference(t, sc, true), splitReference(t, sc, false)
			queued := map[string]int{}
			var partials, queuedSuccesses int
			for nth := 1; ; nth++ {
				r := runSplitFaulted(t, sc, &faultstorage.FaultSpec{Method: "LogAuditEvent", NthCall: nth, Kind: faultstorage.KindError, Err: errFuzzInjected}, refNarrow, refMixed)
				if !r.fired {
					require.Greater(t, nth, 1, "%s never appended an audit row", sc.key)
					break
				}
				rows, err := splitRowsOf(r.in.before, r.in.after, sc)
				require.NoError(t, err)
				for k, n := range rows.owedPending {
					queued[k] = max(queued[k], n)
				}
				if r.in.out.partial {
					partials++
				} else if r.in.out.success && len(rows.owedPending) > 0 {
					queuedSuccesses++
				}
				// A refused append is the audit log failing: the verdict's plain-failure branch
				// (nothing changed) would accept it, but here that is the audit log blocking
				// the narrowing (REVIEW-3482B). Every refused append must end in a success
				// (owed row queued) or a partial apply.
				require.True(t, r.in.out.success || r.in.out.partial,
					"%s with LogAuditEvent#%d refused failed as a whole (%s): the audit log blocked the narrowing", sc.key, nth, r.in.out.detail)
				v := owedAuditSplitVerdict(r.in)
				require.Empty(t, v, "%s with LogAuditEvent#%d refused (%s): %s", sc.key, nth, r.in.out.detail, v)
				t.Logf("LogAuditEvent#%d refused: success=%t partial=%t details=%v queued=%v", nth, r.in.out.success, r.in.out.partial, r.in.out.details, rows.owedPending)
			}
			require.Positive(t, partials, "%s: no refused append produced a partial apply -- the split is not exercised", sc.key)
			require.Positive(t, queuedSuccesses, "%s: no refused append queued the owed row of a successful request", sc.key)
			require.Equal(t, owedAuditSplitExpectedOwedTypes[sc.key], queued,
				"%s: what the narrowing owes (probed) must equal the pinned table", sc.key)
		})
	}
}

// TestOwedAuditSplit_Calibration: the verdict accepts a real partial apply and is red on
// each way it can be wrong. Built from the user deactivate+email scenario.
func TestOwedAuditSplit_Calibration(t *testing.T) {
	sc := splitScenarios()[0]
	refNarrow, refMixed := splitReference(t, sc, true), splitReference(t, sc, false)
	// LogAuditEvent#2 is the second commit's append (the first is the owed row's).
	partialRun := func() splitRun {
		r := runSplitFaulted(t, sc, &faultstorage.FaultSpec{Method: "LogAuditEvent", NthCall: 2, Kind: faultstorage.KindError, Err: errFuzzInjected}, refNarrow, refMixed)
		require.True(t, r.in.out.partial, "precondition: a partial apply (%s)", r.in.out.detail)
		return r
	}
	queuedRun := func() splitRun {
		r := runSplitFaulted(t, sc, &faultstorage.FaultSpec{Method: "LogAuditEvent", NthCall: 1, Kind: faultstorage.KindError, Err: errFuzzInjected}, refNarrow, refMixed)
		require.True(t, r.in.out.success, "precondition: success with the owed row queued (%s)", r.in.out.detail)
		return r
	}

	t.Run("green/partial-apply", func(t *testing.T) {
		require.Empty(t, owedAuditSplitVerdict(partialRun().in))
	})
	t.Run("green/success-owed-row-queued", func(t *testing.T) {
		require.Empty(t, owedAuditSplitVerdict(queuedRun().in))
	})
	t.Run("red/owed-row-neither-written-nor-queued", func(t *testing.T) {
		// The record AND the append failed: the owed row is gone (the NOT-queued gap).
		r := queuedRun()
		require.NoError(t, r.w.db.Where("1 = 1").Delete(&models.PendingAuditEvent{}).Error)
		after, err := snapshotDB(r.w.db)
		require.NoError(t, err)
		r.in.after = after
		require.Contains(t, owedAuditSplitVerdict(r.in), "NOT-queued gap")
	})
	t.Run("red/partial-but-second-commit-applied", func(t *testing.T) {
		r := partialRun()
		r.in.after = refMixed
		require.NotEmpty(t, owedAuditSplitVerdict(r.in))
	})
	t.Run("red/partial-but-narrowing-missing", func(t *testing.T) {
		r := partialRun()
		r.in.after = r.in.before
		require.NotEmpty(t, owedAuditSplitVerdict(r.in))
	})
	t.Run("red/partial-not-machine-readable", func(t *testing.T) {
		r := partialRun()
		r.in.out.details = map[string]string{"code": core.PartialMutationErrorCode, "revocation_applied": "true"}
		require.Contains(t, owedAuditSplitVerdict(r.in), "machine-readably")
	})
	t.Run("red/failure-that-changed-state", func(t *testing.T) {
		r := partialRun()
		r.in.out = splitOutcome{detail: "HTTP 500: a plain failure"}
		require.Contains(t, owedAuditSplitVerdict(r.in), "changed state")
	})
	t.Run("red/no-backfill", func(t *testing.T) {
		r := partialRun()
		r.in.converge = nil
		require.Contains(t, owedAuditSplitVerdict(r.in), "backfill was not run")
	})
}
