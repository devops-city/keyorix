package grpc_test

// authz_walk_lowpriv_test.go — AUTHZ-WALKS-GRPC-1 item 1 (INV-GRPC-LOWPRIV-WALK).
//
// auth_interceptor_completeness_test.go proves every registered method rejects a
// call with NO credential. This walk covers the other half: every registered
// method, unary and streaming, called by an AUTHENTICATED low-privilege caller:
//
//	zero-grant-machine  a machine token whose identity holds no role at all
//	viewer-user         a user with project_viewer in a decoy project only
//	restricted-pat      a project_admin's PAT restricted to the decoy project
//	                    (the canary project is outside it)
//
// The method set comes from grpc.Server.GetServiceInfo (walkMethods), never a
// list. Each method is called with several requests whose id fields are bound to
// canary object ids (walkIDs.variants), every other field filled with a plausible
// value so the call gets past validation to its authorization decision.
//
// Oracle, per call:
//   - the status is PermissionDenied, NotFound or InvalidArgument; or OK where
//     ADR-096 Amendment 1 allows it (a zero-grant LIST/read is an EMPTY response;
//     a scoped viewer/PAT list may be non-empty but never carries the canary);
//     anything else — Internal, Unknown, FailedPrecondition, AlreadyExists, ... —
//     is a violation, and so is an OK that is neither empty nor allow-listed;
//   - no canary substring in any response field or in the status message;
//   - the content digest of every table (walkWorld.digest) is unchanged, whatever the
//     status: a rejected call that wrote anything is a violation;
//   - the audit-row count is unchanged unless the delta is allow-listed below.
//
// Methods a low-privilege caller may legitimately call, or that legitimately
// leave a trace, are in walkLowPrivAllowed with the reason; a method whose verb is
// neither read nor write fails the walk, so a new RPC must be classified.
//
// A positive control (the admin session reads) must reach the canary through at
// least walkMinControlHits read methods, so a broken fixture cannot pass.
//
// What this walk does NOT cover: field VALUES beyond ids (the protoreflect
// fuzzer, INV-GRPC-04); responses that identify canary objects by number only (a
// ShareRecord carries ids, never a name); ADMIN-level writes (not called: they
// would mutate the fixture); credentials in a dead state (item 2).

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
	grpcservices "github.com/keyorixhq/keyorix/server/grpc/services"
)

const (
	personaZeroMachine = "zero-grant-machine"
	personaViewer      = "viewer-user"
	personaPAT         = "restricted-pat"
)

// walkMinControlHits: measured when this was written (see the walk's log line);
// below that so route churn does not trip it, well above zero so a fixture that
// stops seeding the canary does.
const walkMinControlHits = 8

// walkAllowance describes one legitimate OK (or trace) for a persona.
type walkAllowance struct {
	reason string
	// audit allows the call to append audit / access-log rows, but only when the
	// call was refused (PermissionDenied / NotFound).
	audit bool
	// denyOnly: the entry exists for the refusal's side effect; an OK response
	// is still judged by the ordinary rules, not waved through.
	denyOnly bool
}

// walkLowPrivAllowed maps "service/method" -> persona -> why that persona may
// get OK from it. Anything not listed must be rejected (or be an empty read for
// the zero-grant machine). Keep every entry reasoned: a blanket entry here is the
// bypass this walk exists to catch.
var walkLowPrivAllowed = map[string]map[string]walkAllowance{
	"keyorix.v1.SystemService/HealthCheck": {
		personaZeroMachine: {reason: "public liveness probe, no data"},
		personaViewer:      {reason: "public liveness probe, no data"},
		personaPAT:         {reason: "public liveness probe, no data"},
	},
	// system.read is the universal system_viewer baseline every USER holds
	// (internal/core/auth_bootstrap_rbac_test.go; REST gates /system/info and
	// /system/metrics on the same permission), so a project viewer legitimately
	// gets these. A machine identity and a project-restricted PAT hold no
	// system.read and are still expected to be denied. NOTE for the report: the
	// metrics response carries install-wide active-secret and user COUNTS, which
	// the baseline therefore shows to every user on both transports.
	"keyorix.v1.SystemService/GetSystemInfo": {
		personaViewer: {reason: "system.read is the universal system_viewer baseline"},
	},
	"keyorix.v1.SystemService/GetMetrics": {
		personaViewer: {reason: "system.read is the universal system_viewer baseline"},
	},
	// A refused secret-value read is itself audited (audit-denied-reads-1): the
	// denial must leave a trace, so an audit row is the one expected side effect.
	"keyorix.v1.SecretService/GetSecretValue": {
		personaZeroMachine: {reason: "refusal audited (audit-denied-reads-1)", audit: true, denyOnly: true},
		personaViewer:      {reason: "refusal audited (audit-denied-reads-1)", audit: true, denyOnly: true},
		personaPAT:         {reason: "refusal audited (audit-denied-reads-1)", audit: true, denyOnly: true},
	},
}

func (a walkAllowance) String() string { return a.reason }

type walkPersona struct {
	name  string
	token string
	// zeroGrant: holds no role anywhere, so every read must be denied or empty.
	zeroGrant bool
}

func buildLowPrivPersonas(t *testing.T, w *walkWorld) []walkPersona {
	t.Helper()
	ctx := context.Background()
	c := w.core

	mi, err := c.CreateMachineIdentity(ctx, w.ids.decoyProject, "walkzero", "ci", "", "", w.adminID, 0)
	require.NoError(t, err)
	tok, err := c.IssueMachineToken(ctx, w.ids.decoyProject, mi.ID, w.adminID, core.IssueMachineTokenParams{Name: "walkzero-token"})
	require.NoError(t, err)

	mkUser := func(name string) uint {
		u, uerr := c.CreateUser(ctx, &core.CreateUserRequest{Username: name, Email: name + "@example.com", Password: walkPassword})
		require.NoError(t, uerr)
		return u.ID
	}
	viewer := mkUser("walkviewer")
	require.NoError(t, c.AddProjectMember(ctx, w.adminID, w.ids.decoyProject, viewer, "project_viewer", false))
	sess, _, err := c.Login(ctx, &core.LoginRequest{Username: "walkviewer", Password: walkPassword})
	require.NoError(t, err)

	owner := mkUser("walkpatowner")
	require.NoError(t, c.AddProjectMember(ctx, w.adminID, w.ids.canaryProject, owner, "project_admin", false))
	require.NoError(t, c.AddProjectMember(ctx, w.adminID, w.ids.decoyProject, owner, "project_admin", false))
	pat, err := c.CreateOwnPAT(ctx, owner, "walk-decoy-pat", nil, nil, w.ids.decoyProject, 0, nil)
	require.NoError(t, err)

	return []walkPersona{
		{name: personaZeroMachine, token: tok.PlainToken, zeroGrant: true},
		{name: personaViewer, token: sess.SessionToken},
		{name: personaPAT, token: pat.PlainToken},
	}
}

// lowPrivVerdict classifies one call's outcome for persona; it returns "" when
// the outcome satisfies the oracle, else why not. changed lists the tables whose
// content differs after the call, auditDelta the audit rows it appended.
func lowPrivVerdict(m walkMethod, p walkPersona, res walkResult, changed []string, auditDelta map[string]int64) string {
	var why []string
	st := status.Convert(res.err)
	allow, allowed := walkLowPrivAllowed[m.key()][p.name]

	if res.leaksCanary() || strings.Contains(st.Message(), walkCanary) {
		why = append(why, "response carries canary data")
	}
	if len(changed) > 0 {
		why = append(why, fmt.Sprintf("state changed (%s) with status %s", strings.Join(changed, ","), st.Code()))
	}
	refused := st.Code() == codes.PermissionDenied || st.Code() == codes.NotFound
	if len(auditDelta) > 0 && !(allowed && allow.audit && refused) {
		why = append(why, fmt.Sprintf("audit rows appended %v with status %s", auditDelta, st.Code()))
	}
	switch st.Code() {
	case codes.PermissionDenied, codes.NotFound, codes.InvalidArgument:
	case codes.OK:
		switch {
		case allowed && !allow.denyOnly:
		case m.isRead() && p.zeroGrant && len(res.resp) == 0:
			// ADR-096 Amendment 1: a zero-grant list/read is EMPTY, not an error.
		case m.isRead() && !p.zeroGrant && strings.HasPrefix(m.name, "List"):
			// A scoped caller's list may show its own scope; the canary check above
			// is what bounds it.
		default:
			why = append(why, fmt.Sprintf("OK (%d response bytes) is neither empty nor allow-listed for %s", len(res.resp), p.name))
		}
	default:
		why = append(why, fmt.Sprintf("status %s %q is not PermissionDenied/NotFound/InvalidArgument", st.Code(), st.Message()))
	}
	if bad, reason := classifyStatusLeak(res.err); bad {
		why = append(why, reason)
	}
	return strings.Join(why, "; ")
}

func TestEveryGRPCMethodRejectsLowPrivilegeCaller(t *testing.T) {
	forEachWalkBackend(t, func(t *testing.T, w *walkWorld) {
		personas := buildLowPrivPersonas(t, w)
		drain := func() {
			core.DrainBackgroundGoroutines()
			grpcservices.DrainBackgroundGoroutines()
		}

		// Classification gate: a verb that is neither read nor write fails.
		for _, m := range w.methods {
			if m.isRead() == m.isWrite() {
				t.Errorf("%s: cannot classify as read or write by its verb — add it to grpcReadVerbs/grpcWriteVerbs (or walkReadVerbs)", m.key())
			}
		}
		for key, byPersona := range walkLowPrivAllowed {
			found := false
			for _, m := range w.methods {
				found = found || m.key() == key
			}
			require.Truef(t, found, "walkLowPrivAllowed names %s, which is not a registered method — remove the stale entry", key)
			for persona, a := range byPersona {
				require.NotEmptyf(t, strings.TrimSpace(a.reason), "walkLowPrivAllowed[%s][%s] needs a reason", key, persona)
			}
		}

		variants := w.ids.variants()
		conn := w.dial(t)
		t.Cleanup(func() { _ = conn.Close() })

		// Positive control: the admin session (read methods only — a write would
		// mutate the fixture) must see canary data through enough methods.
		controlHits := map[string]bool{}
		for _, m := range w.methods {
			if !m.isRead() {
				continue
			}
			for _, v := range variants {
				if res := call(t, conn, m, w.admin, requestFor(m.input, v.bind)); res.leaksCanary() {
					controlHits[m.key()] = true
				}
			}
		}
		t.Logf("[%s] positive control: admin reached the canary through %d read methods", w.backend, len(controlHits))
		require.GreaterOrEqual(t, len(controlHits), walkMinControlHits,
			"the admin saw canary data through too few read methods: the fixture is not exercising the surface")
		for _, mustSee := range []string{
			"keyorix.v1.SecretService/GetSecret", "keyorix.v1.SecretService/ListSecrets", "keyorix.v1.ProjectService/ListProjects",
		} {
			require.Truef(t, controlHits[mustSee], "positive control: the admin must see canary data via %s", mustSee)
		}

		violations := map[string]bool{}
		calls := 0
		codesSeen := map[string]int{}
		pastValidation := map[string]bool{}
		drain()
		before := w.digest(t)
		for _, p := range personas {
			for _, m := range w.methods {
				for _, v := range variants {
					req := requestFor(m.input, v.bind)
					res := call(t, conn, m, p.token, req)
					drain()
					after := w.digest(t)
					codesSeen[p.name+" "+status.Code(res.err).String()]++
					if status.Code(res.err) != codes.InvalidArgument {
						pastValidation[p.name+" "+m.key()] = true
					}
					calls++
					if why := lowPrivVerdict(m, p, res, before.changedTables(after), before.auditDelta(after)); why != "" {
						violations[fmt.Sprintf("%s as %s [%s]: %s", m.key(), p.name, v.label, why)] = true
					}
					before = after
				}
			}
		}
		t.Logf("[%s] status distribution: %v", w.backend, codesSeen)
		// Not vacuous: if most methods only ever answer InvalidArgument the requests
		// are not reaching the authorization decision.
		for _, p := range personas {
			reached := 0
			for _, m := range w.methods {
				if pastValidation[p.name+" "+m.key()] {
					reached++
				}
			}
			t.Logf("[%s] %s: %d/%d methods answered with something other than InvalidArgument", w.backend, p.name, reached, len(w.methods))
			require.GreaterOrEqualf(t, reached, len(w.methods)*3/4,
				"%s: too many methods only ever answered InvalidArgument — the walk's requests are not reaching authorization", p.name)
		}
		t.Logf("[%s] low-privilege walk: %d methods x %d personas x %d request shapes = %d calls", w.backend, len(w.methods), len(personas), len(variants), calls)

		out := make([]string, 0, len(violations))
		for v := range violations {
			out = append(out, v)
		}
		sort.Strings(out)
		for _, v := range out {
			t.Errorf("AUTHZ WALK VIOLATION %s", v)
		}
	})
}
