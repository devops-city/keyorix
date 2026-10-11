// notify_recipients_guard_test.go — NOTIFY-1's family-wide guard over every
// notification emitter in internal/core (follow-up to #2955).
//
// #2955: break-glass alerts went only to project-scoped members, so an
// install-wide admin (who holds no project-scoped row) got nothing. The same
// "ListProjectMembers + isApproverRole" fan-out was copy-pasted into eight more
// notifiers (access requests, anomaly alerts, expiry / rotation / certificate /
// recertification reminders, ...). Fixing the ones that existed does not stop the
// next copy, so this guard makes the recipient set a declared, checked property:
//
//	TestNotifierRecipients_EveryEmitterDeclaresItsRecipientSet
//	  Every function that emits a notification is discovered by an AST scan and
//	  must appear in notifierRegistry with a documented recipient set (Kind +
//	  Doc). A new notifier that is not registered fails the build, and a registry
//	  entry whose function is gone fails it too (no stale declarations).
//
//	TestNotifierRecipients_DeclaredSetIsActuallyUsed
//	  Each entry's Kind is a checkable claim: a KindProjectAdmins emitter must
//	  resolve its audience through projectAdminRecipients (approver-role members
//	  PLUS active install-wide admins); a KindGlobalAdmins emitter through
//	  globalAdminIDs; a KindDeploymentChannel emitter through the notificationSink.
//
//	TestNotifierRecipients_NoDirectProjectMemberFanOut
//	  Outside the two sanctioned readers, no non-test function in the package may
//	  call ListProjectMembers. This is the exact shape that caused #2955.
//
//	TestNotifierRecipients_GuardCatchesPlantedProjectMemberOnlyNotifier
//	  Red-proof: feeds the scanner a planted notifier that only notifies project
//	  members and asserts every rule above fires; plus the green control (a
//	  notifier resolving through projectAdminRecipients passes).
//
// # What is recognised as an emitter, and why that list is complete
//
// An *ast.FuncDecl is an emitter when its body contains a call whose callee is a
// selector (any receiver spelling) named notify, notifyWithSeverity,
// notifyChecked (#3075), upgradeReminder or CreateNotification, or named Deliver on a receiver whose
// rendered text contains "otificationSink" (notificationSink and
// recipientNotificationSink are the only two sinks); or when its NAME starts with
// notify/remind + an upper-case letter, which catches a notifier that reaches the
// primitives indirectly. Those six primitives are the only ways core persists or
// dispatches a notification (notifications.go is the single place that touches
// storage.CreateNotification and the recipient sink), so an emitter that avoids
// all of them and all naming convention does not emit through core at all.
//
// What this does NOT check: that the Doc string matches docs/ prose (a human
// reads that), that KindExplicitUser recipients are the right person (they are a
// function parameter, not a lookup), and notifiers outside internal/core
// (server/admin's recover-admin alert is an explicit, separately-tested
// all-admins fan-out).
package core

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recipientKind string

const (
	// KindProjectAdmins: the project's admins = approver-role project members PLUS
	// every active install-wide admin (directly or via group). Must resolve via
	// projectAdminRecipients.
	kindProjectAdmins recipientKind = "project-admins"
	// KindGlobalAdmins: every install-wide admin (no project subject). Must
	// resolve via globalAdminIDs (itself, or the function named in `via`).
	kindGlobalAdmins recipientKind = "global-admins"
	// KindExplicitUser: one user the event is about (owner, requester, inviter,
	// share recipient, ...), passed in or read off the subject record.
	kindExplicitUser recipientKind = "explicit-user"
	// KindDeploymentChannel: the operator-configured broadcast channel, never a
	// per-user address. Must go through notificationSink.
	kindDeploymentChannel recipientKind = "deployment-channel"
	// KindPrimitive: the delivery plumbing itself; has no audience of its own.
	kindPrimitive recipientKind = "primitive"
)

type notifierDecl struct {
	kind recipientKind
	// doc is the documented recipient set, written down so a reviewer can compare
	// it with docs/ and the message body.
	doc string
	// via, for kindGlobalAdmins only: the function that resolves the audience when
	// this one receives it as a parameter.
	via string
}

// notifierRegistry is the declared recipient set of every emitter in internal/core.
// Add new notifiers here; a project-admin audience MUST use projectAdminRecipients.
var notifierRegistry = map[string]notifierDecl{
	// --- project admins (docs/CONFIGURATION.md: "the project's admins"; where the
	// docs are silent on install-wide admins, the break-glass rule from #2959) ---
	"notifyBreakGlassAdmins":           {kind: kindProjectAdmins, doc: "break-glass activation: project admins + install-wide admins (#2955)"},
	"notifyOverdueBreakGlassReviewers": {kind: kindProjectAdmins, doc: "overdue break-glass review: project admins + install-wide admins"},
	"notifyAnomalyAdmins":              {kind: kindProjectAdmins, doc: "anomaly alert: project admins + install-wide admins"},
	"notifyAccessRequested":            {kind: kindProjectAdmins, doc: "new access request: project admins + install-wide admins, minus the requester"},
	"notifySecretAccessRequested":      {kind: kindProjectAdmins, doc: "new secret-scoped access request: project admins + install-wide admins, minus the requester"},
	"notifyApprovalProgress":           {kind: kindProjectAdmins, doc: "M-of-K approval progress: project admins + install-wide admins, minus the requester"},
	"SendExpiryReminders":              {kind: kindProjectAdmins, doc: "secret expiry digest: project admins + install-wide admins"},
	"SendRotationReminders":            {kind: kindProjectAdmins, doc: "rotation due digest: project admins + install-wide admins"},
	"ScanCertificateExpiry":            {kind: kindProjectAdmins, doc: "certificate expiry digest: project admins + install-wide admins"},
	"remindRecertificationAdmins":      {kind: kindProjectAdmins, doc: "recertification due: project admins + install-wide admins"},

	// --- install-wide admins (no project subject) ---
	"ScanLicenseExpiry":       {kind: kindGlobalAdmins, doc: "license expiry: every install-wide admin"},
	"notifyMachineCredAdmins": {kind: kindGlobalAdmins, via: "checkMachineCredExpiry", doc: "machine-credential expiry: every install-wide admin"},

	// --- one user the event is about ---
	"notifyMembershipActivated":        {kind: kindExplicitUser, doc: "the inviter"},
	"notifyAccessResolved":             {kind: kindExplicitUser, doc: "the access requester"},
	"notifySecretAccessResolved":       {kind: kindExplicitUser, doc: "the access requester"},
	"notifySecretShared":               {kind: kindExplicitUser, doc: "the user the secret was shared with"},
	"notifyGroupSecretShared":          {kind: kindExplicitUser, doc: "each member of the group the secret was shared with"},
	"notifySecretShareRevoked":         {kind: kindExplicitUser, doc: "the user whose share was revoked"},
	"notifyGroupSecretShareRevoked":    {kind: kindExplicitUser, doc: "each member of the group whose share was revoked"},
	"notifySecretOwnershipTransferred": {kind: kindExplicitUser, doc: "the new owner"},
	"notifySecretsReassigned":          {kind: kindExplicitUser, doc: "the new owner"},
	"emitPATExpiredNotification":       {kind: kindExplicitUser, doc: "the token owner"},
	"checkPATExpiry":                   {kind: kindExplicitUser, doc: "the token owner"},
	"rejectIfCloned":                   {kind: kindExplicitUser, doc: "the passkey owner (clone suspected)"},
	"CheckRoleExpiry":                  {kind: kindExplicitUser, doc: "the holder of the expiring role grant"},
	"CheckReadQuotas":                  {kind: kindExplicitUser, doc: "the secret owner"},

	// --- operator-configured broadcast channel ---
	"notifyRotationFailures": {kind: kindDeploymentChannel, doc: "deployment-wide channel; secret names only, never failure detail"},
	"SendComplianceDigest":   {kind: kindDeploymentChannel, doc: "deployment-wide channel; compliance posture digest"},

	// --- delivery plumbing ---
	"notify":               {kind: kindPrimitive, doc: "creates one in-app notification for the given user"},
	"notifyWithSeverity":   {kind: kindPrimitive, doc: "notify plus severity"},
	"notifyChecked":        {kind: kindPrimitive, doc: "notifyWithSeverity that returns the CreateNotification error (#3075)"},
	"dispatchNotification": {kind: kindPrimitive, doc: "fans a per-user notification to the recipient-addressable sink"},
}

// requiredCallee returns the callee names an emitter of this kind must contain.
func requiredCallee(k recipientKind) []string {
	switch k {
	case kindProjectAdmins:
		return []string{"projectAdminRecipients"}
	case kindGlobalAdmins:
		return []string{"globalAdminIDs"}
	case kindDeploymentChannel:
		return []string{"Deliver"}
	}
	return nil
}

// functions allowed to read ListProjectMembers directly: the pass-through
// wrapper, and the one resolver every project-admin notifier must use.
var listProjectMembersAllowed = map[string]string{
	"ListProjectMembers":     "exported pass-through used by the members endpoint (project_members.go)",
	"projectAdminRecipients": "the single resolver for 'the project's admins' (notifications.go)",
}

var notifierNameRE = regexp.MustCompile(`^(notify|remind)[A-Z]`)

type emitterInfo struct {
	file    string
	callees map[string]bool
	emits   bool
}

// scanEmitters parses the given sources (file name -> source) and returns every
// function (keyed by name) with the set of callee names in its body, and whether
// it is an emitter per the rules in the file header.
func scanEmitters(t testing.TB, sources map[string]string) map[string]*emitterInfo {
	t.Helper()
	fset := token.NewFileSet()
	out := map[string]*emitterInfo{}
	names := make([]string, 0, len(sources))
	for n := range sources {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		f, err := parser.ParseFile(fset, name, sources[name], 0)
		require.NoError(t, err, name)
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			info := &emitterInfo{file: name, callees: map[string]bool{}}
			if notifierNameRE.MatchString(fd.Name.Name) {
				info.emits = true
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fn := call.Fun.(type) {
				case *ast.SelectorExpr:
					info.callees[fn.Sel.Name] = true
					switch fn.Sel.Name {
					case "notify", "notifyWithSeverity", "notifyChecked", "upgradeReminder", "CreateNotification":
						info.emits = true
					case "Deliver":
						if strings.Contains(renderExpr(fn.X), "otificationSink") {
							info.emits = true
						}
					}
				case *ast.Ident:
					info.callees[fn.Name] = true
				}
				return true
			})
			// A method and a function may share a name across receivers; merge.
			if prev, dup := out[fd.Name.Name]; dup {
				for c := range prev.callees {
					info.callees[c] = true
				}
				info.emits = info.emits || prev.emits
			}
			out[fd.Name.Name] = info
		}
	}
	return out
}

func renderExpr(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return renderExpr(x.X) + "." + x.Sel.Name
	}
	return "?"
}

// notifierViolations applies every rule to the scanned functions. checkStale also
// reports registry entries with no matching emitter (real-package run only).
func notifierViolations(funcs map[string]*emitterInfo, registry map[string]notifierDecl, checkStale bool) []string {
	var v []string
	names := make([]string, 0, len(funcs))
	for n := range funcs {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, n := range names {
		info := funcs[n]
		// Rule: no direct project-member fan-out.
		if info.callees["ListProjectMembers"] {
			if _, ok := listProjectMembersAllowed[n]; !ok {
				v = append(v, fmt.Sprintf("%s (%s) calls ListProjectMembers directly: project-scoped rows miss install-wide admins (#2955); resolve through projectAdminRecipients", n, info.file))
			}
		}
		if !info.emits {
			continue
		}
		decl, ok := registry[n]
		if !ok {
			v = append(v, fmt.Sprintf("%s (%s) emits notifications but is not in notifierRegistry: declare its recipient set (Kind + Doc)", n, info.file))
			continue
		}
		if strings.TrimSpace(decl.doc) == "" {
			v = append(v, fmt.Sprintf("%s: registry entry has no documented recipient set", n))
		}
		holder := info
		if decl.via != "" {
			holder = funcs[decl.via]
			if holder == nil {
				v = append(v, fmt.Sprintf("%s: via function %q not found", n, decl.via))
				continue
			}
		}
		for _, need := range requiredCallee(decl.kind) {
			if !holder.callees[need] {
				v = append(v, fmt.Sprintf("%s is declared %s but %s never calls %s", n, decl.kind, nameOr(decl.via, n), need))
			}
		}
	}
	if checkStale {
		var reg []string
		for n := range registry {
			reg = append(reg, n)
		}
		sort.Strings(reg)
		for _, n := range reg {
			if info, ok := funcs[n]; !ok || !info.emits {
				v = append(v, fmt.Sprintf("notifierRegistry has %q but no such emitter exists in the package: remove the stale declaration", n))
			}
		}
	}
	return v
}

func nameOr(via, name string) string {
	if via != "" {
		return via
	}
	return name
}

func readCoreSources(t *testing.T) map[string]string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	src := map[string]string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		require.NoError(t, err)
		src[f] = string(b)
	}
	require.Greater(t, len(src), 50, "scan root is wrong: too few non-test files in internal/core")
	return src
}

func realFuncs(t *testing.T) map[string]*emitterInfo {
	t.Helper()
	funcs := scanEmitters(t, readCoreSources(t))
	emitters := 0
	for _, i := range funcs {
		if i.emits {
			emitters++
		}
	}
	// Floor: a broken walk must fail loudly, not report a vacuous green.
	require.GreaterOrEqual(t, emitters, 25, "emitter scan found implausibly few notifiers")
	require.True(t, funcs["projectAdminRecipients"] != nil, "projectAdminRecipients must exist")
	return funcs
}

func TestNotifierRecipients_EveryEmitterDeclaresItsRecipientSet(t *testing.T) {
	funcs := realFuncs(t)
	var missing []string
	for _, msg := range notifierViolations(funcs, notifierRegistry, true) {
		if strings.Contains(msg, "not in notifierRegistry") || strings.Contains(msg, "stale") || strings.Contains(msg, "no documented") {
			missing = append(missing, msg)
		}
	}
	assert.Empty(t, missing)
}

func TestNotifierRecipients_DeclaredSetIsActuallyUsed(t *testing.T) {
	funcs := realFuncs(t)
	var bad []string
	for _, msg := range notifierViolations(funcs, notifierRegistry, false) {
		if strings.Contains(msg, "is declared") || strings.Contains(msg, "via function") {
			bad = append(bad, msg)
		}
	}
	assert.Empty(t, bad)
}

func TestNotifierRecipients_NoDirectProjectMemberFanOut(t *testing.T) {
	funcs := realFuncs(t)
	var bad []string
	for _, msg := range notifierViolations(funcs, notifierRegistry, false) {
		if strings.Contains(msg, "calls ListProjectMembers directly") {
			bad = append(bad, msg)
		}
	}
	assert.Empty(t, bad)
	for name := range listProjectMembersAllowed {
		assert.Truef(t, funcs[name] != nil && funcs[name].callees["ListProjectMembers"],
			"allowlist entry %q no longer calls ListProjectMembers: remove it", name)
	}
}

const plantedProjectMembersOnly = `package core

import "context"

// The #2955 shape: notifies only project-scoped approver members.
func (c *KeyorixCore) notifyPlantedMembersOnly(ctx context.Context, projectID uint) {
	members, err := c.storage.ListProjectMembers(ctx, projectID)
	if err != nil {
		return
	}
	for _, m := range members {
		if isApproverRole(m.RoleName) {
			c.notify(ctx, m.UserID, "planted", "t", "m", nil, "/")
		}
	}
}
`

const plantedDeclaredButWrong = `package core

import "context"

// Registered as project-admins but never resolves through projectAdminRecipients.
func (c *KeyorixCore) notifyPlantedLiar(ctx context.Context, uid uint) {
	c.notify(ctx, uid, "planted", "t", "m", nil, "/")
}
`

const plantedGood = `package core

import "context"

func (c *KeyorixCore) notifyPlantedGood(ctx context.Context, projectID uint) {
	ids, _ := c.projectAdminRecipients(ctx, projectID)
	for _, uid := range ids {
		c.notify(ctx, uid, "planted", "t", "m", nil, "/")
	}
}
`

func TestNotifierRecipients_GuardCatchesPlantedProjectMemberOnlyNotifier(t *testing.T) {
	// Red 1: an unregistered notifier that reads ListProjectMembers directly trips
	// both the registry rule and the direct-fan-out rule.
	got := notifierViolations(scanEmitters(t, map[string]string{"planted.go": plantedProjectMembersOnly}), notifierRegistry, false)
	joined := strings.Join(got, "\n")
	assert.Contains(t, joined, "notifyPlantedMembersOnly (planted.go) emits notifications but is not in notifierRegistry")
	assert.Contains(t, joined, "notifyPlantedMembersOnly (planted.go) calls ListProjectMembers directly")

	// Red 2: registering it does not help -- the declared set is checked against
	// what the body actually does.
	reg := map[string]notifierDecl{"notifyPlantedMembersOnly": {kind: kindProjectAdmins, doc: "claims project admins"}}
	got = notifierViolations(scanEmitters(t, map[string]string{"planted.go": plantedProjectMembersOnly}), reg, false)
	assert.Contains(t, strings.Join(got, "\n"), "notifyPlantedMembersOnly is declared project-admins but notifyPlantedMembersOnly never calls projectAdminRecipients")

	// Red 3: a notifier that claims project-admins but resolves nobody via the helper.
	reg = map[string]notifierDecl{"notifyPlantedLiar": {kind: kindProjectAdmins, doc: "claims project admins"}}
	got = notifierViolations(scanEmitters(t, map[string]string{"liar.go": plantedDeclaredButWrong}), reg, false)
	assert.Contains(t, strings.Join(got, "\n"), "notifyPlantedLiar is declared project-admins")

	// Red 4: a registry entry with no doc is refused.
	reg = map[string]notifierDecl{"notifyPlantedGood": {kind: kindProjectAdmins}}
	got = notifierViolations(scanEmitters(t, map[string]string{"good.go": plantedGood}), reg, false)
	assert.Contains(t, strings.Join(got, "\n"), "no documented recipient set")

	// Red 5: a stale declaration is refused.
	got = notifierViolations(scanEmitters(t, map[string]string{"good.go": plantedGood}),
		map[string]notifierDecl{"notifyGone": {kind: kindExplicitUser, doc: "x"}, "notifyPlantedGood": {kind: kindProjectAdmins, doc: "x"}}, true)
	assert.Contains(t, strings.Join(got, "\n"), `"notifyGone" but no such emitter`)

	// Green control: a registered notifier that resolves via projectAdminRecipients
	// passes every rule.
	reg = map[string]notifierDecl{"notifyPlantedGood": {kind: kindProjectAdmins, doc: "project admins + install-wide admins"}}
	assert.Empty(t, notifierViolations(scanEmitters(t, map[string]string{"good.go": plantedGood}), reg, true))
}
