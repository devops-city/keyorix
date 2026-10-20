// secret_value_read_core_gate_test.go — INV-GRPC-01: gRPC cannot bypass a control
// HTTP enforces because secret-read enforcement lives in internal/core, not in a
// transport. The gRPC GetSecretValue handler (server/grpc/services/secret_service.go)
// authorizes through core, then reads a HUMAN's value through
// GetSecretForValueRead -> GetPermittedSecretValue. This test drives exactly
// that pair with a bare context.Background(): no gRPC server, no interceptor, no
// UserContext, no transport helper in the path. If the secrets.read gate were
// moved out of core into a transport wrapper, a caller reaching core directly
// would be served and this test goes red.
//
// What it does NOT cover, stated because the invariant's text is broader than
// what a core-level test can show:
//
//   - The machine branch of GetSecretValue. A machine principal is authorized by
//     the handler's authorizeSecretScoped (which asks core.AuthorizeSecretPrincipalForSecretAction)
//     and then reads through GetSecretValueResolved, which takes no principal and
//     so has no secrets.read gate of its own by design (versions.go: "It has no
//     user principal of its own"). The DECISION is core's, but the ENFORCEMENT
//     call for that branch sits in the transport; moving it out of the handler
//     would not turn this file red, and a core-level test cannot show otherwise
//     without a principal to refuse. An earlier draft pinned "core denies an
//     unknown machine id" instead; it asserted a property the handler does not
//     rely on, so it was dropped rather than left as false assurance. Reported
//     to the coordinator in SESSION-INVARIANT-GUARDS-1.md.
//   - Expiry, suspension, schedule and restricted-read gates: each has its own
//     core guard (GetPermittedSecretValue runs enforceSecretReadGuards).
//   - Proof that core's gate is the ONLY one: the HTTP and gRPC parity fuzzers
//     (INV-GRPC-02) own the cross-transport comparison.
//
// Red proof (see the commit message): checkSecretReadPermission made to skip its
// permission check, applied with `go test -overlay` so no production file is
// edited, turns every refusal case below red.
package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// valueReadCallers seeds users who lack secrets.read on secretID's project in
// the three distinct ways a transport would have to reason about, plus the
// positive control that holds it.
type valueReadCallers struct {
	reader, noRole, otherProjectOnly, wrongPermission uint
}

func seedValueReadCallers(t *testing.T, st *store.LocalStorage, projectID uint) valueReadCallers {
	t.Helper()
	ctx := context.Background()
	var out valueReadCallers

	// noRole: an active user holding no role anywhere.
	u, err := st.CreateUser(ctx, foldedTestUser(t, "gate-no-role", "gate-no-role@example.com"))
	require.NoError(t, err)
	out.noRole = u.ID

	// otherProjectOnly: secrets.read, but only on a different project.
	other, err := st.CreateProject(ctx, &models.Project{Name: "gate-other-project"})
	require.NoError(t, err)
	viewer, err := st.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	u, err = st.CreateUser(ctx, foldedTestUser(t, "gate-other-project", "gate-other-project@example.com"))
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, u.ID, viewer.ID, storage.Scope{ProjectID: other.ID}))
	out.otherProjectOnly = u.ID

	// wrongPermission: a role ON THIS project that carries secrets.write only.
	perms, err := st.ListPermissions(ctx)
	require.NoError(t, err)
	var writePerm *models.Permission
	for _, p := range perms {
		if p.Name == permSecretsWrite {
			writePerm = p
		}
	}
	if writePerm == nil {
		writePerm, err = st.CreatePermission(ctx, &models.Permission{Name: permSecretsWrite})
		require.NoError(t, err)
	}
	roleName, err := identity.NewFoldedName("gate-write-only")
	require.NoError(t, err)
	role, err := st.CreateRole(ctx, roleName, "")
	require.NoError(t, err)
	require.NoError(t, st.AssignPermissionToRole(ctx, role.ID, writePerm.ID))
	u, err = st.CreateUser(ctx, foldedTestUser(t, "gate-write-only", "gate-write-only@example.com"))
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, u.ID, role.ID, storage.Scope{ProjectID: projectID}))
	out.wrongPermission = u.ID
	return out
}

// TestSecretValueRead_CoreRefusesCallerWithoutSecretsRead is the guard: the core
// entry points behind gRPC GetSecretValue refuse a caller without secrets.read,
// with nothing but core in the call path, and serve the positive control.
func TestSecretValueRead_CoreRefusesCallerWithoutSecretsRead(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	secretID, readerID, _, projectID := seedClassificationGateFixture(t, st, ClassificationInternal)
	callers := seedValueReadCallers(t, st, projectID)
	callers.reader = readerID
	ctx := context.Background() // no interceptor, no UserContext, no gRPC

	// Positive control: the same two calls the handler makes serve a reader, so a
	// refusal below cannot be an artefact of the fixture (a secret with no
	// version, an expired one) refusing everyone.
	permitted, err := c.GetSecretForValueRead(ctx, secretID, callers.reader)
	require.NoError(t, err, "fixture control: a project_viewer who owns the secret must pass the gate")
	val, err := c.GetPermittedSecretValue(ctx, permitted)
	require.NoError(t, err)
	require.Equal(t, "s3cr3t-value", string(val))

	for name, uid := range map[string]uint{
		"no role anywhere":                     callers.noRole,
		"secrets.read on another project only": callers.otherProjectOnly,
		"role on this project without read":    callers.wrongPermission,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := c.GetSecretForValueRead(ctx, secretID, uid)
			require.Error(t, err, "core must refuse a caller without secrets.read itself")
			assert.Nil(t, got, "a refused check must not hand back the proof GetPermittedSecretValue takes")
			assert.Equal(t, SecretReadDeniedForbidden, ClassifySecretReadDenial(err),
				"the refusal must classify as a permission denial, got: %v", err)

			// The other core value-read entry the HTTP and CLI transports use.
			v, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, uid)
			require.Error(t, err)
			assert.Empty(t, v, "no value may accompany a refusal")

			// GetPermittedSecretValue cannot be handed a forged proof: the type's
			// fields are unexported, so the only value outside this package is the
			// zero one, which the value step refuses.
			v, err = c.GetPermittedSecretValue(ctx, &ReadPermittedSecret{})
			require.Error(t, err)
			assert.Empty(t, v)
		})
	}
}
