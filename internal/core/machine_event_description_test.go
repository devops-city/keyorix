package core

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// #3141 (from #2977 item 8): the description of a machine_identity.* audit event
// must say what HAPPENED, not only restate the identity's state ("→ active" on a
// token_issued row). Every field of the old text (name, type, project, state) stays.
func TestMachineEventDescription_DescribesTheEvent(t *testing.T) {
	m := &models.MachineIdentity{Name: "ci-app", IdentityType: "ci", ProjectID: 1, State: MachineActive}
	want := map[string]string{
		"machine_identity.created":       "created machine identity",
		"machine_identity.token_issued":  "issued token for machine identity",
		"machine_identity.token_rotated": "rotated token for machine identity",
		"machine_identity.token_revoked": "revoked token of machine identity",
		"machine_identity.role_granted":  "granted role to machine identity",
		"machine_identity.role_removed":  "removed role from machine identity",
		"machine_identity.oidc_bound":    "bound OIDC trust to machine identity",
		"machine_identity.oidc_unbound":  "unbound OIDC trust from machine identity",
		"machine_identity.activated":     "activated machine identity",
		"machine_identity.suspended":     "suspended machine identity",
		"machine_identity.revoked":       "revoked machine identity",
	}
	seen := map[string]string{}
	for ev, verb := range want {
		d := machineEventDescription(ev, m)
		if !strings.HasPrefix(d, verb) {
			t.Errorf("%s: %q does not start with %q", ev, d, verb)
		}
		for _, field := range []string{`"ci-app"`, "(ci)", "project 1", "state: active"} {
			if !strings.Contains(d, field) {
				t.Errorf("%s: %q lost field %q", ev, d, field)
			}
		}
		if prev, dup := seen[d]; dup {
			t.Errorf("%s and %s share the description %q", ev, prev, d)
		}
		seen[d] = ev
	}
}
