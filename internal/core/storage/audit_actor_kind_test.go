package storage

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// AuditActorKind in both directions (#2951 review): a row with no principal at
// all is "system"; a row where a principal was involved but no acting user was
// resolved (a failed login) stays "user", so brute-force evidence is found by
// actor_type=user and never mixed into scheduler events.
func TestAuditActorKind_SystemOnlyWithoutAnyPrincipal(t *testing.T) {
	uid, zero, mid, admin := uint(7), uint(0), uint(4), uint(9)
	cases := []struct {
		name string
		e    models.AuditEvent
		want string
	}{
		// system: nothing identifies a principal
		{"scheduler row, default user, no user", models.AuditEvent{EventType: "secret.auto_rotated", ActorType: "user"}, "system"},
		{"legacy empty, no user", models.AuditEvent{EventType: "data.purged", ActorType: ""}, "system"},
		{"user id 0", models.AuditEvent{EventType: "share.expired", ActorType: "user", UserID: &zero}, "system"},
		{"explicit system", models.AuditEvent{EventType: "data.retention_purged", ActorType: "system"}, "system"},
		{"explicit system keeps kind even with an ip", models.AuditEvent{EventType: "security.anomaly_detected", ActorType: "system", IPAddress: "203.0.113.9"}, "system"},
		// user: a principal is involved
		{"failed login: no user, client ip", models.AuditEvent{EventType: "auth.login_failed", ActorType: "user", IPAddress: "198.51.100.7"}, "user"},
		{"failed login without an ip is still an auth attempt", models.AuditEvent{EventType: "auth.login_failed", ActorType: "user"}, "user"},
		{"failed webauthn, legacy empty", models.AuditEvent{EventType: "webauthn.failed", ActorType: ""}, "user"},
		{"mfa failure, no user", models.AuditEvent{EventType: "mfa.failed", ActorType: "user"}, "user"},
		{"request row with client ip, no user", models.AuditEvent{EventType: "secret.read", ActorType: "user", IPAddress: "192.0.2.1"}, "user"},
		{"impersonated, no user", models.AuditEvent{EventType: "secret.read", ActorType: "user", ImpersonatedBy: &admin}, "user"},
		{"machine id on a default row", models.AuditEvent{EventType: "secret.read", ActorType: "user", MachineIdentityID: &mid}, "user"},
		{"real user", models.AuditEvent{EventType: "secret.read", ActorType: "user", UserID: &uid}, "user"},
		{"legacy empty, real user", models.AuditEvent{EventType: "secret.read", ActorType: "", UserID: &uid}, "user"},
		// other stored kinds are shown as stored
		{"machine, no user", models.AuditEvent{EventType: "secret.read", ActorType: "machine_identity", MachineIdentityID: &mid}, "machine_identity"},
		{"machine, nothing else", models.AuditEvent{EventType: "secret.read", ActorType: "machine_identity"}, "machine_identity"},
	}
	for _, c := range cases {
		e := c.e
		if got := AuditActorKind(&e); got != c.want {
			t.Errorf("%s: AuditActorKind = %q, want %q", c.name, got, c.want)
		}
	}
}

// The actor beside the kind: never "system" for a non-system row.
func TestAuditActorName_MatchesKind(t *testing.T) {
	uid := uint(7)
	names := map[uint]string{0: "system", 7: "alice"}
	mid, goneMid := uint(7), uint(99) // machine id 7 deliberately equals user id 7: separate ID spaces
	machineNames := map[uint]string{7: "ci-app"}
	cases := []struct {
		e    models.AuditEvent
		want string
	}{
		{models.AuditEvent{EventType: "secret.auto_rotated", ActorType: "user"}, "system"},
		{models.AuditEvent{EventType: "auth.login_failed", ActorType: "user", IPAddress: "198.51.100.7"}, "unknown"},
		{models.AuditEvent{EventType: "secret.read", ActorType: "machine_identity"}, "unknown"},
		{models.AuditEvent{EventType: "secret.read", ActorType: "user", UserID: &uid}, "alice"},
		// #3150: a machine read is attributed to the machine, not "unknown".
		{models.AuditEvent{EventType: "secret.read", ActorType: "machine_identity", MachineIdentityID: &mid}, "ci-app"},
		{models.AuditEvent{EventType: "secret.read", ActorType: "machine_identity", MachineIdentityID: &goneMid}, "unknown"},
		// Host admin commands stay attributed as the admin CLI, never "system"
		// (deliberate human actions on the host; "system" search excludes them).
		{models.AuditEvent{EventType: "admin.migrate", ActorType: "admin_cli"}, "admin_cli"},
		{models.AuditEvent{EventType: "admin.restore_completed", ActorType: "admin_cli"}, "admin_cli"},
		{models.AuditEvent{EventType: "admin.rotate_kek", ActorType: "admin_cli"}, "admin_cli"},
		{models.AuditEvent{EventType: "audit_checkpoint_key_exported", ActorType: "admin_cli"}, "admin_cli"},
		// A genuine server-internal boot event (stored kind system) is "system".
		{models.AuditEvent{EventType: "security.posture_baseline", ActorType: "system"}, "system"},
		// ...but an admin_cli row that does name a user keeps that user.
		{models.AuditEvent{EventType: "admin.recover_admin", ActorType: "admin_cli", UserID: &uid}, "alice"},
	}
	for _, c := range cases {
		e := c.e
		if got := AuditActorName(&e, names, machineNames); got != c.want {
			t.Errorf("%s/%s: AuditActorName = %q, want %q", e.EventType, e.ActorType, got, c.want)
		}
	}
}

// An admin_cli row is shown as "admin_cli", agrees with its kind (so
// actor_type=admin_cli finds it), and is not matched by the "system" kind.
func TestAuditActorName_AdminCLINeverSystem(t *testing.T) {
	e := models.AuditEvent{EventType: "admin.restore_completed", ActorType: "admin_cli"}
	if got := AuditActorName(&e, nil, nil); got == "system" || got != AuditActorKind(&e) {
		t.Fatalf("admin_cli row: actor %q, kind %q; want actor == kind == admin_cli", got, AuditActorKind(&e))
	}
	boot := models.AuditEvent{EventType: "security.posture_baseline", ActorType: "system"}
	if got := AuditActorName(&boot, nil, nil); got != "system" {
		t.Fatalf("boot event actor = %q, want system", got)
	}
}
