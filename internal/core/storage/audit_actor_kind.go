package storage

import (
	"strings"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Audit actor KIND as the API displays and filters it (#2951). This file is the
// one definition: the HTTP and gRPC audit views call AuditActorKind, and the
// store's actor_type filter uses AuditActorKindWhere, so a row shown as kind K is
// exactly a row that actor_type=K returns
// (internal/storage/store TestAuditActorKindWhere_AgreesWithAuditActorKind).
//
// Display only. The stored actor_type is part of the hash-chained record
// (ADR-029) and is never rewritten; exports that carry the chain keep the stored
// value and add the kind beside it.
//
// The kinds are the stored values core.ActorTypeUser/Machine/System (this
// package cannot import internal/core; server/http/handlers
// TestAuditActorKindConstantsMatchCore pins them).
const (
	auditKindUser   = "user"
	auditKindSystem = "system"
)

// auditPrincipalEventPrefixes are event families that always concern a human or
// service principal, even when no acting user was resolved: a failed login or a
// failed WebAuthn/MFA attempt names (or presents a credential for) a principal
// that was not authenticated. Such a row is never "system", so brute-force
// evidence stays under actor_type=user and is not mixed into scheduler events.
var auditPrincipalEventPrefixes = []string{"auth.", "mfa.", "webauthn."}

// AuditActorKind returns the kind shown for an audit row. A row is "system" when
// it stores "system", or when it stores the default "user" (or the legacy "")
// and NOTHING on it identifies a principal:
//
//   - no acting user (user_id NULL or 0),
//   - no machine identity (machine_identity_id NULL),
//   - no impersonating admin (impersonated_by NULL),
//   - no client address (ip_address empty: request-originated rows record the
//     caller's address, background jobs have none), and
//   - not an authentication-family event (auth.*, mfa.*, webauthn.*).
//
// Every other "user"/"" row is "user", including auth.login_failed (no user id,
// but an attempted principal and a client address). Any other stored value
// (machine_identity, system) is shown as stored.
func AuditActorKind(e *models.AuditEvent) string {
	switch e.ActorType {
	case "", auditKindUser:
		if auditRowHasNoPrincipal(e) {
			return auditKindSystem
		}
		return auditKindUser
	default:
		return e.ActorType
	}
}

func auditRowHasNoPrincipal(e *models.AuditEvent) bool {
	if e.UserID != nil && *e.UserID != 0 {
		return false
	}
	if e.MachineIdentityID != nil || e.ImpersonatedBy != nil || e.IPAddress != "" {
		return false
	}
	for _, p := range auditPrincipalEventPrefixes {
		if strings.HasPrefix(e.EventType, p) {
			return false
		}
	}
	return true
}

// auditNoPrincipalSQL is auditRowHasNoPrincipal over audit_events columns.
// LIKE patterns are constants (no caller input); '_' and '.' are escaped so the
// prefix matches literally.
func auditNoPrincipalSQL() string {
	var b strings.Builder
	b.WriteString("((user_id IS NULL OR user_id = 0) AND machine_identity_id IS NULL AND impersonated_by IS NULL AND COALESCE(ip_address, '') = ''")
	for _, p := range auditPrincipalEventPrefixes {
		b.WriteString(" AND event_type NOT LIKE '")
		b.WriteString(strings.ReplaceAll(p, "_", `\_`))
		b.WriteString(`%' ESCAPE '\'`)
	}
	b.WriteString(")")
	return b.String()
}

// AuditActorKindWhere returns the WHERE clause (and args) selecting exactly the
// audit_events rows AuditActorKind maps to kind.
func AuditActorKindWhere(kind string) (string, []interface{}) {
	defaultKind := "(COALESCE(actor_type, '') IN ('', 'user'))"
	switch kind {
	case auditKindSystem:
		return "(actor_type = ? OR (" + defaultKind + " AND " + auditNoPrincipalSQL() + "))", []interface{}{kind}
	case auditKindUser:
		return "(" + defaultKind + " AND NOT " + auditNoPrincipalSQL() + ")", nil
	default:
		return "actor_type = ?", []interface{}{kind}
	}
}

// AuditSystemActorWhere returns the WHERE clause selecting rows whose displayed
// actor is "system" (kind system). The actor (username) search uses it so a term
// matching "system" finds the same rows the system kind does.
func AuditSystemActorWhere() (string, []interface{}) {
	return AuditActorKindWhere(auditKindSystem)
}

// AuditActorName returns the actor shown beside AuditActorKind: the acting
// user's name from names (core.ResolveUsernames), "system" for a kind-system
// row, the machine identity's name from machineNames (core.ResolveMachineNames)
// for a machine-actor row (#3150), and "unknown" for any other row with no acting
// principal (a failed login), so a row is never shown as actor "system" with
// another kind.
func AuditActorName(e *models.AuditEvent, names, machineNames map[uint]string) string {
	if e.UserID != nil && *e.UserID != 0 {
		if n := names[*e.UserID]; n != "" {
			return n
		}
		return "unknown"
	}
	if e.MachineIdentityID != nil {
		if n := machineNames[*e.MachineIdentityID]; n != "" {
			return n
		}
		return "unknown"
	}
	if AuditActorKind(e) == auditKindSystem {
		return auditKindSystem
	}
	return "unknown"
}
