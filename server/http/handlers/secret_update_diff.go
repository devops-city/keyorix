// secret_update_diff.go — the default-deny diff backing the reqBody.Secret branch of
// PUT /api/v1/secrets/{id} (G80 Phase 0: internal/storage/store/remote_secrets.go's old
// secretUpdateWireRequest carried only 3 of models.SecretNode's ~28 persisted fields, so
// the now-deleted RemoteStorage.UpdateSecret silently dropped every other field the
// internal/core call sites listed in updateSecretAllowlist below mutate before calling
// storage.UpdateSecret — ownership transfers, moves, classification changes, renames, and
// rotation-backend bindings would all have appeared to succeed while changing nothing on
// the hub's authoritative row, had any current CLI command actually reached them through
// RemoteStorage. Tracing every real caller found none did even then (see
// docs/g80-remediation-notes.md's severity correction), and RemoteStorage itself is now
// fully deleted (repo-wide in #2162) — the reqBody.Secret wire shape this file diffs
// against isn't in openapi.yaml's updateSecret request schema at all, so no generated
// client (the CLI's included) can construct a request that reaches updateSecretViaDiff
// today. Left in place as a still-correct interface-contract guard against a raw,
// hand-crafted request hitting this JSON field rather than removed outright — a
// reachability finding worth a dedicated follow-up PR to actually delete, not fixed here.
//
// This is deliberately NOT fixed by widening the wire DTO with named fields for those
// operations and applying them under this endpoint's own plain secrets.write gate: several
// of them are gated by an authorization check this endpoint cannot run (SoD on ownership
// transfer, the G09 read-approval gate on a classification downgrade from restricted,
// requireAdminAuthorityAt on binding a rotation backend) — applying them here would let
// any secrets.write holder bypass all three, a privilege-escalation regression, not a
// completeness fix.
//
// Instead: a caller sending reqBody.Secret sends its FULL locally-mutated SecretNode (see
// secretUpdateWireRequest), and this file diffs it against the hub's OWN authoritative row
// — never against a client-supplied pre-image, which would be trivially forgeable and
// would reopen the exact TOCTOU window G79's proxy fixes closed elsewhere. Every field is
// classified below; a field outside the allowed set that differs rejects the WHOLE request
// by name — no partial application — with an error stating the operation needs its own
// dedicated endpoint (tracked as G80 follow-up work, not yet built).
package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// isNotFoundErr reports whether err is a storage "not found" error. Originated in
// server/http/handlers/dynamic_secrets_proxy.go, removed with the ADR-108 Phase 6
// /system proxy tier deletion; kept here for this file's own live caller.
func isNotFoundErr(err error) bool {
	return strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "record not found")
}

// secretUpdateFieldClass classifies one models.SecretNode field for the default-deny diff.
type secretUpdateFieldClass int

const (
	// secretFieldRejected: the whole request is refused if this field differs from the
	// hub's authoritative row. Two distinct reasons land here, both noted per field in
	// updateSecretAllowlist:
	//   - server-owned: no internal/core call site legitimately mutates this field via
	//     storage.UpdateSecret at all (either it's immutable, or it has its own dedicated
	//     storage primitive — Status/TransitionSecretStatus, CertNotAfter/
	//     SetSecretCertNotAfter, DeletedAt/soft-delete-restore).
	//   - gated: a real internal/core call site mutates it, but only after an
	//     authorization check beyond this endpoint's plain secrets.write gate (SoD,
	//     G09, requireAdminAuthorityAt) — or, for LastRotatedAt, because no generic
	//     diff can distinguish "a real rotation happened" from "an unrelated field on
	//     this same row changed," and stamping it unconditionally would reintroduce the
	//     #408 false "recently rotated" signal.
	secretFieldRejected secretUpdateFieldClass = iota
	// secretFieldAllowed: applied directly when it differs. No internal/core call site
	// gates this field beyond the plain secrets.write check this endpoint already runs.
	secretFieldAllowed
	// secretFieldIgnored: never compared at all. The hub computes its own value; whatever
	// the client sent is irrelevant. Only UpdatedAt qualifies — see the field table for
	// why LastRotatedAt does NOT get this treatment despite looking similar.
	secretFieldIgnored
)

// updateSecretAllowlist classifies every persisted field on models.SecretNode
// (ValueStored is `gorm:"-"`, never persisted, and excluded here for that reason —
// see TestSecretUpdateAllowlist_CoversEveryPersistedField, which fails if a new
// persisted field is added without a corresponding entry here). This is intentional
// friction: a field must be explicitly classified before it can ever be updated
// through this endpoint. Do not "simplify" this into a single default-allow or
// default-reject bucket — that is exactly the shortcut that let the original bug
// happen unnoticed.
var updateSecretAllowlist = map[string]secretUpdateFieldClass{
	// -- allowed: plain secrets.write, no internal/core call site gates these further --
	"Type":        secretFieldAllowed, // core.UpdateSecret (secrets.go)
	"Description": secretFieldAllowed, // core.SetSecretDescription — same gate, verified no second check
	"MaxReads":    secretFieldAllowed, // core.UpdateSecret
	"Expiration":  secretFieldAllowed, // core.UpdateSecret; nil means "no expiration" (fully-resolved state)
	"Metadata":    secretFieldAllowed, // core.UpdateSecret

	// -- ignored: hub-computed, client value never even inspected --
	"UpdatedAt": secretFieldIgnored, // every call site sets it; hub always stamps its own now()

	// -- rejected: server-owned (no call site mutates via storage.UpdateSecret) --
	"ID":            secretFieldRejected,
	"ProjectID":     secretFieldRejected,
	"EnvironmentID": secretFieldRejected,
	"IsSecret":      secretFieldRejected,
	"ReadCount":     secretFieldRejected, // IncrementSecretReadCount's own primitive
	// CacheEpoch is the read-path cache's generation stamp, owned by a database
	// trigger and read-only to GORM (models.SecretNode's own doc comment). No
	// client may propose a value and no Go write can apply one, so a caller
	// supplying it is rejected rather than ignored: silently dropping it would
	// hide a client that believes it controls cache invalidation.
	"CacheEpoch":            secretFieldRejected,
	"Status":                secretFieldRejected, // TransitionSecretStatus's own primitive (G79)
	"CreatedBy":             secretFieldRejected,
	"IsShared":              secretFieldRejected,
	"CreatedAt":             secretFieldRejected,
	"CertNotAfter":          secretFieldRejected, // SetSecretCertNotAfter's own primitive
	"DeletedAt":             secretFieldRejected, // soft-delete/restore's own path
	"RetentionOverrideDays": secretFieldRejected,

	// -- rejected: gated by an authorization check this endpoint cannot run --
	"OwnerID":                secretFieldRejected, // TransferSecretOwnership: current-owner + SoD check
	"OwnerMachineIdentityID": secretFieldRejected, // set at creation only (#1573); reassignment is the same TransferSecretOwnership gate as OwnerID, which explicitly rejects a machine actor
	"ParentID":               secretFieldRejected, // MoveSecret: cross-project/environment guard
	"Name":                   secretFieldRejected, // BulkRenameSecrets: uniqueness + validation
	"Classification":         secretFieldRejected, // ClassifySecret: G09 read-approval gate on downgrade
	// AutoRotate/RotationLength/RotationCharset are set together with
	// RotationBackend/RotationRef in the ONE SetSecretAutoRotate call (rotation_executor.go)
	// as a single AutoRotateSpec. requireAdminAuthorityAt only fires when Backend/Ref
	// transition to/from non-empty — a charset-only tweak with no backend involved has no
	// extra gate today. A field-level diff cannot express "this direction is gated, that
	// one is not" without reintroducing the complexity that caused this bug, so all 5 stay
	// rejected as a unit pending the dedicated endpoint.
	"AutoRotate":      secretFieldRejected,
	"RotationLength":  secretFieldRejected,
	"RotationCharset": secretFieldRejected,
	"RotationBackend": secretFieldRejected, // requireAdminAuthorityAt when non-empty
	"RotationRef":     secretFieldRejected, // bundled with RotationBackend
	// LastRotatedAt looks like UpdatedAt (hub-computed, client value shouldn't matter) but
	// is NOT classified secretFieldIgnored: RotateSecret (secrets.go) leaves it deliberately
	// UNCHANGED on a byte-identical resubmission (#408 — stamping it would falsely signal
	// "recently rotated, low risk" for material that never changed) and SETS it to now on a
	// real rotation. This endpoint has no way to tell which case it's looking at from a
	// generic field diff alone, and unconditionally stamping now() on ANY update through
	// this endpoint (e.g. a plain Description edit) would wrongly mark an unrelated secret
	// as just-rotated. Rejected pending a dedicated "record a rotation" endpoint that always
	// means a rotation genuinely happened, by construction — never ambiguous. See the G80
	// Phase 0 writeup for the operational consequence this has today (rotation-due
	// calculations fall back to CreatedAt, so a secret rotated via connected-mode on-demand
	// rotate remains permanently "overdue").
	"LastRotatedAt": secretFieldRejected,
}

// secretUpdateDiff is the result of diffing a caller's desired SecretNode state against
// the hub's authoritative row. Only Applied fields should ever be persisted; Rejected
// lists exactly what differed outside the allowlist, for the error message.
type secretUpdateDiff struct {
	TypeChanged        bool
	Type               string
	DescriptionChanged bool
	Description        string
	MaxReadsChanged    bool
	MaxReads           *int
	ExpirationChanged  bool
	Expiration         *time.Time
	MetadataChanged    bool
	Metadata           models.JSON
	Rejected           []string
}

// diffSecretUpdate compares desired (the caller's full requested state) against
// authoritative (the hub's current row) and reports what may change. It never mutates
// either argument. Comparing against the hub's OWN row — never a client-supplied
// "before" value — is what makes this default-deny rather than trivially forgeable: a
// forged pre-image could always be made to match whatever the client wants to send.
func diffSecretUpdate(authoritative, desired *models.SecretNode) secretUpdateDiff {
	var d secretUpdateDiff

	if authoritative.Type != desired.Type {
		d.TypeChanged = true
		d.Type = desired.Type
	}
	if authoritative.Description != desired.Description {
		d.DescriptionChanged = true
		d.Description = desired.Description
	}
	if !intPtrEqual(authoritative.MaxReads, desired.MaxReads) {
		d.MaxReadsChanged = true
		d.MaxReads = desired.MaxReads
	}
	if !timePtrEqual(authoritative.Expiration, desired.Expiration) {
		d.ExpirationChanged = true
		d.Expiration = desired.Expiration
	}
	if !bytes.Equal(authoritative.Metadata, desired.Metadata) {
		d.MetadataChanged = true
		d.Metadata = desired.Metadata
	}

	// UpdatedAt is intentionally never compared (secretFieldIgnored).

	if authoritative.ID != desired.ID {
		d.Rejected = append(d.Rejected, "id")
	}
	if !uintPtrEqual(authoritative.ParentID, desired.ParentID) {
		d.Rejected = append(d.Rejected, "parent_id")
	}
	if authoritative.ProjectID != desired.ProjectID {
		d.Rejected = append(d.Rejected, "project_id")
	}
	if authoritative.EnvironmentID != desired.EnvironmentID {
		d.Rejected = append(d.Rejected, "environment_id")
	}
	if authoritative.Name != desired.Name {
		d.Rejected = append(d.Rejected, "name")
	}
	if authoritative.IsSecret != desired.IsSecret {
		d.Rejected = append(d.Rejected, "is_secret")
	}
	if authoritative.ReadCount != desired.ReadCount {
		d.Rejected = append(d.Rejected, "read_count")
	}
	if authoritative.CacheEpoch != desired.CacheEpoch {
		d.Rejected = append(d.Rejected, "cache_epoch")
	}
	if authoritative.Classification != desired.Classification {
		d.Rejected = append(d.Rejected, "classification")
	}
	if authoritative.Status != desired.Status {
		d.Rejected = append(d.Rejected, "status")
	}
	if authoritative.CreatedBy != desired.CreatedBy {
		d.Rejected = append(d.Rejected, "created_by")
	}
	if authoritative.OwnerID != desired.OwnerID {
		d.Rejected = append(d.Rejected, "owner_id")
	}
	if authoritative.OwnerMachineIdentityID != desired.OwnerMachineIdentityID {
		d.Rejected = append(d.Rejected, "owner_machine_identity_id")
	}
	if authoritative.IsShared != desired.IsShared {
		d.Rejected = append(d.Rejected, "is_shared")
	}
	if !authoritative.CreatedAt.Equal(desired.CreatedAt) {
		d.Rejected = append(d.Rejected, "created_at")
	}
	if !timePtrEqual(authoritative.LastRotatedAt, desired.LastRotatedAt) {
		d.Rejected = append(d.Rejected, "last_rotated_at")
	}
	if authoritative.AutoRotate != desired.AutoRotate {
		d.Rejected = append(d.Rejected, "auto_rotate")
	}
	if authoritative.RotationLength != desired.RotationLength {
		d.Rejected = append(d.Rejected, "rotation_length")
	}
	if authoritative.RotationCharset != desired.RotationCharset {
		d.Rejected = append(d.Rejected, "rotation_charset")
	}
	if authoritative.RotationBackend != desired.RotationBackend {
		d.Rejected = append(d.Rejected, "rotation_backend")
	}
	if authoritative.RotationRef != desired.RotationRef {
		d.Rejected = append(d.Rejected, "rotation_ref")
	}
	if !timePtrEqual(authoritative.CertNotAfter, desired.CertNotAfter) {
		d.Rejected = append(d.Rejected, "cert_not_after")
	}
	if authoritative.DeletedAt.Valid != desired.DeletedAt.Valid ||
		(authoritative.DeletedAt.Valid && !authoritative.DeletedAt.Time.Equal(desired.DeletedAt.Time)) {
		d.Rejected = append(d.Rejected, "deleted_at")
	}
	if authoritative.RetentionOverrideDays != desired.RetentionOverrideDays {
		d.Rejected = append(d.Rejected, "retention_override_days")
	}

	return d
}

// rejectedFieldsError formats diff.Rejected as the error UpdateSecret returns to a
// reqBody.Secret caller — named fields, and an explicit statement that the operation isn't
// available through this endpoint yet, so the caller gets a clear, actionable failure
// instead of a silent no-op.
func rejectedFieldsError(rejected []string) error {
	return fmt.Errorf("cannot update field(s) [%s] via this endpoint: each requires its own dedicated endpoint against a hub, not yet available in connected mode",
		strings.Join(rejected, ", "))
}

func intPtrEqual(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func uintPtrEqual(a, b *uint) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func timePtrEqual(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

// updateSecretViaDiff handles PUT /api/v1/secrets/{id} when the request carries a full
// desired SecretNode (reqBody.Secret in secrets_crud.go's UpdateSecret) — the now-deleted
// RemoteStorage's path, per G80 Phase 0 (see this file's package doc for why this branch
// has no known live caller today). desired is the caller's complete locally-mutated state;
// this function decides what of it may actually be persisted.
func (h *SecretHandler) updateSecretViaDiff(w http.ResponseWriter, r *http.Request, id uint, userCtx *middleware.UserContext, desired *models.SecretNode) {
	ctx := r.Context()

	// Permission is checked BEFORE the diff is computed and BEFORE any diff result is
	// returned to the caller: revealing which fields differ from the authoritative row
	// would otherwise let an unauthorized caller use this endpoint's rejection message
	// as an oracle for the secret's current gated-field values (e.g. probing
	// classification by trying different guesses and watching which get rejected vs.
	// silently no-diffed).
	if _, err := h.coreService.EnforceSecretWritePermission(ctx, id, userCtx.UserID); err != nil {
		h.sendError(w, "Forbidden", clientSafe(err), http.StatusForbidden, nil)
		return
	}

	authoritative, err := h.coreService.Storage().GetSecret(ctx, id)
	if err != nil {
		if isNotFoundErr(err) {
			h.sendError(w, "NotFound", errSecretNotFound, http.StatusNotFound, nil)
			return
		}
		log.Printf("Error fetching secret %d for update diff: %v", id, err)
		h.sendError(w, "InternalError", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}

	diff := diffSecretUpdate(authoritative, desired)
	if len(diff.Rejected) > 0 {
		h.sendError(w, "UnsupportedField", rejectedFieldsError(diff.Rejected).Error(), http.StatusBadRequest, nil)
		return
	}

	if !diff.TypeChanged && !diff.DescriptionChanged && !diff.MaxReadsChanged &&
		!diff.ExpirationChanged && !diff.MetadataChanged {
		h.sendSuccess(w, authoritative, i18n.T("SuccessSecretUpdated", nil))
		return
	}

	req := &core.UpdateSecretRequest{
		ID:        id,
		UpdatedBy: userCtx.Username,
		UserID:    userCtx.UserID,
	}
	if diff.TypeChanged {
		req.Type = diff.Type
	}
	if diff.DescriptionChanged {
		req.Description = &diff.Description
	}
	if diff.MaxReadsChanged {
		req.MaxReads = diff.MaxReads
	}
	if diff.ExpirationChanged {
		if diff.Expiration == nil {
			req.ClearExpiration = true
		} else {
			req.Expiration = diff.Expiration
		}
	}
	if diff.MetadataChanged {
		metadata := map[string]string{}
		if len(diff.Metadata) > 0 {
			if err := json.Unmarshal(diff.Metadata, &metadata); err != nil {
				h.sendError(w, "ValidationError", "invalid metadata", http.StatusBadRequest, nil)
				return
			}
		}
		req.Metadata = metadata
	}

	response, err := h.coreService.UpdateSecretWithPermissionCheck(ctx, req)
	if err != nil {
		log.Printf("Error updating secret: %v", err)
		h.sendUpdateSecretError(w, err)
		return
	}

	uid, sID, uname, sname := userCtx.UserID, id, userCtx.Username, response.Name
	ip, ua := r.RemoteAddr, r.Header.Get(hdrUserAgent)
	auditDiff := core.BuildSecretUpdateDiff(authoritative, req, false)
	auditCtx := core.DetachedAuditContext(ctx)
	goSafe(func() {
		h.coreService.LogSecretUpdatedWithDiff(auditCtx, uid, sID, response.ProjectID, uname, sname, ip, ua, auditDiff)
	}) // #nosec G118

	h.sendSuccess(w, newSecretNodeWire(response), i18n.T("SuccessSecretUpdated", nil))
}
