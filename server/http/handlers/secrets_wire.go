// secrets_wire.go — snake_case wire types for internal/storage/models.SecretNode
// (0/30 fields tagged) and SecretWithSharingInfo (which embeds *SecretNode
// anonymously — encoding/json promotes SecretNode's untagged fields to the top
// level regardless of SecretWithSharingInfo's own tags, so every route
// returning either type raw or wrapped was mixed-casing). See
// docs/findings/2026-09-25-FINDING-api-raw-model-exposure.md.
//
// Never carries the secret's plaintext value — that is fetched and included
// separately, under its own permission gate, by the handlers that need it
// (GetSecret's ?include_value=true, GetSecretValueByRef); this type mirrors
// SecretNode's own guarantee of metadata-only.
package handlers

import (
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// SecretNodeWire is exported only because secretWithSharingInfoWire embeds it:
// encoding/json promotes an embedded struct's fields, but utcTimes (reflection)
// cannot rewrite an UNEXPORTED embedded field, so its times would leave in the
// server's local zone (utc_response_structural_guard_test.go).
type SecretNodeWire struct {
	ID                     uint        `json:"id"`
	ParentID               *uint       `json:"parent_id,omitempty"`
	ProjectID              uint        `json:"project_id"`
	EnvironmentID          uint        `json:"environment_id"`
	Name                   string      `json:"name"`
	IsSecret               bool        `json:"is_secret"`
	Type                   string      `json:"type"`
	Description            string      `json:"description,omitempty"`
	MaxReads               *int        `json:"max_reads,omitempty"`
	ReadCount              int         `json:"read_count"`
	Expiration             *time.Time  `json:"expiration,omitempty"`
	Metadata               models.JSON `json:"metadata,omitempty"`
	Classification         string      `json:"classification,omitempty"`
	Status                 string      `json:"status"`
	CreatedBy              string      `json:"created_by"`
	OwnerID                uint        `json:"owner_id"`
	OwnerMachineIdentityID uint        `json:"owner_machine_identity_id,omitempty"`
	IsShared               bool        `json:"is_shared"`
	CreatedAt              time.Time   `json:"created_at"`
	UpdatedAt              time.Time   `json:"updated_at"`
	LastRotatedAt          *time.Time  `json:"last_rotated_at,omitempty"`
	AutoRotate             bool        `json:"auto_rotate"`
	RotationLength         int         `json:"rotation_length,omitempty"`
	RotationCharset        string      `json:"rotation_charset,omitempty"`
	RotationBackend        string      `json:"rotation_backend,omitempty"`
	RotationRef            string      `json:"rotation_ref,omitempty"`
	CertNotAfter           *time.Time  `json:"cert_not_after,omitempty"`
	DeletedAt              *time.Time  `json:"deleted_at,omitempty"`
	RetentionOverrideDays  int         `json:"retention_override_days,omitempty"`
	// TotalReads is the secret's lifetime value-read count
	// (core.SecretTotalReads), set only by the single-secret GETs; omitted in
	// listings. Not ReadCount, which is max_reads accounting (#2963).
	TotalReads *int64 `json:"total_reads,omitempty"`
}

func newSecretNodeWireList(nodes []*models.SecretNode) []SecretNodeWire {
	out := make([]SecretNodeWire, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, newSecretNodeWire(n))
	}
	return out
}

func newSecretNodeWire(s *models.SecretNode) SecretNodeWire {
	w := SecretNodeWire{
		ID: s.ID, ParentID: s.ParentID, ProjectID: s.ProjectID, EnvironmentID: s.EnvironmentID,
		Name: s.Name, IsSecret: s.IsSecret, Type: s.Type, Description: s.Description,
		MaxReads: s.MaxReads, ReadCount: s.ReadCount, Expiration: s.Expiration, Metadata: s.Metadata,
		Classification: s.Classification, Status: s.Status, CreatedBy: s.CreatedBy, OwnerID: s.OwnerID,
		OwnerMachineIdentityID: s.OwnerMachineIdentityID, IsShared: s.IsShared,
		CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt, LastRotatedAt: s.LastRotatedAt,
		AutoRotate: s.AutoRotate, RotationLength: s.RotationLength, RotationCharset: s.RotationCharset,
		RotationBackend: s.RotationBackend, RotationRef: s.RotationRef, CertNotAfter: s.CertNotAfter,
		RetentionOverrideDays: s.RetentionOverrideDays,
	}
	if s.DeletedAt.Valid {
		t := s.DeletedAt.Time
		w.DeletedAt = &t
	}
	return w
}

// secretWithSharingInfoWire mirrors SecretWithSharingInfo's shape exactly
// (flat, not nested — SecretNode's fields promoted alongside the sharing
// fields, matching the shape every existing consumer already expects modulo
// casing) but with every field correctly tagged. SecretNodeWire is embedded
// anonymously so its fields promote using ITS OWN correct tags (verified:
// anonymous-embedding a properly-tagged struct produces clean flat output,
// unlike embedding the untagged model). IsShared is intentionally redeclared
// here, at depth 0: SecretWithSharingInfo does the same (its own
// sharing-computed IsShared, not SecretNode's raw stored one) — Go's
// shallower-field-wins collision rule makes this one win over the embedded
// SecretNodeWire.IsShared automatically, exactly reproducing that intended
// precedence (verified empirically, not assumed).
type secretWithSharingInfoWire struct {
	SecretNodeWire
	ProjectName     string `json:"project_name,omitempty"`
	EnvironmentName string `json:"environment_name,omitempty"`
	IsShared        bool   `json:"is_shared"`
	IsOwnedByUser   bool   `json:"is_owned_by_user"`
	OwnerUsername   string `json:"owner_username,omitempty"`
	UserPermission  string `json:"user_permission,omitempty"`
	ShareCount      int    `json:"share_count"`

	SharedAt *time.Time `json:"shared_at,omitempty"`
	SharedBy string     `json:"shared_by,omitempty"`

	SharingIndicators *models.SharingIndicators `json:"sharing_indicators,omitempty"`
}

func newSecretWithSharingInfoWire(s *models.SecretWithSharingInfo) secretWithSharingInfoWire {
	return secretWithSharingInfoWire{
		SecretNodeWire:    newSecretNodeWire(s.SecretNode),
		ProjectName:       s.ProjectName,
		EnvironmentName:   s.EnvironmentName,
		IsShared:          s.IsShared,
		IsOwnedByUser:     s.IsOwnedByUser,
		OwnerUsername:     s.OwnerUsername,
		UserPermission:    s.UserPermission,
		ShareCount:        s.ShareCount,
		SharedAt:          s.SharedAt,
		SharedBy:          s.SharedBy,
		SharingIndicators: s.SharingIndicators,
	}
}

// secretListResponseWire mirrors models.SecretListResponse.
type secretListResponseWire struct {
	Secrets         []secretWithSharingInfoWire `json:"secrets"`
	Total           int64                       `json:"total"`
	Page            int                         `json:"page"`
	PageSize        int                         `json:"page_size"`
	TotalPages      int                         `json:"total_pages"`
	OwnedCount      int                         `json:"owned_count"`
	SharedCount     int                         `json:"shared_count"`
	ACLGrantedCount int                         `json:"acl_granted_count"`
	// Truncated reports that `total` is a FLOOR, not a count: a listing bound was
	// hit (the storage row bound on any scoped listing, or the multi-scope
	// union's per-scope bound). Omitted when false, so the ordinary
	// response shape is unchanged. A client showing `total` must not present it as a
	// complete count when this is set — see models.SecretListResponse.Truncated.
	Truncated       bool   `json:"truncated,omitempty"`
	TruncatedReason string `json:"truncated_reason,omitempty"`
}

func newSecretListResponseWire(r *models.SecretListResponse) secretListResponseWire {
	secrets := make([]secretWithSharingInfoWire, 0, len(r.Secrets))
	for _, s := range r.Secrets {
		secrets = append(secrets, newSecretWithSharingInfoWire(s))
	}
	return secretListResponseWire{
		Secrets: secrets, Total: r.Total, Page: r.Page, PageSize: r.PageSize,
		TotalPages: r.TotalPages, OwnedCount: r.OwnedCount, SharedCount: r.SharedCount,
		ACLGrantedCount: r.ACLGrantedCount,
		Truncated:       r.Truncated, TruncatedReason: r.TruncatedReason,
	}
}
