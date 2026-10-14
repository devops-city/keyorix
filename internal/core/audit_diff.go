// audit_diff.go — structured before/after diffs for secret mutation audit events.
//
// SECURITY: a diff must never carry a plaintext secret value. For the value
// field we record only {"changed": true}; all other fields are non-sensitive
// metadata (name, type, max_reads, expiration, metadata) whose before/after is
// safe to log.
package core

import (
	"encoding/json"
	"reflect"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// fieldChange is one field's before→after in an audit diff.
type fieldChange struct {
	Before any `json:"before,omitempty"`
	After  any `json:"after,omitempty"`
	// Changed marks a sensitive field (the secret value) as modified without
	// disclosing either side. Only set for the "value" entry.
	Changed bool `json:"changed,omitempty"`
}

// BuildSecretUpdateDiff returns a JSON diff of a secret update. old is the
// pre-update record; req is the requested change. valueProvided indicates the
// caller supplied a new value (we never compare plaintext, so any provided value
// is recorded as changed). Returns "" when nothing changed (no diff to log).
func BuildSecretUpdateDiff(old *models.SecretNode, req *UpdateSecretRequest, valueProvided bool) string {
	if old == nil || req == nil {
		return ""
	}
	diff := map[string]fieldChange{}

	if valueProvided {
		// Never log the value itself — only that it changed.
		diff["value"] = fieldChange{Changed: true}
	}
	if req.Type != "" && req.Type != old.Type {
		diff["type"] = fieldChange{Before: old.Type, After: req.Type}
	}
	if req.Description != nil && *req.Description != old.Description {
		diff["description"] = fieldChange{Before: old.Description, After: *req.Description}
	}
	if req.ClearMaxReads {
		// Explicit clear: record it although the "after" side is nil (as ClearExpiration).
		if old.MaxReads != nil {
			diff["max_reads"] = fieldChange{Before: intPtrVal(old.MaxReads), After: nil}
		}
	} else if req.MaxReads != nil && !eqIntPtr(old.MaxReads, req.MaxReads) {
		diff["max_reads"] = fieldChange{Before: intPtrVal(old.MaxReads), After: intPtrVal(req.MaxReads)}
	}
	switch {
	case req.ClearExpiration:
		// ClearExpiration explicitly transitions an expiring secret to non-expiring —
		// record it even though the "after" side is nil, so the clear itself is
		// visible in the trail (#285).
		if old.Expiration != nil {
			diff["expiration"] = fieldChange{Before: timePtrVal(old.Expiration), After: nil}
		}
	case req.Expiration != nil && !eqTimePtr(old.Expiration, req.Expiration):
		diff["expiration"] = fieldChange{Before: timePtrVal(old.Expiration), After: timePtrVal(req.Expiration)}
	}
	if req.Metadata != nil && !eqMetadata(old.Metadata, req.Metadata) {
		diff["metadata"] = fieldChange{Before: metadataVal(old.Metadata), After: req.Metadata}
	}

	if len(diff) == 0 {
		return ""
	}
	b, err := json.Marshal(diff)
	if err != nil {
		return ""
	}
	return string(b)
}

func eqIntPtr(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func intPtrVal(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

func eqTimePtr(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

func timePtrVal(p *time.Time) any {
	if p == nil {
		return nil
	}
	return p.UTC().Format(time.RFC3339)
}

// eqMetadata reports whether old (the persisted models.SecretNode.Metadata JSON
// blob) is equivalent to new (the requested replacement map). An unparsable or
// empty old value is treated as an empty map, so setting metadata on a secret
// that previously had none still registers as a change.
func eqMetadata(old models.JSON, new map[string]string) bool {
	return reflect.DeepEqual(metadataMap(old), new)
}

// metadataMap decodes a models.SecretNode.Metadata JSON blob into a map,
// treating anything unparsable/empty as an empty (non-nil) map.
func metadataMap(old models.JSON) map[string]string {
	m := map[string]string{}
	if len(old) > 0 {
		_ = json.Unmarshal(old, &m)
	}
	return m
}

// metadataVal returns the "before" side of a metadata diff entry.
func metadataVal(old models.JSON) any {
	return metadataMap(old)
}
