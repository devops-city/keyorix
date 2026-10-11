// secret_tags.go — free-form tags on a secret, for organization and (follow-up)
// tag-based search. Tags are lowercase, trimmed, de-duplicated labels shared across
// secrets (a global Tag table, associated per secret). Get requires read on the
// secret; Set requires write. Setting replaces the secret's whole tag set and is
// audited. Tags are metadata only — they never carry or reveal a secret value.
package core

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/keyorixhq/keyorix/internal/i18n"
)

const (
	maxSecretTags   = 20 // most tags one secret may carry
	maxSecretTagLen = 50 // longest a single tag may be
)

// EventSecretTagsUpdated is audited when a secret's tag set changes.
const EventSecretTagsUpdated = "secret.tags_updated"

// GetSecretTags returns the secret's tags (sorted). The actor must be able to read it.
func (c *KeyorixCore) GetSecretTags(ctx context.Context, secretID, actorID uint) ([]string, error) {
	if _, err := c.EnforceSecretReadPermission(ctx, secretID, actorID); err != nil {
		return nil, err
	}
	tags, err := c.storage.GetSecretTags(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return tags, nil
}

// SetSecretTags replaces the secret's tags with the normalized input and returns the
// stored set. The actor must be able to write the secret. Tag names are trimmed,
// lowercased, de-duplicated, and bounded (≤20 tags, ≤50 chars each); empties are
// dropped. Audited as secret.tags_updated.
func (c *KeyorixCore) SetSecretTags(ctx context.Context, secretID, actorID uint, tags []string) ([]string, error) {
	if _, err := c.EnforceSecretWritePermission(ctx, secretID, actorID); err != nil {
		return nil, err
	}
	normalized, err := normalizeTags(tags)
	if err != nil {
		return nil, err
	}
	if err := c.storage.SetSecretTags(ctx, secretID, normalized); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	uid := actorID
	sid := secretID
	c.writeAuditEvent(ctx, EventSecretTagsUpdated, &uid, &sid,
		fmt.Sprintf("set %d tag(s) on %s", len(normalized), c.auditRef(ctx, c.storage, auditKindSecret, secretID)))
	return normalized, nil
}

// normalizeTags trims, lowercases, de-duplicates (preserving first-seen order), and
// bounds a tag list. Returns a validation error if a tag is too long or there are too
// many.
func normalizeTags(in []string) ([]string, error) {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		t := strings.ToLower(strings.TrimSpace(raw))
		if t == "" {
			continue
		}
		if len(t) > maxSecretTagLen {
			return nil, fmt.Errorf("%s: tag %q exceeds %d characters", i18n.T("ErrorValidation", nil), t, maxSecretTagLen)
		}
		if seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	if len(out) > maxSecretTags {
		return nil, fmt.Errorf("%s: at most %d tags per secret", i18n.T("ErrorValidation", nil), maxSecretTags)
	}
	sort.Strings(out)
	return out, nil
}
