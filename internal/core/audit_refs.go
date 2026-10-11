// audit_refs.go — naming the objects an audit description talks about.
//
// Audit descriptions used to carry only ids ("secret 3 restored", "role 9
// assigned to user 2"), which tells an operator nothing without a second lookup,
// and the lookup is impossible once the object is deleted. New events carry the
// name next to the id, in the shape the older named events already use:
//
//	secret 3 ("db-password") restored
//
// The id stays first and unchanged so everything that parses "kind N" keeps
// working (the web resolver skips a token that is already followed by a name).
// Only NAMES go in here, never a secret value: auditRef reads the Name column of
// the object and nothing else.
//
// Stored events are part of the tamper-evident chain and are never rewritten;
// this only changes what NEW events say. A lookup failure (object already gone,
// storage error) degrades to the bare "kind N" form instead of failing the audit
// write, because the audit row is best-effort enrichment on top of an operation
// that has already happened.
package core

import (
	"context"
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// Audit-reference kinds. The string is the word that precedes the id in the
// description, which is also what the web resolver keys on.
const (
	auditKindSecret  = "secret"
	auditKindProject = "project"
	auditKindRole    = "role"
	auditKindGroup   = "group"
	auditKindUser    = "user"
)

// formatAuditRef renders "kind id" or, when a name is known, `kind id ("name")`.
// %q escapes quotes, control characters and newlines in the name, so a hostile
// name cannot forge a second description clause.
func formatAuditRef(kind string, id uint, name string) string {
	if name == "" {
		return fmt.Sprintf("%s %d", kind, id)
	}
	return fmt.Sprintf("%s %d (%q)", kind, id, name)
}

// auditRef looks the object up through st (pass the transactional handle when the
// caller is inside a transaction, so the read does not need a second connection)
// and renders it with formatAuditRef. Soft-deleted secrets are still named.
func (c *KeyorixCore) auditRef(ctx context.Context, st storage.Storage, kind string, id uint) string {
	return formatAuditRef(kind, id, c.auditObjectName(ctx, st, kind, id))
}

// auditRefTail is auditRef without the leading kind word, for descriptions whose
// verb already ends in it ("removed from group" + `4 ("devs")`).
func (c *KeyorixCore) auditRefTail(ctx context.Context, st storage.Storage, kind string, id uint) string {
	return strings.TrimPrefix(c.auditRef(ctx, st, kind, id), kind+" ")
}

// auditObjectName returns the name of the object, or "" if it cannot be read.
func (c *KeyorixCore) auditObjectName(ctx context.Context, st storage.Storage, kind string, id uint) string {
	if st == nil || id == 0 {
		return ""
	}
	switch kind {
	case auditKindSecret:
		if s, err := st.GetSecretIncludingDeleted(ctx, id); err == nil && s != nil {
			return s.Name
		}
	case auditKindProject:
		if p, err := st.GetProject(ctx, id); err == nil && p != nil {
			return p.Name
		}
	case auditKindRole:
		if r, err := st.GetRole(ctx, id); err == nil && r != nil {
			return r.Name
		}
	case auditKindGroup:
		if g, err := st.GetGroup(ctx, id); err == nil && g != nil {
			return g.Name
		}
	case auditKindUser:
		if u, err := st.GetUser(ctx, id); err == nil && u != nil {
			return u.Username
		}
	}
	return ""
}
