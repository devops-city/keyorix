// secret_access_log_export.go — ExportSecretAccessLog: serialise a secret's
// access history (secret.read audit events) to CSV or JSON for download.
package core

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/csvsafe"
)

const (
	ExportFormatCSV    = "csv"
	ExportFormatJSON   = "json"
	exportAccessAction = "secret.read"
	// ExportMaxRows is the hard cap on rows returned by ExportSecretAccessLog.
	// Callers needing more should use the paginated SearchAuditLogs instead.
	ExportMaxRows = 10_000
)

// AccessLogExportRow is a single row in a secret access-log export. IPAddress is
// omitted (empty string) unless the caller separately holds audit.read -- see
// ExportSecretAccessLog; this is the same gate AccessHistory
// (server/http/handlers/secrets_access_history.go) applies to the JSON route this
// export mirrors.
type AccessLogExportRow struct {
	EventID   uint      `json:"event_id"`
	SecretID  uint      `json:"secret_id"`
	UserID    *uint     `json:"user_id,omitempty"`
	ActorType string    `json:"actor_type"`
	IPAddress string    `json:"ip_address,omitempty"`
	Success   bool      `json:"success"`
	EventTime time.Time `json:"event_time"`
}

// ExportSecretAccessLog fetches up to ExportMaxRows secret.read audit events
// for secretID and serialises them to the requested format (csv or json).
// Returns the encoded bytes and the MIME content-type.
// An unrecognised format or a non-existent secret returns an error.
//
// #G10: this used to trust the caller for authorization ("callers must verify that the
// requesting user holds secrets.read permission... this function does NOT check per-user
// read permission itself"). It now checks secrets.read itself, matching the HTTP router's
// own gate for this route, so it's safe to call from any transport.
func (k *KeyorixCore) ExportSecretAccessLog(ctx context.Context, actorKind string, actorID, secretID uint, format string) ([]byte, string, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	if format != ExportFormatCSV && format != ExportFormatJSON {
		return nil, "", fmt.Errorf("unsupported export format %q: must be csv or json", format)
	}

	// Verify the secret exists before querying audit events.
	if _, err := k.storage.GetSecret(ctx, secretID); err != nil {
		return nil, "", fmt.Errorf("secret not found")
	}
	if allowed, err := k.AuthorizeSecretPrincipal(ctx, actorKind, actorID, secretID, permSecretsRead); err != nil {
		return nil, "", fmt.Errorf("ExportSecretAccessLog: %w", err)
	} else if !allowed {
		return nil, "", fmt.Errorf("not authorized: insufficient permissions")
	}

	action := exportAccessAction
	events, _, err := k.storage.GetAuditLogs(ctx, &storage.AuditFilter{
		SecretID:  &secretID,
		Action:    &action,
		Count:     storage.AuditCountNone,
		Page:      1,
		PageSize:  ExportMaxRows,
		Ascending: true,
	})
	if err != nil {
		return nil, "", fmt.Errorf("ExportSecretAccessLog: %w", err)
	}

	// Same gate as AccessHistory's JSON route: IPAddress is metadata about the
	// READER's own session, not the secret, so a mere secrets.read caller (already
	// authorized above) must not see where OTHER users read this secret from.
	// Global/unscoped, matching /api/v1/audit/*'s own gate. Fails closed: an
	// authorization-check error is treated as "no".
	includeIP, aerr := k.AuthorizePrincipal(ctx, actorKind, actorID, permAuditRead, Scope{})
	if aerr != nil {
		includeIP = false
	}

	rows := make([]AccessLogExportRow, 0, len(events))
	for _, e := range events {
		success := e.Success == nil || *e.Success
		secID := secretID
		if e.SecretNodeID != nil {
			secID = *e.SecretNodeID
		}
		row := AccessLogExportRow{
			EventID:   e.ID,
			SecretID:  secID,
			UserID:    e.UserID,
			ActorType: e.ActorType,
			Success:   success,
			EventTime: e.EventTime,
		}
		if includeIP {
			row.IPAddress = e.IPAddress
		}
		rows = append(rows, row)
	}

	if format == ExportFormatCSV {
		return encodeCSV(rows), "text/csv; charset=utf-8", nil
	}
	data, err := json.Marshal(rows)
	return data, "application/json; charset=utf-8", err
}

// csvSafe neutralises spreadsheet formula injection (CWE-1236) in a CSV cell. It delegates to the
// shared internal/csvsafe leaf so every layer uses ONE implementation of the neutralisation logic
// instead of carrying its own copy. Kept as a package-local name (a thin, drift-free forwarder) so
// core keeps the csvSafe symbol and the csv-writer completeness guard keeps recognising it.
func csvSafe(s string) string { return csvsafe.Neutralize(s) }

func encodeCSV(rows []AccessLogExportRow) []byte {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	// bytes.Buffer.Write never returns an error; ignore return values.
	_ = w.Write([]string{"event_id", "secret_id", "user_id", "actor_type", "ip_address", "success", "event_time"})
	for _, r := range rows {
		userID := ""
		if r.UserID != nil {
			userID = fmt.Sprintf("%d", *r.UserID)
		}
		_ = w.Write([]string{
			fmt.Sprintf("%d", r.EventID),
			fmt.Sprintf("%d", r.SecretID),
			userID,
			csvSafe(r.ActorType),
			csvSafe(r.IPAddress),
			fmt.Sprintf("%t", r.Success),
			r.EventTime.UTC().Format(time.RFC3339),
		})
	}
	w.Flush()
	return buf.Bytes()
}
