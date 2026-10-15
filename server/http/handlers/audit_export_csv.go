// audit_export_csv.go — ExportAuditLogsCSV: a CSV download of audit events for
// compliance hand-off and spreadsheets. Distinct from the JSON /audit/export (SIEM
// pull): this is a single bounded, human/auditor-friendly file with a header row.
package handlers

import (
	"encoding/csv"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// csvExportMaxRows bounds a single CSV download.
const csvExportMaxRows = 10000

// ExportAuditLogsCSV handles GET /api/v1/audit/export.csv — newest-first audit events
// as a CSV attachment. Gated by audit.read AND system.read (router.go) — see
// ExportAuditLogs's doc for why (FIX-1, #2733's sibling class: this export
// includes IPAddress, which /logs and /search deliberately never return).
// Filters: ?project_id, ?user_id, ?since / ?until (RFC3339), ?limit (default
// 1000, cap csvExportMaxRows).
func (h *AuditHandler) ExportAuditLogsCSV(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	filter := parseAuditCSVFilter(r)
	limit := filter.PageSize
	filter.Count = storage.AuditCountNone

	// Streamed in keyset batches over the time indexes (docs/specs/
	// audit-list-keyset.md §3): each batch is written and flushed before the
	// next is read, so neither the server nor the database holds the whole
	// export. A failure before the first byte is a 500. A failure after it
	// aborts the connection (http.ErrAbortHandler): the client sees a truncated
	// transfer, never a well-formed 200 that silently ends early, which an
	// auditor could take for the complete export.
	var cw *csv.Writer
	for written := 0; written < limit; {
		filter.PageSize = min(csvExportBatchRows, limit-written)
		events, _, err := h.coreService.Storage().GetAuditLogs(r.Context(), filter)
		if err != nil {
			if cw == nil {
				sendError(w, "InternalServerError", "Failed to export audit logs", http.StatusInternalServerError, nil)
				return
			}
			log.Printf("audit export.csv: aborting the response after %d rows: %v", written, err)
			panic(http.ErrAbortHandler)
		}
		if cw == nil {
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Content-Disposition", `attachment; filename="audit-export.csv"`)
			cw = csv.NewWriter(w)
			_ = cw.Write([]string{
				"id", "event_time", "event_type", "actor", "actor_type",
				"user_id", "project_id", "secret_id", "ip_address", "success", "description",
			})
		}
		writeAuditCSVRows(cw, events, h.coreService.ResolveUsernames(r.Context(), events), h.coreService.ResolveMachineNames(r.Context(), events))
		cw.Flush()
		if err := cw.Error(); err != nil {
			// The client is gone (or the write failed): nothing more can reach it.
			log.Printf("audit export.csv: write failed after %d rows: %v", written, err)
			return
		}
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		written += len(events)
		if len(events) < filter.PageSize {
			break
		}
		last := events[len(events)-1]
		filter.Before = &storage.AuditCursor{EventTime: last.EventTime, ID: last.ID}
	}
}

// csvExportBatchRows is the keyset batch of the streamed CSV export.
const csvExportBatchRows = 500

func writeAuditCSVRows(cw *csv.Writer, events []*models.AuditEvent, actorNames, machineNames map[uint]string) {
	for _, e := range events {
		success := "true"
		if e.Success != nil && !*e.Success {
			success = "false"
		}
		_ = cw.Write([]string{
			strconv.FormatUint(uint64(e.ID), 10),
			e.EventTime.UTC().Format(time.RFC3339),
			csvSafe(e.EventType),
			csvSafe(auditCSVRowActor(e, actorNames, machineNames)),
			csvSafe(storage.AuditActorKind(e)),
			auditCSVUintStr(e.UserID),
			auditCSVUintStr(e.ProjectID),
			auditCSVUintStr(e.SecretNodeID),
			csvSafe(e.IPAddress),
			success,
			csvSafe(e.Description),
		})
	}
}

func parseAuditCSVFilter(r *http.Request) *storage.AuditFilter {
	filter := &storage.AuditFilter{PageSize: parseAuditCSVLimit(r)}
	if v := r.URL.Query().Get("project_id"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			p := uint(n)
			filter.ProjectID = &p
		}
	}
	if v := r.URL.Query().Get("user_id"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			u := uint(n)
			filter.UserID = &u
		}
	}
	if v := r.URL.Query().Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.StartTime = &t
		}
	}
	if v := r.URL.Query().Get("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.EndTime = &t
		}
	}
	return filter
}

func parseAuditCSVLimit(r *http.Request) int {
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= csvExportMaxRows {
		return l
	}
	return 1000
}

// auditCSVRowActor is the actor column: the acting user's name, or for a machine
// row (no user, a machine identity) the identity's name, as in the JSON audit list
// (#3150). A row with neither stays blank. Names only; no secret material.
func auditCSVRowActor(e *models.AuditEvent, actorNames, machineNames map[uint]string) string {
	if e.UserID == nil && e.MachineIdentityID != nil {
		return storage.AuditActorName(e, actorNames, machineNames)
	}
	return auditCSVActorName(actorNames, e.UserID)
}

func auditCSVActorName(actorNames map[uint]string, id *uint) string {
	if id == nil {
		return ""
	}
	return actorNames[*id]
}

func auditCSVUintStr(id *uint) string {
	if id == nil {
		return ""
	}
	return strconv.FormatUint(uint64(*id), 10)
}
