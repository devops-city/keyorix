// audit.go — GetAuditLogs, GetRBACAuditLogs, and audit log types.
//
// For anomaly alert handlers see audit_anomaly.go.
package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// AuditHandler handles audit log HTTP requests.
type AuditHandler struct {
	coreService *core.KeyorixCore
}

// NewAuditHandler constructs an AuditHandler.
func NewAuditHandler(coreService *core.KeyorixCore) *AuditHandler {
	return &AuditHandler{coreService: coreService}
}

// AuditLogEntry is the wire format returned to the frontend.
type AuditLogEntry struct {
	ID        uint   `json:"id"`
	EventType string `json:"event_type"`
	Actor     string `json:"actor"`
	// ActorType is the acting-principal kind: "user" or "machine_identity"
	// (also "system"). Lets the audit view segment/filter human vs machine
	// activity (ADR-023).
	ActorType   string    `json:"actor_type"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
	// Diff is the structured before/after payload for mutation events (parsed
	// from the stored JSON), omitted when absent. Never contains plaintext values.
	Diff json.RawMessage `json:"diff,omitempty"`
	// Impersonation attribution — present on impersonated events. Actors are
	// resolved to human-readable usernames, not opaque IDs.
	Impersonation  bool   `json:"impersonation,omitempty"`
	ImpersonatedBy string `json:"impersonated_by,omitempty"`
	ActingAs       string `json:"acting_as,omitempty"`
}

// GetAuditLogs handles GET /api/v1/audit/logs
func (h *AuditHandler) GetAuditLogs(w http.ResponseWriter, r *http.Request) { // NOSONAR -- cognitive complexity 38, suppress go:S3776
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	page, pageSize := 1, 50
	if p, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && p > 0 {
		page = p
	}
	if ps, err := strconv.Atoi(r.URL.Query().Get("page_size")); err == nil && ps > 0 && ps <= 100 {
		pageSize = ps
	}

	filter := &storage.AuditFilter{Page: page, PageSize: pageSize}

	if action := r.URL.Query().Get("action"); action != "" {
		filter.Action = &action
	}
	if uidStr := r.URL.Query().Get("user_id"); uidStr != "" {
		if uid, err := strconv.ParseUint(uidStr, 10, 32); err == nil {
			u := uint(uid)
			filter.UserID = &u
		}
	}
	if pidStr := r.URL.Query().Get("project_id"); pidStr != "" {
		if pid, err := strconv.ParseUint(pidStr, 10, 32); err == nil {
			p := uint(pid)
			filter.ProjectID = &p
		}
	}
	if sidStr := r.URL.Query().Get("secret_id"); sidStr != "" {
		if sid, err := strconv.ParseUint(sidStr, 10, 32); err == nil {
			s := uint(sid)
			filter.SecretID = &s
		}
	}
	if st := r.URL.Query().Get("start_time"); st != "" {
		if t, err := time.Parse(time.RFC3339, st); err == nil {
			filter.StartTime = &t
		}
	}
	if et := r.URL.Query().Get("end_time"); et != "" {
		if t, err := time.Parse(time.RFC3339, et); err == nil {
			filter.EndTime = &t
		}
	}
	if at := r.URL.Query().Get("actor_type"); validActorType(at) {
		filter.ActorType = &at
	}

	events, total, err := h.coreService.Storage().GetAuditLogs(r.Context(), filter)
	if err != nil {
		sendError(w, "InternalServerError", "Failed to fetch audit logs", http.StatusInternalServerError, nil)
		return
	}

	entries := h.toAuditLogEntries(r.Context(), events)

	totalPages := int(total)/pageSize + 1
	if int(total)%pageSize == 0 && total > 0 {
		totalPages = int(total) / pageSize
	}

	sendSuccess(w, map[string]any{
		"logs":        entries,
		"page":        page,
		"page_size":   pageSize,
		"total":       total,
		"total_pages": totalPages,
	}, "")
}

// toAuditLogEntries converts raw audit events into the UI-oriented AuditLogEntry
// wire shape, resolving actor IDs to human-readable usernames in bulk. Shared by
// every route that returns audit events to a plain audit.read caller
// (GetAuditLogs, SearchAuditLogs) so they can never drift apart on what gets
// redacted — IPAddress and the tamper-evidence hash chain (PrevHash/EntryHash)
// are deliberately never included here; AuditExportEntry (SIEM export) is the
// one wire shape that carries the full-fidelity fields, and it is not reachable
// merely by holding audit.read (see ExportAuditLogs's own gate).
func (h *AuditHandler) toAuditLogEntries(ctx context.Context, events []*models.AuditEvent) []AuditLogEntry {
	actorNames := h.coreService.ResolveUsernames(ctx, events)
	machineNames := h.coreService.ResolveMachineNames(ctx, events)
	entries := make([]AuditLogEntry, 0, len(events))
	for _, e := range events {
		entry := AuditLogEntry{
			ID:          e.ID,
			EventType:   e.EventType,
			Actor:       storage.AuditActorName(e, actorNames, machineNames),
			ActorType:   storage.AuditActorKind(e),
			Description: e.Description,
			Timestamp:   e.EventTime,
		}
		if e.Diff != "" {
			entry.Diff = json.RawMessage(e.Diff)
		}
		if e.Impersonation {
			entry.Impersonation = true
			if e.ImpersonatedBy != nil {
				entry.ImpersonatedBy = actorNames[*e.ImpersonatedBy]
			}
			if e.ActingAs != nil {
				entry.ActingAs = actorNames[*e.ActingAs]
			}
		}
		entries = append(entries, entry)
	}
	return entries
}

// AuditExportEntry is the full-fidelity wire shape for SIEM ingestion. Unlike
// AuditLogEntry (UI-oriented) it preserves the raw IDs, success flag, diff, and
// impersonation attribution so an external system can index every field.
type AuditExportEntry struct {
	ID          uint      `json:"id"`
	EventType   string    `json:"event_type"`
	Timestamp   time.Time `json:"timestamp"`
	Actor       string    `json:"actor"`
	UserID      *uint     `json:"user_id,omitempty"`
	ProjectID   *uint     `json:"project_id,omitempty"`
	SecretID    *uint     `json:"secret_id,omitempty"`
	Description string    `json:"description"`
	IPAddress   string    `json:"ip_address,omitempty"`
	// ActorType is the STORED actor_type, verbatim (hash-covered; "" on legacy
	// rows). ActorKindDisplay is the kind the API shows and filters by
	// (storage.AuditActorKind, #2951).
	ActorType        string          `json:"actor_type"`
	ActorKindDisplay string          `json:"actor_kind_display"`
	Success          bool            `json:"success"`
	Diff             json.RawMessage `json:"diff,omitempty"`
	Impersonation    bool            `json:"impersonation,omitempty"`
	ImpersonatedBy   string          `json:"impersonated_by,omitempty"`
	ActingAs         string          `json:"acting_as,omitempty"`
	// PrevHash/EntryHash are the ADR-029 chain links. Exporting them gives the SIEM
	// (the off-box observer) the anchor needed to detect on-box tampering —
	// including tail-truncation, which on-box re-verification cannot catch.
	PrevHash  string `json:"prev_hash,omitempty"`
	EntryHash string `json:"entry_hash,omitempty"`
}

// ExportAuditLogs handles GET /api/v1/audit/export — a cursor-paginated,
// full-fidelity audit feed for SIEM pull. Authenticated as a normal API caller
// (a SIEM uses a personal access token) and gated by audit.read AND system.read
// (router.go) — a stronger bar than /logs or /search, matching /anomalies'
// gate (FIX-1, #2733's sibling class): this route's AuditExportEntry shape
// includes IPAddress and the tamper-evidence hash chain, which the base
// viewer/project_auditor tier must not be able to read via any route. Advance
// the cursor by passing the last returned id as ?after_id= on the next
// request; next_cursor in the response is the id to use, or null when caught up.
func (h *AuditHandler) ExportAuditLogs(w http.ResponseWriter, r *http.Request) { // NOSONAR -- cognitive complexity 19, suppress go:S3776
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	limit := 100
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 1000 {
		limit = l
	}
	filter := &storage.AuditFilter{Ascending: true, PageSize: limit}
	if aidStr := r.URL.Query().Get("after_id"); aidStr != "" {
		if aid, err := strconv.ParseUint(aidStr, 10, 32); err == nil {
			a := uint(aid)
			filter.AfterID = &a
		}
	}
	if st := r.URL.Query().Get("since"); st != "" {
		if t, err := time.Parse(time.RFC3339, st); err == nil {
			filter.StartTime = &t
		}
	}

	events, _, err := h.coreService.Storage().GetAuditLogs(r.Context(), filter)
	if err != nil {
		sendError(w, "InternalServerError", "Failed to export audit logs", http.StatusInternalServerError, nil)
		return
	}

	actorNames := h.coreService.ResolveUsernames(r.Context(), events)
	machineNames := h.coreService.ResolveMachineNames(r.Context(), events)
	name := func(id *uint) string {
		if id == nil {
			return ""
		}
		return actorNames[*id]
	}

	entries := make([]AuditExportEntry, 0, len(events))
	var nextCursor *uint
	for _, e := range events {
		success := true
		if e.Success != nil {
			success = *e.Success
		}
		entry := AuditExportEntry{
			ID:          e.ID,
			EventType:   e.EventType,
			Timestamp:   e.EventTime,
			Actor:       exportActorName(e, actorNames, machineNames),
			UserID:      e.UserID,
			ProjectID:   e.ProjectID,
			SecretID:    e.SecretNodeID,
			Description: e.Description,
			IPAddress:   e.IPAddress,
			// The stored, hash-covered value (ADR-029): a verifier re-derives
			// entry_hash from these fields, so it must not be rewritten here.
			// The kind the UI shows is the separate actor_kind_display.
			ActorType:        e.ActorType,
			ActorKindDisplay: storage.AuditActorKind(e),
			Success:          success,
			PrevHash:         e.PrevHash,
			EntryHash:        e.EntryHash,
		}
		if e.Diff != "" {
			entry.Diff = json.RawMessage(e.Diff)
		}
		if e.Impersonation {
			entry.Impersonation = true
			entry.ImpersonatedBy = name(e.ImpersonatedBy)
			entry.ActingAs = name(e.ActingAs)
		}
		entries = append(entries, entry)
		id := e.ID
		nextCursor = &id
	}

	sendSuccess(w, map[string]any{
		"events":      entries,
		"count":       len(entries),
		"next_cursor": nextCursor,
	}, "")
}

// exportActorName is the export feed's actor: the acting user's name (blank when
// there is none, as before), or for a machine row the identity's name (#3150), so
// the CLI's --csv, which renders this feed, fills the actor column too.
func exportActorName(e *models.AuditEvent, actorNames, machineNames map[uint]string) string {
	if e.UserID == nil && e.MachineIdentityID != nil {
		return storage.AuditActorName(e, actorNames, machineNames)
	}
	if e.UserID == nil {
		return ""
	}
	return actorNames[*e.UserID]
}

// validActorType reports whether s is an audit actor-type filter value.
func validActorType(s string) bool {
	switch s {
	case core.ActorTypeUser, core.ActorTypeMachine, core.ActorTypeSystem:
		return true
	default:
		return false
	}
}

// GetRBACAuditLogs handles GET /api/v1/audit/rbac-logs — the role-assignment
// audit trail (role.assigned / role.removed).
func (h *AuditHandler) GetRBACAuditLogs(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	page, pageSize := 1, 50
	if p, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && p > 0 {
		page = p
	}
	if ps, err := strconv.Atoi(r.URL.Query().Get("page_size")); err == nil && ps > 0 && ps <= 100 {
		pageSize = ps
	}

	entries, total, err := h.coreService.ListRBACAuditLogs(r.Context(), page, pageSize)
	if err != nil {
		sendError(w, "InternalError", "Failed to retrieve RBAC audit logs", http.StatusInternalServerError, nil)
		return
	}

	logs := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		logs = append(logs, map[string]any{
			"id":             e.ID,
			"action":         e.Action,
			"actor_user_id":  e.ActorUserID,
			"target_user_id": e.TargetUserID,
			"group_id":       e.GroupID,
			"role_id":        e.RoleID,
			"permission_id":  e.PermissionID,
			"project_id":     e.ProjectID,
			"environment_id": e.EnvironmentID,
			"details":        e.Details,
			"created_at":     e.CreatedAt.UTC().Format(time.RFC3339),
		})
	}

	totalPages := 0
	if pageSize > 0 {
		totalPages = int((total + int64(pageSize) - 1) / int64(pageSize))
	}
	sendSuccess(w, map[string]any{
		"logs": logs, "page": page, "page_size": pageSize, "total": total, "total_pages": totalPages,
	}, "")
}

// GetAuditRetention handles GET /api/v1/audit/retention — reports how far back
// the audit trail demonstrably reaches (total events, oldest/newest event,
// coverage days, and whether that covers the NIS2-mandated 12 months). Keyorix
// never purges audit events, so this makes the unlimited-retention claim
// auditable rather than merely asserted.
func (h *AuditHandler) GetAuditRetention(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	cov, err := h.coreService.AuditRetentionCoverage(r.Context())
	if err != nil {
		sendError(w, "InternalError", "Failed to compute audit retention coverage", http.StatusInternalServerError, nil)
		return
	}

	sendSuccess(w, cov, "")
}

// VerifyAuditChain handles GET /api/v1/audit/verify — re-walks the
// tamper-evidence hash chain (ADR-029) and reports whether the audit trail is
// intact, naming the first divergent event on failure.
func (h *AuditHandler) VerifyAuditChain(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	// ?full=true: the full walk is minutes at scale, so it runs as a background
	// job (docs/specs/audit-incremental-verification.md §5) — 202 + a job id to
	// poll at /audit/verify/jobs/{id}. At most one runs at a time.
	if r.URL.Query().Get("full") == "true" {
		id, _, err := h.coreService.StartAuditFullVerification(r.Context())
		if errors.Is(err, core.ErrAuditVerifyJobsUnavailable) {
			// No signing key: no job state can be kept, and the plain report
			// below is itself a full walk now (mode "full").
			h.writeAuditVerifyReport(w, r)
			return
		}
		if err != nil || id == "" {
			if err != nil {
				log.Printf("Error starting full audit verification: %v", err)
			}
			sendError(w, "Conflict", "a full audit verification could not be started (another may be starting on another replica); retry shortly", http.StatusConflict, nil)
			return
		}
		w.Header().Set("Location", "/api/v1/audit/verify/jobs/"+id)
		sendAccepted(w, map[string]any{
			"job_id":     id,
			"state":      core.AuditVerifyJobRunning,
			"status_url": "/api/v1/audit/verify/jobs/" + id,
		}, "full audit verification running")
		return
	}

	h.writeAuditVerifyReport(w, r)
}

func (h *AuditHandler) writeAuditVerifyReport(w http.ResponseWriter, r *http.Request) {
	v, err := h.coreService.VerifyAuditChainIncremental(r.Context())
	if err != nil {
		sendError(w, "InternalError", "Failed to verify audit chain", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, auditVerifyResponse(v), "")
}

// auditVerifyResponse renders a verification report. The pre-incremental keys
// keep their names and presence rules; valid is true only for status "valid".
func auditVerifyResponse(v *core.AuditVerifyReport) map[string]any {
	resp := map[string]any{
		"valid":            v.Valid,
		"status":           v.Status,
		"mode":             v.Mode,
		"chained_events":   v.ChainedEvents,
		"unchained_events": v.UnchainedEvents,
		// The verified chain head — record (chained_events, head_hash) externally to
		// detect tail-truncation / re-seed that an on-box re-walk can't catch alone.
		"head_hash": v.HeadHash,
		"head_id":   v.HeadID,
		// checkpointed=true when the chain was also verified against a signed in-DB
		// checkpoint (ADR-029) — on-box truncation detection a DBA cannot forge.
		"checkpointed": v.Checkpointed,
	}
	if v.Status == core.AuditVerifyStatusBroken {
		resp["first_broken_id"] = v.FirstBrokenID
		resp["reason"] = v.Reason
	}
	if v.NotProvenReason != "" {
		resp["not_proven_reason"] = v.NotProvenReason
	}
	if v.StateReason != "" {
		resp["state_reason"] = v.StateReason
	}
	if v.CheckpointReason != "" {
		resp["checkpoint_reason"] = v.CheckpointReason
	}
	// What this answer covers (incremental mode): the tail this request walked
	// and the last completed full re-walk.
	if v.Coverage != nil {
		resp["coverage"] = v.Coverage
	}
	if v.Mode == core.AuditVerifyModeIncremental {
		resp["last_full_verification_at"] = v.LastFullVerificationAt
		if v.LastFullVerificationAt != nil {
			resp["last_full_verification_started_at"] = v.LastFullVerificationStartedAt
			resp["last_full_verification_through_id"] = v.LastFullVerificationThroughID
			resp["last_full_verification_source"] = v.LastFullVerificationSource
		}
		if v.RollingCycle != nil {
			resp["rolling_cycle"] = v.RollingCycle
		}
	}
	// Surface the latest checkpoint's raw external-notary (RFC 3161) receipt, when one
	// exists — so an operator/monitor can capture it here (this is the surface an
	// operator actually polls, since checkpoints are normally written by the
	// background scheduler, not this request) and verify it independently against the
	// TSA out-of-band, without having to trust this server's own verification (#182).
	if len(v.AnchorToken) > 0 {
		resp["anchor_token"] = base64.StdEncoding.EncodeToString(v.AnchorToken)
		resp["anchor_provider"] = v.AnchorProvider
		if v.AnchoredAt != nil {
			resp["anchored_at"] = v.AnchoredAt.UTC()
		}
		// anchor_trust_root_configured is false when no TSA trust root (ca_cert_path) is
		// configured — the token above was RECORDED (a real RFC 3161 receipt was
		// obtained) but this server has never checked it against any root of trust. A
		// caller must not treat a recorded-but-unverifiable anchor as proof-equivalent
		// to one this server actually verified without checking this first.
		resp["anchor_trust_root_configured"] = v.AnchorTrustRootConfigured
	}
	return resp
}

// GetAuditVerifyJob handles GET /api/v1/audit/verify/jobs/{id} — the status of
// a ?full=true background verification. Same authorization as /audit/verify.
func (h *AuditHandler) GetAuditVerifyJob(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	j, err := h.coreService.AuditFullVerificationJob(r.Context(), chi.URLParam(r, "id"))
	if errors.Is(err, core.ErrAuditVerifyJobNotFound) {
		sendError(w, "NotFound", "audit verification job not found (unknown, or superseded by a newer job)", http.StatusNotFound, nil)
		return
	}
	if err != nil {
		log.Printf("Error reading audit verification job: %v", err)
		sendError(w, "InternalError", "Failed to read audit verification job", http.StatusInternalServerError, nil)
		return
	}
	resp := map[string]any{
		"job_id":     j.JobID,
		"state":      j.State,
		"started_at": j.StartedAt.UTC(),
	}
	if j.FinishedAt != nil {
		resp["finished_at"] = j.FinishedAt.UTC()
	}
	if j.Error != "" {
		resp["error"] = j.Error
	}
	if j.Result != nil {
		resp["result"] = auditVerifyResponse(j.Result)
	}
	sendSuccess(w, resp, "")
}

// WriteAuditCheckpoint handles POST /api/v1/audit/checkpoint — signs a checkpoint
// of the current verified audit-chain head (ADR-029) on demand. The usual source
// of checkpoints is the background scheduler; this lets an operator re-baseline
// immediately — e.g. right after a DEK rotation, when verify fails closed until a
// fresh checkpoint is written under the new key. Privileged (system.write, on top
// of the audit group's audit.read).
func (h *AuditHandler) WriteAuditCheckpoint(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	cp, written, err := h.coreService.WriteAuditCheckpointIncremental(r.Context())
	if err != nil {
		// The chain did not verify (broken, or a prior signed checkpoint proves a
		// truncation) — the server refuses to notarise it. Surface the reason so the
		// operator can investigate; it is a precondition failure, not a server error.
		// core.WriteAuditCheckpoint also propagates raw storage-layer errors on this
		// path (e.g. a lookup failure), which must not reach the client verbatim.
		msg := err.Error()
		if !strings.Contains(msg, "refusing to checkpoint") {
			log.Printf("Error writing audit checkpoint: %v", err)
			msg = clientSafe(err)
		}
		sendError(w, "Conflict", msg, http.StatusConflict, nil)
		return
	}
	if !written {
		sendError(w, "PreconditionFailed",
			"signed audit checkpoints require encryption to be enabled (the signing key is derived from the DEK)",
			http.StatusPreconditionFailed, nil)
		return
	}

	resp := map[string]any{
		"id":             cp.ID,
		"chained_events": cp.ChainedEvents,
		"head_id":        cp.HeadID,
		"head_hash":      cp.HeadHash,
		"key_version":    cp.KeyVersion,
	}
	// Surface the external-notary anchor when one was obtained (ADR-029), including the
	// raw receipt token — the operator's only chance to capture it from THIS write's
	// response, since checkpoints are normally written by the background scheduler, not
	// this endpoint (#182: independent/off-box verification needs the raw token, not
	// just the asserted time/provider strings).
	if cp.AnchoredAt != nil {
		resp["anchored_at"] = cp.AnchoredAt.UTC()
		resp["anchor_provider"] = cp.AnchorProvider
		resp["anchor_token"] = base64.StdEncoding.EncodeToString(cp.AnchorToken)
		// See VerifyAuditChain's anchor_trust_root_configured for what this means: a
		// token was recorded either way, but without a trust root this server cannot
		// (and never will, until one is configured) verify it locally.
		resp["anchor_trust_root_configured"] = h.coreService.CheckpointAnchorVerifiable()
	}
	sendSuccess(w, resp, "audit checkpoint written")
}

// MigrateAuditChainEncoding handles POST /api/v1/audit/migrate-chain-encoding —
// a one-time, operator-triggered re-derivation of entry_hash/prev_hash for
// every chained audit_events row under the current hash encoding (see
// internal/core/audit_chain_migrate.go's doc comment for why this exists and
// why it is deliberately NOT automatic). Privileged (system.write, same bar
// as /checkpoint): this rewrites the one dataset whose entire purpose is
// tamper evidence.
//
// ?dry_run=true (the default when the query param is absent) computes and
// returns the result WITHOUT persisting anything, so an operator can preview
// row/anchor counts before committing. A real run requires the query param
// set explicitly to "false" — there is no way to trigger a real run by
// omission or typo, only by deliberately opting out of the safe default.
//
// The caller is responsible for ensuring no other process can reach this
// server's audit_events table for the duration of a real run (stop the
// server's OTHER instances if load-balanced, or run during a maintenance
// window) — this endpoint's own transaction only serializes against this
// process's own LogAuditEvent path, not an entirely separate connection.
func (h *AuditHandler) MigrateAuditChainEncoding(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	dryRun := r.URL.Query().Get("dry_run") != "false"

	result, err := h.coreService.MigrateAuditChainEncoding(r.Context(), userCtx.UserID, dryRun)
	if err != nil {
		log.Printf("Error migrating audit chain encoding: %v", err)
		sendError(w, "InternalError", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}

	resp := map[string]any{
		"dry_run":                dryRun,
		"rows_migrated":          result.RowsMigrated,
		"unchained_rows_skipped": result.UnchainedRowsSkipped,
		"head_id":                result.HeadID,
		"head_hash":              result.HeadHash,
	}
	if result.AnchorRowID != 0 {
		resp["anchor_row_id"] = result.AnchorRowID
		resp["anchor_new_entry_hash"] = result.AnchorNewEntryHash
	}
	msg := "audit chain encoding migration preview (dry run — nothing was written; re-run with ?dry_run=false to apply)"
	if !dryRun {
		msg = "audit chain encoding migration applied"
	}
	sendSuccess(w, resp, msg)
}
