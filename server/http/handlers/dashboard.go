package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// DashboardHandler handles dashboard HTTP requests.
type DashboardHandler struct {
	coreService *core.KeyorixCore
}

// NewDashboardHandler constructs a DashboardHandler.
func NewDashboardHandler(coreService *core.KeyorixCore) *DashboardHandler {
	return &DashboardHandler{coreService: coreService}
}

// GetStats handles GET /api/v1/dashboard/stats — the caller's own home dashboard
// (their secret/share counts, expiring secrets). Gated by system.read in the router
// (every real principal must hold at least the baseline); the deployment-wide
// aggregate fields it also returns are separately scoped to audit.read inside
// GetDashboardStats, so a baseline caller sees their own numbers with the org-wide
// aggregates zeroed rather than a 403 on their own home page (#272).
func (h *DashboardHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	stats, err := h.coreService.GetDashboardStats(r.Context(), userCtx.UserID, userCtx.Username, userCtx.PrincipalID())
	if err != nil {
		sendError(w, "InternalServerError", "Failed to fetch dashboard stats", http.StatusInternalServerError, nil)
		return
	}

	sendSuccess(w, stats, "")
}

// GetCompliancePosture handles GET /api/v1/compliance/posture — the deployment-wide
// controls-posture snapshot for auditors (gated by audit.read in the router, not the
// universal system_viewer baseline).
func (h *DashboardHandler) GetCompliancePosture(w http.ResponseWriter, r *http.Request) {
	posture, err := h.coreService.GetCompliancePosture(r.Context())
	if err != nil {
		sendError(w, "InternalServerError", "Failed to compute compliance posture", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, posture, "")
}

// GetComplianceDigest handles GET /api/v1/compliance/digest — the on-demand,
// human-readable compliance digest (the same title + body otherwise broadcast on a
// schedule to the notification channels), so an admin can pull a point-in-time
// summary without waiting for the scheduled send. Gated by audit.read in the router.
func (h *DashboardHandler) GetComplianceDigest(w http.ResponseWriter, r *http.Request) {
	title, body, err := h.coreService.BuildComplianceDigest(r.Context())
	if err != nil {
		sendError(w, "InternalServerError", "Failed to build compliance digest", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]string{"title": title, "body": body}, "")
}

// SendComplianceDigest handles POST /api/v1/compliance/digest/send — triggers an
// on-demand broadcast of the compliance digest to the configured notification channels
// (Slack/Teams/webhook/email). Returns {sent: bool}: false when no channel is wired.
// Gated by system.write in the router (same as admin-jobs compliance-digest).
func (h *DashboardHandler) SendComplianceDigest(w http.ResponseWriter, r *http.Request) {
	var actorID uint
	if userCtx := middleware.GetUserFromContext(r.Context()); userCtx != nil {
		actorID = userCtx.UserID
	}
	sent, err := h.coreService.SendComplianceDigest(r.Context(), actorID)
	if err != nil {
		sendError(w, "InternalServerError", "Failed to send compliance digest", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]any{"sent": sent}, "")
}

// VerifyComplianceEvidence handles POST /api/v1/compliance/evidence/verify — checks
// a previously-exported evidence pack against its detached signature. The pack bytes
// are base64-encoded in the request so arbitrary JSON can ride in a JSON envelope.
func (h *DashboardHandler) VerifyComplianceEvidence(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DataB64   string `json:"data_b64"`
		Signature string `json:"signature"`
		Filename  string `json:"filename"` // canonical pack filename (e.g. keyorix-evidence-20060102T150405Z.json); required for AUD-009 filename-bound signatures
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	data, err := base64.StdEncoding.DecodeString(body.DataB64)
	if err != nil {
		sendError(w, "InvalidParameter", "data_b64 must be base64-encoded", http.StatusBadRequest, nil)
		return
	}
	result := h.coreService.VerifyEvidenceSignature(body.Filename, data, body.Signature)
	var actorID uint
	if userCtx := middleware.GetUserFromContext(r.Context()); userCtx != nil {
		actorID = userCtx.UserID
	}
	h.coreService.LogComplianceEvidenceVerified(r.Context(), actorID, body.Filename, result)
	sendSuccess(w, result, "")
}

// GetComplianceControls handles GET /api/v1/compliance/controls — the control
// matrix mapping each enforced control to its ISO 27001 / SOC 2 / NIS2 / DORA
// references with a live status; gated by audit.read in the router.
func (h *DashboardHandler) GetComplianceControls(w http.ResponseWriter, r *http.Request) {
	controls, err := h.coreService.GetComplianceControls(r.Context())
	if err != nil {
		sendError(w, "InternalServerError", "Failed to evaluate compliance controls", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, controls, "")
}

// GetComplianceEvidence handles GET /api/v1/compliance/evidence — the auditor
// evidence pack (posture + supporting records); gated by audit.read in the router.
//
// Returns the pack alongside its canonical archive name and detached
// signature (data_b64/filename/signature, mirroring VerifyComplianceEvidence's
// own request shape) so `keyorix compliance export` can persist exactly what
// `keyorix compliance verify` needs to check later (AUD-009 filename-bound
// signatures) -- this used to return the bare evidence struct with no name or
// signature at all, so export→verify could never produce VALID for a
// genuinely untampered pack (inventory GAP-2 / Finding S16). data_b64, not a
// nested JSON object, because embedding the pack as a raw JSON value inside
// this response would let the outer marshal re-compact its whitespace,
// changing the exact bytes a client receives from the exact bytes that were
// signed.
func (h *DashboardHandler) GetComplianceEvidence(w http.ResponseWriter, r *http.Request) {
	_, filename, data, signature, signed, err := h.coreService.GenerateSignedComplianceEvidence(r.Context())
	if err != nil {
		sendError(w, "InternalServerError", "Failed to assemble compliance evidence", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]any{
		"filename":  filename,
		"data_b64":  base64.StdEncoding.EncodeToString(data),
		"signature": signature,
		"signed":    signed,
	}, "")
}

// GetActivity handles GET /api/v1/dashboard/activity
func (h *DashboardHandler) GetActivity(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	page := 1
	pageSize := 10

	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		// #G44: an unbounded page number forces an equally unbounded SQL OFFSET
		// downstream (deep-pagination DoS), the same class of bug the storage
		// layer's own maxStoragePage ceiling exists to prevent.
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 && p <= 10000 {
			page = p
		}
	}
	if pageSizeStr := r.URL.Query().Get("pageSize"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 100 {
			pageSize = ps
		}
	}

	feed, err := h.coreService.GetActivityFeed(r.Context(), userCtx.UserID, userCtx.Username, page, pageSize)
	if err != nil {
		sendError(w, "InternalServerError", "Failed to fetch activity feed", http.StatusInternalServerError, nil)
		return
	}

	sendSuccess(w, feed, "")
}
