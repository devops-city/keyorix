// admin_billing.go — GET /api/v1/admin/billing/report handler.
//
// Returns a per-project FinOps billing report (secret counts, read/write
// activity, machine vs. human breakdowns) for a configurable date range, for
// every project or a caller-supplied ?project_id= list, with no ownership
// check anywhere in the call chain. Gated by audit.read in the router (NOT
// system.read — see admin_usage.go's header comment for why: system.read is
// the universal system_viewer baseline every user holds, so it is equivalent
// to no gate at all for a disclosure-sensitive, deployment-wide report; same
// family as CP-001/CP-008) and the "billing" license feature in
// core.GenerateBillingReport — the license check is a deployment capability
// gate, not a per-caller authorization check, so it does not substitute for
// the audit.read requirement.
package handlers

import (
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/license"
)

// AdminBillingHandler serves GET /api/v1/admin/billing/report.
type AdminBillingHandler struct {
	coreService *core.KeyorixCore
}

// NewAdminBillingHandler constructs an AdminBillingHandler.
func NewAdminBillingHandler(cs *core.KeyorixCore) *AdminBillingHandler {
	return &AdminBillingHandler{coreService: cs}
}

// GetBillingReport handles GET /api/v1/admin/billing/report.
//
// Query params:
//
//	from        string  RFC3339 start of the billing window (required)
//	to          string  RFC3339 end of the billing window (required)
//	project_id  string  comma-separated list of project IDs to filter (optional, omit for all)
func (h *AdminBillingHandler) GetBillingReport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// Parse required "from" param
	fromStr := q.Get("from")
	if fromStr == "" {
		sendError(w, "BadRequest", "Missing required query parameter: from", http.StatusBadRequest, nil)
		return
	}
	from, err := time.Parse(time.RFC3339, fromStr)
	if err != nil {
		sendError(w, "BadRequest", "Invalid 'from' parameter: must be RFC3339 (e.g. 2026-01-01T00:00:00Z)", http.StatusBadRequest, nil)
		return
	}

	// Parse required "to" param
	toStr := q.Get("to")
	if toStr == "" {
		sendError(w, "BadRequest", "Missing required query parameter: to", http.StatusBadRequest, nil)
		return
	}
	to, err := time.Parse(time.RFC3339, toStr)
	if err != nil {
		sendError(w, "BadRequest", "Invalid 'to' parameter: must be RFC3339 (e.g. 2026-02-01T00:00:00Z)", http.StatusBadRequest, nil)
		return
	}

	// Parse optional comma-separated project_id list
	var projectIDs []uint
	if pidStr := q.Get("project_id"); pidStr != "" {
		for part := range strings.SplitSeq(pidStr, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			n, err := strconv.ParseUint(part, 10, 32)
			if err != nil {
				sendError(w, "BadRequest", "Invalid project_id value: "+part, http.StatusBadRequest, nil)
				return
			}
			projectIDs = append(projectIDs, uint(n))
		}
	}

	// Checked here (not just inside core.GenerateBillingReport) so the client gets a
	// distinguishable 403 "license required" response instead of the generic 500
	// clientSafe() masks every other error behind — a caller building a billing UI
	// needs to tell "not licensed" apart from "server broke" to render correctly.
	if !h.coreService.HasLicensedFeature(license.FeatureBilling) {
		sendError(w, "Forbidden", "FinOps billing reports require a commercial license (feature: billing)", http.StatusForbidden, nil)
		return
	}

	report, err := h.coreService.GenerateBillingReport(r.Context(), from, to, projectIDs)
	if err != nil {
		log.Printf("GetBillingReport: %v", err)
		sendError(w, "InternalError", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, report, "")
}
