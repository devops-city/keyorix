// access_review_campaign_export_csv.go — ExportAccessReviewCampaignCSV: a CSV download
// of an access-review campaign's items + decisions, for an auditor to archive as the
// signed-off recertification record (ISO 27001 A.5.18). Parallels the audit CSV export;
// reuses GetAccessReviewCampaign for the data and resolves reviewer names once.
package handlers

import (
	"encoding/csv"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// ExportAccessReviewCampaignCSV handles GET
// /api/v1/projects/{id}/access-review/campaigns/{campaignId}/export.csv — every item of
// the campaign with its recertification decision as a CSV attachment. Scoped roles.read
// (project) is enforced by the router. No secret values.
func (h *CatalogHandler) ExportAccessReviewCampaignCSV(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	projectID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	campaignID, err := strconv.ParseUint(chi.URLParam(r, "campaignId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid campaign ID", http.StatusBadRequest, nil)
		return
	}

	detail, err := h.coreService.GetAccessReviewCampaign(r.Context(), uint(projectID), uint(campaignID))
	if err != nil {
		log.Printf("ExportAccessReviewCampaignCSV: error: %v", err)
		sendError(w, "Error", clientSafe(err), campaignStatusForError(err.Error()), nil)
		return
	}

	// Resolve reviewer (decided_by) usernames once per distinct decider.
	deciderName := map[uint]string{}
	for _, it := range detail.Items {
		if it.DecidedBy != 0 {
			deciderName[it.DecidedBy] = ""
		}
	}
	for id := range deciderName {
		if u, err := h.coreService.Storage().GetUser(r.Context(), id); err == nil && u != nil {
			deciderName[id] = u.Username
		}
	}

	tstr := func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.UTC().Format(time.RFC3339)
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", `attachment; filename="access-review-campaign-`+strconv.FormatUint(campaignID, 10)+`.csv"`)

	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{
		"principal_type", "principal", "email", "source", "role", "access_level",
		"environment_id", "secret", "last_used_at", "decision", "reason", "decided_by", "decided_at",
		// What an empty last_used_at means: no use within this many days before the
		// campaign was opened ("all_history" for a campaign opened before the window).
		"last_used_window_days",
	})
	window := "all_history"
	if detail.Campaign != nil && detail.Campaign.ActivityWindowDays > 0 {
		window = strconv.Itoa(detail.Campaign.ActivityWindowDays)
	}
	for _, it := range detail.Items {
		_ = cw.Write([]string{
			csvSafe(it.PrincipalType),
			csvSafe(it.PrincipalName),
			csvSafe(it.Email),
			csvSafe(it.Source),
			csvSafe(it.RoleName),
			csvSafe(it.AccessLevel),
			strconv.FormatUint(uint64(it.EnvironmentID), 10),
			csvSafe(it.SecretName),
			tstr(it.LastUsedAt),
			csvSafe(it.Decision),
			csvSafe(it.Reason),
			csvSafe(deciderName[it.DecidedBy]),
			tstr(it.DecidedAt),
			window,
		})
	}
}
