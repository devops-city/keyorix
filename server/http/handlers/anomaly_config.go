// anomaly_config.go — GET/PUT /api/v1/admin/anomaly-config
//
// Allows operators to read and update the runtime anomaly detection
// configuration (lookback window, quarantine, off-hours, ML parameters)
// without restarting the server.  Changes are persisted to the DB and picked
// up by the anomaly detection scheduler on its next pass.
package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// GetAnomalyConfig handles GET /api/v1/admin/anomaly-config.
// Returns the current persisted anomaly detection configuration (or defaults).
func GetAnomalyConfig(w http.ResponseWriter, r *http.Request) {
	coreService := middleware.GetCoreServiceFromContext(r.Context())
	if coreService == nil {
		sendError(w, "InternalError", "Core service not available", http.StatusInternalServerError, nil)
		return
	}
	cfg, err := coreService.GetAnomalyConfig(r.Context())
	if err != nil {
		sendError(w, "InternalError", "Failed to retrieve anomaly config", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]any{"config": cfg}, "")
}

// UpdateAnomalyConfig handles PUT /api/v1/admin/anomaly-config.
// Replaces the current anomaly detection configuration; the detection scheduler
// will pick up the change on its next pass without a restart.
func UpdateAnomalyConfig(w http.ResponseWriter, r *http.Request) {
	coreService := middleware.GetCoreServiceFromContext(r.Context())
	if coreService == nil {
		sendError(w, "InternalError", "Core service not available", http.StatusInternalServerError, nil)
		return
	}

	var cfg models.AnomalyConfigRecord
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	var updatedBy string
	var actorID uint
	if u := middleware.GetUserFromContext(r.Context()); u != nil {
		updatedBy = u.Username
		actorID = u.UserID
	}

	if err := coreService.UpdateAnomalyConfig(r.Context(), &cfg, updatedBy, actorID); err != nil {
		// core.UpdateAnomalyConfig returns a plain (unwrapped) validation error
		// from validateAnomalyConfig when a knob exceeds its ceiling (#G44) --
		// e.g. "lookback_days exceeds the maximum of 365" -- before ever
		// reaching storage. That's caller input error, not a server failure;
		// treating it as 500 (as this used to, unconditionally) misreports a
		// bad request as an internal error, same class of fix as
		// secrets_bulk_rotate.go's BulkRotateSecrets/catalog.go's
		// CloneEnvironment string-matching their own core layer's validation
		// errors.
		if strings.Contains(err.Error(), "exceeds the maximum") {
			sendError(w, "BadRequest", err.Error(), http.StatusBadRequest, nil)
			return
		}
		sendError(w, "InternalError", "Failed to save anomaly config", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]any{"config": cfg}, "")
}
