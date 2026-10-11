// shares_handler.go — ShareHandler struct, constructor, and response helpers.
//
// Share handler methods are split across:
//   - shares_crud.go  — ShareSecret, UpdateSharePermission, RevokeShare
//   - shares_query.go — ListSecretShares, ListShares, ListSharedSecrets,
//     GetSharingStatusWithIndicators, RemoveSelfFromShare
package handlers

import (
	"log"
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/validation"
)

// ShareHandler handles secret sharing HTTP requests.
type ShareHandler struct {
	coreService *core.KeyorixCore
	validator   *validation.Validator
}

// NewShareHandler creates a new ShareHandler.
func NewShareHandler(coreService *core.KeyorixCore) (*ShareHandler, error) {
	return &ShareHandler{
		coreService: coreService,
		validator:   validation.NewValidator(),
	}, nil
}

func (h *ShareHandler) sendSuccess(w http.ResponseWriter, data interface{}, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := encodeJSONResponse(w, SuccessResponse{Success: true, Data: data, Message: message}); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *ShareHandler) sendError(w http.ResponseWriter, errorType, message string, statusCode int, details interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(statusCode)
	if err := encodeJSONResponse(w, ErrorResponse{
		Error:   errorType,
		Message: message,
		Code:    statusCode,
		Details: details,
	}); err != nil {
		log.Printf("Error encoding JSON error response: %v", err)
	}
}
