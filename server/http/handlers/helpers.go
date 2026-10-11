package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/besteffort"
	"github.com/keyorixhq/keyorix/server/middleware"
)

const (
	hdrContentType         = "Content-Type"
	hdrXContentTypeOptions = "X-Content-Type-Options"
	mimeApplicationJSON    = "application/json"
)

// sendSuccess sends a successful JSON response
//
// The envelope always carries "success": true (in addition to the implicit 2xx
// status code). Every internal/storage/store/remote_*.go method backing
// storage.type: remote decodes the upstream body into
// internal/storage/remote.APIResponse and branches on its Success field, NOT
// the HTTP status — before this field was added, that field silently defaulted
// to Go's zero value (false) for every genuinely successful response from a
// real (non-test-mock) production server, so the entire storage.type: remote
// deployment mode misreported every successful proxied read/write as a
// failure. This is a purely additive JSON key: existing consumers of the
// "data"/"message" keys are unaffected.
func sendSuccess(w http.ResponseWriter, data interface{}, message string) {
	w.Header().Set(hdrContentType, mimeApplicationJSON)
	w.Header().Set(hdrXContentTypeOptions, "nosniff")

	response := map[string]interface{}{
		"success": true,
		"data":    utcTimes(data),
	}
	if message != "" {
		response["message"] = message
	}

	if err := encodeJSONResponse(w, response); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// sendCreated writes a 201 Created JSON success response with correctly ordered
// headers. Unlike calling w.WriteHeader(201) before sendSuccess (which causes
// sendSuccess's Header().Set() calls to be silently ignored), this function sets
// Content-Type and X-Content-Type-Options before WriteHeader.
func sendCreated(w http.ResponseWriter, data interface{}, message string) {
	w.Header().Set(hdrContentType, mimeApplicationJSON)
	w.Header().Set(hdrXContentTypeOptions, "nosniff")
	w.WriteHeader(http.StatusCreated)
	response := map[string]interface{}{
		"success": true,
		"data":    utcTimes(data),
	}
	if message != "" {
		response["message"] = message
	}
	if err := encodeJSONResponse(w, response); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
	}
}

// clientSafe returns a generic, client-safe message in place of err's raw
// Error() text. Use it at the fallback/default branch of an error path once
// the caller has already carved out the small set of deliberately-crafted,
// known-safe outcomes (validation messages, "not found", "already exists",
// etc.) — everything left over is assumed to originate from a lower layer
// (database/ORM/driver, an upstream secret-store connector, a parser) whose
// raw text can leak schema, driver, or hostname details that help an
// attacker fingerprint the backend (backlog #116). The caller MUST still log
// the original err server-side (e.g. via log.Printf) before calling this —
// clientSafe only sanitizes the copy that reaches the client.
func clientSafe(err error) string {
	if err == nil {
		return ""
	}
	return "an internal error occurred; please try again or contact support if the problem persists"
}

// goSafe runs fn in a detached goroutine with panic recovery. Auth handlers
// spawn "fire and forget" goroutines for side effects (audit logging,
// last-login stamps) so the HTTP response isn't blocked on that I/O — but
// those goroutines run on the hottest, lowest-privilege request path (every
// login attempt), and are NOT covered by the HTTP server's per-request
// recovery middleware, which only guards the goroutine actually serving the
// request. A panic in a bare `go func(){...}()` here (nil pointer, index
// out of range, etc., even in "just logging" code) would crash the entire
// process for every in-flight user — a low-privilege DoS lever (backlog
// #243). goSafe closes that gap: any panic in fn is recovered and logged
// instead of taking the server down. Use it in place of a bare `go` for any
// detached side-effect goroutine spawned from a request handler. The actual
// recover/log/metric logic lives in besteffort.RunRecover (package
// besteffort), shared with internal/core's and server/grpc/services'
// identical goSafe.
// goSafeWG tracks every in-flight goSafe goroutine so tests can deterministically
// wait for detached audit/side-effect writes to land instead of guessing with a
// sleep (see DrainBackgroundGoroutines). Negligible overhead in production — one
// Add/Done pair per dispatch, no contention outside test use of the Wait below.
var goSafeWG sync.WaitGroup

// DrainBackgroundGoroutines blocks until every goSafe goroutine dispatched so far
// by this package has returned. Test-only observability hook: production code has
// no reason to call it (goSafe is fire-and-forget by design), but a test asserting
// on an async side effect (e.g. an audit row) needs a deterministic point to scan
// at, not a fixed sleep that can race a slow write and silently miss a real leak.
func DrainBackgroundGoroutines() {
	goSafeWG.Wait()
}

func goSafe(fn func()) {
	goSafeWG.Add(1)
	go func() {
		defer goSafeWG.Done()
		defer besteffort.RunRecover("http.goSafe")()
		fn()
	}()
}

// mustParseUintParam parses a named URL parameter as a uint, sending a 400 error on failure.
// On failure it writes a 400 response and returns (0, false); the caller should return immediately.
// Eliminates repeated ParseUint+sendError blocks across handler files.
func mustParseUintParam(w http.ResponseWriter, r *http.Request, param, errKey, errMsg string) (uint, bool) {
	v, err := strconv.ParseUint(chi.URLParam(r, param), 10, 32)
	if err != nil {
		sendError(w, errKey, errMsg, http.StatusBadRequest, nil)
		return 0, false
	}
	return uint(v), true
}

// mustParseProjectID extracts and validates the "id" URL parameter as a uint project ID.
// On failure it writes a 400 response and returns (0, false); the caller should return immediately.
func mustParseProjectID(w http.ResponseWriter, r *http.Request) (uint, bool) {
	return mustParseUintParam(w, r, "id", "InvalidParameter", errInvalidProjectID)
}

// mustGetUser retrieves the authenticated user from the request context.
// On failure it writes a 401 response and returns (nil, false); the caller should return immediately.
// Eliminates the repeated 4-line GetUserFromContext+sendError block across handler files.
func mustGetUser(w http.ResponseWriter, r *http.Request) (*middleware.UserContext, bool) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return nil, false
	}
	return user, true
}

// mustDecodeBody decodes the JSON request body into v.
// On failure it writes a 400 response and returns false; the caller should return immediately.
// Eliminates the repeated 4-line json.NewDecoder+sendError block across handler files.
func mustDecodeBody(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		sendError(w, "InvalidJSON", errInvalidRequestBody, http.StatusBadRequest, nil)
		return false
	}
	return true
}

// sendError sends an error JSON response
//
// Explicitly carries "success": false. This is not strictly load-bearing for
// internal/storage/remote.HTTPClient today: this body's "error" key is a bare
// string, which doesn't unmarshal into APIResponse.Error's *APIError struct
// type, so json.Unmarshal already fails and makeRequest's parse-failure branch
// synthesizes its own Success:false/Error response instead of ever reading
// this body's fields. That's an accidental, fragile safety net (it would stop
// working the moment this "error" key were ever reshaped into an object to
// match APIError) — writing the field explicitly here means the error path no
// longer depends on that coincidence.
func sendError(w http.ResponseWriter, errorType, message string, statusCode int, details interface{}) {
	w.Header().Set(hdrContentType, mimeApplicationJSON)
	w.Header().Set(hdrXContentTypeOptions, "nosniff")
	w.WriteHeader(statusCode)

	response := map[string]interface{}{
		"success": false,
		"error":   errorType,
		"message": message,
		"code":    statusCode,
	}
	if details != nil {
		response["details"] = details
	}

	if err := encodeJSONResponse(w, response); err != nil {
		log.Printf("Error encoding JSON error response: %v", err)
	}
}
