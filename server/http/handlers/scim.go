// scim.go — SCIM 2.0 provisioning endpoints (RFC 7644). Served under /scim/v2,
// authenticated by the static SCIM token (see middleware.SCIMToken). Unlike the API
// handlers these emit raw SCIM JSON (schemas/id/meta) and SCIM-format errors, not
// the {data,message} envelope. This first increment covers the Users resource +
// ServiceProviderConfig; Groups follow.
package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	scimContentType   = "application/scim+json"
	scimUserSchema    = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimListSchema    = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimErrorSchema   = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimPatchOpSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
)

// SCIMHandler serves the SCIM 2.0 user-provisioning endpoints.
type SCIMHandler struct {
	coreService *core.KeyorixCore
}

// NewSCIMHandler constructs the SCIM handler.
func NewSCIMHandler(coreService *core.KeyorixCore) *SCIMHandler {
	return &SCIMHandler{coreService: coreService}
}

func writeSCIM(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", scimContentType)
	w.WriteHeader(status)
	_ = encodeJSONResponse(w, body)
}

func scimError(w http.ResponseWriter, status int, detail string) {
	writeSCIM(w, status, map[string]interface{}{
		"schemas": []string{scimErrorSchema},
		"status":  strconv.Itoa(status),
		"detail":  detail,
	})
}

// toSCIMUser maps a Keyorix user to a SCIM User resource. SCIM userName echoes the
// email (what the IdP sent); the derived Keyorix username is internal.
func toSCIMUser(u *models.User) map[string]interface{} {
	active := u.IsActive && !core.AccountLoginBlocked(u.ID, u.AccountState)
	res := map[string]interface{}{
		"schemas":     []string{scimUserSchema},
		"id":          strconv.FormatUint(uint64(u.ID), 10),
		"userName":    u.Email,
		"displayName": u.DisplayName,
		"active":      active,
		"emails":      []map[string]interface{}{{"value": u.Email, "primary": true}},
		"meta": map[string]interface{}{
			"resourceType": "User",
			"location":     fmt.Sprintf("/scim/v2/Users/%d", u.ID),
		},
	}
	if u.ExternalID != "" {
		res["externalId"] = u.ExternalID
	}
	return res
}

// scimUserPayload is the subset of the SCIM User schema we consume.
type scimUserPayload struct {
	UserName    string `json:"userName"`
	ExternalID  string `json:"externalId"`
	DisplayName string `json:"displayName"`
	Active      *bool  `json:"active"`
	Name        *struct {
		Formatted string `json:"formatted"`
	} `json:"name"`
	Emails []struct {
		Value   string `json:"value"`
		Primary bool   `json:"primary"`
	} `json:"emails"`
}

// primaryEmail returns the best email from the payload (primary, else first, else
// the userName which is conventionally an email).
func (p *scimUserPayload) primaryEmail() string {
	for _, e := range p.Emails {
		if e.Primary && e.Value != "" {
			return e.Value
		}
	}
	if len(p.Emails) > 0 && p.Emails[0].Value != "" {
		return p.Emails[0].Value
	}
	return p.UserName
}

func (p *scimUserPayload) displayName() string {
	if p.DisplayName != "" {
		return p.DisplayName
	}
	if p.Name != nil {
		return p.Name.Formatted
	}
	return ""
}

// GetServiceProviderConfig handles GET /scim/v2/ServiceProviderConfig — advertises
// the SCIM features this server supports.
func (h *SCIMHandler) GetServiceProviderConfig(w http.ResponseWriter, _ *http.Request) {
	writeSCIM(w, http.StatusOK, map[string]interface{}{
		"schemas":               []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri":      "https://github.com/keyorixhq/keyorix",
		"patch":                 map[string]bool{"supported": true},
		"bulk":                  map[string]interface{}{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":                map[string]interface{}{"supported": true, "maxResults": 200},
		"changePassword":        map[string]bool{"supported": false},
		"sort":                  map[string]bool{"supported": false},
		"etag":                  map[string]bool{"supported": false},
		"authenticationSchemes": []map[string]interface{}{{"type": "oauthbearertoken", "name": "Bearer Token", "description": "Static SCIM bearer token"}},
	})
}

var scimUserNameFilter = regexp.MustCompile(`(?i)userName\s+eq\s+"([^"]+)"`)

// ListUsers handles GET /scim/v2/Users — optionally filtered by userName (the only
// filter IdPs use for reconciliation). Returns a SCIM ListResponse.
func (h *SCIMHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	if filter := r.URL.Query().Get("filter"); filter != "" {
		m := scimUserNameFilter.FindStringSubmatch(filter)
		if m == nil {
			scimError(w, http.StatusBadRequest, "only 'userName eq' filtering is supported")
			return
		}
		user, err := h.coreService.FindSCIMUser(r.Context(), "", m[1])
		if err != nil {
			log.Printf("Error finding SCIM user by filter: %v", err)
			scimError(w, http.StatusInternalServerError, clientSafe(err))
			return
		}
		resources := []map[string]interface{}{}
		// FindSCIMUser falls back to an email match against ANY user so
		// ProvisionSCIMUser's create-time dedup can still refuse a colliding email —
		// but that means a userName-filter query here could otherwise surface (and
		// leak the numeric id of) a NATIVE account SCIM never provisioned. Only
		// SCIM-managed accounts are real matches for discovery/reconciliation (#120).
		if user != nil && user.ExternalID != "" {
			resources = append(resources, toSCIMUser(user))
		}
		writeSCIM(w, http.StatusOK, listResponse(resources))
		return
	}
	startIndex, count := scimPaging(r)
	users, total, err := h.coreService.ListSCIMUsersPage(r.Context(), startIndex, count)
	if err != nil {
		log.Printf("Error listing SCIM users: %v", err)
		scimError(w, http.StatusInternalServerError, clientSafe(err))
		return
	}
	resources := make([]map[string]interface{}, 0, len(users))
	for _, u := range users {
		resources = append(resources, toSCIMUser(u))
	}
	writeSCIM(w, http.StatusOK, listResponsePaged(resources, total, startIndex))
}

// scimPaging parses the SCIM startIndex (1-based, default 1) and count (default and
// max SCIMMaxPageSize) query parameters, clamping count so an unfiltered list cannot
// drain the whole directory into a single response.
func scimPaging(r *http.Request) (startIndex, count int) {
	startIndex = 1
	if v := r.URL.Query().Get("startIndex"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			startIndex = n
		}
	}
	count = core.SCIMMaxPageSize
	if v := r.URL.Query().Get("count"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			count = n
		}
	}
	if count > core.SCIMMaxPageSize {
		count = core.SCIMMaxPageSize
	}
	return startIndex, count
}

func listResponse(resources []map[string]interface{}) map[string]interface{} {
	return listResponsePaged(resources, len(resources), 1)
}

func listResponsePaged(resources []map[string]interface{}, total, startIndex int) map[string]interface{} {
	return map[string]interface{}{
		"schemas":      []string{scimListSchema},
		"totalResults": total,
		"startIndex":   startIndex,
		"itemsPerPage": len(resources),
		"Resources":    resources,
	}
}

// GetUser handles GET /scim/v2/Users/{id}. Routed through GetSCIMUser (not the
// generic core.GetUser also used by the admin console/self-profile lookups) so a
// non-SCIM-managed (native) account's id is refused the same way ReplaceUser/
// PatchUser/DeleteUser already refuse one (#120) — a generic 404 either way, so the
// response never confirms whether an out-of-scope id exists at all (#G85).
func (h *SCIMHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	id, ok := scimID(w, r)
	if !ok {
		return
	}
	user, err := h.coreService.GetSCIMUser(r.Context(), id)
	if err != nil {
		scimError(w, http.StatusNotFound, "user not found")
		return
	}
	writeSCIM(w, http.StatusOK, toSCIMUser(user))
}

// CreateUser handles POST /scim/v2/Users — provision a new user.
func (h *SCIMHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var p scimUserPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		scimError(w, http.StatusBadRequest, "invalid SCIM payload")
		return
	}
	if p.UserName == "" {
		scimError(w, http.StatusBadRequest, "userName is required")
		return
	}
	active := true
	if p.Active != nil {
		active = *p.Active
	}
	user, err := h.coreService.ProvisionSCIMUser(r.Context(), 0, p.UserName, p.displayName(), p.primaryEmail(), p.ExternalID, active)
	if err != nil {
		status := http.StatusBadRequest
		msg := err.Error()
		switch {
		case strings.Contains(msg, "already exists"):
			status = http.StatusConflict
		case strings.Contains(msg, errDomainNotAllowed):
			status = http.StatusForbidden
		case strings.Contains(msg, "is required"):
			// Deliberately safe validation message from ProvisionSCIMUser — pass through.
		default:
			log.Printf("Error provisioning SCIM user %q: %v", p.UserName, err)
			msg = clientSafe(err)
		}
		scimError(w, status, msg)
		return
	}
	writeSCIM(w, http.StatusCreated, toSCIMUser(user))
}

// ReplaceUser handles PUT /scim/v2/Users/{id} — full replace of the mutable fields.
func (h *SCIMHandler) ReplaceUser(w http.ResponseWriter, r *http.Request) {
	id, ok := scimID(w, r)
	if !ok {
		return
	}
	var p scimUserPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		scimError(w, http.StatusBadRequest, "invalid SCIM payload")
		return
	}
	dn := p.displayName()
	email := p.primaryEmail()
	user, err := h.coreService.UpdateSCIMUser(r.Context(), 0, id, &dn, &email, p.Active)
	if err != nil {
		log.Printf("Error replacing SCIM user %d: %v", id, err)
		scimError(w, http.StatusNotFound, clientSafe(err))
		return
	}
	writeSCIM(w, http.StatusOK, toSCIMUser(user))
}

func parseSCIMUserPatchOp(path string, value json.RawMessage) (active *bool, displayName *string) {
	switch strings.ToLower(strings.TrimSpace(path)) {
	case "active":
		var b bool
		if json.Unmarshal(value, &b) == nil {
			active = &b
		}
	case "displayname":
		var s string
		if json.Unmarshal(value, &s) == nil {
			displayName = &s
		}
	case "": // no path → value is an object of attributes
		var obj struct {
			Active      *bool   `json:"active"`
			DisplayName *string `json:"displayName"`
		}
		if json.Unmarshal(value, &obj) == nil {
			active = obj.Active
			displayName = obj.DisplayName
		}
	}
	return active, displayName
}

// scimPatch is a minimal SCIM PatchOp body.
type scimPatch struct {
	Operations []struct {
		Op    string          `json:"op"`
		Path  string          `json:"path"`
		Value json.RawMessage `json:"value"`
	} `json:"Operations"`
}

// PatchUser handles PATCH /scim/v2/Users/{id} — applies replace operations. The IdP
// uses this chiefly to flip `active` (deactivate/reactivate); displayName is also
// honoured. Other paths are accepted as no-ops so a provisioning run doesn't fail.
func (h *SCIMHandler) PatchUser(w http.ResponseWriter, r *http.Request) {
	id, ok := scimID(w, r)
	if !ok {
		return
	}
	var patch scimPatch
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		scimError(w, http.StatusBadRequest, "invalid SCIM patch")
		return
	}
	var active *bool
	var displayName *string
	for _, op := range patch.Operations {
		if !strings.EqualFold(op.Op, "replace") && !strings.EqualFold(op.Op, "add") {
			continue
		}
		a, dn := parseSCIMUserPatchOp(op.Path, op.Value)
		if a != nil {
			active = a
		}
		if dn != nil {
			displayName = dn
		}
	}
	user, err := h.coreService.UpdateSCIMUser(r.Context(), 0, id, displayName, nil, active)
	if err != nil {
		log.Printf("Error patching SCIM user %d: %v", id, err)
		scimError(w, http.StatusNotFound, clientSafe(err))
		return
	}
	writeSCIM(w, http.StatusOK, toSCIMUser(user))
}

// DeleteUser handles DELETE /scim/v2/Users/{id} — deprovision (suspend + soft-delete).
func (h *SCIMHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := scimID(w, r)
	if !ok {
		return
	}
	if err := h.coreService.DeprovisionSCIMUser(r.Context(), 0, id); err != nil {
		log.Printf("Error deprovisioning SCIM user %d: %v", id, err)
		scimError(w, http.StatusNotFound, clientSafe(err))
		return
	}
	w.Header().Set("Content-Type", scimContentType)
	w.WriteHeader(http.StatusNoContent)
}

// scimID parses the {id} path parameter, writing a SCIM error on failure.
func scimID(w http.ResponseWriter, r *http.Request) (uint, bool) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		scimError(w, http.StatusBadRequest, "invalid user id")
		return 0, false
	}
	return uint(id), true
}
