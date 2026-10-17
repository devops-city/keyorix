// Package accesstarget implements accessplan.KeyorixReader (and the Project/Environment
// listing PathMapper construction needs) over the generated apiclient — ADR-114's "talks to
// Keyorix only through the public REST API" rule, same as internal/target does for secret
// values. Every call here is read-only: `vault plan-access` never writes to Keyorix.
package accesstarget

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"unicode"

	"github.com/keyorixhq/keyorix/migrate/internal/accessplan"
	"github.com/keyorixhq/keyorix/migrate/internal/apiclient"
	"github.com/keyorixhq/keyorix/migrate/internal/migrateversion"
)

// clientOriginHeader mirrors internal/core.ClientOriginHeader and internal/target's identically-
// named constant (module boundary — migrate's internal packages don't import each other's
// unexported helpers). The server records its value on the write's audit event as a labelled,
// client-asserted note, so a role/machine identity/grant/OIDC binding apply-access creates is
// distinguishable from a hand-created one in the audit trail — the same #2545 fix internal/
// target already applies to secret values, extended here to every access-model write.
const clientOriginHeader = "X-Keyorix-Client-Origin"

// originEditor sets clientOriginHeader for a write, naming this tool and (via
// accessplan.SourceOrigin) the exact Vault policy/role this object came from. Mirrors internal/
// target's originEditor exactly.
func originEditor(ctx context.Context) apiclient.RequestEditorFn {
	return func(_ context.Context, req *http.Request) error {
		v := "keyorix-migrate/" + migrateversion.Version
		if src := accessplan.SourceOrigin(ctx); src != "" {
			v += " source=" + src
		}
		req.Header.Set(clientOriginHeader, strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return -1
			}
			return r
		}, v))
		return nil
	}
}

// Client implements accessplan.KeyorixReader over the generated apiclient.
type Client struct {
	api *apiclient.ClientWithResponses
}

func New(api *apiclient.ClientWithResponses) *Client {
	return &Client{api: api}
}

// ListProjects returns every project, for PathMapper construction.
func (c *Client) ListProjects(ctx context.Context) ([]accessplan.ProjectRef, error) {
	resp, err := c.api.ListProjectsWithResponse(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil || resp.JSON200.Data.Projects == nil {
		return nil, apiErr("list projects", resp.StatusCode(), resp.Body)
	}
	out := make([]accessplan.ProjectRef, 0, len(*resp.JSON200.Data.Projects))
	for _, p := range *resp.JSON200.Data.Projects {
		if p.Id == nil || p.Name == nil {
			continue
		}
		out = append(out, accessplan.ProjectRef{ID: *p.Id, Name: *p.Name})
	}
	return out, nil
}

// ListEnvironments returns every environment under projectID, for PathMapper construction.
func (c *Client) ListEnvironments(ctx context.Context, projectID int) ([]accessplan.EnvironmentRef, error) {
	if projectID < 0 || int64(projectID) > math.MaxUint32 { // int64: on 32-bit targets an int cannot be compared with a constant above MaxInt32
		return nil, fmt.Errorf("list environments: project id %d out of range", projectID)
	}
	resp, err := c.api.ListProjectEnvironmentsWithResponse(ctx, uint32(projectID), nil)
	if err != nil {
		return nil, fmt.Errorf("list environments for project %d: %w", projectID, err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil || resp.JSON200.Data.Environments == nil {
		return nil, apiErr("list environments", resp.StatusCode(), resp.Body)
	}
	out := make([]accessplan.EnvironmentRef, 0, len(*resp.JSON200.Data.Environments))
	for _, e := range *resp.JSON200.Data.Environments {
		if e.Id == nil || e.Name == nil {
			continue
		}
		out = append(out, accessplan.EnvironmentRef{ID: *e.Id, Name: *e.Name})
	}
	return out, nil
}

// RoleDescriptionByName implements accessplan.KeyorixReader.
func (c *Client) RoleDescriptionByName(ctx context.Context, name string) (int, string, bool, error) {
	resp, err := c.api.GetRoleByNameWithResponse(ctx, &apiclient.GetRoleByNameParams{Name: name})
	if err != nil {
		return 0, "", false, fmt.Errorf("look up role %q: %w", name, err)
	}
	if resp.StatusCode() == http.StatusNotFound {
		return 0, "", false, nil
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return 0, "", false, apiErr("look up role", resp.StatusCode(), resp.Body)
	}
	id := 0
	if resp.JSON200.Data.Id != nil {
		id = *resp.JSON200.Data.Id
	}
	desc := ""
	if resp.JSON200.Data.Description != nil {
		desc = *resp.JSON200.Data.Description
	}
	return id, desc, true, nil
}

// findMachineIdentity lists every machine identity in projectID and returns the one named name,
// or found=false. There is no by-name lookup route (unlike roles' GET /roles/by-name), so this
// lists and searches client-side — acceptable for a one-shot CLI command against a bounded
// per-project machine identity count, not a hot path.
func (c *Client) findMachineIdentity(ctx context.Context, projectID int, name string) (*apiclient.MachineIdentity, bool, error) {
	resp, err := c.api.ListMachineIdentitiesWithResponse(ctx, projectID)
	if err != nil {
		return nil, false, fmt.Errorf("list machine identities in project %d: %w", projectID, err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil || resp.JSON200.Data.MachineIdentities == nil {
		return nil, false, apiErr("list machine identities", resp.StatusCode(), resp.Body)
	}
	for i, m := range *resp.JSON200.Data.MachineIdentities {
		if m.Name != nil && *m.Name == name {
			return &(*resp.JSON200.Data.MachineIdentities)[i], true, nil
		}
	}
	return nil, false, nil
}

// MachineIdentityDescriptionByName implements accessplan.KeyorixReader.
func (c *Client) MachineIdentityDescriptionByName(ctx context.Context, projectID int, name string) (int, string, bool, error) {
	m, found, err := c.findMachineIdentity(ctx, projectID, name)
	if err != nil || !found {
		return 0, "", found, err
	}
	id := 0
	if m.Id != nil {
		id = *m.Id
	}
	desc := ""
	if m.Description != nil {
		desc = *m.Description
	}
	return id, desc, true, nil
}

// MachineHasRoleGrant implements accessplan.KeyorixReader.
func (c *Client) MachineHasRoleGrant(ctx context.Context, projectID int, machineName, roleName string) (bool, error) {
	m, found, err := c.findMachineIdentity(ctx, projectID, machineName)
	if err != nil {
		return false, err
	}
	if !found || m.Id == nil {
		return false, nil // the identity doesn't exist yet — apply-access creates it first.
	}
	resp, err := c.api.ListMachineRolesWithResponse(ctx, projectID, *m.Id)
	if err != nil {
		return false, fmt.Errorf("list roles for machine identity %q: %w", machineName, err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil || resp.JSON200.Data.Roles == nil {
		return false, apiErr("list machine roles", resp.StatusCode(), resp.Body)
	}
	for _, r := range *resp.JSON200.Data.Roles {
		if r.Name != nil && *r.Name == roleName {
			return true, nil
		}
	}
	return false, nil
}

// MachineHasOIDCBinding implements accessplan.KeyorixReader.
func (c *Client) MachineHasOIDCBinding(ctx context.Context, projectID int, machineName, issuer, subject string) (bool, error) {
	m, found, err := c.findMachineIdentity(ctx, projectID, machineName)
	if err != nil {
		return false, err
	}
	if !found || m.Id == nil {
		return false, nil
	}
	resp, err := c.api.ListOIDCBindingsWithResponse(ctx, projectID, *m.Id)
	if err != nil {
		return false, fmt.Errorf("list OIDC bindings for machine identity %q: %w", machineName, err)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil || resp.JSON200.Data.Bindings == nil {
		return false, apiErr("list oidc bindings", resp.StatusCode(), resp.Body)
	}
	for _, b := range *resp.JSON200.Data.Bindings {
		if b.Issuer != nil && b.Subject != nil && *b.Issuer == issuer && *b.Subject == subject {
			return true, nil
		}
	}
	return false, nil
}

// CreateRole implements accessplan.KeyorixWriter.
func (c *Client) CreateRole(ctx context.Context, name, description string, permissions []string) (int, error) {
	resp, err := c.api.CreateRoleWithResponse(ctx, apiclient.CreateRoleJSONRequestBody{
		Name: name, Description: description, Permissions: permissions,
	}, originEditor(ctx))
	if err != nil {
		return 0, fmt.Errorf("create role %q: %w", name, err)
	}
	if resp.JSON201 == nil || resp.JSON201.Data == nil || resp.JSON201.Data.Role == nil || resp.JSON201.Data.Role.Id == nil {
		return 0, apiErr("create role", resp.StatusCode(), resp.Body)
	}
	return *resp.JSON201.Data.Role.Id, nil
}

// CreateMachineIdentity implements accessplan.KeyorixWriter. core.CreateMachineIdentity
// creates it already in state "active" (internal/core/machine_identities.go — confirmed live
// against a real server), so no separate activation step follows.
func (c *Client) CreateMachineIdentity(ctx context.Context, projectID int, name, identityType, description string) (int, error) {
	resp, err := c.api.CreateMachineIdentityWithResponse(ctx, projectID, apiclient.CreateMachineIdentityJSONRequestBody{
		Name: name, IdentityType: &identityType, Description: &description,
	}, originEditor(ctx))
	if err != nil {
		return 0, fmt.Errorf("create machine identity %q: %w", name, err)
	}
	if resp.JSON201 == nil || resp.JSON201.Data == nil || resp.JSON201.Data.MachineIdentity == nil || resp.JSON201.Data.MachineIdentity.Id == nil {
		return 0, apiErr("create machine identity", resp.StatusCode(), resp.Body)
	}
	return *resp.JSON201.Data.MachineIdentity.Id, nil
}

// IssueMachineCredential implements accessplan.KeyorixWriter. Returns the raw bearer token —
// shown exactly once by the real API, and never logged, printed, or included in any report by
// this tool (the caller writes it straight to a 0600 credentials file).
func (c *Client) IssueMachineCredential(ctx context.Context, projectID, machineID int, name string) (string, error) {
	resp, err := c.api.IssueMachineTokenWithResponse(ctx, projectID, machineID, apiclient.IssueMachineTokenJSONRequestBody{Name: name}, originEditor(ctx))
	if err != nil {
		return "", fmt.Errorf("issue credential for machine identity %d: %w", machineID, err)
	}
	if resp.JSON201 == nil || resp.JSON201.Data == nil || resp.JSON201.Data.Token == nil {
		return "", apiErr("issue machine credential", resp.StatusCode(), resp.Body)
	}
	return *resp.JSON201.Data.Token, nil
}

// GrantMachineRole implements accessplan.KeyorixWriter.
func (c *Client) GrantMachineRole(ctx context.Context, projectID, environmentID, machineID, roleID int) error {
	resp, err := c.api.GrantMachineRoleWithResponse(ctx, projectID, machineID, apiclient.GrantMachineRoleJSONRequestBody{
		RoleId: roleID, EnvironmentId: &environmentID,
	}, originEditor(ctx))
	if err != nil {
		return fmt.Errorf("grant role %d to machine identity %d: %w", roleID, machineID, err)
	}
	if resp.StatusCode() != http.StatusOK {
		return apiErr("grant machine role", resp.StatusCode(), resp.Body)
	}
	return nil
}

// CreateOIDCBinding implements accessplan.KeyorixWriter.
func (c *Client) CreateOIDCBinding(ctx context.Context, projectID, machineID int, issuer, subject string) error {
	resp, err := c.api.CreateOIDCBindingWithResponse(ctx, projectID, machineID, apiclient.CreateOIDCBindingJSONRequestBody{
		Issuer: issuer, Subject: subject,
	}, originEditor(ctx))
	if err != nil {
		return fmt.Errorf("create oidc binding for machine identity %d: %w", machineID, err)
	}
	if resp.JSON201 == nil || resp.JSON201.Data == nil {
		return apiErr("create oidc binding", resp.StatusCode(), resp.Body)
	}
	return nil
}

type apiErrorBody struct {
	Message string `json:"message"`
}

// apiErr mirrors internal/target's own helper: never interpolates a response body verbatim,
// only the structured "message" field, so an unexpected response shape can't echo request/
// response content into an error string this tool's report then surfaces.
func apiErr(action string, statusCode int, body []byte) error {
	var eb apiErrorBody
	if err := json.Unmarshal(body, &eb); err == nil && eb.Message != "" {
		return fmt.Errorf("%s failed: %s (HTTP %d)", action, eb.Message, statusCode)
	}
	return fmt.Errorf("%s failed: HTTP %d", action, statusCode)
}
