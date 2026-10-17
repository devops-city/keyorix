// catalog_wire.go — snake_case wire types for internal/storage/models.Project and
// Environment (both carry zero json tags — every human-facing catalog route
// returning either raw was mixed-casing against openapi.yaml, which already
// documented snake_case). See docs/findings/2026-09-25-FINDING-api-raw-model-exposure.md.
//
// Originally kept in sync with project_catalog_proxy.go's projectProxyWire and
// environment_catalog_proxy.go's environmentProxyWire, the RemoteStorage-sync
// /system proxy tier's own wire types for these two models — both files are now
// deleted along with the rest of that tier (ADR-108), so this is the sole wire
// type for either model today.
package handlers

import (
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

type projectWire struct {
	ID          uint       `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	RequireMFA  bool       `json:"require_mfa"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty"`
}

func newProjectWire(p *models.Project) projectWire {
	w := projectWire{
		ID:          p.ID,
		Name:        p.Name,
		Description: p.Description,
		RequireMFA:  p.RequireMFA,
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,
	}
	if p.DeletedAt.Valid {
		t := p.DeletedAt.Time
		w.DeletedAt = &t
	}
	return w
}

type environmentWire struct {
	ID        uint   `json:"id"`
	ProjectID uint   `json:"project_id"`
	Name      string `json:"name"`
	// SecretCount is the number of live secrets (folders excluded) in the
	// environment, computed by the server in one grouped query on the list routes.
	SecretCount int64      `json:"secret_count"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty"`
}

func newEnvironmentWire(e *models.Environment) environmentWire {
	w := environmentWire{
		ID:        e.ID,
		ProjectID: e.ProjectID,
		Name:      e.Name,
		CreatedAt: e.CreatedAt,
		UpdatedAt: e.UpdatedAt,
	}
	if e.DeletedAt.Valid {
		t := e.DeletedAt.Time
		w.DeletedAt = &t
	}
	return w
}

// newEnvironmentWireList maps environments to their wire form, filling
// secret_count from counts (an environment absent from the map has zero).
func newEnvironmentWireList(envs []*models.Environment, counts map[uint]int64) []environmentWire {
	out := make([]environmentWire, 0, len(envs))
	for _, e := range envs {
		w := newEnvironmentWire(e)
		w.SecretCount = counts[e.ID]
		out = append(out, w)
	}
	return out
}

type envCloneResultWire struct {
	SourceEnv      string   `json:"source_env"`
	DestEnv        string   `json:"dest_env"`
	SecretsCloned  int      `json:"secrets_cloned"`
	SecretsSkipped int      `json:"secrets_skipped"`
	Errors         []string `json:"errors,omitempty"`
}

func newEnvCloneResultWire(r *core.EnvCloneResult) envCloneResultWire {
	return envCloneResultWire{
		SourceEnv:      r.SourceEnv,
		DestEnv:        r.DestEnv,
		SecretsCloned:  r.SecretsCloned,
		SecretsSkipped: r.SecretsSkipped,
		Errors:         r.Errors,
	}
}
