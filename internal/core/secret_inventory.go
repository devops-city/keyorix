// secret_inventory.go — a project's secret asset inventory: a metadata manifest of
// every live secret (name, environment, type, classification, owner, timestamps) with
// NO secret values. Backs the compliance asset-inventory export (ISO 27001 A.5.9 —
// inventory of information assets). Counts/metadata only, so it is safe to hand to an
// auditor. Project-scoped (route-gated secrets.read), parallel to [[project_hygiene]].
package core

import (
	"context"
	"fmt"
	"maps"
	"sort"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// secretInventoryMaxRows bounds a single inventory pull.
const secretInventoryMaxRows = 10000

// SecretInventoryItem is one secret's metadata row — never its value.
type SecretInventoryItem struct {
	ID              uint       `json:"id"`
	Name            string     `json:"name"`
	EnvironmentID   uint       `json:"environment_id"`
	EnvironmentName string     `json:"environment_name"`
	Type            string     `json:"type"`
	Classification  string     `json:"classification"`
	OwnerID         uint       `json:"owner_id"`
	OwnerUsername   string     `json:"owner_username"`
	CreatedAt       time.Time  `json:"created_at"`
	Expiration      *time.Time `json:"expiration,omitempty"`
	LastRotatedAt   *time.Time `json:"last_rotated_at,omitempty"`
}

// SecretsInventory returns the metadata manifest of every live secret in the project
// (folders excluded), environment/owner names resolved, sorted by environment then
// name. Never reads or returns a secret value. Bounded to secretInventoryMaxRows.
func (c *KeyorixCore) SecretsInventory(ctx context.Context, projectID uint) ([]SecretInventoryItem, error) { // NOSONAR -- cognitive complexity 18, suppress go:S3776
	if projectID == 0 {
		return nil, fmt.Errorf("project ID is required")
	}

	secrets, _, err := c.storage.ListSecrets(ctx, &storage.SecretFilter{
		ProjectID: &projectID, Page: 1, PageSize: secretInventoryMaxRows,
	})
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}

	// Resolve environment names once (id → name) for this project.
	envName := map[uint]string{}
	if envs, err := c.storage.ListEnvironmentsByProject(ctx, projectID); err == nil {
		for _, e := range envs {
			envName[e.ID] = e.Name
		}
	}

	// Resolve owner usernames once per distinct owner.
	ownerName := map[uint]string{}
	for _, s := range secrets {
		if s.IsSecret && s.OwnerID != 0 {
			ownerName[s.OwnerID] = ""
		}
	}
	if len(ownerName) > 0 {
		ids := make([]uint, 0, len(ownerName))
		for id := range ownerName {
			ids = append(ids, id)
		}
		// One batched lookup (LIST-ENDPOINTS-1); an owner that cannot be read keeps "".
		if names, err := c.storage.GetUsernamesByIDs(ctx, ids); err == nil {
			maps.Copy(ownerName, names)
		}
	}

	out := make([]SecretInventoryItem, 0, len(secrets))
	for _, s := range secrets {
		if !s.IsSecret {
			continue // skip folder nodes — an inventory lists assets, not containers
		}
		out = append(out, SecretInventoryItem{
			ID:              s.ID,
			Name:            s.Name,
			EnvironmentID:   s.EnvironmentID,
			EnvironmentName: envName[s.EnvironmentID],
			Type:            s.Type,
			Classification:  s.Classification,
			OwnerID:         s.OwnerID,
			OwnerUsername:   ownerName[s.OwnerID],
			CreatedAt:       s.CreatedAt,
			Expiration:      s.Expiration,
			LastRotatedAt:   s.LastRotatedAt,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].EnvironmentName != out[j].EnvironmentName {
			return out[i].EnvironmentName < out[j].EnvironmentName
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}
