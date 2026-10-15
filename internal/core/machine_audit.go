// machine_audit.go — deployment-wide machine identity audit report.
//
// GetMachineAuditReport produces a structured summary of every machine identity
// across all projects: credential count, last-used timestamp (most recent across
// all credentials), stale status (no activity > 30 days), and revocation status.
package core

import (
	"context"
	"maps"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// MachineAuditRow is one row in the machine identity audit report.
type MachineAuditRow struct {
	MachineID       uint       `json:"machine_id"`
	Name            string     `json:"name"`
	Description     string     `json:"description,omitempty"`
	CredentialCount int        `json:"credential_count"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
	IsStale         bool       `json:"is_stale"` // no activity > 30 days
	IsRevoked       bool       `json:"is_revoked"`
	CreatedAt       time.Time  `json:"created_at"`
}

// MachineAuditReport is the top-level machine identity audit report payload.
type MachineAuditReport struct {
	GeneratedAt  time.Time         `json:"generated_at"`
	TotalCount   int               `json:"total_count"`
	StaleCount   int               `json:"stale_count"`
	RevokedCount int               `json:"revoked_count"`
	Machines     []MachineAuditRow `json:"machines"`
}

const machineAuditStaleDays = 30

// machineCredMostRecent derives the most recent LastUsedAt across creds.
// Returns nil when no credential has a non-nil LastUsedAt.
func machineCredMostRecent(creds []*models.MachineIdentityCredential) *time.Time {
	var lastUsedAt *time.Time
	for _, cred := range creds {
		if cred.LastUsedAt == nil {
			continue
		}
		if lastUsedAt == nil || cred.LastUsedAt.After(*lastUsedAt) {
			t := *cred.LastUsedAt
			lastUsedAt = &t
		}
	}
	return lastUsedAt
}

// GetMachineAuditReport returns an audit report of all machine identities across
// the deployment. For each identity it counts credentials (all, not only active),
// derives LastUsedAt from the most recent credential's LastUsedAt, and marks an
// identity stale when LastUsedAt is nil OR more than 30 days ago.
func (c *KeyorixCore) GetMachineAuditReport(ctx context.Context) (*MachineAuditReport, error) {
	now := c.now()
	staleThreshold := now.Add(-machineAuditStaleDays * 24 * time.Hour)

	identities, err := c.storage.ListAllMachineIdentities(ctx)
	if err != nil {
		return nil, err
	}

	rows := make([]MachineAuditRow, 0, len(identities))
	staleCount := 0
	revokedCount := 0

	// Every identity's credential usage in batches (LIST-ENDPOINTS-1), not one
	// ListMachineIdentityCredentials per identity; a failed batch fails the report as
	// a failed per-identity lookup did.
	credsByMachine := make(map[uint][]*models.MachineIdentityCredential, len(identities))
	for start := 0; start < len(identities); start += listBatchSize {
		end := min(start+listBatchSize, len(identities))
		ids := make([]uint, 0, end-start)
		for _, m := range identities[start:end] {
			ids = append(ids, m.ID)
		}
		batch, err := c.storage.ListMachineCredentialUsageByMachineIDs(ctx, ids)
		if err != nil {
			return nil, err
		}
		maps.Copy(credsByMachine, batch)
	}

	for _, m := range identities {
		creds := credsByMachine[m.ID]

		lastUsedAt := machineCredMostRecent(creds)

		// An identity is stale when it has never been used OR its last use predates the threshold.
		isStale := lastUsedAt == nil || lastUsedAt.Before(staleThreshold)
		isRevoked := m.State == MachineRevoked

		if isStale {
			staleCount++
		}
		if isRevoked {
			revokedCount++
		}

		rows = append(rows, MachineAuditRow{
			MachineID:       m.ID,
			Name:            m.Name,
			Description:     m.Description,
			CredentialCount: len(creds),
			LastUsedAt:      lastUsedAt,
			IsStale:         isStale,
			IsRevoked:       isRevoked,
			CreatedAt:       m.CreatedAt,
		})
	}

	return &MachineAuditReport{
		GeneratedAt:  now,
		TotalCount:   len(rows),
		StaleCount:   staleCount,
		RevokedCount: revokedCount,
		Machines:     rows,
	}, nil
}
