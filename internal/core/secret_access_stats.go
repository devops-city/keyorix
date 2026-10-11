// secret_access_stats.go — per-secret access statistics: a single, focused read of how
// much a secret is actually used (lifetime read count + a recent-window summary). It
// answers "is this secret used, and by whom lately?" directly, instead of cross-
// referencing the deployment-wide usage analytics, the per-user access log, and the
// composite risk score. Read-only; never returns the secret value.
package core

import (
	"context"
	"fmt"
	"time"
)

// SecretAccessStats summarises a secret's read activity. TotalReads is the lifetime
// value-read count (SecretTotalReads, the same figure as total_reads on GET
// /secrets/{id}); the *Window fields cover the last WindowDays of the (retained) access log.
type SecretAccessStats struct {
	SecretID      uint       `json:"secret_id"`
	TotalReads    int        `json:"total_reads"`
	Versions      int        `json:"versions"`
	WindowDays    int        `json:"window_days"`
	ReadsInWindow int        `json:"reads_in_window"`
	UniqueReaders int        `json:"unique_readers"`
	LastReadAt    *time.Time `json:"last_read_at,omitempty"`
}

// GetSecretAccessStats returns read statistics for a secret, enforcing secrets.read on
// the secret first. windowDays bounds the recent-activity summary (clamped to [1, 365],
// default 30 when <= 0). Lifetime TotalReads and the window fields are both computed
// from the access log's "read" entries. No value is read.
func (c *KeyorixCore) GetSecretAccessStats(ctx context.Context, secretID, actorID uint, windowDays int) (*SecretAccessStats, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("secret ID is required")
	}
	if _, err := c.EnforceSecretReadPermission(ctx, secretID, actorID); err != nil {
		return nil, err
	}

	switch {
	case windowDays <= 0:
		windowDays = 30
	case windowDays > 365:
		windowDays = 365
	}

	stats := &SecretAccessStats{SecretID: secretID, WindowDays: windowDays}

	versions, err := c.storage.GetSecretVersions(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("get versions: %w", err)
	}
	stats.Versions = len(versions)

	// Lifetime reads — the same count GET /secrets/{id} and the versions listing
	// report as total_reads (SecretTotalReads: access-log rows with action "read").
	// NOT the per-version ReadCount sum, which only counts reads charged against
	// max_reads and is 0 for an ordinary secret (AUDIT-UX-3, #2971).
	total, err := c.SecretTotalReads(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("total reads: %w", err)
	}
	stats.TotalReads = int(total)

	// Recent window — from the access log's "read" entries.
	since := c.now().AddDate(0, 0, -windowDays)
	logs, err := c.storage.ListSecretAccessLogs(ctx, secretID, since)
	if err != nil {
		return nil, fmt.Errorf("list access logs: %w", err)
	}
	readers := map[string]struct{}{}
	for i := range logs {
		l := logs[i]
		if l.Action != "read" {
			continue
		}
		stats.ReadsInWindow++
		readers[l.AccessedBy] = struct{}{}
		if stats.LastReadAt == nil || l.AccessTime.After(*stats.LastReadAt) {
			t := l.AccessTime
			stats.LastReadAt = &t
		}
	}
	stats.UniqueReaders = len(readers)
	return stats, nil
}
