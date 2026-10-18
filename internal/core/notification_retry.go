// notification_retry.go — retry policy configuration for notification channels.
// Allows operators to control how many times delivery is retried and the base
// backoff interval for each channel independently.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

const (
	// EventNotificationRetryPolicyUpdated is the audit event type emitted when
	// the retry policy of a notification channel is changed.
	EventNotificationRetryPolicyUpdated = "notification_channel.retry_policy_updated"

	maxRetriesMax     = 10
	retryBackoffMsMin = 100
	retryBackoffMsMax = 60000
)

// NotificationRetryConfig is the retry policy for a notification channel.
type NotificationRetryConfig struct {
	MaxRetries     int `json:"max_retries"`      // 0–10
	RetryBackoffMs int `json:"retry_backoff_ms"` // 100–60000 ms
}

// SetNotificationRetryPolicy updates the retry config for a notification channel.
// Validates: MaxRetries in [0,10], RetryBackoffMs in [100,60000].
// Returns a descriptive error if validation fails.
func (c *KeyorixCore) SetNotificationRetryPolicy(ctx context.Context, actorID, channelID uint, cfg NotificationRetryConfig) error {
	if cfg.MaxRetries < 0 || cfg.MaxRetries > maxRetriesMax {
		return fmt.Errorf("invalid notification channel retry policy: max_retries must be between 0 and %d, got %d", maxRetriesMax, cfg.MaxRetries)
	}
	if cfg.RetryBackoffMs < retryBackoffMsMin || cfg.RetryBackoffMs > retryBackoffMsMax {
		return fmt.Errorf("invalid notification channel retry policy: retry_backoff_ms must be between %d and %d, got %d", retryBackoffMsMin, retryBackoffMsMax, cfg.RetryBackoffMs)
	}
	// AUDIT-TX-3: the change and its audit row commit together (fail closed): alert
	// delivery retries are never turned down unrecorded.
	return c.withAuditedMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
		if err := tx.UpdateNotificationRetryPolicy(ctx, channelID, cfg.MaxRetries, cfg.RetryBackoffMs); err != nil {
			return err
		}
		c.writeAuditEventFullOn(ctx, tgt, EventNotificationRetryPolicyUpdated, actorPtr(actorID), nil, nil, "",
			fmt.Sprintf("notification channel %d retry policy updated: max_retries=%d retry_backoff_ms=%d by actor %d",
				channelID, cfg.MaxRetries, cfg.RetryBackoffMs, actorID))
		return nil
	})
}

// GetNotificationRetryPolicy returns the current retry config for a channel.
func (c *KeyorixCore) GetNotificationRetryPolicy(ctx context.Context, channelID uint) (*NotificationRetryConfig, error) {
	ch, err := c.storage.GetNotificationChannel(ctx, channelID)
	if err != nil {
		return nil, err
	}
	return &NotificationRetryConfig{
		MaxRetries:     ch.MaxRetries,
		RetryBackoffMs: ch.RetryBackoffMs,
	}, nil
}
