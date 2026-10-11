// secret_schedule.go — temporal access policy enforcement for secrets.
//
// A SecretAccessSchedule row pins a secret's read window to specific days of
// the week and hours of the day (expressed in a configurable IANA timezone).
// When a schedule exists, reads outside the window are rejected with
// ErrAccessOutsideSchedule (HTTP 403 at the handler layer).
//
// Intentional fail-open rule: an unrecognised timezone name is treated as "no
// restriction" rather than blanket denial, so a misconfigured timezone does not
// permanently lock out every operator. The mismatch is logged by the caller.
package core

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ErrAccessOutsideSchedule is returned when a permission-checked secret read
// occurs outside the secret's configured temporal access window.
var ErrAccessOutsideSchedule = errors.New("secret access is not permitted outside the configured time window")

// checkSecretAccessSchedule returns ErrAccessOutsideSchedule when the secret
// has a schedule and the current time falls outside the allowed window.
// Returns nil if no schedule is configured or the current time is within it.
func (c *KeyorixCore) checkSecretAccessSchedule(ctx context.Context, secretNodeID uint) error {
	sched, err := c.storage.GetSecretAccessSchedule(ctx, secretNodeID)
	if err != nil || sched == nil {
		return err // nil schedule = no restriction
	}
	return enforceSchedule(sched, time.Now())
}

// enforceSchedule is the pure time-check logic (separated for unit testing).
func enforceSchedule(sched *models.SecretAccessSchedule, now time.Time) error {
	loc, err := time.LoadLocation(sched.Timezone)
	if err != nil {
		// Misconfigured timezone — fail open rather than locking out all access.
		return nil
	}
	local := now.In(loc)

	// Check day of week.
	if sched.AllowedDays != "*" {
		weekday := int(local.Weekday()) // 0=Sun, 1=Mon, …, 6=Sat
		// Convert to ISO 8601: Mon=1 … Sun=7
		isoDay := weekday
		if isoDay == 0 {
			isoDay = 7
		}
		allowed := false
		for _, part := range strings.Split(sched.AllowedDays, ",") {
			d, _ := strconv.Atoi(strings.TrimSpace(part))
			if d == isoDay {
				allowed = true
				break
			}
		}
		if !allowed {
			return ErrAccessOutsideSchedule
		}
	}

	// Check hour window [StartHour, EndHour).
	hour := local.Hour()
	if hour < sched.StartHour || hour >= sched.EndHour {
		return ErrAccessOutsideSchedule
	}
	return nil
}

// GetSecretSchedule returns the access schedule for secretID, or nil if none exists.
func (c *KeyorixCore) GetSecretSchedule(ctx context.Context, secretID uint) (*models.SecretAccessSchedule, error) {
	return c.storage.GetSecretAccessSchedule(ctx, secretID)
}

// SetSecretSchedule validates and upserts a temporal access schedule for secretID.
func (c *KeyorixCore) SetSecretSchedule(ctx context.Context, secretID uint, days string, startHour, endHour int, timezone string) (*models.SecretAccessSchedule, error) {
	if err := validateScheduleParams(days, startHour, endHour, timezone); err != nil {
		return nil, err
	}
	sched := &models.SecretAccessSchedule{
		SecretNodeID: secretID,
		AllowedDays:  days,
		StartHour:    startHour,
		EndHour:      endHour,
		Timezone:     timezone,
	}
	if err := c.storage.SetSecretAccessSchedule(ctx, sched); err != nil {
		return nil, err
	}
	return sched, nil
}

// DeleteSecretSchedule removes the temporal access schedule for secretID (idempotent).
func (c *KeyorixCore) DeleteSecretSchedule(ctx context.Context, secretID uint) error {
	return c.storage.DeleteSecretAccessSchedule(ctx, secretID)
}

// LogSecretScheduleSet/LogSecretScheduleDeleted record a temporal access
// schedule create/update/delete (F5, audit-completeness campaign) --
// standalone methods since SetSecretSchedule/DeleteSecretSchedule take no
// actor parameter, same reasoning as LogRoleCreated/LogRoleUpdated/
// LogRoleDeleted (audit.go). A schedule restricts WHEN a secret can be read,
// so changing it is a real access-control change worth a trail.
func (c *KeyorixCore) LogSecretScheduleSet(ctx context.Context, actorID, secretID uint) {
	sid := secretID
	c.writeAuditEventFull(ctx, "secret.schedule_set", actorPtr(actorID), &sid, nil, "",
		fmt.Sprintf("access schedule set for %s", c.auditRef(ctx, c.storage, auditKindSecret, secretID)))
}

func (c *KeyorixCore) LogSecretScheduleDeleted(ctx context.Context, actorID, secretID uint) {
	sid := secretID
	c.writeAuditEventFull(ctx, "secret.schedule_deleted", actorPtr(actorID), &sid, nil, "",
		fmt.Sprintf("access schedule deleted for %s", c.auditRef(ctx, c.storage, auditKindSecret, secretID)))
}

// validateScheduleParams checks the schedule parameters before persistence.
func validateScheduleParams(days string, startHour, endHour int, timezone string) error {
	if startHour < 0 || startHour > 23 {
		return fmt.Errorf("start_hour must be in [0, 23], got %d", startHour)
	}
	if endHour < 1 || endHour > 24 {
		return fmt.Errorf("end_hour must be in [1, 24], got %d", endHour)
	}
	if endHour <= startHour {
		return fmt.Errorf("end_hour (%d) must be greater than start_hour (%d)", endHour, startHour)
	}
	if _, err := time.LoadLocation(timezone); err != nil {
		return fmt.Errorf("invalid timezone %q: %w", timezone, err)
	}
	if days != "*" {
		// #G44: bound the string before splitting — 7 distinct days ("1,2,3,4,5,6,7")
		// need at most 13 characters; an unbounded caller-supplied string otherwise
		// drives an unbounded number of strconv.Atoi calls below.
		const maxAllowedDaysLen = 64
		if len(days) > maxAllowedDaysLen {
			return fmt.Errorf("days exceeds the maximum length of %d characters", maxAllowedDaysLen)
		}
		for _, part := range strings.Split(days, ",") {
			d, err := strconv.Atoi(strings.TrimSpace(part))
			if err != nil || d < 1 || d > 7 {
				return fmt.Errorf("invalid day %q in days %q: must be integers 1–7 or \"*\"", strings.TrimSpace(part), days)
			}
		}
	}
	return nil
}
