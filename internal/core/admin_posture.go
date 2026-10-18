package core

import (
	"context"
	"fmt"
	"slices"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ListGlobalAdminHolders returns every active, non-deleted global admin-tier
// holder (the install's admin-bypass roles, direct or via group membership —
// see resolveGlobalAdminHolders), in ascending ID order for deterministic
// report output. Backs the ADR-112 posture report's admin checks.
func (c *KeyorixCore) ListGlobalAdminHolders(ctx context.Context) ([]*models.User, error) {
	adminIDs, err := c.adminBypassRoleIDSet(ctx)
	if err != nil {
		return nil, err // fail closed: "can't tell who is an admin" is not "no admins"
	}
	if len(adminIDs) == 0 {
		return nil, nil
	}
	assignments, err := c.storage.ListProjectRoleAssignments(ctx, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve global role assignments: %w", err)
	}
	holders, err := c.resolveGlobalAdminHolders(ctx, adminIDs, assignments, nil, nil)
	if err != nil {
		return nil, err
	}

	ids := make([]uint, 0, len(holders))
	for id := range holders {
		ids = append(ids, id)
	}
	slices.Sort(ids)

	users := make([]*models.User, 0, len(ids))
	for _, id := range ids {
		user, err := c.storage.GetUser(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve admin holder %d: %w", id, err)
		}
		users = append(users, user)
	}
	return users, nil
}

// ListAdminsWithoutMFA returns every global admin-tier holder (see
// ListGlobalAdminHolders) who has neither TOTP MFA nor WebAuthn enrolled.
// Backs the ADR-112 posture report's "admins without MFA" deviation (#2400
// follow-up): admin-tier authority with no second factor is a standing
// deviation regardless of whether security.require_mfa's enforcement is itself
// in its grace period (ADR-112 item 1) — that flag governs the require_mfa
// *setting*, not the posture report's visibility into who has actually
// complied with it yet.
//
// Returned in ascending ID order for deterministic report output.
func (c *KeyorixCore) ListAdminsWithoutMFA(ctx context.Context) ([]*models.User, error) {
	admins, err := c.ListGlobalAdminHolders(ctx)
	if err != nil {
		return nil, err
	}
	var withoutMFA []*models.User
	for _, user := range admins {
		if user.MFAEnabled || user.WebAuthnEnabled {
			continue
		}
		withoutMFA = append(withoutMFA, user)
	}
	return withoutMFA, nil
}
