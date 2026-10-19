// migrate_user_to_machine.go — operator helper to convert a service-account-shaped
// human user into a project machine identity (ADR-023).
//
// Early deployments often model CI runners, automation, and service accounts as
// ordinary user records. ADR-023 keeps machine identities separate from humans so
// the Members view can segment the two and the machine-token auth path (ADR-030)
// can target them. This helper performs the one-way conversion: it materialises a
// machine identity for the user and (by default) suspends the source account so
// the human-login path is closed. The user is never deleted — suspension is
// reversible and preserves audit/ownership history that may still reference it.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// MigrateUserToMachine converts the user identified by username into an active
// machine identity in projectID. identityType defaults to "service" and name
// defaults to the user's username. When suspendSource is true the source user is
// suspended (login blocked) so it can no longer authenticate as a human. actorID
// is the acting admin, recorded on every audit event. The created machine
// identity is returned.
// actorMachineID is the acting MACHINE identity, or 0 for a human actor —
// #2495, found by guards/actor_kind_literal_completeness_test.go. This path is HTTP-
// reachable (POST /api/v1/projects/{id}/machine-identities/migrate-from-user)
// and the route gate is actor-aware, so a machine identity holding the required
// permissions can perform the migration; passing only actorID recorded
// CreatedByMachineIdentityID as 0 on the resulting identity, leaving a
// machine-created machine identity attributed to nobody. Attribution only — no
// privilege ceiling consults it — which is why this is a lower-severity sibling
// of the bulk-approval defect in the same change, not a second ceiling bypass.
func (c *KeyorixCore) MigrateUserToMachine(ctx context.Context, username string, projectID uint, identityType, name string, actorID, actorMachineID uint, suspendSource bool) (*models.MachineIdentity, error) {
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if projectID == 0 {
		return nil, fmt.Errorf("project ID is required")
	}

	user, err := c.storage.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("user %q not found: %w", username, err)
	}

	if identityType == "" {
		identityType = MachineTypeService
	}
	if name == "" {
		name = user.Username
	}
	// The machine identity's Description is readable by any project member
	// holding users.read (project-scoped) via ListMachineIdentities/
	// ListStaleMachineIdentities — a far lower bar than the users.write
	// (global) + roles.assign (project) required to perform this migration.
	// The source user need not be, and often isn't, a member of projectID, so
	// embedding their email here would leak it to anyone in projectID who has
	// no other way to look that user up. Keep the Description limited to the
	// username (already visible in the resulting identity's Name in the
	// common case) and put the full detail, including the email, in the audit
	// event below, which is gated behind audit.read.
	desc := fmt.Sprintf("Migrated from user %q (id %d)", user.Username, user.ID)

	var m *models.MachineIdentity
	if suspendSource {
		// #2867: the identity's insert and the source user's suspension now
		// commit together, in ONE transaction, with every check that can refuse
		// the operation run BEFORE either write.
		//
		// Previously CreateMachineIdentity committed in its own transaction and
		// SuspendUser then ran in a second one, so any refusal or failure in the
		// suspension left a new machine identity beside a still-ACTIVE human
		// account with live sessions and PATs — and the two reliably-reachable
		// refusals (an actor who does not outrank the target; a target who is
		// the install's last global admin) hit that path on ordinary input, not
		// just under injected faults. The old code reported the partial state in
		// its error and left the operator to finish by hand.
		//
		// #2413's reason for taking lastAdminGuardLockKey here first still
		// holds and is now stronger: nothing is written until the lock is
		// actually held, so a lock-acquisition failure leaves nothing behind.
		// WithNamedLock is reentrant via the lock-marked ctx it hands fn (see
		// its own doc comment), so the guard below can be called inside it.
		var evictHashes []string
		lockErr := c.storage.WithNamedLock(ctx, lastAdminGuardLockKey, func(ctx context.Context) error {
			// ---- every refusal, before any write ----
			// The last-admin guard, under the same lock acquisition as the write
			// it protects (#1646) — two concurrent migrations of two different
			// admins must not each see "another admin survives".
			if err := c.guardLastAdminDeactivation(ctx, user.ID); err != nil {
				return err
			}
			// The admin-rank ceiling setAccountState would apply, hoisted here so
			// an under-ranked actor creates no identity. Same condition and same
			// phrasing as setAccountState's own call, so the refusal a caller
			// sees is unchanged.
			if actorID != user.ID {
				if err := c.requireAdminRankCeilingForTarget(ctx, actorID, user.ID, "change the account state of"); err != nil {
					return err
				}
			}
			// Input validation and row assembly, also before the transaction.
			// actorMachineID is threaded through, not dropped: #2495/#2784 made
			// this path record CreatedByMachineIdentityID for a MACHINE actor
			// (the route gate is actor-aware, so a machine identity with the
			// right permissions can perform the migration). Passing 0 here would
			// silently re-open that attribution gap behind an atomicity fix.
			pending, err := c.newMachineIdentityForCreate(projectID, name, identityType, desc, "", actorID, actorMachineID)
			if err != nil {
				return err
			}

			// ---- one transaction for both writes ----
			// accountStateMu is held across it for the same reason
			// setAccountState holds it: #344's read-modify-write race against
			// UpdateSCIMUser is serialized in-process by this mutex and across
			// replicas by setAccountStateInTx's own LockUserForUpdate.
			c.accountStateMu.Lock()
			defer c.accountStateMu.Unlock()
			var created *models.MachineIdentity
			if txErr := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
				var cerr error
				created, cerr = tx.CreateMachineIdentity(ctx, pending)
				if cerr != nil {
					return fmt.Errorf("failed to create machine identity: %w", cerr)
				}
				hashes, serr := c.setAccountStateInTx(ctx, tx, user.ID, AccountSuspended)
				if serr != nil {
					return fmt.Errorf("failed to update account state: %w", serr)
				}
				evictHashes = hashes
				return nil
			}); txErr != nil {
				// Nothing committed: no identity, and the user is untouched.
				return txErr
			}
			m = created
			return nil
		})
		if lockErr != nil {
			return nil, lockErr
		}
		// ---- after commit ----
		// Cache eviction and both audit events run only now, so a rolled-back
		// transaction never evicts a still-valid cache entry (setAccountState's
		// own ordering) and never claims an identity was created.
		// AccountSuspended blocks login, so the TOMBSTONING primitive is the
		// right one here — see accountStateNeedsEvictionSweep.
		c.invalidateTokenCache(evictHashes...)
		purgeStepUpGrants(ctx, c.storage, user.ID)
		c.logMachineEvent(ctx, "machine_identity.created", m, actorID)
		aid := actorID
		c.writeAuditEventFull(ctx, "account.suspended", &aid, nil, nil, "",
			fmt.Sprintf("user %d account state set to %s", user.ID, AccountSuspended))
	} else {
		var err error
		m, err = c.CreateMachineIdentity(ctx, projectID, name, identityType, desc, "", actorID, actorMachineID)
		if err != nil {
			return nil, err
		}
	}

	// Full detail, including the source user's email, goes in the audit event
	// rather than the machine identity's Description: the audit log is gated
	// behind audit.read, whereas Description is readable by any project
	// member with project-scoped users.read (see the comment above).
	aid, pid := actorID, projectID
	c.writeAuditEventFull(ctx, "machine_identity.migrated_from_user", &aid, nil, &pid, "",
		fmt.Sprintf("user %q (id %d, %s) migrated to machine identity %q (id %d) in project %d", user.Username, user.ID, user.Email, m.Name, m.ID, projectID))

	return m, nil
}
