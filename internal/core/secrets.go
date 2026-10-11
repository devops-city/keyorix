// secrets.go — CreateSecretRequest, UpdateSecretRequest types, and core CRUD operations.
//
// For version storage and retrieval see secrets_versions.go.
// For request validation see secrets_validation.go.
package core

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// isEnvironmentNotFoundErr reports whether err is LocalStorage.GetEnvironment's
// own genuine "no such row" sentinel text ("environment not found",
// internal/storage/store/local_secrets.go), as distinct from a real storage
// failure (DB down, timeout, ...) that GetEnvironment also returns as an
// error. SESSION-AT AT1/AT3 (coordinator review, PR #2353): CreateSecret
// previously collapsed BOTH cases into "environment %d not found"
// unconditionally, so a transient storage failure during secret creation
// surfaced to the caller as a clean 422 validation error instead of the 500
// it actually is. No sentinel error type exists to check via errors.Is --
// GetEnvironment returns a plain fmt.Errorf either way -- so this compares
// the exact literal text GetEnvironment uses for the not-found case.
func isEnvironmentNotFoundErr(err error) bool {
	return err != nil && err.Error() == "environment not found"
}

// withEnvironmentSecretGuard acquires storage.EnvironmentSecretGuardLockKey
// for environmentID, re-verifies the environment still exists INSIDE that
// lock, and only then runs fn -- the shared shape CreateSecret and
// CreateFolder both need against a concurrent DeleteEnvironment (SESSION-AT
// AT1/AT3, coordinator review PR #2353: these were originally two
// independently-written copies of this exact logic, which is exactly the
// kind of drift risk the coordinator's review flagged for the lock-key
// itself). On a genuine "environment is gone" outcome, returns the same
// bare, unwrapped "environment %d not found" error the pre-lock
// GetEnvironment check uses, so the HTTP handler's not-found -> 422 mapping
// still matches; any other failure (a real storage error, or fn's own
// error) is wrapped with ErrorStorageFailed.
func (c *KeyorixCore) withEnvironmentSecretGuard(ctx context.Context, environmentID uint, fn func(ctx context.Context) error) error {
	var envGone bool
	lockErr := c.storage.WithNamedLock(ctx, storage.EnvironmentSecretGuardLockKey(environmentID), func(ctx context.Context) error {
		if _, err := c.storage.GetEnvironment(ctx, environmentID); err != nil {
			if !isEnvironmentNotFoundErr(err) {
				return fmt.Errorf("failed to verify target environment %d: %w", environmentID, err)
			}
			envGone = true
			return fmt.Errorf("environment %d not found", environmentID)
		}
		return fn(ctx)
	})
	if lockErr != nil {
		if envGone {
			return lockErr
		}
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), lockErr)
	}
	return nil
}

// CreateSecretRequest represents a request to create a new secret.
type CreateSecretRequest struct {
	Name          string            `json:"name" validate:"required,min=1,max=255"`
	Value         []byte            `json:"value" validate:"required"`
	ProjectID     uint              `json:"project_id" validate:"required"`
	EnvironmentID uint              `json:"environment_id" validate:"required"`
	Type          string            `json:"type" validate:"required"`
	MaxReads      *int              `json:"max_reads,omitempty" validate:"omitempty,min=1"`
	Expiration    *time.Time        `json:"expiration,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	Tags          []string          `json:"tags,omitempty"`
	CreatedBy     string            `json:"created_by" validate:"required"`
	OwnerID       uint              `json:"owner_id,omitempty"`
	// OwnerMachineIdentityID (#1573) records which machine identity created this
	// secret, when OwnerID is 0 because the creator was a machine caller
	// (ADR-030) rather than a human. 0 = none.
	OwnerMachineIdentityID uint `json:"-"`
	// ParentID optionally places the new secret inside a folder node. When set,
	// the parent must exist, belong to the same project/environment, and be a
	// folder (IsSecret=false). A zero value means no parent (root level).
	ParentID *uint `json:"parent_id,omitempty"`
	// Classification is an optional data-sensitivity label (A.5.12): "" or one of
	// public|internal|confidential|restricted.
	Classification string `json:"classification,omitempty"`
	// Description is an optional free-text note (≤maxSecretDescriptionLen chars).
	Description string `json:"description,omitempty"`
}

// UpdateSecretRequest represents a request to update an existing secret.
type UpdateSecretRequest struct {
	ID    uint   `json:"id" validate:"required"`
	Value []byte `json:"value,omitempty"`
	// Type, when non-empty, replaces the secret's type (e.g. "password", "api_key",
	// "certificate", "generic"). An empty string means "leave unchanged".
	Type       string     `json:"type,omitempty"`
	MaxReads   *int       `json:"max_reads,omitempty" validate:"omitempty,min=1"`
	Expiration *time.Time `json:"expiration,omitempty"`
	// ClearExpiration removes an existing expiration. It is distinct from leaving
	// Expiration nil (which means "leave unchanged"): without this flag there is no
	// way to make an expiring secret non-expiring.
	ClearExpiration bool              `json:"clear_expiration,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
	Tags            []string          `json:"tags,omitempty"`
	// Description, when non-nil, replaces the secret's description ("" clears it). A nil
	// pointer means "leave unchanged" — matching Metadata's nil-means-unchanged
	// convention, since "" is itself a meaningful value here (SetSecretDescription has
	// the same gate as the rest of this request; no separate authorization applies).
	Description *string `json:"description,omitempty"`
	UpdatedBy   string  `json:"updated_by" validate:"required"`
	UserID      uint    `json:"user_id,omitempty"`
}

// CreateSecret creates a new secret with business logic validation.
func (c *KeyorixCore) CreateSecret(ctx context.Context, req *CreateSecretRequest) (*models.SecretNode, error) { // NOSONAR -- cognitive complexity 27, suppress go:S3776
	if err := c.validateCreateSecretRequest(req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	if err := c.secretValuePolicy.Validate(req.Value); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	if err := c.checkSecretSize(req.Value); err != nil {
		return nil, err
	}
	if err := c.validateSecretName(req.Name); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	// #1642: NFC-normalize once here, use everywhere below (the duplicate-name
	// pre-check and the stored row) — secret names are addresses, not
	// human-verified identity, so unlike username/role/group this does NOT
	// fold case (PROD_KEY and prod_key must remain distinct); it only closes
	// the NFC-vs-NFD collision gap.
	normalizedName, nerr := identity.NewAddressName(req.Name)
	if nerr != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), nerr)
	}
	if len(strings.TrimSpace(req.Description)) > maxSecretDescriptionLen {
		return nil, fmt.Errorf("%s: description exceeds %d characters", i18n.T("ErrorValidation", nil), maxSecretDescriptionLen)
	}

	// Verify the environment belongs to the stated project.
	env, err := c.storage.GetEnvironment(ctx, req.EnvironmentID)
	if err != nil {
		if !isEnvironmentNotFoundErr(err) {
			// A REAL storage failure (DB down, timeout, ...), not "no such row" --
			// SESSION-AT AT1/AT3 (coordinator review, PR #2353): this used to be
			// collapsed into "environment %d not found" unconditionally, so a
			// transient storage failure during CreateSecret surfaced to the caller
			// as a clean validation error instead of the 500 it actually is.
			return nil, fmt.Errorf("failed to verify target environment %d: %w", req.EnvironmentID, err)
		}
		return nil, fmt.Errorf("environment %d not found", req.EnvironmentID)
	}
	if env.ProjectID != req.ProjectID {
		return nil, fmt.Errorf("environment %d does not belong to project %d", req.EnvironmentID, req.ProjectID)
	}

	existing, err := c.storage.GetSecretByName(ctx, normalizedName.String(), req.ProjectID, req.EnvironmentID)
	switch {
	case err == nil && existing != nil:
		return nil, fmt.Errorf("%s", i18n.T("ErrorSecretAlreadyExists", nil))
	case err != nil && !storage.IsSecretNotFound(err):
		// A real read failure, not "no duplicate" - don't silently assume the
		// name is free (docs/findings/2026-09-23-FINDING-update-secret-read-error-swallowed.md).
		return nil, err
	}

	// Validate parent folder when one is requested.
	if req.ParentID != nil && *req.ParentID != 0 {
		parent, perr := c.storage.GetSecret(ctx, *req.ParentID)
		if perr != nil {
			return nil, fmt.Errorf("%s: parent folder %d not found", i18n.T("ErrorValidation", nil), *req.ParentID)
		}
		if parent.IsSecret {
			return nil, fmt.Errorf("%s: parent %d is a secret, not a folder", i18n.T("ErrorValidation", nil), *req.ParentID)
		}
		if parent.ProjectID != req.ProjectID || parent.EnvironmentID != req.EnvironmentID {
			return nil, fmt.Errorf("%s: parent folder %d does not belong to the same project/environment", i18n.T("ErrorValidation", nil), *req.ParentID)
		}
	}

	if !IsValidClassification(req.Classification) {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "invalid classification")
	}

	// #390: normalize req.Tags UP FRONT, before creating anything, so a caller intending
	// an immediate "reviewed"/"exempt"-style tag at creation time gets a clear validation
	// error instead of a silently-dropped tag list — CreateSecret previously never read
	// req.Tags at all despite both the HTTP and gRPC handlers passing it through.
	var normalizedTags []string
	if len(req.Tags) > 0 {
		normalizedTags, err = normalizeTags(req.Tags)
		if err != nil {
			return nil, err
		}
	}

	secret := &models.SecretNode{
		Name:                   normalizedName.String(),
		ProjectID:              req.ProjectID,
		EnvironmentID:          req.EnvironmentID,
		Type:                   req.Type,
		Description:            strings.TrimSpace(req.Description),
		MaxReads:               req.MaxReads,
		Expiration:             req.Expiration,
		Classification:         req.Classification,
		IsSecret:               true,
		Status:                 "active",
		CreatedBy:              req.CreatedBy,
		OwnerID:                req.OwnerID,
		OwnerMachineIdentityID: req.OwnerMachineIdentityID,
		CreatedAt:              time.Now(),
		UpdatedAt:              time.Now(),
	}
	if req.ParentID != nil && *req.ParentID != 0 {
		secret.ParentID = req.ParentID
	}
	// MIG-1: req.Metadata was validated and decoded all the way from the HTTP/gRPC
	// request body down to this point, but never written onto the model being
	// created — applyUpdateSecretFields (used only by UpdateSecret) has always done
	// this correctly; CreateSecret never had an equivalent. Every metadata key a
	// caller set at creation time (including keyorix-migrate's own idempotency
	// marker, migrate.source-id) was silently discarded, which in turn breaks
	// keyorix-migrate's documented "re-running is safe" guarantee outright: a
	// re-run's conflict check reads this same metadata back and, finding it empty,
	// classifies every already-migrated secret as a conflict with something it
	// didn't create, instead of a skip (docs/design-keyorix-migrate.md's
	// "Idempotency" section; found via docs/specs/vault-migration-fidelity.md's
	// harness, MIG-1).
	if len(req.Metadata) > 0 {
		metadataJSON, err := json.Marshal(req.Metadata)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorInvalidMetadata", nil), err)
		}
		secret.Metadata = metadataJSON
	}

	// req.Value is forwarded as the optional plaintext argument (#499): LocalStorage
	// ignores it (a no-op — the value still flows through the storeSecretVersion call
	// below, unchanged). RemoteStorage (since deleted, #2162) used to forward it over
	// the wire so the upstream handler's required "value" field was satisfied and
	// version 1 was created atomically server-side. Never logged.
	// fix/create-ops-atomicity: the secret row and its version 1 row now share ONE
	// storage.WithTransaction — a fault (or any real failure) partway through rolls
	// both back together, so the caller never sees a mix (secret committed, no
	// version) that neither the pre-create state nor a successful create would
	// produce. This REPLACES the old compensating DeleteSecret cleanup below: a
	// rollback achieves the same "as if nothing happened" outcome without a
	// second best-effort delete that could itself fail and leave the orphan behind.
	// SESSION-AT AT1/AT3: re-verify the environment still exists, and serialize
	// against a concurrent DeleteEnvironment (and CreateFolder/RestoreSecret,
	// which race it the identical way) via storage.EnvironmentSecretGuardLockKey,
	// the same named lock DeleteEnvironment holds for its own active-secret
	// guard (see its doc comment, internal/storage/store/local_secrets.go).
	// The GetEnvironment check earlier in this function happens BEFORE this
	// lock and is not enough on its own: DeleteEnvironment could commit in the
	// window between that check and the create below, silently orphaning this
	// secret (environment_id pointing at a row that no longer exists) --
	// confirmed empirically with a real concurrency test before this lock was
	// added. The lock alone is also not enough on its own: it only prevents
	// the two operations from interleaving, not from running in the legitimate
	// order "delete wins the lock first, finds zero secrets, commits; create
	// then acquires the lock and blindly inserts anyway" -- hence the second
	// existence check INSIDE the lock, immediately before the transaction.
	var createdSecret *models.SecretNode
	if err := c.withEnvironmentSecretGuard(ctx, req.EnvironmentID, func(ctx context.Context) error {
		return c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
			var err error
			createdSecret, err = tx.CreateSecret(ctx, secret, string(req.Value))
			if err != nil {
				return err
			}
			// Skip the separate version-creation call when the backend already stored the
			// value atomically as part of CreateSecret itself (#499): calling storeSecretVersion
			// again here would try to mint a conflicting duplicate version 1 against a secret
			// that already has one. LocalStorage never sets ValueStored, so this call remains
			// exactly as before for it.
			if !createdSecret.ValueStored {
				if err := c.storeSecretVersion(ctx, tx, createdSecret, req.Value, 1); err != nil {
					return err
				}
			}
			// #2702/#2711: and now the PROJECT, after both writes, in this same
			// transaction. Everything above serializes against a concurrent
			// DeleteEnvironment (the named lock plus the in-lock existence check)
			// and nothing serialized against a concurrent DeleteProject, whose
			// cascade takes no such named lock — it row-locks the project and
			// sweeps the project's secrets directly. So the legitimate order
			// "delete wins, sweeps a secret that is not inserted yet, commits;
			// create then inserts anyway" left a LIVE secret, with a live
			// version 1, under a deleted project and a deleted environment.
			//
			// That end state is reachable, not merely untidy: GetSecret and
			// AuthorizeSecret do not check project liveness, so a global-scope
			// role or an ACL grant still reaches the value, the owner
			// short-circuit still applies (IsProjectMember has no liveness
			// join), new shares can still be created on it — and it is never
			// purged, because the purge only collects soft-deleted rows.
			//
			// AFTER the writes, not before: a cascade that runs entirely between
			// a pre-write check and the insert never sees this secret. See
			// lockLiveParent's doc comment.
			live, lerr := tx.LockLiveProject(ctx, secret.ProjectID)
			if lerr != nil {
				return lerr
			}
			if !live {
				return fmt.Errorf("%s: project %d was deleted while this secret was being created",
					i18n.T("ErrorNotFound", nil), secret.ProjectID)
			}
			return nil
		})
	}); err != nil {
		return nil, err
	}

	// Apply the create-time tags (#390) now that the secret and its first version both
	// exist. Calling the storage layer directly (not the core SetSecretTags wrapper)
	// is deliberate: SetSecretTags re-enforces write permission via
	// EnforceSecretWritePermission, which is redundant here (the caller already had
	// secrets.write on this scope to reach CreateSecret at all) and would require
	// resolving an actor ID that CreateSecretRequest doesn't carry uniformly across
	// every caller (HTTP/gRPC/CLI). Tags were already normalized/validated up front.
	// #1600: tagging is a best-effort enhancement layered on an already-successful
	// creation, not a prerequisite for it -- same convention as this codebase's
	// other best-effort post-create/post-action steps (e.g. project_members.go's
	// best-effort cleanup, dashboard.go's best-effort sub-rollups: log loudly,
	// never fail or unwind the primary operation). Previously a SetSecretTags
	// failure here deleted the secret THIS SAME CALL had just created -- a
	// transient storage error on the tag write destroyed data that had nothing
	// wrong with it, and under storage.type: remote (where SetSecretTags is a
	// permanent hard stub) this was not transient at all: every tagged create
	// was guaranteed to create-then-immediately-destroy its own secret. Leave the
	// secret in place, untagged, and surface the failure loudly instead.
	if len(normalizedTags) > 0 {
		if err := c.storage.SetSecretTags(ctx, createdSecret.ID, normalizedTags); err != nil {
			log.Printf("warning: secret %d (%s) created successfully but tags could not be set: %v", createdSecret.ID, createdSecret.Name, err)
		}
	}

	return createdSecret, nil
}

// GetSecret retrieves a secret by ID, checking expiration.
//
// GetSecret intentionally performs NO authorization check of its own — it neither
// verifies ownership nor consults shares/RBAC. Every real HTTP/gRPC caller that
// serves a secret to an end user goes through GetSecretWithPermissionCheck instead,
// which enforces read permission (via EnforceSecretReadPermission) before delegating
// to this method. GetSecret exists as the unguarded primitive for internal callers
// that have already authorized the request some other way (or are working with
// metadata rather than exposing the value). Do not call GetSecret directly from a
// path that serves a secret to a caller without first checking permission — use
// GetSecretWithPermissionCheck for that.
func (c *KeyorixCore) GetSecret(ctx context.Context, id uint) (*models.SecretNode, error) {
	if id == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	secret, err := c.storage.GetSecret(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}
	if secret.Expiration != nil && time.Now().After(*secret.Expiration) {
		return nil, fmt.Errorf("%s", i18n.T("ErrorSecretExpired", nil))
	}
	return secret, nil
}

// GetSecretWithPermissionCheck retrieves a secret by ID with read permission enforcement.
func (c *KeyorixCore) GetSecretWithPermissionCheck(ctx context.Context, id, userID uint) (*models.SecretNode, error) {
	if _, err := c.EnforceSecretReadPermission(ctx, id, userID); err != nil {
		return nil, err
	}
	if err := c.checkSecretAccessSchedule(ctx, id); err != nil {
		return nil, err
	}
	return c.GetSecret(ctx, id)
}

// GetSecretByName resolves a secret by its name within a project/environment. Like
// GetSecret, it performs NO authorization check of its own — callers that serve the
// result to an end user must go through GetSecretByNameWithPermissionCheck instead.
func (c *KeyorixCore) GetSecretByName(ctx context.Context, name string, projectID, environmentID uint) (*models.SecretNode, error) {
	secret, err := c.storage.GetSecretByName(ctx, name, projectID, environmentID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}
	if secret.Expiration != nil && time.Now().After(*secret.Expiration) {
		return nil, fmt.Errorf("%s", i18n.T("ErrorSecretExpired", nil))
	}
	return secret, nil
}

// GetSecretByNameWithPermissionCheck retrieves a secret by name/project/environment
// with read permission enforcement — the name-lookup counterpart to
// GetSecretWithPermissionCheck, mirroring the resolve-then-authorize-by-id pattern
// ResolveSecretRef/GetSecretValueByRef already use for the ref-based value read.
func (c *KeyorixCore) GetSecretByNameWithPermissionCheck(ctx context.Context, name string, projectID, environmentID, userID uint) (*models.SecretNode, error) {
	secret, err := c.storage.GetSecretByName(ctx, name, projectID, environmentID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}
	if _, err := c.EnforceSecretReadPermission(ctx, secret.ID, userID); err != nil {
		return nil, err
	}
	if err := c.checkSecretAccessSchedule(ctx, secret.ID); err != nil {
		return nil, err
	}
	return c.GetSecret(ctx, secret.ID)
}

// UpdateSecret updates an existing secret.
func (c *KeyorixCore) UpdateSecret(ctx context.Context, req *UpdateSecretRequest) (*models.SecretNode, error) {
	if err := c.validateUpdateSecretRequest(req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	// An update that changes the value writes a new version, so it must clear the
	// value policy too (otherwise a weak value bypasses the create/rotate gate).
	if len(req.Value) > 0 {
		if err := c.secretValuePolicy.Validate(req.Value); err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
		}
		if err := c.checkSecretSize(req.Value); err != nil {
			return nil, err
		}
	}
	secret, err := c.storage.GetSecret(ctx, req.ID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}
	if err := applyUpdateSecretFields(secret, req); err != nil {
		return nil, err
	}
	now := time.Now()
	secret.UpdatedAt = now
	// #2695: the columns this request actually asked to change, and nothing
	// else. The previous full-row Save persisted the whole struct read above, so
	// an update landing after a concurrent DeleteSecret resurrected the secret
	// (its shares and ACLs already revoked, no secret.restored audit) and
	// reverted a concurrent SuspendSecret, read-count increment or ownership
	// clear. Built from req, not from the mutated struct, so a field the request
	// did not carry cannot reach the UPDATE at all.
	fields, err := secretFieldUpdateFromRequest(req)
	if err != nil {
		return nil, err
	}
	fields.UpdatedAt = &now

	if len(req.Value) == 0 {
		matched, uerr := c.storage.UpdateSecretFields(ctx, secret.ID, fields)
		if uerr != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), uerr)
		}
		if !matched {
			return nil, fmt.Errorf("%s", i18n.T("ErrorSecretNotFound", nil))
		}
		return secret, nil
	}

	// #121 follow-up: two concurrent UpdateSecret calls on the same secret (or one
	// racing a RotateSecret) can both compute the same "next" version number from a
	// stale GetLatestSecretVersion read; the uniq_secret_versions_node_version index
	// (storage.ensureSecretVersionIndex) makes the loser's insert fail rather than
	// silently duplicate, but a plain storeSecretVersion call surfaced that as a hard
	// error to a caller doing nothing wrong. updateSecretWithNewVersion retries against
	// a freshly re-read version number instead, same as RotateSecret, and shares one
	// transaction between the version write and this row update — see that function's
	// doc comment for why.
	updatedSecret, err := c.updateSecretWithNewVersion(ctx, secret, req.Value, fields)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return updatedSecret, nil
}

// secretFieldUpdateFromRequest derives the column set an UpdateSecretRequest
// asks to change, mirroring applyUpdateSecretFields exactly — that function
// mutates the in-memory struct (for the value returned to the caller and for
// the new-version path), this one names the columns that may be written
// (#2695). They must stay in lockstep; TestUpdateSecretRequest_FieldSetsMatch
// asserts that mechanically rather than by comment.
func secretFieldUpdateFromRequest(req *UpdateSecretRequest) (storage.SecretFieldUpdate, error) {
	var f storage.SecretFieldUpdate
	if req.Type != "" {
		f.Type = &req.Type
	}
	if req.Description != nil {
		f.Description = req.Description
	}
	if req.MaxReads != nil {
		f.SetMaxReads, f.MaxReads = true, req.MaxReads
	}
	if req.ClearExpiration {
		f.SetExpiration, f.Expiration = true, nil
	} else if req.Expiration != nil {
		f.SetExpiration, f.Expiration = true, req.Expiration
	}
	if req.Metadata != nil {
		metadataJSON, err := json.Marshal(req.Metadata)
		if err != nil {
			return f, fmt.Errorf("%s: %w", i18n.T("ErrorInvalidMetadata", nil), err)
		}
		j := models.JSON(metadataJSON)
		f.Metadata = &j
	}
	return f, nil
}

// applyUpdateSecretFields patches the non-value fields (max reads, expiration,
// metadata, description) from req onto secret in place.
func applyUpdateSecretFields(secret *models.SecretNode, req *UpdateSecretRequest) error {
	if req.Type != "" {
		secret.Type = req.Type
	}
	if req.Description != nil {
		secret.Description = *req.Description
	}
	if req.MaxReads != nil {
		secret.MaxReads = req.MaxReads
	}
	if req.ClearExpiration {
		secret.Expiration = nil
	} else if req.Expiration != nil {
		secret.Expiration = req.Expiration
	}
	if req.Metadata != nil {
		metadataJSON, err := json.Marshal(req.Metadata)
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorInvalidMetadata", nil), err)
		}
		secret.Metadata = metadataJSON
	}
	return nil
}

// UpdateSecretWithPermissionCheck updates a secret with write permission enforcement.
func (c *KeyorixCore) UpdateSecretWithPermissionCheck(ctx context.Context, req *UpdateSecretRequest) (*models.SecretNode, error) {
	if req.UserID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required for permission checking")
	}
	if _, err := c.EnforceSecretWritePermission(ctx, req.ID, req.UserID); err != nil {
		return nil, err
	}
	return c.UpdateSecret(ctx, req)
}

// EventSecretRotateNoop is audited when RotateSecret is invoked with a value that is
// byte-identical to the secret's current version (#408). Left unaddressed, resubmitting
// an unchanged credential (a stale automation script, or an operator running `rotate`
// without actually changing anything) resets LastRotatedAt to "just now" with zero
// actual credential change, so risk-scoring/dashboards see "recently rotated, low risk"
// while the underlying secret has genuinely never changed. A new version row is still
// stored for audit-trail completeness, but LastRotatedAt is deliberately withheld.
const EventSecretRotateNoop = "secret.rotate_noop"

// RotateSecret creates a new version with a new value and updates LastRotatedAt.
//
// #408: if newValue is byte-identical to the CURRENT version's decrypted value, the
// rotation is treated as a no-op FOR TIMESTAMP PURPOSES ONLY: a new version row is
// still written (so the attempt is visible in version history / for audit trail
// completeness — someone did call rotate), but LastRotatedAt is deliberately left
// untouched so a false "recently rotated, low risk" signal never reaches
// dashboards/auditors/risk-scoring for material that hasn't actually changed. This
// silently-skip-the-timestamp behavior (rather than refusing/erroring outright) is
// deliberate: RotateSecret is also invoked by the auto-rotation scheduler
// (rotateOneSecret, "system:auto-rotation") and by RollbackSecret, neither of which
// expects — or gracefully handles — a hard error for what they consider a successful
// rotation call; erroring here would turn an edge case (a misbehaving rotation
// backend, or a rollback landing on a value the current version already holds) into an
// automation-breaking failure. The event is still recorded via EventSecretRotateNoop
// so the no-op is auditable rather than fully silent.
// actorID is the acting principal for the read-guard check the no-op
// comparison below requires (#G09) — 0 for system-triggered callers
// (auto-rotation), which is the same "no identifiable user" sentinel
// enforceSecretReadGuards' classification gate already denies restricted
// reads for.
func (c *KeyorixCore) RotateSecret(ctx context.Context, id uint, newValue []byte, actorID uint, rotatedBy string) (*models.SecretNode, error) {
	if err := c.secretValuePolicy.Validate(newValue); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	if err := c.checkSecretSize(newValue); err != nil {
		return nil, err
	}
	secret, err := c.storage.GetSecret(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("secret not found: %w", err)
	}

	// Compare against the CURRENT version's decrypted value, mirroring the existing
	// decrypt-on-read path used by RollbackSecret (direct c.encryption.RetrieveSecret /
	// raw EncryptedValue) rather than routing through readVersionValue — that helper
	// also enforces max-reads by incrementing the read counter, which this internal
	// comparison must NOT do (it would silently burn from a burn-after-N-reads
	// secret's budget on every rotation attempt). subtle.ConstantTimeCompare matches
	// this codebase's convention for comparing genuine secret material (see mfa.go,
	// auth_bootstrap.go, encryption/auth_encryption.go).
	//
	// #G09: this decrypt-and-compare is itself a value disclosure — its RESULT
	// (whether EventSecretRotateNoop fires, and whether LastRotatedAt moves) is
	// an oracle for "does the caller's guess equal the current secret value."
	// Gate it on the SAME read guards (classification-restricted step-up/
	// approval, access-schedule) a real value read of this secret would
	// require; if the actor couldn't pass them, skip the comparison entirely
	// rather than decrypt-to-compare without authorization — this only
	// degrades the no-op-detection optimization (the rotation itself still
	// proceeds and always records a real rotation), it never blocks the
	// rotation outright, so auto-rotation (actorID 0, only relevant for
	// "restricted"-classified secrets with a gate enabled) keeps working.
	valueUnchanged := false
	if c.enforceSecretReadGuards(ctx, secret, actorID) == nil {
		if latestVersion, verr := c.storage.GetLatestSecretVersion(ctx, id); verr == nil && latestVersion != nil {
			currentValue, rerr := c.decryptVersionValue(secret, latestVersion)
			if rerr == nil && subtle.ConstantTimeCompare(currentValue, newValue) == 1 {
				valueUnchanged = true
			}
		}
	}

	// Deliberately NOT wrapped in updateSecretWithNewVersion's shared transaction (unlike
	// UpdateSecret): by this point the upstream backend executor (RunAutoRotation /
	// RotateSecretOnDemand's caller) may already have rotated the REAL credential outside
	// Keyorix's control. If storeNextSecretVersion's write below succeeds but the row
	// update after it fails, keeping that version is correct — it is Keyorix's only record
	// of the value the live upstream credential now actually has. Rolling it back to "make
	// the two writes atomic" would silently make Keyorix's stored value diverge from
	// reality with no trace of what happened. TestRunAutoRotation_BackendSucceedsStoreFails_
	// AuditsDrift pins this: the caller audits this exact split (backend rotated, store
	// failed) as DRIFT rather than a plain failure. See updateSecretWithNewVersion's own
	// doc comment for why UpdateSecret's identical-shaped write does not have this
	// consideration and is made atomic.
	if err := c.storeNextSecretVersion(ctx, secret, newValue); err != nil {
		return nil, fmt.Errorf("failed to store rotated secret: %w", err)
	}
	now := time.Now()
	if valueUnchanged {
		log.Printf("rotate secret %d: new value identical to the current version; version stored but last_rotated_at was NOT updated", id)
		sid := id
		c.writeAuditEvent(ctx, EventSecretRotateNoop, nil, &sid,
			fmt.Sprintf("rotation of secret %q by %s submitted a value identical to the current version: a new version was stored for audit-trail completeness, but last_rotated_at was not updated", secret.Name, rotatedBy))
	} else {
		secret.LastRotatedAt = &now
	}
	secret.UpdatedAt = now
	// #2695: RotateSecret owns last_rotated_at and updated_at, nothing else.
	// SetLastRotatedAt is explicit because the no-op branch above deliberately
	// WITHHOLDS the stamp (#408) — passing secret.LastRotatedAt unconditionally
	// here is correct precisely because that branch left it at its prior value.
	matched, uerr := c.storage.UpdateSecretFields(ctx, secret.ID, storage.SecretFieldUpdate{
		SetLastRotatedAt: true, LastRotatedAt: secret.LastRotatedAt, UpdatedAt: &now,
	})
	if uerr != nil {
		return nil, fmt.Errorf("failed to update rotation timestamp: %w", uerr)
	}
	if !matched {
		return nil, fmt.Errorf("%s", i18n.T("ErrorSecretNotFound", nil))
	}
	updatedSecret := secret
	// Refresh the cached certificate expiry immediately for a certificate-typed secret
	// (ADR-056) so the certificate-hygiene posture reflects the rotated certificate
	// without waiting for the next expiry scan. The plaintext is already in hand, so no
	// re-decryption is needed; a no-op for non-certificate secrets.
	c.refreshCertNotAfterCache(ctx, secret, newValue)
	return updatedSecret, nil
}

// DeleteSecret soft-deletes a secret by ID.
func (c *KeyorixCore) DeleteSecret(ctx context.Context, id uint) error {
	if id == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	secret, err := c.storage.GetSecret(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}
	if err := c.storage.DeleteSecret(ctx, id); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	// Emit an audit event for every dependency edge incident to this secret so
	// operators know which rotation plans are affected (best-effort; the delete
	// already succeeded). actorID 0 here because DeleteSecret itself has no actor
	// context — the HTTP handler's LogSecretDeleted carries the authenticated user.
	c.emitDependencyLifecycleEvents(ctx, EventSecretDependencyInvalidated, 0, id, secret.ProjectID, secret.Name)
	return nil
}

// DeleteSecretWithPermissionCheck deletes a secret with owner permission enforcement.
func (c *KeyorixCore) DeleteSecretWithPermissionCheck(ctx context.Context, id, userID uint) error {
	if userID == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required for permission checking")
	}
	if _, err := c.EnforceSecretOwnerPermission(ctx, id, userID); err != nil {
		return err
	}
	return c.DeleteSecret(ctx, id)
}

// RestoreSecret clears a soft-deleted secret's deleted_at (ADR-033), bringing it
// back within the retention window. actorID is the admin performing it (0 = no
// authenticated principal). Audited as secret.restored — the inverse of the
// secret.deleted event, so a deleted secret reappearing leaves a trail.
func (c *KeyorixCore) RestoreSecret(ctx context.Context, actorID, id uint) error {
	if id == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	// Fetch before restoring so we have name + projectID even though the row is
	// still soft-deleted at this point (GetSecretIncludingDeleted ignores deleted_at).
	secret, err := c.storage.GetSecretIncludingDeleted(ctx, id)
	if err != nil {
		// Fall back gracefully: the storage.RestoreSecret call will re-validate the
		// row and return a proper error if the id is unknown.
		secret = nil
	}
	if err := c.storage.RestoreSecret(ctx, id); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	sid := id
	c.writeAuditEvent(ctx, "secret.restored", actorPtr(actorID), &sid, c.auditRef(ctx, c.storage, auditKindSecret, id)+" restored")
	// Emit an audit event for every dependency edge that is now re-active so
	// operators know which rotation plans are unblocked (best-effort).
	if secret != nil {
		c.emitDependencyLifecycleEvents(ctx, EventSecretDependencyRestored, actorID, id, secret.ProjectID, secret.Name)
	}
	return nil
}

// ListSecrets lists secrets with filtering and pagination.
func (c *KeyorixCore) ListSecrets(ctx context.Context, filter *storage.SecretFilter) ([]*models.SecretNode, int64, error) {
	if filter == nil {
		filter = &storage.SecretFilter{}
	}
	if filter.Page <= 0 {
		filter.Page = 1
	}
	if filter.PageSize <= 0 {
		filter.PageSize = 20
	}
	if filter.PageSize > 100 {
		filter.PageSize = 100
	}
	secrets, total, err := c.storage.ListSecrets(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return secrets, total, nil
}

// CreateFolder creates a SecretNode with IsSecret=false (a folder container).
// name must be non-empty. If parentID is provided the referenced node must
// exist and must itself be a folder (IsSecret=false).
func (c *KeyorixCore) CreateFolder(
	ctx context.Context,
	actorID uint,
	name string,
	projectID, envID uint,
	parentID *uint,
) (*models.SecretNode, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("%s: folder name is required", i18n.T("ErrorValidation", nil))
	}
	// #1642: folders share secret_nodes' (project, environment, name) unique
	// index with secrets, so they share the identical NFC-vs-NFD collision
	// risk CreateSecret closes above — normalize here the same way, not
	// case-folded (a folder name is an address/path segment, not identity).
	normalizedFolderName, nerr := identity.NewAddressName(name)
	if nerr != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), nerr)
	}
	name = normalizedFolderName.String()
	if projectID == 0 {
		return nil, fmt.Errorf("%s: project_id is required", i18n.T("ErrorValidation", nil))
	}
	if envID == 0 {
		return nil, fmt.Errorf("%s: environment_id is required", i18n.T("ErrorValidation", nil))
	}

	// Validate that the parent exists and is itself a folder node.
	if parentID != nil {
		parent, err := c.storage.GetSecret(ctx, *parentID)
		if err != nil {
			return nil, fmt.Errorf("parent folder %d not found: %w", *parentID, err)
		}
		if parent.IsSecret {
			return nil, fmt.Errorf("%s: parent node %d is a secret, not a folder", i18n.T("ErrorValidation", nil), *parentID)
		}
		// The destination parent was loaded with a bare, unauthorized GetSecret:
		// the caller's write authorization was only ever checked against
		// (projectID, envID) — the NEW folder's own claimed scope — and says
		// nothing about the target parent's actual scope. Mirror CreateSecret's
		// own parent-folder validation (above in this file) and MoveSecret's
		// (secret_move.go): require the destination to live in the SAME
		// project/environment the caller was authorized for, otherwise a caller
		// could nest a folder under a parent in a project/environment they have
		// no access to, and folder-inheriting ACL/sharing resolution (see
		// HasSecretACL's ancestor walk in secret_acl.go) would then apply that
		// other project's grants to it.
		if parent.ProjectID != projectID || parent.EnvironmentID != envID {
			return nil, fmt.Errorf("%s: parent folder %d does not belong to the same project/environment", i18n.T("ErrorValidation", nil), *parentID)
		}
	}

	node := &models.SecretNode{
		Name:          name,
		ProjectID:     projectID,
		EnvironmentID: envID,
		ParentID:      parentID,
		IsSecret:      false,
		Type:          "folder",
		Status:        "active",
		CreatedBy:     fmt.Sprintf("%d", actorID),
		OwnerID:       actorID,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	// SESSION-AT AT1/AT3 (coordinator review, PR #2353): a folder counts
	// toward DeleteEnvironment's active-secret guard exactly like a secret
	// does, so this races a concurrent DeleteEnvironment the identical way
	// CreateSecret does -- same lock, same in-lock re-check, same reasoning;
	// see CreateSecret's own doc comment on this pattern.
	var created *models.SecretNode
	if err := c.withEnvironmentSecretGuard(ctx, envID, func(ctx context.Context) error {
		// #2711: wrapped in a transaction purely so the project re-check below
		// can share one with the insert — the insert alone needed none. Same
		// write-then-check as CreateSecret above; see its comment for why the
		// environment guard does not cover a concurrent DeleteProject, and why
		// a folder is affected exactly like a secret (it is a SecretNode row,
		// counts toward DeleteEnvironment's active-secret guard, and ends up
		// live under a deleted project the same way).
		return c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
			var cerr error
			created, cerr = tx.CreateSecret(ctx, node, "")
			if cerr != nil {
				return cerr
			}
			live, lerr := tx.LockLiveProject(ctx, projectID)
			if lerr != nil {
				return lerr
			}
			if !live {
				return fmt.Errorf("%s: project %d was deleted while this folder was being created",
					i18n.T("ErrorNotFound", nil), projectID)
			}
			return nil
		})
	}); err != nil {
		return nil, err
	}
	pid := projectID
	c.writeAuditEventFull(ctx, "folder.created", actorPtr(actorID), nil, &pid, "",
		fmt.Sprintf("folder %d (%q) created in project %d environment %d", created.ID, name, projectID, envID))
	return created, nil
}

// ListFolders returns all folder nodes (IsSecret=false) for a project/environment.
// If parentID is non-nil, only children of that parent are returned.
func (c *KeyorixCore) ListFolders(ctx context.Context, projectID uint, parentID *uint, page, pageSize int) ([]*models.SecretNode, int64, error) {
	isFalse := false
	filter := &storage.SecretFilter{
		IsSecret: &isFalse,
		Page:     page,
		PageSize: pageSize,
	}
	if projectID != 0 {
		filter.ProjectID = &projectID
	}
	if parentID != nil {
		filter.ParentID = parentID
	}
	return c.ListSecrets(ctx, filter)
}
