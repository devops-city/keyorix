// setup_token.go — credential-delivery setup tokens (ADR-028).
//
// A setup token is the single-use bearer string that lets a brand-new principal
// establish their first credential. It backs three producers — invitation
// acceptance (ADR-024), admin-direct account setup (ADR-025), and the reset-link
// path — selected by Purpose. The raw token is returned once on issuance (to embed
// in an https link or display out of band) and never persisted; only its SHA-256
// hash is stored, and lookup is by hash. This mirrors the PAT handling in pat.go.
//
// Lifecycle invariants:
//   - Single-use: consuming flips active → consumed via a state-guarded UPDATE, so a
//     replay matches zero rows and is rejected.
//   - Short TTL: default 24h (configurable). A lazy-expire check flips an overdue
//     active token to expired on read.
//   - Superseded on reissue: minting a new token for the same (purpose, email)
//     supersedes any prior active one, so "resend" kills the old link instantly.
//   - Purpose-scoped: a token minted for one purpose can never drive another.
package core

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ErrSetupTokenIssuanceFailed marks a failure of the supersede+create transaction
// below (not a config/validation problem like a missing base_url or a throttle hit).
// Callers that create a durable record ahead of the setup link (e.g.
// InviteGlobalWithLink/InviteToProjectWithLink creating a ProjectInvitation first)
// use this to tell the two failure classes apart: a config/throttle failure leaves
// prior links untouched and is safe to report as a resendable partial success, but
// this one means the attempted supersede of the subject's prior active links did
// NOT happen (the whole transaction rolled back) -- that must never be reported as
// success, so the caller can fail closed instead of claiming the link was replaced.
var ErrSetupTokenIssuanceFailed = errors.New("setup token issuance transaction failed")

// Setup-token purposes. A token is bound to exactly one at issuance.
const (
	SetupPurposeInvitationAccept  = "invitation_accept"
	SetupPurposeAccountSetup      = "account_setup"
	SetupPurposePasswordResetLink = "password_reset_link"
)

// Setup-token states.
const (
	SetupTokenActive     = "active"
	SetupTokenConsumed   = "consumed"
	SetupTokenExpired    = "expired"
	SetupTokenSuperseded = "superseded"
)

const (
	// setupPrefix marks a raw setup token. Load-bearing for secret-scanning leak
	// detection; the token travels in an https link, not the auth bearer path.
	setupPrefix = "kx_setup_"
	// DefaultSetupTokenTTL is the fallback link lifetime when none is configured.
	DefaultSetupTokenTTL = 24 * time.Hour
)

// validSetupPurpose reports whether p is a recognised purpose.
func validSetupPurpose(p string) bool {
	switch p {
	case SetupPurposeInvitationAccept, SetupPurposeAccountSetup, SetupPurposePasswordResetLink:
		return true
	default:
		return false
	}
}

// IssueSetupTokenRequest describes a token to mint.
type IssueSetupTokenRequest struct {
	Purpose       string
	SubjectEmail  string // the address the token is bound to (required)
	SubjectUserID *uint  // nil until an account exists (e.g. invitation by email)
	InvitationID  *uint  // set for purpose = invitation_accept
	CreatedBy     uint   // issuing admin/inviter; 0 for self-service reset
	// CreatedByMachineIdentityID (#1573) records which machine identity issued
	// this token, when CreatedBy is 0 because the issuer was a machine caller
	// (ADR-030) rather than a human. 0 = none.
	CreatedByMachineIdentityID uint

	// SupersedeProjectID additionally scopes the pre-issuance supersede (see
	// IssueSetupToken below) to a single project's own invitations, instead of every
	// active token for (Purpose, SubjectEmail) across every project
	// (CORE-INVITATIONS-003). Project-scoped invite/resend call sites
	// (InviteToProjectWithLink, ResendInvitationLink) set this to their ProjectID so an
	// admin in one project can never silently invalidate a different project's still-
	// pending invite to the same address. Left nil for flows with no project dimension
	// (InviteGlobalWithLink, account_setup, password_reset_link), which keep the
	// original (Purpose, SubjectEmail)-only supersede scope.
	SupersedeProjectID *uint
}

// IssueSetupTokenResult carries the freshly minted token plus its one-time plaintext.
// PlainToken is never persisted and never returned again.
type IssueSetupTokenResult struct {
	Token      *models.SetupToken
	PlainToken string
}

// IssueSetupToken mints a single-use setup token, superseding any prior active token
// for the same (purpose, email) so a reissue invalidates the old link. The raw token
// is returned once; only its hash is stored.
func (c *KeyorixCore) IssueSetupToken(ctx context.Context, req IssueSetupTokenRequest) (*IssueSetupTokenResult, error) {
	result, err := c.mintSetupTokenOn(ctx, c.storage, req)
	if err != nil {
		return nil, err
	}
	c.auditSetupTokenIssued(ctx, req, result.Token)
	return result, nil
}

// mintSetupTokenOn is IssueSetupToken's actual mint logic, parameterized over
// the storage.Storage handle it writes through, WITHOUT auditing (the audit
// write always happens via emitAudit against c.storage directly and must
// never run until the caller's own transaction, if any, has committed --
// #2444 coordinator follow-up). st is c.storage for the standalone
// IssueSetupToken path above, or an outer caller's already-open transaction
// handle (e.g. createInvitationWithSetupTokenAtomically below) when the mint
// must commit or roll back together with a durable record created ahead of
// it. st.WithTransaction nests as a SAVEPOINT when st is already
// transaction-scoped (GORM's standard nested-transaction behavior, same
// mechanism catalog.go's nested environment-seed transaction relies on), so
// this needs no special-casing for either caller.
func (c *KeyorixCore) mintSetupTokenOn(ctx context.Context, st storage.Storage, req IssueSetupTokenRequest) (*IssueSetupTokenResult, error) {
	if !validSetupPurpose(req.Purpose) {
		return nil, fmt.Errorf("%s: unknown setup-token purpose %q", i18n.T("ErrorValidation", nil), req.Purpose)
	}
	email := strings.TrimSpace(strings.ToLower(req.SubjectEmail))
	if email == "" {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "subject email is required")
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	raw := setupPrefix + base64.RawURLEncoding.EncodeToString(b)

	ttl := c.setupTokenTTL
	if ttl <= 0 {
		ttl = DefaultSetupTokenTTL
	}
	now := c.now()

	tok := &models.SetupToken{
		TokenHash:                  sha256Hex(raw),
		Purpose:                    req.Purpose,
		SubjectUserID:              req.SubjectUserID,
		SubjectEmail:               email,
		InvitationID:               req.InvitationID,
		State:                      SetupTokenActive,
		ExpiresAt:                  now.Add(ttl),
		CreatedBy:                  req.CreatedBy,
		CreatedByMachineIdentityID: req.CreatedByMachineIdentityID,
		CreatedAt:                  now,
	}

	// Supersede any prior active token for this subject+purpose and create the
	// replacement in one transaction: a resend must never kill a still-working
	// link without also successfully minting its replacement (Session O
	// follow-up, 2026-09-29 -- matches CI's FuzzStorageFaultOperations shard 2
	// finding, op=REST POST /api/v1/projects/{id}/invitations
	// fault=CreateSetupToken: an old-link-superseded/new-link-never-created
	// split permanently locks the invitee out with no working link and no
	// self-service recovery). SupersedeProjectID, when set, additionally
	// confines this to the issuing project's own invitations
	// (CORE-INVITATIONS-003) rather than every project's.
	var created *models.SetupToken
	err := st.WithTransaction(ctx, func(tx storage.Storage) error {
		if err := tx.SupersedeActiveSetupTokens(ctx, req.Purpose, email, req.SupersedeProjectID); err != nil {
			return err
		}
		var cerr error
		created, cerr = tx.CreateSetupToken(ctx, tok)
		return cerr
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %w", i18n.T("ErrorStorageFailed", nil), ErrSetupTokenIssuanceFailed, err)
	}

	return &IssueSetupTokenResult{Token: created, PlainToken: raw}, nil
}

// auditSetupTokenIssued writes setup_token.issued. Split out of IssueSetupToken
// so a caller that minted the token via mintSetupTokenOn against an outer,
// not-yet-committed transaction (createInvitationWithSetupTokenAtomically)
// can defer this until AFTER that transaction actually commits -- emitAudit
// always writes through c.storage directly (never a tx handle), so calling
// it before commit would record "issued" for a token a later rollback could
// still erase.
func (c *KeyorixCore) auditSetupTokenIssued(ctx context.Context, req IssueSetupTokenRequest, tok *models.SetupToken) {
	// Issuer is the actor; for self-service reset (CreatedBy == 0) attribute to the
	// subject. No token (not even the hash) is recorded on the audit row.
	actor := actorOrSubject(req.CreatedBy, req.SubjectUserID)
	c.writeAuditEventFull(ctx, "setup_token.issued", actor, nil, nil, "",
		fmt.Sprintf("setup token issued (purpose=%s, subject=%s, expires=%s)",
			req.Purpose, tok.SubjectEmail, tok.ExpiresAt.UTC().Format(time.RFC3339)))
}

// ValidateSetupToken resolves a raw token to its record for the expected purpose,
// without consuming it (the landing page calls this to show the assignment summary).
// It rejects unknown, non-active, wrong-purpose, and expired tokens, lazily flipping
// an overdue active token to expired as a side effect.
func (c *KeyorixCore) ValidateSetupToken(ctx context.Context, raw, expectedPurpose string) (*models.SetupToken, error) {
	tok, err := c.inspectActiveSetupToken(ctx, raw)
	if err != nil {
		return nil, err
	}
	// Purpose-scoping: the token may only drive the flow it was minted for.
	if tok.Purpose != expectedPurpose {
		return nil, fmt.Errorf("%s: setup token purpose mismatch", i18n.T("ErrorValidation", nil))
	}
	return tok, nil
}

// inspectActiveSetupToken resolves a raw token, lazily expires it if overdue, and
// returns it only if active. It does NOT check purpose — callers that know the
// expected purpose use ValidateSetupToken; the GET-describe path (which must report
// the purpose to the landing page) uses this directly.
func (c *KeyorixCore) inspectActiveSetupToken(ctx context.Context, raw string) (*models.SetupToken, error) {
	tok, err := c.lookupSetupToken(ctx, raw)
	if err != nil {
		if !credentialRowGone(err) {
			// #3298: a storage fault, not "no such token": nothing was
			// evaluated. Same text as a dead token (the response must not
			// depend on it), but the transport hands the login slot back.
			return nil, &setupNotEvaluatedError{msg: fmt.Sprintf("%s: invalid setup token", i18n.T("ErrorNotFound", nil))}
		}
		return nil, fmt.Errorf("%s: invalid setup token", i18n.T("ErrorNotFound", nil))
	}

	// Lazy expiry: an active token past its TTL is flipped to expired on read.
	// Best-effort: a failed mutation/audit write here must not block reporting
	// "expired" back to the reader, which is why the error is discarded — see
	// expireSetupToken's own doc for why that's still a single unit, not two
	// independent steps that can silently drift apart (#1622).
	if tok.State == SetupTokenActive && c.now().After(tok.ExpiresAt) {
		_ = c.expireSetupToken(ctx, tok)
		return nil, fmt.Errorf("%s: setup token expired", i18n.T("ErrorNotFound", nil))
	}
	if tok.State != SetupTokenActive {
		return nil, fmt.Errorf("%s: setup token is %s", i18n.T("ErrorNotFound", nil), tok.State)
	}
	return tok, nil
}

// ErrSetupNotEvaluated marks a setup-token consume or describe that reached no
// verdict on the token: its lookup failed on storage (or panicked), so whether
// the token is valid was never checked (#3298). Its text is the dead-token
// text, so nothing a client sees changes; the transport hands the per-IP login
// slot back (the budget counts evaluated attempts, as ErrLoginNotEvaluated on
// /auth/login) and audits auth.login_error.
var ErrSetupNotEvaluated = errors.New("setup token not evaluated: lookup failed")

type setupNotEvaluatedError struct{ msg string }

func (e *setupNotEvaluatedError) Error() string      { return e.msg }
func (*setupNotEvaluatedError) Is(target error) bool { return target == ErrSetupNotEvaluated }

// lookupSetupToken is GetSetupTokenByHash with a panic turned into an error
// (#3298 point 3): the lookup runs before the token is evaluated, so its panic
// answered 500 for a valid and a dead token alike. Now it takes the
// not-evaluated branch: the generic answer, the slot handed back.
func (c *KeyorixCore) lookupSetupToken(ctx context.Context, raw string) (tok *models.SetupToken, err error) {
	defer func() {
		if r := recover(); r != nil {
			tok, err = nil, fmt.Errorf("setup token lookup panicked: %v", r)
		}
	}()
	return c.storage.GetSetupTokenByHash(ctx, sha256Hex(raw))
}

// expireSetupToken performs a setup token's state mutation (active → expired)
// and its setup_token.expired audit write as a single unit, so no exported
// path can do one without the other (#1622). The audit event's ActorType/
// MachineIdentityID come from ctx (set by the auth middleware for every
// authenticated request, human or machine) via writeAuditEventFull — callers
// do not need to thread actor identity through explicitly.
func (c *KeyorixCore) expireSetupToken(ctx context.Context, tok *models.SetupToken) error {
	if err := c.storage.MarkSetupTokenExpired(ctx, tok.ID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.writeAuditEventFull(ctx, "setup_token.expired", tok.SubjectUserID, nil, nil, "",
		fmt.Sprintf("setup token expired (purpose=%s, subject=%s)", tok.Purpose, tok.SubjectEmail))
	return nil
}

// ExpireSetupTokenByID explicitly expires a setup token by ID, resolving it
// first so the audit write carries the same purpose/subject detail as the
// lazy-expiry path. This is the ONLY route into expireSetupToken for a caller
// that has an ID rather than an already-resolved token — originally
// server/http/handlers' ExpireSetupTokenProxy (backing the now-deleted
// RemoteStorage's own lazy-expiry-on-read, #1622), which had to not call
// storage.MarkSetupTokenExpired directly since that would mutate state
// without the audit write. That proxy is itself deleted along with the rest
// of the /system tier (ADR-108), leaving this method (and the
// GetSetupTokenByID call it makes) with zero production callers today —
// another follow-up cleanup candidate, not removed here.
//
// An unknown ID is a no-op, not an error: this mirrors the raw
// storage.MarkSetupTokenExpired's own long-standing idempotent semantics (a
// state-guarded UPDATE matching zero rows was never an error) that
// ExpireSetupTokenProxy's tests already asserted on -- closing the
// audit gap must not also turn a previously-tolerated "already gone" ID into
// a new 500.
func (c *KeyorixCore) ExpireSetupTokenByID(ctx context.Context, id uint) error {
	tok, err := c.storage.GetSetupTokenByID(ctx, id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil
		}
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return c.expireSetupToken(ctx, tok)
}

// ConsumeSetupToken validates a token for the expected purpose and atomically marks
// it consumed (single-use). The returned record lets the caller materialize the
// token's effect (accept the invitation / set the password). Consumption is burned
// up front: if the caller's subsequent materialization fails, the token is already
// spent — a deliberate fail-closed choice, since a setup token is a credential.
func (c *KeyorixCore) ConsumeSetupToken(ctx context.Context, raw, expectedPurpose string) (*models.SetupToken, error) {
	tok, err := c.inspectActiveSetupToken(ctx, raw)
	if err != nil {
		return nil, err
	}
	if err := c.consumeInspectedToken(ctx, tok, expectedPurpose); err != nil {
		return nil, err
	}
	return tok, nil
}

// consumeInspectedToken marks an already-inspected active token consumed (single-use),
// after checking its purpose. CompleteSetup calls this with the token it already
// resolved, so the consume flow performs ONE hash+lookup instead of two — closing the
// lazy-expire race between a re-validate and the mark. Consumption is burned up front
// (fail-closed): a setup token is a credential.
func (c *KeyorixCore) consumeInspectedToken(ctx context.Context, tok *models.SetupToken, expectedPurpose string) error {
	if tok.Purpose != expectedPurpose {
		return fmt.Errorf("%s: setup token purpose mismatch", i18n.T("ErrorValidation", nil))
	}
	ok, err := c.storage.MarkSetupTokenConsumed(ctx, tok.ID, c.now())
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	if !ok {
		// Lost a race to a concurrent consumer (or already spent between inspect and
		// mark). Single-use holds: reject.
		return fmt.Errorf("%s: setup token already used", i18n.T("ErrorNotFound", nil))
	}
	c.writeAuditEventFull(ctx, "setup_token.consumed", tok.SubjectUserID, nil, nil, "",
		fmt.Sprintf("setup token consumed (purpose=%s, subject=%s)", tok.Purpose, tok.SubjectEmail))
	return nil
}

// actorOrSubject returns the issuing admin as the audit actor, falling back to the
// subject for self-service issuance (createdBy == 0).
func actorOrSubject(createdBy uint, subjectUserID *uint) *uint {
	if createdBy != 0 {
		a := createdBy
		return &a
	}
	return subjectUserID
}
