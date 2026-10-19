package core

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failOnceCreateSetupTokenStorage makes CreateSetupToken fail once, mirroring
// the failOnceStorage idiom from #2295.
func failOnceCreateSetupTokenStorage(inner storage.Storage, armed *bool) storage.Storage {
	return hooked(inner, &storeHooks{
		WrapTx: true,
		CreateSetupToken: func(next storage.Storage, ctx context.Context, t *models.SetupToken) (*models.SetupToken, error) {
			if *armed {
				*armed = false
				return nil, errors.New("injected fault: CreateSetupToken")
			}
			return next.CreateSetupToken(ctx, t)
		},
	})
}

// WithTransaction re-wraps the tx handle the underlying storage hands back
// into another failOnceCreateSetupTokenStorage, so the injected fault still
// fires for a CreateSetupToken call made against the tx parameter inside a
// WithTransaction closure -- without this override the fault would only ever
// apply to calls made directly against s, never against the tx handle IssueSetupToken
// actually uses post-fix.
// TestResendInvitationLink_CreateSetupTokenFailureKillsWorkingLink is the
// RED-PROOF for the coordinator's CI-observed candidate (Session O follow-up,
// 2026-09-29, fuzz shard 2 on #2261's run: op=REST POST
// /api/v1/projects/{id}/invitations fault=CreateSetupToken):
// IssueSetupToken (setup_token.go) supersedes any PRIOR active token for the
// same (purpose, email[, project]) FIRST, then creates the new one, as two
// sequential, non-transactional storage calls. If a resend's CreateSetupToken
// then fails, the invitee's STILL-WORKING prior link is already dead
// (superseded) and no replacement was created -- a resend that was supposed
// to fix a delivery problem instead destroys a working link, proving this is
// class A, not S (a resend failing safely, i.e. leaving the old link intact,
// is what "safe by design" would require, and it doesn't).
func TestResendInvitationLink_CreateSetupTokenFailureKillsWorkingLink(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	c.SetCredentialDelivery(nil, "https://kx.example.com") // out-of-band mode, no real SMTP needed

	proj, err := st.CreateProject(ctx, &models.Project{Name: "resend-proj", Description: "d"})
	require.NoError(t, err)
	const email = "invitee@example.com"

	// A first, successful invite -- a genuinely working link exists. The raw
	// token is the last path segment of the out-of-band link (deliverSetupLink:
	// link := c.setupBaseURL + "/auth/setup/" + issued.PlainToken).
	inv, prov, err := c.InviteToProjectWithLink(ctx, proj.ID, email, "project_developer", 1, 0)
	require.NoError(t, err)
	require.NotNil(t, prov)
	require.True(t, prov.Delivered || prov.LinkForAdmin != "", "the first invite must produce a real, working link")
	idx := strings.LastIndex(prov.LinkForAdmin, "/")
	require.Greater(t, idx, -1, "the delivered link must contain the raw token as its final path segment")
	firstRawToken := prov.LinkForAdmin[idx+1:]

	firstTok, terr := st.GetSetupTokenByHash(ctx, sha256Hex(firstRawToken))
	require.NoError(t, terr)
	require.Equal(t, SetupTokenActive, firstTok.State, "the first link's token must be active right after issuance")

	// Clear the per-subject resend cooldown (ADR-028, 60s) so the resend below
	// isn't rejected by the throttle before ever reaching IssueSetupToken.
	c.SetClockForTesting(func() time.Time { return time.Now().Add(2 * time.Minute) })

	// Now resend, injecting a failure into the SECOND write (CreateSetupToken).
	// SupersedeActiveSetupTokens (the FIRST write) is allowed to succeed.
	armed := true
	c.storage = failOnceCreateSetupTokenStorage(st, &armed)

	_, err = c.ResendInvitationLink(ctx, proj.ID, inv.ID, 1)
	require.Error(t, err, "the resend must surface the injected failure")
	require.False(t, armed, "the injected fault must actually have fired")
	require.Contains(t, err.Error(), "injected fault", "the surfaced error must be the injected fault, not an unrelated rejection")

	c.storage = st
	afterTok, terr := st.GetSetupTokenByHash(ctx, sha256Hex(firstRawToken))
	require.NoError(t, terr)
	assert.Equal(t, SetupTokenActive, afterTok.State,
		"a failed resend must leave the ORIGINAL working link's token ACTIVE -- "+
			"not superseded (the old one killed, the new one never created, the invitee locked out with no way in)")
}
