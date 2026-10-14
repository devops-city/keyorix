// break_glass_review_test.go -- ADR-112 §3 (secure-by-default baseline,
// break-glass review item 5): KeyorixCore.ReviewBreakGlass and
// ListUnreviewedBreakGlassActivations.
package core

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// breakGlassActivationFixture is a CONCLUDED activation (revoked), because
// #2461 made a still-active one unreviewable: a reviewer cannot assess what was
// done with access that is still in use. The still-active case has its own test
// below (TestReviewBreakGlass_RefusesWhileStillActive), and the expired case
// too -- so the state rule is pinned in all three directions rather than this
// fixture quietly standing in for one of them.
func breakGlassActivationFixture() *models.BreakGlassActivation {
	return &models.BreakGlassActivation{
		ID: 7, ProjectID: 1, UserID: 10, RoleID: 3, RoleName: "editor", State: BreakGlassRevoked,
	}
}

func TestReviewBreakGlass_RecordsReviewAndAudits(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetBreakGlassActivation", mock.Anything, uint(7)).Return(breakGlassActivationFixture(), nil)
	ms.On("ReviewBreakGlassActivation", mock.Anything, uint(7), uint(99), "checked the justification, looks fine", mock.Anything).Return(nil)
	var captured *models.AuditEvent
	ms.On("LogAuditEvent", mock.Anything, mock.AnythingOfType("*models.AuditEvent")).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*models.AuditEvent) }).Return(nil)

	c := NewKeyorixCore(ms)
	err := c.ReviewBreakGlass(context.Background(), 99, 1, 7, "checked the justification, looks fine")
	require.NoError(t, err)

	if assert.NotNil(t, captured) {
		assert.Equal(t, EventBreakGlassReviewed, captured.EventType)
	}
}

func TestReviewBreakGlass_RejectsShortNote(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetBreakGlassActivation", mock.Anything, uint(7)).Return(breakGlassActivationFixture(), nil)

	c := NewKeyorixCore(ms)
	err := c.ReviewBreakGlass(context.Background(), 99, 1, 7, "ok")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "characters")
	ms.AssertNotCalled(t, "ReviewBreakGlassActivation", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestReviewBreakGlass_RejectsEmptyProjectID(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.ReviewBreakGlass(context.Background(), 99, 0, 7, "a perfectly good review note")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project ID is required")
}

func TestReviewBreakGlass_MismatchedProjectIsNotFound(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetBreakGlassActivation", mock.Anything, uint(7)).Return(breakGlassActivationFixture(), nil)

	c := NewKeyorixCore(ms)
	err := c.ReviewBreakGlass(context.Background(), 99, 999, 7, "a perfectly good review note")
	require.Error(t, err)
	ms.AssertNotCalled(t, "ReviewBreakGlassActivation", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// A CONCLUDED activation is reviewable -- both concluded states, so the state
// rule below is "refuse while active", not "only accept revoked".
func TestReviewBreakGlass_AllowedOnConcludedActivation(t *testing.T) {
	for _, state := range []string{BreakGlassRevoked, BreakGlassExpired} {
		t.Run(state, func(t *testing.T) {
			act := breakGlassActivationFixture()
			act.State = state

			ms := new(MockStorage)
			ms.On("GetBreakGlassActivation", mock.Anything, uint(7)).Return(act, nil)
			ms.On("ReviewBreakGlassActivation", mock.Anything, uint(7), uint(99), mock.Anything, mock.Anything).Return(nil)
			ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

			c := NewKeyorixCore(ms)
			err := c.ReviewBreakGlass(context.Background(), 99, 1, 7, "reviewed after it concluded, looks fine")
			require.NoError(t, err)
		})
	}
}

// TestReviewBreakGlass_RefusesSelfReview is the load-bearing one of the three
// #2461 refusals. ADR-112 keeps break-glass activation single-person
// *because* an independent post-activation review follows it; letting the
// activating user close out their own activation collapses that two-person
// property into one person, leaving the emergency path with no second pair of
// eyes at any point in its lifecycle.
func TestReviewBreakGlass_RefusesSelfReview(t *testing.T) {
	act := breakGlassActivationFixture() // UserID 10
	ms := new(MockStorage)
	ms.On("GetBreakGlassActivation", mock.Anything, uint(7)).Return(act, nil)

	c := NewKeyorixCore(ms)
	err := c.ReviewBreakGlass(context.Background(), 10, 1, 7, "I reviewed my own emergency access")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "own")
	ms.AssertNotCalled(t, "ReviewBreakGlassActivation", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestReviewBreakGlass_RefusesUnattributableReviewer closes the same hole from
// the other side: actorID==0 is a machine identity (which authenticates with
// UserID==0 and authorizes via PrincipalID) or an unauthenticated local-CLI
// invocation. A review attributed to nobody records accountability to nobody,
// and would persist reviewed_by=0 -- indistinguishable from an unreviewed row's
// zero value in every report that reads it. Same rule requireHumanReviewer
// already applies to access-review decisions.
func TestReviewBreakGlass_RefusesUnattributableReviewer(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.ReviewBreakGlass(context.Background(), 0, 1, 7, "reviewed by nobody in particular")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reviewer")
	// Refused before the activation is even loaded.
	ms.AssertNotCalled(t, "GetBreakGlassActivation", mock.Anything, mock.Anything)
	ms.AssertNotCalled(t, "ReviewBreakGlassActivation", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestReviewBreakGlass_RefusesWhileStillActive: the grant must be concluded
// first. A reviewer cannot assess what was done with access that is still in
// use, and a recorded review of an unfinished event reads as a closed item to
// both an auditor and the posture report.
//
// State is a read-time projection (GetBreakGlassActivation), so a TTL-lapsed
// activation already reads BreakGlassExpired here and needs no write first --
// this refusal cannot strand a review behind a state transition nobody
// performs.
func TestReviewBreakGlass_RefusesWhileStillActive(t *testing.T) {
	act := breakGlassActivationFixture()
	act.State = BreakGlassActive

	ms := new(MockStorage)
	ms.On("GetBreakGlassActivation", mock.Anything, uint(7)).Return(act, nil)

	c := NewKeyorixCore(ms)
	err := c.ReviewBreakGlass(context.Background(), 99, 1, 7, "reviewing while the grant is still live")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "still active")
	ms.AssertNotCalled(t, "ReviewBreakGlassActivation", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestBreakGlassActivation_HasNoApproverField guards the PREMISE the
// no-self-review rule rests on, not the rule's conclusion (CLAUDE.md: "when a
// verdict depends on a condition, guard the condition").
//
// The review asked whether a reviewer who was a CO-APPROVER of the activation
// should also be refused. There is no such concept: ADR-112 explicitly rejects
// two-person break-glass ("an emergency path that needs a second person fails
// exactly when it's needed"), so BreakGlassActivation carries no approver
// field, and the acting reviewer plus the activating user are the only two
// identities an activation has -- which is exactly what the actorID ==
// activation.UserID check covers in full.
//
// A guard aimed at the conclusion ("no co-approver can review") would be
// vacuous today: the population it checks is empty precisely because the
// condition holds. This asserts the condition instead, so adding co-approval
// later fails HERE and forces the co-approver exclusion to be written, rather
// than silently leaving a second self-review path open.
func TestBreakGlassActivation_HasNoApproverField(t *testing.T) {
	rt := reflect.TypeFor[models.BreakGlassActivation]()
	for field := range rt.Fields() {
		name := strings.ToLower(field.Name)
		// "ReviewedBy" is the reviewer, not an approver of the activation.
		if strings.HasPrefix(name, "review") {
			continue
		}
		assert.NotContains(t, name, "approv",
			"BreakGlassActivation grew field %q: break-glass has acquired an approver/co-approver concept, so ReviewBreakGlass's self-review refusal (actorID == activation.UserID) is no longer exhaustive -- it must also refuse a reviewer who approved the activation. See ADR-112 and ReviewBreakGlass's doc comment.", field.Name)
	}
}

func TestReviewBreakGlass_AlreadyReviewedIsSurfacedAsValidationError(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetBreakGlassActivation", mock.Anything, uint(7)).Return(breakGlassActivationFixture(), nil)
	ms.On("ReviewBreakGlassActivation", mock.Anything, uint(7), uint(99), mock.Anything, mock.Anything).
		Return(storage.ErrBreakGlassAlreadyReviewed)

	c := NewKeyorixCore(ms)
	err := c.ReviewBreakGlass(context.Background(), 99, 1, 7, "trying to review a second time")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already been reviewed")
}

func TestListUnreviewedBreakGlassActivations_PassesCorrectCutoff(t *testing.T) {
	ms := new(MockStorage)
	var gotCutoff time.Time
	ms.On("ListUnreviewedBreakGlassActivationsBefore", mock.Anything, mock.AnythingOfType("time.Time")).
		Run(func(args mock.Arguments) { gotCutoff = args.Get(1).(time.Time) }).
		Return([]*models.BreakGlassActivation{breakGlassActivationFixture()}, nil)

	c := NewKeyorixCore(ms)
	window := 72 * time.Hour
	before := c.now()
	rows, err := c.ListUnreviewedBreakGlassActivations(context.Background(), window)
	require.NoError(t, err)
	assert.Len(t, rows, 1)

	// cutoff must be "now - window", not some other arithmetic.
	assert.WithinDuration(t, before.Add(-window), gotCutoff, time.Second)
}
