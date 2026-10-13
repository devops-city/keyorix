// audit_machine_read_actor_test.go — guards #3150: a machine identity's value
// read (GET /secrets/{id}?include_value=true) was audited under actor "unknown"
// with the description "User ci-app read secret ...". The row now carries the
// machine identity (actor_type machine_identity, machine_identity_id) and says
// "Machine identity ci-app read secret ...", and the audit views resolve the
// machine's name via ResolveMachineNames.
package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestLogSecretReadWithProject_MachineReadIsAttributedToMachine(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := NewKeyorixCore(store)
	ctx := WithMachineActor(WithActorType(context.Background(), ActorTypeMachine), 5)

	var got *models.AuditEvent
	store.On("LogAuditEventWithAccessLog", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { got = args.Get(1).(*models.AuditEvent) }).
		Return(nil)

	require.NoError(t, c.LogSecretReadWithProject(ctx, 0, 1, 1, "ci-app", "stripe-api-key", "198.51.100.7", "curl"))

	require.NotNil(t, got)
	assert.Equal(t, "secret.read", got.EventType)
	assert.Equal(t, ActorTypeMachine, got.ActorType)
	require.NotNil(t, got.MachineIdentityID)
	assert.Equal(t, uint(5), *got.MachineIdentityID)
	assert.Nil(t, got.UserID, "a machine's ID must never occupy UserID")
	assert.Equal(t, "Machine identity ci-app read secret stripe-api-key", got.Description)
}

// Positive control: a human read keeps the "User" wording.
func TestLogSecretReadWithProject_HumanReadKeepsUserWording(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := NewKeyorixCore(store)

	var got *models.AuditEvent
	store.On("LogAuditEventWithAccessLog", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { got = args.Get(1).(*models.AuditEvent) }).
		Return(nil)

	require.NoError(t, c.LogSecretReadWithProject(context.Background(), 9, 1, 1, "alice", "stripe-api-key", "198.51.100.7", "curl"))

	require.NotNil(t, got)
	assert.Equal(t, "User alice read secret stripe-api-key", got.Description)
}

func TestResolveMachineNames(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := NewKeyorixCore(store)
	store.On("GetMachineIdentity", mock.Anything, uint(5)).Return(&models.MachineIdentity{ID: 5, Name: "ci-app"}, nil)
	store.On("GetMachineIdentity", mock.Anything, uint(6)).Return((*models.MachineIdentity)(nil), assert.AnError)

	five, six, user := uint(5), uint(6), uint(5)
	names := c.ResolveMachineNames(context.Background(), []*models.AuditEvent{
		{MachineIdentityID: &five},
		{MachineIdentityID: &five},
		{MachineIdentityID: &six},
		{UserID: &user}, // human row: no machine lookup
	})

	assert.Equal(t, map[uint]string{5: "ci-app", 6: "unknown"}, names)
	store.AssertNumberOfCalls(t, "GetMachineIdentity", 2) // 5 is looked up once
}
