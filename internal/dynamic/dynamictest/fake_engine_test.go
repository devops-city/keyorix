package dynamictest

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFakeEngine_Issue validates that the FakeEngine records issued roles
// and returns a non-empty credential.
func TestFakeEngine_Issue(t *testing.T) {
	fe := &FakeEngine{}
	cred, role, err := fe.Issue(context.Background(), "dsn", "template", 5*time.Minute)
	require.NoError(t, err)
	assert.NotEmpty(t, role)
	assert.NotEmpty(t, cred.Username)
	assert.NotEmpty(t, cred.Password)
	assert.Len(t, fe.Issued, 1)
	assert.Equal(t, role, fe.Issued[0])
}

// TestFakeEngine_IssueFailure validates that FailIssue causes Issue to error.
func TestFakeEngine_IssueFailure(t *testing.T) {
	fe := &FakeEngine{FailIssue: true}
	_, _, err := fe.Issue(context.Background(), "dsn", "tpl", time.Minute)
	require.Error(t, err)
	assert.Empty(t, fe.Issued)
}

// TestFakeEngine_Revoke validates that the FakeEngine records revoked roles.
func TestFakeEngine_Revoke(t *testing.T) {
	fe := &FakeEngine{}
	err := fe.Revoke(context.Background(), "dsn", "role_abc")
	require.NoError(t, err)
	require.Len(t, fe.Revoked, 1)
	assert.Equal(t, "role_abc", fe.Revoked[0])
}

// TestFakeEngine_RevokeFailure validates that FailRevoke causes Revoke to error.
func TestFakeEngine_RevokeFailure(t *testing.T) {
	fe := &FakeEngine{FailRevoke: true}
	err := fe.Revoke(context.Background(), "dsn", "role_xyz")
	require.Error(t, err)
	assert.Empty(t, fe.Revoked)
}

// TestFakeEngine_Renew validates that the FakeEngine records renewed roles.
func TestFakeEngine_Renew(t *testing.T) {
	fe := &FakeEngine{}
	err := fe.Renew(context.Background(), "dsn", "role_abc", time.Now().Add(time.Hour))
	require.NoError(t, err)
	require.Len(t, fe.Renewed, 1)
	assert.Equal(t, "role_abc", fe.Renewed[0])
}

// TestFakeEngine_RenewFailure validates that FailRenew causes Renew to error.
func TestFakeEngine_RenewFailure(t *testing.T) {
	fe := &FakeEngine{FailRenew: true}
	err := fe.Renew(context.Background(), "dsn", "role_xyz", time.Now().Add(time.Hour))
	require.Error(t, err)
	assert.Empty(t, fe.Renewed)
}

// TestFakeEngine_Metadata validates BackendType, SupportsNativeExpiry, and IsEphemeralBackend.
func TestFakeEngine_Metadata(t *testing.T) {
	fe := &FakeEngine{}
	assert.Equal(t, "fake", fe.BackendType())
	assert.False(t, fe.SupportsNativeExpiry())
	assert.False(t, fe.IsEphemeralBackend())

	fe2 := &FakeEngine{NativeExpiry: true, Ephemeral: true}
	assert.True(t, fe2.SupportsNativeExpiry())
	assert.True(t, fe2.IsEphemeralBackend())
}

// TestFakeEngine_RevokeInvalidatesCredential checks default and override behavior.
func TestFakeEngine_RevokeInvalidatesCredential(t *testing.T) {
	// Non-ephemeral: revoke invalidates (true)
	fe := &FakeEngine{Ephemeral: false}
	assert.True(t, fe.RevokeInvalidatesCredential("any-dsn"))

	// Ephemeral: revoke does NOT invalidate by default (false)
	fe2 := &FakeEngine{Ephemeral: true}
	assert.False(t, fe2.RevokeInvalidatesCredential("any-dsn"))

	// Explicit override via RevokeEffective
	trueVal := true
	fe3 := &FakeEngine{Ephemeral: true, RevokeEffective: &trueVal}
	assert.True(t, fe3.RevokeInvalidatesCredential("any-dsn"))

	falseVal := false
	fe4 := &FakeEngine{Ephemeral: false, RevokeEffective: &falseVal}
	assert.False(t, fe4.RevokeInvalidatesCredential("any-dsn"))
}

// TestFakeEngine_IssueFields validates that IssueFields are returned in the credential.
func TestFakeEngine_IssueFields(t *testing.T) {
	fe := &FakeEngine{
		IssueFields: map[string]string{"access_key_id": "AKID", "secret_access_key": "SAK"},
	}
	cred, _, err := fe.Issue(context.Background(), "dsn", "tpl", time.Minute)
	require.NoError(t, err)
	assert.Equal(t, "AKID", cred.Fields["access_key_id"])
	assert.Equal(t, "SAK", cred.Fields["secret_access_key"])
}

// TestFakeEngine_MultipleConcurrentIssues validates thread-safe issue under the mu lock.
func TestFakeEngine_MultipleConcurrentIssues(t *testing.T) {
	fe := &FakeEngine{}
	const n = 10
	done := make(chan struct{}, n)
	for range n {
		go func() {
			defer func() { done <- struct{}{} }()
			_, _, err := fe.Issue(context.Background(), "dsn", "tpl", time.Minute)
			assert.NoError(t, err)
		}()
	}
	for range n {
		<-done
	}
	fe.mu.Lock()
	assert.Len(t, fe.Issued, n)
	fe.mu.Unlock()
}

// TestRandString_Length validates that randString returns exactly n characters.
func TestRandString_Length(t *testing.T) {
	for _, n := range []int{0, 1, 8, 16, 64} {
		s, err := randString(n)
		require.NoError(t, err)
		assert.Lenf(t, s, n, "randString(%d)", n)
	}
}

// TestRandString_Alphabet validates that randString only uses safe characters.
func TestRandString_Alphabet(t *testing.T) {
	for range 20 {
		s, err := randString(32)
		require.NoError(t, err)
		for _, r := range s {
			ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
			assert.Truef(t, ok, "unexpected character %q in randString output", r)
		}
	}
}
