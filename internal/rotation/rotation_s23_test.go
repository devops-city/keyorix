//go:build !lean && !noaws && !nogcp

package rotation

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// AWS IAM: nil AccessKeyId on the created key triggers the no-credential guard
// ---------------------------------------------------------------------------

// fakeIAMNilKeyID returns a CreateAccessKey output where the key is non-nil
// but AccessKeyId is nil, exercising the second sub-expression of the nil guard
// at awsiam.go:127.
type fakeIAMNilKeyID struct{}

func (f *fakeIAMNilKeyID) ListAccessKeys(_ context.Context, _ *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	return &iam.ListAccessKeysOutput{}, nil
}
func (f *fakeIAMNilKeyID) CreateAccessKey(_ context.Context, _ *iam.CreateAccessKeyInput, _ ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
	return &iam.CreateAccessKeyOutput{AccessKey: &iamtypes.AccessKey{
		AccessKeyId:     nil,
		SecretAccessKey: aws.String("secret"),
	}}, nil
}
func (f *fakeIAMNilKeyID) DeleteAccessKey(_ context.Context, _ *iam.DeleteAccessKeyInput, _ ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error) {
	return &iam.DeleteAccessKeyOutput{}, nil
}

// TestAWSIAM_S23_CreateReturnsNilKeyID verifies that a CreateAccessKey response
// where the AccessKey is non-nil but AccessKeyId is nil is treated as "no
// credential" and returned as an error.
func TestAWSIAM_S23_CreateReturnsNilKeyID(t *testing.T) {
	e := NewAWSIAMExecutor("aws-s23-nilkeyid", "us-east-1", []string{"svc-"})
	e.newClient = func(context.Context) (iamAPI, error) { return &fakeIAMNilKeyID{}, nil }

	_, err := e.GenerateUpstream(context.Background(), "svc-app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "returned no credential")
}

// ---------------------------------------------------------------------------
// AWS IAM: nil SecretAccessKey on the created key triggers the no-credential guard
// ---------------------------------------------------------------------------

// fakeIAMNilSecret returns a CreateAccessKey output with a valid AccessKeyId
// but nil SecretAccessKey, exercising the third sub-expression of the nil guard.
type fakeIAMNilSecret struct{}

func (f *fakeIAMNilSecret) ListAccessKeys(_ context.Context, _ *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	return &iam.ListAccessKeysOutput{}, nil
}
func (f *fakeIAMNilSecret) CreateAccessKey(_ context.Context, _ *iam.CreateAccessKeyInput, _ ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
	return &iam.CreateAccessKeyOutput{AccessKey: &iamtypes.AccessKey{
		AccessKeyId:     aws.String("AKIAFOO"),
		SecretAccessKey: nil,
	}}, nil
}
func (f *fakeIAMNilSecret) DeleteAccessKey(_ context.Context, _ *iam.DeleteAccessKeyInput, _ ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error) {
	return &iam.DeleteAccessKeyOutput{}, nil
}

// TestAWSIAM_S23_CreateReturnsNilSecret verifies that a CreateAccessKey response
// where AccessKey and AccessKeyId are both non-nil but SecretAccessKey is nil is
// treated as "no credential".
func TestAWSIAM_S23_CreateReturnsNilSecret(t *testing.T) {
	e := NewAWSIAMExecutor("aws-s23-nilsecret", "us-east-1", []string{"svc-"})
	e.newClient = func(context.Context) (iamAPI, error) { return &fakeIAMNilSecret{}, nil }

	_, err := e.GenerateUpstream(context.Background(), "svc-app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "returned no credential")
}

// ---------------------------------------------------------------------------
// AWS IAM: GenerateUpstream with a prior delete that partially fails and
// partially succeeds (two prior keys, one delete succeeds, one fails)
// ---------------------------------------------------------------------------

// fakeIAMPartialCleanup has two prior keys; deleting the first succeeds and
// deleting the second fails, so a PartialRotationError must be returned with
// the first key removed but the second still live.
type fakeIAMPartialCleanup struct {
	deletedIDs []string
}

func (f *fakeIAMPartialCleanup) ListAccessKeys(_ context.Context, in *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	return &iam.ListAccessKeysOutput{
		AccessKeyMetadata: []iamtypes.AccessKeyMetadata{
			{AccessKeyId: aws.String("AKIA_OLD_A"), Status: iamtypes.StatusTypeActive},
			{AccessKeyId: aws.String("AKIA_OLD_B"), Status: iamtypes.StatusTypeActive},
			{AccessKeyId: aws.String("AKIA_OLD_C"), Status: iamtypes.StatusTypeInactive},
		},
	}, nil
}
func (f *fakeIAMPartialCleanup) CreateAccessKey(_ context.Context, _ *iam.CreateAccessKeyInput, _ ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
	return &iam.CreateAccessKeyOutput{AccessKey: &iamtypes.AccessKey{
		AccessKeyId:     aws.String("AKIA_NEW"),
		SecretAccessKey: aws.String("newsecret"),
	}}, nil
}
func (f *fakeIAMPartialCleanup) DeleteAccessKey(_ context.Context, in *iam.DeleteAccessKeyInput, _ ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error) {
	id := aws.ToString(in.AccessKeyId)
	// Allow deleting all except AKIA_OLD_B.
	if id == "AKIA_OLD_B" {
		return nil, errors.New("AccessDenied: cannot delete AKIA_OLD_B")
	}
	f.deletedIDs = append(f.deletedIDs, id)
	return &iam.DeleteAccessKeyOutput{}, nil
}

// TestAWSIAM_S23_ThreeKeysPartialCleanup covers the multi-prior-key path where
// three prior keys exist (two active, one inactive). The inactive key is evicted
// first to free a slot, a new key is created, then the two remaining priors are
// deleted with one failing. A PartialRotationError must be returned.
func TestAWSIAM_S23_ThreeKeysPartialCleanup(t *testing.T) {
	fake := &fakeIAMPartialCleanup{}
	e := NewAWSIAMExecutor("aws-s23-partial3", "us-east-1", []string{"svc-"})
	e.newClient = func(context.Context) (iamAPI, error) { return fake, nil }

	v, err := e.GenerateUpstream(context.Background(), "svc-app")
	require.Error(t, err)

	var partial *PartialRotationError
	require.ErrorAs(t, err, &partial, "must be PartialRotationError when some priors survive")
	assert.Empty(t, v, "value must be empty — it is carried on the error, not returned")
	assert.Contains(t, partial.Value, "AKIA_NEW", "new key ID must be in the preserved value")
	assert.Contains(t, err.Error(), "AKIA_OLD_B", "surviving key must be named in the error")
	assert.Contains(t, fake.deletedIDs, "AKIA_OLD_C", "inactive victim must have been slot-freed")
}

// ---------------------------------------------------------------------------
// AWS IAM: GenerateUpstream ref guards
// ---------------------------------------------------------------------------

// TestAWSIAM_S23_EmptyRefGuard verifies that an empty ref is rejected before
// any AWS call is made.
func TestAWSIAM_S23_EmptyRefGuard(t *testing.T) {
	e := NewAWSIAMExecutor("aws-s23-emptyref", "us-east-1", []string{"svc-"})
	e.newClient = func(context.Context) (iamAPI, error) {
		// Should not be called if the ref guard fires first.
		return nil, errors.New("should not reach client init")
	}
	_, err := e.GenerateUpstream(context.Background(), "")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "should not reach client init",
		"client must not be initialised when ref is empty")
	assert.Contains(t, err.Error(), "required")
}

// TestAWSIAM_S23_NoAllowedRefsGuard verifies that a missing allowed_refs
// config fails closed before any AWS call.
func TestAWSIAM_S23_NoAllowedRefsGuard(t *testing.T) {
	e := NewAWSIAMExecutor("aws-s23-noallowed", "us-east-1", nil)
	e.newClient = func(context.Context) (iamAPI, error) {
		return nil, errors.New("should not reach client init")
	}
	_, err := e.GenerateUpstream(context.Background(), "svc-app")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "should not reach client init")
	assert.Contains(t, err.Error(), "no allowed_refs")
}

// ---------------------------------------------------------------------------
// GCP: GenerateUpstream — at-limit minus one does NOT free a slot
// ---------------------------------------------------------------------------

// fakeGCPNearLimit holds gcpServiceAccountMaxKeys-1 existing keys; since the
// account is one key short of the limit, no slot-freeing delete should be
// issued before creating the new key.
type fakeGCPNearLimit struct {
	existing []string
	deleted  []string
}

func (f *fakeGCPNearLimit) ListKeys(_ context.Context, _ string) ([]gcpServiceAccountKeyInfo, error) {
	keys := make([]gcpServiceAccountKeyInfo, len(f.existing))
	for i, name := range f.existing {
		keys[i] = gcpServiceAccountKeyInfo{Name: name}
	}
	return keys, nil
}
func (f *fakeGCPNearLimit) CreateKey(_ context.Context, _ string) (string, string, error) {
	return "k/NEW", `{"type":"service_account","key":"new"}`, nil
}
func (f *fakeGCPNearLimit) DeleteKey(_ context.Context, kn string) error {
	f.deleted = append(f.deleted, kn)
	return nil
}

// TestGCP_S23_NearLimitNoSlotFree verifies that when the account has
// gcpServiceAccountMaxKeys-1 keys (one below the limit), no slot-freeing
// delete is issued before the create, and all prior keys are cleaned up after.
func TestGCP_S23_NearLimitNoSlotFree(t *testing.T) {
	count := gcpServiceAccountMaxKeys - 1
	existing := make([]string, count)
	for i := range existing {
		existing[i] = "k/OLD"
	}
	fake := &fakeGCPNearLimit{existing: existing}
	e := NewGCPServiceAccountKeyExecutor("gcp-s23-nearlimit", []string{"svc-"})
	e.newClient = func(context.Context) (gcpKeyAPI, error) { return fake, nil }

	v, err := e.GenerateUpstream(context.Background(), "svc-app@p.iam")
	require.NoError(t, err)
	assert.Contains(t, v, "new")
	// All prior keys must be deleted after the create (cleanup phase).
	assert.Len(t, fake.deleted, count, "all %d prior keys must be cleaned up", count)
}

// ---------------------------------------------------------------------------
// GCP: GenerateUpstream — at-limit frees slot then create fails
// ---------------------------------------------------------------------------

// fakeGCPSlotFreeThenCreateErr deletes the slot-free key successfully but
// then fails on CreateKey, so the slot-free delete cost is paid but no new
// key is returned.
type fakeGCPSlotFreeThenCreateErr struct {
	existing []string
	deleted  []string
}

func (f *fakeGCPSlotFreeThenCreateErr) ListKeys(_ context.Context, _ string) ([]gcpServiceAccountKeyInfo, error) {
	keys := make([]gcpServiceAccountKeyInfo, len(f.existing))
	for i, name := range f.existing {
		keys[i] = gcpServiceAccountKeyInfo{Name: name}
	}
	return keys, nil
}
func (f *fakeGCPSlotFreeThenCreateErr) CreateKey(_ context.Context, _ string) (string, string, error) {
	return "", "", errors.New("GCP: quota exceeded")
}
func (f *fakeGCPSlotFreeThenCreateErr) DeleteKey(_ context.Context, kn string) error {
	f.deleted = append(f.deleted, kn)
	return nil
}

// TestGCP_S23_AtLimitCreateFails verifies that when the slot-free delete succeeds
// but CreateKey fails, the error is propagated and includes the backend context.
func TestGCP_S23_AtLimitCreateFails(t *testing.T) {
	existing := make([]string, gcpServiceAccountMaxKeys)
	for i := range existing {
		existing[i] = "k/OLD"
	}
	fake := &fakeGCPSlotFreeThenCreateErr{existing: existing}
	e := NewGCPServiceAccountKeyExecutor("gcp-s23-slotfree-createerr", []string{"svc-"})
	e.newClient = func(context.Context) (gcpKeyAPI, error) { return fake, nil }

	_, err := e.GenerateUpstream(context.Background(), "svc-app@p.iam")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "quota exceeded")
	// The slot-free delete must have been attempted (one key freed before create).
	assert.Len(t, fake.deleted, 1, "one key must be deleted to free the slot")
}

// ---------------------------------------------------------------------------
// Manager: executor returned from Get has correct Type and Name
// ---------------------------------------------------------------------------

// TestManager_S23_GetReturnsCorrectExecutor verifies that the executor returned
// by Get carries the correct Name() and Type() as declared by the implementation.
func TestManager_S23_GetReturnsCorrectExecutor(t *testing.T) {
	e1 := NewPostgresExecutor("pg-backend", "dsn", []string{"role-"})
	e2 := NewMySQLExecutor("mysql-backend", "dsn", []string{"svc-"})
	e3 := NewRedisExecutor("redis-backend", "redis://localhost/0", []string{"cache-"})

	m := NewManager([]Executor{e1, e2, e3})

	got, ok := m.Get("pg-backend")
	require.True(t, ok)
	assert.Equal(t, "pg-backend", got.Name())
	assert.Equal(t, "postgresql", got.Type())

	got, ok = m.Get("mysql-backend")
	require.True(t, ok)
	assert.Equal(t, "mysql-backend", got.Name())
	assert.Equal(t, "mysql", got.Type())

	got, ok = m.Get("redis-backend")
	require.True(t, ok)
	assert.Equal(t, "redis-backend", got.Name())
	assert.Equal(t, "redis", got.Type())
}

// TestManager_S23_GetMissing verifies that Get returns (nil, false) for an
// executor name that was never registered.
func TestManager_S23_GetMissing(t *testing.T) {
	m := NewManager([]Executor{stubExec{name: "present"}})
	got, ok := m.Get("absent")
	assert.False(t, ok)
	assert.Nil(t, got)
}

// TestManager_S23_LastWriterWinsOnNameCollision verifies that when two
// executors share a name, the last one registered wins and Names() still
// lists the name exactly once.
func TestManager_S23_LastWriterWinsOnNameCollision(t *testing.T) {
	first := NewMySQLExecutor("shared", "dsn-first", []string{"a-"})
	second := NewPostgresExecutor("shared", "dsn-second", []string{"b-"})

	m := NewManager([]Executor{first, second})
	assert.ElementsMatch(t, []string{"shared"}, m.Names(),
		"colliding names must be deduplicated to one entry")

	got, ok := m.Get("shared")
	require.True(t, ok)
	// The last-registered executor (Postgres) must win.
	assert.Equal(t, "postgresql", got.Type())
}

// ---------------------------------------------------------------------------
// prefixAllowed: additional edge cases
// ---------------------------------------------------------------------------

// TestPrefixAllowed_S23_ExactMatchIsAllowed verifies that a ref equal to the
// prefix itself (not just starting with it) is permitted.
func TestPrefixAllowed_S23_ExactMatchIsAllowed(t *testing.T) {
	assert.True(t, prefixAllowed([]string{"svc-app"}, "svc-app"),
		"ref equal to the prefix must be allowed")
}

// TestPrefixAllowed_S23_SubstringNotSufficient verifies that a ref that
// CONTAINS the prefix but does not START with it is not permitted.
func TestPrefixAllowed_S23_SubstringNotSufficient(t *testing.T) {
	assert.False(t, prefixAllowed([]string{"svc-"}, "prefix-svc-app"),
		"prefix must match from the start, not just be contained")
}

// TestPrefixAllowed_S23_WhitespacePrefix verifies that a whitespace-only
// prefix does NOT match an arbitrary ref (it is non-empty, so it can match
// only refs that start with whitespace, which are not valid identifiers).
func TestPrefixAllowed_S23_WhitespacePrefix(t *testing.T) {
	assert.False(t, prefixAllowed([]string{" "}, "svc-app"))
	assert.True(t, prefixAllowed([]string{" "}, " svc-app"),
		"a whitespace-prefixed ref must be allowed by a whitespace prefix")
}

// ---------------------------------------------------------------------------
// redactSQLError: backslash in error (not inside a quoted literal) is preserved
// ---------------------------------------------------------------------------

// TestRedactSQLError_S23_BackslashOutsideLiteralPreserved verifies that a
// backslash in an error message that is NOT inside a quoted SQL literal is
// left untouched — only single-quoted literals are redacted.
func TestRedactSQLError_S23_BackslashOutsideLiteralPreserved(t *testing.T) {
	raw := errors.New(`C:\path\error.log: permission denied`)
	wrapped := redactSQLError("postgresql", "role", raw)
	require.Error(t, wrapped)
	assert.Contains(t, wrapped.Error(), `C:\path\error.log`)
}

// TestRedactSQLError_S23_LiteralAfterBackslash verifies that a single-quoted
// SQL literal appearing immediately after a backslash (which is not a SQL
// escape in this context but may appear in a driver error string) is redacted
// as a normal SQL literal.
func TestRedactSQLError_S23_LiteralAfterBackslash(t *testing.T) {
	// The driver error contains a backslash followed by a proper single-quoted
	// SQL literal containing the credential.
	raw := errors.New(`at position: \'secretvalue'`)
	wrapped := redactSQLError("mysql", "user", raw)
	require.Error(t, wrapped)
	// 'secretvalue' is a complete SQL literal; it must be redacted.
	assert.NotContains(t, wrapped.Error(), "secretvalue")
	assert.Contains(t, wrapped.Error(), "'***'")
}

// TestRedactSQLError_S23_PrefixAndSuffixPreserved verifies that the backend name
// and ref always appear in the wrapped error, and that the credential value
// embedded as a quoted literal is redacted.
func TestRedactSQLError_S23_PrefixAndSuffixPreserved(t *testing.T) {
	// Use a credential value that does not overlap with the backend name or ref,
	// so the assertion that it is absent is unambiguous.
	raw := errors.New("authentication failed for user 'xS3cr3tCred!'")
	wrapped := redactSQLError("postgresql", "myapp_role", raw)
	require.Error(t, wrapped)
	assert.Contains(t, wrapped.Error(), "postgresql", "backend name must be in the error")
	assert.Contains(t, wrapped.Error(), "myapp_role", "ref must be in the error")
	// The credential inside the SQL literal must be gone.
	assert.NotContains(t, wrapped.Error(), "xS3cr3tCred!",
		"the literal value inside a SQL literal must be redacted")
	assert.Contains(t, wrapped.Error(), "'***'")
}

// TestRedactSQLError_S23_MultipleLiteralsOnSameLine verifies that when a driver
// error echoes multiple password literals on the same line, every one of them
// is replaced with '***'.
func TestRedactSQLError_S23_MultipleLiteralsOnSameLine(t *testing.T) {
	raw := errors.New("near 'alpha': expected 'beta' or 'gamma'")
	wrapped := redactSQLError("mysql", "role", raw)
	require.Error(t, wrapped)
	assert.NotContains(t, wrapped.Error(), "alpha")
	assert.NotContains(t, wrapped.Error(), "beta")
	assert.NotContains(t, wrapped.Error(), "gamma")
	// Each literal is replaced individually.
	count := 0
	s := wrapped.Error()
	for i := 0; i < len(s)-4; i++ {
		if s[i:i+5] == "'***'" {
			count++
		}
	}
	assert.Equal(t, 3, count, "three distinct literals must each be redacted")
}

// ---------------------------------------------------------------------------
// quoteMySQLString: host-segment escaping
// ---------------------------------------------------------------------------

// TestQuoteMySQLString_S23_AtSignInValue verifies that an '@' in the value
// (not a ref separator) is preserved as-is (it has no special meaning in MySQL
// string literals).
func TestQuoteMySQLString_S23_AtSignInValue(t *testing.T) {
	assert.Equal(t, `'u@dom'`, quoteMySQLString("u@dom"))
}

// TestQuoteMySQLString_S23_NullByte verifies that a null byte embedded in the
// value is preserved (the quoting function must not silently drop characters).
func TestQuoteMySQLString_S23_NullByte(t *testing.T) {
	s := "before\x00after"
	result := quoteMySQLString(s)
	assert.Equal(t, "'before\x00after'", result)
}

// TestQuoteMySQLString_S23_OnlyBackslashes verifies a value consisting only of
// backslashes is doubled correctly.
func TestQuoteMySQLString_S23_OnlyBackslashes(t *testing.T) {
	assert.Equal(t, `'\\\\'`, quoteMySQLString(`\\`))
}

// ---------------------------------------------------------------------------
// MySQL Rotate: ref@host where host itself contains special SQL chars
// ---------------------------------------------------------------------------

// TestMySQL_S23_RotateHostWithSingleQuote verifies that a host component
// containing a single quote is properly escaped in the ALTER USER statement.
func TestMySQL_S23_RotateHostWithSingleQuote(t *testing.T) {
	fake := &fakeMySQL{}
	e := NewMySQLExecutor("my-s23-quotedhost", "dsn", []string{"svc-"})
	e.newConn = func(context.Context, string) (mysqlConn, error) { return fake, nil }

	err := e.Rotate(context.Background(), "svc-app@host'name", "pw")
	require.NoError(t, err)
	// The host part "host'name" must be escaped to "host''name" in the ALTER USER.
	assert.Contains(t, fake.query, `'host''name'`)
}

// TestMySQL_S23_RotateHostWithBackslash verifies that a host component
// containing a backslash is doubled in the ALTER USER statement.
func TestMySQL_S23_RotateHostWithBackslash(t *testing.T) {
	fake := &fakeMySQL{}
	e := NewMySQLExecutor("my-s23-bshost", "dsn", []string{"svc-"})
	e.newConn = func(context.Context, string) (mysqlConn, error) { return fake, nil }

	err := e.Rotate(context.Background(), `svc-app@host\name`, "pw")
	require.NoError(t, err)
	assert.Contains(t, fake.query, `'host\\name'`)
}

// ---------------------------------------------------------------------------
// Postgres Rotate: role name with multiple double-quotes
// ---------------------------------------------------------------------------

// TestPostgres_S23_RotateMultipleDoubleQuotesInRole verifies that a role name
// containing several double-quote characters has each one doubled in the
// quoteIdentifier output, so none can escape the DDL identifier delimiters.
func TestPostgres_S23_RotateMultipleDoubleQuotesInRole(t *testing.T) {
	fake := &fakePG{}
	e := NewPostgresExecutor("pg-s23-multiquote", "dsn", []string{`ro"`})
	e.newConn = func(context.Context, string) (pgConn, error) { return fake, nil }

	// Role: ro"le"name — two embedded double-quotes.
	err := e.Rotate(context.Background(), `ro"le"name`, "pw")
	require.NoError(t, err)
	assert.Equal(t, `ALTER ROLE "ro""le""name" WITH PASSWORD 'pw'`, fake.sql)
}

// ---------------------------------------------------------------------------
// PartialRotationError: equality of Error() and Unwrap() across all three backends
// ---------------------------------------------------------------------------

// TestPartialRotationError_S23_AllBackendMessages verifies that the Error()
// method on a PartialRotationError delegates to Err.Error() regardless of
// which backend produced the message, and that Unwrap() returns the original
// cause for use with errors.Is.
func TestPartialRotationError_S23_AllBackendMessages(t *testing.T) {
	causes := []error{
		errors.New("aws-iam: still live"),
		errors.New("gcp-service-account: still live"),
		errors.New("azure-app: still live"),
	}
	for _, cause := range causes {
		pErr := &PartialRotationError{Value: "cred", Err: cause}
		assert.Equal(t, cause.Error(), pErr.Error(),
			"Error() must return the underlying message for %q", cause)
		assert.True(t, errors.Is(pErr.Unwrap(), cause),
			"Unwrap() must return the exact cause for %q", cause)
	}
}

// ---------------------------------------------------------------------------
// Azure GenerateUpstream: metachar rejection (path/query chars)
// ---------------------------------------------------------------------------

// TestAzure_S23_GenerateUpstream_MetacharRefs verifies that ref values
// containing any of '/', '?', '#', '%' are rejected before reaching the
// Azure client, even if the ref starts with an allowed prefix.
func TestAzure_S23_GenerateUpstream_MetacharRefs(t *testing.T) {
	metacharRefs := []struct {
		ref  string
		desc string
	}{
		{"app-guid/extra", "slash"},
		{"app-guid?q=1", "query"},
		{"app-guid#frag", "fragment"},
		{"app-guid%2F", "percent-encoded"},
	}
	for _, tc := range metacharRefs {
		t.Run(tc.desc, func(t *testing.T) {
			e := NewAzureAppSecretExecutor("azure-s23-"+tc.desc, []string{"app-"})
			e.newClient = func(context.Context) (azureGraphAPI, error) {
				return nil, errors.New("should not reach client init")
			}
			_, err := e.GenerateUpstream(context.Background(), tc.ref)
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "should not reach client init",
				"metachar ref %q must be rejected before client init", tc.ref)
			assert.Contains(t, err.Error(), "invalid application object id")
		})
	}
}

// ---------------------------------------------------------------------------
// GCP GenerateUpstream: metachar rejection
// ---------------------------------------------------------------------------

// TestGCP_S23_GenerateUpstream_MetacharRef verifies that a ref containing a
// percent sign is rejected before the GCP client is initialised, even if the
// ref starts with an allowed prefix.
func TestGCP_S23_GenerateUpstream_MetacharRef(t *testing.T) {
	e := NewGCPServiceAccountKeyExecutor("gcp-s23-metachar", []string{"svc-"})
	e.newClient = func(context.Context) (gcpKeyAPI, error) {
		return nil, errors.New("should not reach client init")
	}
	_, err := e.GenerateUpstream(context.Background(), "svc-app%2F@p.iam")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "should not reach client init")
	assert.Contains(t, err.Error(), "resource path")
}

// ---------------------------------------------------------------------------
// GCP GenerateUpstream: empty ref guard
// ---------------------------------------------------------------------------

// TestGCP_S23_GenerateUpstream_EmptyRef verifies the empty-ref guard in
// GenerateUpstream fires before any client interaction.
func TestGCP_S23_GenerateUpstream_EmptyRef(t *testing.T) {
	e := NewGCPServiceAccountKeyExecutor("gcp-s23-emptyref", []string{"svc-"})
	e.newClient = func(context.Context) (gcpKeyAPI, error) {
		return nil, errors.New("should not reach client init")
	}
	_, err := e.GenerateUpstream(context.Background(), "")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "should not reach client init")
	assert.Contains(t, err.Error(), "required")
}

// ---------------------------------------------------------------------------
// Azure GenerateUpstream: AddPassword error propagation
// ---------------------------------------------------------------------------

// TestAzure_S23_GenerateUpstream_AddError verifies that an AddPassword failure
// surfaces directly as an error (the new secret is not yet minted, so no
// PartialRotationError is appropriate).
func TestAzure_S23_GenerateUpstream_AddError(t *testing.T) {
	fake := &fakeAzure{
		existing: []string{"kid-old"},
		addErr:   errors.New("Forbidden: Application.ReadWrite.OwnedBy required"),
	}
	v, err := azureWith(fake, "app-").GenerateUpstream(context.Background(), "app-guid")
	require.Error(t, err)
	assert.Empty(t, v)
	assert.Contains(t, err.Error(), "Forbidden")
	// The error must not be a PartialRotationError (no value was minted).
	var partial *PartialRotationError
	assert.False(t, errors.As(err, &partial), "AddPassword failure must not produce PartialRotationError")
}

// ---------------------------------------------------------------------------
// Redis Rotate: error message includes backend name and ref
// ---------------------------------------------------------------------------

// TestRedis_S23_RotateErrorContainsContext verifies that when SetUserPassword
// returns an error, the wrapped error carries both the backend name ("redis")
// and the ref so operators can identify which ACL user and backend are involved.
func TestRedis_S23_RotateErrorContainsContext(t *testing.T) {
	e := NewRedisExecutor("redis-s23-ctx", "redis://localhost/0", []string{"svc-"})
	e.newConn = func(context.Context, string) (redisConn, error) {
		return &fakeRedis{err: errors.New("NOPERM no permissions to run the 'acl' command")}, nil
	}
	err := e.Rotate(context.Background(), "svc-myservice", "newpass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redis")
	assert.Contains(t, err.Error(), "svc-myservice")
	assert.Contains(t, err.Error(), "NOPERM")
}

// ---------------------------------------------------------------------------
// MongoDB Rotate: error message includes backend name and ref
// ---------------------------------------------------------------------------

// TestMongo_S23_RotateErrorContainsContext verifies that when UpdateUserPassword
// returns an error, the wrapped error carries both "mongodb" and the ref for
// diagnostics.
func TestMongo_S23_RotateErrorContainsContext(t *testing.T) {
	e := NewMongoExecutor("mongo-s23-ctx", "mongodb://localhost:27017", []string{"svc-"})
	e.newConn = func(context.Context, string) (mongoConn, error) {
		return &fakeMongo{err: errors.New("command updateUser requires authentication")}, nil
	}
	err := e.Rotate(context.Background(), "svc-myuser", "newpass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mongodb")
	assert.Contains(t, err.Error(), "svc-myuser")
	assert.Contains(t, err.Error(), "requires authentication")
}

// ---------------------------------------------------------------------------
// Executor type assertions via Manager
// ---------------------------------------------------------------------------

// TestManager_S23_GeneratingExecutorLookup verifies that when a GeneratingExecutor
// is registered in the Manager and retrieved via Get, it can be type-asserted to
// GeneratingExecutor and its GenerateUpstream is callable.
func TestManager_S23_GeneratingExecutorLookup(t *testing.T) {
	// AWSIAMExecutor implements GeneratingExecutor.
	exec := NewAWSIAMExecutor("cloud-key", "us-east-1", []string{"svc-"})
	exec.newClient = func(ctx context.Context) (iamAPI, error) {
		return &fakeIAM{newID: "AKIAGEN", newSecret: "gen-sec"}, nil
	}

	m := NewManager([]Executor{exec})
	got, ok := m.Get("cloud-key")
	require.True(t, ok)

	ge, ok := got.(GeneratingExecutor)
	require.True(t, ok, "AWSIAMExecutor must be retrievable as GeneratingExecutor")

	val, err := ge.GenerateUpstream(context.Background(), "svc-app")
	require.NoError(t, err)
	assert.Contains(t, val, "AKIAGEN")
}
