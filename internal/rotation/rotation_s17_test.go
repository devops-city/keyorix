//go:build !lean && !noaws && !nogcp

package rotation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// evictableAccessKey — uncovered CreateDate branch
// ---------------------------------------------------------------------------

// TestEvictableAccessKey_NilIDs skips keys with nil AccessKeyId.
func TestEvictableAccessKey_NilIDs(t *testing.T) {
	keys := []iamtypes.AccessKeyMetadata{
		{AccessKeyId: nil},
	}
	assert.Equal(t, "", evictableAccessKey(keys))
}

// TestEvictableAccessKey_OlderByCreateDate covers the CreateDate comparison branch:
// all keys are Active but have distinct CreateDate values — the one with the
// earlier date must be selected as the eviction victim.
func TestEvictableAccessKey_OlderByCreateDate(t *testing.T) {
	old := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	keys := []iamtypes.AccessKeyMetadata{
		{AccessKeyId: aws.String("NEWER"), Status: iamtypes.StatusTypeActive, CreateDate: &newer},
		{AccessKeyId: aws.String("OLDER"), Status: iamtypes.StatusTypeActive, CreateDate: &old},
	}
	assert.Equal(t, "OLDER", evictableAccessKey(keys))
}

// TestEvictableAccessKey_NilCreateDate covers the branch where CreateDate is nil:
// the first non-nil ID without a create-date is still assigned as initial victim.
func TestEvictableAccessKey_NilCreateDate(t *testing.T) {
	keys := []iamtypes.AccessKeyMetadata{
		{AccessKeyId: aws.String("NODATEID"), Status: iamtypes.StatusTypeActive, CreateDate: nil},
	}
	// Should be selected as victim (oldest = nil, so first non-nil id wins)
	result := evictableAccessKey(keys)
	assert.Equal(t, "NODATEID", result)
}

// ---------------------------------------------------------------------------
// AWSIAMExecutor — GenerateUpstream: client error path
// ---------------------------------------------------------------------------

func TestAWSIAM_GenerateUpstream_ClientError(t *testing.T) {
	e := NewAWSIAMExecutor("aws-err", "us-east-1", []string{"svc-"})
	e.newClient = func(context.Context) (iamAPI, error) {
		return nil, errors.New("credential chain failed")
	}
	_, err := e.GenerateUpstream(context.Background(), "svc-app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "credential chain failed")
}

// TestAWSIAM_GenerateUpstream_ListError covers the ListAccessKeys error branch.
func TestAWSIAM_GenerateUpstream_ListError(t *testing.T) {
	fake := &listErrIAM{}
	e := NewAWSIAMExecutor("aws-listerr", "us-east-1", []string{"svc-"})
	e.newClient = func(context.Context) (iamAPI, error) { return fake, nil }
	_, err := e.GenerateUpstream(context.Background(), "svc-app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list access keys")
}

type listErrIAM struct{}

func (f *listErrIAM) ListAccessKeys(_ context.Context, _ *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	return nil, errors.New("list failed")
}
func (f *listErrIAM) CreateAccessKey(_ context.Context, _ *iam.CreateAccessKeyInput, _ ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
	return nil, nil
}
func (f *listErrIAM) DeleteAccessKey(_ context.Context, _ *iam.DeleteAccessKeyInput, _ ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error) {
	return nil, nil
}

// TestAWSIAM_GenerateUpstream_CreateReturnsNilKey covers the nil-credential guard.
func TestAWSIAM_GenerateUpstream_CreateReturnsNilKey(t *testing.T) {
	fake := &nilKeyIAM{}
	e := NewAWSIAMExecutor("aws-nilkey", "us-east-1", []string{"svc-"})
	e.newClient = func(context.Context) (iamAPI, error) { return fake, nil }
	_, err := e.GenerateUpstream(context.Background(), "svc-app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "returned no credential")
}

type nilKeyIAM struct{}

func (f *nilKeyIAM) ListAccessKeys(_ context.Context, _ *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	return &iam.ListAccessKeysOutput{}, nil
}
func (f *nilKeyIAM) CreateAccessKey(_ context.Context, _ *iam.CreateAccessKeyInput, _ ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
	// Return output with nil AccessKey — the nil guard must fire.
	return &iam.CreateAccessKeyOutput{AccessKey: nil}, nil
}
func (f *nilKeyIAM) DeleteAccessKey(_ context.Context, _ *iam.DeleteAccessKeyInput, _ ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error) {
	return &iam.DeleteAccessKeyOutput{}, nil
}

// TestAWSIAM_GenerateUpstream_TwoKeys_EvictInactiveThenDeletePrefer confirms that
// an Inactive key at the two-key cap is preferred for eviction (not the oldest).
func TestAWSIAM_GenerateUpstream_TwoKeys_EvictInactive(t *testing.T) {
	old := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	// AKIA2 is Inactive; AKIA1 is Active-older. Eviction should pick AKIA2 (Inactive).
	fake := &fakeIAMWithStatus{
		keys: []iamtypes.AccessKeyMetadata{
			{AccessKeyId: aws.String("AKIA1"), Status: iamtypes.StatusTypeActive, CreateDate: &old},
			{AccessKeyId: aws.String("AKIA2"), Status: iamtypes.StatusTypeInactive, CreateDate: &newer},
		},
		newID:     "AKIANEW",
		newSecret: "s",
	}
	e := NewAWSIAMExecutor("aws-inactive", "us-east-1", []string{"svc-"})
	e.newClient = func(context.Context) (iamAPI, error) { return fake, nil }
	_, err := e.GenerateUpstream(context.Background(), "svc-app")
	require.NoError(t, err)
	// AKIA2 must have been evicted first (to free a slot), then AKIA1 deleted as prior.
	assert.Contains(t, fake.deleted, "AKIA2", "Inactive key must be evicted first")
	assert.Contains(t, fake.deleted, "AKIA1", "remaining prior key must be cleaned up")
}

type fakeIAMWithStatus struct {
	keys      []iamtypes.AccessKeyMetadata
	newID     string
	newSecret string
	deleted   []string
}

func (f *fakeIAMWithStatus) ListAccessKeys(_ context.Context, _ *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	return &iam.ListAccessKeysOutput{AccessKeyMetadata: f.keys}, nil
}
func (f *fakeIAMWithStatus) CreateAccessKey(_ context.Context, in *iam.CreateAccessKeyInput, _ ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
	return &iam.CreateAccessKeyOutput{AccessKey: &iamtypes.AccessKey{
		AccessKeyId: aws.String(f.newID), SecretAccessKey: aws.String(f.newSecret), UserName: in.UserName,
	}}, nil
}
func (f *fakeIAMWithStatus) DeleteAccessKey(_ context.Context, in *iam.DeleteAccessKeyInput, _ ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error) {
	f.deleted = append(f.deleted, aws.ToString(in.AccessKeyId))
	return &iam.DeleteAccessKeyOutput{}, nil
}

// ---------------------------------------------------------------------------
// Azure GenerateUpstream — uncovered branches (extends azure_test.go)
// ---------------------------------------------------------------------------

// fakeAzureRemoveErr is a fakeAzure that also supports RemovePassword errors,
// used for the partial-rotation path not covered by the existing azure_test.go.
type fakeAzureRemoveErr struct {
	fakeAzure
	removeErr error
}

func (f *fakeAzureRemoveErr) RemovePassword(_ context.Context, _, keyID string) error {
	if f.removeErr != nil {
		return f.removeErr
	}
	f.removed = append(f.removed, keyID)
	return nil
}

func azureS17With(fake azureGraphAPI, allowed ...string) *AzureAppSecretExecutor {
	e := NewAzureAppSecretExecutor("azure", allowed)
	e.newClient = func(context.Context) (azureGraphAPI, error) { return fake, nil }
	return e
}

func TestAzureS17_GenerateUpstream_ClientError(t *testing.T) {
	e := NewAzureAppSecretExecutor("azure-err", []string{"app-"})
	e.newClient = func(context.Context) (azureGraphAPI, error) {
		return nil, errors.New("credential error")
	}
	_, err := e.GenerateUpstream(context.Background(), "app-guid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "credential error")
}

func TestAzureS17_GenerateUpstream_ListError(t *testing.T) {
	fake := &fakeAzure{listErr: errors.New("graph list failed")}
	_, err := azureS17With(fake, "app-").GenerateUpstream(context.Background(), "app-guid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list secrets")
}

func TestAzureS17_GenerateUpstream_EmptySecretText(t *testing.T) {
	// fakeAzure with empty newSecret — AddPassword returns "" so the nil-secret guard fires.
	fake := &fakeAzure{newSecret: ""}
	_, err := azureS17With(fake, "app-").GenerateUpstream(context.Background(), "app-guid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "returned no secret text")
}

func TestAzureS17_GenerateUpstream_PartialRotationOnDeleteFailure(t *testing.T) {
	fake := &fakeAzureRemoveErr{
		fakeAzure: fakeAzure{
			existing:  []string{"kid-old"},
			newSecret: "new-secret",
		},
		removeErr: errors.New("permission denied"),
	}
	v, err := azureS17With(fake, "app-").GenerateUpstream(context.Background(), "app-guid")
	require.Error(t, err)
	var partial *PartialRotationError
	require.ErrorAs(t, err, &partial)
	assert.Equal(t, "new-secret", partial.Value)
	assert.Contains(t, err.Error(), "still live")
	assert.Empty(t, v)
}

// ---------------------------------------------------------------------------
// GCP GenerateUpstream — uncovered partial-rotation and error branches
// ---------------------------------------------------------------------------

// fakeGCPDeleteErr extends fakeGCP with a delete error for old keys (but not slot-free).
type fakeGCPDeleteErr struct {
	existing  []string
	newName   string
	newJSON   string
	deleteErr error
	deleted   []string
}

func (f *fakeGCPDeleteErr) ListKeys(_ context.Context, _ string) ([]gcpServiceAccountKeyInfo, error) {
	keys := make([]gcpServiceAccountKeyInfo, len(f.existing))
	for i, name := range f.existing {
		keys[i] = gcpServiceAccountKeyInfo{Name: name}
	}
	return keys, nil
}
func (f *fakeGCPDeleteErr) CreateKey(_ context.Context, saName string) (string, string, error) {
	return f.newName, f.newJSON, nil
}
func (f *fakeGCPDeleteErr) DeleteKey(_ context.Context, keyName string) error {
	f.deleted = append(f.deleted, keyName)
	return f.deleteErr
}

func gcpWithFake(fake gcpKeyAPI, allowed ...string) *GCPServiceAccountKeyExecutor {
	e := NewGCPServiceAccountKeyExecutor("gcp", allowed)
	e.newClient = func(context.Context) (gcpKeyAPI, error) { return fake, nil }
	return e
}

func TestGCP_GenerateUpstream_PartialRotationOnDeleteFailure(t *testing.T) {
	fake := &fakeGCPDeleteErr{
		existing:  []string{"k/OLD1"},
		newName:   "k/NEW",
		newJSON:   `{"k":"v"}`,
		deleteErr: errors.New("permission denied"),
	}
	v, err := gcpWithFake(fake, "svc-").GenerateUpstream(context.Background(), "svc-app@p.iam")
	require.Error(t, err)
	var partial *PartialRotationError
	require.ErrorAs(t, err, &partial)
	assert.Equal(t, `{"k":"v"}`, partial.Value)
	assert.Contains(t, err.Error(), "still live")
	assert.Empty(t, v)
}

func TestGCP_GenerateUpstream_ClientError(t *testing.T) {
	e := NewGCPServiceAccountKeyExecutor("gcp-err", []string{"svc-"})
	e.newClient = func(context.Context) (gcpKeyAPI, error) {
		return nil, errors.New("gcp credential error")
	}
	_, err := e.GenerateUpstream(context.Background(), "svc-app@p.iam")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gcp credential error")
}

func TestGCP_GenerateUpstream_ListError(t *testing.T) {
	e := NewGCPServiceAccountKeyExecutor("gcp-listerr", []string{"svc-"})
	e.newClient = func(context.Context) (gcpKeyAPI, error) {
		return &listErrGCP{}, nil
	}
	_, err := e.GenerateUpstream(context.Background(), "svc-app@p.iam")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list keys")
}

type listErrGCP struct{}

func (f *listErrGCP) ListKeys(_ context.Context, _ string) ([]gcpServiceAccountKeyInfo, error) {
	return nil, errors.New("list failed")
}
func (f *listErrGCP) CreateKey(_ context.Context, _ string) (string, string, error) {
	return "k/NEW", `{"k":"v"}`, nil
}
func (f *listErrGCP) DeleteKey(_ context.Context, _ string) error { return nil }

func TestGCP_GenerateUpstream_EmptyKeyJSON(t *testing.T) {
	e := NewGCPServiceAccountKeyExecutor("gcp-emptykey", []string{"svc-"})
	e.newClient = func(context.Context) (gcpKeyAPI, error) {
		return &emptyKeyGCP{}, nil
	}
	_, err := e.GenerateUpstream(context.Background(), "svc-app@p.iam")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no key material")
}

type emptyKeyGCP struct{}

func (f *emptyKeyGCP) ListKeys(_ context.Context, _ string) ([]gcpServiceAccountKeyInfo, error) {
	return nil, nil
}
func (f *emptyKeyGCP) CreateKey(_ context.Context, _ string) (string, string, error) {
	return "k/NEW", "", nil // empty keyJSON triggers the guard
}
func (f *emptyKeyGCP) DeleteKey(_ context.Context, _ string) error { return nil }

func TestGCP_GenerateUpstream_FreesSlot_DeleteFails(t *testing.T) {
	// At max keys, the slot-free delete fails — error must propagate.
	existing := make([]string, gcpServiceAccountMaxKeys)
	for i := range existing {
		existing[i] = "k/OLD"
	}
	e := NewGCPServiceAccountKeyExecutor("gcp-slotfree", []string{"svc-"})
	e.newClient = func(context.Context) (gcpKeyAPI, error) {
		return &slotFreeErrGCP{existing: existing}, nil
	}
	_, err := e.GenerateUpstream(context.Background(), "svc-app@p.iam")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "free key slot")
}

type slotFreeErrGCP struct{ existing []string }

func (f *slotFreeErrGCP) ListKeys(_ context.Context, _ string) ([]gcpServiceAccountKeyInfo, error) {
	keys := make([]gcpServiceAccountKeyInfo, len(f.existing))
	for i, name := range f.existing {
		keys[i] = gcpServiceAccountKeyInfo{Name: name}
	}
	return keys, nil
}
func (f *slotFreeErrGCP) CreateKey(_ context.Context, _ string) (string, string, error) {
	return "k/NEW", `{"k":"v"}`, nil
}
func (f *slotFreeErrGCP) DeleteKey(_ context.Context, _ string) error {
	return errors.New("permission denied")
}

// ---------------------------------------------------------------------------
// Redis Rotate — SetUserPassword error path
// ---------------------------------------------------------------------------

// fakeRedisConn is a fake redisConn.
type fakeRedisConn struct {
	setErr error
}

func (f *fakeRedisConn) SetUserPassword(_ context.Context, _, _ string) error {
	return f.setErr
}
func (f *fakeRedisConn) Close() error { return nil }

func TestRedisExecutor_RotateSetUserPasswordError(t *testing.T) {
	e := NewRedisExecutor("redis-seterr", "redis://localhost:6379/0", []string{"svc-"})
	e.newConn = func(context.Context, string) (redisConn, error) {
		return &fakeRedisConn{setErr: errors.New("WRONGPASS")}, nil
	}
	err := e.Rotate(context.Background(), "svc-app", "newpass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "WRONGPASS")
}

func TestRedisExecutor_RotateEmptyRef(t *testing.T) {
	e := NewRedisExecutor("redis-emptyref", "redis://localhost:6379/0", []string{"svc-"})
	err := e.Rotate(context.Background(), "", "newpass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

func TestRedisExecutor_RotateEmptyValue(t *testing.T) {
	e := NewRedisExecutor("redis-emptyval", "redis://localhost:6379/0", []string{"svc-"})
	err := e.Rotate(context.Background(), "svc-app", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

func TestRedisExecutor_RotateNoAllowedRefs(t *testing.T) {
	e := NewRedisExecutor("redis-noallowed", "redis://localhost:6379/0", nil)
	err := e.Rotate(context.Background(), "svc-app", "newpass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no allowed_refs")
}

func TestRedisExecutor_RotateNotPermitted(t *testing.T) {
	e := NewRedisExecutor("redis-notpermit", "redis://localhost:6379/0", []string{"prod-"})
	err := e.Rotate(context.Background(), "dev-app", "newpass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not permitted")
}

// ---------------------------------------------------------------------------
// MongoDB Rotate — UpdateUserPassword error path
// ---------------------------------------------------------------------------

type fakeMongoConn struct {
	updateErr error
}

func (f *fakeMongoConn) UpdateUserPassword(_ context.Context, _, _ string) error {
	return f.updateErr
}
func (f *fakeMongoConn) Close(_ context.Context) {}

func TestMongoExecutor_RotateUpdateError(t *testing.T) {
	e := NewMongoExecutor("mongo-uperr", "mongodb://localhost:27017", []string{"svc-"})
	e.newConn = func(context.Context, string) (mongoConn, error) {
		return &fakeMongoConn{updateErr: errors.New("auth failed")}, nil
	}
	err := e.Rotate(context.Background(), "svc-app", "newpass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth failed")
}

func TestMongoExecutor_RotateEmptyRef(t *testing.T) {
	e := NewMongoExecutor("mongo-emptyref", "mongodb://localhost:27017", []string{"svc-"})
	err := e.Rotate(context.Background(), "", "newpass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

func TestMongoExecutor_RotateEmptyValue(t *testing.T) {
	e := NewMongoExecutor("mongo-emptyval", "mongodb://localhost:27017", []string{"svc-"})
	err := e.Rotate(context.Background(), "svc-app", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

func TestMongoExecutor_RotateNoAllowedRefs(t *testing.T) {
	e := NewMongoExecutor("mongo-noallowed", "mongodb://localhost:27017", nil)
	err := e.Rotate(context.Background(), "svc-app", "newpass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no allowed_refs")
}

func TestMongoExecutor_RotateNotPermitted(t *testing.T) {
	e := NewMongoExecutor("mongo-notpermit", "mongodb://localhost:27017", []string{"prod-"})
	err := e.Rotate(context.Background(), "dev-app", "newpass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not permitted")
}

// ---------------------------------------------------------------------------
// MySQL Rotate — empty ref/value guards and Exec error path
// ---------------------------------------------------------------------------

type fakeMySQLConn struct {
	execErr error
}

func (f *fakeMySQLConn) Exec(_ context.Context, _ string, _ ...any) error {
	return f.execErr
}
func (f *fakeMySQLConn) Close() error { return nil }

func TestMySQLExecutor_RotateEmptyRef(t *testing.T) {
	e := NewMySQLExecutor("mysql-emptyref", "dsn", []string{"svc-"})
	err := e.Rotate(context.Background(), "", "newpass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

func TestMySQLExecutor_RotateEmptyValue(t *testing.T) {
	e := NewMySQLExecutor("mysql-emptyval", "dsn", []string{"svc-"})
	err := e.Rotate(context.Background(), "svc-app", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

func TestMySQLExecutor_RotateNoAllowedRefs(t *testing.T) {
	e := NewMySQLExecutor("mysql-noallowed", "dsn", nil)
	err := e.Rotate(context.Background(), "svc-app", "newpass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no allowed_refs")
}

func TestMySQLExecutor_RotateNotPermitted(t *testing.T) {
	e := NewMySQLExecutor("mysql-notpermit", "dsn", []string{"prod-"})
	err := e.Rotate(context.Background(), "dev-app", "newpass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not permitted")
}

func TestMySQLExecutor_RotateExecError(t *testing.T) {
	e := NewMySQLExecutor("mysql-execerr", "dsn", []string{"svc-"})
	e.newConn = func(context.Context, string) (mysqlConn, error) {
		return &fakeMySQLConn{execErr: errors.New("ERROR 1045 (28000): Access denied")}, nil
	}
	err := e.Rotate(context.Background(), "svc-app", "newpass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Access denied")
}

// TestMySQLExecutor_RotateWithHost covers the user@host ref split path.
func TestMySQLExecutor_RotateWithHost(t *testing.T) {
	e := NewMySQLExecutor("mysql-withhost", "dsn", []string{"svc-"})
	e.newConn = func(context.Context, string) (mysqlConn, error) {
		return &fakeMySQLConn{}, nil // no error → success
	}
	err := e.Rotate(context.Background(), "svc-app@10.0.0.1", "newpass")
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Postgres Rotate — empty ref/value guards and Exec error path
// ---------------------------------------------------------------------------

type fakePgConn struct {
	execErr error
}

func (f *fakePgConn) Exec(_ context.Context, _ string) error {
	return f.execErr
}
func (f *fakePgConn) Close(_ context.Context) {}

func TestPostgresExecutor_RotateEmptyRef(t *testing.T) {
	e := NewPostgresExecutor("pg-emptyref", "dsn", []string{"svc-"})
	err := e.Rotate(context.Background(), "", "newpass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

func TestPostgresExecutor_RotateEmptyValue(t *testing.T) {
	e := NewPostgresExecutor("pg-emptyval", "dsn", []string{"svc-"})
	err := e.Rotate(context.Background(), "svc-app", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

func TestPostgresExecutor_RotateNoAllowedRefs(t *testing.T) {
	e := NewPostgresExecutor("pg-noallowed", "dsn", nil)
	err := e.Rotate(context.Background(), "svc-app", "newpass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no allowed_refs")
}

func TestPostgresExecutor_RotateNotPermitted(t *testing.T) {
	e := NewPostgresExecutor("pg-notpermit", "dsn", []string{"prod-"})
	err := e.Rotate(context.Background(), "dev-app", "newpass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not permitted")
}

func TestPostgresExecutor_RotateExecError(t *testing.T) {
	e := NewPostgresExecutor("pg-execerr", "dsn", []string{"svc-"})
	e.newConn = func(context.Context, string) (pgConn, error) {
		return &fakePgConn{execErr: errors.New("syntax error")}, nil
	}
	err := e.Rotate(context.Background(), "svc-app", "newpass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "syntax error")
}

func TestPostgresExecutor_RotateSuccess(t *testing.T) {
	e := NewPostgresExecutor("pg-ok", "dsn", []string{"svc-"})
	e.newConn = func(context.Context, string) (pgConn, error) {
		return &fakePgConn{}, nil
	}
	err := e.Rotate(context.Background(), "svc-app", "newpass")
	require.NoError(t, err)
}
