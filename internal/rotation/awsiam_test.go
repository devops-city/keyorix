//go:build !lean && !noaws

package rotation

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeIAM struct {
	existing  []string // current access key ids for the user
	newID     string
	newSecret string
	createErr error
	deleteErr error // when set, DeleteAccessKey fails (cleanup-failure path)
	deleted   []string
	createdAs string // username passed to CreateAccessKey
}

func (f *fakeIAM) ListAccessKeys(_ context.Context, in *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	md := make([]iamtypes.AccessKeyMetadata, 0, len(f.existing))
	for _, id := range f.existing {
		md = append(md, iamtypes.AccessKeyMetadata{AccessKeyId: &id, UserName: in.UserName})
	}
	return &iam.ListAccessKeysOutput{AccessKeyMetadata: md}, nil
}

func (f *fakeIAM) CreateAccessKey(_ context.Context, in *iam.CreateAccessKeyInput, _ ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	f.createdAs = aws.ToString(in.UserName)
	return &iam.CreateAccessKeyOutput{AccessKey: &iamtypes.AccessKey{
		AccessKeyId: aws.String(f.newID), SecretAccessKey: aws.String(f.newSecret), UserName: in.UserName,
	}}, nil
}

func (f *fakeIAM) DeleteAccessKey(_ context.Context, in *iam.DeleteAccessKeyInput, _ ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error) {
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	f.deleted = append(f.deleted, aws.ToString(in.AccessKeyId))
	return &iam.DeleteAccessKeyOutput{}, nil
}

func iamWith(fake *fakeIAM, allowed ...string) *AWSIAMExecutor {
	e := NewAWSIAMExecutor("aws", "us-east-1", allowed)
	e.newClient = func(context.Context) (iamAPI, error) { return fake, nil }
	return e
}

// TestAWSIAM_Client_LoadDefaultConfigError exercises the awsconfig.LoadDefaultConfig
// error branch inside AWSIAMExecutor.client() when newClient is nil. Pointing
// AWS_CONFIG_FILE at a directory (rather than a file) makes the SDK's shared-config
// read fail deterministically, without any network I/O or real AWS credentials.
func TestAWSIAM_Client_LoadDefaultConfigError(t *testing.T) {
	t.Setenv("AWS_SDK_LOAD_CONFIG", "1")
	t.Setenv("AWS_CONFIG_FILE", t.TempDir())

	e := NewAWSIAMExecutor("aws-test", "us-east-1", nil)
	// e.newClient is left nil so the real awsconfig.LoadDefaultConfig path runs.
	cl, err := e.client(context.Background())
	require.Error(t, err)
	assert.Nil(t, cl)
	assert.Contains(t, err.Error(), "aws-iam: load config")
}

func TestAWSIAM_TypeAndName(t *testing.T) {
	e := NewAWSIAMExecutor("prod-aws", "", nil)
	assert.Equal(t, "prod-aws", e.Name())
	assert.Equal(t, "aws-iam", e.Type())
}

func TestAWSIAM_RotateNotSupported(t *testing.T) {
	err := iamWith(&fakeIAM{}, "svc-").Rotate(context.Background(), "svc-app", "v")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GenerateUpstream")
}

func TestAWSIAM_GenerateUpstream_NoExistingKeys(t *testing.T) {
	fake := &fakeIAM{newID: "AKIANEW", newSecret: "s3cr3t"}
	v, err := iamWith(fake, "svc-").GenerateUpstream(context.Background(), "svc-app")
	require.NoError(t, err)
	assert.Equal(t, "svc-app", fake.createdAs)
	assert.Empty(t, fake.deleted, "no prior keys to delete")

	var cred map[string]string
	require.NoError(t, json.Unmarshal([]byte(v), &cred))
	assert.Equal(t, "AKIANEW", cred["access_key_id"])
	assert.Equal(t, "s3cr3t", cred["secret_access_key"])
}

func TestAWSIAM_GenerateUpstream_DeletesPriorKeys(t *testing.T) {
	// One prior key → create new, then delete the prior.
	fake := &fakeIAM{existing: []string{"AKIAOLD"}, newID: "AKIANEW", newSecret: "x"}
	_, err := iamWith(fake, "svc-").GenerateUpstream(context.Background(), "svc-app")
	require.NoError(t, err)
	assert.Equal(t, []string{"AKIAOLD"}, fake.deleted)
}

func TestAWSIAM_GenerateUpstream_TwoKeysFreesSlotFirst(t *testing.T) {
	// At the 2-key limit → delete oldest (to make room), create, delete the remaining prior.
	fake := &fakeIAM{existing: []string{"AKIA1", "AKIA2"}, newID: "AKIANEW", newSecret: "x"}
	_, err := iamWith(fake, "svc-").GenerateUpstream(context.Background(), "svc-app")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"AKIA1", "AKIA2"}, fake.deleted, "both prior keys removed; only the new one remains")
}

// TestAWSIAM_GenerateUpstream_PriorDeleteFailureIsSurfaced proves the rotation is
// NOT silently reported as success when a prior (possibly compromised) access key
// cannot be deleted. It must return a *PartialRotationError that still carries the
// new credential (so it can be stored) while surfacing the leftover key.
func TestAWSIAM_GenerateUpstream_PriorDeleteFailureIsSurfaced(t *testing.T) {
	fake := &fakeIAM{existing: []string{"AKIAOLD"}, newID: "AKIANEW", newSecret: "s3cr3t", deleteErr: errors.New("AccessDenied")}
	v, err := iamWith(fake, "svc-").GenerateUpstream(context.Background(), "svc-app")

	require.Error(t, err)
	var partial *PartialRotationError
	require.ErrorAs(t, err, &partial, "a cleanup failure must surface as PartialRotationError, not a clean success")
	assert.Contains(t, err.Error(), "AKIAOLD")
	assert.Contains(t, err.Error(), "still live")
	assert.Empty(t, v, "the value is carried on the error, not the return")

	// The new credential is preserved on the error so the caller can still store it.
	var cred map[string]string
	require.NoError(t, json.Unmarshal([]byte(partial.Value), &cred))
	assert.Equal(t, "AKIANEW", cred["access_key_id"])
	assert.Equal(t, "s3cr3t", cred["secret_access_key"])
}

// TestAWSIAM_GenerateUpstream_EvictionFallbackToFirstPrior exercises the defensive
// `if victim == "" { victim = prior[0] }` fallback in GenerateUpstream: when
// evictableAccessKey returns "" (all its candidate IDs happen to be the empty
// string — a degenerate value AWS should never actually hand back, but one the
// code must not crash on), the caller must still pick a concrete victim to evict
// rather than leaving `victim` empty and calling DeleteAccessKey with a blank id
// silently succeeding against the wrong "nothing".
func TestAWSIAM_GenerateUpstream_EvictionFallbackToFirstPrior(t *testing.T) {
	// Two prior keys, both reporting an empty-string AccessKeyId: evictableAccessKey
	// still treats a non-nil *string as a candidate (only a nil pointer is skipped),
	// so with no Inactive key and no CreateDate ordering it settles on "" as the
	// victim. That drives the fallback: GenerateUpstream must fall back to prior[0]
	// (also "") rather than leaving victim empty and skipping the eviction call.
	fake := &fakeIAM{existing: []string{"", ""}, newID: "AKIANEW", newSecret: "x"}
	v, err := iamWith(fake, "svc-").GenerateUpstream(context.Background(), "svc-app")
	require.NoError(t, err)
	assert.Contains(t, fake.deleted, "", "the fallback victim (prior[0], the empty id) must actually be deleted, not silently skipped")

	var cred map[string]string
	require.NoError(t, json.Unmarshal([]byte(v), &cred))
	assert.Equal(t, "AKIANEW", cred["access_key_id"])
}

func TestAWSIAM_GenerateUpstream_Errors(t *testing.T) {
	t.Run("empty ref", func(t *testing.T) {
		_, err := iamWith(&fakeIAM{}, "svc-").GenerateUpstream(context.Background(), "")
		require.Error(t, err)
	})
	t.Run("fail-closed without allowed_refs", func(t *testing.T) {
		_, err := iamWith(&fakeIAM{}).GenerateUpstream(context.Background(), "svc-app")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no allowed_refs")
	})
	t.Run("allowed_refs guardrail", func(t *testing.T) {
		fake := &fakeIAM{newID: "x", newSecret: "y"}
		_, err := iamWith(fake, "svc-").GenerateUpstream(context.Background(), "root")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not permitted")
		assert.Empty(t, fake.createdAs, "a disallowed ref never reaches AWS")
	})
	t.Run("create error propagates", func(t *testing.T) {
		fake := &fakeIAM{createErr: errors.New("LimitExceeded")}
		_, err := iamWith(fake, "svc-").GenerateUpstream(context.Background(), "svc-app")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "LimitExceeded")
	})
	// TestAWSIAM_GenerateUpstream_Errors/empty credential fields is a regression test
	// (fuzz-confirmed, #2209): CreateAccessKey's response fields are non-nil *string
	// pointers to "" on a degenerate/misbehaving response, which a nil-check alone lets
	// through as a "successful" rotation. Emptiness, not nilness, is what must gate.
	t.Run("empty access key id rejected", func(t *testing.T) {
		fake := &fakeIAM{newID: "", newSecret: "s3cr3t"}
		_, err := iamWith(fake, "svc-").GenerateUpstream(context.Background(), "svc-app")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no credential")
	})
	t.Run("empty secret access key rejected", func(t *testing.T) {
		fake := &fakeIAM{newID: "AKIANEW", newSecret: ""}
		_, err := iamWith(fake, "svc-").GenerateUpstream(context.Background(), "svc-app")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no credential")
	})
}

// NOTE on the g05 concurrency finding: this file used to carry
// TestAWSIAM_GenerateUpstream_ConcurrentSameRef, which reproduced two concurrent
// GenerateUpstream calls for the SAME ref interleaving unsafely, via a private
// per-ref mutex (refLocks) AWSIAMExecutor held internally. That protection has moved:
// it now lives centrally in internal/core/rotation_executor.go's applyBackendRotation
// (rotationBackendLock), the single entry point both the auto-rotation scheduler and
// on-demand rotation go through for EVERY registered backend, not just AWS. Exercising
// AWSIAMExecutor.GenerateUpstream in isolation (as this package's tests do, correctly,
// for everything else) can no longer demonstrate that protection — it was never this
// executor's job to serialize itself once the orchestrator does it centrally. The
// equivalent (and now broader) concurrency proof lives in
// internal/core/rotation_orchestrator_lock_test.go, which exercises the real shared
// entry point instead.
