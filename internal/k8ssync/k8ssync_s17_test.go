package k8ssync

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSync_LogsPerTargetErrors exercises the for-loop over res.Errors inside Sync:
// when mappings fail (fetch error), each failure is logged individually.
func TestSync_LogsPerTargetErrors(t *testing.T) {
	f := &fakeFetcher{fail: map[string]bool{"prod/db": true, "prod/api": true}}
	s := newFakeSink()
	e := NewEngine(f, s)

	var logged []string
	logf := func(format string, args ...any) {
		msg := format
		// simple string capture for test assertions
		if len(args) > 0 {
			// use fmt.Sprintf equivalent via the format string directly
			logged = append(logged, format)
		} else {
			logged = append(logged, msg)
		}
	}

	mappings := []SecretMapping{
		{Ref: "prod/db", Namespace: "app", Name: "creds", Key: "DB"},
		{Ref: "prod/api", Namespace: "app", Name: "creds", Key: "API"},
	}
	res := Sync(context.Background(), e, mappings, logf)

	// Both keys fail fetch → one target fails.
	assert.Equal(t, 1, res.Failed)
	// Sync must have logged at least the summary line and the per-error line.
	assert.GreaterOrEqual(t, len(logged), 2, "must log summary + per-error lines")
}

// TestSync_SuccessLogs exercises the happy-path log line in Sync (no error from
// Reconcile, no per-target errors).
func TestSync_SuccessLogs(t *testing.T) {
	f := &fakeFetcher{values: map[string][]byte{"prod/db": []byte("v")}}
	s := newFakeSink()
	e := NewEngine(f, s)

	var logged []string
	logf := func(format string, args ...any) {
		logged = append(logged, format)
	}

	res := Sync(context.Background(), e, []SecretMapping{
		{Ref: "prod/db", Namespace: "app", Name: "creds", Key: "DB"},
	}, logf)

	assert.Equal(t, 1, res.Created)
	require.Len(t, logged, 1, "only the summary line must be logged on success")
	assert.Contains(t, logged[0], "k8s-sync:")
}

// TestValidateMapping_InvalidDNS1123Subdomain exercises the !isDNS1123Subdomain branch
// in validateMapping: a Secret name containing uppercase letters or other invalid chars
// must be rejected with a descriptive error.
func TestValidateMapping_InvalidDNS1123Subdomain(t *testing.T) {
	// All required fields present and valid namespace, but name is not a valid
	// RFC 1123 DNS subdomain (uppercase letters are not allowed).
	m := SecretMapping{
		Ref:       "prod/db",
		Namespace: "default",
		Name:      "InvalidName", // uppercase → not a valid DNS subdomain
		Key:       "DB_PASSWORD",
	}
	err := validateMapping(m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RFC1123 subdomain")
}

// TestValidateMapping_TooLongName exercises isDNS1123Subdomain returning false for
// a name that exceeds 253 characters.
func TestValidateMapping_TooLongName(t *testing.T) {
	longName := ""
	for i := range 26 {
		if i > 0 {
			longName += "."
		}
		longName += "abcdefghij" // 10 chars per segment × 26 = 260 > 253
	}
	m := SecretMapping{
		Ref:       "prod/db",
		Namespace: "default",
		Name:      longName,
		Key:       "DB",
	}
	err := validateMapping(m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RFC1123 subdomain")
}

// TestValidateMapping_AllValid verifies that a fully-valid mapping passes validation.
func TestValidateMapping_AllValid(t *testing.T) {
	m := SecretMapping{
		Ref:       "prod/db",
		Namespace: "default",
		Name:      "my-secret",
		Key:       "DB_PASSWORD",
	}
	assert.NoError(t, validateMapping(m))
}

// TestValidateMapping_EmptyFields exercises the early-return branches for each
// required field being empty.
func TestValidateMapping_EmptyFields(t *testing.T) {
	base := SecretMapping{Ref: "prod/db", Namespace: "default", Name: "creds", Key: "k"}

	cases := []struct {
		name    string
		mutate  func(*SecretMapping)
		wantMsg string
	}{
		{"no ref", func(m *SecretMapping) { m.Ref = "" }, "ref is required"},
		{"no namespace", func(m *SecretMapping) { m.Namespace = "" }, "namespace is required"},
		{"no name", func(m *SecretMapping) { m.Name = "" }, "name is required"},
		{"no key", func(m *SecretMapping) { m.Key = "" }, "key is required"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := base
			c.mutate(&m)
			err := validateMapping(m)
			require.Error(t, err)
			assert.Contains(t, err.Error(), c.wantMsg)
		})
	}
}

// TestValidateMapping_InvalidKey exercises the !isK8sSecretKey branch: a key
// containing a character outside [-._a-zA-Z0-9] (here a slash) must be rejected,
// even when every other field is valid.
func TestValidateMapping_InvalidKey(t *testing.T) {
	m := SecretMapping{
		Ref:       "prod/db",
		Namespace: "default",
		Name:      "my-secret",
		Key:       "not/a/valid/key",
	}
	err := validateMapping(m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid Kubernetes Secret data key")
}

// TestValidateMapping_InvalidNamespace exercises the !isDNS1123Label branch.
func TestValidateMapping_InvalidNamespace(t *testing.T) {
	m := SecretMapping{
		Ref:       "prod/db",
		Namespace: "Invalid-NS", // uppercase → not a valid DNS label
		Name:      "my-secret",
		Key:       "DB",
	}
	err := validateMapping(m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RFC1123 label")
}

// TestSync_ReconcileErrorPath exercises the err != nil branch in Sync by using
// a fetcher that always returns an error, verifying Sync returns the result even
// when per-target failures propagate. (Engine.Reconcile returns nil error but
// populates res.Errors for per-target failures; the error branch here is for
// a complete Reconcile failure which can't be triggered with the current Engine
// implementation — this test instead ensures the res.Errors log loop is covered.)
func TestSync_WithMixedResults(t *testing.T) {
	f := &fakeFetcher{
		values: map[string][]byte{"prod/ok": []byte("v")},
		fail:   map[string]bool{"prod/bad": true},
	}
	s := newFakeSink()
	e := NewEngine(f, s)

	var errorLines int
	logf := func(format string, args ...any) {
		if len(args) > 0 {
			errorLines++
		}
	}

	res := Sync(context.Background(), e, []SecretMapping{
		{Ref: "prod/bad", Namespace: "app", Name: "broken", Key: "K"},
		{Ref: "prod/ok", Namespace: "app", Name: "good", Key: "K"},
	}, logf)

	assert.Equal(t, 1, res.Created)
	assert.Equal(t, 1, res.Failed)
	// The per-error log line must be produced for the failed target.
	assert.GreaterOrEqual(t, errorLines, 1, "per-target error must be logged")
}

// TestSync_ReturnsResult verifies that Sync returns a non-zero Result and calls
// logf when all fetches fail. Engine.Reconcile currently never returns a non-nil
// outer error; this test covers the per-target-error path reachable without
// restructuring the production code.
func TestSync_ReturnsResult(t *testing.T) {
	f := &fakeFetcher{fail: map[string]bool{"ref": true}}
	s := newFakeSink()
	e := NewEngine(f, s)

	called := false
	logf := func(format string, args ...any) { called = true }

	res := Sync(context.Background(), e, []SecretMapping{
		{Ref: "ref", Namespace: "ns", Name: "name", Key: "key"},
	}, logf)

	assert.True(t, called, "logf must be called")
	assert.Equal(t, 1, res.Failed)
}
