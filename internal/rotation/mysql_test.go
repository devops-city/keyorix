package rotation

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeMySQL struct {
	query  string
	args   []any
	called bool
	err    error
}

func (f *fakeMySQL) Exec(_ context.Context, q string, args ...any) error {
	f.called = true
	f.query = q
	f.args = args
	return f.err
}
func (f *fakeMySQL) Close() error { return nil }

func myWith(fake *fakeMySQL, allowed ...string) *MySQLExecutor {
	e := NewMySQLExecutor("my", "user:pw@tcp(db:3306)/", allowed)
	e.newConn = func(context.Context, string) (mysqlConn, error) { return fake, nil }
	return e
}

func TestMySQL_TypeAndName(t *testing.T) {
	e := NewMySQLExecutor("prod-my", "dsn", nil)
	assert.Equal(t, "prod-my", e.Name())
	assert.Equal(t, "mysql", e.Type())
}

func TestMySQL_RotateBuildsAlterUser(t *testing.T) {
	fake := &fakeMySQL{}
	// bare user → default host '%'
	require.NoError(t, myWith(fake, "app_").Rotate(context.Background(), "app_svc", "n3wp4ss"))
	assert.True(t, fake.called)
	assert.Equal(t, `ALTER USER 'app_svc'@'%' IDENTIFIED BY ?`, fake.query)
	assert.Equal(t, []any{"n3wp4ss"}, fake.args)
}

func TestMySQL_RotateWithExplicitHost(t *testing.T) {
	fake := &fakeMySQL{}
	require.NoError(t, myWith(fake, "app_").Rotate(context.Background(), "app_svc@10.0.0.5", "pw"))
	assert.Equal(t, `ALTER USER 'app_svc'@'10.0.0.5' IDENTIFIED BY ?`, fake.query)
	assert.Equal(t, []any{"pw"}, fake.args)
}

// A crafted account/password cannot break out: internal quotes and backslashes doubled.
func TestMySQL_RotateEscapesInjection(t *testing.T) {
	fake := &fakeMySQL{}
	require.NoError(t, myWith(fake, "ro").Rotate(context.Background(), `ro'le`, `pa\'ss`))
	// Account names are still quoted (DDL identifiers can't be parameterised);
	// the password is a ? placeholder so no escaping is needed there.
	assert.Equal(t, `ALTER USER 'ro''le'@'%' IDENTIFIED BY ?`, fake.query)
	assert.Equal(t, []any{`pa\'ss`}, fake.args)
}

func TestMySQL_RotateFailsClosedWithoutAllowedRefs(t *testing.T) {
	fake := &fakeMySQL{}
	err := myWith(fake).Rotate(context.Background(), "any", "v") // no allowed_refs
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no allowed_refs")
	assert.False(t, fake.called)
}

// TestMySQL_ConnRealPath_OpenError exercises the sql.Open error branch in
// MySQLExecutor.conn() when newConn is nil. A structurally malformed DSN (missing
// the mandatory slash before the database name) is rejected by the mysql driver's
// DSN parser at Open time, deterministically and without any network I/O.
func TestMySQL_ConnRealPath_OpenError(t *testing.T) {
	e := &MySQLExecutor{
		name:        "mysql-test",
		dsn:         "not a valid dsn",
		allowedRefs: []string{"svc-"},
	}
	c, err := e.conn(context.Background())
	require.Error(t, err)
	assert.Nil(t, c)
	assert.Contains(t, err.Error(), "mysql: open")
}

func TestMySQL_RotateErrors(t *testing.T) {
	t.Run("empty ref", func(t *testing.T) {
		fake := &fakeMySQL{}
		require.Error(t, myWith(fake, "x").Rotate(context.Background(), "", "v"))
		assert.False(t, fake.called)
	})
	t.Run("allowed_refs guardrail", func(t *testing.T) {
		fake := &fakeMySQL{}
		err := myWith(fake, "app_").Rotate(context.Background(), "root", "v")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not permitted")
		assert.False(t, fake.called)
	})
	t.Run("backend error propagates", func(t *testing.T) {
		fake := &fakeMySQL{err: errors.New("access denied")}
		err := myWith(fake, "app_").Rotate(context.Background(), "app_svc", "v")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access denied")
	})
	// #132: mirrors the postgres redaction test — a driver error echoing the
	// failing statement must not leak the new password literal.
	t.Run("backend error echoing the statement is redacted", func(t *testing.T) {
		fake := &fakeMySQL{err: errors.New(`Error 1064: syntax error near 'S3cr3t-Live-Value!'`)}
		err := myWith(fake, "app_").Rotate(context.Background(), "app_svc", "S3cr3t-Live-Value!")
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "S3cr3t-Live-Value!", "the live credential must never appear in the returned error")
		assert.Contains(t, err.Error(), "app_svc")
	})
}
