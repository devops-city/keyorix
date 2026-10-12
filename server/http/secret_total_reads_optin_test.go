package http

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// countingReadsStorage counts CountSecretReadsBySecretIDs calls: the O(reads)
// query behind total_reads.
type countingReadsStorage struct {
	storage.Storage
	calls atomic.Int64
}

func (s *countingReadsStorage) CountSecretReadsBySecretIDs(ctx context.Context, ids []uint, since time.Time) (map[uint]int, error) {
	s.calls.Add(1)
	return s.Storage.CountSecretReadsBySecretIDs(ctx, ids, since)
}

// total_reads on GET /secrets/{id} is opt-in (include=total_reads): the default
// request must not run the access-log count at all, and the opt-in request must
// return the same figure as before.
func TestSecretGet_TotalReadsIsOptIn(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	var counter *countingReadsStorage
	c := newTestCoreWrapped(t, func(s storage.Storage) storage.Storage {
		counter = &countingReadsStorage{Storage: s}
		return counter
	})
	token := createTestToken(t, c)
	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()

	do := func(method, path, body string) (int, []byte) {
		t.Helper()
		req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := (&http.Client{}).Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp.StatusCode, b
	}

	st, body := do(http.MethodPost, "/api/v1/secrets", `{"name":"opt-in","value":"v1","project_id":1,"environment_id":1,"type":"password"}`)
	require.Equal(t, http.StatusCreated, st, string(body))
	var created struct {
		Data struct {
			ID uint `json:"ID"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &created))
	id := created.Data.ID

	type secretWire struct {
		TotalReads *int64 `json:"total_reads"`
	}
	get := func(query string) (secretWire, secretWire) {
		t.Helper()
		st, body := do(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d%s", id, query), "")
		require.Equal(t, http.StatusOK, st, string(body))
		var out struct {
			Data struct {
				secretWire
				Secret secretWire `json:"secret"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(body, &out))
		return out.Data.secretWire, out.Data.Secret
	}

	// Two value reads so the opt-in figure is non-trivial.
	for i := 1; i <= 2; i++ {
		_, inner := get("?include_value=true&include=total_reads")
		require.NotNil(t, inner.TotalReads)
		assert.Equal(t, int64(i), *inner.TotalReads, "opt-in value read: total includes that read")
	}

	// Default requests (metadata and value): no field, and no count executed.
	counter.calls.Store(0)
	meta, _ := get("")
	assert.Nil(t, meta.TotalReads, "default GET must not carry total_reads")
	_, inner := get("?include_value=true")
	assert.Nil(t, inner.TotalReads, "default value GET must not carry total_reads")
	assert.Zero(t, counter.calls.Load(), "default GET /secrets/{id} must not run the total_reads count")

	// Unknown include tokens do not opt in.
	other, _ := get("?include=something_else")
	assert.Nil(t, other.TotalReads)
	assert.Zero(t, counter.calls.Load())

	// Opt-in (single, comma-separated, repeated): same value as before, one count each.
	for _, q := range []string{"?include=total_reads", "?include=other,total_reads", "?include=other&include=total_reads"} {
		before := counter.calls.Load()
		m, _ := get(q)
		require.NotNil(t, m.TotalReads, q)
		assert.Equal(t, int64(3), *m.TotalReads, "%s: two value reads above plus the default-path value read", q)
		assert.Equal(t, before+1, counter.calls.Load(), "%s: exactly one count", q)
	}
}
