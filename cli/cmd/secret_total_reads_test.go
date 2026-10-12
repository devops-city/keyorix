// secret_total_reads_test.go — #2971: `secret get` and `secret versions` show the
// secret's lifetime total_reads (the server's core.SecretTotalReads), next to the
// per-version READS column, which counts only reads charged against max_reads.
package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// totalReadsQueries records the `include` query values of GET /api/v1/secrets/{id}
// requests seen by totalReadsServer.
var totalReadsQueries []string

func totalReadsServer(t *testing.T, routes map[string]string) *httptest.Server {
	t.Helper()
	totalReadsQueries = nil
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/secrets/") && !strings.HasSuffix(r.URL.Path, "/versions") {
			totalReadsQueries = append(totalReadsQueries, r.URL.Query().Get("include"))
		}
		w.Header().Set("Content-Type", "application/json")
		body, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	setPATCreds(t, srv)
	return srv
}

func TestSecretGet_PrintsTotalReads(t *testing.T) {
	t.Run("metadata read by id", func(t *testing.T) {
		totalReadsServer(t, map[string]string{
			"/api/v1/secrets/1": `{"data":{"id":1,"name":"db","type":"generic","status":"active","total_reads":7}}`,
		})
		secretGetID = 1
		defer func() { secretGetID = 0 }()
		out := captureStdout(t, func() {
			if err := runSecretGet(secretGetCmd, nil); err != nil {
				t.Fatalf("runSecretGet: %v", err)
			}
		})
		if !strings.Contains(out, "Total Reads: 7") {
			t.Fatalf("expected 'Total Reads: 7', got: %q", out)
		}
		// total_reads is opt-in on the server; the view that prints it must ask.
		if len(totalReadsQueries) != 1 || totalReadsQueries[0] != "total_reads" {
			t.Fatalf("secret get must send include=total_reads, got include values %q", totalReadsQueries)
		}
	})

	t.Run("value read by id", func(t *testing.T) {
		totalReadsServer(t, map[string]string{
			"/api/v1/secrets/1": `{"data":{"secret":{"id":1,"name":"db","type":"generic","total_reads":3},"value":"v"}}`,
		})
		secretGetID, secretGetShowValue = 1, true
		defer func() { secretGetID, secretGetShowValue = 0, false }()
		out := captureStdout(t, func() {
			if err := runSecretGet(secretGetCmd, nil); err != nil {
				t.Fatalf("runSecretGet: %v", err)
			}
		})
		if !strings.Contains(out, "Total Reads: 3") {
			t.Fatalf("expected 'Total Reads: 3', got: %q", out)
		}
	})

	t.Run("absent when the server omits it", func(t *testing.T) {
		totalReadsServer(t, map[string]string{
			"/api/v1/secrets/1": `{"data":{"id":1,"name":"db","type":"generic","status":"active"}}`,
		})
		secretGetID = 1
		defer func() { secretGetID = 0 }()
		out := captureStdout(t, func() {
			if err := runSecretGet(secretGetCmd, nil); err != nil {
				t.Fatalf("runSecretGet: %v", err)
			}
		})
		if strings.Contains(out, "Total Reads") {
			t.Fatalf("must not print a Total Reads line the server did not send: %q", out)
		}
	})

	t.Run("by name resolves through the list, then reads total_reads by id", func(t *testing.T) {
		totalReadsServer(t, map[string]string{
			"/api/v1/secrets":   `{"data":{"secrets":[{"id":1,"name":"db","type":"generic"}]}}`,
			"/api/v1/secrets/1": `{"data":{"id":1,"name":"db","type":"generic","status":"active","total_reads":5}}`,
		})
		secretGetName, secretGetProject, secretGetEnv = "db", 1, 1
		defer func() { secretGetName, secretGetProject, secretGetEnv = "", 0, 0 }()
		out := captureStdout(t, func() {
			if err := runSecretGet(secretGetCmd, nil); err != nil {
				t.Fatalf("runSecretGet: %v", err)
			}
		})
		if !strings.Contains(out, "Total Reads: 5") {
			t.Fatalf("expected 'Total Reads: 5' for a by-name get, got: %q", out)
		}
		if len(totalReadsQueries) != 1 || totalReadsQueries[0] != "total_reads" {
			t.Fatalf("by-name secret get must send include=total_reads, got include values %q", totalReadsQueries)
		}
	})
}

func TestSecretVersions_PrintsTotalReads(t *testing.T) {
	routes := map[string]string{
		"/api/v1/secrets/1":          `{"data":{"id":1,"name":"db","type":"generic"}}`,
		"/api/v1/secrets/1/versions": `{"data":{"total_reads":9,"versions":[{"id":1,"version_number":1,"read_count":0,"created_at":"2026-10-10T10:00:00Z"}]}}`,
	}

	t.Run("table", func(t *testing.T) {
		totalReadsServer(t, routes)
		secretVersionsID, secretVersionsFormat = 1, "table"
		defer func() { secretVersionsID = 0 }()
		out := captureStdout(t, func() {
			if err := runSecretVersions(secretVersionsCmd, nil); err != nil {
				t.Fatalf("runSecretVersions: %v", err)
			}
		})
		if !strings.Contains(out, "Total Reads: 9") {
			t.Fatalf("expected 'Total Reads: 9', got: %q", out)
		}
	})

	t.Run("json", func(t *testing.T) {
		totalReadsServer(t, routes)
		secretVersionsID, secretVersionsFormat = 1, "json"
		defer func() { secretVersionsID, secretVersionsFormat = 0, "table" }()
		out := captureStdout(t, func() {
			if err := runSecretVersions(secretVersionsCmd, nil); err != nil {
				t.Fatalf("runSecretVersions: %v", err)
			}
		})
		if !strings.Contains(out, `"total_reads": 9`) {
			t.Fatalf(`expected "total_reads": 9 in JSON, got: %q`, out)
		}
	})
}
