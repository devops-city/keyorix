// Package e2e wires vaultsource, plan, report, and target together against a real Vault dev
// server (docker) and an httptest fake Keyorix server — the "real Vault ... plus an httptest
// Keyorix" option docs/design-keyorix-migrate.md's "Testing" section names explicitly, as an
// alternative to a real keyorix-server binary. The fake server implements exactly the wire
// contract internal/target.Client depends on (by-name lookup, get with/without include_value,
// create, update — all under the {"data": ...} envelope every real handler uses), so this
// exercises the real generated apiclient's HTTP encoding/decoding, not just Go-level fakes.
//
// Vault side skips (doesn't fail) without $VAULT_ADDR, matching vaultsource's own integration
// test convention — see vaultsource's vault_integration_test.go doc comment for how to run
// this locally.
package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/migrate/internal/apiclient"
	"github.com/keyorixhq/keyorix/migrate/internal/plan"
	"github.com/keyorixhq/keyorix/migrate/internal/report"
	"github.com/keyorixhq/keyorix/migrate/internal/target"
	"github.com/keyorixhq/keyorix/migrate/internal/vaultsource"
)

// fakeSecret mirrors the wire-relevant subset of internal/storage/models.SecretNode.
type fakeSecret struct {
	ID       int               `json:"ID"`
	Name     string            `json:"Name"`
	Value    string            `json:"-"`
	Metadata map[string]string `json:"Metadata"`
}

// fakeKeyorix is a minimal httptest fake of the four Keyorix REST endpoints
// internal/target.Client calls — same {"data": ...} envelope every real handler
// (sendSuccess, server/http/handlers/helpers.go) uses, and the same "raw SecretNode on GET
// without include_value, {secret,value} with it" shape GetSecret documents.
type fakeKeyorix struct {
	mu      sync.Mutex
	nextID  int
	byID    map[int]*fakeSecret
	callLog []string // records write operations, for the resume test's duplicate check.
}

func newFakeKeyorix() *fakeKeyorix {
	return &fakeKeyorix{byID: map[int]*fakeSecret{}, nextID: 1}
}

func (f *fakeKeyorix) server() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/secrets/by-name", f.handleByName)
	mux.HandleFunc("/api/v1/secrets", f.handleCreate)
	mux.HandleFunc("/api/v1/secrets/", f.handleGetOrUpdate)
	return httptest.NewServer(mux)
}

func (f *fakeKeyorix) handleByName(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.byID {
		if s.Name == name {
			writeEnvelope(w, http.StatusOK, s)
			return
		}
	}
	writeError(w, http.StatusNotFound, "secret not found")
}

func (f *fakeKeyorix) handleCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		Name     string            `json:"name"`
		Value    string            `json:"value"`
		Metadata map[string]string `json:"metadata"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad body")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	s := &fakeSecret{ID: f.nextID, Name: body.Name, Value: body.Value, Metadata: body.Metadata}
	f.byID[f.nextID] = s
	f.nextID++
	f.callLog = append(f.callLog, "create:"+body.Name)
	writeEnvelope(w, http.StatusCreated, s)
}

func (f *fakeKeyorix) handleGetOrUpdate(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/v1/secrets/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad id")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.byID[id]
	if !ok {
		writeError(w, http.StatusNotFound, "secret not found")
		return
	}

	switch r.Method {
	case http.MethodGet:
		if r.URL.Query().Get("include_value") == "true" {
			writeEnvelope(w, http.StatusOK, map[string]any{"secret": s, "value": s.Value})
			return
		}
		writeEnvelope(w, http.StatusOK, s)
	case http.MethodPut:
		var body struct {
			Value *string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "bad body")
			return
		}
		if body.Value != nil {
			s.Value = *body.Value
		}
		f.callLog = append(f.callLog, "update:"+s.Name)
		writeEnvelope(w, http.StatusOK, s)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func writeEnvelope(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": data})
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "message": message, "error": message})
}

func vaultEnv(t *testing.T) (addr, token string) {
	t.Helper()
	addr = os.Getenv("VAULT_ADDR")
	if addr == "" {
		t.Skip("VAULT_ADDR not set — skipping end-to-end test (see vaultsource's vault_integration_test.go to run locally)")
	}
	return addr, os.Getenv("VAULT_TOKEN")
}

func vaultAdminSeed(t *testing.T, addr, token, mount, path, value string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"data": map[string]any{"value": value}})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, addr+"/v1/"+mount+"/data/"+path, strings.NewReader(string(body)))
	req.Header.Set("X-Vault-Token", token)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("seed vault %s: %v", path, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode >= 300 {
		t.Fatalf("seed vault %s: HTTP %d", path, resp.StatusCode)
	}
}

func vaultAdminMount(t *testing.T, addr, token, mount string) {
	t.Helper()
	body := strings.NewReader(`{"type":"kv","options":{"version":"2"}}`)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, addr+"/v1/sys/mounts/"+mount, body)
	req.Header.Set("X-Vault-Token", token)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("mount %s: %v", mount, err)
	}
	defer resp.Body.Close()                               //nolint:errcheck
	if resp.StatusCode >= 300 && resp.StatusCode != 400 { // 400 "already in use" is fine for a re-run.
		t.Fatalf("mount %s: HTTP %d", mount, resp.StatusCode)
	}
}

// buildPlanEntries walks the given Vault mount into plan.Entry values, the same
// path cmd/vault.go's runVault takes (name sanitization, SourceID derivation) — duplicated
// here rather than exported from cmd, since cmd intentionally has no public API (it's a
// cobra command tree, not a library) and this test asserting the end-to-end wire contract
// doesn't need cobra flag parsing at all.
func buildPlanEntries(t *testing.T, addr, token, mount string) []plan.Entry {
	t.Helper()
	vc, err := vaultsource.New(context.Background(), vaultsource.Config{Addr: addr, Mount: mount, Token: token})
	if err != nil {
		t.Fatalf("vaultsource.New: %v", err)
	}
	entries, _, err := vc.Walk(context.Background(), "", false)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	out := make([]plan.Entry, 0, len(entries))
	for _, e := range entries {
		name := sanitize(e.Path)
		if e.Field != "" {
			name = sanitize(e.Path + "-" + e.Field)
		}
		out = append(out, plan.Entry{
			SourceKind: "vault",
			Path:       "vault:" + mount + "/" + e.Path,
			Name:       name,
			Value:      e.Value,
			Metadata:   e.Metadata,
			SourceID:   plan.SourceID(addr, mount, e.Path, orDefault(e.Field, "value")),
		})
	}
	return out
}

func sanitize(s string) string {
	s = strings.NewReplacer("/", "-", "\\", "-", " ", "-", ":", "-").Replace(s)
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	return strings.Trim(s, "-")
}

func orDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// TestEndToEnd_CreateThenIdempotentReRun imports a small Vault tree into the fake Keyorix
// twice: the first run must create every item, the second must skip every item (identical
// value, matching source-id) — the core idempotency contract
// docs/design-keyorix-migrate.md's "Idempotency" and "Resume" sections describe, exercised
// through the real generated apiclient's HTTP wire encoding, not a Go-level fake.
func TestEndToEnd_CreateThenIdempotentReRun(t *testing.T) {
	addr, token := vaultEnv(t)
	mount := "e2e-idempotent"
	vaultAdminMount(t, addr, token, mount)
	vaultAdminSeed(t, addr, token, mount, "svc/one", "value-one-e2e")
	vaultAdminSeed(t, addr, token, mount, "svc/two", "value-two-e2e")

	fk := newFakeKeyorix()
	srv := fk.server()
	defer srv.Close()
	apiClient, err := apiclient.NewClientWithResponses(srv.URL)
	if err != nil {
		t.Fatalf("NewClientWithResponses: %v", err)
	}
	tgt := target.New(apiClient, 1, 1)

	entries := buildPlanEntries(t, addr, token, mount)
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}

	items, err := plan.BuildPlan(context.Background(), tgt, entries)
	if err != nil {
		t.Fatalf("BuildPlan (first run): %v", err)
	}
	for _, item := range items {
		if item.Outcome != plan.Create {
			t.Errorf("first-run outcome for %q = %s, want create", item.Entry.Name, item.Outcome)
		}
	}
	results := plan.Apply(context.Background(), tgt, items, false)
	for _, r := range results {
		if r.Error != "" {
			t.Fatalf("apply error for %q: %s", r.Item.Entry.Name, r.Error)
		}
	}

	// Second run: same entries, same source — must resolve to Skip for both, and must not
	// create any new secret (the fake's ID counter / secret count is the ground truth).
	fk.mu.Lock()
	countAfterFirst := len(fk.byID)
	fk.mu.Unlock()

	items2, err := plan.BuildPlan(context.Background(), tgt, entries)
	if err != nil {
		t.Fatalf("BuildPlan (second run): %v", err)
	}
	for _, item := range items2 {
		if item.Outcome != plan.Skip {
			t.Errorf("second-run outcome for %q = %s, want skip", item.Entry.Name, item.Outcome)
		}
	}
	results2 := plan.Apply(context.Background(), tgt, items2, false)
	for _, r := range results2 {
		if r.Ran {
			t.Errorf("second-run item %q ran, want a no-op skip", r.Item.Entry.Name)
		}
	}

	fk.mu.Lock()
	countAfterSecond := len(fk.byID)
	fk.mu.Unlock()
	if countAfterSecond != countAfterFirst {
		t.Errorf("secret count changed on idempotent re-run: %d -> %d (duplicates created)", countAfterFirst, countAfterSecond)
	}
}

// TestEndToEnd_ResumeAfterPartialApply simulates a kill mid-run: Apply only the first item,
// then rebuild the plan fresh (as a real resumed process would) and apply everything — the
// already-created item must resolve to Skip, not a duplicate Create, and the final secret
// count must equal the source item count exactly.
func TestEndToEnd_ResumeAfterPartialApply(t *testing.T) {
	addr, token := vaultEnv(t)
	mount := "e2e-resume"
	vaultAdminMount(t, addr, token, mount)
	vaultAdminSeed(t, addr, token, mount, "svc/a", "value-a-resume")
	vaultAdminSeed(t, addr, token, mount, "svc/b", "value-b-resume")
	vaultAdminSeed(t, addr, token, mount, "svc/c", "value-c-resume")

	fk := newFakeKeyorix()
	srv := fk.server()
	defer srv.Close()
	apiClient, err := apiclient.NewClientWithResponses(srv.URL)
	if err != nil {
		t.Fatalf("NewClientWithResponses: %v", err)
	}
	tgt := target.New(apiClient, 1, 1)

	entries := buildPlanEntries(t, addr, token, mount)
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}

	items, err := plan.BuildPlan(context.Background(), tgt, entries)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	// Simulate "killed mid-run": apply only the first item, as if the process died before
	// reaching the rest.
	partial := plan.Apply(context.Background(), tgt, items[:1], false)
	if partial[0].Error != "" {
		t.Fatalf("partial apply error: %s", partial[0].Error)
	}

	// Resume: a fresh process re-derives the plan from scratch (no saved state read back —
	// docs/design-keyorix-migrate.md's "Resume" section: this IS the resume mechanism) and
	// applies everything.
	resumedItems, err := plan.BuildPlan(context.Background(), tgt, entries)
	if err != nil {
		t.Fatalf("BuildPlan (resume): %v", err)
	}
	outcomeByName := map[string]plan.Outcome{}
	for _, item := range resumedItems {
		outcomeByName[item.Entry.Name] = item.Outcome
	}
	if outcomeByName[items[0].Entry.Name] != plan.Skip {
		t.Errorf("already-applied item %q resumed as %s, want skip", items[0].Entry.Name, outcomeByName[items[0].Entry.Name])
	}
	for _, item := range items[1:] {
		if outcomeByName[item.Entry.Name] != plan.Create {
			t.Errorf("not-yet-applied item %q resumed as %s, want create", item.Entry.Name, outcomeByName[item.Entry.Name])
		}
	}

	results := plan.Apply(context.Background(), tgt, resumedItems, false)
	for _, r := range results {
		if r.Error != "" {
			t.Fatalf("resume apply error for %q: %s", r.Item.Entry.Name, r.Error)
		}
	}

	fk.mu.Lock()
	finalCount := len(fk.byID)
	fk.mu.Unlock()
	if finalCount != len(entries) {
		t.Errorf("final secret count = %d, want %d (source item count) — resume produced duplicates or lost an item", finalCount, len(entries))
	}
}

// TestEndToEnd_CanaryValueNeverLogged plants a distinctive marker value and asserts it
// appears nowhere in the JSON or human-readable report output — the exact contract
// docs/design-keyorix-migrate.md's "Never log, print, or report a secret value" section
// describes. Covers both a dry-run plan report and an apply report.
func TestEndToEnd_CanaryValueNeverLogged(t *testing.T) {
	addr, token := vaultEnv(t)
	mount := "e2e-canary"
	vaultAdminMount(t, addr, token, mount)
	const canary = "CANARY-VALUE-DO-NOT-LEAK-9f3ae7c2"
	vaultAdminSeed(t, addr, token, mount, "svc/secret-one", canary)

	fk := newFakeKeyorix()
	srv := fk.server()
	defer srv.Close()
	apiClient, err := apiclient.NewClientWithResponses(srv.URL)
	if err != nil {
		t.Fatalf("NewClientWithResponses: %v", err)
	}
	tgt := target.New(apiClient, 1, 1)
	entries := buildPlanEntries(t, addr, token, mount)

	var jsonBuf, humanBuf strings.Builder
	w := report.New(&jsonBuf, &humanBuf)

	items, err := plan.BuildPlan(context.Background(), tgt, entries)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	for _, item := range items {
		if err := w.PlanLine(item); err != nil {
			t.Fatalf("PlanLine: %v", err)
		}
	}
	results := plan.Apply(context.Background(), tgt, items, false)
	for _, res := range results {
		if err := w.ResultLine(res); err != nil {
			t.Fatalf("ResultLine: %v", err)
		}
	}

	if strings.Contains(jsonBuf.String(), canary) {
		t.Errorf("canary value leaked into JSON report: %s", jsonBuf.String())
	}
	if strings.Contains(humanBuf.String(), canary) {
		t.Errorf("canary value leaked into human-readable report: %s", humanBuf.String())
	}

	// Confirm the canary DID make it into the actual secret's value in the fake target —
	// proving the import worked, not that the report is merely (uselessly) empty.
	fk.mu.Lock()
	found := false
	for _, s := range fk.byID {
		if s.Value == canary {
			found = true
		}
	}
	fk.mu.Unlock()
	if !found {
		t.Fatal("canary value was never written to the target — test setup is broken, not proving anything")
	}
}
