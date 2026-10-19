// Command fakevault serves a Vault KV v2 export FILE over the subset of the Vault HTTP API that
// `keyorix-migrate vault` reads (mount-version lookup, KV v2 list, KV v2 data read), so the
// Vault-migration demo runs with no Vault container. DEMO/TEST helper only - not a Vault
// implementation, never part of a shipped binary.
//
//	fakevault -file scripts/demo/fixtures/vault-export.json -addr 127.0.0.1:18200
//
// Fixture format: {"mount":"secret","secrets":{"<path>":{"<field>":"<value>", ...}, ...}}.
// Every request must carry X-Vault-Token equal to $FAKEVAULT_TOKEN (read from the environment,
// never from argv); anything else is a 403, like a real Vault.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

type export struct {
	Mount   string                       `json:"mount"`
	Secrets map[string]map[string]string `json:"secrets"`
}

func main() {
	file := flag.String("file", "", "Vault export fixture (JSON)")
	addr := flag.String("addr", "127.0.0.1:18200", "listen address (loopback only)")
	flag.Parse()
	token := os.Getenv("FAKEVAULT_TOKEN")
	if *file == "" || token == "" {
		fmt.Fprintln(os.Stderr, "fakevault: need -file and FAKEVAULT_TOKEN")
		os.Exit(2)
	}
	raw, err := os.ReadFile(*file) // #nosec G304 -- demo helper, operator-supplied fixture path
	if err != nil {
		fmt.Fprintln(os.Stderr, "fakevault:", err)
		os.Exit(1)
	}
	var ex export
	if err := json.Unmarshal(raw, &ex); err != nil || ex.Mount == "" {
		fmt.Fprintln(os.Stderr, "fakevault: bad fixture:", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != token {
			writeJSON(w, http.StatusForbidden, map[string]any{"errors": []string{"permission denied"}})
			return
		}
		p := strings.TrimPrefix(r.URL.Path, "/v1/")
		switch {
		case strings.HasPrefix(p, "sys/internal/ui/mounts/"):
			writeJSON(w, 200, map[string]any{"data": map[string]any{"path": ex.Mount + "/", "options": map[string]string{"version": "2"}}})
		case strings.HasPrefix(p, ex.Mount+"/metadata/") || p == ex.Mount+"/metadata":
			dir := strings.Trim(strings.TrimPrefix(strings.TrimPrefix(p, ex.Mount+"/metadata"), "/"), "/")
			keys := children(ex.Secrets, dir)
			if len(keys) == 0 {
				writeJSON(w, 404, map[string]any{"errors": []string{}})
				return
			}
			writeJSON(w, 200, map[string]any{"data": map[string]any{"keys": keys}})
		case strings.HasPrefix(p, ex.Mount+"/data/"):
			name := strings.Trim(strings.TrimPrefix(p, ex.Mount+"/data/"), "/")
			fields, ok := ex.Secrets[name]
			if !ok {
				writeJSON(w, 404, map[string]any{"errors": []string{}})
				return
			}
			writeJSON(w, 200, map[string]any{"data": map[string]any{
				"data":     fields,
				"metadata": map[string]any{"version": 1, "created_time": time.Now().UTC().Format(time.RFC3339), "custom_metadata": nil},
			}})
		default:
			writeJSON(w, 404, map[string]any{"errors": []string{}})
		}
	})
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	fmt.Fprintf(os.Stderr, "fakevault: serving %d secret(s) from %s on http://%s\n", len(ex.Secrets), *file, *addr)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, "fakevault:", err)
		os.Exit(1)
	}
}

// children lists the immediate children of dir the way Vault's KV v2 LIST does:
// leaf names plain, sub-folders with a trailing slash.
func children(secrets map[string]map[string]string, dir string) []string {
	prefix := ""
	if dir != "" {
		prefix = dir + "/"
	}
	set := map[string]bool{}
	for path := range secrets {
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		rest := strings.TrimPrefix(path, prefix)
		if i := strings.Index(rest, "/"); i >= 0 {
			set[rest[:i+1]] = true
		} else {
			set[rest] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
