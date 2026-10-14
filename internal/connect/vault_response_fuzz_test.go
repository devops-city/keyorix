package connect

// vault_response_fuzz_test.go — FuzzVaultConnectorResponse fuzzes what a hostile
// or broken Vault server sends back to VaultConnector.GetSecret. vault.go already
// has extensive example-based coverage (vault_test.go, connect_s2*_test.go) for the
// KV v1/v2 envelope shapes, soft-delete, redirect refusal, and non-200 variety --
// this target mutates the same response surface (status/body) to explore shapes
// those examples don't enumerate, with mechanically-checkable oracles rather than
// example assertions.
//
// The KV mount-version lookup (resolveKVMountVersion, a SEPARATE round trip GetSecret
// makes before the actual secret read) is answered with a canned, always-valid
// response so the fuzzer's mutation budget goes toward the more interesting secret-
// read decode path, not toward incidentally tripping the mount-version lookup's own
// error handling on every input.
import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// vaultFuzzToken is THE connector's actual Vault token for this target -- not a
// response-body canary. Oracle (d) (RULES: "the backend auth token/credential the
// client SENT never appears in errors") is about this value, not response
// content, and deliberately does NOT get mixed into the fuzzed response body:
// an earlier version of this harness prefixed a canary directly onto every
// response body, which corrupted JSON syntax on nearly every input and meant the
// KV v1/v2 decode success path was almost never actually reached by the fuzzer --
// body is sent to the fake server byte-for-byte as the mutator produced it.
const vaultFuzzToken = "fuzz-vault-token-canary-x9k2"

func FuzzVaultConnectorResponse(f *testing.F) {
	f.Add(true, 200, []byte(`{"data":{"data":{"password":"s3cr3t"},"metadata":{"version":2}}}`))
	f.Add(false, 200, []byte(`{"data":{"password":"s3cr3t"}}`))
	f.Add(true, 200, []byte(`{"data":{"data":null,"metadata":{}}}`)) // KV v2 soft-delete
	f.Add(false, 200, []byte(`{"data":{"data":"literal-field-collision","metadata":"also-literal"}}`))
	f.Add(true, 403, []byte(`{"errors":["permission denied"]}`))
	f.Add(true, 500, []byte(``))
	f.Add(true, 200, []byte(`not json`))
	f.Add(true, 200, []byte(`{"data":null}`))
	f.Add(true, 301, []byte(``))
	f.Add(true, 200, []byte(`{"data":{}}`))
	f.Add(false, 80, []byte(`{"dAtA":{}}`)) // non-200 + case-insensitive JSON field match ("dAtA" -> Data)
	// status=1200 clamps to code=200 (1200%400==0) AND 1200%3==0, so this seed
	// drives the second-GetSecret/mount-cache-hit oracle on a genuine success
	// case (see clampHTTPStatus's own remap arithmetic) -- ensures the
	// cache-hit branch (vault.go:169) is reached by the seed corpus alone, not
	// only by fuzzer-mutated inputs.
	f.Add(true, 1200, []byte(`{"data":{"data":{"password":"s3cr3t"},"metadata":{"version":2}}}`))

	f.Fuzz(func(t *testing.T, mountIsV2 bool, status int, body []byte) {
		code := clampHTTPStatus(status)

		var attackerHits atomic.Int32
		attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			attackerHits.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"data":{"password":"ATTACKER-CONTROLLED"}}}`))
		}))
		defer attacker.Close()

		var secretGetHits atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "sys/internal/ui/mounts") {
				v := "1"
				if mountIsV2 {
					v = "2"
				}
				w.WriteHeader(http.StatusOK)
				_, _ = fmt.Fprintf(w, `{"data":{"path":"secret/","options":{"version":%q}}}`, v)
				return
			}
			secretGetHits.Add(1)
			if code >= 300 && code < 400 {
				w.Header().Set("Location", attacker.URL)
			}
			w.WriteHeader(code)
			_, _ = w.Write(body)
		}))
		defer srv.Close()

		c := NewVaultConnector("fuzz", srv.URL, vaultFuzzToken, nil)

		var val string
		var err error
		fuzzutil.Guard(t.Fatalf, "VaultConnector.GetSecret", func() {
			val, err = c.GetSecret(context.Background(), "secret/data/fuzz")
		})
		hitsAfterFirst := secretGetHits.Load()

		// Oracle (b): fail-closed, two ways --
		//  1. vault.go's GetSecret requires EXACTLY 200 (resp.StatusCode !=
		//     http.StatusOK) -- any other status must error, never be treated as a
		//     successful read.
		//  2. a 200 response that structurally has no usable data -- for KV v1: no
		//     "data" envelope at all; for KV v2: "data" present but its own nested
		//     "data" is absent or the literal JSON null (the documented soft-delete
		//     shape) -- must ALSO error. This mirrors vault.go's GetSecret decode
		//     logic exactly (see its own doc comments on KV v1 vs v2 dispatch and
		//     the soft-delete null case), not an independent guess at the shape.
		if code != http.StatusOK && err == nil {
			t.Fatalf("BYPASS: non-200 status %d treated as success, returned value %q", code, val)
		}
		if code == http.StatusOK && err == nil {
			var env struct {
				Data json.RawMessage `json:"data"`
			}
			envOK := json.Unmarshal(body, &env) == nil && len(env.Data) > 0
			hasValue := envOK
			if envOK && mountIsV2 {
				var kv2 struct {
					Data json.RawMessage `json:"data"`
				}
				hasValue = json.Unmarshal(env.Data, &kv2) == nil && len(kv2.Data) > 0 && string(kv2.Data) != "null"
			}
			if !hasValue {
				t.Fatalf("BYPASS: response has no usable data envelope (mountIsV2=%v) but GetSecret returned success with value %q", mountIsV2, val)
			}
		}

		// Oracle (d): no credential echo. The token the connector actually sent
		// must never appear in a returned error.
		if err != nil && strings.Contains(err.Error(), vaultFuzzToken) {
			t.Fatalf("LEAK: the connector's own Vault token appeared in a returned error: %v", err)
		}

		// Oracle (e): redirect refusal. VaultConnector's http.Client always refuses
		// to follow a redirect (CheckRedirect returns http.ErrUseLastResponse) --
		// the attacker-controlled Location target must never receive a request.
		if attackerHits.Load() != 0 {
			t.Fatalf("REDIRECT FOLLOWED: connector dialed the redirect target instead of refusing")
		}

		// Oracle (a): bounded work, retries. VaultConnector has no retry logic at
		// all -- a single c.client.Do(req) call per HTTP round trip -- so the
		// secret-GET path must be hit AT MOST once per GetSecret call, regardless
		// of the fuzzed status/body (no Retry-After header exists in this
		// response shape for Vault to honor or ignore in the first place). NOT
		// "exactly once": the mount-info lookup (a separate, real network round
		// trip GetSecret makes first) can itself transiently fail under fuzzing
		// concurrency (confirmed by a genuine -fuzz run flake: a failing input
		// replayed standalone passed cleanly, consistent with a load-dependent
		// connection failure, not a deterministic bug), which correctly makes
		// GetSecret return an error BEFORE ever attempting the secret-GET
		// request at all -- hits==0 is a legitimate outcome of that path, not a
		// missed attempt. Only hits>1 (an actual repeat) is a real violation.
		if hitsAfterFirst > 1 {
			t.Fatalf("RETRY STORM: secret-GET path hit %d times for a single GetSecret call (VaultConnector has no retry logic; expected at most 1)", hitsAfterFirst)
		}

		// For ~1/3 of inputs (derived from the fuzzed status, no extra fuzz
		// parameter needed), issue a SECOND GetSecret on the SAME connector for
		// the SAME ref. resolveKVMountVersion caches the KV mount version keyed
		// by mount path (vault.go's mountVersions map) after its first,
		// real-round-trip lookup -- a single GetSecret call per fuzz iteration
		// can never exercise the cache-HIT branch (the `for mountPath, version
		// := range c.mountVersions` loop that returns without a network call),
		// only the cache-MISS/populate path. This second call is the one place
		// in this harness that can reach it.
		//
		// Oracle: metamorphic, not a fresh property. The second call hits the
		// identical fake server (same status/body) via the SAME ref, so a
		// correct mount-version cache must make the second call agree with the
		// first on success/failure and, when both succeed, on the decoded
		// value -- if the cache ever bound the second call to a different
		// mount's cached version, KV v1 vs v2 dispatch (GetSecret's own
		// kvVersion branch) decodes the identical body differently and this is
		// exactly the assertion it would violate.
		//
		// NOT asserted when the first call's own error came from the
		// mount-info lookup itself (vault.go's "could not determine KV mount
		// version" wrap): that specific shape means resolveKVMountVersion's
		// real network round trip failed transiently (the same load-dependent
		// flake already documented for oracle (a) above) BEFORE the cache was
		// populated at all -- the second call then does its OWN fresh,
		// independent mount-info round trip (cache still empty) and can
		// legitimately succeed where the first didn't, which is a timing
		// artifact, not a cache-binding bug. Whenever the first call's error
		// (if any) is instead about the secret-GET response itself -- reached
		// only after resolveKVMountVersion already succeeded and the cache was
		// already populated -- the second call's cache-HIT path makes no
		// network call at all and so cannot independently flake; the strict
		// comparison is sound there.
		if status%3 == 0 && !(err != nil && strings.Contains(err.Error(), "could not determine KV mount version")) {
			var val2 string
			var err2 error
			fuzzutil.Guard(t.Fatalf, "VaultConnector.GetSecret (second call, mount-cache path)", func() {
				val2, err2 = c.GetSecret(context.Background(), "secret/data/fuzz")
			})
			hitsAfterSecond := secretGetHits.Load()
			if delta := hitsAfterSecond - hitsAfterFirst; delta > 1 {
				t.Fatalf("RETRY STORM: second GetSecret call (mount-cache path) hit secret-GET %d times, expected at most 1", delta)
			}
			if (err2 == nil) != (err == nil) {
				t.Fatalf("MOUNT CACHE: second GetSecret (cache-hit path) returned a different success/failure outcome than the first for the identical ref+response (val=%q err=%v; val2=%q err2=%v)", val, err, val2, err2)
			}
			if err == nil && val2 != val {
				t.Fatalf("MOUNT CACHE: second GetSecret (cache-hit path) returned a different value than the first for the identical ref+response -- mount-version cache bound to the wrong version (val=%q val2=%q)", val, val2)
			}
			if err2 != nil && strings.Contains(err2.Error(), vaultFuzzToken) {
				t.Fatalf("LEAK: the connector's own Vault token appeared in a returned error (second call): %v", err2)
			}
		}

		if n := runtime.NumGoroutine(); n > connectLeakCeiling {
			t.Fatalf("goroutine leak: %d goroutines after VaultConnector.GetSecret (expected O(10))", n)
		}
		if fd := connectOpenFDCount(); fd > connectLeakCeiling {
			t.Fatalf("fd leak: %d open descriptors after VaultConnector.GetSecret (expected O(10))", fd)
		}
	})
}
