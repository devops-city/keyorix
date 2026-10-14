//go:build !noazure

package connect

// azurekv_response_fuzz_test.go — FuzzAzureKVConnectorResponse fuzzes what a
// hostile or broken Azure Key Vault endpoint sends back to
// AzureKeyVaultConnector.GetSecret.
//
// Existing tests (azurekv_test.go, connect_s2*_test.go) inject a hand-written
// azSecretGetter fake operating on already-decoded Go structs. This target instead
// builds a REAL azsecrets.Client pointed at an httptest.Server, injected through the
// existing c.newClient seam -- no production code change. Two SDK-specific wrinkles
// this needed to account for (both confirmed by reading the vendored SDK source, not
// assumed):
//
//   - azsecrets authenticates via a two-step "challenge" handshake
//     (KeyVaultChallengePolicy): the first request carries no Authorization header;
//     the server must answer 401 + WWW-Authenticate so the client learns the
//     scope/tenant, then retries WITH a bearer token attached. The fake server
//     below implements exactly that handshake (using the SAME shape the SDK's own
//     internal.FakeChallenge test helper produces) and only serves the fuzzed
//     status/body on the SECOND (authenticated) request -- verified against
//     policy_bearer_token.go's handleChallenge, which only re-triggers the
//     challenge flow on a 401 that ALSO carries a WWW-Authenticate header, so a
//     fuzzed 401 on the second response (no such header) cannot loop.
//   - azcore's BearerTokenPolicy refuses to attach a credential to a non-https
//     request by default (checkHTTPSForAuth). The obvious fix -- azcore.ClientOptions'
//     own InsecureAllowCredentialWithHTTP field -- does NOT work here: confirmed by
//     reading azsecrets' NewClient, it builds its OWN internal BearerTokenPolicy via
//     internal.NewKeyVaultChallengePolicy, which constructs a fresh
//     policy.BearerTokenOptions with no AllowHTTP wiring at all -- the top-level
//     ClientOptions field never reaches it, so setting it is a silent no-op (an
//     earlier version of this harness set it and every single execution failed at
//     this gate with a transport error, never reaching the fake server's response
//     logic at all -- caught only by adding a temporary diagnostic log, since none of
//     this harness's oracles are stated in the "must succeed" direction). The actual
//     fix: use a real httptest.NewTLSServer and srv.Client() as the Transport, so the
//     request genuinely is https and the gate passes on its own merits.
//
// Redirect behavior: FIXED as of the hardened-client PR (hardened_client.go's
// refuseRedirect) -- this connector used to follow cross-host 301/302/303/307/308
// redirects and blindly trust the redirected response as the secret value (see
// docs/findings/2026-09-19-FINDING-connect-response-trust-gaps.md §2 for the full
// original repro). Oracle (e) below is the merged regression guard, mirroring
// Vault's own pre-existing oracle (e).
import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// azureFuzzBearerToken is THE bearer token this target's fake credential actually
// sends -- not a response-body canary. Oracle (d) (RULES: "the backend auth
// token/credential the client SENT never appears in errors") is about this
// value, not response content; the fuzzed body is sent to the fake server
// byte-for-byte, unmodified, so azsecrets' JSON decode success path is actually
// reachable by the mutator (an earlier version of this harness prefixed a canary
// directly onto every response body, which corrupted JSON syntax on nearly every
// input and meant the success path was almost never reached).
const azureFuzzBearerToken = "fuzz-bearer-token-canary-c4e8"

// azureSecretValueRef is a minimal reference decode of the Key Vault secret
// bundle's wire shape (field name "value" confirmed against the vendored SDK's
// models_serde.go), used ONLY to derive whether the fuzzed body structurally
// carries a usable secret value -- so oracle (b) can assert the "no value"
// fail-closed path fires whenever it should, not just on a non-200 status.
type azureSecretValueRef struct {
	Value *string `json:"value"`
}

// fuzzAzureCred is a static azcore.TokenCredential -- GetToken always succeeds
// with a fixed token, so the harness exercises the connector's response handling,
// not azidentity's own credential-acquisition logic (out of scope here).
type fuzzAzureCred struct{}

func (fuzzAzureCred) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: azureFuzzBearerToken, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func FuzzAzureKVConnectorResponse(f *testing.F) {
	f.Add(200, []byte(`{"value":"s3cr3t","id":"https://v.vault.azure.net/secrets/db/abc123"}`))
	f.Add(404, []byte(`{"error":{"code":"SecretNotFound","message":"not found"}}`))
	f.Add(403, []byte(`{"error":{"code":"Forbidden","message":"denied"}}`))
	f.Add(500, []byte(``))
	f.Add(200, []byte(`not json`))
	f.Add(200, []byte(`{"value":null}`))
	f.Add(200, []byte(`{"value":""}`))
	f.Add(200, []byte(`{}`))
	f.Add(301, []byte(``))
	f.Add(302, []byte(``))
	f.Add(303, []byte(``))
	f.Add(307, []byte(``))
	f.Add(308, []byte(``))

	f.Fuzz(func(t *testing.T, status int, body []byte) {
		code := clampHTTPStatus(status)

		// attacker is a cross-host redirect target -- non-TLS, "localhost" rather
		// than its natural "127.0.0.1" so it is genuinely cross-host relative to
		// srv's "127.0.0.1" (see the doc comment above: same-IP-different-port is
		// NOT a valid cross-host test, Go's shouldCopyHeaderOnRedirect compares
		// only the port-stripped hostname string). Oracle (e) below doesn't
		// actually depend on this distinction anymore -- refuseRedirect blocks
		// EVERY redirect, same-host or not -- but the genuinely-cross-host setup
		// is kept so this test would still catch a future regression that only
		// reintroduced cross-host-specific following.
		var attackerHits atomic.Int32
		attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			attackerHits.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"value":"ATTACKER-CONTROLLED"}`))
		}))
		defer attacker.Close()
		attackerURL := strings.Replace(attacker.URL, "127.0.0.1", "localhost", 1)

		var hits, challengeHits int32
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") == "" {
				atomic.AddInt32(&challengeHits, 1)
				// Unauthenticated first request: elicit the challenge, same shape
				// azsecrets' own internal.FakeChallenge test helper produces. Not
				// counted as a "hit" for the retry-bounded oracle -- this is the
				// fixed one-time auth handshake, not a retry of the fuzzed response.
				w.Header().Set("WWW-Authenticate", `Bearer authorization="https://fake.local/tenant" resource="https://vault.azure.net"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			atomic.AddInt32(&hits, 1)
			if code >= 300 && code < 400 {
				w.Header().Set("Location", attackerURL)
			}
			w.WriteHeader(code)
			_, _ = w.Write(body)
		}))
		defer srv.Close()

		// MaxRetries=2 (not -1/"one try") with a small positive RetryDelay so
		// oracle (a) below can measure a real retry loop without wall-clock cost.
		// NOT RetryDelay: -1, despite that being policy.RetryOptions' own
		// documented way to request "no delay between retries": confirmed by
		// reading policy_retry.go's calcDelay directly, RetryDelay<0 gets
		// normalized to exactly 0 by setDefaults, and calcDelay's own overflow
		// check (`if delay < factor { delay = math.MaxInt64 }`) has a genuine
		// false-positive there -- 0 is always < factor (>=1), so a deliberately
		// zero delay gets misclassified as an overflow and replaced with
		// approximately MaxInt64, which then clamps down to MaxRetryDelay
		// (60s by default) instead of the intended ~0. This is a real bug in
		// the vendored SDK, not a harness issue (see docs/findings/); confirmed
		// empirically via azcore/log's EventRetryPolicy listener showing
		// "Delay=1m0s" for a RetryDelay:-1 config on the very first retry.
		// Transport: srv.Client()'s own Transport (so the request genuinely trusts
		// srv's self-signed TLS cert, per this file's own doc comment above on
		// why InsecureAllowCredentialWithHTTP alone doesn't work here), wrapped in
		// an *http.Client that ALSO sets CheckRedirect: refuseRedirect -- the
		// actual production function under test (hardened_client.go), not a
		// reimplementation of it, so a regression in refuseRedirect itself is
		// what this oracle would catch.
		cl, err := azsecrets.NewClient(srv.URL, fuzzAzureCred{}, &azsecrets.ClientOptions{
			DisableChallengeResourceVerification: true,
			ClientOptions: azcore.ClientOptions{
				Transport: &http.Client{
					Transport:     srv.Client().Transport,
					CheckRedirect: refuseRedirect,
				},
				Retry: policy.RetryOptions{MaxRetries: 2, RetryDelay: time.Millisecond, MaxRetryDelay: time.Millisecond},
			},
		})
		if err != nil {
			t.Fatalf("unexpected azsecrets.NewClient error: %v", err)
		}

		c := NewAzureKeyVaultConnector("fuzz", srv.URL, nil)
		c.newClient = func(_ context.Context) (azSecretGetter, error) { return cl, nil }

		var val string
		fuzzutil.Guard(t.Fatalf, "AzureKeyVaultConnector.GetSecret", func() {
			val, err = c.GetSecret(context.Background(), "fuzz-secret")
		})

		// Oracle (b): fail-closed, two ways --
		//  1. azsecrets.GetSecret requires EXACTLY 200 (runtime.HasStatusCode(
		//     httpResp, http.StatusOK)) -- any other status must error, never be
		//     treated as a successful read.
		//  2. a 200 response that structurally carries no non-null, non-empty
		//     "value" field must ALSO error -- matches azurekv.go's own explicit
		//     "secret %q has no value" check. Non-empty, not just non-null: a
		//     body like {"value":""} decodes to a non-nil pointer to "", which
		//     is not a real secret value either (the sibling bug this oracle
		//     definition was strengthened for -- see
		//     docs/findings/2026-09-20-FINDING-awssm-empty-secret-response.md).
		if code != http.StatusOK && err == nil {
			t.Fatalf("BYPASS: non-200 status %d treated as success, returned value %q", code, val)
		}
		var ref azureSecretValueRef
		hasValue := json.Unmarshal(body, &ref) == nil && ref.Value != nil && *ref.Value != ""
		if code == http.StatusOK && !hasValue && err == nil {
			t.Fatalf("BYPASS: response has no non-null, non-empty value field but GetSecret returned success with value %q", val)
		}

		// Oracle (d): no credential echo. The bearer token the connector actually
		// sent must never appear in a returned error.
		if err != nil && strings.Contains(err.Error(), azureFuzzBearerToken) {
			t.Fatalf("LEAK: the connector's own bearer token appeared in a returned error: %v", err)
		}

		// Oracle (a): bounded work, retries. MaxRetries=2 is configured above --
		// the authenticated-response path must never be hit more than that,
		// regardless of the fuzzed status. The challenge handshake is a fixed
		// one-time exchange (see handleChallenge's own doc comment on why a
		// fuzzed 401-with-no-WWW-Authenticate on the SECOND request can't
		// re-trigger it) -- it must never repeat either, whatever the fuzzed
		// status/body is.
		if h := atomic.LoadInt32(&hits); h > connectRetryCeiling {
			t.Fatalf("RETRY STORM: authenticated response path hit %d times for a single GetSecret call (MaxRetries=2 configured)", h)
		}
		// NOT "exactly once": as with Vault's mount-info lookup, the initial
		// unauthenticated round trip is a real network call that could itself
		// transiently fail under fuzzing concurrency, making GetSecret return an
		// error before the challenge completes at all -- challengeHits==0 is a
		// legitimate outcome of that path. Only >1 (a genuine repeat) matters.
		if ch := atomic.LoadInt32(&challengeHits); ch > 1 {
			t.Fatalf("RETRY STORM: auth challenge handshake ran %d times for a single GetSecret call (expected at most 1)", ch)
		}

		// Oracle (e): redirect refusal (mirrors Vault's oracle (e)). The
		// connector's client now refuses to follow any redirect (refuseRedirect,
		// hardened_client.go) -- the attacker-controlled Location target must
		// never receive a request. Was previously a confirmed-open gap (see this
		// file's own header comment); now the fix's regression guard.
		if attackerHits.Load() != 0 {
			t.Fatalf("REDIRECT FOLLOWED: connector dialed the redirect target instead of refusing")
		}

		if n := runtime.NumGoroutine(); n > connectLeakCeiling {
			t.Fatalf("goroutine leak: %d goroutines after AzureKeyVaultConnector.GetSecret (expected O(10))", n)
		}
		if fd := connectOpenFDCount(); fd > connectLeakCeiling {
			t.Fatalf("fd leak: %d open descriptors after AzureKeyVaultConnector.GetSecret (expected O(10))", fd)
		}
	})
}
