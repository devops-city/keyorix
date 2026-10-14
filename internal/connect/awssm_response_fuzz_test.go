//go:build !noaws

package connect

// awssm_response_fuzz_test.go — FuzzAWSSMConnectorResponse fuzzes what a hostile
// or broken AWS Secrets Manager endpoint sends back to
// AWSSecretsManagerConnector.GetSecret.
//
// Existing tests (awssm_test.go, connect_s2*_test.go) inject a hand-written
// smSecretGetter fake operating on already-decoded Go structs -- that bypasses the
// AWS SDK's own JSON wire decode entirely. This target instead builds a REAL
// secretsmanager.Client pointed at an httptest.Server via the SDK's BaseEndpoint
// option (with static, non-functional credentials and retries disabled), injected
// through the existing c.newClient test seam -- no production code change. This
// exercises the actual smithy-go awsJson1_1 protocol decode, not just the
// connector's own post-decode field checks.
import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/internal/netutil"
)

// awsFuzzAccessKeyID/awsFuzzSecretKey are THE static credentials this target's
// client actually sends -- not response-body canaries. Oracle (d) (RULES: "the
// backend auth token/credential the client SENT never appears in errors") is
// about these values, not response content; the fuzzed body is sent to the fake
// server byte-for-byte, unmodified, so the smithy-go JSON decode success path is
// actually reachable by the mutator (an earlier version of this harness prefixed
// a canary directly onto every response body, which corrupted JSON syntax on
// nearly every input and meant the success path was almost never reached).
const (
	awsFuzzAccessKeyID = "AKIAFUZZCANARY7E91XY"
	awsFuzzSecretKey   = "fuzzSecretAccessKeyCanary7e91xyfuzzSecretKey"
)

// awsAccessSecretValueRef is a minimal reference decode of GetSecretValueOutput's
// wire shape (field names/types confirmed against the vendored SDK's
// deserializers.go), used ONLY to derive whether the fuzzed body structurally
// carries a usable secret value -- so oracle (b) can assert the "no value"
// fail-closed path fires whenever it should, not just on a non-2xx status.
type awsAccessSecretValueRef struct {
	SecretString *string `json:"SecretString"`
	SecretBinary []byte  `json:"SecretBinary"`
}

func FuzzAWSSMConnectorResponse(f *testing.F) {
	f.Add(200, []byte(`{"SecretString":"s3cr3t"}`))
	f.Add(200, []byte(`{"SecretBinary":"AAEC"}`))
	f.Add(200, []byte(`{}`))
	f.Add(400, []byte(`{"__type":"ResourceNotFoundException","Message":"Secrets Manager can't find the specified secret."}`))
	f.Add(403, []byte(`{"__type":"AccessDeniedException","Message":"denied"}`))
	f.Add(500, []byte(``))
	f.Add(200, []byte(`not json`))
	f.Add(200, []byte(`{"SecretString":null,"SecretBinary":null}`))
	f.Add(307, []byte(``))
	f.Add(308, []byte(``))
	// status=1200 clamps to code=200 (1200%400==0) AND 1200%3==0 with
	// (1200/3)%2==0, so this seed drives the accountID+matching-ARN branch on
	// a genuine success case; status=1203 (1203%3==0, (1203/3)%2==1) drives
	// the mismatched-account branch. Together they ensure awsRefAccountID
	// (awssm.go) is reached by the seed corpus alone, not only by
	// fuzzer-mutated inputs -- see clampHTTPStatus's own remap arithmetic for
	// why these specific raw values were chosen.
	f.Add(1200, []byte(`{"SecretString":"s3cr3t"}`))
	f.Add(1203, []byte(`{"SecretString":"s3cr3t"}`))

	f.Fuzz(func(t *testing.T, status int, body []byte) {
		code := clampHTTPStatus(status)

		// attacker is a cross-host target for the redirect check below. Its
		// address (127.0.0.1, loopback) is itself a netutil.IsPrivateOrLinkLocal
		// target -- reusing that SAME predicate (not reimplementing an SSRF
		// classification), rather than needing a real non-loopback private IP,
		// to establish "this target is one Keyorix's own SSRF guard elsewhere
		// would refuse to dial."
		var attackerHits atomic.Int32
		var attackerMu sync.Mutex
		var attackerAuthHeader string
		attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attackerHits.Add(1)
			attackerMu.Lock()
			attackerAuthHeader = r.Header.Get("Authorization")
			attackerMu.Unlock()
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"SecretString":"ATTACKER-CONTROLLED"}`))
		}))
		defer attacker.Close()
		if u, uerr := url.Parse(attacker.URL); uerr == nil {
			if host, _, herr := net.SplitHostPort(u.Host); herr == nil {
				if ip := net.ParseIP(host); ip != nil && !netutil.IsPrivateOrLinkLocal(ip) {
					t.Fatalf("test bug: attacker target %q is not classified as private/link-local by netutil -- the redirect check below would be meaningless", attacker.URL)
				}
			}
		}

		var hits atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			// AWS's limitedRedirect (aws/transport/http/client.go) only follows
			// 307/308 -- any other status/Location combination is refused outright
			// by the SDK's own CheckRedirect, so only those two codes are worth
			// testing here.
			if code == http.StatusTemporaryRedirect || code == http.StatusPermanentRedirect {
				w.Header().Set("Location", attacker.URL)
			}
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			w.WriteHeader(code)
			_, _ = w.Write(body)
		}))
		defer srv.Close()

		// MaxAttempts=3 (not 1) so retries actually happen -- oracle (a) below
		// needs a real retry loop to measure. A custom zero-delay Backoff
		// bypasses aws-sdk-go-v2's own ExponentialJitterBackoff, whose
		// throttle-classified path forces a ~1s floor regardless of any
		// configured max -- irrelevant to what's being tested here (whether
		// attempts are BOUNDED, not how long a real backoff would take) and
		// would otherwise make this target too slow to fuzz.
		cl := secretsmanager.New(secretsmanager.Options{
			Region:       "us-east-1",
			Credentials:  credentials.NewStaticCredentialsProvider(awsFuzzAccessKeyID, awsFuzzSecretKey, ""),
			BaseEndpoint: aws.String(srv.URL),
			Retryer: retry.NewStandard(func(o *retry.StandardOptions) {
				o.MaxAttempts = 3
				o.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
			}),
		})

		// For ~1/3 of inputs (derived from the fuzzed status, no extra fuzz
		// parameter needed), configure a non-empty accountID and pass an
		// ARN-shaped ref instead of a bare name, so awsRefAccountID (awssm.go)
		// actually runs -- with a second bit (also derived from status, not a
		// new fuzz parameter) choosing whether the ARN's account segment
		// matches the configured accountID or not, exercising both the
		// early-return-not-ARN-shaped path (the default bare-name case below)
		// and both outcomes of the match comparison at awssm.go's own
		// "refAccount != c.accountID" check.
		smRef := "fuzz/secret"
		accountID := ""
		if status%3 == 0 {
			accountID = "123456789012"
			if (status/3)%2 == 0 {
				smRef = "arn:aws:secretsmanager:us-east-1:123456789012:secret:fuzz/secret-AbCdEf"
			} else {
				smRef = "arn:aws:secretsmanager:us-east-1:999999999999:secret:fuzz/secret-AbCdEf"
			}
		}

		c := NewAWSSecretsManagerConnector("fuzz", "us-east-1", accountID, nil)
		c.newClient = func(_ context.Context, _ string) (smSecretGetter, error) { return cl, nil }

		var val string
		var err error
		fuzzutil.Guard(t.Fatalf, "AWSSecretsManagerConnector.GetSecret", func() {
			val, err = c.GetSecret(context.Background(), smRef)
		})
		// Oracle (b): fail-closed, two ways --
		//  1. the smithy-go awsJson1_1 deserializer routes any response outside
		//     [200,300) to the error deserializer -- GetSecret must therefore
		//     error, never return a value, on such a status.
		//  2. a 2xx response that structurally carries neither a non-empty
		//     SecretString nor a non-empty SecretBinary must ALSO error --
		//     matches awssm.go's own explicit "secret %q has no value"
		//     fallback. Non-empty, not just non-nil: a body like
		//     {"SecretString":""} decodes to a non-nil pointer to "", which is
		//     not a real secret value either (awssm.go's own check, and the
		//     reason this reference must mirror it -- see
		//     docs/findings/2026-09-20-FINDING-awssm-empty-secret-response.md).
		if (code < 200 || code >= 300) && err == nil {
			t.Fatalf("BYPASS: status %d outside [200,300) treated as success, returned value %q", code, val)
		}
		// Decoded with json.NewDecoder(...).Decode, not json.Unmarshal: the two
		// disagree on trailing bytes after the first JSON value, and this
		// reference decode must match what the SDK actually does, not what a
		// strict decoder would do. Confirmed by reading the vendored SDK
		// directly -- (*awsAwsjson11_deserializeOpGetSecretValue).HandleDeserialize
		// (github.com/aws/aws-sdk-go-v2/service/secretsmanager@v1.49.0/deserializers.go,
		// ~line 1063) builds `decoder := json.NewDecoder(body)` and calls
		// `decoder.Decode(&shape)` exactly once: it decodes the first JSON value
		// and never checks for (or rejects) anything left in the stream after
		// it. json.Unmarshal, by contrast, errors on any trailing non-whitespace
		// byte -- so a body like `{"SecretBinary":"0000"}0` decodes successfully
		// under the SDK's own decoder (GetSecret correctly returns a value) but
		// was previously reported as "no value" by this reference decode, a
		// false positive on oracle (b), not a real bypass.
		var ref awsAccessSecretValueRef
		hasValue := json.NewDecoder(bytes.NewReader(body)).Decode(&ref) == nil &&
			((ref.SecretString != nil && *ref.SecretString != "") || len(ref.SecretBinary) > 0)
		if code >= 200 && code < 300 && !hasValue && err == nil {
			t.Fatalf("BYPASS: response has no non-empty SecretString/SecretBinary field but GetSecret returned success with value %q", val)
		}

		// Oracle (d): no credential echo. The access key ID the connector actually
		// sent (in the SigV4 Authorization header) must never appear in a
		// returned error.
		if err != nil && strings.Contains(err.Error(), awsFuzzAccessKeyID) {
			t.Fatalf("LEAK: the connector's own AWS access key ID appeared in a returned error: %v", err)
		}

		// Oracle (a): bounded work, retries. MaxAttempts=3 is configured above --
		// the fake server must never see more than that, regardless of the
		// fuzzed status (whatever the SDK's own retry classifier decides is
		// retryable) or a fuzzed Retry-After-shaped header the body might
		// resemble. connectRetryCeiling is a generous margin above the
		// configured bound, not an exact-equality check, so this stays sound
		// even if the classifier's retryable-status set differs from a naive
		// reading of it.
		if h := hits.Load(); h > connectRetryCeiling {
			t.Fatalf("RETRY STORM: fake server hit %d times for a single GetSecret call (MaxAttempts=3 configured)", h)
		}

		// Oracle (redirect): the connector never reaches a cross-host redirect
		// target at all. Confirmed empirically, not merely by reading
		// limitedRedirect's own source: aws-sdk-go-v2's transport/http package
		// doc-comments its BuildableClient.Do as "Redirect (3xx) responses will
		// not be followed, the HTTP response received will [be] returned
		// instead" -- and a live run against this exact client construction
		// path (the same one awssm.go's own default client() method uses)
		// confirms it: for both 307 and 308 (the only codes limitedRedirect's
		// switch statement would otherwise return nil/"follow" for), the
		// deserializer received the redirect status itself as the FINAL
		// response (attackerHits stayed 0), not the attacker's 200. So unlike
		// the theoretical reading of limitedRedirect in isolation, the real,
		// observed behavior is that this connector never follows a redirect at
		// all -- a genuinely good property, asserted here as a hard regression
		// guard. The credential check is kept as defense-in-depth: if this ever
		// regresses (an SDK update that does start following), the credential
		// must still never reach the attacker.
		if h := attackerHits.Load(); h > 0 {
			attackerMu.Lock()
			gotAuth := attackerAuthHeader
			attackerMu.Unlock()
			if strings.Contains(gotAuth, awsFuzzAccessKeyID) {
				t.Fatalf("LEAK: the connector's own AWS access key ID appeared in the Authorization header sent to a cross-host redirect target: %q", gotAuth)
			}
			t.Fatalf("REDIRECT FOLLOWED: connector reached a cross-host redirect target (attackerHits=%d) -- previously confirmed this never happens via this client construction path", h)
		}

		if n := runtime.NumGoroutine(); n > connectLeakCeiling {
			t.Fatalf("goroutine leak: %d goroutines after AWSSecretsManagerConnector.GetSecret (expected O(10))", n)
		}
		if fd := connectOpenFDCount(); fd > connectLeakCeiling {
			t.Fatalf("fd leak: %d open descriptors after AWSSecretsManagerConnector.GetSecret (expected O(10))", fd)
		}
	})
}
