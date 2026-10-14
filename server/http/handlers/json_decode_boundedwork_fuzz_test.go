package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// globalBodyCap mirrors the production default applied by router.go's
// r.Use(customMiddleware.MaxBodyBytes(cfg.Server.HTTP.EffectiveMaxRequestBodyBytes()))
// — a zero-value config means "no override configured", so this calls the exact
// same method production calls and gets the real 10 MiB default, rather than a
// hand-copied constant that could drift from it.
var globalBodyCap = config.ServerInstanceConfig{}.EffectiveMaxRequestBodyBytes()

// cappedRequest reproduces the exact body-wrapping router.go applies to EVERY
// request before any handler ever sees r.Body: middleware.MaxBodyBytes(cap) around
// a plain POST. Returns the *http.Request as the real handler would receive it,
// with r.Body already an http.MaxBytesReader over the fuzzed bytes.
func cappedRequest(cap int64, body []byte) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "http://keyorix.invalid/x", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	var out *http.Request
	middleware.MaxBodyBytes(cap)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		out = r
	})).ServeHTTP(rec, req)
	return out
}

var errMustDecodeBodyFailed = errors.New("mustDecodeBody reported failure")

// jsonDecodeCase drives ONE real handler's decode statement end-to-end: the
// production size-cap middleware chain, then the exact decode call/helper that
// handler uses on its own request-body struct (or map, where that's what the real
// handler decodes into).
type jsonDecodeCase struct {
	name string
	// routeCap is what cappedRequest wraps r.Body in — the cap router.go actually
	// applies to this route (always the global default here; no route in
	// jsonDecodeCases carries its own router-level override).
	routeCap int64
	// boundCap is the TIGHTEST cap boundedWorkLimit should assume for this case.
	// Equal to routeCap for every case except webauthn.FinishWebAuthnLogin, whose
	// OWN decodeJSON helper re-wraps r.Body in a much smaller 64 KiB
	// (maxWebAuthnBody) io.LimitReader independent of the router-level cap. Using
	// routeCap there instead would make the bound so generous (10 MiB-scaled) that
	// a regression removing decodeJSON's inner cap could never trip it — the outer
	// cap alone would mask it.
	boundCap int64
	// decode performs the SAME decode call the real handler makes against r (r.Body
	// already wrapped by the production cap middleware for this case).
	decode func(r *http.Request) error
}

// jsonDecodeCases is the 2026-09-18 JSON-decode-bounded-work investigation's route
// set: every unauthenticated, pre-session JSON-body endpoint (auth.Login,
// auth.PasswordReset, webauthn.FinishWebAuthnLogin — the highest-traffic bodies an
// anonymous attacker can drive), the shared mustDecodeBody helper's own call shape
// (helpers.go:142, the most common decode path in this codebase), and BOTH
// unbounded-allocation-shape leads Step 1's sweep found: alert_escalation.go's and
// notification_channels.go's Update handlers decode the WHOLE body into
// map[string]interface{} instead of a fixed-field struct, so every
// attacker-supplied key becomes its own Go map entry + boxed interface{} — a
// materially different allocation shape than the flat-struct cases. (These were
// the only two map[string]interface{} body-decode sites found anywhere in this
// package.)
func jsonDecodeCases() []jsonDecodeCase {
	return []jsonDecodeCase{
		{
			// POST /auth/login (auth.go:106) — unauthenticated, highest-traffic body route.
			name:     "auth.Login",
			routeCap: globalBodyCap,
			boundCap: globalBodyCap,
			decode: func(r *http.Request) error {
				var body loginRequestBody
				return json.NewDecoder(r.Body).Decode(&body)
			},
		},
		{
			// POST /auth/password-reset (auth.go) — unauthenticated.
			name:     "auth.PasswordReset",
			routeCap: globalBodyCap,
			boundCap: globalBodyCap,
			decode: func(r *http.Request) error {
				var body passwordResetRequestBody
				return json.NewDecoder(r.Body).Decode(&body)
			},
		},
		{
			// POST /auth/webauthn/login/finish (webauthn.go:235) — unauthenticated;
			// decodeJSON layers its OWN 64 KiB cap (maxWebAuthnBody) via io.LimitReader on
			// top of the global cap. Calling decodeJSON itself (not a reimplementation)
			// reproduces that exactly. Credential is json.RawMessage — the decoder must
			// still walk/skip its full structure to find the matching close, without
			// building Go values for it. boundCap is the inner 64 KiB cap, not the outer
			// global one — see jsonDecodeCase's own doc comment for why.
			name:     "webauthn.FinishWebAuthnLogin",
			routeCap: globalBodyCap,
			boundCap: maxWebAuthnBody,
			decode: func(r *http.Request) error {
				var body struct {
					Challenge       string          `json:"mfa_challenge"`
					WebAuthnSession string          `json:"webauthn_session"`
					Credential      json.RawMessage `json:"credential"`
				}
				return decodeJSON(r, &body)
			},
		},
		{
			// POST /api/v1/projects/{id}/machine-identities (machine_identities.go:61) —
			// authenticated, but this is mustDecodeBody's (helpers.go:142) own call shape:
			// the shared decode helper used across a dozen handler files, with no cap of
			// its own beyond the global middleware.
			name:     "catalog.CreateMachineIdentity(mustDecodeBody)",
			routeCap: globalBodyCap,
			boundCap: globalBodyCap,
			decode: func(r *http.Request) error {
				var body struct {
					Name           string `json:"name"`
					IdentityType   string `json:"identity_type"`
					Description    string `json:"description"`
					Classification string `json:"classification"`
				}
				if !mustDecodeBody(httptest.NewRecorder(), r, &body) {
					return errMustDecodeBodyFailed
				}
				return nil
			},
		},
		{
			// PUT /api/v1/alert-escalation-policies/{id} (alert_escalation.go:138) — the
			// unbounded-allocation-shape lead: decodes straight into map[string]interface{},
			// no fixed field set, guarded only by the global cap.
			name:     "alertEscalation.Update(map[string]interface{})",
			routeCap: globalBodyCap,
			boundCap: globalBodyCap,
			decode: func(r *http.Request) error {
				var body map[string]any
				return json.NewDecoder(r.Body).Decode(&body)
			},
		},
		{
			// PUT /api/v1/notification-channels/{id} (notification_channels.go:137) — the
			// SECOND (and only other) map[string]interface{}-decode site found in Step 1's
			// sweep of server/http/handlers; same unbounded-allocation shape and same
			// global-cap-only guard as alertEscalation.Update above.
			name:     "notificationChannel.Update(map[string]interface{})",
			routeCap: globalBodyCap,
			boundCap: globalBodyCap,
			decode: func(r *http.Request) error {
				var body map[string]any
				return json.NewDecoder(r.Body).Decode(&body)
			},
		},
	}
}

// boundedWorkLimit returns a generous allocation ceiling for one decode case over a
// bodyLen-byte input. Work is bounded by min(bodyLen, cap) — not bodyLen alone —
// because a correctly-capped reader never reads past cap regardless of how much
// more the attacker sends; that's the exact property under test, so the limit must
// track it (an uncapped reader would blow this the moment bodyLen > cap, which is
// precisely the regression this is meant to catch).
//
// Per-target multiplier: map[string]interface{} decode allocates a map bucket +
// boxed interface{} PER KEY, on top of the bytes themselves, so it gets a much
// larger multiplier than a fixed-field struct decode (which allocates roughly the
// string/byte content once, plus fixed per-field overhead independent of body
// size). Both constants carry wide headroom over any real single-digit-multiple
// measured in a same-worktree dry run (see PR description) — sized to catch an
// order-of-magnitude amplification regression, not to enforce tight efficiency.
func boundedWorkLimit(caseName string, bodyLen int, cap int64) uint64 {
	bounded := bodyLen
	if cap >= 0 && int64(bounded) > cap {
		bounded = int(cap)
	}
	// Matched by shape, not by an exhaustive name list — every case whose name
	// carries this suffix decodes into map[string]interface{} (see jsonDecodeCases)
	// and gets the map-shaped multiplier below regardless of which route it is.
	if strings.HasSuffix(caseName, "(map[string]interface{})") {
		return uint64(1<<20) + uint64(bounded)*256
	}
	return uint64(1<<16) + uint64(bounded)*64
}

// depthArray/depthObject build a JSON document nested to exactly depth levels:
// depth `[` followed by depth `]` (array nesting), or depth repeats of `{"a":`
// followed by a scalar and depth `}` (object nesting). Used to construct seeds
// precisely at/around encoding/json's own maxNestingDepth (this repo's pinned Go
// 1.27 toolchain, scanner.go: 10000) — the boundary "no panic / no stack overflow
// on depth" actually depends on.
func depthArray(depth int) []byte {
	var b strings.Builder
	b.Grow(depth * 2)
	for range depth {
		b.WriteByte('[')
	}
	for range depth {
		b.WriteByte(']')
	}
	return []byte(b.String())
}

func depthObject(depth int) []byte {
	var b strings.Builder
	b.Grow(depth*6 + 4)
	for range depth {
		b.WriteString(`{"a":`)
	}
	b.WriteString("0")
	for range depth {
		b.WriteByte('}')
	}
	return []byte(b.String())
}

func bigNumberArray(approxBytes int) []byte {
	var b strings.Builder
	b.Grow(approxBytes + 8)
	b.WriteByte('[')
	for b.Len() < approxBytes {
		if b.Len() > 1 {
			b.WriteByte(',')
		}
		b.WriteByte('1')
	}
	b.WriteByte(']')
	return []byte(b.String())
}

// jsonBracketDepth computes the maximum '{'/'[' nesting depth in data, tracking
// quoted-string state (with backslash-escape handling) so structural brackets
// inside string content are never miscounted as nesting. Deliberately simple: it
// does not fully validate JSON, so callers should only trust it well past any
// boundary they care about (see the >10010 margin below, comfortably clear of
// encoding/json's own maxNestingDepth of 10000) rather than at the exact edge.
func jsonBracketDepth(data []byte) int {
	depth, max := 0, 0
	inString, escaped := false, false
	for _, b := range data {
		if inString {
			switch {
			case escaped:
				escaped = false
			case b == '\\':
				escaped = true
			case b == '"':
				inString = false
			}
			continue
		}
		switch b {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > max {
				max = depth
			}
		case '}', ']':
			depth--
		}
	}
	return max
}

func manyKeysObject(n int) []byte {
	var b strings.Builder
	b.WriteByte('{')
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		b.WriteString("k")
		b.WriteString(strconv.Itoa(i))
		b.WriteString(`":1`)
	}
	b.WriteByte('}')
	return []byte(b.String())
}

// FuzzJSONDecodeBoundedWork asserts that decoding an HTTP API JSON request body —
// the stage that runs before ANY handler logic, on every route including every
// unauthenticated one — costs work (time, allocation) bounded by a linear function
// of the body size actually read, for every one of the 6 real production decode
// call shapes in jsonDecodeCases: deep nesting, giant arrays/strings, and
// many/duplicate keys must not drive CPU/alloc beyond that bound.
//
//   - fuzzutil.Guard bounds TIME: a hang or super-linear slowdown fails the target
//     (3s per case per input).
//   - boundedWorkLimit bounds MEMORY via TotalAlloc delta, tracking min(len(body),
//     cap) — see its own doc comment for why the cap enters the bound.
//   - depth: jsonBracketDepth independently measures each input's own nesting
//     depth (string-aware bracket counting, no dependency on encoding/json); when
//     it is unambiguously past encoding/json's maxNestingDepth (10000 — confirmed
//     against this repo's pinned Go 1.27 toolchain source, scanner.go), every case
//     must return a non-nil decode error — confirms none of the 6 call sites wrap
//     decode in a way that swallows that rejection (several OTHER handlers in this
//     package do discard decode errors for an "optional body" — see catalog.go /
//     secrets_suspend.go's `_ = json.NewDecoder(...).Decode(...)` — none of the 6
//     harnessed here do). A Go stack overflow itself (unlike a panic) cannot be
//     recovered from; it would crash the whole `go test -fuzz` process, which is
//     itself a directly observable finding regardless of this assertion.
//
// Investigated but NOT added: a differential oracle between the two decode sites
// that read the user-roles assign/remove body twice (server/middleware/auth.go's
// ScopeFromRoleAssignmentBody, then the handler's own decode of the re-buffered
// body) — Step 1 flagged this as a double-decode lead, but both sites call
// encoding/json (json.Unmarshal and json.Decoder.Decode respectively), which share
// one duplicate-key resolution rule (last occurrence wins) by construction of the
// same standard-library scanner. No divergence is structurally possible between
// them, so a differential assertion here would never be able to fire — not sound
// coverage, just a permanently-vacuous check. The duplicate-key seed below still
// exercises the bounded-work property generally (which does not depend on this).
//
// Sound: every assertion is an upper bound (time, allocation) or a must-not-accept
// (past the depth limit) — never "must succeed" on arbitrary input.
func FuzzJSONDecodeBoundedWork(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"username":"a","password":"b"}`))
	f.Add(depthArray(9999))
	f.Add(depthArray(10020))
	f.Add(depthObject(9999))
	f.Add(depthObject(10020))
	f.Add(bigNumberArray(1 << 20)) // ~1 MiB of "[1,1,1,...]"
	f.Add(manyKeysObject(10000))
	f.Add([]byte(`{"project_id":"A","project_id":"B"}`))              // duplicate security field
	f.Add([]byte{0xff, 0xfe, 0xfd})                                   // invalid UTF-8, invalid JSON syntax too
	f.Add([]byte(`{"username":"` + "\xff\xfe" + `","password":"x"}`)) // invalid UTF-8 inside a valid string

	f.Fuzz(func(t *testing.T, data []byte) {
		// Computed once per input, well clear (>10010) of encoding/json's own
		// maxNestingDepth (10000) so jsonBracketDepth's simple string-aware counter
		// never disagrees with the real scanner's own bookkeeping near the boundary.
		pastDepthLimit := jsonBracketDepth(data) > 10010

		for _, c := range jsonDecodeCases() {
			req := cappedRequest(c.routeCap, data)

			var m0, m1 runtime.MemStats
			runtime.ReadMemStats(&m0)

			var decErr error
			fuzzutil.Guard(t.Fatalf, c.name, func() {
				decErr = c.decode(req) // a decode error is otherwise routine (most fuzzed bytes are invalid JSON); only time+memory are the property EXCEPT for the depth check below
			})

			if pastDepthLimit && decErr == nil {
				t.Fatalf("DEPTH-LIMIT: %s accepted a body nested past encoding/json's maxNestingDepth (10000) instead of rejecting it — depth protection bypassed on this decode path", c.name)
			}

			runtime.ReadMemStats(&m1)
			alloc := m1.TotalAlloc - m0.TotalAlloc
			limit := boundedWorkLimit(c.name, len(data), c.boundCap)
			if alloc > limit {
				t.Fatalf("BOUNDED-WORK: %s allocated %d bytes decoding a %d-byte body (bound cap %d, limit %d) — amplification regression",
					c.name, alloc, len(data), c.boundCap, limit)
			}
		}
	})
}
