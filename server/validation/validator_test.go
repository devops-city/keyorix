package validation

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Several validation rules render their message via i18n.T, whose GetLocalizer
// panics when the bundle is uninitialized. Initialize it once for the package.
func TestMain(m *testing.M) {
	if err := i18n.InitializeForTesting(); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

func TestValidate_NonStructIsError(t *testing.T) {
	v := NewValidator()
	err := v.Validate("not a struct")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be a struct")
}

func TestValidate_AcceptsPointerToStruct(t *testing.T) {
	type payload struct {
		Name string `json:"name" validate:"required"`
	}
	v := NewValidator()
	require.NoError(t, v.Validate(&payload{Name: "ok"}))
}

func TestValidate_Required(t *testing.T) {
	type payload struct {
		Name string `json:"name" validate:"required"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Name: "present"}))

	err := v.Validate(payload{Name: ""})
	require.Error(t, err)
}

func TestValidate_Required_RejectsWhitespaceAndZeroWidthOnly(t *testing.T) {
	type payload struct {
		Name string `json:"name" validate:"required"`
	}
	v := NewValidator()

	// Positive case: real content still passes.
	require.NoError(t, v.Validate(payload{Name: "Payments"}))

	for name, bad := range map[string]string{
		"pure whitespace":      "   \t\n  ",
		"zero-width space":     "\u200b\u200b",
		"zero-width + spaces":  "  \u200b \u200b  ",
		"non-breaking + ZWNBS": "\u00a0\ufeff",
	} {
		err := v.Validate(payload{Name: bad})
		require.Error(t, err, name)
	}
}

func TestValidate_Identifier(t *testing.T) {
	type payload struct {
		Name string `json:"name" validate:"omitempty,identifier"`
	}
	v := NewValidator()

	for _, good := range []string{"", "Payments", "prod-db_01", "team 42"} {
		require.NoError(t, v.Validate(payload{Name: good}), good)
	}
	zwsp := string(rune(0x200B)) // ZERO WIDTH SPACE
	for _, bad := range []string{
		"=cmd|'/c calc'!A1",
		"name" + zwsp + "with" + zwsp + "zero" + zwsp + "width",
		"path/traversal",
		"<script>",
		"semicolon;here",
	} {
		require.Error(t, v.Validate(payload{Name: bad}), bad)
	}
}

func TestValidate_Omitempty_SkipsRemainingRules(t *testing.T) {
	type payload struct {
		Nickname string `json:"nickname" validate:"omitempty,min=3"`
	}
	v := NewValidator()

	// Empty → omitempty short-circuits, min is not enforced.
	require.NoError(t, v.Validate(payload{Nickname: ""}))
	// Present but too short → min applies.
	require.Error(t, v.Validate(payload{Nickname: "ab"}))
	// Present and long enough → ok.
	require.NoError(t, v.Validate(payload{Nickname: "abc"}))
}

func TestValidate_MinMax_StringLength(t *testing.T) {
	type payload struct {
		Code string `json:"code" validate:"min=2,max=4"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Code: "abc"}))
	require.Error(t, v.Validate(payload{Code: "a"}), "below min")
	require.Error(t, v.Validate(payload{Code: "abcde"}), "above max")
}

func TestValidate_MinMax_IntValue(t *testing.T) {
	type payload struct {
		Age int `json:"age" validate:"min=18,max=99"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Age: 30}))
	require.Error(t, v.Validate(payload{Age: 17}), "below min")
	require.Error(t, v.Validate(payload{Age: 100}), "above max")
}

func TestValidate_MinMax_UintValue(t *testing.T) {
	type payload struct {
		Count uint `json:"count" validate:"min=1,max=10"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Count: 5}))
	require.Error(t, v.Validate(payload{Count: 11}), "above max")
}

func TestValidate_Email(t *testing.T) {
	type payload struct {
		Email string `json:"email" validate:"email"`
	}
	v := NewValidator()

	for _, good := range []string{"a@b.co", "user.name+tag@example.com"} {
		require.NoError(t, v.Validate(payload{Email: good}), good)
	}
	for _, bad := range []string{"no-at", "a@b", "a@.com", "@b.com"} {
		require.Error(t, v.Validate(payload{Email: bad}), bad)
	}
	// Empty is allowed by the rule itself (use `required` to forbid).
	require.NoError(t, v.Validate(payload{Email: ""}))
}

func TestValidate_URL(t *testing.T) {
	type payload struct {
		URL string `json:"url" validate:"url"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{URL: "https://example.com/x"}))
	require.NoError(t, v.Validate(payload{URL: "http://example.com"}))
	require.Error(t, v.Validate(payload{URL: "ftp://example.com"}))
	require.Error(t, v.Validate(payload{URL: "not a url"}))
}

func TestValidate_CharacterClasses(t *testing.T) {
	type payload struct {
		Alpha    string `json:"alpha" validate:"omitempty,alpha"`
		AlphaNum string `json:"alphanum" validate:"omitempty,alphanum"`
		Numeric  string `json:"numeric" validate:"omitempty,numeric"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Alpha: "abc", AlphaNum: "abc123", Numeric: "123"}))
	require.Error(t, v.Validate(payload{Alpha: "abc1"}), "alpha rejects digit")
	require.Error(t, v.Validate(payload{AlphaNum: "abc-1"}), "alphanum rejects dash")
	require.Error(t, v.Validate(payload{Numeric: "12a"}), "numeric rejects letter")
}

func TestValidate_OneOf(t *testing.T) {
	type payload struct {
		Env string `json:"env" validate:"oneof=dev staging prod"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Env: "staging"}))
	require.Error(t, v.Validate(payload{Env: "qa"}))
}

func TestValidate_UntaggedAndUnexportedFieldsSkipped(t *testing.T) {
	type payload struct {
		Tagged   string `json:"tagged" validate:"required"`
		Untagged string // no validate tag → ignored
		secret   string // unexported → ignored
	}
	v := NewValidator()
	require.NoError(t, v.Validate(payload{Tagged: "x"}))
	_ = payload{}.secret
}

func TestValidate_CollectsMultipleErrors(t *testing.T) {
	type payload struct {
		Name  string `json:"name" validate:"required"`
		Email string `json:"email" validate:"required,email"`
	}
	v := NewValidator()

	err := v.Validate(payload{Name: "", Email: "bad"})
	require.Error(t, err)
	ve, ok := err.(ValidationErrors)
	require.True(t, ok, "expected ValidationErrors")
	assert.GreaterOrEqual(t, len(ve.Errors), 2, "both fields should report errors")
}

func TestValidationErrors_ErrorString(t *testing.T) {
	ve := ValidationErrors{Errors: []ValidationError{
		{Field: "name", Message: "is required"},
		{Field: "age", Message: "must be at least 18"},
	}}
	got := ve.Error()
	assert.Contains(t, got, "name: is required")
	assert.Contains(t, got, "age: must be at least 18")
	assert.Contains(t, got, "; ")
}

// --- Pointer-typed field regression tests (#347) ---
//
// Pointer-typed fields (*int, *string, *[]string) must be validated against
// the SAME rules as their non-pointer equivalent once the pointer is known
// to be non-nil. A nil pointer with `omitempty` must still pass, exactly as
// before.

func intPtr(i int) *int                { return &i }
func strPtr(s string) *string          { return &s }
func sliceStrPtr(s []string) *[]string { return &s }

func TestValidate_PointerMin_NonNilBelowMin_Errors(t *testing.T) {
	type payload struct {
		MaxReads *int `json:"max_reads" validate:"omitempty,min=1"`
	}
	v := NewValidator()

	// The primary #347 regression: max_reads=0 and max_reads=-100 must be
	// rejected, not silently pass as "unlimited reads".
	require.Error(t, v.Validate(payload{MaxReads: intPtr(0)}), "max_reads=0 must be rejected")
	require.Error(t, v.Validate(payload{MaxReads: intPtr(-100)}), "max_reads=-100 must be rejected")
}

func TestValidate_PointerMin_NonNilAtOrAboveMin_Passes(t *testing.T) {
	type payload struct {
		MaxReads *int `json:"max_reads" validate:"omitempty,min=1"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{MaxReads: intPtr(1)}))
	require.NoError(t, v.Validate(payload{MaxReads: intPtr(100)}))
}

func TestValidate_PointerOmitempty_NilPointerPasses(t *testing.T) {
	type payload struct {
		MaxReads *int `json:"max_reads" validate:"omitempty,min=1"`
	}
	v := NewValidator()

	// A nil pointer must still be treated as "absent" and pass omitempty,
	// exactly like before this fix.
	require.NoError(t, v.Validate(payload{MaxReads: nil}))
}

func TestValidate_PointerString_MinMax(t *testing.T) {
	type payload struct {
		Username *string `json:"username" validate:"omitempty,min=3,max=50"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Username: nil}), "nil pointer passes via omitempty")
	require.NoError(t, v.Validate(payload{Username: strPtr("abc")}))
	require.Error(t, v.Validate(payload{Username: strPtr("ab")}), "below min")
	require.Error(t, v.Validate(payload{Username: strPtr(strings.Repeat("a", 51))}), "above max")
}

func TestValidate_PointerString_Email(t *testing.T) {
	type payload struct {
		Email *string `json:"email" validate:"omitempty,email"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Email: nil}), "nil pointer passes via omitempty")
	require.NoError(t, v.Validate(payload{Email: strPtr("a@b.co")}))
	require.Error(t, v.Validate(payload{Email: strPtr("not-an-email <script>")}), "malformed email must be rejected")
}

func TestValidate_PointerString_NonNilZeroValueIsNotOmitted(t *testing.T) {
	// A non-nil pointer to a zero value ("") must NOT be short-circuited by
	// omitempty — only a nil pointer means "not provided". A caller who
	// explicitly sends an empty string must still hit min=1 and be rejected;
	// this is the whole reason MaxReads/DisplayName/etc. use pointer types
	// instead of plain int/string (to distinguish "omitted" from "explicit
	// zero value").
	type payload struct {
		DisplayName *string `json:"display_name" validate:"omitempty,min=1,max=100"`
	}
	v := NewValidator()

	empty := ""
	require.Error(t, v.Validate(payload{DisplayName: &empty}), "non-nil pointer to empty string must still be validated, not treated as absent")
	require.NoError(t, v.Validate(payload{DisplayName: nil}), "nil pointer is absent, correctly skipped")
}

func TestValidate_PointerSlice_MinMax(t *testing.T) {
	type payload struct {
		Permissions *[]string `json:"permissions" validate:"omitempty,min=1"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Permissions: nil}), "nil pointer passes via omitempty")
	require.NoError(t, v.Validate(payload{Permissions: sliceStrPtr([]string{"secrets.read"})}))
	require.Error(t, v.Validate(payload{Permissions: sliceStrPtr([]string{})}), "empty slice behind non-nil pointer must fail min=1")
}

func TestValidate_PointerAndNonPointer_IdenticalRuleOutcome(t *testing.T) {
	// A *string field and its non-pointer equivalent must reach the same
	// pass/fail verdict for the same underlying value and rule set.
	type withPtr struct {
		Value *string `json:"value" validate:"omitempty,min=3,max=5,alphanum"`
	}
	type withoutPtr struct {
		Value string `json:"value" validate:"omitempty,min=3,max=5,alphanum"`
	}
	v := NewValidator()

	cases := []struct {
		val     string
		wantErr bool
	}{
		{"ab", true},     // below min
		{"abc12", false}, // ok
		{"abcdef", true}, // above max
		{"abc-1", true},  // alphanum rejects dash (within min/max range)
	}
	for _, c := range cases {
		ptrErr := v.Validate(withPtr{Value: strPtr(c.val)})
		plainErr := v.Validate(withoutPtr{Value: c.val})
		if c.wantErr {
			require.Error(t, ptrErr, "pointer case: %q", c.val)
			require.Error(t, plainErr, "non-pointer case: %q", c.val)
		} else {
			require.NoError(t, ptrErr, "pointer case: %q", c.val)
			require.NoError(t, plainErr, "non-pointer case: %q", c.val)
		}
	}
}

// --- G47: `required` and `identifier` must dereference a pointer field ---
//
// Every rule in applyRule/validateXxx is supposed to call derefForRule so a
// pointer-typed field is judged against its pointed-to value, exactly like
// its non-pointer equivalent. `required` and `validateIdentifier` were the
// two rules that skipped this: `required` inspected isEmpty(field) directly,
// so a non-nil pointer was NEVER considered empty (isEmpty's Pointer case
// only checks IsNil) and `required` silently passed a non-nil pointer to a
// blank string. `validateIdentifier` checked field.Kind() != reflect.String
// directly, so a *string field's Kind() is Pointer, never String, and the
// charset check was silently skipped entirely for any pointer-typed field.

func TestValidate_Required_NonNilPointerToBlankString_Fails(t *testing.T) {
	type payload struct {
		Name *string `json:"name" validate:"required"`
	}
	v := NewValidator()

	// Non-pointer equivalent: an explicit blank string must fail required.
	type payloadNonPtr struct {
		Name string `json:"name" validate:"required"`
	}
	require.Error(t, v.Validate(payloadNonPtr{Name: ""}), "non-pointer equivalent must fail required")

	// A non-nil pointer to a blank string must fail required the same way,
	// not silently pass just because the pointer itself is non-nil.
	require.Error(t, v.Validate(payload{Name: strPtr("")}), "non-nil pointer to empty string must fail required")
	require.Error(t, v.Validate(payload{Name: strPtr("   ")}), "non-nil pointer to whitespace-only string must fail required")
}

func TestValidate_Required_NonNilPointerToNonBlankString_Passes(t *testing.T) {
	type payload struct {
		Name *string `json:"name" validate:"required"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Name: strPtr("present")}))
}

func TestValidate_Required_NilPointer_Fails(t *testing.T) {
	// A nil pointer means "not provided", which must still fail a bare
	// `required` tag (no `omitempty` present to short-circuit it first) —
	// this must keep working exactly as before the derefForRule fix.
	type payload struct {
		Name *string `json:"name" validate:"required"`
	}
	v := NewValidator()

	require.Error(t, v.Validate(payload{Name: nil}), "nil pointer must fail required")
}

func TestValidate_Required_NonNilPointerToZeroInt_Fails(t *testing.T) {
	// Same principle for a non-string kind: a non-nil *int pointing at 0
	// must fail required exactly as a plain int field set to 0 would.
	type payload struct {
		Count *int `json:"count" validate:"required"`
	}
	v := NewValidator()

	require.Error(t, v.Validate(payload{Count: intPtr(0)}), "non-nil pointer to zero int must fail required")
	require.NoError(t, v.Validate(payload{Count: intPtr(5)}))
}

func TestValidate_Identifier_NonNilPointerToInvalidCharset_Fails(t *testing.T) {
	type payload struct {
		Name *string `json:"name" validate:"omitempty,identifier"`
	}
	v := NewValidator()

	// Non-pointer equivalent: disallowed characters must fail identifier.
	type payloadNonPtr struct {
		Name string `json:"name" validate:"omitempty,identifier"`
	}
	require.Error(t, v.Validate(payloadNonPtr{Name: "path/traversal"}), "non-pointer equivalent must fail identifier")

	// A non-nil pointer to the same invalid value must fail identically,
	// not be silently skipped because Kind() is Pointer rather than String.
	require.Error(t, v.Validate(payload{Name: strPtr("path/traversal")}), "non-nil pointer with disallowed charset must fail identifier")
	require.Error(t, v.Validate(payload{Name: strPtr("<script>")}), "non-nil pointer with disallowed charset must fail identifier")
}

func TestValidate_Identifier_NonNilPointerToValidCharset_Passes(t *testing.T) {
	type payload struct {
		Name *string `json:"name" validate:"omitempty,identifier"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Name: strPtr("prod-db_01")}))
}

func TestValidate_Identifier_NilPointer_Passes(t *testing.T) {
	// A nil pointer has nothing to validate against the charset rule and
	// must pass, matching every other charset rule's nil-pointer handling
	// (validateEmail, validateURL, validateAlpha, etc via derefForRule).
	type payload struct {
		Name *string `json:"name" validate:"omitempty,identifier"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Name: nil}))
}

func TestValidate_Identifier_NilPointer_NoOmitempty_Passes(t *testing.T) {
	// Same as TestValidate_Identifier_NilPointer_Passes but WITHOUT an
	// `omitempty` rule ahead of `identifier`. With `omitempty` present,
	// validateField's own isEmpty short-circuit returns before
	// validateIdentifier is ever reached for a nil pointer, so that test
	// alone never exercises validateIdentifier's own derefForRule ok=false
	// branch (line "if !ok { return nil }"). A bare `identifier` tag routes
	// straight into applyRule -> validateIdentifier with the nil pointer
	// field, confirming validateIdentifier itself treats "nothing to
	// validate" as a pass, matching every other charset rule's handling of a
	// nil pointer.
	type payload struct {
		Name *string `json:"name" validate:"identifier"`
	}
	v := NewValidator()

	require.NoError(t, v.Validate(payload{Name: nil}))
}

func TestValidate_UsesJSONNameForErrorField(t *testing.T) {
	type payload struct {
		UserName string `json:"user_name" validate:"required"`
	}
	v := NewValidator()

	err := v.Validate(payload{})
	require.Error(t, err)
	ve := err.(ValidationErrors)
	require.Len(t, ve.Errors, 1)
	assert.Equal(t, "user_name", ve.Errors[0].Field, "json tag name preferred over Go field name")
}

// --- Concurrent-Validate regression test (#476) ---
//
// Validator instances are constructed exactly once at server startup (one
// per handler, plus a package-level shared instance in
// server/http/handlers/rbac.go) and then called concurrently by every
// subsequent HTTP request for the life of the process. Validate must
// therefore be safe to call concurrently on a single shared *Validator: no
// data race, and no goroutine result may be corrupted by another
// goroutine concurrently running Validate.
//
// Before the fix, Validate reset and mutated a *Validator-level errors map
// with zero synchronization. That reliably reported a concurrent map
// read/write under go test -race here, and separately from the race
// report, this test could also observe wrong pass/fail verdicts (a valid
// input spuriously failing, or an invalid input spuriously passing)
// because one goroutine map reset-then-accumulate sequence could stomp a
// different concurrent goroutine in-flight accumulation.
func TestValidate_ConcurrentCallsAreIsolated(t *testing.T) {
	type payload struct {
		Name string `json:"name" validate:"required,min=3"`
	}

	v := NewValidator() // a single shared instance, exactly as in production

	const goroutines = 50
	const itersPerGoroutine = 20

	var wg sync.WaitGroup
	var unexpectedNoErr atomic.Int32 // invalid input that should have failed but did not
	var unexpectedErr atomic.Int32   // valid input that should have passed but did not

	for g := range goroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := range itersPerGoroutine {
				valid := (id+i)%2 == 0

				var p payload
				if valid {
					p = payload{Name: fmt.Sprintf("valid-name-%d-%d", id, i)}
				} else {
					p = payload{Name: ""} // empty: fails required
				}

				err := v.Validate(&p)

				if valid && err != nil {
					unexpectedErr.Add(1)
				}
				if !valid && err == nil {
					unexpectedNoErr.Add(1)
				}
			}
		}(g)
	}

	wg.Wait()

	assert.Equal(t, int32(0), unexpectedErr.Load(),
		"a valid input incorrectly failed validation under concurrency (result corrupted by another concurrent call)")
	assert.Equal(t, int32(0), unexpectedNoErr.Load(),
		"an invalid input incorrectly passed validation under concurrency (validation bypass)")
}
