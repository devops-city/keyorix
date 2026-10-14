package validation

import (
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/utils/safeconv"
)

// Validator provides request validation functionality.
//
// Validator instances are constructed once at process startup (see the
// handler constructors in server/http/handlers) and shared across every
// subsequent concurrent request for the lifetime of the server process.
// Validate MUST therefore be stateless: it must never read or write any
// Validator field across calls. All per-call error accumulation happens in
// a map that is local to a single Validate call and is returned directly,
// never stored on the struct — this removes the concurrent map read/write
// hazard entirely rather than serializing it behind a mutex.
type Validator struct{}

// NewValidator creates a new validator instance
func NewValidator() *Validator {
	return &Validator{}
}

// ValidationError represents validation errors
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Value   any    `json:"value,omitempty"`
}

// ValidationErrors represents multiple validation errors
type ValidationErrors struct {
	Errors []ValidationError `json:"errors"`
}

func (ve ValidationErrors) Error() string {
	var messages []string
	for _, err := range ve.Errors {
		messages = append(messages, fmt.Sprintf("%s: %s", err.Field, err.Message))
	}
	return strings.Join(messages, "; ")
}

// Validate validates a struct using reflection and validation tags. It is
// stateless: every call builds its own local errs map and never reads or
// writes any Validator field, so a single shared *Validator instance can be
// called concurrently by many goroutines/requests without risk of a
// concurrent map read/write (which the Go runtime treats as fatal) or of one
// call's in-flight errors being corrupted by another's.
func (v *Validator) Validate(s any) error { // NOSONAR -- cognitive complexity 19, suppress go:S3776
	errs := make(map[string][]string)

	val := reflect.ValueOf(s)
	if val.Kind() == reflect.Pointer {
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return fmt.Errorf("validation target must be a struct")
	}

	typ := val.Type()

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)

		// Skip unexported fields
		if !field.CanInterface() {
			continue
		}

		// Get validation tag
		tag := fieldType.Tag.Get("validate")
		if tag == "" {
			continue
		}

		// Get JSON field name for error reporting
		jsonTag := fieldType.Tag.Get("json")
		fieldName := fieldType.Name
		if jsonTag != "" {
			parts := strings.Split(jsonTag, ",")
			if parts[0] != "" && parts[0] != "-" {
				fieldName = parts[0]
			}
		}

		// Validate field
		v.validateField(errs, fieldName, field, tag)
	}

	if len(errs) > 0 {
		var validationErrors []ValidationError
		for field, messages := range errs {
			for _, message := range messages {
				validationErrors = append(validationErrors, ValidationError{
					Field:   field,
					Message: message,
				})
			}
		}
		return ValidationErrors{Errors: validationErrors}
	}

	return nil
}

// validateField validates a single field based on validation rules,
// accumulating any failures into errs, which is local to the enclosing
// Validate call (see the stateless-by-design note on Validate).
func (v *Validator) validateField(errs map[string][]string, fieldName string, field reflect.Value, tag string) {
	rules := strings.SplitSeq(tag, ",")

	for rule := range rules {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}

		// Handle optional fields
		if rule == "omitempty" && v.isEmpty(field) {
			return
		}

		// Parse rule and parameters
		parts := strings.Split(rule, "=")
		ruleName := parts[0]
		var param string
		if len(parts) > 1 {
			param = parts[1]
		}

		// Apply validation rule
		if err := v.applyRule(fieldName, field, ruleName, param); err != nil {
			addError(errs, fieldName, err.Error())
		}
	}
}

// applyRule applies a specific validation rule
func (v *Validator) applyRule(fieldName string, field reflect.Value, ruleName, param string) error {
	switch ruleName {
	case "required":
		// A nil pointer/interface has nothing to check (ok=false) and is
		// itself "not provided", so it fails required just like isEmpty's
		// own Pointer/Interface case does. A non-nil pointer is dereferenced
		// so it's judged by the SAME emptiness rule as its non-pointer
		// equivalent (e.g. a non-nil *string pointing at "" or a non-nil
		// *int pointing at 0 must fail required exactly as a plain ""/0
		// field would) instead of unconditionally passing just because the
		// pointer itself is non-nil.
		resolved, ok := derefForRule(field)
		if !ok || v.isEmpty(resolved) {
			return fmt.Errorf("%s", i18n.T("ErrorValidation", nil))
		}
	case "min":
		return v.validateMin(field, param)
	case "max":
		return v.validateMax(field, param)
	case "email":
		return v.validateEmail(field)
	case "url":
		return v.validateURL(field)
	case "alpha":
		return v.validateAlpha(field)
	case "alphanum":
		return v.validateAlphaNum(field)
	case "numeric":
		return v.validateNumeric(field)
	case "oneof":
		return v.validateOneOf(field, param)
	case "identifier":
		return v.validateIdentifier(field)
	}

	return nil
}

// isBlank reports whether s has no visible content once ordinary whitespace and
// Unicode zero-width/format (Cf) and control (Cc) characters (e.g. U+200B ZERO WIDTH
// SPACE) are disregarded. Used by isEmpty so a whitespace-only or zero-width-only
// string doesn't pass a `required` check.
func isBlank(s string) bool {
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Cc, r) {
			continue
		}
		return false
	}
	return true
}

// isEmpty checks if a field is empty. A nil pointer/interface is empty (and
// `omitempty` short-circuits the remaining rules for it). A NON-nil pointer
// is deliberately NOT treated as empty even when it points at a zero value
// (e.g. a non-nil *int pointing at 0, or a non-nil *string pointing at "").
// Pointer-typed request fields exist precisely so a caller can distinguish
// "not provided" (nil — skip validation, leave any existing value alone)
// from "explicitly set to the zero value" (non-nil — must still satisfy
// every other rule, e.g. reject a `max_reads: 0` that a `min=1` tag forbids,
// rather than silently letting the zero value pass as if it were absent).
// A string field is additionally treated as empty when it is blank per isBlank
// (whitespace-only or composed solely of Unicode zero-width/format/control
// characters), so such a value can't slip past a `required` check.
func (v *Validator) isEmpty(field reflect.Value) bool {
	switch field.Kind() {
	case reflect.String:
		return isBlank(field.String())
	case reflect.Slice, reflect.Map, reflect.Array:
		return field.Len() == 0
	case reflect.Pointer, reflect.Interface:
		return field.IsNil()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return field.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return field.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return field.Float() == 0
	case reflect.Bool:
		return !field.Bool()
	}
	return false
}

// derefForRule resolves field to the value that the Kind()-based validation
// rules (min/max/email/url/alpha/alphanum/numeric/oneof) should inspect: a
// non-pointer field is returned unchanged; a non-nil pointer is dereferenced
// so it's validated against the same rules as its non-pointer equivalent; a
// nil pointer has nothing to validate (ok=false) — the rule should pass,
// exactly as it does today for an absent value (omitempty, if present, has
// already short-circuited via isEmpty; `required` is enforced separately).
func derefForRule(field reflect.Value) (resolved reflect.Value, ok bool) {
	if field.Kind() == reflect.Pointer {
		if field.IsNil() {
			return reflect.Value{}, false
		}
		return field.Elem(), true
	}
	return field, true
}

// validateMin validates minimum length/value
func (v *Validator) validateMin(field reflect.Value, param string) error {
	resolved, ok := derefForRule(field)
	if !ok {
		return nil
	}
	field = resolved

	var min int
	_, _ = fmt.Sscanf(param, "%d", &min)

	switch field.Kind() {
	case reflect.String:
		if len(field.String()) < min {
			return fmt.Errorf("must be at least %d characters", min)
		}
	case reflect.Slice, reflect.Array:
		if field.Len() < min {
			return fmt.Errorf("must have at least %d items", min)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if field.Int() < int64(min) {
			return fmt.Errorf("must be at least %d", min)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		minUint64, err := safeconv.IntToUint64(min)
		if err != nil {
			return fmt.Errorf("invalid min value: %v", err)
		}
		if field.Uint() < minUint64 {
			return fmt.Errorf("must be at least %d", min)
		}
	}

	return nil
}

// validateMax validates maximum length/value
func (v *Validator) validateMax(field reflect.Value, param string) error {
	resolved, ok := derefForRule(field)
	if !ok {
		return nil
	}
	field = resolved

	var max int
	_, _ = fmt.Sscanf(param, "%d", &max)

	switch field.Kind() {
	case reflect.String:
		if len(field.String()) > max {
			return fmt.Errorf("must be at most %d characters", max)
		}
	case reflect.Slice, reflect.Array:
		if field.Len() > max {
			return fmt.Errorf("must have at most %d items", max)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if field.Int() > int64(max) {
			return fmt.Errorf("must be at most %d", max)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		maxUint64, err := safeconv.IntToUint64(max)
		if err != nil {
			return fmt.Errorf("invalid max value: %v", err)
		}
		if field.Uint() > maxUint64 {
			return fmt.Errorf("must be at most %d", max)
		}
	}

	return nil
}

// emailRegex matches the email format accepted by validateEmail. Compiled
// once at package init (like identifierRegex below) instead of per-call,
// since Validate is invoked by many concurrent goroutines against a single
// shared *Validator on every request that carries an `email` field.
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

// validateEmail validates email format
func (v *Validator) validateEmail(field reflect.Value) error {
	resolved, ok := derefForRule(field)
	if !ok {
		return nil
	}
	field = resolved
	if field.Kind() != reflect.String {
		return nil
	}

	email := field.String()
	if email == "" {
		return nil
	}

	if !emailRegex.MatchString(email) {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), i18n.T("LabelEmail", nil))
	}

	return nil
}

// urlRegex matches the URL format accepted by validateURL. Compiled once at
// package init instead of per-call (see emailRegex).
var urlRegex = regexp.MustCompile(`^https?://[^\s/$.?#].[^\s]*$`)

// validateURL validates URL format
func (v *Validator) validateURL(field reflect.Value) error {
	resolved, ok := derefForRule(field)
	if !ok {
		return nil
	}
	field = resolved
	if field.Kind() != reflect.String {
		return nil
	}

	url := field.String()
	if url == "" {
		return nil
	}

	if !urlRegex.MatchString(url) {
		return fmt.Errorf("%s: must be a valid URL", i18n.T("ErrorValidation", nil))
	}

	return nil
}

// alphaRegex matches the alphabetic-only charset accepted by validateAlpha.
// Compiled once at package init instead of per-call (see emailRegex).
var alphaRegex = regexp.MustCompile(`^[a-zA-Z]+$`)

// validateAlpha validates alphabetic characters only
func (v *Validator) validateAlpha(field reflect.Value) error {
	resolved, ok := derefForRule(field)
	if !ok {
		return nil
	}
	field = resolved
	if field.Kind() != reflect.String {
		return nil
	}

	str := field.String()
	if str == "" {
		return nil
	}

	if !alphaRegex.MatchString(str) {
		return fmt.Errorf("%s: must contain only alphabetic characters", i18n.T("ErrorValidation", nil))
	}

	return nil
}

// alphaNumRegex matches the alphanumeric-only charset accepted by
// validateAlphaNum. Compiled once at package init instead of per-call (see
// emailRegex).
var alphaNumRegex = regexp.MustCompile(`^[a-zA-Z0-9]+$`)

// validateAlphaNum validates alphanumeric characters only
func (v *Validator) validateAlphaNum(field reflect.Value) error {
	resolved, ok := derefForRule(field)
	if !ok {
		return nil
	}
	field = resolved
	if field.Kind() != reflect.String {
		return nil
	}

	str := field.String()
	if str == "" {
		return nil
	}

	if !alphaNumRegex.MatchString(str) {
		return fmt.Errorf("%s: must contain only alphanumeric characters", i18n.T("ErrorValidation", nil))
	}

	return nil
}

// numericRegex matches the numeric-only charset accepted by validateNumeric.
// Compiled once at package init instead of per-call (see emailRegex).
var numericRegex = regexp.MustCompile(`^[0-9]+$`)

// validateNumeric validates numeric characters only
func (v *Validator) validateNumeric(field reflect.Value) error {
	resolved, ok := derefForRule(field)
	if !ok {
		return nil
	}
	field = resolved
	if field.Kind() != reflect.String {
		return nil
	}

	str := field.String()
	if str == "" {
		return nil
	}

	if !numericRegex.MatchString(str) {
		return fmt.Errorf("%s: must contain only numeric characters", i18n.T("ErrorValidation", nil))
	}

	return nil
}

// identifierRegex matches a safe resource-identifier charset: letters, digits,
// spaces, `-`, and `_`. Deliberately excludes punctuation with special meaning
// elsewhere (CSV-formula triggers, path separators, shell/URL metacharacters) and
// any character outside this allowlist, so it also rejects zero-width/homograph
// characters that could otherwise render a name blank or visually deceptive.
var identifierRegex = regexp.MustCompile(`^[a-zA-Z0-9 _-]+$`)

// validateIdentifier validates that a string is a safe resource identifier: letters,
// digits, spaces, `-`, `_` only (see identifierRegex), with no leading/trailing or
// repeated internal whitespace and not entirely whitespace — a value can satisfy the
// charset alone (e.g. "   ", "  my project  ", "my  project") and still be visually
// confusable with, or indistinguishable from, another value. Opt-in via
// `validate:"identifier"` for Name-like fields that should be restricted to a safe,
// unambiguous charset — not applied globally, since some fields (e.g. free-form secret
// names) intentionally allow a broader charset.
func (v *Validator) validateIdentifier(field reflect.Value) error {
	resolved, ok := derefForRule(field)
	if !ok {
		return nil
	}
	field = resolved
	if field.Kind() != reflect.String {
		return nil
	}

	str := field.String()
	if str == "" {
		return nil
	}

	if !identifierRegex.MatchString(str) {
		return fmt.Errorf("%s: must contain only letters, digits, spaces, - or _", i18n.T("ErrorValidation", nil))
	}

	// Reject whitespace variants that stay inside the [a-zA-Z0-9 _-] charset
	// but defeat the anti-spoofing intent above: a name that's entirely
	// whitespace (renders blank), has leading/trailing whitespace, or has
	// repeated internal whitespace (e.g. "Support Team" vs "Support  Team")
	// can be visually indistinguishable from — or confusable with — another
	// name despite passing the charset check.
	if trimmed := strings.TrimSpace(str); trimmed == "" || trimmed != str || strings.Contains(trimmed, "  ") {
		return fmt.Errorf("%s: must not be all whitespace or have leading, trailing, or repeated internal whitespace", i18n.T("ErrorValidation", nil))
	}

	return nil
}

// validateOneOf validates that value is one of allowed values
func (v *Validator) validateOneOf(field reflect.Value, param string) error {
	resolved, ok := derefForRule(field)
	if !ok {
		return nil
	}
	field = resolved
	if field.Kind() != reflect.String {
		return nil
	}

	value := field.String()
	if value == "" {
		return nil
	}

	allowedValues := strings.Split(param, " ")
	if slices.Contains(allowedValues, value) {
		return nil
	}

	return fmt.Errorf("%s: must be one of: %s", i18n.T("ErrorValidation", nil), strings.Join(allowedValues, ", "))
}

// addError records a validation failure into errs, the map local to a
// single Validate call (see the stateless-by-design note on Validate). It
// is a plain function, not a *Validator method, precisely so it cannot be
// tempted into touching shared struct state.
func addError(errs map[string][]string, field, message string) {
	if errs[field] == nil {
		errs[field] = []string{}
	}
	errs[field] = append(errs[field], message)
}
