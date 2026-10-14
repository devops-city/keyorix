package secrettemplate

import (
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzParse fuzzes parse (render.go), the hand-rolled byte-index parser for
// "${secret:<ref>}" placeholder syntax in user-authored template text. Unlike
// this package's other logic, parse is genuine custom parsing over arbitrary
// input — not a stdlib wrapper — so it is worth pressure-testing directly for
// panics and non-termination, and for the invariants its own doc comment
// promises: every reference in the returned distinct/segment list must have
// actually come from a well-formed "${secret:...}" placeholder in the input,
// and the MaxDistinctReferences cap is never bypassed.
func FuzzParse(f *testing.F) {
	// Seed corpus: empty input, a lone "$", the "$$" literal-collapse rule, a
	// well-formed single and multiple placeholders, back-to-back placeholders
	// with no literal between them, an empty ref (error), an unterminated
	// placeholder (error), a nested-looking placeholder, more than
	// MaxDistinctReferences distinct refs (to hit the cap), a very long
	// literal run, a very long run of placeholders, and control
	// characters/NUL mixed with placeholder syntax.
	f.Add("")
	f.Add("$")
	f.Add("$$")
	f.Add("${secret:x}")
	f.Add("${secret:a}-${secret:b}")
	f.Add("${secret:a}${secret:b}")
	f.Add("${secret:}")
	f.Add("${secret:x")
	f.Add("${secret:${secret:x}}")
	f.Add("$${secret:x}")
	f.Add("prefix ${secret: ref-with-space } suffix")
	f.Add(strings.Repeat("${secret:x}", 5))

	var manyRefs strings.Builder
	for i := range MaxDistinctReferences + 10 {
		manyRefs.WriteString("${secret:ref")
		manyRefs.WriteString(strconv.Itoa(i))
		manyRefs.WriteString("}")
	}
	f.Add(manyRefs.String())

	f.Add(strings.Repeat("x", 20000))
	f.Add(strings.Repeat("${secret:x}", 5000))
	f.Add("\x00${secret:\x00}\x00")
	f.Add("${secret:x}\n\r${secret:y}")

	f.Fuzz(func(t *testing.T, tmpl string) {
		// Must never panic and must never loop forever; go test's fuzz engine
		// enforces a per-input execution budget, so an infinite loop here
		// surfaces as a fuzz timeout/hang rather than a clean failure — this
		// still catches it (see task instructions to prove empirically with a
		// real -fuzztime burst rather than by code inspection alone).
		var segments []segment
		var distinct []string
		var err error
		fuzzutil.Guard(t.Fatalf, "secrettemplate.parse", func() { segments, distinct, err = parse(tmpl) })

		if err != nil {
			return
		}

		// Invariant 1: the MaxDistinctReferences cap is never bypassed on any
		// codepath that returns success.
		if len(distinct) > MaxDistinctReferences {
			t.Fatalf("parse(%q) returned %d distinct refs, exceeding MaxDistinctReferences=%d", tmpl, len(distinct), MaxDistinctReferences)
		}

		// Invariant 2: "empty ref is an error" is never silently violated —
		// no entry in distinct (or in any ref-bearing segment) is empty on a
		// success path.
		for _, ref := range distinct {
			if ref == "" {
				t.Fatalf("parse(%q) returned an empty entry in distinct", tmpl)
			}
		}

		distinctSet := make(map[string]bool, len(distinct))
		for _, ref := range distinct {
			distinctSet[ref] = true
		}

		seenSegRefs := make(map[string]bool)
		var rebuilt strings.Builder
		for _, seg := range segments {
			if seg.ref == "" {
				rebuilt.WriteString(seg.literal)
				continue
			}
			// Invariant 3: no ref-bearing segment has an empty ref.
			if seg.ref == "" {
				t.Fatalf("parse(%q) produced a segment with an empty ref", tmpl)
			}
			// Invariant 4: every ref-bearing segment's ref must actually have
			// appeared inside a "${secret:...}" placeholder in the original
			// input — i.e. it must be a substring of tmpl (parse trims
			// surrounding whitespace from the raw ref text, so compare
			// against a whitespace-trimmed substring rather than requiring an
			// exact placeholder match) and must also be one of the refs
			// recorded in distinct (no ref fabricated out of thin air,
			// distinct from what's actually walked).
			if !distinctSet[seg.ref] {
				t.Fatalf("parse(%q) produced segment ref %q that isn't in distinct %v", tmpl, seg.ref, distinct)
			}
			if !strings.Contains(tmpl, seg.ref) {
				t.Fatalf("parse(%q) fabricated ref %q that never appears in the input", tmpl, seg.ref)
			}
			seenSegRefs[seg.ref] = true
			rebuilt.WriteString("${secret:" + seg.ref + "}")
		}

		// Invariant 5: every distinct ref was actually used by at least one
		// segment (distinct is derived strictly from the segments walk, so it
		// can never name a reference the segment list doesn't reference).
		for _, ref := range distinct {
			if !seenSegRefs[ref] {
				t.Fatalf("parse(%q) recorded distinct ref %q that no segment references", tmpl, ref)
			}
		}
	})
}
