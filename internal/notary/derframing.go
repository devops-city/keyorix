package notary

import "fmt"

// A malformed RFC 3161 token can drive the CMS/BER decoder into pathological
// memory allocation: certain nesting shapes cause the input to be re-parsed and
// re-encoded until it balloons far beyond its own byte size. A size cap cannot
// separate such an input from a legitimate token, because the cost is driven by
// nesting structure, not length.
//
// A genuine TimeStampToken is DER: definite-length, and every child exactly
// tiles its parent's content. The pathological shapes violate that — indefinite
// length is not DER at all, and the overlapping-definite shape has a child whose
// declared length runs past its parent. Validating strict DER framing before the
// token reaches the decoder rejects those shapes while accepting every
// well-formed token. This walks only the tag/length headers (never the content
// bytes) and allocates nothing, so it is itself immune to the same problem.
//
// Rejecting indefinite-length form is not just a heuristic: RFC 3161 §2.4.2
// requires the TimeStampToken to be DER-encoded, and DER forbids the indefinite
// form, so a spec-compliant TSA never emits it.
//
// The limits below are generous for a real token — a SignedData with an embedded
// 2048-bit signing cert sits well within them.
const (
	maxDERDepth = 32
	maxDERNodes = 8192
)

// validateDERFraming reports an error if data is not a single well-formed DER
// object that consumes exactly all of data, or if its structure exceeds
// maxDERDepth / maxDERNodes. It does not validate tags, values, or semantics —
// only the definite-length TLV framing — so it never diverges from the real
// decoder in the accepting direction: anything it accepts is strict DER, which
// the BER decoder then handles in linear time.
func validateDERFraming(data []byte) error {
	nodes := 0
	rest, err := scanDERElement(data, 0, &nodes)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("notary: %d trailing bytes after top-level DER element (not a single well-formed token)", len(rest))
	}
	return nil
}

// scanDERElement consumes exactly one TLV element at the front of data and
// returns the bytes after it. depth is the current nesting depth; nodes counts
// every element seen across the whole walk.
func scanDERElement(data []byte, depth int, nodes *int) ([]byte, error) {
	if depth > maxDERDepth {
		return nil, fmt.Errorf("notary: token nesting deeper than %d — refusing to parse (possible decoder-amplification input)", maxDERDepth)
	}
	*nodes++
	if *nodes > maxDERNodes {
		return nil, fmt.Errorf("notary: token has more than %d structural elements — refusing to parse (possible decoder-amplification input)", maxDERNodes)
	}
	if len(data) < 2 {
		return nil, fmt.Errorf("notary: truncated DER element header")
	}

	b := data[0]
	off := 1
	// High-tag-number form: tag continues while the top bit is set.
	if b&0x1f == 0x1f {
		for {
			if off >= len(data) {
				return nil, fmt.Errorf("notary: truncated DER high-tag-number tag")
			}
			c := data[off]
			off++
			if c&0x80 == 0 {
				break
			}
		}
	}
	constructed := b&0x20 != 0

	if off >= len(data) {
		return nil, fmt.Errorf("notary: truncated DER length")
	}
	l := data[off]
	off++
	var length int
	switch {
	case l == 0x80:
		// Indefinite length: legal BER, never DER. This is one of the two bomb
		// shapes; reject outright.
		return nil, fmt.Errorf("notary: indefinite-length encoding is not valid DER (possible decoder-amplification input)")
	case l&0x80 == 0:
		length = int(l)
	default:
		n := int(l & 0x7f)
		if n > 4 {
			return nil, fmt.Errorf("notary: DER length field wider than 4 bytes")
		}
		if off+n > len(data) {
			return nil, fmt.Errorf("notary: truncated DER long-form length")
		}
		for range n {
			length = length<<8 | int(data[off])
			off++
		}
		if length < 0 {
			return nil, fmt.Errorf("notary: negative DER length")
		}
	}

	if off+length > len(data) {
		return nil, fmt.Errorf("notary: DER element length %d exceeds the %d bytes available (overlapping/oversized nesting)", length, len(data)-off)
	}
	content := data[off : off+length]
	rest := data[off+length:]

	if constructed {
		// Children must exactly tile the parent's content: nothing left over,
		// nothing running past the end. That is what the overlapping-definite
		// bomb violates.
		for len(content) > 0 {
			var err error
			content, err = scanDERElement(content, depth+1, nodes)
			if err != nil {
				return nil, err
			}
		}
	}
	return rest, nil
}
