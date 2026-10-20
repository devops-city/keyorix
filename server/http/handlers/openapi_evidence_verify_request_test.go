package handlers

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/require"
)

// verifyEvidenceRequestSchema loads POST /api/v1/compliance/evidence/verify's
// application/json request schema from openapi.yaml.
func verifyEvidenceRequestSchema(t *testing.T) *openapi3.Schema {
	t.Helper()
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile("openapi.yaml")
	require.NoError(t, err)
	item := doc.Paths.Find("/api/v1/compliance/evidence/verify")
	require.NotNil(t, item, "verify path missing from openapi.yaml")
	require.NotNil(t, item.Post)
	require.NotNil(t, item.Post.RequestBody)
	media := item.Post.RequestBody.Value.Content.Get("application/json")
	require.NotNil(t, media)
	return media.Schema.Value
}

// TestContract_EvidenceVerifyRequest_RequiresFilename: the evidence signature is
// bound to the pack's canonical filename (AUD-009; core.VerifyEvidenceSignature
// MACs filename + 0x00 + data), so a verify request without `filename` can never
// verify. The request schema must say so: GET /compliance/evidence returns
// {filename, data_b64, signature} and a client that follows the spec has to send
// all three back (DEMO-E2E-1: the schema listed only data_b64 and signature, so
// a spec-following client built a request the server could never accept as valid).
func TestContract_EvidenceVerifyRequest_RequiresFilename(t *testing.T) {
	schema := verifyEvidenceRequestSchema(t)

	require.Contains(t, schema.Properties, "filename", "request schema must declare filename")
	require.Contains(t, schema.Required, "filename", "request schema must require filename")

	// What GET /compliance/evidence hands a client, sent back verbatim, is valid.
	full := map[string]any{
		"filename":  "keyorix-evidence-20060102T150405Z.json",
		"data_b64":  "aGVsbG8=",
		"signature": "1:" + "00",
	}
	require.NoError(t, schema.VisitJSON(full))

	// A request without filename is rejected by the schema.
	noName := map[string]any{"data_b64": full["data_b64"], "signature": full["signature"]}
	require.Error(t, schema.VisitJSON(noName), "a request without filename must not validate")
}
