package saml

// provider_epilogue_test.go is a deterministic regression test for the signature-bypass
// FuzzParseResponse found: neither this package's XML-DSig verification nor crewjam/saml's
// own internal xrv.Validate reject a validly-signed response with bytes appended after its
// root element closes (an "XML epilogue") -- xrv checks per-token round-trip fidelity, not
// document structure, and a trailing plain-text or comment token round-trips cleanly.
//
// The fuzz seed reproduced this only probabilistically (naively string-concatenating onto
// the base64 text lands on a byte alignment that breaks base64 decoding more often than
// not), so this test builds the tampered input the reliable way: decode the valid,
// per-run-unique signed response to raw XML, append real bytes, then re-encode -- valid
// base64 regardless of length, every run.

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	csaml "github.com/crewjam/saml"
	"github.com/stretchr/testify/require"
)

// buildSignedResponseB64 returns one genuinely valid, signed, IDP-initiated SAMLResponse
// (base64, undecoded) plus the Provider that trusts it -- the same construction
// TestParseResponse_Success uses, factored out so tampering tests can mutate the decoded
// bytes before re-submitting.
func buildSignedResponseB64(t *testing.T) (p *Provider, acsURL string, validB64 string) {
	t.Helper()
	return buildSignedResponseB64WithAssertion(t, nil)
}

// buildSignedResponseB64WithAssertion is buildSignedResponseB64 with a hook: when mutate
// is non-nil, it is applied to the unsigned Assertion element, which is then signed with
// the trusted IdP key -- a validly signed assertion of any shape the test needs.
func buildSignedResponseB64WithAssertion(t *testing.T, mutate func(assertion *etree.Element)) (p *Provider, acsURL string, validB64 string) {
	t.Helper()
	const idpEntityID = "https://idp.example/entity"
	const spEntityID = "https://keyorix.internal/saml/corp/metadata"
	acsURL = "https://keyorix.internal/auth/saml/corp/acs"

	idpMD, idpKey, idpCert := signedIDPFixture(t, idpEntityID)

	p, err := NewProvider(Config{
		Name:              "corp",
		IDPMetadataXML:    idpMD,
		SPEntityID:        spEntityID,
		ACSURL:            acsURL,
		AllowIDPInitiated: true,
		EmailAttr:         "mail",
		NameAttr:          "cn",
		GroupsAttr:        "eduPersonAffiliation",
	})
	require.NoError(t, err)

	idpMetadataURL, err := url.Parse(idpEntityID)
	require.NoError(t, err)
	idp := &csaml.IdentityProvider{Key: idpKey, Certificate: idpCert, MetadataURL: *idpMetadataURL}
	spMetadata := p.sp.Metadata()

	var acsEndpoint *csaml.IndexedEndpoint
	var spssoDescriptor *csaml.SPSSODescriptor
	for i := range spMetadata.SPSSODescriptors {
		d := spMetadata.SPSSODescriptors[i]
		for j := range d.AssertionConsumerServices {
			ep := d.AssertionConsumerServices[j]
			if ep.Binding == csaml.HTTPPostBinding {
				acsEndpoint = &ep
				spssoDescriptor = &d
				break
			}
		}
		if acsEndpoint != nil {
			break
		}
	}
	require.NotNil(t, acsEndpoint)

	idpReq := &csaml.IdpAuthnRequest{
		IDP:                     idp,
		HTTPRequest:             httptest.NewRequest(http.MethodGet, "https://idp.example/sso", nil),
		RelayState:              "return-here",
		ServiceProviderMetadata: spMetadata,
		SPSSODescriptor:         spssoDescriptor,
		ACSEndpoint:             acsEndpoint,
		Now:                     time.Now(),
	}
	session := &csaml.Session{
		ID:             "sess-1",
		CreateTime:     time.Now(),
		ExpireTime:     time.Now().Add(time.Hour),
		NameID:         "user@corp.example",
		UserEmail:      "user@corp.example",
		UserCommonName: "User Corp",
		Groups:         []string{"admins", "devs"},
	}
	require.NoError(t, csaml.DefaultAssertionMaker{}.MakeAssertion(idpReq, session))
	if mutate != nil {
		idpReq.AssertionEl = signMutatedAssertion(t, idpReq.Assertion.Element(), mutate, idpKey, idpCert)
	}
	form, err := idpReq.PostBinding()
	require.NoError(t, err)
	return p, acsURL, form.SAMLResponse
}

func submitSAMLResponse(t *testing.T, p *Provider, acsURL, samlResponseB64 string) (*AssertionInfo, error) {
	t.Helper()
	body := url.Values{"SAMLResponse": {samlResponseB64}}.Encode()
	req := httptest.NewRequest(http.MethodPost, acsURL, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	require.NoError(t, req.ParseForm())
	return p.ParseResponse(req, nil)
}

func TestParseResponse_RejectsXMLEpilogue(t *testing.T) {
	p, acsURL, validB64 := buildSignedResponseB64(t)
	decoded, err := base64.StdEncoding.DecodeString(validB64)
	require.NoError(t, err)

	tamper := func(suffix string) string {
		return base64.StdEncoding.EncodeToString(append(append([]byte{}, decoded...), []byte(suffix)...))
	}

	cases := []struct {
		name   string
		suffix string
	}{
		{"plain text", "AAA"},
		{"comment (can carry arbitrary attacker bytes)", "<!--AAA-->"},
		{"second top-level element", "<x/>"},
		{"processing instruction", "<?x?>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info, err := submitSAMLResponse(t, p, acsURL, tamper(tc.suffix))
			if err == nil {
				t.Fatalf("SIGNATURE BYPASS: response with trailing %q was accepted: %+v", tc.suffix, info)
			}
			require.Nil(t, info)
		})
	}
}

// TestParseResponse_AllowsTrailingWhitespace guards the condition the rejection above
// depends on: real IdPs commonly emit a trailing newline after the closing tag, so the
// epilogue check must reject non-whitespace content specifically, not any content at all.
func TestParseResponse_AllowsTrailingWhitespace(t *testing.T) {
	p, acsURL, validB64 := buildSignedResponseB64(t)
	decoded, err := base64.StdEncoding.DecodeString(validB64)
	require.NoError(t, err)

	withTrailingNewline := base64.StdEncoding.EncodeToString(append(append([]byte{}, decoded...), '\n'))
	info, err := submitSAMLResponse(t, p, acsURL, withTrailingNewline)
	require.NoError(t, err, "a trailing newline alone must not be treated as an attack")
	require.NotNil(t, info)
	require.Equal(t, "user@corp.example", info.Subject)
}
