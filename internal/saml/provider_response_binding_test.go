package saml

// provider_response_binding_test.go: more probes for the namespace-strict assertion
// shape check, plus the binding (artifact), encryption and depth refusals.

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/beevik/etree"
	csaml "github.com/crewjam/saml"
	"github.com/stretchr/testify/require"
)

func TestParseResponse_StrictShape_RefusesRebindingAndExtraIdentifiers(t *testing.T) {
	cases := map[string]func(*etree.Element){
		"saml prefix rebound to a foreign namespace on NameID": func(a *etree.Element) {
			nid := childByTag(childByTag(a, "Subject"), "NameID")
			nid.CreateAttr("xmlns:saml", "urn:example:not-saml")
		},
		"default namespace redeclared foreign on NameID": func(a *etree.Element) {
			nid := childByTag(childByTag(a, "Subject"), "NameID")
			nid.Space = ""
			nid.CreateAttr("xmlns", "urn:example:not-saml")
		},
		"saml prefix rebound on Subject": func(a *etree.Element) {
			childByTag(a, "Subject").CreateAttr("xmlns:saml", "urn:example:not-saml")
		},
		"EncryptedID beside NameID": func(a *etree.Element) {
			s := childByTag(a, "Subject")
			s.InsertChildAt(1, etree.NewElement("saml:EncryptedID"))
		},
		"EncryptedID in a foreign namespace beside NameID": func(a *etree.Element) {
			e := etree.NewElement("x:EncryptedID")
			e.CreateAttr("xmlns:x", "urn:example:not-saml")
			childByTag(a, "Subject").InsertChildAt(1, e)
		},
		"NameID with a child element": func(a *etree.Element) {
			nid := childByTag(childByTag(a, "Subject"), "NameID")
			nid.CreateElement("saml:NameID").SetText("attacker@corp.example")
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p, acsURL, b64 := buildSignedResponseB64WithAssertion(t, mutate)
			info, err := submitSAMLResponse(t, p, acsURL, b64)
			require.ErrorIs(t, err, errInvalidSAMLResponse)
			require.Nil(t, info)
		})
	}
}

func TestParseResponse_StrictShape_AcceptsCommentInNameID(t *testing.T) {
	cases := map[string]func(*etree.Element){
		"comment inside NameID (both readers concatenate)": func(a *etree.Element) {
			nid := childByTag(childByTag(a, "Subject"), "NameID")
			nid.SetText("user@corp")
			nid.CreateComment("x")
			nid.CreateText(".example")
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p, acsURL, b64 := buildSignedResponseB64WithAssertion(t, mutate)
			info, err := submitSAMLResponse(t, p, acsURL, b64)
			require.NoError(t, err)
			require.Equal(t, "user@corp.example", info.Subject)
		})
	}
}

// TestParseResponse_RefusesArtifactBinding: crewjam's ParseResponse switches to the
// artifact binding when req.Form (query string included) carries SAMLart, and then never
// reads the SAMLResponse the shape check parsed. The artifact path must be refused before
// any outbound resolution call.
func TestParseResponse_RefusesArtifactBinding(t *testing.T) {
	p, acsURL, b64 := buildSignedResponseB64(t)
	var hits atomic.Int32
	ars := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ars.Close()
	for i := range p.sp.IDPMetadata.IDPSSODescriptors {
		p.sp.IDPMetadata.IDPSSODescriptors[i].ArtifactResolutionServices = []csaml.Endpoint{
			{Binding: csaml.SOAPBinding, Location: ars.URL},
		}
	}
	const art = "AAQAAMFbLinlXaCM+FIxiDwGOLAy2T71gbpO7ZhNzAgEANlB90ECfpNEVLg="
	for name, tc := range map[string]struct {
		target string
		body   url.Values
	}{
		"SAMLart in query":           {acsURL + "?" + url.Values{"SAMLart": {art}}.Encode(), url.Values{"SAMLResponse": {b64}}},
		"SAMLart in body":            {acsURL, url.Values{"SAMLResponse": {b64}, "SAMLart": {art}}},
		"empty SAMLart then a value": {acsURL + "?SAMLart=&SAMLart=" + url.QueryEscape(art), url.Values{"SAMLResponse": {b64}}},
		"empty SAMLart only":         {acsURL + "?SAMLart=", url.Values{"SAMLResponse": {b64}}},
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.target, strings.NewReader(tc.body.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			require.NoError(t, req.ParseForm())
			info, err := p.ParseResponse(req, nil)
			require.ErrorIs(t, err, errInvalidSAMLResponse)
			require.Nil(t, info)
			require.Zero(t, hits.Load(), "artifact resolution service was contacted")
		})
	}
}

// TestStrictAssertionShape_RefusesEncryptedAssertion: the library returns a decrypted
// assertion ahead of a plaintext one, so an EncryptedAssertion beside the Assertion this
// check reads must be refused.
func TestStrictAssertionShape_RefusesEncryptedAssertion(t *testing.T) {
	const doc = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<saml:EncryptedAssertion/>` +
		`<saml:Assertion><saml:Subject><saml:NameID>user@corp.example</saml:NameID></saml:Subject><saml:Conditions/></saml:Assertion>` +
		`</samlp:Response>`
	for name, d := range map[string]string{
		"plaintext only":          strings.Replace(doc, `<saml:EncryptedAssertion/>`, "", 1),
		"with EncryptedAssertion": doc,
		"EncryptedAssertion, default namespace": strings.Replace(doc, `<saml:EncryptedAssertion/>`,
			`<EncryptedAssertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion"/>`, 1),
		"EncryptedAssertion, other prefix": strings.Replace(doc, `<saml:EncryptedAssertion/>`,
			`<a2:EncryptedAssertion xmlns:a2="urn:oasis:names:tc:SAML:2.0:assertion"/>`, 1),
		"EncryptedAssertion, foreign namespace": strings.Replace(doc, `<saml:EncryptedAssertion/>`,
			`<x:EncryptedAssertion xmlns:x="urn:example:not-saml"/>`, 1),
		"second root element": strings.Replace(doc, `<saml:EncryptedAssertion/>`, "", 1) +
			strings.Replace(doc, `<saml:EncryptedAssertion/>`, "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/acs", strings.NewReader(url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString([]byte(d))}}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			require.NoError(t, req.ParseForm())
			nameID, err := strictAssertionShape(req)
			if name == "plaintext only" {
				require.NoError(t, err)
				require.Equal(t, "user@corp.example", nameID)
				return
			}
			require.Error(t, err)
		})
	}
}

func TestStrictAssertionShape_RefusesDeepNesting(t *testing.T) {
	doc := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">` + strings.Repeat("<a>", 1000) + strings.Repeat("</a>", 1000) + `</samlp:Response>`
	req := httptest.NewRequest(http.MethodPost, "/acs", strings.NewReader(url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString([]byte(doc))}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	require.NoError(t, req.ParseForm())
	_, err := strictAssertionShape(req)
	require.ErrorContains(t, err, "nests deeper")
}
