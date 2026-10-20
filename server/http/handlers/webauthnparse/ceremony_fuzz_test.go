package webauthnparse

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// The ceremony targets below run what the WebAuthn finish handlers run after
// the parse (server/http/handlers/webauthn.go -> internal/core/webauthn.go):
// webauthn.CreateCredential for registration and webauthn.ValidateLogin for
// login, reauth and passwordless. FuzzWebAuthnCredentialResponse stops at the
// parse, but the attestation statement of every format (packed, tpm,
// android-key, android-safetynet, fido-u2f, apple, compound: x5c certificates,
// TPM certInfo/pubArea structures, JWS) is decoded only in CreateCredential's
// verification, so the parse-only target never reached it. The seeds are real
// ceremonies for a fixed relying party, challenge and key, so mutations start
// past the challenge, origin and rpIdHash checks.
//
// Reachability: registration-finish needs a logged-in user who re-authenticates
// (TOTP or password); the assertion paths are reached before authentication.

const (
	fzRPID   = "localhost"
	fzOrigin = "https://localhost"
)

var (
	fzChallengeRaw = bytes.Repeat([]byte{0xC7}, 32)
	fzChallenge    = base64.RawURLEncoding.EncodeToString(fzChallengeRaw)
	fzUserID       = []byte("keyorix-fuzz-user-0001")
	fzCredID       = bytes.Repeat([]byte{0x5A}, 32)
)

// fzKey is a fixed P-256 credential key, so the committed corpus's assertion
// signatures verify against the credential the assertion target stores.
func fzKey(tb testing.TB) *ecdsa.PrivateKey {
	tb.Helper()
	d := sha256.Sum256([]byte("keyorix webauthnparse fuzz credential key"))
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d[:])
	if err != nil {
		tb.Fatal(err)
	}
	return k
}

type fzUser struct{ creds []webauthn.Credential }

func (u fzUser) WebAuthnID() []byte                         { return fzUserID }
func (u fzUser) WebAuthnName() string                       { return "fuzz" }
func (u fzUser) WebAuthnDisplayName() string                { return "fuzz" }
func (u fzUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func fzRP(tb testing.TB) *webauthn.WebAuthn {
	tb.Helper()
	// Same fields server/main.go sets; everything else is the library default.
	rp, err := webauthn.New(&webauthn.Config{RPID: fzRPID, RPDisplayName: "Keyorix", RPOrigins: []string{fzOrigin}})
	if err != nil {
		tb.Fatal(err)
	}
	return rp
}

func fzSession() webauthn.SessionData {
	return webauthn.SessionData{
		Challenge:        fzChallenge,
		RelyingPartyID:   fzRPID,
		UserID:           fzUserID,
		Expires:          time.Now().Add(time.Hour),
		UserVerification: protocol.VerificationPreferred,
		CredParams:       webauthn.CredentialParametersDefault(), // what BeginRegistration records
	}
}

func fzCOSEKey(tb testing.TB, k *ecdsa.PrivateKey) []byte {
	tb.Helper()
	raw, err := k.PublicKey.Bytes() // 0x04 || X || Y
	if err != nil {
		tb.Fatal(err)
	}
	b, err := webauthncbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: raw[1:33], -3: raw[33:65]})
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

func fzAuthData(tb testing.TB, flags byte, attested []byte) []byte {
	tb.Helper()
	h := sha256.Sum256([]byte(fzRPID))
	out := append([]byte{}, h[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, 1)
	return append(out, attested...)
}

func fzClientData(tb testing.TB, typ string) []byte {
	tb.Helper()
	b, err := json.Marshal(map[string]any{"type": typ, "challenge": fzChallenge, "origin": fzOrigin, "crossOrigin": false})
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

func fzSign(tb testing.TB, k *ecdsa.PrivateKey, authData, clientData []byte) []byte {
	tb.Helper()
	cdh := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authData...), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k, digest[:])
	if err != nil {
		tb.Fatal(err)
	}
	return sig
}

func fzCert(tb testing.TB, k *ecdsa.PrivateKey) []byte {
	tb.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "keyorix fuzz attestation"},
		NotBefore: time.Unix(0, 0), NotAfter: time.Unix(4102444800, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		tb.Fatal(err)
	}
	return der
}

func fzB64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// registrationSeeds returns attestation responses: a valid "none" and a valid
// packed self-attestation, then well-shaped statements of the other formats
// whose contents fail verification deeper inside each format's parser.
func registrationSeeds(tb testing.TB) [][]byte {
	tb.Helper()
	k := fzKey(tb)
	attested := append(append(make([]byte, 16), byte(len(fzCredID)>>8), byte(len(fzCredID))), fzCredID...)
	attested = append(attested, fzCOSEKey(tb, k)...)
	authData := fzAuthData(tb, 0x45, attested) // UP | UV | AT
	cd := fzClientData(tb, "webauthn.create")
	sig := fzSign(tb, k, authData, cd)
	cert := fzCert(tb, k)
	stmts := []struct {
		fmt  string
		stmt any
	}{
		{"none", map[string]any{}},
		{"packed", map[string]any{"alg": -7, "sig": sig}},
		{"packed", map[string]any{"alg": -7, "sig": sig, "x5c": [][]byte{cert}}},
		{"fido-u2f", map[string]any{"sig": sig, "x5c": [][]byte{cert}}},
		{"android-key", map[string]any{"alg": -7, "sig": sig, "x5c": [][]byte{cert}}},
		{"apple", map[string]any{"x5c": [][]byte{cert}}},
		{"tpm", map[string]any{"ver": "2.0", "alg": -7, "sig": sig, "x5c": [][]byte{cert},
			"certInfo": append([]byte{0xff, 'T', 'C', 'G', 0x80, 0x17}, make([]byte, 64)...), "pubArea": append([]byte{0x00, 0x23, 0x00, 0x0b}, make([]byte, 64)...)}},
		{"android-safetynet", map[string]any{"ver": "1", "response": []byte("eyJhbGciOiJFUzI1NiJ9.eyJub25jZSI6IiJ9.c2ln")}},
		{"compound", []any{map[string]any{"fmt": "none", "attStmt": map[string]any{}}, map[string]any{"fmt": "packed", "attStmt": map[string]any{"alg": -7, "sig": sig}}}},
	}
	var out [][]byte
	for _, s := range stmts {
		att, err := webauthncbor.Marshal(map[string]any{"fmt": s.fmt, "attStmt": s.stmt, "authData": authData})
		if err != nil {
			tb.Fatal(err)
		}
		b, err := json.Marshal(map[string]any{
			"id": fzB64(fzCredID), "rawId": fzB64(fzCredID), "type": "public-key",
			"response": map[string]any{"clientDataJSON": fzB64(cd), "attestationObject": fzB64(att)},
		})
		if err != nil {
			tb.Fatal(err)
		}
		out = append(out, b)
	}
	return out
}

// assertionSeed returns a valid assertion by fzKey for fzCredID.
func assertionSeed(tb testing.TB) []byte {
	tb.Helper()
	k := fzKey(tb)
	authData := fzAuthData(tb, 0x05, nil) // UP | UV
	cd := fzClientData(tb, "webauthn.get")
	b, err := json.Marshal(map[string]any{
		"id": fzB64(fzCredID), "rawId": fzB64(fzCredID), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON": fzB64(cd), "authenticatorData": fzB64(authData),
			"signature": fzB64(fzSign(tb, k, authData, cd)), "userHandle": fzB64(fzUserID),
		},
	})
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

// TestCeremonySeeds_AreAcceptedByTheLibrary proves the seeds start where they
// claim: the "none" and packed registrations and the assertion pass the same
// verification the handlers run, so the fuzzer begins past the outer checks.
func TestCeremonySeeds_AreAcceptedByTheLibrary(t *testing.T) {
	rp := fzRP(t)
	regs := registrationSeeds(t)
	for i, name := range []string{"none", "packed self"} {
		pcc, err := protocol.ParseCredentialCreationResponseBytes(regs[i])
		if err != nil {
			t.Fatalf("%s seed does not parse: %v", name, err)
		}
		if _, err := rp.CreateCredential(fzUser{}, fzSession(), pcc); err != nil {
			t.Fatalf("%s seed is rejected: %v", name, err)
		}
	}
	pcr, err := protocol.ParseCredentialRequestResponseBytes(assertionSeed(t))
	if err != nil {
		t.Fatalf("assertion seed does not parse: %v", err)
	}
	if _, err := rp.ValidateLogin(fzStoredUser(t), fzSession(), pcr); err != nil {
		t.Fatalf("assertion seed is rejected: %v", err)
	}
}

func fzStoredUser(tb testing.TB) fzUser {
	tb.Helper()
	return fzUser{creds: []webauthn.Credential{{ID: fzCredID, PublicKey: fzCOSEKey(tb, fzKey(tb))}}}
}

// FuzzWebAuthnRegistrationCeremony: parse plus CreateCredential, as
// FinishWebAuthnRegistration runs them. Invariants: no panic or hang; no error
// together with a credential; a created credential implies the checks the
// relying party must make on registration held (type webauthn.create, the
// session's challenge, an allowed origin, this RP's rpIdHash, user presence,
// an attested credential whose ID and key are the ones returned).
func FuzzWebAuthnRegistrationCeremony(f *testing.F) {
	for _, s := range registrationSeeds(f) {
		f.Add(s)
	}
	rp := fzRP(f)
	rpIDHash := sha256.Sum256([]byte(fzRPID))
	f.Fuzz(func(t *testing.T, data []byte) {
		var (
			pcc  *protocol.ParsedCredentialCreationData
			cred *webauthn.Credential
			err  error
		)
		fuzzutil.Guard(t.Fatalf, "CreateCredential", func() {
			if pcc, err = protocol.ParseCredentialCreationResponseBytes(data); err != nil {
				return
			}
			cred, err = rp.CreateCredential(fzUser{}, fzSession(), pcc)
		})
		if err != nil {
			if cred != nil {
				t.Fatalf("CreateCredential returned an error and a credential: %v", err)
			}
			return
		}
		if cred == nil {
			t.Fatal("CreateCredential returned neither an error nor a credential")
		}
		cdd, ad := pcc.Response.CollectedClientData, pcc.Response.AttestationObject.AuthData
		switch {
		case cdd.Type != protocol.CreateCeremony:
			t.Fatalf("credential created from client data of type %q", cdd.Type)
		case cdd.Challenge != fzChallenge:
			t.Fatalf("credential created for challenge %q, session had %q", cdd.Challenge, fzChallenge)
		case cdd.Origin != fzOrigin:
			t.Fatalf("credential created from origin %q", cdd.Origin)
		case !bytes.Equal(ad.RPIDHash, rpIDHash[:]):
			t.Fatalf("credential created with rpIdHash %x", ad.RPIDHash)
		case !ad.Flags.HasUserPresent():
			t.Fatal("credential created without user presence")
		case !bytes.Equal(cred.ID, ad.AttData.CredentialID) || !bytes.Equal(cred.PublicKey, ad.AttData.CredentialPublicKey):
			t.Fatal("created credential differs from the attested credential data")
		}
	})
}

// FuzzWebAuthnAssertionCeremony: parse plus ValidateLogin against one stored
// credential (fzKey), as the login, reauth and passwordless finish paths run
// them. Invariants: no panic or hang; no error together with a credential; a
// successful login implies an independent ECDSA check of the signature over
// authenticatorData || SHA-256(clientDataJSON) under the stored key, the
// session's challenge, type webauthn.get, an allowed origin, this RP's
// rpIdHash, user presence and the stored credential ID.
func FuzzWebAuthnAssertionCeremony(f *testing.F) {
	f.Add(assertionSeed(f))
	rp := fzRP(f)
	user := fzStoredUser(f)
	pub := &fzKey(f).PublicKey
	rpIDHash := sha256.Sum256([]byte(fzRPID))
	f.Fuzz(func(t *testing.T, data []byte) {
		var (
			pcr  *protocol.ParsedCredentialAssertionData
			cred *webauthn.Credential
			err  error
		)
		fuzzutil.Guard(t.Fatalf, "ValidateLogin", func() {
			if pcr, err = protocol.ParseCredentialRequestResponseBytes(data); err != nil {
				return
			}
			cred, err = rp.ValidateLogin(user, fzSession(), pcr)
		})
		if err != nil {
			if cred != nil {
				t.Fatalf("ValidateLogin returned an error and a credential: %v", err)
			}
			return
		}
		if cred == nil {
			t.Fatal("ValidateLogin returned neither an error nor a credential")
		}
		rawAD, rawCD := pcr.Raw.AssertionResponse.AuthenticatorData, pcr.Raw.AssertionResponse.ClientDataJSON
		cdh := sha256.Sum256(rawCD)
		digest := sha256.Sum256(append(append([]byte{}, rawAD...), cdh[:]...))
		cdd, ad := pcr.Response.CollectedClientData, pcr.Response.AuthenticatorData
		switch {
		case !ecdsa.VerifyASN1(pub, digest[:], pcr.Response.Signature):
			t.Fatal("login accepted a signature the stored key does not verify")
		case cdd.Type != protocol.AssertCeremony:
			t.Fatalf("login accepted client data of type %q", cdd.Type)
		case cdd.Challenge != fzChallenge:
			t.Fatalf("login accepted challenge %q, session had %q", cdd.Challenge, fzChallenge)
		case cdd.Origin != fzOrigin:
			t.Fatalf("login accepted origin %q", cdd.Origin)
		case !bytes.Equal(ad.RPIDHash, rpIDHash[:]):
			t.Fatalf("login accepted rpIdHash %x", ad.RPIDHash)
		case !ad.Flags.HasUserPresent():
			t.Fatal("login accepted without user presence")
		case !bytes.Equal(cred.ID, fzCredID):
			t.Fatalf("login returned credential %x, only %x is stored", cred.ID, fzCredID)
		}
	})
}
