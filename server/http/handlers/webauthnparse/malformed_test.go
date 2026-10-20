package webauthnparse

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"maps"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

// cborPairs encodes a CBOR map from key/value pairs in order, duplicates
// included (webauthncbor.Marshal of a Go map cannot produce one).
func cborPairs(tb testing.TB, indefinite bool, kv ...any) []byte {
	tb.Helper()
	var out []byte
	if indefinite {
		out = []byte{0xBF}
	} else {
		out = []byte{0xA0 | byte(len(kv)/2)}
	}
	for _, x := range kv {
		b, err := webauthncbor.Marshal(x)
		if err != nil {
			tb.Fatal(err)
		}
		out = append(out, b...)
	}
	if indefinite {
		out = append(out, 0xFF)
	}
	return out
}

func registrationWith(tb testing.TB, attObj []byte) []byte {
	tb.Helper()
	b, err := json.Marshal(map[string]any{
		"id": fzB64(fzCredID), "rawId": fzB64(fzCredID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": fzB64(fzClientData(tb, "webauthn.create")), "attestationObject": fzB64(attObj)},
	})
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

// TestCeremonyMalformedInputs_Refused pins how the library (go-webauthn
// v0.18.2, fxamacker/cbor via webauthncbor) treats the malformed shapes an
// attacker controls on the finish endpoints: each is refused with an error,
// none panics, none creates a credential or logs in. A dependency upgrade that
// relaxes one of these goes red here.
func TestCeremonyMalformedInputs_Refused(t *testing.T) {
	k := fzKey(t)
	cose := fzCOSEKey(t, k)
	attested := func(idLen uint16, id []byte) []byte {
		b := append(make([]byte, 16), 0, 0)
		binary.BigEndian.PutUint16(b[16:], idLen)
		return append(append(b, id...), cose...)
	}
	good := fzAuthData(t, 0x45, attested(uint16(len(fzCredID)), fzCredID))
	att := func(authData []byte) []byte {
		b, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": authData})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	nested := any(map[string]any{})
	for range 6 {
		nested = map[string]any{"n": nested}
	}
	regCases := []struct {
		name   string
		attObj []byte
	}{
		{"authData shorter than 37 bytes", att(good[:36])},
		{"AT flag without attested data", att(fzAuthData(t, 0x45, nil))},
		{"credential ID length 0xFFFF past the end", att(fzAuthData(t, 0x45, attested(0xFFFF, fzCredID)))},
		{"credential ID length 1024 (above the 1023 cap)", att(fzAuthData(t, 0x45, attested(1024, bytes.Repeat([]byte{1}, 1024))))},
		{"credential public key truncated", att(good[:len(good)-5])},
		{"trailing bytes after the key without the ED flag", att(append(append([]byte{}, good...), 0x00))},
		{"duplicate fmt key", cborPairs(t, false, "fmt", "none", "fmt", "packed", "attStmt", map[string]any{}, "authData", good)},
		{"duplicate authData key", cborPairs(t, false, "fmt", "none", "attStmt", map[string]any{}, "authData", good, "authData", good)},
		{"indefinite-length map", cborPairs(t, true, "fmt", "none", "attStmt", map[string]any{}, "authData", good)},
		{"attStmt nested 7 levels", cborPairs(t, false, "fmt", "none", "attStmt", nested, "authData", good)},
		{"attestationObject truncated", att(good)[:40]},
		{"attestationObject is not a map", []byte{0x83, 0x01, 0x02, 0x03}},
		{"none with a non-empty attStmt", cborPairs(t, false, "fmt", "none", "attStmt", map[string]any{"sig": []byte{1}}, "authData", good)},
	}
	rp := fzRP(t)
	for _, tc := range regCases {
		t.Run("registration/"+tc.name, func(t *testing.T) {
			pcc, err := protocol.ParseCredentialCreationResponseBytes(registrationWith(t, tc.attObj))
			if err == nil {
				if _, err = rp.CreateCredential(fzUser{}, fzSession(), pcc); err == nil {
					t.Fatal("accepted")
				}
			}
		})
	}

	// Assertions: the valid seed with one field changed.
	var seed map[string]any
	if err := json.Unmarshal(assertionSeed(t), &seed); err != nil {
		t.Fatal(err)
	}
	resp := seed["response"].(map[string]any)
	ad := fzAuthData(t, 0x05, nil)
	cd := fzClientData(t, "webauthn.get")
	asCases := []struct {
		name, field string
		value       []byte
	}{
		{"authenticatorData truncated", "authenticatorData", ad[:36]},
		{"authenticatorData with trailing bytes", "authenticatorData", append(append([]byte{}, ad...), 0)},
		{"signature over other authenticatorData", "authenticatorData", fzAuthData(t, 0x01, nil)},
		{"empty signature", "signature", nil},
		{"signature truncated", "signature", fzSign(t, k, ad, cd)[:20]},
		{"clientDataJSON not JSON", "clientDataJSON", []byte("{")},
		{"clientDataJSON of type webauthn.create", "clientDataJSON", fzClientData(t, "webauthn.create")},
		{"userHandle of another user", "userHandle", []byte("someone-else")},
	}
	user := fzStoredUser(t)
	for _, tc := range asCases {
		t.Run("assertion/"+tc.name, func(t *testing.T) {
			r := maps.Clone(resp)
			r[tc.field] = fzB64(tc.value)
			b, err := json.Marshal(map[string]any{"id": seed["id"], "rawId": seed["rawId"], "type": seed["type"], "response": r})
			if err != nil {
				t.Fatal(err)
			}
			pcr, err := protocol.ParseCredentialRequestResponseBytes(b)
			if err == nil {
				if _, err = rp.ValidateLogin(user, fzSession(), pcr); err == nil {
					t.Fatal("accepted")
				}
			}
		})
	}
}
