package core

import (
	"encoding/json"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// referenceVersionMetadataStatus is the two-decode classifier versionMetadataStatus
// replaced. It is the oracle: the single-decode version must agree on every input.
func referenceVersionMetadataStatus(meta models.JSON) metadataStatus {
	if len(meta) == 0 {
		return metadataPlaintext
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(meta, &fields); err != nil {
		return metadataAmbiguous
	}
	if len(fields) == 0 {
		return metadataPlaintext
	}
	var m struct {
		Algorithm string `json:"algorithm"`
	}
	if err := json.Unmarshal(meta, &m); err != nil {
		return metadataAmbiguous
	}
	if m.Algorithm == "" {
		return metadataAmbiguous
	}
	return metadataEncrypted
}

var metadataStatusCorpus = []string{
	``, `{}`, ` { } `, `null`, ` null `, `[]`, `[{}]`, `"x"`, `5`, `true`, `{`, `{"algorithm"`, `garbage`,
	`{"algorithm":"aes-256-gcm"}`, `{"algorithm":"aes-256-gcm","nonce":"abc"}`,
	`{"algorithm":""}`, `{"algorithm":null}`, `{"algorithm":5}`, `{"algorithm":["a"]}`, `{"algorithm":{"a":1}}`,
	`{"Algorithm":"x"}`, `{"ALGORITHM":"x"}`, `{"algorithm":"a","Algorithm":""}`, `{"Algorithm":"","algorithm":"a"}`,
	`{"algorithm":"a","algorithm":""}`, `{"algorithm":"","algorithm":"a"}`,
	`{"other":1}`, `{"other":"x","nonce":"y"}`, `{"algorithm":"x"} trailing`, `{"algorithm":"x"}{}`,
	"\x00\x01", `{"a":}`, `{"algorithm":"aes"}`,
}

func TestVersionMetadataStatus_SingleDecodeMatchesReference(t *testing.T) {
	for _, in := range metadataStatusCorpus {
		if got, want := versionMetadataStatus(models.JSON(in)), referenceVersionMetadataStatus(models.JSON(in)); got != want {
			t.Errorf("input %q: got %v, reference %v", in, got, want)
		}
	}
	if versionMetadataStatus(nil) != metadataPlaintext {
		t.Error("nil metadata must stay plaintext")
	}
}

func FuzzVersionMetadataStatus_MatchesReference(f *testing.F) {
	for _, in := range metadataStatusCorpus {
		f.Add([]byte(in))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		if got, want := versionMetadataStatus(models.JSON(in)), referenceVersionMetadataStatus(models.JSON(in)); got != want {
			t.Fatalf("input %q: got %v, reference %v", in, got, want)
		}
	})
}

func BenchmarkVersionMetadataStatus_Encrypted(b *testing.B) {
	meta := models.JSON(`{"algorithm":"aes-256-gcm","key_id":"k1","nonce":"AAAAAAAAAAAAAAAA"}`)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if versionMetadataStatus(meta) != metadataEncrypted {
			b.Fatal("unexpected status")
		}
	}
}

func BenchmarkVersionMetadataStatus_EncryptedReference(b *testing.B) {
	meta := models.JSON(`{"algorithm":"aes-256-gcm","key_id":"k1","nonce":"AAAAAAAAAAAAAAAA"}`)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if referenceVersionMetadataStatus(meta) != metadataEncrypted {
			b.Fatal("unexpected status")
		}
	}
}
