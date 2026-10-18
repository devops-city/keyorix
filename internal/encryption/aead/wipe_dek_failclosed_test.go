package aead

import (
	"errors"
	"testing"
)

// TestWipeDEK_ServiceRefusesUseAfterWipe pins WipeDEK to ending the service's
// ability to use the key, not only to zeroing es.dek. cipher.NewGCM keeps its
// own expanded AES key schedule, so before REVIEW-COVERAGE-1 a wiped service
// (IsDEKWiped()==true) still encrypted and decrypted with the superseded DEK:
// any reference that outlived a rotation or Shutdown kept a working key, and
// IsDEKWiped reported the opposite. Every operation must now fail with
// ErrDEKWiped. (The schedule itself stays in memory until the GC reclaims the
// cipher: crypto/aes offers no way to zero it.)
func TestWipeDEK_ServiceRefusesUseAfterWipe(t *testing.T) {
	key, err := GenerateRandomKey(32)
	if err != nil {
		t.Fatal(err)
	}
	es, err := NewEncryptionService(key)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := es.Encrypt([]byte("before-wipe"), "v1")
	if err != nil {
		t.Fatal(err)
	}
	sealedAAD, err := es.EncryptWithAAD([]byte("before-wipe"), "v1", []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	chunks, err := es.EncryptChunked([]byte("before-wipe-chunked"), 4, "v1")
	if err != nil {
		t.Fatal(err)
	}

	es.WipeDEK()

	ops := map[string]func() error{
		"Encrypt": func() error { _, err := es.Encrypt([]byte("x"), "v1"); return err },
		"EncryptWithAAD": func() error {
			_, err := es.EncryptWithAAD([]byte("x"), "v1", []byte("aad"))
			return err
		},
		"EncryptChunked": func() error { _, err := es.EncryptChunked([]byte("xyz"), 1, "v1"); return err },
		"Decrypt":        func() error { _, err := es.Decrypt(sealed); return err },
		"DecryptWithAAD": func() error { _, err := es.DecryptWithAAD(sealedAAD, []byte("aad")); return err },
		"DecryptChunked": func() error { _, err := es.DecryptChunked(chunks); return err },
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			err := op()
			if !errors.Is(err, ErrDEKWiped) {
				t.Fatalf("%s after WipeDEK: err = %v, want ErrDEKWiped (the wiped service must not use the old key schedule)", name, err)
			}
		})
	}
}
