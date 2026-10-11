// Package awskms implements crypto.KMSClient against AWS KMS (ADR-041). It is the
// only place the AWS KMS SDK is imported, keeping internal/crypto cloud-SDK-free.
// Region and credentials come from the standard AWS chain (env, instance profile,
// IRSA, …) — never from Keyorix config.
package awskms

import (
	"context"
	"fmt"
	"log"
	"maps"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	keyorixcrypto "github.com/keyorixhq/keyorix/internal/crypto"
)

// awsKMSAPI is the slice of the KMS client the provider uses — an interface seam so
// the SDK stays contained here and the encryption-context fallback is unit-testable.
type awsKMSAPI interface {
	Encrypt(ctx context.Context, in *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(ctx context.Context, in *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
	DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
}

// FallbackHook, when non-nil, is invoked after a Decrypt succeeds ONLY via the
// no-context fallback retry (allowFallback, see New's doc comment) — i.e. every
// time this client actually used the weaker, unbound decrypt path. Lets a caller
// (internal/encryption.Service) turn that event into a durable audit record
// instead of only the log.Printf line this file always emits. Best-effort: called
// synchronously from Decrypt, so it must not block or panic.
type FallbackHook func(ctx context.Context, keyID string)

type client struct {
	kms           awsKMSAPI
	keyID         string
	encCtx        map[string]string // AWS EncryptionContext bound to the wrapped KEK (may be empty)
	allowFallback bool              // #123: opt-in, see KMSAllowContextFallback's doc comment
	fallbackHook  FallbackHook      // optional; see FallbackHook's doc comment
}

// New builds an AWS-KMS-backed crypto.KMSClient for the given key (ID, ARN, or
// alias). It loads the default AWS config; the caller's environment supplies the
// region and credentials. keyID is resolved ONCE, here, to its canonical key ARN
// via kms:DescribeKey (which accepts an ID, ARN, or alias and always returns the
// immutable ARN) and that ARN — never the original alias — is what every
// subsequent Encrypt/Decrypt pins as KeyId. This matters because an alias is a
// mutable pointer: whoever holds alias-management IAM privilege can repoint
// "alias/foo" to a different CMK at any time with zero visibility from this
// codebase, which would otherwise silently undermine the confused-deputy KeyId
// pinning this client relies on (see TestAWSKMS_CrossInstallDenied). Resolution
// failure is fatal — New fails closed rather than falling back to pinning the
// possibly-mutable alias verbatim.
//
// encContext, when non-empty, is bound to the wrapped KEK so a different install
// sharing the same CMK cannot unwrap it — UNLESS allowFallback is also set, in
// which case a context-bound Decrypt failure retries once without any context
// (see config.KeyProviderConfig.KMSAllowContextFallback for the full rationale;
// default false = the binding is strictly enforced). fallbackHook, if non-nil, is
// called on every successful use of that fallback path — see FallbackHook.
func New(ctx context.Context, keyID string, encContext map[string]string, allowFallback bool, fallbackHook FallbackHook) (keyorixcrypto.KMSClient, error) {
	if keyID == "" {
		return nil, fmt.Errorf("aws-kms: kms_key_id is required")
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws-kms: load AWS config: %w", err)
	}
	return newClient(ctx, kms.NewFromConfig(cfg), keyID, encContext, allowFallback, fallbackHook)
}

// newClient is the testable core New() delegates to, taking the awsKMSAPI as a
// parameter so tests can inject a fake and exercise the DescribeKey-based ARN
// resolution (and everything downstream of it) without a real AWS call.
func newClient(ctx context.Context, api awsKMSAPI, keyID string, encContext map[string]string, allowFallback bool, fallbackHook FallbackHook) (keyorixcrypto.KMSClient, error) {
	arn, err := resolveKeyARN(ctx, api, keyID)
	if err != nil {
		return nil, err
	}
	return &client{
		kms:           api,
		keyID:         arn,
		encCtx:        maps.Clone(encContext), // defensive copy: caller's map must not be a live handle into this client's binding
		allowFallback: allowFallback,
		fallbackHook:  fallbackHook,
	}, nil
}

// resolveKeyARN resolves an ID/ARN/alias to its canonical, immutable key ARN via
// kms:DescribeKey. DescribeKey accepts any of the three forms and always returns
// the same ARN for a given CMK regardless of which alias currently points at it,
// so this is safe to call unconditionally rather than special-casing
// already-ARN/ID input.
func resolveKeyARN(ctx context.Context, api awsKMSAPI, keyID string) (string, error) {
	out, err := api.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &keyID})
	if err != nil {
		return "", fmt.Errorf("aws-kms: resolve key ARN for %q: %w", keyID, err)
	}
	if out.KeyMetadata == nil || out.KeyMetadata.Arn == nil || *out.KeyMetadata.Arn == "" {
		return "", fmt.Errorf("aws-kms: DescribeKey for %q returned no key ARN", keyID)
	}
	return *out.KeyMetadata.Arn, nil
}

func (c *client) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	in := &kms.EncryptInput{KeyId: &c.keyID, Plaintext: plaintext}
	if len(c.encCtx) > 0 {
		in.EncryptionContext = c.encCtx
	}
	out, err := c.kms.Encrypt(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("aws-kms: encrypt: %w", err)
	}
	// A 2xx response with a missing/empty CiphertextBlob is not success: the
	// caller (kms_provider.go's generateAndWrap) persists this value verbatim
	// as the wrapped-KEK file, so an unchecked empty blob would look like a
	// successful first-run startup and then be unusable on the next restart.
	// Same class as the already-fixed SecretString=="" gap in
	// internal/connect/awssm.go (docs/findings/2026-09-20-FINDING-awssm-empty-secret-response.md).
	if len(out.CiphertextBlob) == 0 {
		return nil, fmt.Errorf("aws-kms: encrypt: response had no ciphertext")
	}
	return out.CiphertextBlob, nil
}

func (c *client) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	// Pin KeyId so the blob is only decryptable by the expected CMK.
	in := &kms.DecryptInput{CiphertextBlob: ciphertext, KeyId: &c.keyID}
	if len(c.encCtx) > 0 {
		in.EncryptionContext = c.encCtx
	}
	out, err := c.kms.Decrypt(ctx, in)
	// #123: the no-context retry is now OPT-IN (allowFallback) rather than automatic on
	// any failure. With it off — the default — a context-bound Decrypt failure is
	// final: this is the actual enforcement of the "different install can't unwrap my
	// KEK" property. An unconditional fallback made that advisory, since a blob an
	// attacker (with kms:Encrypt on the shared CMK but not Keyorix's own data) planted
	// with NO context always succeeds on the fallback attempt regardless of what this
	// install's context is. When allowFallback IS set (a deliberate, transient
	// migration aid — see KMSAllowContextFallback), a successful fallback is logged
	// loudly: it means this decrypt just used the weaker, unbound path, which should
	// be closed by re-wrapping (`keyorix encryption migrate-provider
	// --to-kms-encryption-context=...`) and turning the flag back off.
	if err != nil && len(c.encCtx) > 0 && c.allowFallback {
		out, err = c.kms.Decrypt(ctx, &kms.DecryptInput{CiphertextBlob: ciphertext, KeyId: &c.keyID})
		if err == nil {
			log.Printf("aws-kms: decrypted a wrapped KEK WITHOUT its configured encryption context (insecure_allow_kms_context_fallback is on) — this blob is not bound to this install; re-wrap it under the context via 'keyorix encryption migrate-provider --to-kms-encryption-context=...' and disable insecure_allow_kms_context_fallback")
			if c.fallbackHook != nil {
				c.fallbackHook(ctx, c.keyID)
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("aws-kms: decrypt: %w", err)
	}
	return out.Plaintext, nil
}
