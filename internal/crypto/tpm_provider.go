// tpm_provider.go — TPM 2.0 KEK provider (ADR-038 tier-2). The KEK is sealed to the
// host's TPM and only unsealable on that machine: a random KEK is generated on first
// use, sealed under the TPM's storage hierarchy, and the resulting sealed blob is the
// only thing on disk. At startup the blob is loaded and unsealed inside the TPM, so
// the KEK is bound to the hardware and never recoverable from the disk alone.
//
// The seal/unseal command flow is exercised end-to-end against an in-process TPM 2.0
// simulator in the tests; only the device open is platform-specific (and fail-closed:
// no TPM ⇒ startup fails loudly, never a silent fallback).
//
// KNOWN LIMITATION — no PCR policy binding: the sealed object's auth policy is empty
// (PasswordAuth(nil)); nothing here builds a PolicyPCR session or seals with an
// AuthPolicy over a PCR selection. Concretely, this means the seal is bound to "the
// TPM chip is present and this is the primary it derived at seal time" — NOT to a
// verified/untampered boot state. Any code path capable of asking this TPM to unseal
// the blob succeeds regardless of what firmware, bootloader, or kernel got the machine
// there; a compromised-but-still-genuine boot chain unseals the KEK exactly as
// successfully as a clean one would. Do not describe this provider as boot-attestation
// or measured-boot binding until PCR policy sealing is implemented.
//
// This is a deliberate deferral, not an oversight — investigated for real PCR-policy
// binding (go-tpm v0.9.8's tpm2.PolicyPCR/PolicySession fully support it; a trial
// session at seal time plus a real session at unseal time is a well-trodden pattern,
// verifiable against the go-tpm-tools simulator) and concluded impractical to add
// *as a standalone change* given how this provider's surrounding machinery works
// today:
//   - Keyorix does not own or control the host's boot chain. It ships as a plain Go
//     binary / container image (see install.sh, deploy/helm/); there is no
//     Keyorix-authored OS image, systemd/package-manager hook, or any other
//     mechanism to detect an impending firmware/bootloader/kernel update and reseal
//     beforehand. Any customer-driven OS patch on the host silently changes PCR 0-7
//     and would fail closed on next restart with zero warning.
//   - There is no recovery/escrow fallback (e.g. a PolicyOR combining the PCR
//     policy with a break-glass password/share) if the PCR values do change. A
//     sealed blob whose PCR policy no longer matches is unseal-proof by design —
//     that is the entire point — so without a second authorization path a routine,
//     uncoordinated host patch converts into unrecoverable loss of the KEK and
//     therefore the DEK and every encrypted secret behind it.
//   - `keyorix-server admin encryption migrate-provider` cannot serve as that recovery path
//     either: it re-wraps the DEK by first calling KEK() on the *current* provider,
//     so once a PCR mismatch makes this provider's blob unsealable there is no way
//     to migrate off it. There is no in-place "reseal under fresh PCR values"
//     command today.
//
// In short: PCR binding is real and testable, but bolting it on here without also
// building host-update integration and a recovery/escrow path would trade a known,
// narrow limitation (host-binding only) for a silent single-outage-away total data
// loss risk — worse for a secrets manager than the status quo. Revisit only
// alongside a reseal/recovery design, not as an isolated fix.
package crypto

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/keyorixhq/keyorix/internal/securefiles"
)

// DefaultTPMDevice is the resource-managed TPM device used when none is configured.
const DefaultTPMDevice = "/dev/tpmrm0"

// tpmSealedBlob is the persisted sealed KEK: the TPM2B public + private of the sealed
// keyed-hash object. It is meaningless without the TPM that sealed it.
type tpmSealedBlob struct {
	Public  []byte `json:"public"`
	Private []byte `json:"private"`
}

// TPMKeyProvider seals/unseals the KEK with the host TPM 2.0. The sealed blob lives
// at blobPath (resolved under baseDir, like the KMS providers' wrapped_key_path);
// devicePath is the TPM device. open is injectable so the seal/unseal logic can be
// tested against a simulator.
//
// No PCR policy is enforced (see the package doc): the seal is bound to the TPM chip
// only, not to a verified boot state.
type TPMKeyProvider struct {
	devicePath string
	baseDir    string
	blobPath   string
	open       func() (transport.TPMCloser, error)
}

// NewTPMKeyProvider builds a TPM provider. blobPath is resolved under baseDir; an
// empty device path defaults to DefaultTPMDevice.
func NewTPMKeyProvider(devicePath, baseDir, blobPath string) *TPMKeyProvider {
	if devicePath == "" {
		devicePath = DefaultTPMDevice
	}
	p := &TPMKeyProvider{devicePath: devicePath, baseDir: baseDir, blobPath: blobPath}
	// transport.OpenTPM is the cross-platform device opener; the suggested
	// replacements (linuxtpm/windowstpm) are build-tagged per-OS and would force
	// platform-split files for no behavioural gain here.
	p.open = func() (transport.TPMCloser, error) { return transport.OpenTPM(p.devicePath) } //nolint:staticcheck // SA1019: cross-platform opener kept deliberately
	return p
}

func (p *TPMKeyProvider) Name() string { return "tpm" }

func (p *TPMKeyProvider) KEK() ([]byte, error) {
	if p.blobPath == "" {
		return nil, fmt.Errorf("tpm key provider: wrapped_key_path is required (where the sealed KEK blob lives)")
	}
	full := filepath.Join(p.baseDir, p.blobPath)
	if _, err := os.Stat(full); os.IsNotExist(err) {
		return p.generateAndSeal()
	}
	data, err := securefiles.SafeReadFile(p.baseDir, p.blobPath)
	if err != nil {
		return nil, fmt.Errorf("tpm key provider: read sealed blob: %w", err)
	}
	var blob tpmSealedBlob
	if jerr := json.Unmarshal(data, &blob); jerr != nil {
		return nil, fmt.Errorf("tpm key provider: corrupt sealed blob %s: %w", p.blobPath, jerr)
	}
	kek, uerr := p.unseal(blob)
	if uerr != nil {
		// No PCR policy is enforced here (see the package doc), so a PCR/boot-state
		// mismatch is never the cause of an unseal failure — do not suggest it. The
		// only reasons this TPM can fail to unseal the blob are: it is not the TPM
		// (or does not derive the same primary) that sealed it, or the blob itself is
		// corrupt/truncated.
		return nil, fmt.Errorf("tpm key provider: unseal failed (not the sealing TPM, or the sealed blob is corrupt): %w", uerr)
	}
	return validateKEK(kek, "tpm")
}

// generateAndSeal creates a fresh KEK, seals it to the TPM, durably persists the
// sealed blob (0600), and returns the plaintext KEK. First-run only.
func (p *TPMKeyProvider) generateAndSeal() ([]byte, error) {
	kek := make([]byte, KEKSize)
	if _, err := rand.Read(kek); err != nil {
		return nil, fmt.Errorf("tpm key provider: generate KEK: %w", err)
	}
	blob, err := p.seal(kek)
	if err != nil {
		return nil, fmt.Errorf("tpm key provider: seal failed: %w", err)
	}
	out, err := json.Marshal(blob)
	if err != nil {
		return nil, err
	}
	// Durably persist before returning: the DEK will be wrapped under this KEK, and
	// the sealed blob is the only way to recover it on restart.
	if err := securefiles.SecureWriteFileSync(p.baseDir, p.blobPath, out, 0600); err != nil {
		return nil, fmt.Errorf("tpm key provider: persist sealed blob: %w", err)
	}
	return kek, nil
}

// primaryTemplate is the storage-root primary used as the sealing parent. It is the
// TCG reference ECC-P256 SRK template, which CreatePrimary derives deterministically
// from the TPM's persistent seed — so the same primary (and thus the ability to load
// the sealed blob) is reproduced across restarts.
func createPrimary(t transport.TPM) (*tpm2.CreatePrimaryResponse, error) {
	return tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(t)
}

func flush(t transport.TPM, h tpm2.TPMHandle) {
	_, _ = tpm2.FlushContext{FlushHandle: h}.Execute(t)
}

// seal generates nothing — it seals the given secret under a fresh primary and
// returns the sealed public/private blob.
func (p *TPMKeyProvider) seal(secret []byte) (tpmSealedBlob, error) {
	t, err := p.open()
	if err != nil {
		return tpmSealedBlob{}, err
	}
	defer func() { _ = t.Close() }()

	prim, err := createPrimary(t)
	if err != nil {
		return tpmSealedBlob{}, fmt.Errorf("create primary: %w", err)
	}
	defer flush(t, prim.ObjectHandle)

	created, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{Handle: prim.ObjectHandle, Name: prim.Name, Auth: tpm2.PasswordAuth(nil)},
		InSensitive: tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{
			Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: secret}),
		}},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:     true,
				FixedParent:  true,
				UserWithAuth: true,
				NoDA:         true,
			},
		}),
	}.Execute(t)
	if err != nil {
		return tpmSealedBlob{}, fmt.Errorf("create sealed object: %w", err)
	}
	return tpmSealedBlob{
		Public:  tpm2.Marshal(created.OutPublic),
		Private: tpm2.Marshal(created.OutPrivate),
	}, nil
}

// unseal reloads the sealed blob under a fresh primary and returns the secret.
func (p *TPMKeyProvider) unseal(blob tpmSealedBlob) ([]byte, error) {
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](blob.Public)
	if err != nil {
		return nil, fmt.Errorf("decode sealed public: %w", err)
	}
	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](blob.Private)
	if err != nil {
		return nil, fmt.Errorf("decode sealed private: %w", err)
	}

	t, err := p.open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = t.Close() }()

	prim, err := createPrimary(t)
	if err != nil {
		return nil, fmt.Errorf("create primary: %w", err)
	}
	defer flush(t, prim.ObjectHandle)

	loaded, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{Handle: prim.ObjectHandle, Name: prim.Name, Auth: tpm2.PasswordAuth(nil)},
		InPrivate:    *priv,
		InPublic:     *pub,
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("load sealed object: %w", err)
	}
	defer flush(t, loaded.ObjectHandle)

	un, err := tpm2.Unseal{
		ItemHandle: tpm2.NamedHandle{Handle: loaded.ObjectHandle, Name: loaded.Name},
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("unseal: %w", err)
	}
	return un.OutData.Buffer, nil
}
