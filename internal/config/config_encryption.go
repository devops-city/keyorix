package config

// EncryptionConfig configures the ADR-004 envelope scheme. The KEK is derived
// from the master passphrase at runtime (PBKDF2) and never touches disk, so the
// only key material on disk is the salt and the wrapped DEK.
type EncryptionConfig struct {
	Enabled  bool   `yaml:"enabled"`
	DEKPath  string `yaml:"dek_path"`
	SaltPath string `yaml:"salt_path"`
	// KeyProvider selects where the KEK comes from (ADR-038). Absent/zero value =
	// the default passphrase derivation (KEYORIX_MASTER_PASSWORD + on-disk salt),
	// byte-identical to the historical behaviour.
	KeyProvider KeyProviderConfig `yaml:"key_provider"`
	// KeyDirLock selects how a server coordinates with other processes using the
	// same key files (docs/multi-replica-keys.md). "" or "flock" (default): the
	// server holds an exclusive flock(2) on <key dir>/dek.lock for its lifetime,
	// so exactly one server can use a key directory. "database" (PostgreSQL
	// only, for several replicas): the server takes no key-directory lock; the
	// server-presence advisory lock it already holds keeps key-changing admin
	// commands out, and first-boot key generation and rotation crash recovery
	// run under a PostgreSQL advisory lock. The key directory may then be a
	// shared ReadWriteMany volume without working flock, or read-only.
	KeyDirLock string `yaml:"key_dir_lock"`
}

// Key-directory lock modes (EncryptionConfig.KeyDirLock).
const (
	KeyDirLockFlock    = "flock"
	KeyDirLockDatabase = "database"
)

// KeyDirLockIsDatabase reports whether the key-directory lock is the
// PostgreSQL-backed one (storage.encryption.key_dir_lock: database).
func (e *EncryptionConfig) KeyDirLockIsDatabase() bool {
	return e.KeyDirLock == KeyDirLockDatabase
}

// KeyProviderConfig selects the KEK source. type: "password" (default) derives the
// KEK from KEYORIX_MASTER_PASSWORD; "file" reads raw key material from FilePath;
// "env" reads it from the EnvVar's value (hex or base64); "exec" runs ExecCommand
// and reads the KEK from its stdout; "shamir" reconstructs it from K-of-N Shamir
// shares (ShamirShareFiles / ShamirShareEnv); "tpm" seals it to the host TPM 2.0
// (TPMDevice, sealed blob at WrappedKeyPath); "aws-kms" / "gcp-kms" / "azure-kms"
// envelope-wrap the KEK with a cloud KMS/HSM key (ADR-041) and store the wrapped
// blob at WrappedKeyPath. file/env/exec suit a KEK injected by a sealed/SOPS secret,
// a CSI driver, or any external secret store; shamir splits it across custodians;
// tpm binds it to host hardware; the KMS providers keep the wrapping key in the cloud HSM.
type KeyProviderConfig struct {
	Type     string `yaml:"type"`
	FilePath string `yaml:"file_path"`
	EnvVar   string `yaml:"env_var"`
	// KMSKeyID is the cloud KMS key for type aws-kms / gcp-kms / azure-kms: an AWS
	// key ID, ARN, or alias; a GCP crypto-key resource name
	// (projects/P/locations/L/keyRings/R/cryptoKeys/K); or an Azure Key Vault key
	// identifier URL (https://{vault}.vault.azure.net/keys/{name}[/{version}]).
	// Region/credentials come from the standard cloud environment, not from here.
	KMSKeyID string `yaml:"kms_key_id"`
	// WrappedKeyPath is where the KMS-wrapped KEK blob lives (aws-kms / gcp-kms /
	// azure-kms).
	WrappedKeyPath string `yaml:"wrapped_key_path"`
	// KMSEncryptionContext binds the wrapped KEK to this install (aws-kms /gcp-kms):
	// it's passed as the AWS EncryptionContext / GCP AdditionalAuthenticatedData on
	// wrap+unwrap, so a different install sharing the same CMK cannot unwrap this
	// install's KEK. Set a value unique to the install, e.g. {keyorix-install: <id>}.
	// Empty = no binding (the prior behaviour). NOT supported by azure-kms (RSA wrap
	// has no AAD) — setting it there is a hard startup error, not a silent downgrade.
	//
	// #123: on its own this is enforced (a mismatched or missing context on the
	// wrapped blob fails decryption outright) UNLESS KMSAllowContextFallback is also
	// set — see that field.
	KMSEncryptionContext map[string]string `yaml:"kms_encryption_context"`
	// KMSAllowContextFallback opts into a ONE-DIRECTION migration aid: when
	// KMSEncryptionContext is set and a context-bound Decrypt fails, retry once
	// without any context, so enabling the binding on an install with an existing
	// (pre-binding) wrapped KEK doesn't lock it out. Off by default — with it off (the
	// secure default), a KMS Decrypt failure is final: the whole point of
	// KMSEncryptionContext is that an attacker with kms:Encrypt on the shared CMK (but
	// not Keyorix's own data) cannot plant a wrapped-KEK blob that decrypts under this
	// install's identity; a fallback that auto-retries without the context on ANY
	// failure makes that binding purely advisory, since a blob encrypted with no
	// context at all (the trivial attack) always succeeds on the fallback attempt.
	// Enable this ONLY transiently while migrating an existing install onto a newly
	// configured context (`keyorix-server admin encryption migrate-provider --to-kms-encryption-
	// context=...` to durably re-wrap under the context), then disable it again —
	// every fallback use is logged loudly specifically so that migration window is
	// observable and finite, not a permanent standing weakening.
	//
	// #3398: the window ends by itself. When the stored wrapped KEK already
	// decrypts WITH its context (the migration is done), the flag is refused at
	// start-up with a message saying it can be removed
	// (crypto.ErrKMSContextFallbackNotNeeded, checked in KMSKeyProvider.KEK).
	KMSAllowContextFallback bool `yaml:"insecure_allow_kms_context_fallback"`
	// ExecCommand is the argv for type "exec": the resolver command (argv[0] is the
	// binary, the rest are arguments) whose stdout supplies the KEK as raw 32 bytes
	// or a hex/base64 encoding thereof. Run directly without a shell. Lets a
	// deployment fetch the KEK from any external secret store (e.g.
	// ["op","read","op://vault/kek/value"], ["sops","-d","kek.enc"]).
	ExecCommand []string `yaml:"exec_command"`
	// ShamirShareFiles / ShamirShareEnv list the K-of-N Shamir shares for type
	// "shamir": the KEK is reconstructed by combining the shares read from these file
	// paths and/or env-var values (each a hex/base64 share from
	// `keyorix-server admin encryption shamir-split`). Provide at least the threshold many; no
	// single share reveals the KEK.
	ShamirShareFiles []string `yaml:"shamir_share_files"`
	ShamirShareEnv   []string `yaml:"shamir_share_env"`
	// ShamirCommitment is the hex-encoded HMAC-SHA256 commitment to the original KEK
	// (crypto.CommitKEK), printed by `keyorix-server admin encryption shamir-split` alongside the
	// shares. It is verified against the RECONSTRUCTED KEK at unseal time (#429):
	// without it, reconstruction is checked only by a 4-byte magic embedded in the
	// split payload, which an attacker holding threshold-1 genuine shares can forge
	// (each byte of the reconstructed payload — magic and KEK alike — is
	// independently retargetable via the forged share's Lagrange coordinate, so a
	// bigger in-payload check wouldn't help either). The commitment is safe to store
	// in the clear here — it is one-way and reveals nothing about the KEK. Empty is
	// accepted for key material split before this field existed, but every startup
	// then logs a loud warning that verification is reduced to the forgeable magic
	// check alone.
	ShamirCommitment string `yaml:"shamir_commitment"`
	// TPMDevice is the TPM 2.0 device for type "tpm" (default /dev/tpmrm0). The KEK
	// is sealed to this TPM and the sealed blob stored at WrappedKeyPath.
	TPMDevice string `yaml:"tpm_device"`
	// Fallbacks is an ordered list of providers tried when the primary fails.
	Fallbacks []KeyProviderConfig `yaml:"fallbacks,omitempty"`
	// AllowWeakerFallback must be explicitly set to allow a Fallbacks chain that
	// downgrades KEK-sourcing strength — e.g. a hardware/HSM/cloud-KMS-backed
	// provider (tpm, aws-kms, gcp-kms, azure-kms) falling back to a software-
	// derivable one (password, file, env, exec) or to shamir. Without it, a
	// downgrading chain is a hard startup error (crypto.DetectFallbackDowngrade):
	// silently accepting one would mean a transient failure of the strong primary
	// (a momentary TPM glitch, a KMS network blip) quietly drops the deployment's
	// actual security to "whatever a local password/file/env-var can be
	// leaked/brute-forced", with only a log line marking the moment it happened. A
	// fallback chain that stays flat or gets stronger (e.g. one KMS region falling
	// back to another) is unaffected and never needs this flag.
	AllowWeakerFallback bool `yaml:"insecure_allow_weaker_kek_fallback"`
}
