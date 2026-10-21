package config

import (
	"fmt"
)

type SecretsConfig struct {
	Chunking ChunkingConfig `yaml:"chunking"`
	Limits   LimitsConfig   `yaml:"limits"`
}

type ChunkingConfig struct {
	Enabled            bool `yaml:"enabled"`
	MaxChunkSizeKB     int  `yaml:"max_chunk_size_kb"`
	MaxChunksPerSecret int  `yaml:"max_chunks_per_secret"`
}

type LimitsConfig struct {
	MaxSecretsPerUser int `yaml:"max_secrets_per_user"`
	// MaxSecretSize caps a secret value's size in bytes, enforced on create/update/
	// rotate (never on read/delete — a secret already stored above the cap, e.g. from
	// before this was introduced or before an operator lowered it, stays fully
	// readable and deletable; only new writes are rejected). 0 (unset) defaults to
	// DefaultMaxSecretSize; Validate rejects any configured value above
	// MaxSecretSizeHardCeiling. See DefaultMaxSecretSize's doc comment for the
	// industry-comparison rationale behind the default.
	MaxSecretSize int `yaml:"max_secret_size"`
}

// DefaultMaxSecretSize (64 KiB) is the default ceiling on a secret value's size when
// secrets.limits.max_secret_size is unset. This is the number the major managed
// secret stores have converged on, not an arbitrary round figure: AWS Secrets
// Manager and GCP Secret Manager both cap at 64 KB (AWS's limit is explicitly
// documented as non-adjustable and was raised twice, under customer pressure,
// before settling at 64 KB); Azure Key Vault caps at 25 KB; HashiCorp Vault chunks
// entries above 512 KiB and its own documentation warns that large entries degrade
// other storage operations (backend replication, snapshot/restore, KV listing).
// 64 KiB is the number defensible in this product's own docs for the same reasons.
const DefaultMaxSecretSize = 65536

// secretSizeEnvelopeHeadroomBytes is added on top of a secret value's base64-
// inflated size (DeriveMaxRequestBodySize) to cover the REST of a create/update/
// rotate request body: JSON field names and quoting, and the request's other
// fields (name up to 255 bytes, metadata, tags, description, etc.), none of which
// are the secret value itself and none of which max_secret_size is meant to bound.
// 16 KiB is a generous, round number chosen to comfortably clear ordinary metadata/
// tag usage without making the wire-level cap effectively unlimited -- it is a
// coarse DoS backstop, not the precise enforcement point (that's the decoded-value
// check against max_secret_size itself, applied separately after the body is
// successfully read).
const secretSizeEnvelopeHeadroomBytes = 16 * 1024

// DeriveMaxRequestBodySize returns the maximum HTTP/gRPC request body size a
// caller must be allowed to send in order to successfully submit a secret value of
// exactly maxSecretSize bytes, plus headroom for the rest of the request envelope.
//
// A secret value never travels as raw bytes: the HTTP JSON API and gRPC's
// generated string fields both carry it base64-encoded. Base64 inflates N bytes to
// exactly ceil(N/3)*4 bytes -- setting a request-body limit to maxSecretSize itself
// (the natural but wrong first instinct) would reject every valid maximum-size
// secret outright, roughly 33% before the JSON envelope is even counted. This
// function exists specifically so that mistake has one place it can't be made:
// every caller that needs a body-size limit derived from max_secret_size (the HTTP
// router's per-route secretBodyLimit middleware) calls this,
// rather than each re-deriving (and potentially mis-deriving) its own.
func DeriveMaxRequestBodySize(maxSecretSize int) int64 {
	base64Size := ((maxSecretSize + 2) / 3) * 4 // ceil(n/3)*4: the exact base64 output length
	return int64(base64Size) + secretSizeEnvelopeHeadroomBytes
}

// applySecretsLimits defaults secrets.limits.max_secret_size and checks its bounds (Validate step;
// it writes the default into c).
func applySecretsLimits(c *Config) error {
	if c.Secrets.Limits.MaxSecretSize == 0 {
		c.Secrets.Limits.MaxSecretSize = DefaultMaxSecretSize
	}
	if c.Secrets.Limits.MaxSecretSize < 0 {
		return fmt.Errorf("secrets.limits.max_secret_size (%d) must not be negative", c.Secrets.Limits.MaxSecretSize)
	}
	if c.Secrets.Limits.MaxSecretSize > MaxSecretSizeHardCeiling {
		return fmt.Errorf("secrets.limits.max_secret_size (%d) exceeds the hard ceiling of %d bytes (1 MiB) -- "+
			"a secret store is not a general blob store; use a purpose-built object store for larger values",
			c.Secrets.Limits.MaxSecretSize, MaxSecretSizeHardCeiling)
	}
	return nil
}
