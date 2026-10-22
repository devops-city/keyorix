//go:build noaws && noazure && nogcp

package config

// airgapProfile is true in the AIR-GAPPED server profile (-tags noaws,noazure,nogcp
// together, ADR-109 step 6; `make build-server-airgap`). It is the same condition
// internal/encryption's kms_registry_airgap_test.go uses for "every cloud KMS is
// excluded". See airgap_profile.go for what it gates.
const airgapProfile = true
