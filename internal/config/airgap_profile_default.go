//go:build !(noaws && noazure && nogcp)

package config

// airgapProfile is false outside the AIR-GAPPED server profile; see
// airgap_profile_airgap.go.
const airgapProfile = false
