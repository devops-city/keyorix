package services

import (
	"math"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
)

// TestUintToU32_Boundaries pins uintToU32, which replaced intToU32(int(id)) at
// model-ID call sites so a uint ID never round-trips through int.
func TestUintToU32_Boundaries(t *testing.T) {
	assert.Equal(t, uint32(0), uintToU32(0))
	assert.Equal(t, uint32(7), uintToU32(7))
	assert.Equal(t, uint32(math.MaxUint32), uintToU32(math.MaxUint32))
	assert.Equal(t, uint32(0), uintToU32(math.MaxUint32+1))
	assert.Equal(t, uint32(0), uintToU32(math.MaxUint))
}

// TestMachineIdentityToProto_ProjectIDNarrowing pins the ProjectId narrowing in
// machineIdentityToProto (CodeQL go/incorrect-integer-conversion, alert 1268):
// an in-range ID is carried through, an out-of-range one saturates to 0.
func TestMachineIdentityToProto_ProjectIDNarrowing(t *testing.T) {
	for _, tc := range []struct {
		in   uint
		want uint32
	}{
		{0, 0},
		{42, 42},
		{math.MaxUint32, math.MaxUint32},
		{math.MaxUint32 + 1, 0},
		{math.MaxInt64 + 1, 0},
		{math.MaxUint, 0},
	} {
		got := machineIdentityToProto(&models.MachineIdentity{ProjectID: tc.in})
		assert.Equal(t, tc.want, got.ProjectId, "ProjectID %d", tc.in)
	}
}
