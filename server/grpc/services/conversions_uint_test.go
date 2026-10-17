package services

import (
	"math"
	"testing"

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
