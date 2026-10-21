package safeconv

import (
	"math"
	"testing"
)

// TestConversions_PlatformExtremes (REVIEW-COVERAGE-2) adds the inputs the
// boundary tests do not reach: the extremes of int and uint themselves, where a
// check written with the wrong type (an int32 comparison, a wrapped constant)
// would pass at the int32 boundary and fail here. Every out-of-range input
// returns the zero value with an error, never a truncated one.
func TestConversions_PlatformExtremes(t *testing.T) {
	for _, v := range []uint{math.MaxUint, math.MaxUint32 + 1, 1 << 40} {
		if got, err := UintToUint32(v); err == nil || got != 0 {
			t.Errorf("UintToUint32(%d) = %d, %v; want 0 and an error", v, got, err)
		}
	}
	for _, v := range []int{math.MaxInt, math.MinInt, math.MaxInt32 + 1, math.MinInt32 - 1, 1 << 40, -(1 << 40)} {
		if got, err := IntToInt32(v); err == nil || got != 0 {
			t.Errorf("IntToInt32(%d) = %d, %v; want 0 and an error", v, got, err)
		}
	}
	for _, v := range []int{math.MinInt, -1, math.MinInt32} {
		if got, err := IntToUint64(v); err == nil || got != 0 {
			t.Errorf("IntToUint64(%d) = %d, %v; want 0 and an error", v, got, err)
		}
	}
	if got, err := IntToUint64(math.MaxInt); err != nil || got != math.MaxInt {
		t.Errorf("IntToUint64(MaxInt) = %d, %v", got, err)
	}
	if got, err := IntToInt32(0); err != nil || got != 0 {
		t.Errorf("IntToInt32(0) = %d, %v", got, err)
	}
	if got, err := UintToUint32(0); err != nil || got != 0 {
		t.Errorf("UintToUint32(0) = %d, %v", got, err)
	}
}
