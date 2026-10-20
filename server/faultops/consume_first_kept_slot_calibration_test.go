package faultops

import "testing"

// keepsLoginSlot (AUTH-2 item 4) accepts the one LoginAttempt row a
// post-verdict fault keeps, and nothing more: calibrated in both directions.
func TestPureRowAdditionAtMost_Calibration(t *testing.T) {
	tbl := func(rows ...string) tableSnapshot { return tableSnapshot{Table: "LoginAttempt", Rows: rows} }
	for _, tc := range []struct {
		name          string
		before, after tableSnapshot
		want          bool
	}{
		{"unchanged", tbl("a"), tbl("a"), true},
		{"one kept slot", tbl("a"), tbl("a", "b"), true},
		{"two rows added", tbl("a"), tbl("a", "b", "c"), false},
		{"row deleted", tbl("a", "b"), tbl("a"), false},
		{"row edited", tbl("a"), tbl("a2"), false},
		{"row edited plus one added", tbl("a"), tbl("a2", "b"), false},
	} {
		if got := pureRowAdditionAtMost(tc.before, tc.after, 1); got != tc.want {
			t.Errorf("%s: pureRowAdditionAtMost = %v, want %v", tc.name, got, tc.want)
		}
	}
}
