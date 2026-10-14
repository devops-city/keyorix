package healthscan

import "testing"

func TestScore_PerfectWhenNoFindings(t *testing.T) {
	if got := Score(nil); got != 100 {
		t.Errorf("Score(nil) = %d, want 100", got)
	}
}

func TestScore_DeductsBySeverity(t *testing.T) {
	findings := []Finding{
		{ID: "a", Severity: SeverityCritical},
		{ID: "b", Severity: SeverityHigh},
		{ID: "c", Severity: SeverityInfo},
	}
	got := Score(findings)
	want := 100 - 25 - 15 // info deducts nothing.
	if got != want {
		t.Errorf("Score = %d, want %d", got, want)
	}
}

func TestScore_FloorsAtZero(t *testing.T) {
	findings := []Finding{
		{ID: "a", Severity: SeverityCritical}, {ID: "b", Severity: SeverityCritical},
		{ID: "c", Severity: SeverityCritical}, {ID: "d", Severity: SeverityCritical},
		{ID: "e", Severity: SeverityCritical},
	}
	if got := Score(findings); got != 0 {
		t.Errorf("Score = %d, want 0 (floored)", got)
	}
}

func TestScore_ExcludesMigrationReadiness(t *testing.T) {
	// migration-readiness is always SeverityInfo anyway (zero weight), but this proves the
	// exclusion is by ID, not incidentally by severity — a future change to that check's
	// severity must not silently start affecting the score.
	findings := []Finding{{ID: "migration-readiness", Severity: SeverityCritical}}
	if got := Score(findings); got != 100 {
		t.Errorf("Score = %d, want 100 (migration-readiness must never affect score)", got)
	}
}

func TestTopRisks_OrdersBySeverityThenID(t *testing.T) {
	findings := []Finding{
		{ID: "z-medium", Severity: SeverityMedium},
		{ID: "a-critical", Severity: SeverityCritical},
		{ID: "b-critical", Severity: SeverityCritical},
		{ID: "info-only", Severity: SeverityInfo},
		{ID: "migration-readiness", Severity: SeverityCritical},
	}
	got := TopRisks(findings, 5)
	want := []string{"a-critical", "b-critical", "z-medium"}
	if len(got) != len(want) {
		t.Fatalf("TopRisks returned %d items, want %d: %+v", len(got), len(want), got)
	}
	for i, id := range want {
		if got[i].ID != id {
			t.Errorf("TopRisks[%d].ID = %q, want %q", i, got[i].ID, id)
		}
	}
}

func TestTopRisks_LimitsToN(t *testing.T) {
	var findings []Finding
	for i := range 10 {
		findings = append(findings, Finding{ID: string(rune('a' + i)), Severity: SeverityHigh})
	}
	got := TopRisks(findings, 5)
	if len(got) != 5 {
		t.Fatalf("TopRisks(_, 5) returned %d items, want 5", len(got))
	}
}
