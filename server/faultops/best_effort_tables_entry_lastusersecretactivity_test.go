// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

func init() {
	// LastUserSecretActivity: OpenAccessReviewCampaign (internal/core/
	// access_review_campaign.go) deliberately, by design (#483), persists a
	// failure of this ONE sub-query onto the campaign row itself —
	// Degraded/DegradedReasons — rather than aborting the campaign or
	// silently leaving every item's LastUsedAt nil (indistinguishable from
	// "genuinely never used"). annotateLastUsedAt (access_review.go) only
	// sets report.degrade(...) and returns on this specific error; it does
	// not alter entries, so AccessReviewItem rows are identical either way
	// — the ENTIRE diff this failure can ever produce is confined to
	// AccessReviewCampaign's own Degraded/DegradedReasons columns, found
	// live by FuzzStorageFaultOperations (REST POST .../access-review/
	// campaigns). This is the intended, documented behavior #483 built —
	// not an undiscovered bug — so it belongs here, not in
	// knownOpenTolerances.
	registerBestEffortTable("LastUserSecretActivity", []string{"AccessReviewCampaign"})
}
