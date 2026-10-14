// classification_count.go — shared helper for the compliance classification
// posture: count rows of a classifiable table grouped by classification label.
package store

import (
	"context"

	"gorm.io/gorm"
)

// countByClassification returns row counts of model keyed by its classification
// label ("" = unclassified), install-wide, via a single GROUP BY.
func countByClassification(ctx context.Context, db *gorm.DB, model any) (map[string]int, error) {
	var rows []struct {
		Classification string
		N              int
	}
	if err := db.WithContext(ctx).Model(model).
		Select("classification, COUNT(*) AS n").Group("classification").Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]int, len(rows))
	for _, r := range rows {
		out[r.Classification] = r.N
	}
	return out, nil
}
