package core

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

// TestAuthBudgetRejectionMetric: a budget check that answers "limited" moves
// keyorix_auth_budget_rejections_total for that budget; one that answers "allowed"
// does not. A private budget name keeps this exact under parallel tests.
func TestAuthBudgetRejectionMetric(t *testing.T) {
	c, _ := newRateLimitCore(t)
	ctx := context.Background()
	b := authBudget{name: "obs1_probe", limit: 2, window: time.Hour}
	counter := authBudgetRejectionsTotal.WithLabelValues(b.name)

	assert.False(t, c.budgetLimited(ctx, b, "k"))
	assert.Equal(t, float64(0), testutil.ToFloat64(counter), "an allowed check is not a rejection")

	c.budgetRecord(ctx, b, "k")
	c.budgetRecord(ctx, b, "k")
	assert.True(t, c.budgetLimited(ctx, b, "k"))
	assert.Equal(t, float64(1), testutil.ToFloat64(counter))

	assert.False(t, c.budgetLimited(ctx, b, "other-key"), "a different key is unaffected")
	assert.Equal(t, float64(1), testutil.ToFloat64(counter))
}
