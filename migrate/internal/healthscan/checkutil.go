package healthscan

import (
	"context"
	"encoding/json"
	"fmt"
)

// getJSON issues c.Get(path) and, on a 200 with a non-empty body, decodes it into out. Callers
// branch on the returned status themselves — a 403 (permission denied) and a 404 (the feature
// doesn't exist on this edition/backend/version) mean different things to different checks, so
// this helper never collapses either into an error.
func getJSON(ctx context.Context, c *Client, path string, out any) (status int, err error) {
	status, body, err := c.Get(ctx, path)
	if err != nil {
		return status, err
	}
	if status == StatusOK && len(body) > 0 {
		if err := json.Unmarshal(body, out); err != nil {
			return status, fmt.Errorf("decode %s response: %w", path, err)
		}
	}
	return status, nil
}

// listJSON is getJSON's LIST counterpart.
func listJSON(ctx context.Context, c *Client, path string, out any) (status int, err error) {
	status, body, err := c.List(ctx, path)
	if err != nil {
		return status, err
	}
	if status == StatusOK && len(body) > 0 {
		if err := json.Unmarshal(body, out); err != nil {
			return status, fmt.Errorf("decode %s response: %w", path, err)
		}
	}
	return status, nil
}

// denied builds the NotChecked a check returns when Vault answered 403 for the path it needs —
// id must match the Check's own ID (Run/RunChecks key findings and gaps by it), and policyLine
// is the exact healthscan-policy.hcl stanza that would grant access, so the report can tell the
// operator precisely what to add.
func denied(id, path, policyLine string) Result {
	return Result{NotChecked: &NotChecked{
		ID:         id,
		Reason:     fmt.Sprintf("permission denied reading %s", path),
		PolicyLine: policyLine,
	}}
}
