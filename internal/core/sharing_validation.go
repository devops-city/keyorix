// sharing_validation.go — Request validation helpers used by sharing.go.
package core

import "fmt"

func (c *KeyorixCore) validateShareSecretRequest(req *ShareSecretRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}
	if req.SecretID == 0 {
		return fmt.Errorf("secret ID is required")
	}
	if req.RecipientID == 0 {
		return fmt.Errorf("recipient ID is required")
	}
	if req.Permission != string(PermissionRead) && req.Permission != string(PermissionWrite) {
		return fmt.Errorf("invalid permission: %s (must be 'read' or 'write')", req.Permission)
	}
	if req.SharedBy == 0 {
		return fmt.Errorf("sharedBy is required")
	}
	// #3422: ShareSecret has no group-scope check; a group recipient must go through
	// ShareSecretWithGroup, which enforces IsGroupProjectScoped.
	if req.IsGroup {
		return fmt.Errorf("group shares must use ShareSecretWithGroup")
	}
	// #252: a self-share (sharing a secret with yourself) is meaningless at best and
	// a landmine at worst — it inflates share/audit counts and confuses risk-scoring
	// with no real access-boundary crossed. Only direct shares reach here (group
	// recipients are refused above, where RecipientID is a group ID, not a user ID).
	if req.RecipientID == req.SharedBy {
		return fmt.Errorf("cannot share a secret with yourself")
	}
	return nil
}

func (c *KeyorixCore) validateUpdateShareRequest(req *UpdateShareRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}
	if req.ShareID == 0 {
		return fmt.Errorf("share ID is required")
	}
	if req.Permission != string(PermissionRead) && req.Permission != string(PermissionWrite) {
		return fmt.Errorf("invalid permission: %s (must be 'read' or 'write')", req.Permission)
	}
	if req.UpdatedBy == 0 {
		return fmt.Errorf("updatedBy is required")
	}
	return nil
}
