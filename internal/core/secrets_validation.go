// secrets_validation.go — validateCreateSecretRequest, validateUpdateSecretRequest.
//
// Used by secrets.go only.
package core

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
)

func (c *KeyorixCore) validateCreateSecretRequest(req *CreateSecretRequest) error {
	if req.Name == "" {
		return fmt.Errorf("%s", i18n.T("LabelName", nil))
	}
	if err := validateNameLength("secret name", req.Name); err != nil {
		return err
	}
	if len(req.Value) == 0 {
		return fmt.Errorf("%s", i18n.T("LabelValue", nil))
	}
	if req.ProjectID == 0 {
		return fmt.Errorf("%s", i18n.T("LabelProject", nil))
	}
	if req.EnvironmentID == 0 {
		return fmt.Errorf("%s", i18n.T("LabelEnvironment", nil))
	}
	if req.CreatedBy == "" {
		return fmt.Errorf("%s", i18n.T("ErrorRequiredField", nil))
	}
	return nil
}

func (c *KeyorixCore) validateUpdateSecretRequest(req *UpdateSecretRequest) error {
	if req.ID == 0 {
		return fmt.Errorf("secret ID is required")
	}
	if req.UpdatedBy == "" {
		return fmt.Errorf("%s", i18n.T("ErrorRequiredField", nil))
	}
	if req.ClearMaxReads && req.MaxReads != nil {
		return fmt.Errorf("max_reads and clear_max_reads are mutually exclusive")
	}
	return nil
}
