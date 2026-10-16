// share_view_secret_names.go — secret name and project on the Sharing Management list
// (#3153).
//
// ShareView used to carry only SecretID, so the web page printed "Secret #2". The name
// is added here, but only for a secret the caller may read: the list is gated on
// secrets.read at some scope, not on every secret it lists (a received share, a PAT
// confined to one project, a project the owner has left). Each distinct secret goes
// through the secrets.read decision — ACL, role, share, PAT restriction — the same
// one GET /secrets/{id} makes (AuthorizeSecret), decided for the whole page at once by
// AuthorizeSecretsBatch. A secret that fails it (or no longer resolves)
// keeps SecretID only: no name, no project. Fails closed: an authorization or lookup
// error leaves the name out, it never returns the list with a name unchecked.
package core

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// annotateShareViewSecrets fills SecretName, ProjectID and ProjectName on views for the
// secrets userID may read. See the file header.
func (c *KeyorixCore) annotateShareViewSecrets(ctx context.Context, userID uint, views []ShareView) {
	if len(views) == 0 || userID == 0 {
		return
	}
	ids := make([]uint, 0, len(views))
	for _, v := range views {
		ids = append(ids, v.SecretID)
	}
	secrets, err := c.storage.GetSecretsByIDs(ctx, dedupeUints(ids))
	if err != nil {
		return // no names rather than unchecked names
	}
	// One batch decision for the page, equal to AuthorizeSecret(secrets.read) per secret
	// (SHARES-BATCH-AUTHZ-1); a failed read leaves every name out.
	allowed, aerr := c.AuthorizeSecretsBatch(ctx, userID, permSecretsRead, secrets)
	if aerr != nil {
		return
	}
	readable := make(map[uint]*models.SecretNode, len(secrets))
	for _, sec := range secrets {
		if sec != nil && allowed[sec.ID] {
			readable[sec.ID] = sec
		}
	}
	projectNames := map[uint]string{}
	for i := range views {
		sec, ok := readable[views[i].SecretID]
		if !ok {
			continue
		}
		views[i].SecretName = sec.Name
		views[i].ProjectID = sec.ProjectID
		if sec.ProjectID == 0 {
			continue
		}
		name, seen := projectNames[sec.ProjectID]
		if !seen {
			if p, perr := c.storage.GetProject(ctx, sec.ProjectID); perr == nil && p != nil {
				name = p.Name
			}
			projectNames[sec.ProjectID] = name
		}
		views[i].ProjectName = name
	}
}
