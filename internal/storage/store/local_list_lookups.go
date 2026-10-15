package store

import (
	"context"
	"fmt"
	"time"

	storage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Name lookups for list views (LIST-ENDPOINTS-1): one query for a whole page
// instead of one per row. They select only the id and the display column, never
// the full row, so a list that only needs a name cannot start carrying hashes,
// emails or other fields. Soft-deleted rows are absent from the result, exactly
// as the single-row GetUser / GetGroup / GetMachineIdentity miss them.

// listLookupChunk keeps one IN (...) list well under every backend's bind-variable
// limit while still being a handful of statements for a 10000-row listing bound.
const listLookupChunk = 2000

// forEachIDChunk calls fn on consecutive chunks of the de-duplicated ids.
func forEachIDChunk(ids []uint, fn func(chunk []uint) error) error {
	seen := make(map[uint]struct{}, len(ids))
	uniq := make([]uint, 0, len(ids))
	for _, id := range ids {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		uniq = append(uniq, id)
	}
	for start := 0; start < len(uniq); start += listLookupChunk {
		end := min(start+listLookupChunk, len(uniq))
		if err := fn(uniq[start:end]); err != nil {
			return err
		}
	}
	return nil
}

func lookupErr(err error) error {
	return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
}

// GetUsernamesByIDs maps user id to username for the live users in ids.
func (ls *LocalStorage) GetUsernamesByIDs(ctx context.Context, ids []uint) (map[uint]string, error) {
	out := make(map[uint]string, len(ids))
	err := forEachIDChunk(ids, func(chunk []uint) error {
		var rows []struct {
			ID       uint
			Username string
		}
		if err := ls.db.WithContext(ctx).Model(&models.User{}).
			Select("id", "username").Where("id IN ?", chunk).Find(&rows).Error; err != nil {
			return lookupErr(err)
		}
		for _, r := range rows {
			out[r.ID] = r.Username
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetGroupNamesByIDs maps group id to name for the live groups in ids.
func (ls *LocalStorage) GetGroupNamesByIDs(ctx context.Context, ids []uint) (map[uint]string, error) {
	out := make(map[uint]string, len(ids))
	err := forEachIDChunk(ids, func(chunk []uint) error {
		var rows []struct {
			ID   uint
			Name string
		}
		if err := ls.db.WithContext(ctx).Model(&models.Group{}).
			Select("id", "name").Where("id IN ?", chunk).Find(&rows).Error; err != nil {
			return lookupErr(err)
		}
		for _, r := range rows {
			out[r.ID] = r.Name
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetMachineIdentityNamesByIDs maps machine identity id to name for the machine
// identities in ids.
func (ls *LocalStorage) GetMachineIdentityNamesByIDs(ctx context.Context, ids []uint) (map[uint]string, error) {
	out := make(map[uint]string, len(ids))
	err := forEachIDChunk(ids, func(chunk []uint) error {
		var rows []struct {
			ID   uint
			Name string
		}
		if err := ls.db.WithContext(ctx).Model(&models.MachineIdentity{}).
			Select("id", "name").Where("id IN ?", chunk).Find(&rows).Error; err != nil {
			return lookupErr(err)
		}
		for _, r := range rows {
			out[r.ID] = r.Name
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetSecretTagsBySecretIDs is the batch form of GetSecretTags: tag names per
// secret id (name-ordered, like GetSecretTags). A secret with no tags is absent.
func (ls *LocalStorage) GetSecretTagsBySecretIDs(ctx context.Context, ids []uint) (map[uint][]string, error) {
	out := make(map[uint][]string, len(ids))
	err := forEachIDChunk(ids, func(chunk []uint) error {
		var rows []struct {
			SecretNodeID uint
			Name         string
		}
		if err := ls.db.WithContext(ctx).Model(&models.Tag{}).
			Select("secret_tags.secret_node_id AS secret_node_id, tags.name AS name").
			Joins("JOIN secret_tags ON secret_tags.tag_id = tags.id").
			Where("secret_tags.secret_node_id IN ?", chunk).
			Order("tags.name ASC").Find(&rows).Error; err != nil {
			return lookupErr(err)
		}
		for _, r := range rows {
			out[r.SecretNodeID] = append(out[r.SecretNodeID], r.Name)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetUserBriefsByIDs maps user id to username and email for the live users in ids
// (id, username and email columns only, never the full row).
func (ls *LocalStorage) GetUserBriefsByIDs(ctx context.Context, ids []uint) (map[uint]storage.UserBrief, error) {
	out := make(map[uint]storage.UserBrief, len(ids))
	err := forEachIDChunk(ids, func(chunk []uint) error {
		var rows []struct {
			ID       uint
			Username string
			Email    string
		}
		if err := ls.db.WithContext(ctx).Model(&models.User{}).
			Select("id", "username", "email").Where("id IN ?", chunk).Find(&rows).Error; err != nil {
			return lookupErr(err)
		}
		for _, r := range rows {
			out[r.ID] = storage.UserBrief{Username: r.Username, Email: r.Email}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetUserRoleScopesByUserIDs is the batch form of GetUserRoleScopes: for each user
// in ids, the distinct (project, environment) scopes at which they hold a live role,
// directly or through a live group. A user with no live role is absent.
func (ls *LocalStorage) GetUserRoleScopesByUserIDs(ctx context.Context, ids []uint) (map[uint][]storage.Scope, error) {
	seen := make(map[uint]map[storage.Scope]struct{}, len(ids))
	add := func(userID, projectID, environmentID uint) {
		if seen[userID] == nil {
			seen[userID] = map[storage.Scope]struct{}{}
		}
		seen[userID][storage.Scope{ProjectID: projectID, EnvironmentID: environmentID}] = struct{}{}
	}
	now := ls.rbacEffectiveNow(time.Now().UTC())
	err := forEachIDChunk(ids, func(chunk []uint) error {
		var direct []struct {
			UserID        uint
			ProjectID     uint
			EnvironmentID uint
		}
		if err := ls.db.WithContext(ctx).Model(&models.UserRole{}).
			Select("user_id, project_id, environment_id").
			Where("user_id IN ?", chunk).
			Where(sqlWhereURNotExpired, now).
			Group("user_id, project_id, environment_id").
			Scan(&direct).Error; err != nil {
			return lookupErr(err)
		}
		for _, r := range direct {
			add(r.UserID, r.ProjectID, r.EnvironmentID)
		}
		var viaGroups []struct {
			UserID        uint
			ProjectID     uint
			EnvironmentID uint
		}
		if err := ls.db.WithContext(ctx).Table("group_roles").
			Select("user_groups.user_id AS user_id, group_roles.project_id AS project_id, group_roles.environment_id AS environment_id").
			Joins(sqlJoinUserGroups).
			Joins(sqlJoinGroups).
			Where("user_groups.user_id IN ?", chunk).
			Where(sqlWhereGRNotExpired, now).
			Group("user_groups.user_id, group_roles.project_id, group_roles.environment_id").
			Scan(&viaGroups).Error; err != nil {
			return lookupErr(err)
		}
		for _, r := range viaGroups {
			add(r.UserID, r.ProjectID, r.EnvironmentID)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := make(map[uint][]storage.Scope, len(seen))
	for uid, set := range seen {
		for s := range set {
			out[uid] = append(out[uid], s)
		}
	}
	return out, nil
}

// ListUserProjectMembershipsByUserIDs is the batch form of ListUserProjectMemberships:
// each user's membership rows, newest invite first (the single-user order), keyed by
// user id. A user with no row is absent.
func (ls *LocalStorage) ListUserProjectMembershipsByUserIDs(ctx context.Context, ids []uint) (map[uint][]*models.ProjectMembership, error) {
	out := make(map[uint][]*models.ProjectMembership, len(ids))
	err := forEachIDChunk(ids, func(chunk []uint) error {
		var rows []*models.ProjectMembership
		if err := ls.db.WithContext(ctx).
			Where("user_id IN ?", chunk).
			Order("invited_at DESC").
			Find(&rows).Error; err != nil {
			return lookupErr(err)
		}
		for _, m := range rows {
			out[m.UserID] = append(out[m.UserID], m)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ListMachineCredentialUsageByMachineIDs is the batch form of
// ListMachineIdentityCredentials for the machine audit report: per machine identity,
// its credentials (all, revoked included) carrying ONLY id, machine_identity_id and
// last_used_at -- a count and a most-recent use are all the report needs, so no token
// hash or CIDR list is loaded. A machine without credentials is absent.
func (ls *LocalStorage) ListMachineCredentialUsageByMachineIDs(ctx context.Context, ids []uint) (map[uint][]*models.MachineIdentityCredential, error) {
	out := make(map[uint][]*models.MachineIdentityCredential, len(ids))
	err := forEachIDChunk(ids, func(chunk []uint) error {
		var rows []*models.MachineIdentityCredential
		if err := ls.db.WithContext(ctx).
			Select("id", "machine_identity_id", "last_used_at").
			Where("machine_identity_id IN ?", chunk).
			Find(&rows).Error; err != nil {
			return lookupErr(err)
		}
		for _, r := range rows {
			out[r.MachineIdentityID] = append(out[r.MachineIdentityID], r)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
