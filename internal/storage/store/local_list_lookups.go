package store

import (
	"context"
	"fmt"

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
