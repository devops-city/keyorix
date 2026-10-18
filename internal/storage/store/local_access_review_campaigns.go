// local_access_review_campaigns.go — access-review campaign + item persistence
// (ISO 27001 A.5.18). For the remote (HTTP) equivalent see
// remote_access_review_campaigns.go (server-side only — stubs there).
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// --- Campaigns ---

func (ls *LocalStorage) CreateAccessReviewCampaign(ctx context.Context, c *models.AccessReviewCampaign) (*models.AccessReviewCampaign, error) {
	if err := ls.db.WithContext(ctx).Create(c).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return c, nil
}

func (ls *LocalStorage) GetAccessReviewCampaign(ctx context.Context, id uint) (*models.AccessReviewCampaign, error) {
	var c models.AccessReviewCampaign
	if err := ls.db.WithContext(ctx).First(&c, id).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &c, nil
}

func (ls *LocalStorage) ListAccessReviewCampaigns(ctx context.Context, projectID uint) ([]*models.AccessReviewCampaign, error) {
	var rows []*models.AccessReviewCampaign
	err := ls.db.WithContext(ctx).
		Where("project_id = ?", projectID).
		Order(sqlOrderCreatedAtDesc).
		Limit(maxUnboundedListRows).
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

// GetOpenAccessReviewCampaign returns the project's open campaign (nil if none is
// open) via a targeted `WHERE project_id = ? AND state = 'open'` lookup — not by
// loading and filtering the project's full campaign history. #238: the
// recertification scheduler tick used to call ListAccessReviewCampaigns (which
// returns EVERY campaign the project has ever had, oldest to newest) on every tick
// for every project just to answer "is one open right now"; the cost of that grew
// unboundedly with a deployment's accumulated campaign history. This query costs the
// same whether the project has 1 or 10,000 historical campaigns.
func (ls *LocalStorage) GetOpenAccessReviewCampaign(ctx context.Context, projectID uint) (*models.AccessReviewCampaign, error) {
	var c models.AccessReviewCampaign
	err := ls.db.WithContext(ctx).
		Where("project_id = ? AND state = ?", projectID, accessReviewCampaignOpen).
		Order(sqlOrderCreatedAtDesc).
		First(&c).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &c, nil
}

// GetLatestClosedAccessReviewCampaign returns the project's most recently created
// non-open campaign (nil if it has never had one) via a targeted
// `ORDER BY created_at DESC LIMIT 1` lookup, so the recertification scheduler tick
// (#238) can anchor the next-due date without loading the project's entire
// historical campaign corpus just to find the newest closed row.
func (ls *LocalStorage) GetLatestClosedAccessReviewCampaign(ctx context.Context, projectID uint) (*models.AccessReviewCampaign, error) {
	var c models.AccessReviewCampaign
	err := ls.db.WithContext(ctx).
		Where("project_id = ? AND state <> ?", projectID, accessReviewCampaignOpen).
		Order(sqlOrderCreatedAtDesc).
		First(&c).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &c, nil
}

// accessReviewCampaignOpen mirrors core.CampaignStateOpen (the store package cannot
// import core: core already imports storage/store). Both sides of this state
// machine — core's pre-check and this conditional UPDATE — must agree on the same
// "still open" sentinel string.
const accessReviewCampaignOpen = "open"

// UpdateAccessReviewCampaign persists a campaign state transition with a conditional
// UPDATE (`WHERE id = ? AND state = 'open'`), not the prior unconditional Save. The
// only mutation path today is CloseAccessReviewCampaign (open -> closed): a plain
// read-then-write left a window for two concurrent close calls — or a close racing a
// concurrent decision that read the campaign while it was still "open" — to both pass
// their in-memory precondition before either write lands. Making the persist itself
// the single conditional statement closes that race the same way #319 closed it at
// the item layer: whichever call's UPDATE lands first wins (RowsAffected==1); the
// loser is told so instead of silently re-closing (or clobbering) the winner's record.
func (ls *LocalStorage) UpdateAccessReviewCampaign(ctx context.Context, c *models.AccessReviewCampaign) (bool, error) {
	res := ls.db.WithContext(ctx).Model(&models.AccessReviewCampaign{}).
		Where("id = ? AND state = ?", c.ID, accessReviewCampaignOpen).
		Select("*").
		Updates(c)
	if res.Error != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), res.Error)
	}
	return res.RowsAffected == 1, nil
}

// --- Items ---

func (ls *LocalStorage) CreateAccessReviewItems(ctx context.Context, items []*models.AccessReviewItem) error {
	if len(items) == 0 {
		return nil
	}
	if err := ls.db.WithContext(ctx).Create(items).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

func (ls *LocalStorage) ListAccessReviewItems(ctx context.Context, campaignID uint) ([]*models.AccessReviewItem, error) {
	var rows []*models.AccessReviewItem
	err := ls.db.WithContext(ctx).
		Where("campaign_id = ?", campaignID).
		Order("id ASC").
		Limit(maxUnboundedListRows).
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

// CountPendingAccessReviewItems returns the number of items still awaiting a
// decision for a campaign via a single `COUNT(*) WHERE decision = 'pending'`, not by
// loading every item row and tallying in Go — used by the recertification scheduler
// tick (#238) to size an in-flight campaign's remaining work for a reminder.
func (ls *LocalStorage) CountPendingAccessReviewItems(ctx context.Context, campaignID uint) (int, error) {
	var n int64
	err := ls.db.WithContext(ctx).Model(&models.AccessReviewItem{}).
		Where("campaign_id = ? AND decision = ?", campaignID, accessReviewItemPending).
		Count(&n).Error
	if err != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return int(n), nil
}

func (ls *LocalStorage) GetAccessReviewItem(ctx context.Context, id uint) (*models.AccessReviewItem, error) {
	var item models.AccessReviewItem
	if err := ls.db.WithContext(ctx).First(&item, id).Error; err != nil {
		// Was an unconditional "not found" wrap regardless of the underlying
		// error, so a genuine storage failure (e.g. a closed/unreachable DB)
		// read identically to a real not-found to any caller string-matching
		// on it. Distinguish genuine not-found (gorm.ErrRecordNotFound) from
		// everything else, matching GetMachineIdentityCredentialByID's/
		// GetAccessRequest's already-established fix for the identical bug
		// class.
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &item, nil
}

// accessReviewItemPending mirrors core.ReviewItemPending (the store package cannot
// import core: core already imports storage/store). Both sides of this decision
// state machine — core's pre-check and this conditional UPDATE — must agree on the
// same "undecided" sentinel string.
const accessReviewItemPending = "pending"

// UpdateAccessReviewItem persists a recertification decision with a conditional
// UPDATE (`WHERE id = ? AND decision = 'pending' AND campaign_id IN (SELECT id FROM
// access_review_campaigns WHERE id = ? AND state = 'open')`), not an unconditional
// Save. A decision is a one-way transition (pending -> attested|revoked):
// DecideAccessReviewItem reads the item AND the campaign, checks the item is still
// pending and the campaign is still open, then acts and persists — a plain
// read-then-write with a gap in between (the action itself, plus everything else in
// the request) wide enough for two concurrent/replayed decisions to both pass the
// pending check before either writes (#319), or for a decision to observe the
// campaign as "open" immediately before a concurrent force-close freezes it (#343).
// Making the persist itself a single conditional statement that verifies BOTH
// preconditions atomically closes both races in one shot: whichever write lands
// first wins (RowsAffected==1); the loser's UPDATE matches zero rows and is told so,
// instead of silently overwriting the winner's decision (#319) or landing a fresh
// decision into a campaign whose evidence snapshot was supposed to be frozen at
// close time (#343).
func (ls *LocalStorage) UpdateAccessReviewItem(ctx context.Context, item *models.AccessReviewItem) (bool, error) {
	openCampaign := ls.db.Model(&models.AccessReviewCampaign{}).
		Select("id").
		Where("id = ? AND state = ?", item.CampaignID, accessReviewCampaignOpen)
	res := ls.db.WithContext(ctx).Model(&models.AccessReviewItem{}).
		Where("id = ? AND decision = ? AND campaign_id IN (?)", item.ID, accessReviewItemPending, openCampaign).
		Select("*").
		Updates(item)
	if res.Error != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), res.Error)
	}
	return res.RowsAffected == 1, nil
}
