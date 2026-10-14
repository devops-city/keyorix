// secret_listing_query.go — ListSecretsWithSharingInfo and helpers.
//
// For sharing status and UI indicators see secret_listing_sharing.go.
package core

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ListSecretsInScope lists every secret in the filter's project/environment
// scope, with no per-user ownership or sharing resolution. It backs machine
// principals (ADR-030), which have no user identity and whose authorization to
// the scope is already enforced by the route's scoped-permission gate. The
// response shape matches ListSecretsWithSharingInfo so the handler is uniform;
// the sharing fields are owner-agnostic (a machine does not "own" or have
// secrets "shared with" it).
func (c *KeyorixCore) ListSecretsInScope(ctx context.Context, filter *models.SecretListFilter) (*models.SecretListResponse, error) {
	if filter == nil {
		filter = &models.SecretListFilter{}
	}
	rows, clamped, err := c.listSecretsInScopeRows(ctx, filter)
	if err != nil {
		return nil, err
	}
	// No sharing metadata on this path, so the sharing-dependent filters cannot be
	// evaluated and are deliberately not applied here -- see
	// secretPassesSharingFilters. The one external caller is the machine-identity
	// branch (secrets_list.go), where ownership and shares do not apply to the
	// principal at all; ListSecretsInScopeWithSharingInfo is the path that has the
	// metadata and does apply them.
	return c.pageScopedSecrets(ctx, rows, filter, clamped), nil
}

// listSecretsInScopeRows is the shared, UNPAGINATED body of ListSecretsInScope and
// ListSecretsInScopeWithSharingInfo: the storage fetch plus every filter that can
// be decided from the secret row alone.
//
// Split out so the sharing-info variant can attach its metadata and apply the
// sharing-dependent filters BEFORE pagination. Doing it after would reproduce
// #251 one layer up -- Total and TotalPages would describe the pre-filter set
// while Secrets carried the post-filter one, which is exactly what this file's
// own convertToStorageFilter comment exists to prevent.
//
// clamped reports that the storage bound (secretListingMaxRows) cut the row set
// short, so the eventual Total is a floor rather than a count.
func (c *KeyorixCore) listSecretsInScopeRows(ctx context.Context, filter *models.SecretListFilter) (rows []*models.SecretWithSharingInfo, clamped bool, err error) {
	storageFilter := c.convertToStorageFilter(filter)
	// storageTotal is the PRE-LIMIT COUNT(*) from the storage layer, and it is the
	// only place the secretListingMaxRows clamp is observable. It used to be
	// discarded into `_`, and that single character was what made every truncation
	// signal in this package inert: Total is derived from the length of the
	// ALREADY-CLAMPED set, so len(resp.Secrets) == resp.Total always held and
	// nothing downstream could ever detect a short count. A scope holding more than
	// secretListingMaxRows secrets returned exactly that many with Truncated=false
	// -- a confidently-wrong floor presented as a count, which is the defect class
	// #2780 exists to remove. Found by the coordinator's review of #2874 (F1).
	secrets, storageTotal, err := c.storage.ListSecrets(ctx, storageFilter)
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	// Compared against the ROW COUNT, not against the post-filter total: the
	// in-memory filters below legitimately shrink the set further, so a smaller
	// total is normal and is not truncation. Only the storage clamp is, and it
	// shows up as storage having more matching rows than it handed back.
	clamped = storageTotal > int64(len(secrets))

	all := make([]*models.SecretWithSharingInfo, 0, len(secrets))
	for _, secret := range secrets {
		all = append(all, &models.SecretWithSharingInfo{SecretNode: secret})
	}
	return c.applySecretFilters(ctx, all, filter), clamped, nil
}

// pageScopedSecrets sorts, pages and annotates a scoped listing result. Shared by
// both scoped list entry points so the truncation signal cannot be set on one and
// forgotten on the other.
func (c *KeyorixCore) pageScopedSecrets(ctx context.Context, all []*models.SecretWithSharingInfo, filter *models.SecretListFilter, clamped bool) *models.SecretListResponse {
	_ = ctx
	c.sortSecrets(all, filter.SortBy, filter.SortOrder)

	total := int64(len(all))
	page := max(filter.Page, 1)
	pageSize := filter.PageSize
	if pageSize < 1 {
		pageSize = 20
	}
	start := (page - 1) * pageSize
	end := start + pageSize
	totalInt := int(total)
	if start > totalInt {
		start = totalInt
	}
	if end > totalInt {
		end = totalInt
	}
	totalPages := (totalInt + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}
	resp := &models.SecretListResponse{
		Secrets:    all[start:end],
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}
	// Set HERE rather than in each caller, so every path through a scoped listing
	// is covered by construction: ListReadableSecrets' tier 1 (global reader, no
	// scope filter), its tier 2 union (per scope), and the machine branch all land
	// on this one function. Tier 1 previously had no truncation check at all.
	if clamped {
		resp.Truncated = true
		resp.TruncatedReason = fmt.Sprintf(
			"the secret listing is bounded at %d rows per query and this scope matches more; "+
				"the total shown is a floor, not a count", c.listingMaxRows())
	}
	return resp
}

// ListSecretsInScopeWithSharingInfo lists every secret in the filter's
// project/environment scope — like ListSecretsInScope — but additionally
// attaches per-secret sharing metadata (ownership / share / ACL status) for
// userID where applicable.
//
// Use this instead of ListSecretsWithSharingInfo when userID holds a
// role-based secrets.read grant covering the requested scope: unlike
// ListSecretsWithSharingInfo (which only ever surfaces secrets the user
// personally owns or holds a per-secret ACL/share grant for), this surfaces
// every secret the ROLE itself grants visibility to. Without it, a
// project-scoped viewer role could GET any individual secret in their
// project (RequireScopedPermission's middleware honors the role) but never
// discover it via listing, since the list path checked ownership/ACL/shares
// only and ignored the role entirely.
func (c *KeyorixCore) ListSecretsInScopeWithSharingInfo(ctx context.Context, userID uint, filter *models.SecretListFilter) (*models.SecretListResponse, error) {
	if filter == nil {
		filter = &models.SecretListFilter{}
	}
	// Rows, not a paged response: the sharing metadata is attached and the
	// sharing-dependent filters applied BEFORE pagination below. This used to call
	// ListSecretsInScope, i.e. it paged first and never applied those filters at
	// all -- see secretPassesSharingFilters for what that cost.
	rows, clamped, err := c.listSecretsInScopeRows(ctx, filter)
	if err != nil {
		return nil, err
	}
	// PAT-GUARD-1: every caller authorizes the filter's scope before calling this,
	// so for them this is a no-op. It is here so the function cannot return a row
	// outside a PAT restriction if a future caller forgets to.
	rows = filterSecretsByPATRestriction(ctx, rows)
	if len(rows) == 0 {
		return c.pageScopedSecrets(ctx, rows, filter, clamped), nil
	}

	// Sharing-info lookup, built from the same three sources
	// ListSecretsWithSharingInfo merges, mirroring its semantics exactly
	// (including "shared secrets excluded when filtering by project"). These
	// are raw, UNPAGINATED calls used only to attach metadata onto the
	// already-paginated base set above — never to replace it or its
	// pagination, which reflects the full role-visible scope, not just the
	// owned/ACL/shared subset.
	owned, err := c.getOwnedSecretsWithSharingInfo(ctx, userID, filter)
	if err != nil {
		return nil, err
	}
	// The caller's own shares are looked up for a project-scoped listing too. Here they
	// only DECORATE rows the role already makes visible (the byID join below never adds a
	// row), so the "shared secrets are excluded when filtering by project" rule that
	// ListSecretsWithSharingInfo applies to the rows it adds does not apply. Without them
	// a recipient of a write share on a secret in their own project got no user_permission,
	// and the UI could not offer the Edit / Rotate the share elevates them to.
	shared, err := c.getSharedSecretsWithSharingInfo(ctx, userID, filter)
	if err != nil {
		return nil, err
	}
	aclGranted, err := c.getACLGrantedSecretsWithSharingInfo(ctx, userID, filter)
	if err != nil {
		return nil, err
	}

	// Precedence matches ListSecretsWithSharingInfo's own merge order
	// (owned, then shared, then ACL-granted) so a secret that is e.g. both
	// owned and ACL-granted reports as owned, not ACL-granted.
	byID := make(map[uint]*models.SecretWithSharingInfo, len(owned)+len(shared)+len(aclGranted))
	for _, s := range aclGranted {
		byID[s.ID] = s
	}
	for _, s := range shared {
		byID[s.ID] = s
	}
	for _, s := range owned {
		byID[s.ID] = s
	}

	for _, s := range rows {
		info, ok := byID[s.ID]
		if !ok {
			continue // visible via role only -- no owned/shared/ACL relationship
		}
		s.IsShared = info.IsShared
		s.IsOwnedByUser = info.IsOwnedByUser
		s.OwnerUsername = info.OwnerUsername
		s.UserPermission = info.UserPermission
		s.ShareCount = info.ShareCount
		s.SharedAt = info.SharedAt
		s.SharedBy = info.SharedBy
		s.SharingIndicators = info.SharingIndicators
	}

	// Only now, with IsShared/IsOwnedByUser populated, can the sharing-dependent
	// filters be evaluated -- and before pagination, so Total describes the set
	// actually returned.
	filtered := make([]*models.SecretWithSharingInfo, 0, len(rows))
	for _, s := range rows {
		if secretPassesSharingFilters(s, filter) {
			filtered = append(filtered, s)
		}
	}
	// F3 (coordinator review of #2874): the aggregate counts are wire fields the UI
	// renders, and they were populated only by ListSecretsWithSharingInfo -- so
	// every caller routed here (which, since this PR, is every global and
	// scope-granted reader) got three zeroes. Computed from the same attached
	// metadata, over the WHOLE filtered set rather than the current page, matching
	// Total's own scope.
	resp := c.pageScopedSecrets(ctx, filtered, filter, clamped)
	for _, s := range filtered {
		switch {
		case s.IsOwnedByUser:
			resp.OwnedCount++
		case s.IsShared:
			resp.SharedCount++
		case s.UserPermission != "":
			resp.ACLGrantedCount++
		}
	}
	return resp, nil
}

// secretPassesSharingFilters evaluates the two list filters that depend on
// per-secret SHARING metadata (IsShared / IsOwnedByUser), separately from
// secretPassesFilters, which may run before that metadata is attached.
//
// Splitting them is the F2 fix from the coordinator's review of #2874. The
// sharing-only predicate used to live in secretPassesFilters, which
// listSecretsInScopeRows runs over bare &SecretWithSharingInfo{SecretNode: ...}
// values -- so `filter.ShowSharedOnly && !s.IsShared` was evaluated against the
// ZERO value and dropped everything: ?show_shared_only=true returned total: 0 for
// a global reader who did have shared secrets. And ShowOwnedOnly was not checked
// anywhere at all, so ?show_owned_only=true returned the whole deployment. Both
// params are parsed in secrets_list.go and documented in openapi.yaml, and both
// were honoured by the ListSecretsWithSharingInfo path this PR's tier 1 replaced.
//
// Defined as a free function, not a method: it reads only the two attached
// booleans, so a reviewer can see at a glance that it cannot query anything and
// therefore cannot be correct-looking-but-unpopulated the way the old call site
// was.
func secretPassesSharingFilters(s *models.SecretWithSharingInfo, filter *models.SecretListFilter) bool {
	if filter.ShowSharedOnly && !s.IsShared {
		return false
	}
	if filter.ShowOwnedOnly && !s.IsOwnedByUser {
		return false
	}
	return true
}

// ListSecretsWithSharingInfo lists secrets with sharing information for a specific user.
func (c *KeyorixCore) ListSecretsWithSharingInfo(ctx context.Context, userID uint, filter *models.SecretListFilter) (*models.SecretListResponse, error) { // NOSONAR -- cognitive complexity 19, suppress go:S3776
	if filter == nil {
		filter = &models.SecretListFilter{}
	}

	// Fetch owned secrets (skip when user only wants to see what's shared with them).
	var ownedSecrets []*models.SecretWithSharingInfo
	if !filter.ShowSharedOnly {
		var err error
		ownedSecrets, err = c.getOwnedSecretsWithSharingInfo(ctx, userID, filter)
		if err != nil {
			return nil, err
		}
	}

	// Fetch shared secrets (only when not filtering by project — project view shows owned only).
	var sharedSecrets []*models.SecretWithSharingInfo
	if !filter.ShowOwnedOnly && filter.ProjectID == nil {
		var err error
		sharedSecrets, err = c.getSharedSecretsWithSharingInfo(ctx, userID, filter)
		if err != nil {
			return nil, err
		}
	}

	// Fetch ACL-granted secrets — secrets the user holds a per-secret or per-folder
	// SecretACL grant for but neither owns nor has a legacy ShareRecord for.
	var aclGrantedSecrets []*models.SecretWithSharingInfo
	if !filter.ShowOwnedOnly {
		var err error
		aclGrantedSecrets, err = c.getACLGrantedSecretsWithSharingInfo(ctx, userID, filter)
		if err != nil {
			return nil, err
		}
	}

	// PAT-GUARD-1: this set is decided by ownership, shares and ACL rows, never by
	// Authorize, so it must apply the caller's PAT restriction itself. Filtered per
	// source, before the merge, so OwnedCount/SharedCount/ACLGrantedCount describe
	// the rows the token can actually see.
	ownedSecrets = filterSecretsByPATRestriction(ctx, ownedSecrets)
	sharedSecrets = filterSecretsByPATRestriction(ctx, sharedSecrets)
	aclGrantedSecrets = filterSecretsByPATRestriction(ctx, aclGrantedSecrets)

	// Merge owned + shared + acl-granted, deduplicating by secret ID.
	// aclDistinctCount tracks how many ACL-granted secrets were NOT already
	// covered by owned or shared, so ACLGrantedCount reflects only net-new grants.
	seen := make(map[uint]bool)
	var all []*models.SecretWithSharingInfo
	for _, s := range ownedSecrets {
		if !seen[s.ID] {
			seen[s.ID] = true
			all = append(all, s)
		}
	}
	for _, s := range sharedSecrets {
		if !seen[s.ID] {
			seen[s.ID] = true
			all = append(all, s)
		}
	}
	aclDistinctCount := 0
	for _, s := range aclGrantedSecrets {
		if !seen[s.ID] {
			seen[s.ID] = true
			all = append(all, s)
			aclDistinctCount++
		}
	}

	// Apply post-fetch filters (search, type, shared-only)
	all = c.applySecretFilters(ctx, all, filter)
	// The sharing-dependent filters, applied here too. They used to be folded into
	// applySecretFilters, where this path's populated metadata made them work and
	// the scoped path's unpopulated metadata made them wrong (F2). Keeping them for
	// THIS caller is not redundant with its own fetch gating above: with
	// ShowSharedOnly set it skips the owned fetch but still fetches ACL-granted
	// secrets, which are not shared -- so without this pass ?show_shared_only=true
	// would start returning ACL grants, a behaviour change this fix must not make.
	sharingFiltered := make([]*models.SecretWithSharingInfo, 0, len(all))
	for _, sec := range all {
		if secretPassesSharingFilters(sec, filter) {
			sharingFiltered = append(sharingFiltered, sec)
		}
	}
	all = sharingFiltered

	// Sort
	c.sortSecrets(all, filter.SortBy, filter.SortOrder)

	total := int64(len(all))

	// Paginate
	page := max(filter.Page, 1)
	pageSize := filter.PageSize
	if pageSize < 1 {
		pageSize = 20
	}
	start := (page - 1) * pageSize
	end := start + pageSize
	totalInt := int(total)
	if start > totalInt {
		start = totalInt
	}
	if end > totalInt {
		end = totalInt
	}
	paged := all[start:end]

	totalPages := (totalInt + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}

	return &models.SecretListResponse{
		Secrets:         paged,
		Total:           total,
		Page:            page,
		PageSize:        pageSize,
		TotalPages:      totalPages,
		OwnedCount:      len(ownedSecrets),
		SharedCount:     len(sharedSecrets),
		ACLGrantedCount: aclDistinctCount,
	}, nil
}

// getOwnedSecretsWithSharingInfo retrieves secrets owned by the user with sharing information.
func (c *KeyorixCore) getOwnedSecretsWithSharingInfo(ctx context.Context, userID uint, filter *models.SecretListFilter) ([]*models.SecretWithSharingInfo, error) {
	storageFilter := c.convertToStorageFilter(filter)

	// Resolve the user first — fail closed for an unknown/zero principal (e.g. a
	// machine identity has no owning user, so it owns no secrets).
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil || user == nil {
		return nil, fmt.Errorf("failed to resolve user for secret listing: %w", err)
	}
	// "Owned" means owner_id == userID — the canonical ownership the permission
	// model uses (CheckSecretPermission), not the created_by username string. The
	// username proxy missed CLI-created secrets (created_by "cli-user") and could
	// mis-attribute ownership across a deleted-then-reused username.
	storageFilter.OwnerID = &userID

	secrets, _, err := c.storage.ListSecrets(ctx, storageFilter)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	var result []*models.SecretWithSharingInfo
	for _, secret := range secrets {
		shares, err := c.storage.ListSharesBySecret(ctx, secret.ID, c.shareEffectiveNow())
		if err != nil {
			continue
		}
		s := &models.SecretWithSharingInfo{
			SecretNode:        secret,
			IsShared:          len(shares) > 0,
			IsOwnedByUser:     true,
			UserPermission:    "",
			ShareCount:        len(shares),
			SharingIndicators: c.buildSharingIndicators(secret, shares, true, ""),
		}
		result = append(result, s)
	}
	return result, nil
}

func (c *KeyorixCore) getSharedSecretsWithSharingInfo(ctx context.Context, userID uint, _ *models.SecretListFilter) ([]*models.SecretWithSharingInfo, error) {
	shares, err := c.storage.ListSharesByUser(ctx, userID, c.shareEffectiveNow())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	var result []*models.SecretWithSharingInfo
	for _, share := range shares {
		secret, err := c.storage.GetSecret(ctx, share.SecretID)
		if err != nil || secret == nil {
			continue
		}
		ownerUsername := ""
		if owner, err := c.storage.GetUser(ctx, secret.OwnerID); err == nil && owner != nil {
			ownerUsername = owner.Username
		}
		s := &models.SecretWithSharingInfo{
			SecretNode:        secret,
			IsShared:          true,
			IsOwnedByUser:     false,
			OwnerUsername:     ownerUsername,
			UserPermission:    string(share.Permission),
			ShareCount:        0,
			SharingIndicators: c.buildSharingIndicators(secret, nil, false, string(share.Permission)),
		}
		result = append(result, s)
	}
	return result, nil
}

func (c *KeyorixCore) applySecretFilters(ctx context.Context, secrets []*models.SecretWithSharingInfo, filter *models.SecretListFilter) []*models.SecretWithSharingInfo { // nosemgrep: keyorix-unbounded-bulk-slice-param -- secrets is an already-fetched, storage-bounded listing result, not a raw client-supplied array in one request
	// Tag filter: require every requested tag (AND). Resolved per secret only when a
	// tag filter is present, so the common no-tag list path does no extra queries.
	want := normalizeTagFilter(filter.Tags)
	var out []*models.SecretWithSharingInfo
	for _, s := range secrets {
		if c.secretPassesFilters(ctx, s, filter, want) {
			out = append(out, s)
		}
	}
	return out
}

// secretPassesFilters reports whether a secret satisfies every list filter that
// can be decided from the secret ROW alone.
//
// ShowSharedOnly/ShowOwnedOnly are deliberately NOT here: they depend on sharing
// metadata that is attached later, and evaluating ShowSharedOnly here against an
// unpopulated IsShared is precisely the F2 defect. They live in
// secretPassesSharingFilters, which only runs where the metadata exists.
func (c *KeyorixCore) secretPassesFilters(ctx context.Context, s *models.SecretWithSharingInfo, filter *models.SecretListFilter, want []string) bool {
	if len(want) > 0 && !c.secretHasAllTags(ctx, s.ID, want) {
		return false
	}
	if filter.Search != nil && *filter.Search != "" {
		if !c.secretMatchesSearch(ctx, s, strings.ToLower(*filter.Search)) {
			return false
		}
	}
	if filter.Type != nil && *filter.Type != "" && s.Type != *filter.Type {
		return false
	}
	if !secretMatchesClassification(s, filter) {
		return false
	}
	return secretMatchesExpiration(s, filter)
}

func secretMatchesClassification(s *models.SecretWithSharingInfo, filter *models.SecretListFilter) bool {
	if filter.Classification == nil || *filter.Classification == "" {
		return true
	}
	if *filter.Classification == "unclassified" {
		return s.Classification == ""
	}
	return s.Classification == *filter.Classification
}

func secretMatchesExpiration(s *models.SecretWithSharingInfo, filter *models.SecretListFilter) bool {
	if filter.ExpiresBefore == nil {
		return true
	}
	return s.Expiration != nil && s.Expiration.Before(*filter.ExpiresBefore)
}

// normalizeTagFilter trims/lowercases/de-duplicates requested tag filters (matching
// how tags are stored), dropping empties.
func normalizeTagFilter(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		t := strings.ToLower(strings.TrimSpace(raw))
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}

// secretHasAllTags reports whether the secret carries every tag in want. A storage
// error is treated as "no match" (fail closed — the secret is excluded).
func (c *KeyorixCore) secretHasAllTags(ctx context.Context, secretID uint, want []string) bool {
	have, err := c.storage.GetSecretTags(ctx, secretID)
	if err != nil {
		return false
	}
	set := make(map[string]bool, len(have))
	for _, t := range have {
		set[t] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}

// secretMatchesSearch reports whether the secret matches the (lower-cased) search
// query by name, description, or any tag. Name/description are in-memory; tags are
// looked up only when neither already matched (so the common name-hit costs nothing
// extra). A tag-lookup error just means tags don't contribute to the match.
func (c *KeyorixCore) secretMatchesSearch(ctx context.Context, s *models.SecretWithSharingInfo, q string) bool {
	if strings.Contains(strings.ToLower(s.Name), q) {
		return true
	}
	if s.Description != "" && strings.Contains(strings.ToLower(s.Description), q) {
		return true
	}
	tags, err := c.storage.GetSecretTags(ctx, s.ID)
	if err != nil {
		return false
	}
	for _, t := range tags { // stored tags are already lower-cased
		if strings.Contains(t, q) {
			return true
		}
	}
	return false
}

// sortSecrets sorts the secret list by name, created_at, updated_at, or owner.
// Uses strict comparators (Before/After, <, >) so equal elements return false in
// both directions, letting sort.SliceStable preserve insertion order as a tie-break.
func (c *KeyorixCore) sortSecrets(secrets []*models.SecretWithSharingInfo, sortBy, sortOrder string) { // NOSONAR -- cognitive complexity 16, suppress go:S3776
	if sortBy == "" {
		sortBy = "updated_at"
	}
	if sortOrder == "" {
		sortOrder = "desc"
	}
	desc := sortOrder == "desc"
	sort.SliceStable(secrets, func(i, j int) bool {
		a, b := secrets[i], secrets[j]
		switch sortBy {
		case "name":
			if desc {
				return a.Name > b.Name
			}
			return a.Name < b.Name
		case "created_at":
			if desc {
				return a.CreatedAt.After(b.CreatedAt)
			}
			return a.CreatedAt.Before(b.CreatedAt)
		case "owner":
			if desc {
				return a.OwnerUsername > b.OwnerUsername
			}
			return a.OwnerUsername < b.OwnerUsername
		default: // updated_at / recently modified
			if desc {
				return a.UpdatedAt.After(b.UpdatedAt)
			}
			return a.UpdatedAt.Before(b.UpdatedAt)
		}
	})
}

// secretListingMaxRows bounds the single unpaginated storage fetch backing
// ListSecretsInScope / ListSecretsWithSharingInfo (mirrors secretInventoryMaxRows
// in secret_inventory.go). Both callers apply post-fetch filters in Go — tag
// AND-matching and cross-field search need a per-secret storage lookup, and
// ShowSharedOnly only makes sense after owned+shared results are merged — none of
// which can be expressed as a single SQL predicate the storage layer could apply
// before its own LIMIT/OFFSET. If the DB paginated to the caller's requested page
// FIRST and the post-fetch filter ran second, the filter would silently operate on
// (and the code below would re-paginate) an already-sliced page: page >= 2 could
// come back empty even when more genuinely-matching secrets exist beyond page 1,
// and Total/TotalPages would reflect the pre-filter page count rather than the
// true post-filter match count (#251). So the storage fetch always pulls every
// matching row (up to this bound) and pagination is applied once, in Go, after
// filtering the full set.
const secretListingMaxRows = 10000

// listingMaxRows is the storage row bound actually in force. It is injectable for
// the same reason unionPageSize is: a bound that can only be exercised by seeding
// 10001 secrets is a bound nobody has watched behave, and this one had never been
// watched at all — it silently shadowed the union bound every truncation test
// thought it was driving (coordinator review of #2874, F1).
func (c *KeyorixCore) listingMaxRows() int {
	if c.listingMaxRowsOverride > 0 {
		return c.listingMaxRowsOverride
	}
	return secretListingMaxRows
}

// convertToStorageFilter converts SecretListFilter to storage.SecretFilter. It
// deliberately ignores the caller's Page/PageSize — see secretListingMaxRows.
// Search is intentionally NOT forwarded: the storage layer's LIKE filter only
// matches by name, while the in-memory applySecretFilters / secretMatchesSearch
// covers name + description + tags. Pushing Search into SQL would exclude
// description/tag matches before they ever reach the in-memory pass.
func (c *KeyorixCore) convertToStorageFilter(filter *models.SecretListFilter) *storage.SecretFilter {
	return &storage.SecretFilter{
		Page:           1,
		PageSize:       c.listingMaxRows(),
		Type:           filter.Type,
		Classification: filter.Classification,
		CreatedBy:      filter.CreatedBy,
		ProjectID:      filter.ProjectID,
		EnvironmentID:  filter.EnvironmentID,
		IncludeDeleted: filter.IncludeDeleted,
		ParentID:       filter.ParentID,
		FolderOnly:     filter.FolderOnly,
	}
}

// aclFolderMaxDepth caps the BFS depth when expanding folder-level ACL grants to
// their descendant leaf secrets. Mirrors the ancestor-walk cap in GetSecretAncestors.
const aclFolderMaxDepth = 20

// getACLGrantedSecretsWithSharingInfo returns secrets the user holds a per-secret or
// per-folder SecretACL grant for but neither owns nor has a legacy ShareRecord for.
// It expands folder grants by collecting all descendant leaf secrets via BFS.
func (c *KeyorixCore) getACLGrantedSecretsWithSharingInfo(ctx context.Context, userID uint, filter *models.SecretListFilter) ([]*models.SecretWithSharingInfo, error) {
	acls, err := c.storage.ListSecretACLsByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	if len(acls) == 0 {
		return nil, nil
	}

	seen := make(map[uint]bool)
	var result []*models.SecretWithSharingInfo

	for _, acl := range acls {
		c.applyACLGrant(ctx, acl, filter, seen, &result)
	}

	return result, nil
}

// collectFolderDescendants does a BFS from folderID and returns all leaf
// (IsSecret=true) descendant SecretNodes. Sub-folders are expanded up to
// aclFolderMaxDepth levels to match the ancestor-walk cap in HasSecretACL.
// Project/environment filters are honoured so that a folder grant in project A
// does not bleed into project B when the caller is listing project B only.
func (c *KeyorixCore) collectFolderDescendants(ctx context.Context, folderID uint, filter *models.SecretListFilter, depth int) []*models.SecretNode {
	if depth >= aclFolderMaxDepth {
		return nil
	}
	sf := &storage.SecretFilter{
		Page:          1,
		PageSize:      secretListingMaxRows,
		ParentID:      &folderID,
		ProjectID:     filter.ProjectID,
		EnvironmentID: filter.EnvironmentID,
	}
	children, _, err := c.storage.ListSecrets(ctx, sf)
	if err != nil {
		return nil
	}
	var result []*models.SecretNode
	for _, child := range children {
		if child.IsSecret {
			result = append(result, child)
		} else {
			result = append(result, c.collectFolderDescendants(ctx, child.ID, filter, depth+1)...)
		}
	}
	return result
}

// applyACLGrant processes a single ACL grant, expanding folder nodes to leaf
// secrets and appending any un-seen entries to result.
func (c *KeyorixCore) applyACLGrant(ctx context.Context, acl *models.SecretACL, filter *models.SecretListFilter, seen map[uint]bool, result *[]*models.SecretWithSharingInfo) {
	perm := ""
	if perms := DecodeSecretACLPerms(acl.Permissions); len(perms) > 0 {
		perm = normaliseACLPerm(perms[0])
	}

	node, err := c.storage.GetSecret(ctx, acl.SecretID)
	if err != nil || node == nil {
		return
	}
	if filter.ProjectID != nil && node.ProjectID != *filter.ProjectID {
		return
	}
	if filter.EnvironmentID != nil && node.EnvironmentID != *filter.EnvironmentID {
		return
	}

	var leaves []*models.SecretNode
	if node.IsSecret {
		leaves = []*models.SecretNode{node}
	} else {
		leaves = c.collectFolderDescendants(ctx, node.ID, filter, 0)
	}

	for _, leaf := range leaves {
		if seen[leaf.ID] {
			continue
		}
		seen[leaf.ID] = true
		*result = append(*result, &models.SecretWithSharingInfo{
			SecretNode:        leaf,
			IsShared:          false,
			IsOwnedByUser:     false,
			UserPermission:    perm,
			SharingIndicators: c.buildSharingIndicators(leaf, nil, false, perm),
		})
	}
}

// normaliseACLPerm maps an RBAC-style ACL permission name ("secrets.read",
// "secrets.write") to the sharing-style short form ("read", "write") used by
// the SharingIndicators builder and the UserPermission field. Unknown values
// are returned unchanged.
func normaliseACLPerm(p string) string {
	switch p {
	case "secrets.read":
		return "read"
	case "secrets.write":
		return "write"
	default:
		return p
	}
}
