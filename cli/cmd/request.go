// request.go ports `keyorix request` (docs/cli-split-inventory.md §2.5, PR 7): project
// access requests (ADR-024) -- access (create), list, withdraw, review (approve/reject),
// secret-access (the narrower single-secret-value variant), bulk-approve/bulk-reject, and
// rejection-reason-template management. Same flags, output, and exit codes as the old
// CLI's internal/cli/request package's remote-mode branch -- a pure transport port (REST
// only), not a behavior change.
//
// GAP-F-BULK (Finding S15, docs/cli-split-inventory.md §7's listed hard prerequisite for
// this PR) does not block this port: it described bulk-approve/bulk-reject/rejection-
// templates-delete never checking common.NewRemoteClient() in the OLD CLI, silently
// operating on local storage instead of a configured remote server. That bug was already
// fixed independently before this track started (PR #2014, "fix(cli): dual-mode request
// bulk-approve/bulk-reject/rejection-templates delete") -- confirmed by reading the
// current internal/cli/request/bulk.go, which checks NewRemoteClient() correctly in all
// three commands. This thin CLI is REST-only from the start, so the bug's local-mode half
// cannot recur here regardless.
package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

var requestCmd = &cobra.Command{
	Use:   "request",
	Short: "Manage project access requests",
	Long:  "Request access to a project, list, withdraw, and review (approve/reject) requests (ADR-024).",
}

func init() {
	requestCmd.AddCommand(requestAccessCmd, requestSecretAccessCmd, requestListCmd, requestWithdrawCmd, requestReviewCmd,
		requestBulkApproveCmd, requestBulkRejectCmd, requestRejectionTemplatesCmd)
}

// requestProjectName resolves a project name from --project or KEYORIX_PROJECT (this
// thin CLI has no persisted "active project" concept yet -- see cli/cmd/client.go; that's
// PR 6 scope, not duplicated here to avoid a merge conflict once both land).
func requestProjectName(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if v := os.Getenv("KEYORIX_PROJECT"); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("no project specified — use --project or set KEYORIX_PROJECT")
}

// projectIDFlagUsage is the shared --project-id help text. Every `keyorix request`
// subcommand carries it (#2360): project-NAME resolution goes through
// resolveRequestProjectID -> GET /api/v1/projects.
//
// Since #2780 that listing serves a project-scoped caller their own projects, so
// --project now works for anyone who already holds a grant somewhere. It still
// cannot help the persona self-service access requests exist for -- a caller with
// NO project grant at all, who has nothing to list and therefore no way to turn a
// name into the ID these project-scoped routes need in their URL. That is a
// property of not having access yet, not a gate the listing imposes, and
// --project-id is how such a caller proceeds.
const projectIDFlagUsage = "Project ID -- use this instead of --project when the caller holds no project grant yet " +
	"(nothing to list, so a name cannot be resolved); the project-scoped access-request routes themselves do not require it"

// requestProjectTarget resolves which project a `keyorix request` subcommand targets
// from its own --project-id / --project flags (and KEYORIX_PROJECT), before any network
// call, so a missing flag fails fast without contacting the server.
//
// A nonzero projectID means --project-id was given: resolveRequestProjectID (and the
// GET /api/v1/projects listing behind it) is bypassed entirely, which remains the only
// path open to a caller holding no project grants — since #2780 the listing serves a
// project-scoped caller their own projects, but a caller with nothing granted still has
// nothing to list. Otherwise projectName is resolved through that listing.
//
// Exactly one of the two return values is ever meaningful: (id, "") or (0, name).
func requestProjectTarget(projectIDFlag uint, projectNameFlag string) (projectID uint, projectName string, err error) {
	if projectIDFlag != 0 {
		return projectIDFlag, "", nil
	}
	projectName, err = requestProjectName(projectNameFlag)
	if err != nil {
		return 0, "", fmt.Errorf("no project specified — use --project, --project-id, or set KEYORIX_PROJECT")
	}
	return 0, projectName, nil
}

// requestResolveProject completes requestProjectTarget once a client exists: it turns a
// name into an ID via the listing, and is a no-op when --project-id already supplied one.
func requestResolveProject(ctx context.Context, client *apiclient.ClientWithResponses, projectID uint, projectName string) (uint, error) {
	if projectID != 0 {
		return projectID, nil
	}
	return resolveRequestProjectID(ctx, client, projectName)
}

// resolveRequestProjectID finds a project's ID by exact name match via GET /api/v1/projects.
func resolveRequestProjectID(ctx context.Context, client *apiclient.ClientWithResponses, name string) (uint, error) {
	_, id, err := resolveProjectRef(ctx, client, name, false)
	if err != nil {
		return 0, err
	}
	return uint(id), nil // #nosec G115 -- resolveProjectRef only returns positive IDs
}

// requestAccessRequest mirrors models.AccessRequest's untagged, PascalCase wire shape
// (matches this package's own doc comment, and rotation.go's documented precedent).
type requestAccessRequest struct {
	ID                uint
	ProjectID         uint
	UserID            uint
	SuggestedRole     string
	GrantedRole       string
	SecretID          *uint
	State             string
	Reason            string
	ApprovalsReceived int
	RequiredApprovals int
}

func fetchAccessRequests(ctx context.Context, client *apiclient.ClientWithResponses, projectID uint) ([]requestAccessRequest, error) {
	resp, err := client.ListAccessRequestsWithResponse(ctx, int(projectID))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() != 200 {
		return nil, apiError("list access requests", resp.StatusCode(), resp.Body)
	}
	data, err := decodeData[struct {
		AccessRequests []requestAccessRequest `json:"access_requests"`
	}](resp.Body)
	if err != nil {
		return nil, err
	}
	return data.AccessRequests, nil
}

// fetchAccessRequest finds one access request by ID within projectID's list. There is no
// human-facing GET-by-ID-alone route (mirrors the old CLI's identical doc comment,
// remote.go), so this is deliberately scoped to a single project's list.
func fetchAccessRequest(ctx context.Context, client *apiclient.ClientWithResponses, projectID, reqID uint) (requestAccessRequest, error) {
	requests, err := fetchAccessRequests(ctx, client, projectID)
	if err != nil {
		return requestAccessRequest{}, fmt.Errorf("failed to look up access request %d: %w", reqID, err)
	}
	for _, r := range requests {
		if r.ID == reqID {
			return r, nil
		}
	}
	return requestAccessRequest{}, fmt.Errorf("access request %d not found in project (id=%d)", reqID, projectID)
}

func requestUserLabel(ctx context.Context, client *apiclient.ClientWithResponses, userID uint) string {
	resp, err := client.GetUserWithResponse(ctx, int(userID))
	if err != nil || resp.StatusCode() != 200 {
		return fmt.Sprintf("#%d", userID)
	}
	u, err := decodeData[struct {
		ID       uint   `json:"id"`
		Username string `json:"username"`
	}](resp.Body)
	if err != nil || u.ID == 0 {
		return fmt.Sprintf("#%d", userID)
	}
	return fmt.Sprintf("%s (#%d)", u.Username, userID)
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// ── request access ───────────────────────────────────────────────────────────

var (
	requestAccessProject   string
	requestAccessProjectID uint
	requestAccessRole      string
	requestAccessReason    string
)

var requestAccessCmd = &cobra.Command{
	Use:   "access",
	Short: "Request access to a project",
	Long:  "Create a pending access request for the caller to a project, optionally suggesting a role (ADR-024).",
	RunE:  runRequestAccess,
}

func init() {
	requestAccessCmd.Flags().StringVar(&requestAccessProject, "project", "", "Project name (or use KEYORIX_PROJECT)")
	requestAccessCmd.Flags().UintVar(&requestAccessProjectID, "project-id", 0, projectIDFlagUsage)
	requestAccessCmd.Flags().StringVar(&requestAccessRole, "role", "", "Suggested project role (optional)")
	requestAccessCmd.Flags().StringVar(&requestAccessReason, "reason", "", "Reason for the request (optional)")
	requestAccessCmd.MarkFlagsMutuallyExclusive("project", "project-id")
}

// accessProjectDisplay renders the project for status output: the quoted name with its ID when
// known, otherwise just the bare ID (--project-id path, where no name lookup ever happened).
func accessProjectDisplay(projectID uint, projectName string) string {
	if projectName == "" {
		return fmt.Sprintf("id=%d", projectID)
	}
	return fmt.Sprintf("%q (id=%d)", projectName, projectID)
}

// requestProjectLabel is accessProjectDisplay for the messages that historically printed
// the quoted NAME alone (golden-output parity with the old CLI's request/review.go): the
// quoted name when one was given, the bare ID on the --project-id path.
func requestProjectLabel(projectID uint, projectName string) string {
	if projectName == "" {
		return fmt.Sprintf("id=%d", projectID)
	}
	return fmt.Sprintf("%q", projectName)
}

func runRequestAccess(_ *cobra.Command, _ []string) error {
	projectID, projectName, err := requestProjectTarget(requestAccessProjectID, requestAccessProject)
	if err != nil {
		return err
	}
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	if projectID, err = requestResolveProject(ctx, client, projectID, projectName); err != nil {
		return err
	}

	fmt.Printf("Requesting access to project %s...\n", accessProjectDisplay(projectID, projectName))
	fmt.Println("Note: this request is self-service -- it is always attributed to the authenticated " +
		"caller's own session. If you are requesting access on behalf of someone else, have them run " +
		"this command themselves via their own 'keyorix login' session.")

	body := apiclient.CreateAccessRequestJSONRequestBody{}
	if requestAccessRole != "" {
		body.SuggestedRole = &requestAccessRole
	}
	if requestAccessReason != "" {
		body.Reason = &requestAccessReason
	}
	resp, err := client.CreateAccessRequestWithResponse(ctx, int(projectID), body)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 && resp.StatusCode() != 201 {
		return apiError("request access", resp.StatusCode(), resp.Body)
	}
	data, err := decodeData[struct {
		AccessRequest requestAccessRequest `json:"access_request"`
	}](resp.Body)
	if err != nil {
		return err
	}
	req := data.AccessRequest
	confirmProject := projectName
	if confirmProject == "" {
		confirmProject = fmt.Sprintf("id=%d", req.ProjectID)
	}
	fmt.Printf("Access requested: id=%d project=%s requester=user#%d suggested-role=%s state=%s\n",
		req.ID, confirmProject, req.UserID, dashIfEmpty(req.SuggestedRole), req.State)
	return nil
}

// ── request list ─────────────────────────────────────────────────────────────

var (
	requestListProject   string
	requestListProjectID uint
)

var requestListCmd = &cobra.Command{
	Use:   "list",
	Short: "List a project's access requests",
	RunE:  runRequestList,
}

func init() {
	requestListCmd.Flags().StringVar(&requestListProject, "project", "", "Project name (or use KEYORIX_PROJECT)")
	requestListCmd.Flags().UintVar(&requestListProjectID, "project-id", 0, projectIDFlagUsage)
	requestListCmd.MarkFlagsMutuallyExclusive("project", "project-id")
}

func runRequestList(_ *cobra.Command, _ []string) error {
	if err := checkOutputFormat(requestListFormat); err != nil {
		return err
	}
	projectID, projectName, err := requestProjectTarget(requestListProjectID, requestListProject)
	if err != nil {
		return err
	}
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	if projectID, err = requestResolveProject(ctx, client, projectID, projectName); err != nil {
		return err
	}
	requests, err := fetchAccessRequests(ctx, client, projectID)
	if err != nil {
		return fmt.Errorf("failed to list access requests: %w", err)
	}
	return emitList(requestListFormat, requests, func() error {
		if len(requests) == 0 {
			fmt.Println("No access requests found.")
			return nil
		}
		fmt.Printf("%-6s %-24s %-14s %-14s %-11s %-10s %s\n", "ID", "USER", "SUGGESTED", "GRANTED", "STATE", "SECRET", "REASON")
		for _, req := range requests {
			secretCol := "-"
			if req.SecretID != nil {
				secretCol = fmt.Sprintf("#%d", *req.SecretID)
			}
			fmt.Printf("%-6d %-24s %-14s %-14s %-11s %-10s %s\n",
				req.ID, requestUserLabel(ctx, client, req.UserID), dashIfEmpty(req.SuggestedRole),
				dashIfEmpty(req.GrantedRole), req.State, secretCol, dashIfEmpty(req.Reason))
		}
		return nil
	})
}

// ── request withdraw ─────────────────────────────────────────────────────────

var (
	requestWithdrawID        uint
	requestWithdrawProject   string
	requestWithdrawProjectID uint
)

var requestWithdrawCmd = &cobra.Command{
	Use:   "withdraw",
	Short: "Withdraw your own pending access request",
	Long:  "Cancel a pending access request you own, by ID (self-service, ADR-024).",
	RunE:  runRequestWithdraw,
}

func init() {
	requestWithdrawCmd.Flags().UintVar(&requestWithdrawID, "id", 0, "Access request ID (required)")
	requestWithdrawCmd.Flags().StringVar(&requestWithdrawProject, "project", "", "Project name (or use --project-id / KEYORIX_PROJECT)")
	requestWithdrawCmd.Flags().UintVar(&requestWithdrawProjectID, "project-id", 0, projectIDFlagUsage)
	_ = requestWithdrawCmd.MarkFlagRequired("id")
	// --project is NOT MarkFlagRequired: #2360 -- the requester withdrawing their own
	// request is typically the zero-grant caller who cannot resolve a project NAME at
	// all. One of --project / --project-id / KEYORIX_PROJECT is required instead,
	// enforced in runRequestWithdraw.
	requestWithdrawCmd.MarkFlagsMutuallyExclusive("project", "project-id")
}

func runRequestWithdraw(_ *cobra.Command, _ []string) error {
	if requestWithdrawID == 0 {
		return fmt.Errorf("--id is required")
	}
	projectID, projectName, err := requestProjectTarget(requestWithdrawProjectID, requestWithdrawProject)
	if err != nil {
		return fmt.Errorf("%w (POST .../projects/{id}/access-requests/{requestId}/withdraw is project-scoped in its URL)", err)
	}
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	if projectID, err = requestResolveProject(ctx, client, projectID, projectName); err != nil {
		return err
	}
	fmt.Printf("Withdrawing access request %d from project %s...\n", requestWithdrawID, accessProjectDisplay(projectID, projectName))

	resp, err := client.WithdrawAccessRequestWithResponse(ctx, int(projectID), int(requestWithdrawID))
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("withdraw access request", resp.StatusCode(), resp.Body)
	}
	fmt.Printf("Access request %d withdrawn.\n", requestWithdrawID)
	return nil
}

// ── request review ───────────────────────────────────────────────────────────

var (
	requestReviewID        uint
	requestReviewAction    string
	requestReviewRole      string
	requestReviewReason    string
	requestReviewTTL       string
	requestReviewProject   string
	requestReviewProjectID uint
)

var requestReviewCmd = &cobra.Command{
	Use:   "review",
	Short: "Approve or reject a pending access request",
	Long: "Resolve a pending access request (admin-driven, ADR-024).\n" +
		"Approving grants the role at the project scope (--role overrides the suggested role);\n" +
		"rejecting records a --reason.",
	RunE: runRequestReview,
}

func init() {
	requestReviewCmd.Flags().UintVar(&requestReviewID, "id", 0, "Access request ID (required)")
	requestReviewCmd.Flags().StringVar(&requestReviewAction, "action", "", "approve | reject (required)")
	requestReviewCmd.Flags().StringVar(&requestReviewRole, "role", "", "Role to grant on approve (defaults to the suggested role)")
	requestReviewCmd.Flags().StringVar(&requestReviewReason, "reason", "", "Reason on reject")
	requestReviewCmd.Flags().StringVar(&requestReviewTTL, "ttl", "", "Time-bound the granted role on approve (Go duration, e.g. 4h); empty = permanent")
	requestReviewCmd.Flags().StringVar(&requestReviewProject, "project", "", "Project name (or use --project-id / KEYORIX_PROJECT)")
	requestReviewCmd.Flags().UintVar(&requestReviewProjectID, "project-id", 0, projectIDFlagUsage)
	_ = requestReviewCmd.MarkFlagRequired("id")
	_ = requestReviewCmd.MarkFlagRequired("action")
	// --project is NOT MarkFlagRequired: #2360 -- a reviewer may have no resolvable
	// project name available (a caller holding no project grant has nothing to list;
	// before #2780 a project-scoped reviewer was denied the listing outright). One of
	// --project / --project-id / KEYORIX_PROJECT is required, enforced in runRequestReview.
	requestReviewCmd.MarkFlagsMutuallyExclusive("project", "project-id")
}

func runRequestReview(_ *cobra.Command, _ []string) error { // NOSONAR -- cognitive complexity, mirrors old CLI's runReviewRemote
	if requestReviewID == 0 {
		return fmt.Errorf("--id is required")
	}
	if requestReviewAction != "approve" && requestReviewAction != "reject" {
		return fmt.Errorf("--action must be approve or reject")
	}
	projectID, projectName, err := requestProjectTarget(requestReviewProjectID, requestReviewProject)
	if err != nil {
		return fmt.Errorf("%w (PUT .../projects/{id}/access-requests/{requestId} is project-scoped in its URL)", err)
	}
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	if projectID, err = requestResolveProject(ctx, client, projectID, projectName); err != nil {
		return err
	}

	existing, err := fetchAccessRequest(ctx, client, projectID, requestReviewID)
	if err != nil {
		return err
	}
	requesterLabel := requestUserLabel(ctx, client, existing.UserID)
	fmt.Printf("Resolved access request %d in project %s: requester %s, state=%s.\n",
		requestReviewID, requestProjectLabel(projectID, projectName), requesterLabel, existing.State)

	if existing.SecretID != nil {
		if requestReviewRole != "" || requestReviewTTL != "" {
			return fmt.Errorf("--role and --ttl do not apply to a secret-scoped request (id %d) -- it grants no role", requestReviewID)
		}
		body := apiclient.ResolveSecretAccessRequestJSONRequestBody{
			Action: apiclient.ResolveSecretAccessRequestJSONBodyAction(requestReviewAction),
		}
		if requestReviewReason != "" {
			body.Reason = &requestReviewReason
		}
		resp, err := client.ResolveSecretAccessRequestWithResponse(ctx, int(requestReviewID), body)
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 {
			return apiError(fmt.Sprintf("%s secret access request", requestReviewAction), resp.StatusCode(), resp.Body)
		}
		switch requestReviewAction {
		case "approve":
			fmt.Printf("Secret access request %d approved for %s to read secret %d.\n", requestReviewID, requesterLabel, *existing.SecretID)
		case "reject":
			fmt.Printf("Secret access request %d rejected.\n", requestReviewID)
		}
		return nil
	}

	var ttl time.Duration
	if requestReviewTTL != "" {
		ttl, err = time.ParseDuration(requestReviewTTL)
		if err != nil || ttl < 0 {
			return fmt.Errorf("--ttl must be a non-negative Go duration (e.g. 4h)")
		}
	}
	body := apiclient.ResolveAccessRequestJSONRequestBody{
		Action: apiclient.ResolveAccessRequestJSONBodyAction(requestReviewAction),
	}
	if requestReviewRole != "" {
		body.GrantedRole = &requestReviewRole
	}
	if requestReviewReason != "" {
		body.Reason = &requestReviewReason
	}
	if requestReviewTTL != "" {
		body.GrantTtl = &requestReviewTTL
	}
	resp, err := client.ResolveAccessRequestWithResponse(ctx, int(projectID), int(requestReviewID), body)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError(fmt.Sprintf("%s access request", requestReviewAction), resp.StatusCode(), resp.Body)
	}

	// The PUT response carries no body -- re-fetch to report the ACTUAL resulting
	// state, since under dual control an approve may still be pending more approvals.
	updated, err := fetchAccessRequest(ctx, client, projectID, requestReviewID)
	if err != nil {
		return fmt.Errorf("access request %d was %sd, but re-fetching its state to confirm failed: %w",
			requestReviewID, requestReviewAction, err)
	}
	switch requestReviewAction {
	case "approve":
		if updated.State != "approved" {
			fmt.Printf("Approval recorded for access request %d (%d of %d) — more approvals needed before the role is granted.\n",
				updated.ID, updated.ApprovalsReceived, updated.RequiredApprovals)
			return nil
		}
		grantNote := "permanently"
		if ttl > 0 {
			grantNote = fmt.Sprintf("for %s (time-bound)", ttl)
		}
		fmt.Printf("Access request %d approved: granted role %q to %s %s.\n",
			updated.ID, updated.GrantedRole, requesterLabel, grantNote)
	case "reject":
		fmt.Printf("Access request %d rejected.\n", updated.ID)
	}
	return nil
}

// ── request secret-access ────────────────────────────────────────────────────

var (
	requestSecretAccessSecretID uint
	requestSecretAccessRef      string
	requestSecretAccessReason   string
)

var requestSecretAccessCmd = &cobra.Command{
	Use:   "secret-access",
	Short: "Request approval to read one restricted secret's value",
	Long: "Create a pending, secret-scoped access request: approval to read ONE specific\n" +
		"secret's value, distinct from `request access`'s broader project/role request.\n" +
		"Only relevant when classification.restricted_requires_approval is enabled and\n" +
		"the target secret's classification is \"restricted\" — the gate this satisfies.",
	RunE: runRequestSecretAccess,
}

func init() {
	requestSecretAccessCmd.Flags().UintVar(&requestSecretAccessSecretID, "secret-id", 0, "Secret ID (or use --ref)")
	requestSecretAccessCmd.Flags().StringVar(&requestSecretAccessRef, "ref", "", "Secret reference \"project/environment/name\" (or use --secret-id)")
	requestSecretAccessCmd.Flags().StringVar(&requestSecretAccessReason, "reason", "", "Reason for the request (required)")
}

// parseSecretRef splits "project/environment/name" into its three parts. Mirrors
// internal/core/rules.ParseSecretRef exactly (a leaf, dependency-free parser -- not
// imported since this module cannot depend on internal/core; see internal/depguard).
func parseSecretRef(ref string) (project, environment, name string, err error) {
	parts := strings.SplitN(strings.TrimSpace(ref), "/", 3)
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("invalid secret ref %q: want \"project/environment/name\"", ref)
	}
	project, environment, name = strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2])
	if project == "" || environment == "" || name == "" {
		return "", "", "", fmt.Errorf("invalid secret ref %q: want \"project/environment/name\"", ref)
	}
	return project, environment, name, nil
}

func resolveSecretIDRemote(ctx context.Context, client *apiclient.ClientWithResponses, secretID uint, ref string) (uint, error) {
	if secretID != 0 {
		return secretID, nil
	}
	projectName, envName, secretName, err := parseSecretRef(ref)
	if err != nil {
		return 0, err
	}
	projectID, err := resolveRequestProjectID(ctx, client, projectName)
	if err != nil {
		return 0, fmt.Errorf("resolve ref %q: %w", ref, err)
	}
	envResp, err := client.ListProjectEnvironmentsWithResponse(ctx, uint32(projectID), nil) // #nosec G115 -- projectID resolved from a real project row, always small
	if err != nil {
		return 0, fmt.Errorf("resolve ref %q: failed to list environments: %w", ref, err)
	}
	if envResp.StatusCode() != 200 {
		return 0, apiError("list environments", envResp.StatusCode(), envResp.Body)
	}
	envData, err := decodeData[struct {
		Environments []struct {
			ID   uint   `json:"id"`
			Name string `json:"name"`
		} `json:"environments"`
	}](envResp.Body)
	if err != nil {
		return 0, err
	}
	var envID uint
	for _, e := range envData.Environments {
		if e.Name == envName {
			envID = e.ID
			break
		}
	}
	if envID == 0 {
		return 0, fmt.Errorf("resolve ref %q: environment %q not found in project %q", ref, envName, projectName)
	}

	params := &apiclient.GetSecretByNameParams{Name: secretName, ProjectId: int(projectID), EnvironmentId: int(envID)}
	resp, err := client.GetSecretByNameWithResponse(ctx, params)
	if err != nil {
		return 0, fmt.Errorf("resolve ref %q: %w", ref, err)
	}
	if resp.StatusCode() != 200 {
		return 0, apiError(fmt.Sprintf("resolve ref %q", ref), resp.StatusCode(), resp.Body)
	}
	secret, err := decodeData[struct {
		ID uint `json:"id"`
	}](resp.Body)
	if err != nil {
		return 0, err
	}
	if secret.ID == 0 {
		return 0, fmt.Errorf("resolve ref %q: secret not found", ref)
	}
	return secret.ID, nil
}

func runRequestSecretAccess(_ *cobra.Command, _ []string) error {
	if requestSecretAccessSecretID == 0 && requestSecretAccessRef == "" {
		return fmt.Errorf("--secret-id or --ref is required")
	}
	if requestSecretAccessReason == "" {
		return fmt.Errorf("--reason is required")
	}
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	secretID, err := resolveSecretIDRemote(ctx, client, requestSecretAccessSecretID, requestSecretAccessRef)
	if err != nil {
		return err
	}
	body := apiclient.CreateSecretAccessRequestJSONRequestBody{SecretId: int(secretID), Reason: requestSecretAccessReason}
	resp, err := client.CreateSecretAccessRequestWithResponse(ctx, body)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 && resp.StatusCode() != 201 {
		return apiError("request secret access", resp.StatusCode(), resp.Body)
	}
	data, err := decodeData[struct {
		AccessRequest requestAccessRequest `json:"access_request"`
	}](resp.Body)
	if err != nil {
		return err
	}
	fmt.Printf("Secret access requested: id=%d secret=%d state=%s\n", data.AccessRequest.ID, secretID, data.AccessRequest.State)
	return nil
}

// ── request bulk-approve / bulk-reject ──────────────────────────────────────

var requestBulkApproveIDs string

var requestBulkApproveCmd = &cobra.Command{
	Use:   "bulk-approve",
	Short: "Approve multiple pending access requests at once",
	Long: "Approve several pending access requests in a single call (ADR-024 extension).\n" +
		"Provide a comma-separated list of request IDs with --ids.",
	RunE: runRequestBulkApprove,
}

func init() {
	requestBulkApproveCmd.Flags().StringVar(&requestBulkApproveIDs, "ids", "", "Comma-separated list of access request IDs (required)")
	_ = requestBulkApproveCmd.MarkFlagRequired("ids")
}

type bulkAccessError struct {
	RequestID uint   `json:"request_id"`
	Error     string `json:"error"`
}

func parseIDList(s string) ([]int, error) {
	parts := strings.Split(strings.TrimSpace(s), ",")
	ids := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid ID %q: must be a positive integer", p)
		}
		ids = append(ids, int(n))
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("at least one ID is required")
	}
	return ids, nil
}

func runRequestBulkApprove(_ *cobra.Command, _ []string) error {
	ids, err := parseIDList(requestBulkApproveIDs)
	if err != nil {
		return fmt.Errorf("--ids: %w", err)
	}
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	resp, err := client.BulkApproveAccessRequestsWithResponse(ctx, apiclient.BulkApproveAccessRequestsJSONRequestBody{RequestIds: ids})
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("bulk approve access requests", resp.StatusCode(), resp.Body)
	}
	data, err := decodeData[struct {
		Result struct {
			Approved []uint            `json:"approved"`
			Failed   []bulkAccessError `json:"failed"`
		} `json:"result"`
	}](resp.Body)
	if err != nil {
		return err
	}
	printBulkApproveResult(data.Result.Approved, data.Result.Failed)
	return nil
}

func printBulkApproveResult(approved []uint, failed []bulkAccessError) {
	fmt.Printf("Approved %d request(s), %d failure(s).\n", len(approved), len(failed))
	for _, id := range approved {
		fmt.Printf("  ✓ request %d approved\n", id)
	}
	for _, f := range failed {
		fmt.Printf("  ✗ request %d: %s\n", f.RequestID, f.Error)
	}
}

var (
	requestBulkRejectIDs    string
	requestBulkRejectReason string
)

var requestBulkRejectCmd = &cobra.Command{
	Use:   "bulk-reject",
	Short: "Reject multiple pending access requests at once",
	Long: "Reject several pending access requests in a single call (ADR-024 extension).\n" +
		"All rejected requests share the same --reason.",
	RunE: runRequestBulkReject,
}

func init() {
	requestBulkRejectCmd.Flags().StringVar(&requestBulkRejectIDs, "ids", "", "Comma-separated list of access request IDs (required)")
	requestBulkRejectCmd.Flags().StringVar(&requestBulkRejectReason, "reason", "", "Rejection reason shared across all requests (required)")
	_ = requestBulkRejectCmd.MarkFlagRequired("ids")
	_ = requestBulkRejectCmd.MarkFlagRequired("reason")
}

func runRequestBulkReject(_ *cobra.Command, _ []string) error {
	ids, err := parseIDList(requestBulkRejectIDs)
	if err != nil {
		return fmt.Errorf("--ids: %w", err)
	}
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	resp, err := client.BulkRejectAccessRequestsWithResponse(ctx, apiclient.BulkRejectAccessRequestsJSONRequestBody{RequestIds: ids, Reason: requestBulkRejectReason})
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("bulk reject access requests", resp.StatusCode(), resp.Body)
	}
	data, err := decodeData[struct {
		Result struct {
			Rejected []uint            `json:"rejected"`
			Failed   []bulkAccessError `json:"failed"`
		} `json:"result"`
	}](resp.Body)
	if err != nil {
		return err
	}
	fmt.Printf("Rejected %d request(s), %d failure(s).\n", len(data.Result.Rejected), len(data.Result.Failed))
	for _, id := range data.Result.Rejected {
		fmt.Printf("  ✓ request %d rejected\n", id)
	}
	for _, f := range data.Result.Failed {
		fmt.Printf("  ✗ request %d: %s\n", f.RequestID, f.Error)
	}
	return nil
}

// ── request rejection-templates ─────────────────────────────────────────────

var requestRejectionTemplatesCmd = &cobra.Command{
	Use:   "rejection-templates",
	Short: "Manage rejection-reason templates",
}

func init() {
	requestRejectionTemplatesCmd.AddCommand(rejectionTemplatesListCmd, rejectionTemplatesAddCmd, rejectionTemplatesDeleteCmd)
}

type rejectionReasonTemplate struct {
	ID     uint   `json:"id"`
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

var rejectionTemplatesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all rejection-reason templates",
	RunE:  runRejectionTemplatesList,
}

func runRejectionTemplatesList(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	resp, err := client.ListRejectionReasonTemplatesWithResponse(ctx)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("list rejection-reason templates", resp.StatusCode(), resp.Body)
	}
	data, err := decodeData[struct {
		Templates []rejectionReasonTemplate `json:"templates"`
	}](resp.Body)
	if err != nil {
		return err
	}
	if len(data.Templates) == 0 {
		fmt.Println("No rejection-reason templates defined.")
		return nil
	}
	for _, t := range data.Templates {
		fmt.Printf("  id=%-4d  name=%-30s  reason=%s\n", t.ID, t.Name, t.Reason)
	}
	return nil
}

var (
	rejectionTemplateName   string
	rejectionTemplateReason string
)

var rejectionTemplatesAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new rejection-reason template",
	RunE:  runRejectionTemplatesAdd,
}

func init() {
	rejectionTemplatesAddCmd.Flags().StringVar(&rejectionTemplateName, "name", "", "Short label for the template (required)")
	rejectionTemplatesAddCmd.Flags().StringVar(&rejectionTemplateReason, "reason", "", "Template rejection text (required)")
	_ = rejectionTemplatesAddCmd.MarkFlagRequired("name")
	_ = rejectionTemplatesAddCmd.MarkFlagRequired("reason")
}

func runRejectionTemplatesAdd(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Creating rejection-reason template %q...\n", rejectionTemplateName)
	resp, err := client.CreateRejectionReasonTemplateWithResponse(ctx, apiclient.CreateRejectionReasonTemplateJSONRequestBody{
		Name: rejectionTemplateName, Reason: rejectionTemplateReason,
	})
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 && resp.StatusCode() != 201 {
		return apiError("create rejection-reason template", resp.StatusCode(), resp.Body)
	}
	data, err := decodeData[struct {
		Template rejectionReasonTemplate `json:"template"`
	}](resp.Body)
	if err != nil {
		return err
	}
	fmt.Printf("Template created: id=%d name=%s\n", data.Template.ID, data.Template.Name)
	return nil
}

var rejectionTemplatesDeleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete a rejection-reason template by ID",
	Args:  cobra.ExactArgs(1),
	RunE:  runRejectionTemplatesDelete,
}

func runRejectionTemplatesDelete(_ *cobra.Command, args []string) error {
	id, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return fmt.Errorf("invalid template ID %q: %w", args[0], err)
	}
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	resp, err := client.DeleteRejectionReasonTemplateWithResponse(ctx, int(id))
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("delete rejection-reason template", resp.StatusCode(), resp.Body)
	}
	fmt.Printf("Template %d deleted.\n", id)
	return nil
}
