- **INV-CORE-owned-share-list-is-member-scoped** `ListOwnedShareViews`
  (`share_owned_list.go`, behind `GET /api/v1/shares/owned`) lists, for caller U, only
  (1) shares U created (`ShareRecord.OwnerID == U`), (2) on secrets that still resolve,
  (3) in projects U is a member of NOW per `IsProjectMember` (the one definition), so
  removing U from P hides U's shares in P on the next request, without revoking them.
  Received shares are not listed, and global secrets.read adds nothing (the global list
  is `GET /api/v1/shares`, unchanged). (4) Only a user may ask: any other actor type, or
  actor id 0, is refused. (5) Every refusal is the same 403 with
  `OwnedShareListDeniedMessage`, from the route gate (`RequirePermissionInAnyScope`:
  secrets.read at the global scope or at one or more project scopes, with `DenyMessage`)
  and from core. (6) A PAT least-privilege restriction (ADR-042) narrows the list per
  secret exactly as it narrows a read of that secret: a share is listed only if
  `PATRestriction.Allows(secrets.read, {secret's project, environment})` (the check
  `AuthorizeSecret` makes, PAT-SCOPE-002); a token that may not read secrets lists
  nothing. An environment-confined token is refused at the route gate (it fails every
  project-level check), fail-closed. Why: SHARE-3 (a project-only owner could share but got 403 on the
  Sharing Management page, decision Andrei 2026-10-10). Guard:
  `server/http/share_owned_list_test.go` (real router and sessions; (1)-(5) each mutated
  and went red, see SESSION-SHARE-3; (6) by
  `TestOwnedShares_PATRestrictionNarrowsTheList`, red before the fix, SESSION-SHARE-4),
  `server/http/handlers/openapi_contract_pr9_test.go:TestContractShare3_ListOwnedShares`
  (schema forbids extra fields), `actor_sentinel_completeness_test.go` (the actor-id-0
  refusal is classified). All default-ci. **Not covered**: shares keep the OwnerID of the
  secret's owner at creation; `TransferSecretOwnership` does not re-own existing shares,
  so after a transfer they stay on the previous owner's list (and that owner can no longer
  revoke them, `requireShareAuthority`). Same as `GET /api/v1/shares` today.
