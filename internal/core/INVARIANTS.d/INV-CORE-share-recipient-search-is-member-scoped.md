- **INV-CORE-share-recipient-search-is-member-scoped** `SearchShareRecipients`
  (`share_recipients.go`, behind `GET /api/v1/projects/{id}/share-recipients`) answers
  "who could I share a secret in project P with" and nothing wider: (1) only a caller who
  holds secrets.write at P's scope AND is a member of P (the owner-must-be-a-member rule,
  RBAC-001), or who holds global users.read (can already list every user), may ask; a
  machine principal never may; (2) it lists only users for whom `IsProjectMember` (the one
  definition) is true and whose account is active (not deleted, `IsActive`, not
  suspended/deprovisioned), so the list equals the set `ShareSecret` accepts as recipients;
  (3) each row is id, username, display_name, plus email ONLY when the caller holds
  users.read at P's scope (the gate of `GET /projects/{id}/members`), and an email prefix
  matches only then (otherwise it would be an oracle for addresses the caller cannot see);
  (4) every refusal is the same 403 with `ShareRecipientSearchDeniedMessage`, from the
  route gate (`DenyMessage`, which `RequireScopedPermission` applies to both its denial
  shapes) and from core, whether or not P exists. Why: SHARE-2 (a project-only admin
  could share but not find a recipient, because the dialog searched the global
  `GET /users`). Guard: `server/http/share_recipients_search_test.go` (real router and
  sessions; each of (1)-(4) was mutated and went red),
  `server/http/handlers/openapi_contract_pr9_test.go:TestContractShare2_SearchShareRecipients`
  (response schema forbids extra fields). All default-ci. **Not covered**: a member with
  secrets.write only at an ENVIRONMENT scope of P cannot search (the gate checks P's
  project scope); that under-grants, never over-grants.
