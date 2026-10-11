- **INV-CORE-access-report-share-term-matches-enforcement** `ListSecretAccessors` reads a
  secret's shares once and evaluates each user's share grants from that list
  (`reportShareGrants`) instead of calling `sharePermissionFor` per user. Its strongest share
  grant for every user must equal what `sharePermissionFor` grants (write for the allowlisted
  `SecretActionUpdate`, else read, else nothing): direct shares for the recipient; group
  shares only through a membership that is global or scoped to the secret's project
  (`GetUserGroupsAt`); stored levels other than read/write grant nothing (`shareLevel`); no
  share applies to a non-member; expired shares are dropped. Every applying share is reported
  as its own grant. A failed group-membership lookup degrades the report (enforcement treats
  it as "no group share"). Why: #3020 review: the report listed only the strongest share and
  re-read the shares once or twice per user.
  Guard: `secret_access_list_test.go` `TestListSecretAccessors_ShareGrantsMatchDecisionTerm`
  (differential against `sharePermissionFor` over direct, group, other-project-scoped
  membership, non-member, expired and corrupt-level shares),
  `TestListSecretAccessors_ListsEveryShareGrant`, `TestListSecretAccessors_LoadsSharesOnce`,
  `TestListSecretAccessors_DegradedOnGroupShareLookupError`.
  **Not covered**: a new rule added to `activeShareGrant` is caught only if the differential
  fixture has a case for it; add one with the rule.
