- **INV-CORE-pat-restriction-outside-authorize** Every read or decision whose visibility
  is decided OUTSIDE `Authorize`/`AuthorizePrincipal`/`AuthorizeSecret` applies the
  caller's PAT restriction (ADR-042) itself, at the row's own scope, failing closed:
  the personal secret set (`ListSecretsWithSharingInfo`, and defensively
  `ListSecretsInScopeWithSharingInfo`) keeps a secret only if the restriction allows
  `secrets.read` at its project/environment; `CheckSecretPermission` checks the mapped
  permission at the secret's scope before honouring ownership, shares or ACL rows (the
  `AuthorizeSecret` PAT-SCOPE-002 check); the notification feed shows a restricted
  token only notifications whose project it may `secrets.read`, none without a project,
  and its badge count and mark-read writes follow the same visibility, narrowed in the
  query (`patNotificationScope`) so a limit or count never applies to a newest-N
  window of rows it cannot see; `GET /dashboard/stats` (gated only on `system.read`)
  names in its expiring-secrets list, own recent activity and share counts only
  secrets the restriction allows `secrets.read` on, and a restricted token does not
  overwrite the user's trend snapshot; the secret
  access-request family checks `roles.assign` at the request's project before admin
  authority (`requireAccessRequestAuthorityAt`) and `secrets.read` there for the
  requester's own rows; a restricted PAT cannot create a PAT
  (`ErrRestrictedPATCannotMintPAT`); and a restricted PAT cannot activate
  break-glass (`ErrRestrictedPATCannotBreakGlass`, checked first in
  `ActivateBreakGlass`, HTTP and gRPC), while revoking the owner's OWN tokens and
  sessions stays allowed (ADR-042 addendum of 2026-10-11, PAT-GUARD-2; guarded by
  `TestPATRestriction_RestrictedPATCannotActivateBreakGlass`,
  `TestPATRestriction_RestrictedPATRevokesOnlyOwnTokensAndSessions` and
  `TestGRPCPATRestriction_RestrictedPATCannotActivateBreakGlass`). More generally, a
  restricted PAT is refused on EVERY ungated write (no permission gate, so no
  `Authorize`), deny-by-default: `restrictedPATUngatedWrites`
  (`pat_restriction_writes.go`) gives each one a policy whose zero value refuses
  (`ErrRestrictedPATSelfServiceWrite`, or the write's own sentinel), and allowing one
  takes a written reason — own-credential revocation, the creates authorized in the
  handler through `Authorize`, and the routes a PAT never authenticates. Both
  transports refuse from that one table (HTTP `RefuseRestrictedPATUngatedWrites` on
  `/api/v1`, the gRPC auth interceptors) before the handler runs (ADR-042 addendum
  "ungated writes, deny-by-default", PAT-GUARD-3; guarded by `server/http`
  `TestEveryUngatedWriteDeclaresRestrictedPATPolicy` over every ungated route from
  `router.go`'s AST and `server/grpc` `TestEveryUngatedGRPCWriteDeclaresRestrictedPATPolicy`
  over every ungated write RPC from the services' AST: an undeclared write fails, and
  every declaration is checked behaviourally with the restricted personas). Helpers:
  `pat_restriction_listing.go`, `pat_restriction_writes.go`. Why:
  PAT-GUARD-1, after SHARE-4 found #3018's `/shares/owned` listing by membership; the
  sweep then found `/secrets`, `/notifications`, `/secret-access-requests` and
  `POST /auth/tokens` doing the same on main. Guard: `server/http`
  `TestEveryGETRouteHonoursPATRestriction` (every GET route from `chi.Walk`, restricted
  PATs of a project-only owner and a global admin against a canary project, with
  unrestricted controls) and `server/grpc` `TestEveryGRPCReadHonoursPATRestriction`
  (every unary read RPC from the live server); targeted `TestPATRestriction_*` in
  `server/http`; `internal/core` `TestPATRestrictionListingFilters_Edges`,
  `TestGetDashboardStats_HonoursPATRestriction`,
  `TestNotifications_RestrictedPATSeesVisibleRowsBeyondNewestWindow` and
  `TestPATNotificationScope_MatchesPerRowCheck`.
