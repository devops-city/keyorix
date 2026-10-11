### Security
- **A restricted personal access token is refused on every ungated write.** Writes
  that no permission gate covers (profile, password, MFA and passkey changes, step-up,
  access requests, marking notifications read, leaving a share, break-glass, PAT
  creation) now answer a PAT with any scope, project, environment or CIDR restriction
  with 403 (gRPC `PermissionDenied`). Still allowed: revoking the owner's own tokens
  and sessions, and creating secrets, folders, rotation policies and dynamic-secret
  configs inside the token's restriction. Unrestricted PATs, sessions and machine
  tokens are unchanged. One table for both transports
  (`internal/core/pat_restriction_writes.go`), guarded family-wide (ADR-042).
