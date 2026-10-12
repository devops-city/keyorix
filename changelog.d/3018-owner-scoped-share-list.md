### Added
- **Owner-scoped share list: a project-only owner can see and revoke their shares.**
  New `GET /api/v1/shares/owned` returns only the shares the caller created, on secrets in
  projects they are a member of now, within the caller's PAT restriction. The Sharing
  Management page falls back to it (labelled "Shares you created") when `GET /api/v1/shares`
  (global `secrets.read`) is refused; a global admin's page is unchanged.

### Security
- The share lists (`GET /api/v1/shares`, `GET /api/v1/shares/owned`, and the embedded-mode
  core calls) now refuse a list of 10000 or more shares (the storage layer silently cuts
  unpaginated lists off at 10000) instead of running an unbounded number of user/group
  lookups or showing a list that may be missing shares. Over the cap the HTTP answer is a
  typed `422 ShareListOverCap`, not a 500; the list is never truncated. Real pagination is
  a follow-up.
