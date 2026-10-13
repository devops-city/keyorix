### Changed
- **Published images carry a build date.** `docker-publish` now passes `BUILD_DATE` (the commit date in UTC, never the wall clock, so rebuilding a commit reproduces the stamp) to the server, server airgap and web image builds, so `keyorix --version` / `system info` on a published server image no longer reports `unknown`.
