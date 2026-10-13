### Fixed
- **The demo image, `keyorix system info` and the web footer report the real build.**
  `scripts/demo/up.sh` (and `check.sh --postgres`) now pass `VERSION`, `GIT_COMMIT` and
  `BUILD_DATE` (from `git describe`, `rev-parse` and the commit date) to `docker build`, so the
  image is no longer `dev` / `none`. `GET /system/info` reports the injected build date as
  `build_time` instead of a hard-coded `unknown`. `keyorix system info` prints the server's
  version, commit and build time plus the CLI's own version, and shows an unstamped value as
  `dev (not stamped)` / `n/a`, never raw `none` or an empty field. The web footer shows the
  server version from the API (the web bundle's own version only as a secondary detail when it
  differs). On the dashboard the Security tile reads "No anomaly or expiry alerts" (it does not
  cover Compliance gaps), and a DB connection count of 0 is shown as `n/a`.
