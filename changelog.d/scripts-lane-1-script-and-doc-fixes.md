### Security
- **The DAST stack's server config no longer says `ssl_mode: prefer`.** `scripts/dast/keyorix-dast.yaml` now states `ssl_mode: disable` with a comment: that stack's PostgreSQL is stock `postgres:15-alpine` with no TLS and no CA, so verify-full is not possible there, and an explicit plaintext setting is reported honestly as `storage.database.insecure_disable_database_tls` instead of a silent plaintext fallback.

### Fixed
- **Drill scripts: the last `cmd | grep -q` under `set -o pipefail`.** `scripts/drills/disaster.sh` checked `list_names | grep -qx ...`, which could report a false failure (grep exits early, the left side gets SIGPIPE) and also passed silently when listing failed. It now captures the listing first and greps a here-string. `scripts/drills/selftest.sh` now fails on any `<command> | grep -q`, not only `echo`/`printf`.

### Documentation
- **`docs/CONFIGURATION.md` no longer says `migrate-provider` takes "no DB lock".** The command holds the exclusive database-presence lock for its whole run and refuses to run next to a live server or another `admin` command; the paragraph now says so. The Makefile comment on release stripping no longer quotes binary sizes.
