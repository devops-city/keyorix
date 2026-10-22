### Documentation
- **SSO/JIT accounts cannot be offboarded through SCIM or an IdP disable.** `docs/CONFIGURATION.md` ("Offboarding an SSO / JIT account") and the SCIM/SSO threat model now say plainly that the PATs and sessions of an `sso:`-scheme account survive until an administrator suspends or deletes the user (or the PAT expires or the session lifetime ends), that the inactivity sweep (`keyorix user suspend-inactive`) is not scheduled, and give the CLI and API steps. The JIT paragraph no longer claims a later SCIM push reconciles to the JIT account (false since #3493).
- **`docs/UPGRADING.md` section 6v:** a check query, identical on SQLite and PostgreSQL, that lists the SCIM-created rows whose `externalId` starts with `sso:` and so stopped being SCIM-managed in #3493.

### Testing
- `TestUpgrading6vCheckQuery_FindsOnlySCIMCreatedSSORows` runs the query printed in `docs/UPGRADING.md` against SQLite (always) and PostgreSQL (when `KEYORIX_TEST_PG_DSN` is set).
