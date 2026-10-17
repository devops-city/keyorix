### Testing

- PostgreSQL tests that need the full production schema now clone a migrated template database (`pgdsn.MigratedDatabase`, one template per schema fingerprint, built once under an advisory lock) instead of migrating an empty one every time. `KEYORIX_TEST_PG_TEMPLATE=0` restores create-empty-and-migrate.
