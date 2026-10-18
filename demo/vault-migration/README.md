# Demo: migrate off HashiCorp Vault in 5 minutes

A self-contained, one-command demo of Keyorix's flagship "leave Vault" story: it
stands up Keyorix **and** a throwaway HashiCorp Vault, seeds Vault with sample
secrets, then migrates every one of them into Keyorix with a single command and
shows them — then tears it all down.

## Run it

Prerequisites: `docker`, `curl`, `jq`, `sudo` (the script hands its throwaway secret
files to root, because the server refuses secret files owned by any other account), and
the Keyorix CLI:

```sh
curl -fsSL https://raw.githubusercontent.com/keyorixhq/keyorix/main/install.sh | sh
```

Then, from the repo root:

```sh
./demo/vault-migration/run.sh
```

That's it. It runs five steps and cleans up on exit (Ctrl-C is safe):

1. Start Keyorix (Postgres + API + web UI) via `docker compose`.
2. Start a throwaway Vault and seed it with sample secrets.
3. Show what's in Vault.
4. **Migrate** — `keyorix secret import --source vault --vault-path demo/prod`.
5. List the migrated secrets, now living in Keyorix.

## What it demonstrates

The seeded Vault holds three KV paths:

```
secret/demo/prod/database  → { username, password }
secret/demo/prod/stripe    → { value }
secret/demo/prod/redis     → { url }
```

One command imports all of them. Multi-field paths explode into one secret per
field (`demo-prod-database-username`, `demo-prod-database-password`), a single
`value` field keeps the path name (`demo-prod-stripe`), and credentials never
touch the Keyorix server — the CLI reads Vault with your local token and POSTs
only the resolved secrets.

## Try it on your own Vault

Skip step 2 and point the importer at a real Vault:

```sh
export KEYORIX_SERVER=https://keyorix.your-company.internal
export KEYORIX_TOKEN=<machine token with secrets.write>
export VAULT_ADDR=https://vault.your-company.internal:8200
export VAULT_TOKEN=<a token with read+list on the path>

keyorix secret import --source vault --vault-path prod \
  --project payments --env production --dry-run   # preview first
```

See [docs/MIGRATION.md](../../docs/MIGRATION.md) for AWS Secrets Manager and
Azure Key Vault, and the full flag reference.
