# Migrating secrets into Keyorix

> **Want to see it first?** [`demo/vault-migration/`](../demo/vault-migration/README.md)
> is a one-command demo that stands up Keyorix + a throwaway Vault and migrates
> live secrets end to end.


`keyorix secret import` pulls existing secrets into Keyorix — either from a file
or **directly from a running secrets manager** (HashiCorp Vault, AWS Secrets
Manager, Azure Key Vault, Google Cloud Secret Manager). It runs in remote mode
against your Keyorix server, so
first connect:

```sh
export KEYORIX_SERVER=https://keyorix.your-company.internal
export KEYORIX_TOKEN=<a service or personal access token with secrets.write>
# or: keyorix login --server …   (prompts for the password; stores a session token)
```

Every import targets one project + environment and is **idempotent** by default
(`--skip-existing`, on): re-running skips secrets that already exist. Use
`--dry-run` first to preview without writing anything.

## Live sources

Live mode reads the source with **your own local credentials** (the same env
vars the provider's own CLI uses). Those credentials never reach the Keyorix
server — the CLI fetches name/value pairs locally and POSTs only the resolved
secrets. The source is only ever **read** (LIST/GET); nothing is modified or
deleted there.

### HashiCorp Vault (KV engine)

```sh
export VAULT_ADDR=https://vault.your-company.internal:8200
export VAULT_TOKEN=<token with read+list on the KV path>

# Preview the whole 'secret/' mount
keyorix secret import --source vault --dry-run

# Import everything under secret/prod/ into project=payments, env=production
keyorix secret import --source vault \
  --vault-mount secret --vault-path prod \
  --project payments --env production
```

The KV tree is walked recursively. Each leaf's fields become Keyorix secrets:
a leaf with a single `value` field → one secret named after its path; a
multi-field leaf (e.g. `username` + `password`) → one secret per field,
`<path>-<field>`. Flags: `--vault-addr`, `--vault-token`, `--vault-mount`
(default `secret`), `--vault-path`, `--vault-kv-version` (`2` default, `1`
supported).

### AWS Secrets Manager

Uses the standard AWS credential chain (env vars, shared config/profile, SSO,
instance/task role).

```sh
export AWS_REGION=eu-west-1
# plus your usual AWS auth (AWS_PROFILE, env keys, or an assumed role)

keyorix secret import --source aws --aws-region eu-west-1 \
  --aws-prefix prod/ --project payments --env production
```

A secret whose value is a JSON object explodes into one Keyorix secret per field
(`<secret-name>-<field>`); a plain-string value becomes a single secret. Binary
secrets (`SecretBinary`) are skipped with a notice. Filter by name with
`--aws-prefix`.

### Azure Key Vault

Uses `DefaultAzureCredential` (env vars, managed identity, Azure CLI login, …).

```sh
az login   # or set the AZURE_* env vars

keyorix secret import --source azure \
  --azure-vault-url https://my-vault.vault.azure.net \
  --project payments --env production
```

JSON-object values explode per field as above; plain strings import as a single
secret.

### Google Cloud Secret Manager

Uses Application Default Credentials (`GOOGLE_APPLICATION_CREDENTIALS`, `gcloud
auth application-default login`, or workload identity / the metadata server).

```sh
gcloud auth application-default login   # or set GOOGLE_APPLICATION_CREDENTIALS

keyorix secret import --source gcp \
  --gcp-project my-gcp-project \
  --gcp-prefix prod- --project payments --env production
```

Each secret's **latest enabled version** is read; one with no accessible version
is skipped with a notice. JSON-object values explode per field as above; plain
strings import as a single secret. Filter by name with `--gcp-prefix`.

## File sources

```sh
keyorix secret import --file .env            --format dotenv --env production
keyorix secret import --file secrets.json    --format json   --env staging
keyorix secret import --file vault-export.yaml --format vault --env production
```

`dotenv` (KEY=VALUE), `json` (flat object), and `vault` (a Medusa/Vault YAML
export file) are supported.

## Common flags

| Flag | Purpose |
|------|---------|
| `--dry-run` | Preview what would be imported; contacts no server |
| `--skip-existing` | Skip (don't fail on) secrets that already exist — default on |
| `--prefix` | Prepend a namespace to every imported secret name |
| `--no-explode` | Store JSON-object / multi-field values as a single secret |
| `--project`, `--env` | Target project and environment (must already exist) |

## Not yet supported

Values are imported; **version history, tags/metadata, and TTLs are not**. Also
out of scope for now: Vault Enterprise namespaces, AWS/GCP binary secrets, and
auto-detecting the Vault KV version (use `--vault-kv-version`). These are tracked
follow-ups.
