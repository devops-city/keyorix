# Keyorix documentation

## Operator path (start here for a pilot install)

| Step | Document |
|------|----------|
| The one supported pilot install, step by step | [operations/pilot-install.md](./operations/pilot-install.md) |
| Binaries, first admin, first secret | [QUICK_START.md](../QUICK_START.md) |
| Install with an AI assistant, no secret typed or shown | [INSTALL-WITH-AI.md](../INSTALL-WITH-AI.md) |
| Docker Compose + PostgreSQL, TLS, backups, metrics, troubleshooting | [SELF_HOSTING.md](./SELF_HOSTING.md) |
| Kubernetes | [Helm chart](../deploy/helm/keyorix/README.md) |
| Every `keyorix.yaml` key and environment variable | [CONFIGURATION.md](./CONFIGURATION.md) |
| Hardening | [security/hardening-guide.md](./security/hardening-guide.md) |
| Backup, restore and offline audit anchors (also air-gapped) | [AIRGAP_RUNBOOK.md](./AIRGAP_RUNBOOK.md) |
| Upgrading | [UPGRADING.md](./UPGRADING.md) |
| Key rotation, lost admin, troubleshooting | [operator/j6-key-rotation.md](./operator/j6-key-rotation.md), [operator/j5-lost-admin.md](./operator/j5-lost-admin.md), [operator/j7-troubleshooting.md](./operator/j7-troubleshooting.md) |
| PostgreSQL tuning, audit durability | [PERFORMANCE.md](./PERFORMANCE.md) |
| Edge and industrial devices | [edge-deployment.md](./edge-deployment.md) |
| A guided tour of the CLI | [operator/demo.md](./operator/demo.md) |

## Using Keyorix

- [API_REFERENCE.md](./API_REFERENCE.md): REST API (complete) and gRPC (partial surface, ADR-105).
  The machine-readable spec is [openapi.yaml](../server/http/handlers/openapi.yaml), served at
  `/openapi.yaml` and `/swagger/` when `server.http.swagger_enabled` is true.
- [cli-reference.md](./cli-reference.md): every `keyorix` command, flag and example, generated
  from the command tree (man page: [man/keyorix.1](./man/keyorix.1)).
- [SECRET_SHARING_USER_GUIDE.md](./SECRET_SHARING_USER_GUIDE.md): sharing.
- [MIGRATION.md](./MIGRATION.md), [migrate-from-vault.md](./migrate-from-vault.md): importing secrets.
- [CI_CD.md](./CI_CD.md): fetching secrets in GitHub Actions, GitLab CI and CircleCI.
- [sdks.md](./sdks.md): Go, Python, Node.js and Java SDKs.

## Security

- [SECURITY.md](./SECURITY.md): features and reporting.
- [security/architecture.md](./security/architecture.md): encryption, key management, authn/authz, transport.
- [security/SECURITY-MODEL.md](./security/SECURITY-MODEL.md) and [compliance/](./compliance/README.md).
- [project-soft-delete-lifecycle.md](./project-soft-delete-lifecycle.md): what a project delete, restore and purge do to secrets, grants, shares and machine identities.

## Development

- [TESTING_FRAMEWORK.md](./TESTING_FRAMEWORK.md), [TESTING_BEST_PRACTICES.md](./TESTING_BEST_PRACTICES.md)
- [Server README](../server/README.md), [Web dashboard README](../web/README.md)
- [ARCHITECTURE.md](./ARCHITECTURE.md), the ADRs (`adr-*.md`) and [INVARIANTS.md](./INVARIANTS.md)

## Essential URLs (a local server)

Scheme and port follow `server.http` in your config; a config written by `admin init` serves
HTTPS on 8080 with a self-signed certificate (`--cacert certs/server.crt`).

- Health: `https://localhost:8080/health`
- API base: `https://localhost:8080/api/v1/`
- OpenAPI and Swagger UI: `/openapi.yaml`, `/swagger/` (only when `swagger_enabled: true`)
