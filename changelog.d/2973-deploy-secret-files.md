### Security
- **The shipped compose stack and Helm chart no longer put credentials in any
  container's environment.** Compose uses Docker secrets files under `./secrets`
  (created by `scripts/selfhost/init-secrets.sh`, which also migrates an existing
  `.env` with `--from-env`); the chart mounts its Secret as a read-only 0440
  volume and sets `*_FILE` variables. Requires a server image with `*_FILE`
  support (#2968). **Upgrade notes in `docs/UPGRADING.md` §5.**
