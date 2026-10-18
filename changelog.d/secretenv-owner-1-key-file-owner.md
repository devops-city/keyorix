### Security
- **Secret files must be owned by root or by the server's user (#3393).** The server
  now also checks who owns a secret file read through a `<NAME>_FILE` variable, not only
  its mode. The owner of a file can always rewrite it, so a master-password, KEK or
  Shamir-share file owned by any other account let that account swap the key material
  (for example on a server running as root). Such a file is now refused at boot, and the
  error names the file and its owner uid. Key material (`KEYORIX_MASTER_PASSWORD_FILE`,
  `key_provider.env_var`, `shamir_share_env`) is always refused. The other secret files
  are refused under `security.enable_file_permission_check` (the default) and only
  warned about without it. There is no list of extra trusted owners.
  **Upgrade action for the Docker Compose install:** `scripts/selfhost/init-secrets.sh`
  leaves `secrets/*` owned by the user who ran it, so hand the files to root and keep
  their group before upgrading: `sudo chown root:"$KEYORIX_SECRETS_GID" secrets/*`
  (the script now prints this). For other installs: `chown root:<group> <file>` for a
  group-readable `0440` mount, or `chown <server user> <file>` for a `0600`/`0400` file.
  Kubernetes Secret volumes are root-owned already and need no change.
