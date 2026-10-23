### Security

- The CLI (`KEYORIX_TOKEN_FILE`, `KEYORIX_PASSWORD_FILE`, `KEYORIX_MFA_CODE_FILE`, `KEYORIX_ADMIN_PASSWORD_FILE`, `KEYORIX_BOOTSTRAP_TOKEN_FILE` and the other `*_FILE` credentials) and the container entrypoint (`KEYORIX_ADMIN_PASSWORD_FILE`, `KEYORIX_BOOTSTRAP_TOKEN_FILE`) now refuse a secret file owned by anyone other than the running user or root, as the server already does (#3393). Another account that owns the file can rewrite it, so it could substitute the credential, for example to choose the first admin's password. Fix: `chown` the file to the user the command runs as, or to root.
- A relative `*_FILE` value is no longer printed in any error. Someone who sets `KEYORIX_DB_PASSWORD_FILE=hunter2` (the value instead of a path) used to get `KEYORIX_DB_PASSWORD_FILE="hunter2": ... no such file or directory` in the boot log. Now the server, the CLI, `keyorix-k8s-sync` and the container entrypoint say `KEYORIX_DB_PASSWORD_FILE (a relative path, not shown: it may be the secret itself): ...`. Relative paths such as `KEYORIX_TOKEN_FILE=./token` still work, and an absolute path is still shown.

### Fixed

- `keyorix user create` now reads `KEYORIX_INITIAL_PASSWORD_FILE`. The refusal of `--password` already told users to set it, but the command ignored it and prompted instead.
