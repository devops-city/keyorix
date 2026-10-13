### Security
- **A FIFO named as the CLI's CA file (`--ca-file` / `KEYORIX_CA_FILE` / `ca_file`) is refused instead of hanging the command.** `apiclient.LoadCAPool` now opens the file non-blocking and refuses a non-regular file on the opened descriptor with `read CA file <path>: not a regular file`. A regular file, or a symlink to one (Kubernetes Secret volumes), still loads.
