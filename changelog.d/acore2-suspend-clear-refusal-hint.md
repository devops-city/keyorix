### Changed
- **A refused clear-synced-copies suspend now says how to cut access anyway.** When a
  suspend or project freeze that also clears the copies synced to Kubernetes clusters is
  refused because its audit event cannot be recorded (500, nothing changed), the API
  message, and therefore the CLI and web dialog, ends with "Retry, or suspend without
  clearing to cut access now". A plain suspend is never blocked by the audit log.
