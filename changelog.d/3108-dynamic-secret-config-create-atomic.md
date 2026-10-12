### Fixed
- **Creating a dynamic-secret config is now all-or-nothing (#3108, #3095).** The config row was inserted and its encrypted admin DSN written in two separate commits, so a failure of the second write (or of the first one's reply) answered an error but left a config row with no DSN behind. Both writes (and the encryption between them) now run in one transaction, over HTTP and gRPC alike.
