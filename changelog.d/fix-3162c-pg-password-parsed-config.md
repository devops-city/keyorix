### Security
- **`KEYORIX_DB_PASSWORD` can no longer change where or how Keyorix connects to PostgreSQL.**
  Since v0.96.0 (#3159) the password from `KEYORIX_DB_PASSWORD`, `KEYORIX_DB_PASSWORD_FILE` or
  `storage.database.password` was spliced into `storage.database.dsn`. With a keyword DSN ending
  in a backslash, a password such as `a sslmode=disable host=evil x=\` became connection
  keywords (another host, TLS off); with a URL DSN holding `?` in the user name, the result
  connected to a different host with `sslmode=prefer`. The DSN is now parsed by the driver's own
  parser and the password is set on the parsed connection settings; it is never written into a
  connection string. A DSN the driver cannot parse is now reported at startup (`admin validate`)
  rather than at the first connection, and a keyword DSN with an unterminated quote no longer
  crashes the config check. Password precedence is unchanged (a DSN that has its own password
  plus a configured one is still refused).
