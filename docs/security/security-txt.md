# security.txt: source, hosting, renewal

[`security.txt`](security.txt) in this directory is the source of truth for the
RFC 9116 file Keyorix publishes. The policy it points at is
[`SECURITY.md`](../../SECURITY.md).

## Where it must be served

RFC 9116 binds the file to the host it is served from:
`https://keyorix.com/.well-known/security.txt`. That host is the marketing site,
which is not part of this repository, so **publishing is a hosting change that
this repository cannot make**. Copy the file unchanged to that path (and
`/security.txt`), over HTTPS, `Content-Type: text/plain; charset=utf-8`.

### Why it is not in the product web build

`web/` is the dashboard that customers run on their own hosts. Serving the file
there was considered and rejected:

- A customer's instance is not Keyorix's host. A `Canonical` line naming
  `keyorix.com` would be served from a different origin, which RFC 9116 treats
  as not authoritative, and a researcher would be pointed at us about a
  deployment we do not operate.
- The file carries an `Expires` date. A file baked into a versioned image goes
  stale in every image already deployed, and an expired file must be ignored by
  clients.
- It would need real changes: `web/nginx.conf` denies every path starting with a
  dot (`location ~ /\.`), so `/.well-known/` would return 403 until an exact-match
  location was added, and the embedded server build (`server/webui`) would need
  the same treatment.

## Renewal

`Expires` is set about six months out. Renew it at least 30 days before it
lapses: bump `Expires` (never more than one year ahead), republish the file, and
note the new date in the commit message. `deploy/security_txt_test.go` fails when
the date is in the past or more than 366 days ahead, so a missed renewal shows up
in CI rather than in a researcher's scanner. It logs a warning from 60 days out.

## Not included, on purpose

- `Encryption`: no PGP key or other report-encryption key is published. GitHub
  private vulnerability reporting is the encrypted-in-transit alternative. Add the
  field only when a key exists and is monitored.
- `Acknowledgments`: no researcher has been credited yet (see SECURITY.md,
  Hall of Fame). Add the field when the first advisory credits one.
- `Hiring`: not applicable.
