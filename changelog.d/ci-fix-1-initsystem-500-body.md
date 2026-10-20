### Security
- `POST /system/init` no longer returns the raw error text on a server-side failure (for example a database error naming a host and role). The client gets the standard 500 body; the detail is logged. Bad or missing bootstrap token and weak-password rejections (403) are unchanged.
