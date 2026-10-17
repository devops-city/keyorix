# Server logs

Set `server.log.format: json` to get one JSON object per log line, ready for a log
collector. The default, `text`, is unchanged.

```yaml
server:
  log:
    format: json
```

Lines written before the format is applied (configuration load and validation failures)
are always plain text. Everything after that is JSON.

## Fields

Every line has:

| Field | Meaning |
|---|---|
| `ts` | UTC time, RFC 3339 with nanoseconds |
| `level` | `debug`, `info`, `warn` or `error` |
| `msg` | the message |

Lines about an HTTP request (the access log, panics, and core's audit-write failures) also have:

| Field | Meaning |
|---|---|
| `request_id` | the request's correlation id (see below) |
| `principal_type` | `anonymous`, `user` or `machine_identity`: who the request authenticated as |
| `route` | the matched route pattern, e.g. `/api/v1/secrets/{id}`, or `unmatched`. Never the raw path |

The access log line (`"msg":"http request"`) adds `method`, `uri` (with setup/reset tokens and
secret-reference query strings already redacted), `remote_addr`, `status`, `bytes` and `duration_ms`.
5xx responses are `error`, everything else `info`.

Level for the many pre-existing plain log lines is taken from their prefix: `PANIC`, `FATAL`,
`ERROR` and `SECURITY` are `error`, `WARN`/`WARNING` are `warn`, `DEBUG` is `debug`, anything else `info`.

## Request ids

- A request's `X-Request-ID` header is used as its id when present. It is cleaned first: printable
  ASCII only, at most 128 characters. Otherwise the server mints a random id.
- The id is returned in the response's `X-Request-ID` header, so "what was the id of the failing
  call" can be answered from the client side and grepped here.
- The id travels from the HTTP edge through the request context into core, so a core log line for
  that request (for example a failed audit write) carries it. Audit writes that continue after the
  request has finished keep the same id.
- gRPC requests do not carry a request id yet.

### Not yet: the id on the audit row

The `audit_events` row does not store the request id. Its fields are covered by the tamper-evident
hash chain, and adding a column to a hashed record, or adding an unhashed one next to it, changes
what the chain proves. That is a product decision, so it is deliberately not done here. Until then,
correlate an audit event with its request by time, actor and `ip_address`.

## Secrets in logs

Two controls, in this order of importance:

1. **Call sites do not log secret values.** `TestJSONLogs_ShapeCorrelationAndNoSecrets` starts a
   real server in JSON mode, pushes canary passwords, a canary secret value, a session token, bad
   bearer tokens and a bad personal access token through bootstrap, login, secret creation and
   rejected requests, and fails if any canary appears anywhere in the output.
2. **A scrubber catches recognisable shapes** that slip through: Keyorix credentials
   (`kx_pat_…`, `kx_machine_…`, …), `Bearer`/`Basic` values, JWTs, PEM private keys,
   `password=`/`token=`/`secret=`-style pairs (numeric ids such as `secret=12` are kept) and
   `scheme://user:password@host`. It applies in JSON mode only; in `text` mode lines are written
   as before.

The scrubber cannot recognise an arbitrary secret value written as free text. That is what the
canary test is for.

## Log injection

In JSON mode a message that looks like a log record is just data: it is escaped into `msg`. Only
the server's own structured logger can write a field-bearing line, and it proves it with a
per-process random marker no log text can know.
