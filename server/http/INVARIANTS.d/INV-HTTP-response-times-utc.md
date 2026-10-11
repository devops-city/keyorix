- **INV-HTTP-response-times-utc** Every time an API response carries is UTC RFC 3339.
  REST JSON bodies are written only by `handlers.encodeJSONResponse`, which runs
  `utcTimes` (every `time.Time`, `*time.Time`, `gorm.DeletedAt`, through exported fields
  and exported embedded structs, slices, maps and interfaces); gRPC sends
  `google.protobuf.Timestamp` or a reviewed UTC-formatted string. Display only: stored
  values and hash inputs are untouched; free text (`description`) and the stored audit
  `diff` are returned as recorded. Why: #2951 and AUDIT-UX-2 (on main 78 route/field pairs
  returned `+02:00` under a non-UTC server zone). Guard: `server/faultops`
  `TestUTCResponseGuard` (runtime: every GET route + every read RPC in a seeded world, process
  zone forced to UTC+2; skips listed with reasons), `server/http/handlers`
  `TestUTCStructural_EveryResponseEncoderIsEncodeJSONResponse`,
  `TestUTCStructural_ResponseTypesAreSeenByUTCTimes` (json.Marshalers reviewed, no unexported
  embedded time-holding struct), `TestUTCStructural_NonHandlerJSONWritersAreTimeFree`, and
  `server/grpc/services` `TestUTCStructural_ProtoStringTimeFieldsAreReviewed`.
