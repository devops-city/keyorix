- **INV-HTTP-channel-url-create-only** The full notification channel URL (a bearer
  credential) is returned only in the `POST /api/v1/notification-channels` response.
  List, get and update return `url` as scheme+host with the path elided
  (`https://hooks.slack.com/…`) plus `url_set`; an update that omits `url` keeps the
  stored URL and an explicit `url` replaces it. The only way to build the response
  shape is `channelToAPI(ch, revealURL)`, and only the create handler passes true.
  Why: #3425 (every `alerts.write` caller could read every channel's token).
  Guard: `server/http` `TestNotificationChannelURL_AlertsWriteOnlyNeverSeesPathTokenAfterCreate`
  (real router, a user holding only `alerts.write`), `server/http/handlers`
  `TestElideChannelURL`, `TestChannelToAPI_RevealOnlyWhenAsked`.
  **Not covered**: the gRPC surface has no notification-channel service today; if one
  is added it must apply the same rule. The CLI prints whatever `url` it is given.
