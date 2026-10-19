- **INV-CORE-channel-url-never-in-errors** A notification channel URL is a bearer
  credential (Slack-style tokens live in its path), so no error string, log line or
  audit diff built from it carries more than scheme and host. `postJSONToURL` names
  its destination with `netutil.RedactURLHost` and strips the `*url.Error` layer
  from transport failures (`netutil.RedactErrorURLs`, which keeps `errors.Is` on the
  cause); `parseWebhookURLLiteral`'s parse error carries neither the raw URL nor the
  `*url.Error`; the audit before/after goes through `redactedNotificationChannelForAudit`.
  `url.URL.Redacted()` is NOT enough: it masks userinfo only. Why: #3426.
  Guard: `internal/core` `TestPostJSONToURL_ReceiverErrorDoesNotLeakPathToken`,
  `TestPostJSONToURL_TransportErrorDoesNotLeakPathToken`,
  `TestPostJSONToURL_RefusedStoredURLDoesNotLeakPathToken`,
  `TestValidateNotificationChannel_ErrorDoesNotEchoPathToken`,
  `TestBroadcastRecoverAdminAlert_DispatchFailureLogDoesNotLeakPathToken`,
  `TestDispatchPolicyChannels_DispatchFailureLogDoesNotLeakPathToken`,
  `TestNotificationChannelAudit_NeverCarriesURL`.
  **Not covered**: a new call site that formats a channel URL itself (the tests pin
  the sites that exist today, not a static rule over all `ch.URL` uses), and
  `notifychan` sinks, which apply the same helpers through `sanitizeDeliveryError`
  and are pinned by their own tests.
