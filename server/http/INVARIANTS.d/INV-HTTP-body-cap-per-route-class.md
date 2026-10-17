- **INV-HTTP-body-cap-per-route-class** Every route router.go registers that can take
  a body is behind the one global `MaxBodyBytesFor(requestBodyLimit(...))` middleware,
  which caps it by route class: the unauthenticated credential routes (`/auth/*`,
  `/system/init`) at 64 KiB, the SAML ACS at 1 MiB, everything else at
  `server.http.max_request_body_bytes`; the secret-value routes add `secretBodyLimit`
  on top. A class cap is never lifted by raising or disabling the global setting. A
  body whose declared length is over the cap gets 413 before authentication or any
  handler runs. Why: HARDEN-HTTP-1: the public routes accepted the 10 MiB API default
  from anyone, and an oversized body reached handlers that answered it with their
  generic 400. Guard: `body_limit_routes_test.go`
  (`TestEveryBodyRoute_RefusesOverItsClassCap` walks every body-taking route of the
  real router, SCIM included; `TestPublicAuthRoutes_TightBodyCap`,
  `TestRequestBodyLimit_ClassCapsSurviveGlobalOverride`,
  `TestSecretValueRoutes_TighterBodyCapThroughRouter`). Not covered: a chunked body is
  cut off inside the handler's read, and that handler chooses the 4xx.
