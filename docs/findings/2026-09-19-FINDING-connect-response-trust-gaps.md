# FINDING: internal/connect backends trust unvalidated response identity/content; two have no response-size bound

**Date**: 2026-09-19
**Found by**: response-side fuzz harness construction/verification for the 4 Connect
backends (`FuzzVaultConnectorResponse`, `FuzzAWSSMConnectorResponse`,
`FuzzAzureKVConnectorResponse`, `FuzzGCPSMConnectorResponse`,
`internal/connect/*_response_fuzz_test.go`), not by a planted assertion catching a
regression — these are pre-existing design gaps, confirmed by direct source reading
and, where noted, by live reproduction against the real backend SDKs.

Status: **§2 and §3 fixed in this PR** (branch `fix/connect-hardened-client`, off
`test/fuzz-connect-backend-responses`) — see §5, now the implementation record
rather than a draft. §1 (ref-binding) is **not fixed**, deliberately: it's
orthogonal to this fix (response identity vs. transport hardening) and was already
assessed Low/not-obviously-worth-closing on its own merits; still open for a
separate product decision. §4 (pagination) confirms N/A, unchanged. §6 is the
coverage-replay accounting of the 15 surviving `internal/connect` mutants against
the 4 fuzz targets — its line-number citations were renumbered for this PR's
changes (see §6's own note).

---

## 1. No ref-binding / response-identity check in any of the 4 connectors

None of the four connectors verify that the value returned in a response actually
belongs to the ref that was requested, even though three of the four backends' own
response shapes carry an identity field that could be checked:

| Backend | Identity field in the real response | Checked against the request? |
|---|---|---|
| Vault | *(none — KV read/write envelope carries no path/name field)* | N/A |
| AWS Secrets Manager | `GetSecretValueOutput.ARN`, `.Name` (`api_op_GetSecretValue.go`) | No — `awssm.go`'s `GetSecret` reads only `SecretString`/`SecretBinary` |
| Azure Key Vault | `Secret.ID` (parses into name+version via `ID.Name()`/`ID.Version()`) | No — `azurekv.go`'s `GetSecret` reads only `Value` |
| GCP Secret Manager | `AccessSecretVersionResponse.Name` | No — `gcpsm.go`'s `GetSecret` reads only `Payload.Data` |

**Why this matters**: the request-response pairing over a single synchronous
HTTP/gRPC call is normally sufficient to bind a response to its request — the gap
only becomes exploitable when something ELSE can make the server answer for a
*different* ref than the one asked (a compromised/misconfigured backend, a
confused-deputy bug on the backend's own side, a caching proxy in front of the
backend, or — see finding 2 below — a followed redirect). None of the four
connectors would notice; the response is trusted as-is and returned to the Keyorix
caller as if it were the requested secret.

**Scope note**: AWS's `account_id` pin and GCP's `project_id` pin (both already
enforced, see `awsRefAccountID`/`gcpRefProjectID`) check the *requested ref's own
ARN/resource-name shape* before the call — a different, already-covered property
("don't even ask for a secret outside my pinned account/project"), not "does the
response's own claimed identity match what I asked for." The two are complementary,
not redundant; this finding is about the latter, which has no coverage at all.

**Recommendation**: not obviously worth adding for AWS/GCP (their pin checks already
bound via a different mechanism) — but worth considering for Azure specifically in
combination with finding 2 below, since Azure is also the one that actively follows
redirects.

**Severity: Low.** This is a defense against *misrouting* (a proxy, cache, or
backend-side bug answering for the wrong ref), not against a *compromised* backend —
a backend that has been compromised outright can simply lie about the identity field
too, so checking it would not have stopped that case. The value of closing this is
narrower than it might first look: it catches accidental misrouting, not malicious
backends.

---

## 2. Azure/AWS connector egress has no SSRF guard at all; redirect is the one path where the destination is attacker-, not operator-, controlled — **FIXED in this PR**

**Fixed**: the redirect-follow gap (Azure) and the link-local slice of the baseline
gap (Vault + Azure) are both closed — `internal/connect/hardened_client.go`'s
`refuseRedirect` and `validateConnectorAddressNotLinkLocal`/`connectGuardedDialer`,
wired into all three HTTP-based backends (`vault.go`, `azurekv.go`, `awssm.go`).
Proving tests: `FuzzAzureKVConnectorResponse`'s oracle (e)
(`azurekv_response_fuzz_test.go`, red-proofed by temporarily removing
`CheckRedirect: refuseRedirect` — the redirect-status seeds fail),
`TestValidateConnectorAddressNotLinkLocal`, `TestVaultConnector_RefusesLinkLocalAddress`,
`TestAzureKVConnector_RefusesLinkLocalAddress` (`link_local_guard_test.go`,
red-proofed by disabling the check inside `validateConnectorAddressNotLinkLocal`).
The general private/RFC-1918/on-prem slice of the baseline (§2's own SSRF-baseline
finding below) is **deliberately still unguarded** — see §5's design reasoning for
why narrowing to link-local-only, not a full private-range block, is what makes
this fix compatible with the on-prem deployment baseline this section itself
established. The original investigation and severity reasoning below is kept
verbatim for the record; the **Severity** paragraph has a **Fix note** appended
rather than being rewritten, so the historical assessment stays legible.

**SSRF baseline, tested first**: is the *configured* address (`ConnectorConfig.Address`
in `internal/config/config.go`, what an operator's YAML `address:` field sets)
validated against `netutil` — or anything — at registration time or read time?

- **No registration-time check exists for any backend.** Confirmed exhaustively:
  exactly four validators run over `cfg.Connect` (`validateConnectTypes`,
  `validateConnectScopes`, `validateConnectGCPProjectID`,
  `validateConnectAWSAccountID`, all in `internal/config/config.go`) — none touch
  `Address` at all, let alone against a host-classification predicate.
- **AWS has no configurable address in the first place.**
  `server/main.go` constructs the AWS connector as
  `NewAWSSecretsManagerConnector(cn.Name, cn.Region, cn.AccountID, cn.AllowedRefs)`
  — no address/endpoint field, ever. AWS's real endpoint is resolved entirely by
  the AWS SDK's own region-based default resolution
  (`secretsmanager.<region>.amazonaws.com`-shaped, an AWS-owned domain), so "is the
  configured AWS endpoint validated" doesn't apply — there is no configured
  endpoint to validate. (The `BaseEndpoint` override used elsewhere in this repo's
  own test harnesses is a test-only SDK option, not anything `ConnectorConfig`
  exposes.)
- **Vault and Azure both accept a private/link-local `Address` with no error, at
  either construction or read time** — confirmed live, not inferred:
  `NewVaultConnector("x", "http://169.254.169.254:1234", ...)` and
  `NewAzureKeyVaultConnector("x", "https://169.254.169.254:1234", ...)` both
  construct cleanly, and a subsequent `GetSecret` call fails only with an ordinary
  network-level error (`context deadline exceeded` for both, after a real dial
  attempt — Vault's own 15s client timeout, Azure's context-bounded 5s in the
  test), never a validation-rejection message. Azure's plain-`http://` variant
  fails faster, but with `"authorized requests are not permitted for non-TLS
  protected (https) endpoints"` — that's `azcore`'s `checkHTTPSForAuth`, a
  **scheme-only** check with no awareness of which host it is; `https://` to the
  identical private/link-local target sails through it.

**This baseline absence is deliberate, not an oversight, for Vault** —
`validateConnectorURL`'s own doc comment says so explicitly: "Vault connectors are
admin-configured and commonly point at on-prem/private-network instances by
design." An operator-typed `address:` pointing at an internal Vault is the
*primary* legitimate use case for an on-prem product, so guarding the
operator-trusted configuration value itself would be the wrong fix — the
CLAUDE.md-documented reasoning behind `IsLinkLocal` vs. `IsPrivateOrLinkLocal`
(`internal/netutil/dialer.go`) makes exactly this distinction for the JWKS
fetcher's egress already. Azure has no equivalent doc comment, but the same
reasoning applies by construction (Key Vault is also commonly on-prem/private in
this product's deployment shape).

**What follows from this**: there is no "SSRF guard being bypassed by the
redirect" — there is no guard at any point in this egress path, for either
backend. The redirect finding below isn't special because it defeats a check; it's
the **one place the destination comes from an untrusted party (the responding
server) instead of the trusted operator's own configuration** — the same already-
unguarded dial path just receives attacker-chosen input instead of
operator-chosen input. AWS is not part of this reframing in the same way: it has
neither a configurable address (so no baseline case) nor redirect-following
behavior (confirmed in this finding's own §2 body below), so there is no path by
which an untrusted party influences its egress destination at all.

Confirmed by direct, repeated live reproduction (not just source reading) against
the real `azsecrets` client construction path Keyorix's own `azurekv.go` uses:

- A response with status 301, 302, 303, 307, or 308 and a `Location` header pointing
  at a **different host** is followed. This is Go's stdlib default `http.Client`
  redirect policy — `azurekv.go`'s `client()` method builds the SDK client with no
  `CheckRedirect` override, and azcore's own `defaultHTTPClient` doesn't set one
  either (`runtime/transport_default_http_client.go`).
- The credential is **not** leaked to the redirect target: Go's stdlib
  `shouldCopyHeaderOnRedirect` (`net/http/client.go`) strips the `Authorization`
  header on a genuine cross-host hop, confirmed empirically (`attackerAuth=""` in
  the repro below) — this part works correctly.
- The redirected response's content **is** trusted unconditionally: `GetSecret`
  returns the attacker-controlled value with `err == nil`, exactly as if it had come
  from the real Key Vault.

**Repro** (from a version of `azurekv_response_fuzz_test.go` with the redirect
scaffolding — since removed from the merged harness, see below): for a genuinely
cross-host redirect (verified using two different hostname strings, `127.0.0.1` vs
`localhost`, both resolving to the same loopback interface — see the caveat below on
why same-`127.0.0.1`-different-port is *not* a valid cross-host test):

```
code=301 attackerHits=1 attackerAuth="" val="ATTACKER-CONTROLLED" err=<nil>
code=302 attackerHits=1 attackerAuth="" val="ATTACKER-CONTROLLED" err=<nil>
code=303 attackerHits=1 attackerAuth="" val="ATTACKER-CONTROLLED" err=<nil>
code=307 attackerHits=1 attackerAuth="" val="ATTACKER-CONTROLLED" err=<nil>
code=308 attackerHits=1 attackerAuth="" val="ATTACKER-CONTROLLED" err=<nil>
```

**Methodology caveat, worth recording since it cost real debugging time**: an
earlier version of this repro used two `httptest` servers both naturally bound to
`127.0.0.1` (different ports only) for "origin" and "attacker". Go's own
`shouldCopyHeaderOnRedirect` compares only `url.URL.Hostname()` (port-stripped) to
decide whether a redirect is cross-host for header-stripping purposes — two
same-IP-different-port servers are, to that comparison, the *same host*. That
version of the repro showed the real bearer token reaching "attacker" on every
redirect code, which read as a much worse finding (credential leak) — but it wasn't
real; it was an artifact of an accidentally same-host test. The corrected repro
(renaming the non-TLS attacker's URL to use `"localhost"` instead of its natural
`"127.0.0.1"`, giving Go's comparison a genuinely different hostname string to
compare against origin's `"127.0.0.1"`) shows the credential is NOT leaked, only the
response content is trusted. A `127.0.0.2` second loopback alias would also work but
does not bind without an explicit `ifconfig lo0 alias` on macOS — not portable to a
dev machine, hence the hostname-string substitution instead.

**Why this is not a merged fuzz assertion**: there is no existing host-classification
or response-identity check anywhere in this path to red-proof, and no netutil-style
SSRF dial guard is wired into this connector's transport (unlike the JWKS fetcher,
which does use `netutil.IsLinkLocal` on its dialer). A hard assertion against a
confirmed, currently-true, unaddressed gap would just be a permanently-red test, not
a regression guard — so this was investigated as a one-time, documented
repro rather than left in `internal/connect/azurekv_response_fuzz_test.go`.

**By contrast, AWS does not follow ANY redirect status** via the same connector
construction path (`awssm.go`'s `client()` method, using
`secretsmanager.New(...)` with no custom `HTTPClient`) — confirmed live for both 307
and 308 (`attackerHits=0` in both cases), consistent with
`aws-sdk-go-v2/aws/transport/http.BuildableClient.Do`'s own doc comment: "Redirect
(3xx) responses will not be followed, the HTTP response received will [be] returned
instead." This also held with a bare `&http.Client{}` substituted in (still
`attackerHits=0`), which was not expected going in — the exact mechanism preventing
it even with stdlib defaults wasn't fully traced, but the observed behavior is
consistent and reproducible either way, so this specific property IS asserted as a
hard regression guard in the merged `FuzzAWSSMConnectorResponse` target. Vault
refuses to follow any redirect by explicit design (`CheckRedirect` returns
`http.ErrUseLastResponse`, already merged and tested). GCP is gRPC, not HTTP — no
redirect concept applies.

**Does the connector's transport use `netutil`'s guarded dialer?** No — confirmed by
instrumenting the actual `DialContext` the connector's transport uses (a wrapper
recording every address dialed, not a stand-in), not by reading source and
inferring. Redirected to two targets:

```
target="127.0.0.1:1"        dialed=[<origin>, 127.0.0.1:1]        err="... connect: connection refused"
target="169.254.169.254:80" dialed=[<origin>, 169.254.169.254:80] err="... context deadline exceeded"
```

Both targets were actually dialed (recorded by the spy *before* the real
`net.Dialer.DialContext` ran) — the `127.0.0.1:1` case fails fast with a normal TCP
refusal (nothing listens there), and the `169.254.169.254` case fails only after the
client's own request timeout, consistent with a dial attempt that got no response
(link-local addresses are not specially blocked at the OS/sandbox level here
either). Neither failure comes from a guard rejecting the target *before* dialing —
both are ordinary network-level outcomes. This confirms `azurekv.go`'s connector
does not wire in `netutil.Dialer` (or any other host-classification check) on its
HTTP transport, unlike the JWKS fetcher's `jwksEgressTransport`
(`internal/core/oidc_jwks.go`), which does use `netutil.IsLinkLocal` on its dialer
for exactly this class of guard.

**Authz: who can create or modify a connector's `Address`?** Traced the full call
graph, not just the obvious `/connect` handlers, since a generic config/settings API
could plausibly expose `ConnectorConfig` as a sub-resource. It doesn't:

- **No runtime API sets or changes `Address` at all — HTTP, gRPC, or CLI.**
  `ConnectorConfig` (`internal/config/config.go:177-230`, `Address` at line 182) is
  populated exactly once, from the static YAML, via `config.LoadConfig()`
  (`server/main.go:99`), before the HTTP/gRPC servers even start;
  `server/main.go:703` then builds each `connect.Connector` from that already-loaded
  config. The only runtime `/connect` surfaces
  (`server/http/handlers/connect.go`, `server/grpc/services/connect_service.go`,
  routed at `server/http/router.go:440-447`) are `ListConnectors`/`ReadSecret`
  (gated `connect.read`) and the ref-grants CRUD (gated `roles.read`/`roles.write`)
  — ref-grants (ADR-045) only authorize a *role* to use an *already-configured*
  connector by name with a ref-prefix; none of them ever touch `Address`, `Type`,
  or `Region`. No `CreateConnector`/`UpdateConnector` exists anywhere in the repo.
- **No config-reload/push path exists either.** `config.LoadConfig()` runs exactly
  once, at boot; there is no SIGHUP handler, no reload endpoint, and no `keyorix
  config apply`-style CLI command that pushes config into a running server (the
  one CLI command with a superficially similar name, `keyorix connect <endpoint>`
  in `internal/cli/connect/connect.go`, configures the *CLI's own* client-mode
  target via `cliconfig.SaveCLIConfig` — an unrelated, purely-local concept that
  doesn't touch the server's `ConnectConfig` at all).
- **The only way to set or change `Address` is direct filesystem access to the
  deployed `keyorix.yaml` (or the deploy pipeline that generates it), followed by
  a server restart/redeploy.** No in-app RBAC role governs this at all — not
  because it maps to a high-privilege role, but because there is no code path for
  an authenticated principal to reach it through the running application,
  regardless of role.

**Severity: Low** (revised from the earlier Medium given the authz trace above —
this is the primary driver of the revision, not a reframing of the redirect
mechanism itself, which is unchanged and still true). The reasoning splits into two
independent threads:

1. **The baseline (an operator-configured address as an SSRF primitive) requires
   filesystem/deploy access, a strictly HIGHER trust tier than even an in-app admin
   role** — whoever can edit the deployed config and restart/redeploy the server
   already has capability well beyond anything Keyorix's own RBAC could grant (this
   is the "admin-only → Low" case from this round's own framing, made stronger:
   it isn't merely admin-gated, it's gated by a capability admin itself doesn't
   necessarily have). There is no "lower-privileged role" case to weigh — the trace
   found no in-app role in this path at all, so the Medium-favoring branch of that
   question doesn't apply.
2. **The redirect-follow mechanism (Azure) is orthogonal to connector-config
   privilege** — it's triggered by the *real, already-configured* backend
   answering with a hostile redirect (a compromised Key Vault, or a MITM'd/
   misconfigured reverse proxy in front of it), not by anyone's ability to set
   `Address`. Its own containing factors are unchanged from the earlier draft:
   credentials are confirmed not to leak, and it requires the operator's own
   already-legitimate endpoint to actually emit a redirect, which is not the
   default posture of a healthy, uncompromised Vault. On its own this thread would
   still argue for something above Low — but it was never gated by connector-config
   authz to begin with, so the authz trace doesn't change ITS severity; it changes
   the OVERALL rating because the baseline thread (which the authz trace does
   bound) was the thread actually elevating this section above a single-mechanism
   assessment. Recorded as its own, still-live consideration — not erased by the
   authz finding, just no longer the section's controlling factor.

**Fix note, 2026-09-19**: option (a) below was implemented as-is —
`AzureKeyVaultConnector`'s client now refuses every redirect
(`hardened_client.go`'s `refuseRedirect`), closing thread 2 above outright rather
than narrowing its blast radius. Thread 1 (the baseline) is now partially closed
too, but NARROWER than either recommendation option below: link-local only
(`validateConnectorAddressNotLinkLocal` + `connectGuardedDialer`'s
`netutil.IsLinkLocal`), not the full `netutil.IsPrivateOrLinkLocal` option (b)
proposed — see §5 for why link-local-only is the correct scope, not a partial
implementation of (b).

**Recommendation**: for Azure specifically, either (a) refuse redirects outright the
same way Vault does (`CheckRedirect` returning a refusal), which is almost certainly
correct since Key Vault's real GetSecret API has no legitimate reason to redirect a
GET, or (b) at minimum validate the redirect target isn't
private/link-local (reusing `netutil.IsPrivateOrLinkLocal`, the same predicate
already used elsewhere in this codebase for exactly this class of guard, and now
confirmed by live test to be exactly what's missing) before following. (a) is the
smaller, more clearly-correct change.

---

## 3. No response-size bound for AWS or Azure; Vault and GCP are bounded (one explicitly, one incidentally) — **FIXED in this PR**

**Fixed**: `internal/connect/hardened_client.go`'s `sizeCappedRoundTripper` now
caps AWS's and Azure's response body at `connectMaxResponseBytes` (reusing
Vault's own `vaultMaxResponseBytes`, 1 MiB, as the shared bound — see §5),
applied AFTER the transport's transparent gzip decompression, not on the wire
bytes — the same place Vault's own `io.LimitReader` already sat, just relocated
to the transport layer since AWS/Azure's SDKs read the response body internally
with no connector-level interception point. Proving tests:
`TestAWSSMConnector_ResponseSizeCap_FailsClosed`,
`TestAzureKVConnector_ResponseSizeCap_FailsClosed`
(`response_size_cap_test.go`), each red-proofed by temporarily removing/widening
the cap and confirming a decompressed body exceeding it once again decodes
successfully instead of failing closed. These use a payload just over the cap
(not the original ~1 GiB measurement scale below) — fast enough to run every
test invocation; the measurement question (how bad was it) stays answered by
the numbers already recorded here, the regression-guard question (does the fix
hold) doesn't need the original scale to answer.

Requested per-backend report (pre-fix state, kept for the record):

| Backend | Size-limited? | Mechanism | Keyorix's own code, or inherited? |
|---|---|---|---|
| Vault | **Yes** | `io.LimitReader(resp.Body, vaultMaxResponseBytes)`, 1 MiB (`vault.go`) | Keyorix's own, explicit |
| AWS Secrets Manager | **No** | `json.NewDecoder(body).Decode(&shape)` streams from `response.Body` directly, no `io.LimitReader` anywhere in the deserializer (`deserializers.go:1059-1066`, confirmed by direct read) | — |
| Azure Key Vault | **No** | `runtime.Payload()` → `io.ReadAll(resp.Body)`, unconditional (`sdk/internal/exported/exported.go:52`, confirmed by direct read) | — |
| GCP Secret Manager | **Yes, but not Keyorix's** | gRPC client-side `MaxRecvMsgSize` default, 4 MiB (`google.golang.org/grpc/clientconn.go:139`, `defaultClientMaxReceiveMessageSize`) | Inherited from grpc-go's own default, not set by Keyorix |

**Measured** (not inferred): a fake server sending `Content-Encoding: gzip` with a
~2.1 MiB compressed body (a JSON envelope wrapping a ~1 GiB run of a single
repeated byte, ~510:1 compression ratio) against each connector's real client
construction path, peak `runtime.MemStats.HeapAlloc` sampled every 2ms during the
call (a watermark — a spike narrower than the sample interval could be missed —
and delta is measured against a baseline taken immediately before the call, not an
absolute number):

| Backend | `Accept-Encoding` sent | Transparent decompression? | Peak HeapAlloc delta | Elapsed | Result |
|---|---|---|---|---|---|
| AWS Secrets Manager | `gzip` (Go's transport default; SDK sets nothing explicit) | Yes | **~4.09 GiB** | 6.4s | `err=nil`, full ~1 GiB string returned as the secret value |
| Azure Key Vault | `gzip` (same) | Yes | **~3.64 GiB** | 5.9s | `err=nil`, full ~1 GiB string returned as the value |
| Vault (control) | `gzip` (same) | Yes | **~0.9 MiB** | 7ms | `err="secret ... has no data"` — the 1 MiB `io.LimitReader` truncates the read, `json.Unmarshal` fails on the truncated bytes, fails closed |

Confirms both open questions from the earlier (inference-only) version of this
section: (1) neither SDK sets its own `Accept-Encoding`, so Go's `http.Transport`
does add it and transparently decompress — the gzip-bomb shape works exactly as the
threat model describes; (2) the resulting amplification is real and large (~4x the
decompressed size in peak heap, likely accounting for the raw decompressed bytes
buffer plus at least one further copy during JSON decode/UTF-8 validation — not
further decomposed here), not merely theoretical. The Vault control confirms the
inverse just as concretely: the *same* transparent-decompression behavior occurs
(`Accept-Encoding: gzip` is sent, nothing in Vault's connector disables it either),
but the explicit `io.LimitReader` caps what `GetSecret` ever pulls through
`resp.Body.Read()` regardless of how much the underlying gzip reader could produce —
bounding both the memory (~0.9 MiB vs ~4 GiB) and the time (7ms vs ~6s) by roughly
three orders of magnitude, and failing closed rather than returning a
truncated/garbage value.

**Severity: Medium.** A single unauthenticated-adjacent response (the connector
already holds valid credentials to the backend, so this requires the backend itself
to be hostile/compromised/MITM'd, not an anonymous attacker) forces ~4 GiB of heap
allocation and several seconds of latency per request, with no cap — repeated
requests could exhaust available memory on the Keyorix process. Not High because it
requires a hostile backend (not a passive misconfiguration) and the blast radius is
availability (DoS), not confidentiality/integrity.

**Recommendation** (implemented, 2026-09-19): Vault's `io.LimitReader` pattern —
implemented for both AWS and Azure via `sizeCappedRoundTripper` wrapping
`resp.Body`, at the connector's own client construction (`awssm.go`'s
`HTTPClient` option, `azurekv.go`'s `azcore.ClientOptions.Transport`), not inside
either vendor's own deserializer/`runtime.Payload()`. Azure's version needed the
custom `policy.Transporter`-shaped wrapper this paragraph anticipated (a plain
`*http.Client` satisfies `Transporter`, so `sizeCappedRoundTripper` didn't need
anything azcore-specific); AWS's needed only the `HTTPClient` functional option,
confirming the original size estimate ("Azure's is a larger change than AWS's")
was about right in relative terms, though both landed as thin wrappers around one
shared `hardened_client.go` component rather than two separate implementations.

---

## 4. Pagination: not applicable

Confirmed by reading all four connectors: each is a single-item read
(`GetSecretValue`, `GetSecret`, `AccessSecretVersion`) with no list/pagination
operation, no next-token/next-link field anywhere in the four files. The
"cyclic/repeating next-token must terminate" oracle class does not apply to any of
the four backends as currently implemented.

---

## 5. Implemented, 2026-09-19 (was: draft fix): one shared hardened `http.Client` for connectors

**Implemented in this PR** (branch `fix/connect-hardened-client`) —
`internal/connect/hardened_client.go`, wired into `vault.go`, `azurekv.go`, and
`awssm.go`. The rest of this section is kept close to its original draft form
(what follows was written BEFORE implementation, describing the design this PR
then built) with **Landed** notes marking where the real implementation refined
or departed from the draft — most of the design held, a few details changed once
actually writing the code surfaced something the draft's prose didn't catch.

Sketching the fix §2 and §3 both separately recommended, as one shared piece rather
than two backend-specific patches, since AWS/Azure/Vault all accept *some* shape of
custom `http.Client`/`Transporter` at client-construction time (`awssm.go`'s
`secretsmanager.Options.HTTPClient`, `azurekv.go`'s `azcore.ClientOptions.Transport`,
`vault.go`'s own `*http.Client` field directly). Three components, each targeting a
different gap identified above:

**1. Redirect policy: refuse ALL redirects outright**, matching Vault's existing
`CheckRedirect` (`http.ErrUseLastResponse`) extended to Azure (which currently
follows Go's stdlib default policy, §2) and AWS (which already refuses at the SDK
layer, so this is a no-op for AWS, confirmed in §2). This is recommendation (a) from
§2, not (b) — refuse outright rather than "follow only same-host, non-private"
— since none of these backends' real APIs have any legitimate reason to redirect a
single-secret GET, the simpler policy is also the more clearly correct one (see §2's
own recommendation for why (a) beats (b) here).

**2. Post-decompression body cap, reusing Vault's `io.LimitReader` pattern.**
Requires more than copying Vault's one-liner: Vault caps the RAW wire body because
it never enables transparent decompression in the first place (it never sends
`Accept-Encoding: gzip` — Go's `http.Transport` only auto-decompresses when the
caller hasn't set that header itself, and Vault's connector doesn't). AWS and Azure
DO get transparent decompression (§3's whole gzip-bomb measurement depends on this),
so a cap on the wire bytes wouldn't touch the decompressed size at all — the
`io.LimitReader` has to wrap `resp.Body` in a custom `http.RoundTripper` that runs
*after* the stdlib transport's own gzip unwrapping (i.e., wrap the `Transport`, not
replace it: `rt.Transport.RoundTrip(req)` then `resp.Body =
io.NopCloser(io.LimitReader(resp.Body, cap))` before returning).

**Landed, with one correction to the sketch above**: plain `io.NopCloser` would
silently discard the real `resp.Body.Close()`, which `net/http` needs to safely
release the underlying connection back to its pool — `sizeCappedRoundTripper`
(the real implementation, `hardened_client.go`) uses a small `limitedReadCloser`
wrapper instead: `io.LimitReader` for `Read`, but `Close()` still calls through
to the original `resp.Body.Close`. A cap-truncated body means the connection
can't be safely reused for keep-alive afterward (the caller stopped reading
before EOF) — an accepted, expected trade-off only for the rare/adversarial
oversized-response case, not the common case.

The cap value itself is a product decision, not drafted here — Vault's existing
`vaultMaxResponseBytes` (1 MiB) is a reasonable starting point for AWS since a real
Secrets Manager value is capped at 64 KiB by AWS itself; Azure's Key Vault secret
value has no documented AWS-style hard cap, so the right number needs a separate
check against Azure's own documented limits before reuse.

**3. Guarded dialer, REVISED 2026-09-19 — narrowed to link-local only, not
private/link-local, and now included rather than dropped.** The earlier draft of
this section dropped this component outright because a `netutil.IsPrivateOrLinkLocal`
guard applied uniformly would reject the operator's own legitimate on-prem
Vault/Key Vault address, contradicting §2's baseline finding. That objection does
NOT apply to the narrower `netutil.IsLinkLocal` predicate (169.254.0.0/16,
`fe80::/10` — see `internal/netutil/dialer.go`'s own doc comment on why this is
deliberately smaller than `IsPrivateOrLinkLocal`): no legitimate Vault, Azure Key
Vault, AWS Secrets Manager, or GCP Secret Manager deployment lives at a link-local
address, including cloud instance-metadata (169.254.169.254, shared by AWS/GCP/Azure)
— unlike general RFC-1918 space, link-local has no on-prem-deployment legitimate use
for any of these four backends, so guarding it costs the baseline case nothing.
Applied at BOTH points, per this round's instruction:

- **The configured `Address`, at validation time** (`validateConnectorURL` for
  Vault, and Azure's equivalent construction path — AWS has no configurable address,
  so this doesn't apply there): reject a literal-IP address that
  `netutil.IsLinkLocal` flags, fast and loud, so an operator who mistypes or is
  tricked into pointing a connector at IMDS finds out at config time, not silently
  at first read. A *hostname* (not a literal IP) can't be fully checked here
  without a DNS resolution at validation time, which would reintroduce exactly the
  validate-once/dial-later gap `netutil.Dialer`'s own package doc (G48) already
  identifies and fixes for the dial-time case below — so this registration-time
  check is a fail-fast UX improvement for the literal-IP case, not the sole
  enforcement.
- **Every dial, via `netutil.Dialer{Disallow: netutil.IsLinkLocal}`** wired as the
  shared client's `DialContext` (mirroring the JWKS fetcher's own
  `jwksEgressTransport`, `internal/core/oidc_jwks.go`): re-validates on every
  connection, including a *hostname*-configured address that resolves differently
  than it did at registration time (the DNS-rebinding gap `netutil.Dialer`'s own
  doc comment describes) — this is the enforcement that actually matters, the
  registration-time check above is only a UX nicety on top of it. Once redirects
  are refused outright (component 1), this is also the only dial target that
  exists for any of the three backends, so there's no separate "redirect target"
  case left needing a different check.

**Prerequisite CLOSED, 2026-09-19**: `IsLinkLocal`, before this PR, did **not**
decode NAT64 (`64:ff9b::/96`) or deprecated IPv4-compatible (`::a.b.c.d`)
encodings of an embedded IPv4 address — confirmed by direct read of
`internal/netutil/dialer.go`: only `IsPrivateOrLinkLocal` called the
`embeddedIPv4` decode step (the #1937 fix, `docs/security-closures.d/`'s
`ssrf-nat64-ipv4compat-001` row); `IsLinkLocal` checked the raw IP against
`linkLocalCIDRs` only. A NAT64- or compat-encoded IMDS target (e.g.
`64:ff9b::a9fe:a9fe`, which embeds 169.254.169.254) would have passed
`IsLinkLocal` even though `IsPrivateOrLinkLocal` already correctly rejected it.
**Fixed**: both functions now share a single `matchesCIDRsWithEmbedded` helper
(the same decode step, parameterized by which CIDR list to check against) —
`IsLinkLocal(ip) == matchesCIDRsWithEmbedded(ip, linkLocalCIDRs)`,
`IsPrivateOrLinkLocal` unchanged in behavior, refactored onto the same helper.
Proving test: `TestIsLinkLocal_IPv4EmbeddingEncodings`
(`internal/netutil/linklocal_nat64_test.go`), red-proofed by temporarily
reverting `IsLinkLocal` to its old direct-`linkLocalCIDRs`-only form — 3 of the
4 reject cases failed. Reverted, never committed.

**What flipped from report-only to a merged assertion, LANDED 2026-09-19 (all three
components (1)/(2)/(3) implemented — this table is now the actual closure record,
not a forecast)**:

| Formerly report-only item | Now asserted by | Red-proofed how |
|---|---|---|
| §2's Azure redirect-follows-and-trusts-content gap | `FuzzAzureKVConnectorResponse` oracle (e), `azurekv_response_fuzz_test.go` — asserts `attackerHits == 0` across 5 redirect-status seeds (301/302/303/307/308) | Temporarily removed `CheckRedirect: refuseRedirect` from the fuzz target's own client construction — 5 of 12 seeds failed (via oracle (b), the attacker's forged 200 response getting returned as if it were the original non-200 status — an even earlier catch than oracle (e) itself). Reverted, never committed. |
| §3's AWS/Azure unbounded-decompression gzip-bomb gap | `TestAWSSMConnector_ResponseSizeCap_FailsClosed`, `TestAzureKVConnector_ResponseSizeCap_FailsClosed` (`response_size_cap_test.go`) — assert `GetSecret` fails closed on a decompressed body just over `connectMaxResponseBytes` | Temporarily removed the cap (AWS: `newConnectHardenedTransport` returned its base transport uncapped; Azure: `MaxBytes` set to 100x) — both tests failed (no error, oversized value returned). Reverted, never committed. |
| §2's baseline, IMDS/link-local slice only | `TestValidateConnectorAddressNotLinkLocal` (direct, isolated function test) plus `TestVaultConnector_RefusesLinkLocalAddress`/`TestAzureKVConnector_RefusesLinkLocalAddress` (integration, confirm the check is actually wired into `GetSecret`) — 5 encodings each (raw IPv4, IPv4 IMDS, IPv6 link-local, NAT64-encoded IMDS, IPv4-compatible-encoded IMDS) | Temporarily disabled the `netutil.IsLinkLocal` check inside `validateConnectorAddressNotLinkLocal` — the direct function test failed cleanly on exactly the 5 reject cases. (The GetSecret-level integration tests turned out NOT to cleanly red-proof at that same granularity — see `link_local_guard_test.go`'s own comment: Vault's dial-time `netutil.Dialer` guard, still active, independently catches the same address with different wording, a genuine defense-in-depth finding, not a test bug.) Reverted, never committed. |
| §1's no-ref-binding gap (all 4 backends) | **Unaffected by this fix** — orthogonal problem (response identity vs. transport hardening); would need each backend's own response-identity field (`ARN`/`Name`, `Secret.ID`, `AccessSecretVersionResponse.Name`) checked against the requested ref, not anything in the shared client. |
| §2's baseline, general private/RFC-1918/on-prem slice | **Still deliberately unaffected — stays report-only, on purpose.** Only the link-local slice above is now guarded; a genuinely private/on-prem address (e.g. `10.x`, `192.168.x`) remains unguarded at both registration and dial, exactly as `validateConnectorURL`'s own doc comment already argues is correct for this product's on-prem deployment shape — confirmed by `TestVaultConnector_AllowsGenuinelyPrivateAddress` (`link_local_guard_test.go`), the explicit contrast case. |

### 5a. Post-review hardening, 2026-09-19: proxy bypass, TLS/transport parity, explicit cap error

A second review of the landed fix (before push) found one real gap and confirmed two
things that needed verifying rather than assuming. All four items below landed in
the same PR, same branch (`fix/connect-hardened-client`).

**1. Proxy bypass — real gap, fixed.** `connectGuardedDialer`'s per-dial
`netutil.Dialer` check is blind to the request's actual target when a proxy is
configured: with `Transport.Proxy` set (all three base transports set it, matching
each backend's own pre-fix default), `DialContext` dials the *proxy's* address for
a plain-HTTP request, or the proxy first for an HTTPS CONNECT tunnel — never the
origin target. A request to `http://169.254.169.254/...` routed through a
configured proxy would have sailed past the dial-time guard entirely, since the
guard only ever validated the proxy's own (non-link-local) address. Fixed by
`targetGuardRoundTripper` (`hardened_client.go`): a new outermost `RoundTripper`
layer that checks `req.URL.Hostname()` — the request's own declared target, set by
the caller regardless of how the transport ends up reaching it — before the
proxy/dial layer ever sees the request. Scope, stated explicitly (the same
discipline as the rest of this doc): this only catches a *literal* link-local IP as
the target; a *hostname* that resolves to link-local only at the proxy's own DNS
resolution is not caught here — the client never sees or controls that resolution
when a proxy is in use, and closing it would mean either resolving client-side
first (defeating the point of the proxy) or trusting the proxy's own policy (out of
scope). Proving tests:
`TestConnectHardenedTransport_ProxyDoesNotBypassLinkLocalGuard` (target refused,
proxy never contacted — `proxyHits == 0`),
`TestConnectHardenedTransport_ProxyStillWorksForLegitimateTarget` (contrast case,
confirms the fix doesn't just block everything once a proxy is configured).
Red-proofed by temporarily removing `targetGuardRoundTripper` — the request
succeeded through the proxy (`proxyHits == 1`, no error) instead of being refused.
Reverted, never committed.

**2. TLS/transport parity — investigated, no pre-existing config to regress, but a
real transport-tuning gap was found and fixed anyway.** Before assuming anything,
checked whether Vault, Azure Key Vault, or AWS Secrets Manager ever exposed a way
for an operator to configure a custom CA or client certificate: confirmed,
exhaustively, **no** — `ConnectorConfig` (`internal/config/config.go`) has no
TLS-related field at all, and none of `vault.go`/`azurekv.go`/`awssm.go` ever read
one, before or after this fix. So there was nothing to "preserve" on that specific
axis; this fix does not regress custom-CA support because it never existed.
What the review DID find real: `newConnectHardenedTransport` originally built its
base transport as `http.DefaultTransport.Clone()` unconditionally for all three
backends, discarding Azure's and AWS's own SDK-tuned transport defaults (Vault
never had SDK tuning to discard, since it's raw `net/http` — see below). Fixed by
giving each backend its own base-transport constructor
(`vaultBaseTransport`/`azureBaseTransport`/`awsBaseTransport`, `hardened_client.go`),
and having `newConnectHardenedTransport` take a `*http.Transport` parameter and
clone/wrap IT rather than building a fresh one from Go's generic default:

| Field | Vault (before = after) | Azure (before → after) | AWS (before → after) |
|---|---|---|---|
| Source | Go `http.DefaultTransport` (never had SDK tuning) | Go generic default → azcore's own default (hand-replicated, see below) | Go generic default → **real clone** of `awshttp.NewBuildableClient().GetTransport()` |
| Dial timeout / keep-alive | 30s / 30s (unchanged — matches all three's own convention) | 30s / 30s (unchanged in value; now explicit via `connectGuardedDialer`, not inherited implicitly) | 30s / 30s (unchanged in value, same reason) |
| `ForceAttemptHTTP2` | `true` | `true` | `true` |
| `MaxIdleConns` | 100 | 100 | 100 |
| `MaxIdleConnsPerHost` | 0 (→ Go's `DefaultMaxIdleConnsPerHost`=2 internally) | 0 → **10** | 0 → **10** |
| `MaxConnsPerHost` | 0 (unlimited) | 0 (unlimited) | 0 → **2048** |
| `IdleConnTimeout` | 90s | 90s | 90s |
| `TLSHandshakeTimeout` | 10s | 10s | 10s |
| `ExpectContinueTimeout` | 1s | 1s | 1s |
| `ResponseHeaderTimeout` | 0/none (all three backends' own defaults agree — none set one) | 0/none | 0/none |
| `TLSClientConfig.MinVersion` | unset (Go's own crypto/tls default, effectively ≥TLS1.2 today) | unset → **TLS1.2 explicit** | unset → **TLS1.2 explicit** |
| `TLSClientConfig.Renegotiation` | unset (`RenegotiateNever`) | unset → **`RenegotiateFreelyAsClient`** | unset (AWS's own default doesn't set this either) |
| `TLSClientConfig.CurvePreferences` | unset | unset (azcore doesn't set this) | unset → **FIPS-140-restricted when `crypto/fips140.Enabled()`, else unset** (tracks AWS SDK's own logic automatically, not a hand-copy) |

Before this fix, Azure and AWS would have silently lost `MaxIdleConnsPerHost`
(10→2, more connection churn under concurrent load), AWS would have lost its
`MaxConnsPerHost` ceiling (2048→unlimited) and its FIPS-mode curve restriction (a
real compliance-relevant gap for a FIPS-140 deployment), and Azure would have lost
`Renegotiation: RenegotiateFreelyAsClient` (could break a legacy Key Vault-adjacent
endpoint requiring TLS renegotiation). None of these are hand-copied literals for
AWS — `awsBaseTransport` calls the SDK's own exported `GetTransport()` accessor, so
it tracks the SDK's actual defaults across version bumps automatically, the same
"prefer machine-checked over hand-duplicated" discipline this repo's own
engineering practices already require elsewhere. Azure has no equivalent exported
accessor (`azcore/runtime`'s own default transport is unexported with no public
accessor), so `azureBaseTransport` is a hand-replication of
`azcore@v1.23.1/runtime/transport_default_http_client.go` (version pinned per
`go.mod` at the time of writing) — flagged as needing re-verification against that
file whenever azcore is bumped, not silently assumed to stay correct forever.
Deliberately NOT replicated: azcore's own HTTP/2 `ReadIdleTimeout`(10s)/`PingTimeout`(5s)
tuning (via `http2.ConfigureTransports`) — a connection-health nicety, not a
correctness or security property; replicating it would mean vendoring
`golang.org/x/net/http2` directly for a minor gap, and Go's own `ForceAttemptHTTP2`
already configures a working (if less tightly tuned) HTTP/2 transport
automatically. Proving test:
`TestConnectHardenedTransport_ParityWithBackendDefaults` (`transport_parity_test.go`),
red-proofed per-field by temporarily discarding a backend's real base transport in
favor of Go's generic default — the AWS case failed cleanly on
`MaxIdleConnsPerHost` (10 expected, 0 actual). Reverted, never committed.

Separately, confirmed the **design property** that matters going forward even
though no operator-facing custom-CA config exists today:
`newConnectHardenedTransport` wraps whatever base transport it's given rather than
replacing it, so if custom-CA support is ever added (a realistic future ask for
Vault specifically — on-prem Vault instances commonly use an internal CA) this
hardened-client layer won't be what silently breaks it. Proving test:
`TestConnectHardenedTransport_PreservesCustomTLSTrust` (connects successfully
against an `httptest.NewTLSServer` whose cert is trusted only via a custom
`RootCAs` pool supplied on the base transport, standing in for a private CA),
paired with `TestConnectBaseTransports_NoCustomCAConfiguredToday` (machine-checks
the accurate CURRENT-state claim: none of the three base-transport constructors
set a custom `RootCAs` today). Red-proofed by temporarily making
`newConnectHardenedTransport` discard its `base` parameter and rebuild from Go's
generic default instead — the private-CA connection failed with a genuine `x509:
certificate signed by unknown authority` error. Reverted, never committed.

**3. Cap-overflow behavior — was silent truncation, now an explicit, typed,
non-retryable error.** The original implementation used `io.LimitReader`, which
silently truncates: a downstream JSON decoder then fails on the resulting
malformed-JSON tail with a generic "unexpected end of JSON input"-shaped error,
fail-closed but indistinguishable from any other truncated-body decode failure.
Fixed by `cappedBodyReader` (`hardened_client.go`), adapting `net/http.MaxBytesReader`'s
own read-n+1-bytes algorithm (server-side request bodies; `net/http` has no
exported client-side response-body equivalent) for a response body: each `Read`
requests at most one more byte than the remaining budget, so a single call can
distinguish "the stream ended exactly at the cap" from "there was more data past
it" and return a distinct `responseTooLargeError` in the latter case, matched via
`errors.Is`. A genuinely unexpected finding while wiring this in: both SDKs'
default retry policies (Azure's azcore, AWS's aws-sdk-go-v2) classify an
unrecognized I/O error surfacing during body-read as *possibly transient* and
retry the whole request — confirmed empirically, Azure's client under its own
DEFAULT retry policy (azurekv.go sets no override) added **~8 seconds** of real
exponential-backoff delay retrying a cap failure against the exact same,
still-oversized response 3 extra times, before this was addressed. A cap overflow
is a permanent condition (the SAME response will exceed the cap on a retry too),
so `responseTooLargeError` now implements both SDKs' "don't retry me" marker
interfaces *structurally* — satisfying `errorinfo.NonRetriable`'s and
`retry.RetryableError`'s method sets without importing either SDK's internal
retry-classification package (Azure's is genuinely internal and unimportable;
Go interface satisfaction doesn't require importing the defining package). Proving
tests: `TestAWSSMConnector_ResponseSizeCap_FailsClosed` /
`TestAzureKVConnector_ResponseSizeCap_FailsClosed` (`response_size_cap_test.go`)
assert `errors.Is(err, errResponseTooLarge)`; the Azure test additionally asserts
wall-clock elapsed time under 2s, deliberately WITHOUT overriding azcore's default
retry policy (unlike the fuzz harness, which does, for unrelated reasons) — that
default is exactly what the timing assertion checks against. Red-proofed twice,
separately: (a) reverting `cappedBodyReader` to `io.LimitReader` — both
`errors.Is` assertions failed, matching generic "unexpected EOF"-shaped errors
instead; (b) removing just the two marker methods with `cappedBodyReader` still in
place — the Azure timing assertion failed at 8.28s. Both reverted, never
committed.

**4. Cap value vs. each backend's own documented maximum secret size, requested
per-backend.** `connectMaxResponseBytes` (1 MiB, reusing `vaultMaxResponseBytes`)
is set well above every backend's own documented legitimate maximum, on purpose —
the cap exists to bound a HOSTILE response's amplification, not to model a real
secret's size tightly against it:

| Backend | Documented max secret-value size | `connectMaxResponseBytes` | Headroom |
|---|---|---|---|
| AWS Secrets Manager | 64 KiB | 1 MiB | ~16x |
| Azure Key Vault | 25 KiB | 1 MiB | ~41x |
| GCP Secret Manager | 64 KiB (per version) | 1 MiB (not currently applied — GCP is gRPC, out of this fix's scope; bounded today only by grpc-go's own 4 MiB default `MaxRecvMsgSize`, per §3's original table) | ~16x, if ever applied |
| Vault | no documented hard cap (operator-defined KV backend) | 1 MiB (`vaultMaxResponseBytes`, pre-existing, unchanged by this fix) | N/A |

The ~16-41x headroom is deliberate, not an oversight: a cap set tight against the
legitimate maximum would risk false-positive failures on a real secret that
happens to sit near a provider's own documented ceiling (encoding overhead,
JSON-escaping expansion, envelope/metadata fields alongside the value), where a cap
with generous headroom only ever fires on a response that's already wildly outside
any legitimate shape — exactly the gzip-bomb case this section exists to bound.

---

## 6. Surviving `internal/connect` mutants (`killed_by=survived_no_fuzz_coverage`) vs. coverage replay

Source: `~/proj/fuzz-archive/2026-09-19-mutation/connect_mutants.csv`, the 15 rows
with `killed_by == "survived_no_fuzz_coverage"`. Mutants were **not** re-run here
(per instruction — the rig will do that); this is only a coverage-replay check of
whether the 4 new fuzz targets' seed corpora ever *execute* the mutated line at
all, done by generating a per-target `-coverprofile` (`go test -run
'^FuzzX$' -coverpkg=...`, seed corpus only, `-count=1` to force a fresh run) and
checking the exact line's hit count in each of the 4 profiles.

11 distinct file:line locations, one row per mutant (some lines carry more than one
mutant/operator).

**Line numbers below were RENUMBERED 2026-09-19** to match this PR's hardened-client
changes to `vault.go`/`awssm.go`/`azurekv.go` (the fix in §2/§3/§5 below), which
inserted production code above several of these lines — a stale citation here would
be exactly the kind of decayed claim this repo's own engineering practices warn
against. Verified by direct `grep`/`Read` against the current file state, not by
arithmetic on the diff: `vault.go:169→174`, `vault.go:178→183`, `vault.go:205→210`,
`vault.go:214→219`, `vault.go:326→334`, `vault.go:329→337`, `awssm.go:80→81`,
`awssm.go:94→95`, `awssm.go:98→99`, `awssm.go:131→145`, `azurekv.go:54→72`. The
mutant IDs, operators, and reachability verdicts are unchanged — only the line
numbers moved; re-verify against a fresh checkout before trusting these numbers past
this PR, same caveat as always for a line-anchored citation.

| File:Line | Operator | Mutant ID | Reached by | Why |
|---|---|---|---|---|
| `azurekv.go:54` | negate-condition | `cc29006a25` | **none** | Inside `client()`'s real `azsecrets.NewClient` error check — `FuzzAzureKVConnectorResponse` always sets `c.newClient`, so `client()`'s real body (containing this line) is never called at all. Count 0 in all 4 profiles. |
| `azurekv.go:54` | drop-err-guard | `cb9d14f751` | **none** | Same line, same reason. |
| `azurekv.go:54` | comparison-flip | `186a7fad4a` | **none** | Same line, same reason. |
| `awssm.go:80` | off-by-one | `06e35e3b71` | **`FuzzAWSSMConnectorResponse`** (as of the 2026-09-19 harness update below) | Inside `awsRefAccountID`, called only when `c.accountID != ""` (`awssm.go:115`). Originally unreached — the fuzz target constructed `NewAWSSecretsManagerConnector(..., "", nil)` (empty accountID) unconditionally. Now: for ~1/3 of inputs (`status%3==0`, no new fuzz parameter), the harness configures a non-empty `accountID` and passes an ARN-shaped ref instead of the bare name, with a second bit (`(status/3)%2`) choosing whether the ARN's account segment matches or not — both outcomes reach line 80 (the ARN-shape gate at lines 77-79 passes either way; only the value comparison at line 116 differs). Seed corpus alone now confirms it (`status=1200` → matching, `status=1203` → mismatched; both raw values clamp to `code=200` via `clampHTTPStatus`'s remap arithmetic). Count 1 in the AWS profile as of this update, 0 in the other 3 (unchanged). |
| `awssm.go:94` | negate-condition | `e6acac4769` | **none** | Inside `client()`'s real `awsconfig.LoadDefaultConfig` path — same `newClient`-bypass reason as azurekv.go:54. Count 0 in all 4. |
| `awssm.go:94` | comparison-flip | `978638a44c` | **none** | Same line, same reason. |
| `awssm.go:98` | drop-err-guard | `edbf959596` | **none** | Same `client()` real-path region as line 94. Count 0 in all 4. |
| `awssm.go:131` | off-by-one | `c8ede9dcd4` | **`FuzzAWSSMConnectorResponse`** | `if len(out.SecretBinary) > 0` on `GetSecret`'s direct decode path (not gated by `client()`). Seed `{"SecretBinary":"AAEC"}` drives the true branch, `{}` the false branch. Count 1 in the AWS profile, 0 elsewhere. |
| `vault.go:169` | negate-condition | `763e3dabfa` | **`FuzzVaultConnectorResponse`** (as of the 2026-09-19 harness update below) | `if strings.HasPrefix(safeRef, mountPath)` inside the mount-version *cache-hit* loop (`for mountPath, version := range c.mountVersions`). Originally unreached — each fuzz execution constructed a brand-new `*VaultConnector` and called `GetSecret` exactly once, so the cache was always empty. Now: for ~1/3 of inputs (`status%3==0`, no new fuzz parameter), the harness issues a SECOND `GetSecret` on the SAME connector for the SAME ref, guarded off (skipping the strict metamorphic comparison, not the call itself) when the first call's own error came from the mount-info lookup transiently failing rather than the fuzzed response shape — see the harness's own comment for why that specific guard is needed to stay sound under real `-fuzz` concurrency. Seed corpus alone now confirms it (`status=1200`, which also clamps to `code=200`, giving a genuine cache-hit-then-success case). Count 1 in Vault's profile as of this update, 0 in the other 3 (unchanged). |
| `vault.go:178` | drop-err-guard | `366efeca88` | **`FuzzVaultConnectorResponse`** (statement only) | `if err != nil` after `http.NewRequestWithContext` for the mount-info request. The *statement* executes every call (bundled with lines 176-177 in the coverage profile, count 1 in Vault's profile, 0 in the other 3) — but the guarded error body itself is realistically unreachable by any fuzzed input, since `http.NewRequestWithContext` only errors on a malformed method/URL, and the URL is built from fixed, well-formed components the fuzzer doesn't influence. Coverage-replay says "reached"; the mutant's actual kill condition is a separate question this check doesn't answer. |
| `vault.go:205` | drop-err-guard | `225940c17b` | **`FuzzVaultConnectorResponse`** | `if err := json.Unmarshal(body, &mountResp); err != nil` — on the main path of every Vault `GetSecret` call. Count 1 in Vault's profile, 0 elsewhere. |
| `vault.go:214` | negate-condition | `4424845b07` | **`FuzzVaultConnectorResponse`** | `if mountPath == ""` — reached whenever the (always-valid, canned) mount-info response parses successfully, i.e. every Vault call. Count 1 in Vault's profile, 0 elsewhere. |
| `vault.go:214` | comparison-flip | `de8496a35a` | **`FuzzVaultConnectorResponse`** | Same line. |
| `vault.go:326` | drop-err-guard | `6be5386b63` | **`FuzzVaultConnectorResponse`** | `if err := json.Unmarshal(env.Data, &kv2); err != nil` — the KV v2 unwrap, reached whenever `mountIsV2=true` and the outer envelope parses. Vault's seed corpus includes multiple `mountIsV2=true` cases with valid outer JSON. Count 1 in Vault's profile, 0 elsewhere. |
| `vault.go:329` | off-by-one | `d9bd87e81c` | **`FuzzVaultConnectorResponse`** | `if len(kv2.Data) == 0 \|\| string(kv2.Data) == "null"` — the soft-delete check; Vault's own seed corpus has a dedicated soft-delete seed (`{"data":{"data":null,"metadata":{}}}`) that directly drives the true branch, plus other seeds driving the false branch. Count 1 in Vault's profile, 0 elsewhere. |

**Summary, updated 2026-09-19 (post-harness-change)**: originally 6 of 11 lines (7 of
15 mutants) were reached by `FuzzVaultConnectorResponse` or
`FuzzAWSSMConnectorResponse`, and 5 of 11 lines (8 of 15 mutants) by **none** of the
4 targets, for two distinct structural reasons enumerated below. (Correcting an
arithmetic slip in this section's earlier draft, which had these two mutant counts
swapped — 7 reached/8 unreached is what the table above actually shows, not 8/7.) A
follow-up harness change (item 2 of the same round that produced the SSRF-baseline
reframing in §2 above) specifically targeted reasons 2 and 3 below, since both were
scoping choices rather than genuine structural limits — **now 8 of 11 lines (9 of 15
mutants) are reached**; only reason 1 (6 of 11 lines, 6 mutants) remains open, and
it stays a genuine structural gap, not a scoping one:

1. **`client()`'s real-SDK-construction path is never exercised** (`azurekv.go:54`,
   `awssm.go:94`, `awssm.go:98` — 6 of the remaining 6 unreached mutants, all 3 of
   the remaining unreached lines). All 4 targets inject a real backend client
   through the `newClient` test seam specifically to get wire-level decode coverage
   without needing live cloud credentials — the necessary tradeoff is that the
   credential-resolution/client-construction branch of `client()` itself
   (`awsconfig.LoadDefaultConfig`, `azidentity.NewDefaultAzureCredential`,
   `azsecrets.NewClient`) is structurally unreachable through this seam. Closing
   this would need a *different* test (one that lets `newClient` stay nil and
   exercises the real credential chain, closer to what `coverage_test.go`'s
   `TestAWSSM_ClientRealPath_*` / `TestAzureKV_ClientRealPath` already do at the
   unit-test level, not fuzz-level). **Not addressed by the harness change below** —
   it's a different kind of gap than reasons 2/3, not just a different backend.
2. **CLOSED, 2026-09-19**: `awsRefAccountID` (`awssm.go:80` — 1 mutant) was never
   called because the fuzz target's connector had no `accountID` configured. Fixed
   by configuring a non-empty `accountID` and an ARN-shaped ref for ~1/3 of inputs
   (see the table row above for the exact mechanism) — this was a fuzz-target
   scoping choice, not a structural limitation, so closing it needed only a harness
   change, no new test.
3. **CLOSED, 2026-09-19**: `vault.go:169`'s cache-hit loop needed cross-call state
   (1 mutant) that a single-`GetSecret`-per-execution harness never provided. Fixed
   by issuing a second `GetSecret` on the same connector for ~1/3 of inputs (see the
   table row above), reusing the same connector instance rather than adding
   genuine cross-execution state — RULES' "fuzz inputs are independent, no state
   carried between execs" is about state persisting ACROSS fuzz executions (e.g. a
   package-level cache surviving between `f.Fuzz` calls), which this does not do;
   the connector and its cache are still constructed fresh inside each execution,
   just exercised twice within that one execution.
