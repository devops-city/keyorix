# ADR-104: Security remediation timelines — published commitment vs. internal target

## Status

Accepted. Supersedes this ADR's own first version (a severity-tiered 14-day
CRITICAL / 30-day HIGH published commitment) after further research found
that shape doesn't match what any comparable project actually publishes —
see Context.

Policy layer alongside [ADR-067](adr-067-release-lifecycle-support-policy.md).
ADR-067 decided *which versions* get a fix and *for how long* (the support
period). This ADR decides *how fast a fix ships once a report is
validated* — a different commitment class, orthogonal to support-period
length. Public expression of the published half of this policy lives in
[`SECURITY.md`](../SECURITY.md) § Remediation Timelines.

**Authority is split by section, deliberately, not held by one document:**
`SECURITY.md` is authoritative for the **published** commitments — it's the
customer-facing document, read by the audience they're for, and if the two
ever disagree, `SECURITY.md` is current and this ADR's copy is stale. This
ADR is authoritative for the **internal-target** table, the **CRITICAL
definition**, and the **backport roadmap note** — none of those are
published anywhere else, so there is nothing for them to drift out of sync
with. Neither document restates the other's own section from scratch.

## Context

Keyorix is maintained by one person, with no on-call rotation and no funded
team. `SECURITY.md` already publishes two commitments — acknowledge a
report within 48 hours, initial assessment within 7 days — and those are
correct and unchanged by this ADR. What's missing is the next commitment
class: once a report is validated, how long until a fix reaches an
installable release. That gap was visible in practice before this ADR: PR
#1789 (last-admin lockout via a PAT confused deputy) sat merged and
correct on `main`, unreachable by any operator, for days, with nothing
published that says how long that's supposed to take.

### Why this ADR's first version is wrong, and being replaced rather than patched

This ADR originally published a severity-tiered fix deadline — 14 days for
CRITICAL, 30 for HIGH. That number was calibrated against an assumed
industry norm. The norm doesn't exist. Researched 2026-09-08, with sources:

| Vendor | Ack / triage | Fix SLA | Support window |
|---|---|---|---|
| HashiCorp Vault | none | none | "approx 1 year" published, ~4 months observed; LTS is Enterprise-only |
| CyberArk / Conjur | none | none — only scope of fix per severity | ~6 months of code fixes per version |
| Doppler | 2d response, 5d triage (HackerOne) | none | not published |
| Infisical | 3 business days ack, 7 business days assessment | none | latest only, no backports |
| Bitwarden | none | none | current + previous 2 majors |
| 1Password | none — explicitly disclaimed | none | not published |
| **OpenBao** (5 maintainers) | 7 days to validate | **≤90 days, all severities**; 1 week advance notice for High/Critical | latest only, best effort |

Sources: [HashiCorp](https://www.hashicorp.com/en/trust/security/vulnerability-management) ·
[CyberArk policy](https://www.cyberark.com/cyberark-security-vulnerability-policy.pdf) ·
[CyberArk EOL](https://docs.cyberark.com/end-of-life-policy/latest/en/content/eol-self-hosted-products.htm) ·
[Doppler](https://hackerone.com/doppler/policy_versions) ·
[Infisical](https://infisical.com/vulnerability-disclosure) ·
[Bitwarden](https://raw.githubusercontent.com/bitwarden/server/main/SECURITY.md) ·
[1Password](https://support.1password.com/security-assessments/) ·
[OpenBao CVE policy](https://openbao.org/community/policies/cve/) ·
[OpenBao support policy](https://openbao.org/community/policies/support/)

Almost nobody publishes a remediation SLA at all. Every vendor with more
funding and headcount than Keyorix either publishes nothing, or (Conjur)
publishes fix *scope* per severity with no *time* commitment. **OpenBao is
the only one, and it is the right model** — comparable team size (five
maintainers, no funded on-call), and the community Keyorix actually
recruits from, not the vendors with an incident-response rotation. Its shape
is deliberate, and every choice in it removes an expensive promise:

- **One global ceiling (90 days, all severities) instead of a severity
  matrix.** A matrix asks a solo maintainer to make a fast, public,
  legally-flavoured severity call under time pressure, then hit a different
  clock depending on the answer. A single ceiling removes that decision
  from the critical path entirely — severity still matters for
  prioritization, just not for which published clock is ticking.
- **A cheap triage promise (7 days) rather than a fix promise.** Triage is
  bounded, cheap effort; a fix is not. Promising the bounded thing and
  leaving the unbounded thing to a generous ceiling is the survivable
  split.
- **A communication commitment (1-week advance notice for High/Critical)
  instead of a faster fix.** Advance notice costs an email. A faster fix
  costs engineering time nobody is funded to guarantee.
- **Latest-release-only, no backports.** This is what keeps the *fix*
  commitment affordable — no maintenance-line multiplication, no
  cherry-pick queue, no divergent CI matrix per line.

This ADR now adopts that shape rather than inventing a new one. The
comparison also sharpens the advisory commitment (§ Decision below): Vault
publishes advisories 1–54 days after the patch ships, Conjur shipped a
High-severity RCE with no CVE assigned at all, and Bitwarden/1Password/
Infisical have empty or absent advisory feeds. A same-day GHSA with a
requested CVE is cheap for one person and is a genuine, checkable
differentiator none of these actually deliver.

### Two other timelines that use similar-looking numbers and are not this one

- **`SECURITY.md`'s existing 7-day *initial assessment*** is about
  triage — confirming a report is real and roughly how bad it is. It is not
  a remediation commitment and this ADR does not change it. (It also now
  happens to match OpenBao's own "7 days to validate" — coincidence of two
  independently-reasonable numbers, not a copy.)
- **ADR-067's own follow-up list** (§ Follow-ups) names a future "24h/72h/
  14-day ENISA reporting chain" — a *regulatory notification* timeline to
  authorities for actively-exploited vulnerabilities under the CRA, not yet
  documented or implemented anywhere. Different commitment, different
  audience (a regulator, not a customer). When that runbook is written, it
  should cross-reference this ADR so its own day-counts are never read as
  the same commitment as anything here.

### Reconciling with the pre-1.0 posture

`SECURITY.md` states Keyorix is pre-1.0 and has not declared a support
period under the CRA — that sentence is about *which versions remain
patchable at all and for how long* (ADR-067's subject). The remediation
timelines below are a *different, narrower* commitment: given that a
version IS the one receiving fixes (today, unconditionally, the latest
release only — matching OpenBao's own scoping), how fast does a validated
fix reach it. A project can have zero declared support period and still
commit to a remediation ceiling once it's actively fixing something; the
two are independent axes, and pre-1.0 status affects the first, not the
second. The published section is written as **a current operating
commitment, not a CRA-declared support period** — that phrase is used
verbatim in `SECURITY.md` so a non-lawyer reader doesn't have to infer the
distinction.

## Decision

### Published (in `SECURITY.md`, this ADR's copy is for the record only)

Sized for the worst realistic month, not the best one. This is what a
customer may rely on.

| Class | Commitment |
|---|---|
| Acknowledge a report | 48 hours *(already published, unchanged)* |
| Initial assessment | 7 days *(already published, unchanged)* |
| Fix, all severities | **≤90 days** from a validated report |
| High / Critical | **1 week advance notice** before the security release ships |
| Advisory | **GHSA with a requested CVE**, published the **same day** as the fix |
| Supported versions | **Latest release only** |
| Release cadence | **Not published** — see "Cadence is deliberately not published yet" below |

The 90-day ceiling is the standard coordinated-disclosure clock — defensible
to any reviewer, and it is a *ceiling*, not a target: most fixes will and
should ship far inside it (see internal targets below). It applies
uniformly across severity so there is no public clock that depends on a
fast, contestable severity call. The advance-notice and same-day-advisory
items are the genuinely differentiating pieces, and they cost communication
effort, not engineering time.

### Internal targets (not published, not promised to anyone)

Tighter, not promised. A miss here has no external consequence and should
be treated as ordinary triage information, not an incident. These are
last cycle's near-published numbers, kept as the internal aim once
research showed they shouldn't be the public commitment — the reasoning
that made them too risky to publish (no demonstrated track record, no
redundancy) doesn't make them unreasonable to *aim* for.

| Class | Internal aim |
|---|---|
| CRITICAL | Workaround guidance within 24 hours; fixed release within 14 days |
| HIGH | Fixed release within 30 days |
| MEDIUM / LOW | Next scheduled release (same as published — no internal/external gap for this tier) |

If these internal numbers are ever consistently beaten by a wide, durable
margin, that is the trigger to *revise the published ceiling* in
`SECURITY.md` deliberately — not to publish the internal table as-is. Any
tightening of the published commitment goes through the same review this
ADR itself got, not a quiet edit.

### Cadence is deliberately not published yet

An earlier draft of this policy proposed a published monthly-minor
cadence. Not adopted. The repository went four weeks with zero tags pushed
immediately before that draft was written — a cadence claim written the
same month it wasn't met is not evidence, it's a hope. Per this ADR:
**release cadence remains an internal working agreement, not a published
commitment, until it has been hit three consecutive times.** Three, not
one, because a single on-time month after a miss proves the miss was
noticed, not that the underlying capacity exists. Once three consecutive
months hit the internal aim, publishing a cadence becomes a decision to
revisit — this ADR does not pre-approve it; it only names the bar.

### CRITICAL, defined narrowly — for prioritization and the advance-notice trigger, not a separate published deadline

The published commitment above does not give CRITICAL its own clock —
High and Critical share the identical published treatment (90-day ceiling,
1-week advance notice, same-day advisory). A CRITICAL definition is still
needed for two things this ADR *does* rely on: which findings get the
tightest **internal** aim (above), and confirming that the most severe
findings correctly fall inside the High/Critical bucket that triggers
advance notice, rather than being argued down to MEDIUM where none of the
publish-facing commitments apply at all.

**CRITICAL: remote, unauthenticated compromise of stored secret values, or
of the authentication boundary itself, requiring no valid credential of any
kind and no prior account state.**

Both halves of "requiring no valid credential of any kind" matter and are
independently sufficient to keep a finding out of this tier:

- If exploitation requires *any* authentication material — a full-strength
  session, a scoped-down PAT, a since-revoked-but-technically-still-typed
  password, a machine credential, even a deliberately restricted one — it
  is not CRITICAL under this definition, regardless of what that credential
  then lets the holder do.
- If exploitation requires the target to be in some prior state that only
  an already-provisioned account can be in (suspended, deprovisioned, mid
  password-reset), it is not CRITICAL either, even if the eventual access
  is unrestricted — the attacker needed something about that specific
  account first.

"Compromise of stored secrets" means reading or deriving actual secret
*values* — not metadata, not knowing a secret exists, not a timing
side-channel about whether one does. "Compromise of the authentication
boundary" means forging or bypassing authentication outright — minting a
valid session/token without ever presenting a real credential, or a
cryptographic verification (JWT/OIDC signature, PBKDF2-wrapped key)
accepting something it should reject.

Everything that clears CRITICAL's bar but still represents a genuine
authenticated bypass, escalation, or control-integrity failure is HIGH —
that tier is intentionally the larger bucket, and both tiers now get the
same published treatment regardless, which lowers the stakes of the
boundary considerably compared to this ADR's first version (where the
boundary alone decided 14 days vs. 30). It still matters for internal
triage order and for keeping the tightest internal aim genuinely rare.

#### Worked examples, both from this repository's own history

**#1742 — account-takeover via blank `AccountState` → HIGH, not CRITICAL.**
A suspended or deprovisioned account could be silently reactivated for
login because `AccountLoginBlocked` read a blank/unrecognized
`account_state` as "not blocked" (fail-open). Serious, and — per the
release-prep work that preceded this ADR — already exploitable in the
currently shipped version. But exploiting it requires the account to
already exist in a specific prior state (suspended/deprovisioned) *and*
requires whoever logs back in to hold that account's own already-known
credentials — there is no path from zero credentials to a working session
through this bug alone. It fails the "no prior account state" clause
outright. **HIGH** — inside the High/Critical bucket either way, so it
still gets advance notice and same-day advisory; the internal 24-hour aim
does not apply to it.

**#1789 — last-admin lockout via PAT confused deputy → HIGH, not CRITICAL.**
An actor holding a restricted PAT — deliberately scoped away from admin
authority — could deactivate the install's last global admin, because the
guard asked a function about the *target's* admin status that was built to
answer a question about the *acting caller*. Severe: it strands the whole
installation with no administrator, recoverable only via direct DB
intervention. But it requires an authenticated actor already holding a
valid (if restricted) PAT — it fails "requiring no valid credential of any
kind" outright, and separately, it's an availability/control-integrity
failure (denial of administration), not a secrets-compromise or an
authentication-boundary bypass — it doesn't clear either half of the
"compromise of X" clause either. Two independent reasons it's not CRITICAL,
not one. **HIGH.**

**Illustrative CRITICAL example (hypothetical, not a real finding — included
because the definition needs at least one concrete positive case to be
legible, and none of this repository's real findings to date happen to
clear the bar):** an unauthenticated caller presenting no credential at all
is able to submit a request to the OIDC/JWKS verification path that Keyorix
accepts as a validly-signed session token — no password, no PAT, no prior
account, nothing. That clears both halves: no credential of any kind, and a
direct authentication-boundary bypass. **This is the shape CRITICAL exists
for.** The fact that neither #1742 nor #1789 — both genuinely severe —
clears it is the definition working as intended, not a sign it's drawn
wrong.

### Backported fixes: the open competitive space, not a promise

Recorded here, internal-only, deliberately not published, per this ADR's
own split rationale:

Every comparable vendor leaves the same gap. Conjur backports for roughly
six months per version — the closest any of them get. Vault Community gets
no backports at all; LTS is an Enterprise-only, paid tier. Infisical ships
3–4 releases a week with no stable branch to backport onto in the first
place. **None of them serve an operator who upgrades annually at best** —
exactly the air-gapped, change-approval-bound profile ADR-067 identifies as
Keyorix's target segment. Latest-release-only (this ADR's own published
scoping, above) is the same gap, adopted deliberately because it's what
keeps the *published* fix commitment affordable for one person.

Backporting a security fix to at least one prior minor is the differentiator
to aim at — it directly serves the customer segment this product is built
for, and no competitor at comparable team size currently offers it. It is
**not promised here or anywhere else.** It costs real, ongoing maintenance
effort (a second line to patch, a second CI matrix, cherry-pick conflicts
as lines age — the same costs ADR-067 § Consequences already names for the
LTS lines that don't exist yet either) that does not exist without a
funded team. Promising it now, to win the sales conversation, then missing
it, is exactly the failure mode this whole ADR is written to avoid. Treat
it as a roadmap target to revisit at the same trigger ADR-067 names for
extended support generally: when remediation capacity is funded beyond one
person.

### Who decides

Severity classification against the CRITICAL definition above is made once,
at merge time, by whoever fixed the issue together with the maintainer —
not re-litigated later at release-cut time. It is recorded as a row in
`docs/security-closures.d/` (the existing closure-ledger convention),
which is also how a reader can check whether a given published commitment
was actually met, rather than taking that on trust. Publishing a release
(cutting the tag) remains the maintainer's call, always — this ADR sets
the target, it does not remove the human gate on when a tag actually goes
out.

## Consequences

**Positive.** A single 90-day ceiling removes a fast, public, legally-
flavoured severity call from the critical path — the maintainer classifies
for prioritization and advance-notice purposes, on no deadline, rather than
racing a clock to decide which clock applies. The commitments that remain
(advance notice, same-day advisory with a requested CVE) are the ones a
solo maintainer can reliably deliver and that meaningfully beat every
funded competitor researched here, none of whom publish a fix SLA at all
and several of whom have empty advisory feeds. The internal/published
split means tightening practice over time doesn't require walking back a
public commitment — only tightening it, and only after a demonstrated
track record (the three-consecutive-months cadence rule is the template
for how any future tightening should be justified generally).

**Negative.** A 90-day published ceiling is a materially weaker headline
number than this ADR's first version's 14-day CRITICAL figure, and reads
less impressive in a sales conversation than a severity matrix would. That
is accepted deliberately: a matrix this team cannot reliably hit is worth
less than a ceiling it can, and the previous draft's 14-day number was
compared against no actual competitor data when it was written. A reader
skimming only the published table, without the Context section's
competitor comparison, may not immediately see why 90 days is generous
rather than slow — the same-day-advisory and advance-notice commitments
exist partly to give that reader something concretely better to point at
in the meantime.

## Follow-ups

- Revisit publishing a release cadence once three consecutive months hit
  the internal target (see "Cadence is deliberately not published yet").
- The ENISA 24h/72h/14-day regulatory reporting chain (ADR-067 §
  Follow-ups) should, when written, explicitly cross-reference this ADR to
  keep its own day-counts from being read as the same commitment.
- Revisit the backported-fixes roadmap item (above) once remediation
  capacity is funded beyond one person — do not promise it before then.
- If remediation capacity is ever funded beyond one person, this ADR's
  "who decides" and internal-target numbers are the first section to
  revisit — the published numbers should not move until the internal ones
  have proven durable under the new capacity, same rule as the cadence bar
  above.

## Amendment 1 (2026-10-22): pre-1.0 backports of Critical and High to the previous minor

Decision (Andrei, 2026-10-22, ask `security-ir-1-support-two-lines`, option a with
severity limits): the text above is left as written; this amendment supersedes it
where they differ.

- **Supported versions, pre-1.0.** "Latest release only" (the Published table and
  "Reconciling with the pre-1.0 posture") is superseded. Security fixes of every
  severity land on the current minor. Critical and High (CVSS v3.1 7.0-10.0) are also
  backported to the previous minor. Medium and Low on the previous minor require an
  upgrade. `SECURITY.md` § Supported Versions (pre-1.0) holds the table and is
  authoritative, as for every published commitment in this ADR.
- **Backports are no longer only a roadmap target.** "Backported fixes: the open
  competitive space, not a promise" said backporting to a prior minor was not promised
  anywhere. For Critical and High on the previous minor it now is, for the window
  below. Its reasoning about cost still stands, which is why the scope stops at one
  previous minor and two severities.
- **Window.** A minor receives Critical and High backports until the later of: the
  release of the next-but-one minor, or 30 days after its immediate successor is
  released.
- **Exceptions.** A fix that cannot be backported safely is not backported partially:
  the advisory says so and names the minimum version that contains the fix.
- **Dependencies.** Third-party dependency and Go toolchain vulnerabilities follow the
  same rules by their severity as it applies to Keyorix.
- **After 1.0.** Not decided here. A new policy is published with 1.0.0 and replaces
  the pre-1.0 terms.
- **Unchanged.** The 90-day ceiling, the one-week advance notice, the same-day
  advisory and the internal targets are not touched by this amendment.
