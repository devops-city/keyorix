# Incident Response Plan

**Status: DRAFT for Andrei's review and signature. Not yet adopted.**
Owner: Andrei Beshkov. Review: after every tabletop and every real SEV1/SEV2, and at
least once a year. Exercise log: [`tabletop-1.md`](tabletop-1.md).

Every legal or regulatory statement in this plan is a **draft marked
`CONFIRM WITH COUNSEL`**. Deadlines, thresholds and who must be notified are *facts to
confirm* (section 7), not assertions. Do not rely on them, or quote them to a
customer or regulator, until counsel has confirmed them.

This plan covers incidents in **Keyorix's own operation**: our source repository, CI
and release pipeline, signing and publishing, company accounts and laptops, and any
system we operate (for example a hosted demo). It also says what we do when a
researcher reports a vulnerability ([`SECURITY.md`](../../SECURITY.md) is the public
policy and stays canonical).

It does **not** cover incidents inside a customer's own Keyorix deployment. Keyorix is
self-hosted with no telemetry and no phone-home, so we have no access to a customer's
instance, secrets or audit log. A customer's incident is the customer's to run; our
role there is support and, if the root cause is a Keyorix defect, a vulnerability
response (section 8.4). `CONFIRM WITH COUNSEL`: whether any pilot or hosted
arrangement makes Keyorix a processor of personal data, which changes this.

## 1. Roles

Keyorix is a small team: a founder plus cofounders, no on-call rota, no security
staff. One person will often hold several roles. What must hold regardless:

| Role | Does | Default | Deputy |
|---|---|---|---|
| **Incident Commander (IC)** | Declares the incident and severity, owns decisions, keeps the clock | Andrei | [cofounder A] |
| **Technical lead** | Contains, investigates, fixes; owns evidence handling | Andrei, or whoever knows the affected system | [cofounder B] |
| **Communications lead** | Writes and sends customer, researcher and regulator messages after IC approval | [cofounder A] | Andrei |
| **Scribe** | Keeps the timeline (UTC, one line per event or decision) | Anyone who is **not** the technical lead | [cofounder B] |
| **Counsel** | Confirms notification duties and wording | External counsel `[firm, contact: CONFIRM]` | none |

Rules for a team this size:

1. **There is always a scribe.** If you are alone, the timeline is a plain text file you
   append to as you go. Reconstructing it later is where mistakes enter.
2. **The IC and the technical lead should not be the same person for SEV1** if a second
   person can be reached within 30 minutes. Otherwise write down that you were alone.
3. **Two-person rule for irreversible, outward-facing actions:** withdrawing a release,
   publishing an advisory, notifying a regulator, rotating a signing identity. The IC
   proposes, a second person (a cofounder, or counsel) confirms in writing. If nobody
   can be reached within the response target, the IC acts and records why.
4. **Out of reach.** If the IC cannot be reached in 1 hour for a SEV1, the deputy
   becomes IC. Every role holder keeps the contact sheet (below) offline.
5. Do not discuss the incident on a channel that the suspected compromise may touch
   (company chat or email, if those are in scope). Use the out-of-band channel named
   in the contact sheet.

**Contact sheet** lives outside this repository (the repository is public): phone
numbers, personal email, counsel, hosting and registrar support lines, the GitHub
organisation owners. Andrei to create it and name its location here:
`[location: CONFIRM]`.

## 2. Severity scale

Severity is set by the IC at declaration and re-set whenever facts change. Over-call
first, downgrade later.

| Sev | Meaning for Keyorix | Examples | Response | Update cadence |
|---|---|---|---|---|
| **SEV1** | Customers' secrets or trust are at risk now, or a trust anchor is compromised | Malicious or tampered release or image published; signing identity or release credentials compromised; remote unauthenticated compromise of secret values or the auth boundary (the CRITICAL definition in ADR-104) | Start within 15 min, all hands | hourly |
| **SEV2** | Serious exposure, not yet shown to reach customers | Leaked CI or publish token that has *not* been used; exploited vulnerability with a workaround; compromise of one maintainer account; audit-chain break reported against a supported release | Start within 1 h | every 4 h |
| **SEV3** | Contained or limited | Valid vulnerability report without known exploitation; suspicious activity on a company account, no sign of misuse; dependency advisory reachable in Keyorix | Same business day | daily |
| **SEV4** | Hygiene | Invalid or out-of-scope report; near miss | Next business day | on close |

This is an *incident* scale. It is not the vulnerability severity used for
prioritising fixes in `SECURITY.md` / ADR-104; a SEV1 incident can have a High
vulnerability behind it and the published 90-day ceiling and same-day-advisory
commitments still apply.

## 3. Detection and intake

Ways we find out: the security mailbox, a GitHub private vulnerability report, a
customer or pilot contact, GitHub notifications (secret scanning, push protection,
Dependabot, unexpected workflow runs or releases), a failing signature or attestation
check, a failing `verify-audit`, a teammate noticing something odd.

- Anyone who suspects an incident **declares it**. A false alarm costs an hour; a late
  declaration costs the clock in section 7.
- Mailbox and GitHub private reports: acknowledge within 48 hours (public
  commitment). Treat a report that describes a live compromise as SEV1/SEV2 and ignore
  the 48-hour target; the IC replies the same hour.
- **Open a private incident record** at declaration: one private document or
  private GitHub issue titled `INC-YYYY-MM-DD-<slug>` with severity, IC, start time
  (UTC), and the timeline. Keep it out of this public repository until disclosure.

## 4. First-hour checklist

Work top to bottom. Times are targets from declaration (T+0).

**T+0 to T+10: declare**
- [ ] IC named. Scribe named. Out-of-band channel chosen.
- [ ] Severity set (section 2). Incident record created. Clock started: write down
      **the time we became aware** (UTC); regulatory clocks may count from here
      (section 7).
- [ ] Say in the record what is *known*, what is *suspected*, what is *unknown*.

**T+10 to T+30: stop the bleeding without destroying evidence**
- [ ] Snapshot before you change: screenshot or export the current state of the
      affected system (workflow runs, release list, token list, audit log) *before*
      revoking or deleting (section 6).
- [ ] Revoke or rotate the suspected credential. Disable the affected workflow or
      automation. Suspend the affected account's sessions.
- [ ] If an artifact may be malicious: stop distribution (section 8.3), do not delete
      it yet.
- [ ] Check what else the credential could do: scopes, organisations, repositories,
      packages, registries, other tokens in the same place.

**T+30 to T+60: scope and decide**
- [ ] Establish the window: first possible misuse to now. Pull logs for that window
      (section 6).
- [ ] List what was reachable and what was actually touched. Mark each "confirmed",
      "possible", "ruled out".
- [ ] Decide customer notification (section 5) with the IC and counsel. If the answer
      is "probably yes", prepare the message now; do not wait for certainty.
- [ ] Decide whether a regulatory clock has started (section 7). Ask counsel today,
      not on day three.
- [ ] Set the next update time and tell the team.

If a step cannot be done in the hour, write why in the timeline and move on.

## 5. Customer and reporter communication

Who we tell, in order: affected pilot and customer contacts → everyone who may have
installed an affected artifact (public advisory) → the researcher, if there is one →
regulators, if counsel confirms a duty (section 7).

- **Principle:** tell customers what to *do* first (which versions, which digests,
  which credentials to rotate, how to verify), then what happened. Keep a facts-only
  tone. No speculation about attribution or motives.
- **Channels:** direct email to the named security contact for each pilot customer
  `[customer contact register: CONFIRM, create before the pilot]`; a GitHub Security
  Advisory for public issues; the GitHub Release notes and `CHANGELOG.md` `### Security`
  entry. Do not use a channel that the incident may have compromised.
- **Draft the message in the record**, IC approves, a second person reads it for
  accuracy before it is sent.
- **Contractual notice.** Pilot and commercial agreements may impose their own
  incident-notice periods. `CONFIRM WITH COUNSEL` and check each signed agreement;
  the shortest period governs.
- **Personal data.** If the incident involves personal data we hold (for example
  customer contact details, or a hosted service we operate), a GDPR notification
  analysis is required (section 7). Because the product has no telemetry, this will
  usually be company data only. `CONFIRM WITH COUNSEL`.
- **Researcher.** Keep the reporter informed; agree the disclosure date; credit them
  unless they decline ([`SECURITY.md`](../../SECURITY.md)).
- **Do not** confirm or deny a compromise to the press or social media from this plan.
  Route enquiries to the communications lead with counsel.

## 6. Evidence preservation

Preserve first, then remediate. Evidence that cannot be re-obtained must be copied
before it is changed or ages out.

1. **Record time and hands.** Everything you do is written in the timeline with a UTC
   time. Note who handled each item (chain of custody).
2. **Export, do not just look.** Save to a private, access-restricted location that is
   *not* the possibly-compromised system, and write the SHA-256 of each file into the
   record:
   - GitHub: organisation audit log and repository security log for the window
     (export before retention expires), workflow run logs and their artifacts,
     list of tokens, deploy keys, apps and OAuth grants, the release list, and
     container package versions with their digests and tags.
   - Registry (GHCR): package version list with digests, creation times and the
     actor if shown; manifests of every suspect image (`docker buildx imagetools inspect`).
   - Signature evidence: the cosign signature and certificate for each artifact, the
     GitHub attestation (`gh attestation verify`), and the corresponding public
     transparency-log entries (these are immutable and independently checkable).
   - Suspect artifacts: download the bytes, record digests, keep read-only copies for
     analysis. Never run suspect binaries on a machine holding credentials.
   - Host or VM: disk and memory image before reboot if a host was compromised; a
     provider snapshot is acceptable.
   - Email and chat: headers of phishing messages; the researcher's original report.
3. **Retention clock.** GitHub's audit-log and Actions-log retention windows are
   finite and plan-dependent. `[retention periods: CONFIRM against our plan]`. Export
   at T+30 for a SEV1/SEV2 instead of assuming the data will be there later.
4. **Do not clean up early.** Do not delete the malicious release, force-push over
   history, or remove a token's record until the exports are done and hashed. Hide or
   withdraw instead (section 8.3).
5. **Legal hold.** Once a regulator or litigation is plausible, stop routine deletion of
   related records. `CONFIRM WITH COUNSEL`.
6. **Keep a copy of the final record for at least `[retention: CONFIRM WITH COUNSEL]`.**

## 7. Notification clocks: FACTS TO CONFIRM

> **Nothing in this section is advice or an assertion of what applies to Keyorix.** It
> lists the regimes we believe may apply and the clocks we recall for them, so that
> counsel can confirm or strike each line before the plan is adopted. Each row is
> `CONFIRM WITH COUNSEL`. Citations are to be verified against the current official
> text; they are from memory and may be wrong or out of date.

| Regime | Might apply because | Clock we believe exists (verify) | To confirm |
|---|---|---|---|
| **GDPR** | We hold personal data (customer contacts, staff, any hosted service) | Controller notifies the supervisory authority without undue delay and, where feasible, within 72 hours of becoming aware of a personal-data breach that is likely to result in a risk; processor notifies the controller without undue delay; data subjects if high risk (Arts. 33 and 34) | Are we a controller, a processor, or both, for any data? Which authority (Keyorix SL, Valencia: AEPD?). What counts as "aware". |
| **NIS2** | Customers are essential/important entities and may push duties down by contract; we may ourselves be in scope as a provider | Early warning within 24 h, incident notification within 72 h, final report within one month, for significant incidents (Art. 23) | Is Keyorix SL itself an in-scope entity in Spain? Which CSIRT/authority? Do customers' contracts require us to support their reporting? |
| **DORA** | Financial-sector customers using Keyorix as an ICT third-party service | Financial entities classify and report major ICT incidents on staged deadlines (initial, intermediate, final) set in delegated acts; ICT third-party providers must support them (Art. 19 and the technical standards) | Are we an ICT third-party service provider to any pilot customer? What do the contractual clauses require of us and by when? |
| **CRA** | We are a manufacturer of a product with digital elements | Manufacturers notify actively exploited vulnerabilities and severe incidents affecting product security via a single reporting platform: early warning within 24 h, notification within 72 h, final report on a later fixed schedule (Art. 14) | From what date do these obligations apply, and do pre-1.0 development tags count? (`SUPPORT.md` says they are not placed on the market. `SECURITY.md` currently states we operate under the CRA reporting regime: reconcile.) |
| **Contracts** | Pilot / commercial agreements | Customer-specific notice periods | Read each signed agreement. |

Practical rule until counsel responds: **treat the shortest clock in the table as
running from the moment of awareness for any SEV1, and ask counsel within the first
hour** whether any of them has actually started. Record the awareness time (section 4).
It is cheaper to be told "no duty" than to discover a missed one.

## 8. Platform-specific cases

Keyorix is a secrets platform, so three failure modes recur. Each is written as: how
it presents, first actions, decision points, what *not* to do.

### 8.1 Suspected master key exposure

*Context (verify against `docs/security/architecture.md` §1-2 and `docs/SELF_HOSTING.md`
§4 before relying on this):* secrets are encrypted with a DEK; the DEK is wrapped by a
KEK derived from `KEYORIX_MASTER_PASSWORD` (or supplied by a KMS/TPM/Shamir/file/env
key provider). `admin encryption rotate` replaces the **DEK** and re-encrypts every
secret; `admin encryption rotate-kek` changes the **KEK/passphrase**. Editing the
variable by hand makes every secret undecryptable.

**Who:** this is almost always a *customer* deployment. For Keyorix's own systems
(a hosted demo, our CI) apply the same steps to our own deployment.

**Triage question: what leaked, and does the attacker also have the data?**

| Exposed | Attacker also has DB or backup | Meaning |
|---|---|---|
| Master password / KEK source only | No | Cannot decrypt anything alone. Rotate the KEK promptly; lower urgency. |
| Master password / KEK source | **Yes (database dump, volume or backup)** | **Every secret in that data set is decryptable.** Treat all stored values as disclosed. |
| Wrapped DEK / key volume only | No KEK | Cannot decrypt alone; rotate anyway. |
| Decrypted DEK or process memory | n/a | As above; assume everything the process held. |

**First actions (customer-facing guidance; the customer's IC runs them):**
1. Establish the window and the set of copies of the data: live DB, replicas,
   backups, snapshots, exported archives. Old backups remain decryptable with the old
   KEK even after rotation.
2. Rotate the KEK source (`admin encryption rotate-kek`, or the KMS key) and rotate the
   DEK (`admin encryption rotate`); the sweep fences writes briefly and survives a
   restart. Do both when the attacker may hold any ciphertext.
3. **Rotating Keyorix's keys does not un-leak a secret value the attacker already
   decrypted.** If decryption was possible, the customer must rotate the *secrets
   themselves* at their source (database passwords, API keys, certificates), highest
   blast radius first. Keyorix's rotation and dynamic-secret features can drive this.
4. Revoke sessions, tokens and PATs if the same breach may have reached them; review the
   audit log for unexpected secret reads or admin activity in the window.
5. Decide the fate of old backups: re-encrypt, or destroy once they are no longer
   needed, per the customer's retention rules.

**Decisions for Keyorix:** is this a product defect (key written somewhere it should
not be: log, error, backup manifest, crash dump)? If yes, it is a vulnerability: go to
8.4 and `SECURITY.md`. Otherwise support only.

**Do not:** edit `KEYORIX_MASTER_PASSWORD` in place; delete the key volume "to be
safe"; rotate before copying the evidence that shows how the key leaked.

**To confirm before adoption:** what `rotate-kek` does to the signed audit checkpoints
and backup-manifest signing key, which are KEK-derived (`architecture.md` §3,
`UPGRADING.md`); write the verified answer into this section. `[CONFIRM by test]`

### 8.2 Audit-chain break

*Presents as:* `keyorix-server admin verify-audit` exits non-zero, or
`GET /api/v1/audit/verify` reports a mismatch, or a checkpoint is refused.

**Principle:** the chain is evidence. A break means one of: a **bug** in Keyorix, a
**storage or restore fault**, or **tampering**. Do not decide which before preserving
it, and do not "repair" it.

**First actions:**
1. **Stop writes that would destroy evidence?** Take a detached copy of the database
   (SQLite file copy, or a restored/replica PostgreSQL) *before* anything else. Run
   verification on the copy; `verify-audit` on a copy takes no lock
   (`hardening-guide.md`).
2. Record: the first failing entry id, the failure type (hash mismatch, gap, reorder,
   truncation, checkpoint signature), the Keyorix version, and when the last good
   verification ran.
3. Compare against independent anchors if the customer has them: the off-box `--anchor`,
   the RFC 3161 `--tsa-roots` timestamp, signed checkpoint exports on write-once media.
4. Look at what happened near the break: restore, upgrade, migration, failover, manual
   SQL, disk full, a rotation.
5. Classify: reproducible on a clean copy of the same version → bug (8.4);
   correlates with a restore or migration → process fault; no benign explanation and
   admin/DB access in the window → treat as tampering and a security incident (SEV2,
   SEV1 if it hides secret reads).

**Decisions:** whether to treat all secrets read in the unverifiable range as possibly
exposed; whether the customer must notify (their regimes, not ours).

**Do not:** let the scheduler "re-baseline" the checkpoint before the copy exists (a
checkpoint is refused over a shorter chain, and verification fails closed until the next
re-baseline: that behaviour is evidence); edit or delete rows; restore over the
original.

**Stated limit:** a DB-level actor who can write the checkpoints table can force a
fail-closed verify but cannot forge a valid checkpoint for a truncated chain
(`architecture.md` §3). The off-box anchor and timestamp are what protect against a
fully privileged attacker, so ask early whether they exist.

### 8.3 Malicious release or artifact

*Presents as:* an unexpected tag, release, workflow run or image; a signature or
attestation that does not verify or names an unexpected workflow; a hash that differs
from `checksums.txt`; a report from a customer or researcher; a leaked publish
credential.

This is the most severe case we can have: our users run what we publish. Treat it as
**SEV1 until the artifacts are proven clean**. [`tabletop-1.md`](tabletop-1.md)
exercises it.

**Normal artifact trust, for reference** ([`SECURITY.md`](../../SECURITY.md) § Verifying
a Release): `checksums.txt` and container images are keylessly signed by cosign with the
identity of our release / docker-publish workflow, and carry SLSA provenance. An
artifact pushed directly with a stolen registry token would **not** carry a valid
signature from that workflow identity, so users who verify can detect it; users who do
not verify cannot. Say this plainly in the advisory.

**First actions:**
1. **Contain the publisher.** Revoke the leaked or suspected credential (token,
   deploy key, app installation, personal access token). Disable the release and
   image-publish workflows. Remove any new collaborator, key, secret or workflow
   change made in the window. (After exporting, section 6.)
2. **Enumerate what was published in the window:** git tags and releases, GHCR image
   tags and digests, packages, Helm chart versions, SBOMs, anything else. Record each
   digest and tag. Compare against the last known-good release.
3. **Classify each artifact:** *legitimate* (built by our workflow from a reviewed
   commit: signature, provenance and `checksums.txt` agree), *malicious or unknown*
   (anything else). When unsure, withdraw.
4. **Stop distribution without erasing evidence:** mark a release as draft or
   pre-release and edit its notes to say "do not use"; remove or retag the container
   tag so that `latest` and the version tag no longer resolve to the bad digest. The
   **digest remains pullable by anyone who has it**: say so. Deleting the package
   version outright waits for the evidence export.
5. **Advisory within hours, not days.** Publish a GitHub Security Advisory naming
   affected versions, bad digests, the exact verification commands, what to do if you
   pulled it (stop, quarantine, treat the host's reachable secrets as exposed, rotate
   them), and the fixed version. A malicious image running inside a customer's secrets
   manager is a full compromise of that deployment's stored secrets. Do not minimise it.
6. **Ship a clean release** from a verified-clean commit and a rebuilt pipeline, under
   a **new version number**: never reuse a tag. Publish new digests and re-verify with
   the commands in `SECURITY.md` before announcing.
7. **Reset trust:** rotate every credential the publishing path could reach; review
   and tighten token scope and expiry; re-check branch protection and the break-glass
   bypass actor (`SDLC.md` § Branch protection); review who can approve workflow
   changes. Pin consumers to digests in our own compose files and chart.

**Decisions for the IC (two-person rule):** withdraw vs. leave a release up; when to
publish the advisory; whether regulators and customer contracts are triggered (section
7); whether to tell customers *before* the advisory.

**Do not:** reuse the compromised version number; delete evidence first; assume our
own CI is clean after revoking one token; announce "no impact" before the digest
inventory is complete.

### 8.4 Vulnerability reported or found in Keyorix (not an active compromise)

Follow [`SECURITY.md`](../../SECURITY.md): acknowledge in 48 h, assess in 7 days, fix
within 90 days, one week advance notice for High/Critical, same-day GHSA with CVE.
Develop the fix in a private advisory fork, not a public branch. Every `fix(security)`
change carries a regression test and a closure fragment in `docs/security-closures.d/`
(`CLAUDE.md` § Closing a security fix). Escalate to this plan's SEV levels if the
vulnerability is **being exploited** (SEV1/SEV2), then sections 4 to 7 apply.

For a flaw in a **third-party dependency**, report privately to that project, agree an
embargo, land a guard on our side first, and name nothing publicly until upstream has
disclosed or agrees (`scripts/fuzzing/DISCLOSURE-TRIAGE.md`; embargo rule in
`docs/security/testing.md` and `SDLC.md`).

## 9. Closing an incident

- [ ] Containment confirmed and monitored for a defined period.
- [ ] All customers who needed to be told have been told; the researcher is told.
- [ ] Advisory published or a recorded decision not to publish (and why).
- [ ] Regulator and contract duties decided with counsel and recorded.
- [ ] Evidence exports complete, hashed and stored.
- [ ] **Blameless review within 5 business days:** what happened, timeline, what went
      well, what did not, the control that would have stopped or detected it.
- [ ] Each corrective action has an owner, a date and a check that fails if it
      regresses (`CLAUDE.md` § machine-checked over asserted), or says why not.
- [ ] This plan updated where it was wrong or slow.

## 10. Maintenance and open items

- Exercised by [`tabletop-1.md`](tabletop-1.md); outcomes feed back here.
- Open items before adoption (also in the PR): counsel confirmation of section 7; the
  contact sheet; the customer contact register; GitHub retention periods; the
  verified effect of `rotate-kek` on checkpoints; deputy names; whether the hosted demo
  is operated by Keyorix and what data it holds.
