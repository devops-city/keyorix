# Tabletop 1: a leaked CI token publishes a bad image

**Status: script ready, not yet run.** Facilitator: Andrei. Plan under test:
[`incident-response-plan.md`](incident-response-plan.md), mainly sections 2, 4, 5, 6,
7 and 8.3.

This is a discussion exercise. Nothing is run against real systems, and no real token,
image or customer is touched. Participants talk through what they would do, using the
real runbook, and the scribe records where the plan was missing, wrong or slow.

## Setup

- **Duration:** 60 to 90 minutes. **Who:** Andrei (IC), the cofounders, and, if
  possible, counsel for the injects marked (counsel). If you are alone, play every
  role and write down which hat made each decision.
- **Rules:** answer from what you could actually see and do on the day, not what you
  wish existed. If a step needs a document, contact or permission you cannot name,
  that is a finding. Use the real plan; do not improvise a better one.
- **Facilitator** reads each inject aloud, waits for decisions, notes the time taken,
  then reveals the next inject. Do not preview later injects.
- **Scribe** is not the IC. Record timeline, decisions, and the "expected decision"
  checks below.
- Allocate roles per plan section 1 before starting. Start a real incident record
  (`INC-TT1-<date>`) so the record-keeping is practised too.

## Scenario background (read to all)

It is a Thursday, 16:40 local time. Keyorix has a public container image on GHCR and
GitHub Releases with cosign signatures and SLSA provenance. Pilot customers have been
told to verify signatures; two of them run the `latest` tag in a staging environment.
You have three people, no on-call rota. One of you is on a flight until tomorrow.

The scenario is fictional. Names and numbers are invented.

## Injects

### Inject 1 (T+0): the first signal

A researcher emails the security address: *"Your image `ghcr.io/keyorixhq/keyorix-server:<next-patch>`
was pushed 40 minutes ago and `cosign verify` fails with your documented command. The
tag is not on your releases page. I did not pull it past that point. Is this yours?"*

Nobody on the team pushed anything.

Ask: *What do you do in the first ten minutes? Who is told, and how? What severity
and why?*

**Expected decisions**
- Declare an incident immediately; do not wait to prove it. Name IC and scribe; start
  the record and write down the awareness time (UTC).
- Initial severity SEV1 (possible malicious release), because a signed-artifact trust
  failure on a secrets manager's image is the worst case; downgrade later with evidence.
- Reply to the researcher the same hour (not 48 h), ask them not to publish, and thank
  them.
- Use an out-of-band channel; do not assume company chat or email is clean.
- Snapshot before changing anything (plan 4, T+10 to T+30).

### Inject 2 (T+20): what was published

You look at GHCR. A new image version exists under a version tag that is not one of
yours, plus the `latest` tag now points at it. It was pushed by a personal access
token belonging to a maintainer, not by the publish workflow. The image has no
attestation. `checksums.txt` and the GitHub Releases are unchanged. The maintainer is
the one on the flight and is unreachable for 6 hours.

Ask: *What do you revoke and disable, in what order? What do you preserve first?
Can you act without that maintainer?*

**Expected decisions**
- Export before changing: the package version list with digests and timestamps, the
  org audit log, the token list, workflow run history (plan 6). Hash the exports.
- Revoke that maintainer's token (an org owner can; no need to wait for them). Disable
  the publish workflow until the cause is known. Check for other tokens, keys and
  apps the account held.
- Do not delete the bad image version yet. Stop `latest` resolving to it (retag to the
  last known-good digest) and record the bad digest.
- Two-person rule for the retag and any deletion; write down the confirmer.
- Treat the unreachable maintainer as possibly compromised (laptop, other accounts),
  but not as a suspect; do not accuse.

### Inject 3 (T+45): who pulled it

Registry download counts show 9 pulls of the bad digest. Two pulls came from IP
ranges that match a pilot customer's staging network. A pilot's security contact
emails you: *"Our staging pulled something odd. Should we be worried?"*

Ask: *What do you tell the pilot, now? What do you ask them to do? What is the worst
case you must plan for? What do you not yet know?*

**Expected decisions**
- Tell the pilot immediately, directly, with actions first: stop and isolate the
  container, do not restart it, preserve it, pin to the last good digest, verify
  signatures, treat any secrets reachable by that container as exposed and begin
  rotating them, highest blast radius first.
- State known / suspected / unknown honestly. Do not say "no impact".
- Recognise that a malicious image inside a secrets manager can read everything that
  instance stores: this is the customer's incident to run, with our support.
- Identify the other pilot on `latest`, and contact them too, without waiting to see
  whether they pulled it.
- Ask counsel (counsel) whether the contract's incident-notice clause is triggered
  and the clock (plan 7). Record the answer and the time.

### Inject 4 (T+75): analysis returns

A teammate pulls the bad image in an isolated VM. It is the real server binary with an
extra goroutine that, once a secret is read, sends the plaintext to an unfamiliar
host. The binary reads the master key from the process. The audit chain on a test
instance still verifies, because the chain records access events, not network
egress.

Ask: *What changes in the severity, the advisory, and the customer guidance? What does
this say about the audit chain's guarantees?*

**Expected decisions**
- Confirm SEV1. Customer guidance is now: any deployment that ran the bad digest
  should be treated as a **full secret and master-key exposure**: rotate the KEK
  and DEK (plan 8.1), then rotate the secrets themselves at source. Rotating Keyorix's
  keys alone does not help, since the attacker saw plaintext.
- A passing audit verification is **not** evidence of safety here; say so explicitly in
  the advisory.
- Share the exfiltration host and the file hashes as indicators in the advisory.
- Preserve the binary and analysis notes (plan 6); do not run it again on any machine
  with credentials.

### Inject 5 (T+100): the researcher and the clock

The researcher says they will publish their findings on social media in 3 hours unless
they hear about a fix. Meanwhile counsel (counsel) asks whether Keyorix itself is
subject to any incident notification, and what the "time of awareness" was.

Ask: *What do you tell the researcher? What goes to counsel? Do you publish the
advisory before the clean release is ready?*

**Expected decisions**
- Call the researcher; agree a short, concrete timeline; credit them. Do not threaten.
- Publish the advisory **before** the clean release if customers are still exposed: the
  action users need (stop, quarantine, verify, rotate) does not depend on the fix.
- Give counsel the awareness time (Inject 1), the data collected, and the regimes in
  plan 7. Record the answer and what the clock deadlines would be.
- Do not wait for full root cause to notify.

### Inject 6 (T+150): root cause

The maintainer lands and reports they pasted a token into a public gist while pairing
two months ago. Push protection never saw it because it was not in the repository.
The token had write access to packages in the organisation and no expiry.

Ask: *What do you change, and how do you know it worked? What goes in the advisory?
What is the clean release process?*

**Expected decisions**
- Revoke and replace all long-lived tokens; adopt short-lived, scoped credentials or
  workflow-identity publishing where possible; remove the ability for personal tokens
  to push release images; require provenance for the images we tell users to run.
- Corrective actions have owners, dates and a check that fails if they regress, not
  just a promise.
- Clean release: new version number, built from a verified commit by the rebuilt
  pipeline, signed and attested; verify it with the documented commands before
  announcing; never reuse the burned tag.
- Advisory states root cause plainly and what verification would have caught it.
- Schedule the blameless review within 5 business days.

## Debrief questions (15 minutes)

1. What took longest? Where did we have to guess a command, contact or permission?
2. Which decision did we disagree on? Was the plan silent or unclear?
3. Could the two-person rule have been met at 02:00 on a Sunday?
4. Did we tell the customer what to *do* before telling them what happened?
5. What would have detected this earlier (alerting on pushes outside the workflow,
   token expiry, provenance enforcement on pull)?
6. Which line of the plan is wrong, missing or unrealistic for a team of our size?

## Outcomes (Andrei fills in after running)

**Run date:** ____ **Facilitator:** ____ **Participants / roles:** ____ **Duration:** ____

| # | Inject | Expected decisions met? (Y/partial/N) | What the team actually did | Time taken | Gap found (plan, tooling, contact, permission) | Corrective action | Owner | Due |
|---|---|---|---|---|---|---|---|---|
| 1 | First signal | | | | | | | |
| 2 | What was published | | | | | | | |
| 3 | Who pulled it | | | | | | | |
| 4 | Analysis returns | | | | | | | |
| 5 | Researcher and the clock | | | | | | | |
| 6 | Root cause | | | | | | | |

**Plan sections changed because of this exercise:** ____

**Time from first signal to (a) incident declared, (b) bad artifact contained,
(c) customers told, (d) advisory published:** ____

**Questions for counsel raised during the run:** ____

**Overall result** (Pass / Pass with actions / Fail, and why): ____

**Next tabletop** (date and scenario; suggestions: suspected master-key exposure on a
pilot, audit-chain break after a restore): ____
