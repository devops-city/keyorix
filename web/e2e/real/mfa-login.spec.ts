// web/e2e/real/mfa-login.spec.ts — SESSION-WEB-E2E item 1: exercises TOTP MFA
// through the real Profile → Security UI (no mocked routes, same real-backend
// shape as pages.spec.ts) and a subsequent login.
//
// Both known product bugs this file originally tracked are now fixed:
// - #2441 (MFA enrollment always 400ing — EnrollModal never collected/sent the
//   account password ActivateMFA requires): EnrollModal now has a password
//   field, and mfaApi.activate sends it alongside the code.
// - #2442 (logging in with MFA enabled never prompted for a code — authStore
//   ignored mfa_required): login() now stores a pending mfaChallenge instead
//   of landing a bogus "authenticated" session, LoginPage renders a code-entry
//   step, and verifyMfa() completes it against the real VerifyMFA endpoint.
// Both tests below assert the real flow completes end to end, instead of
// test.fail()ing on either known bug.
//
// Note on "bootstrap admin via the UI" (SESSION-WEB-E2E item 1's own wording):
// there is no such UI flow in this app. POST /system/init (internal/core's
// bootstrap) has no corresponding page -- grepped web/src for any
// system-init/setup-wizard component and found none; web/src/pages/auth/
// SetupPage.tsx is a DIFFERENT flow (ADR-028 credential-delivery links for
// already-created users, not first-run bootstrap). The admin account below is
// bootstrapped the same way web-real-smoke.sh already does it (POST
// /system/init via curl). This is a real, documented product gap (no UI
// onboarding wizard), not a shortcut taken by this test -- flagged in
// SESSION-WEB-E2E's report, not silently worked around.
//
// TOTP codes below are computed with a minimal local RFC 6238 implementation
// (totpCode()) rather than pulling in a new npm dependency for one helper --
// internal/core/mfa.go's totpPeriod/Digits/Algorithm constants (30s, 6
// digits, SHA1) are mirrored exactly, not guessed, and cross-checked live
// against the real github.com/pquerna/otp output for the same secret/time
// before this file was written.
//
// Both tests create their own dedicated throwaway user (createDedicatedUser)
// for the actual MFA enroll/login attempt -- MFA is a one-way, session-
// breaking mutation, so enabling it on the shared ADMIN_USERNAME would make
// every other spec file's (and this suite's own repeat-run) admin login
// order-dependent on whether this file ran first. ADMIN_USERNAME is used
// only for its unrelated authority to create another account via
// POST /api/v1/users, exactly like web-real-smoke.sh already uses it to
// create a project -- the shared admin's own MFA/session/role/password state
// is never touched. Because each test operates on a throwaway user nobody
// else depends on, neither test needs a disable-MFA cleanup step.
import { test, expect } from '@playwright/test';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
    createDedicatedUser,
    enableMfaViaApi,
    realLogin,
    submitLogin,
    totpCode,
    waitForFreshTotpCode,
} from './helpers';
import { compliantPassword, passwordPolicyFailures, personalInfoCandidates } from './support/password';

// The TOTP/base32/apiLogin/createDedicatedUser/enableMfaViaApi helpers these tests use
// now live in ./helpers.ts, shared with mfa-disable-dialog.spec.ts (#2738). The only
// change in the move is that createDedicatedUser there now carries main's #2815/#2830
// compliantPassword logic; see that file's own comments.

// #2815's guard. Deliberately added to THIS spec file rather than a new
// *.spec.ts: scripts/e2e/web-real-smoke.sh discovers groups with
// `find e2e/real -maxdepth 1 -name '*.spec.ts'` and bootstraps a fresh backend
// per group, so a new file would cost a whole extra backend for two tests that
// need no server at all. These run in milliseconds inside an existing group.
test('the fixture password generator always satisfies the password policy (#2815)', () => {
    // 200 runs, the number #2815 asks for. The flaw it replaces failed 7.4% of
    // calls, so 200 runs would have produced ~15 failures -- measured at
    // exactly 15/200 locally before the fix. Zero is the only passing result.
    const RUNS = 200;
    const stamp = Date.now();
    const username = `mfaguard${stamp}`;
    const info = personalInfoCandidates({
        username,
        email: `${username}@example.invalid`,
        displayName: `MFA Test User ${stamp}`,
    });
    const offenders: string[][] = [];
    for (let i = 0; i < RUNS; i++) {
        const failures = passwordPolicyFailures(compliantPassword(info), info);
        if (failures.length > 0) offenders.push(failures);
    }
    expect(offenders, `${offenders.length}/${RUNS} generated passwords did not satisfy DefaultPasswordPolicy`).toEqual(
        []
    );

    // Calibration: the assertion above is only meaningful if the predicate it
    // uses can actually fail. Feed it the exact literal #2815 was about (no
    // digit anywhere) and the exact personal-info trap, and require both to be
    // reported -- otherwise a vacuous predicate would make the 200 runs above
    // pass no matter what the generator did.
    expect(passwordPolicyFailures('Quartz-Falcon-ifvoqppv-Garnet!')).toContain('contain a digit');
    expect(passwordPolicyFailures('short1A!')).toContain('be at least 16 characters');
    expect(passwordPolicyFailures(`Aa1!bbbbbbbbbbbb${stamp}`, info).join(' ')).toContain(
        'username, email or display name'
    );
});

test('no real-backend spec hand-rolls a fixture password (#2815)', () => {
    // Family-wide guard, not a guard on the one fixed line: the broken idiom
    // was a base-36 stringification of a random float used as the ONLY source
    // of a required character class. Both known instances now call
    // compliantPassword, and this keeps the next one from being written.
    //
    // WHAT THIS RECOGNISES, stated per CLAUDE.md's "an enumeration is only as
    // complete as the idioms it knows about": exactly one idiom -- the base-36
    // random stringification assembled in IDIOM below -- on a non-comment line
    // that also mentions "password" (case-insensitive), in any *.spec.ts
    // directly under e2e/real. It does NOT recognise a hand-written password
    // literal with no randomness, a password built in a helper file outside
    // e2e/real, or randomness drawn from node:crypto. Those would need their
    // own check; this one closes the idiom that actually caused #2815.
    //
    // IDIOM is assembled from fragments rather than written as one literal so
    // this guard cannot match its own source -- it scans the directory it
    // lives in, and a verbatim literal here made it fail on its own prose.
    // Comment lines are skipped for the same reason: a sibling spec is allowed
    // to EXPLAIN the idiom without being accused of using it.
    const IDIOM = ['Math', '.random()', '.toString(', '36)'].join('');
    // ESM: no __dirname. Resolve this spec's own directory from import.meta.
    const dir = fileURLToPath(new URL('.', import.meta.url));
    const offenders: string[] = [];
    const specs = readdirSync(dir).filter((n) => n.endsWith('.spec.ts'));
    // A zero-file sweep would make this assertion vacuously green -- the exact
    // "a check that always passes" failure mode. This file is itself one of
    // them, so the floor is 1.
    expect(specs.length, `found no *.spec.ts files under ${dir} -- the sweep would be vacuous`).toBeGreaterThan(0);
    for (const name of specs) {
        const lines = readFileSync(join(dir, name), 'utf8').split('\n');
        lines.forEach((line, idx) => {
            const trimmed = line.trim();
            if (trimmed.startsWith('//') || trimmed.startsWith('*')) return;
            if (!trimmed.includes(IDIOM)) return;
            if (!/password/i.test(trimmed)) return;
            offenders.push(`${name}:${idx + 1}: ${trimmed}`);
        });
    }
    expect(
        offenders,
        'these lines build a fixture password from a base-36 random stringification, which ' +
            'satisfies DefaultPasswordPolicy only by chance (#2815) -- use compliantPassword() ' +
            'from ./support/password instead'
    ).toEqual([]);
});

test('MFA enrollment via Profile → Security completes (fixes known bug #2441)', async ({ page }) => {
    // https://github.com/keyorixhq/keyorix/issues/2441 -- server/http/handlers/mfa.go's
    // ActivateMFA requires BOTH the TOTP code and the account password
    // (internal/core/mfa.go's requireReauth falls through to the
    // password-compare branch, since MFAEnabled is still false during
    // enrollment). web/src/features/account/MfaSection.tsx's EnrollModal now
    // collects both -- mfaApi.activate(code, password) sends {code, password}
    // -- so the backend's real contract (confirmed live in the issue's own
    // repro: the exact same request shape with both fields succeeds) is now
    // reachable through the UI.

    const user = await createDedicatedUser('mfaenroll');
    await realLogin(page, user.username, user.password);

    await page.goto('/profile');
    await page.getByRole('button', { name: 'Security' }).click();
    await expect(page.getByText('Two-Factor Authentication')).toBeVisible();

    await page.getByRole('button', { name: 'Enable' }).click();
    const secretLocator = page.locator('code').first();
    await expect(secretLocator).toBeVisible({ timeout: 10_000 });
    const secret = (await secretLocator.textContent())?.trim();
    expect(secret, 'enrollment must render a non-empty setup key').toBeTruthy();

    // A genuinely correct code, straight from the real secret.
    await page.getByPlaceholder('123456').fill(totpCode(secret as string));
    await page.getByPlaceholder('Your current password').fill(user.password);
    await page.getByRole('button', { name: 'Verify & enable' }).click();

    // What SHOULD happen: recovery codes render, confirming activation.
    await expect(page.getByText('Save your recovery codes')).toBeVisible({ timeout: 10_000 });
});

test('logging in with MFA enabled completes via the code-entry step (fixes known bug #2442)', async ({ page }) => {
    // https://github.com/keyorixhq/keyorix/issues/2442 -- server/http/handlers/auth.go's
    // Login returns HTTP 200 with {mfa_required: true, mfa_challenge, ...} on
    // a correct password for an MFA account (no session cookie set).
    // authStore.login() now stores this as a pending mfaChallenge instead of
    // treating it as a completed session, LoginPage renders MfaChallengeForm
    // once mfaChallenge is set, and verifyMfa() calls the real VerifyMFA
    // endpoint with the challenge + code.

    // waitForFreshTotpCode below waits, by design, for the NEXT 30s TOTP step
    // (0..30s of wall time, uniform) so the login's code is not refused by the
    // per-account anti-replay counter that enableMfaViaApi's activation already
    // advanced. That wait plus setup plus the UI login does not fit the 30s
    // default test timeout (it timed out ~1/3 of runs, #2442 follow-up). Size the
    // budget for one full period plus setup and the UI steps; the anti-replay
    // behaviour itself is untouched.
    test.setTimeout(90_000);

    const user = await createDedicatedUser('mfalogin');
    const { secret: totpSecret, activatedStep } = await enableMfaViaApi(user.username, user.password);

    // See waitForFreshTotpCode's own comment: the activate call above and this
    // verify both draw from the same per-account anti-replay counter, and this
    // SPA's routing can make them only moments apart in wall-clock time.
    const verifyCode = await waitForFreshTotpCode(page, totpSecret, activatedStep);

    await page.goto('/login');
    await submitLogin(page, user.username, user.password);

    // The code-entry step for the pending MFA challenge.
    await expect(page.getByPlaceholder('123456')).toBeVisible({ timeout: 10_000 });
    await page.getByPlaceholder('123456').fill(verifyCode.code);
    await page.getByRole('button', { name: /verify/i }).click();
    await page.waitForURL('/dashboard', { timeout: 15_000 });
});
