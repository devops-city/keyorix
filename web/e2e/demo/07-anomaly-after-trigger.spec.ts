// e2e-server: anomaly_schedule=15s
//
// web/e2e/demo/07-anomaly-after-trigger.spec.ts -- DEMO-E2E-1 journey 7 of 8: "someone starts reading
// everything". The demo's anomaly act: one person reads five secrets they have never touched, and the
// detector's alert appears in the console, naming them.
//
// The first line of this file is read by scripts/e2e/web-real-smoke.sh: the group that runs this file
// boots with `anomaly_alerts.schedule: 15s`. The detection pass is hourly by default, which no browser
// test can wait for. The detector's scan window is floored at one hour whatever the cadence, so the short
// schedule changes only how soon a pass happens, never what it looks at. The FIRST pass is deferred a
// minute plus up to one interval of jitter after the server starts (server/scheduler_run.go), so this
// journey is the slowest of the eight: it waits for the alert by polling the page, not by sleeping.
//
// THE TRIGGER. The demo's trigger script (scripts/demo/trigger-anomaly.sh, `bulk-read`; DEMO-LOCAL-2,
// #3342) does exactly this through the API: one principal, five never-read secrets. That script is not on
// main yet, so the same trigger is made here, inline, with the seeded project's five secrets. When #3342
// lands this can call the script instead; the assertions stay as they are.
//
// WHAT IT GUARDS:
//   1. before the trigger there is no alert for the actor (the calm control);
//   2. after it, the console's Audit -> Anomaly Alerts tab lists a "Principal Breadth" alert for THAT
//      actor, medium severity (5 secrets: the threshold is 5, high starts at 10), and expanding it shows
//      the description "<actor> accessed 5 distinct secrets ...";
//   3. the detection is also written to the audit trail (security.anomaly_detected).
//
// The actor is a fresh project_viewer, so the alert can only come from this journey's reads and is
// matched on a name nothing else uses.
//
// LOGIN BUDGET: harness 1 + admin API 1 + actor API 1 + admin UI 1 = 4 of 10.
import { test, expect } from '@playwright/test';
import {
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    addProjectMember,
    apiLogin,
    bearer,
    createUser,
    mustBearer,
    realLogin,
    seedProject,
} from './support';

test('five first-ever reads by one person raise a Principal Breadth alert in the console', async ({ page }) => {
    test.setTimeout(300_000);

    const adminToken = await apiLogin(ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
    const project = await seedProject(adminToken);
    const actor = await createUser(adminToken, 'demoanom', 'Demo Anomaly Actor');
    await addProjectMember(adminToken, project.id, actor.id, 'project_viewer');
    const actorToken = await apiLogin(actor.username, actor.password);

    const alertsFor = async () => {
        const res = await bearer(adminToken, 'GET', '/api/v1/audit/anomalies');
        expect(res.status).toBe(200);
        return (res.body.data.alerts as { AlertType: string; AccessedBy: string; Severity: string }[]).filter(
            (a) => a.AccessedBy === actor.username
        );
    };

    // 1. Calm: nothing is flagged for this person yet.
    expect(await alertsFor()).toEqual([]);

    // The trigger: this person reads every secret the project holds, none of which they have read before.
    const secretIds = Object.values(project.secrets);
    expect(secretIds.length, 'the seeded project must hold the five fixture secrets').toBeGreaterThanOrEqual(5);
    for (const id of secretIds) {
        const read = await bearer(actorToken, 'GET', `/api/v1/secrets/${id}?include_value=true`);
        expect(read.status, `reading secret ${id} as ${actor.username}`).toBe(200);
    }

    // 2. The console shows it. The page loads the alert list once per visit, so go back to it until the
    //    detector has run (first pass: ~1-1.5 minutes after the server started).
    await realLogin(page, ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
    const alertRow = () =>
        page.getByRole('row').filter({ hasText: 'Principal Breadth' }).filter({ hasText: actor.username });
    await expect(async () => {
        await page.goto('/audit?tab=anomalies');
        await expect(alertRow()).toBeVisible({ timeout: 5_000 });
    }).toPass({ timeout: 200_000, intervals: [5_000] });

    await expect(alertRow().getByText('medium', { exact: true })).toBeVisible();
    await alertRow().click();
    await expect(page.getByText(`${actor.username} accessed ${secretIds.length} distinct secrets`)).toBeVisible();

    // The API agrees: one breadth alert for the actor, medium (5 secrets; high starts at 10).
    const breadth = (await alertsFor()).filter((a) => a.AlertType === 'principal_breadth');
    expect(breadth.map((a) => a.Severity)).toEqual([secretIds.length >= 10 ? 'high' : 'medium']);

    // 3. The detection is in the audit trail too.
    await expect
        .poll(
            async () => {
                const logs = await mustBearer(
                    adminToken,
                    'GET',
                    '/api/v1/audit/search?action=security.anomaly_detected&page_size=100'
                );
                return (logs.data.events as { description: string }[]).some(
                    (e) => e.description.includes('principal_breadth') && e.description.includes(actor.username)
                );
            },
            { timeout: 30_000, intervals: [1_000] }
        )
        .toBe(true);
});
