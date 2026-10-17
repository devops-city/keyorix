// web/e2e/demo/05-audit-search.spec.ts -- DEMO-E2E-1 journey 5 of 8: "what did that person just do?"
// The demo's audit act: take a handful of actions, then find exactly those actions in the audit log by
// actor and by event type, in the console and through the search API.
//
// WHAT IT GUARDS:
//   1. every action just taken is listed, with the right event name: Created, Rotated, Rolled back,
//      Shared, Deleted -- each on THIS secret;
//   2. the actor filter narrows to the person, and a filter that matches nobody shows nothing (the
//      negative control: a search that returns everything for every input would pass step 1);
//   3. the event-type filter narrows to one kind of event;
//   4. GET /api/v1/audit/search, the server-side query behind the same facts, returns the action asked
//      for (filtered by action: its secret_id parameter is not a filter, so this server's one rotation
//      is identified by the action and checked by its description).
//
// The actions are taken through the API with the admin's token: this journey is about FINDING them, and
// the UI that takes them (create/rotate/rollback, share) is driven by journeys 2 and 3. Every row below
// is matched on this run's unique secret name, so rows from other journeys' work cannot satisfy it.
//
// LOGIN BUDGET: harness 1 + admin API 1 + admin UI 1 = 3 of 10.
import { test, expect, Page } from '@playwright/test';
import {
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    LOWPRIV_USERNAME,
    apiLogin,
    bearer,
    mustBearer,
    openAudit,
    realLogin,
    seedProject,
} from './support';

test('the audit log finds the actions just taken, by actor and by event type', async ({ page }) => {
    test.setTimeout(90_000);
    const stamp = Date.now();
    const secretName = `demo-audit-${stamp}`;

    // ── Take the actions ────────────────────────────────────────────────────
    const adminToken = await apiLogin(ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
    const project = await seedProject(adminToken);
    const secretId = (
        await mustBearer(adminToken, 'POST', '/api/v1/secrets', {
            name: secretName,
            value: `first-${stamp}`,
            type: 'text',
            project_id: project.id,
            environment_id: project.environments['development'],
        })
    ).data.id as number;
    await mustBearer(adminToken, 'POST', `/api/v1/secrets/${secretId}/rotate`, { new_value: `second-${stamp}` });
    await mustBearer(adminToken, 'POST', `/api/v1/secrets/${secretId}/rollback`, { version: 1 });
    const users = (await mustBearer(adminToken, 'GET', '/api/v1/users?page_size=100')).data;
    const recipientId = (users.users ?? users.data).find(
        (u: { username: string }) => u.username === LOWPRIV_USERNAME
    ).id;
    await mustBearer(adminToken, 'POST', `/api/v1/secrets/${secretId}/share`, {
        recipient_id: recipientId,
        is_group: false,
        permission: 'read',
    });
    expect((await bearer(adminToken, 'DELETE', `/api/v1/secrets/${secretId}`)).status).toBe(204);

    // ── Find them in the console ────────────────────────────────────────────
    await realLogin(page, ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
    const rowsFor = (p: Page) => p.getByRole('row').filter({ hasText: secretName });

    await expect(async () => {
        await openAudit(page);
        await page.getByPlaceholder('Filter by actor…').fill(ADMIN_USERNAME as string);
        await expect(rowsFor(page)).toHaveCount(5, { timeout: 5_000 });
    }).toPass({ timeout: 60_000 });

    // Each action, named as the log names it (labels from web/src/utils/eventLabels.ts, descriptions as
    // the server writes them).
    // The badge text is matched exactly: a substring "Created" would also match the share's own
    // humanised event name.
    for (const label of ['Created', 'Rotated', 'Rolled back', 'Deleted']) {
        await expect(rowsFor(page).filter({ has: page.getByText(label, { exact: true }) })).toHaveCount(1);
    }
    await expect(rowsFor(page).filter({ hasText: `Shared secret ${secretId} ("${secretName}")` })).toHaveCount(1);

    // The actor filter is a filter: someone else did none of this.
    await page.getByPlaceholder('Filter by actor…').fill(`nobody-${stamp}`);
    await expect(rowsFor(page)).toHaveCount(0);
    await page.getByPlaceholder('Filter by actor…').fill(ADMIN_USERNAME as string);
    await expect(rowsFor(page)).toHaveCount(5);

    // The event-type filter narrows to one kind.
    await page.getByLabel('Filter by event type').selectOption({ label: 'Rotated' });
    await expect(rowsFor(page)).toHaveCount(1);
    await expect(rowsFor(page).first()).toContainText(`rotated secret ${secretName}`);
    await page.getByLabel('Filter by event type').selectOption({ label: 'All event types' });
    await expect(rowsFor(page)).toHaveCount(5);

    // ── And through the server-side search ──────────────────────────────────
    const found = await bearer(adminToken, 'GET', `/api/v1/audit/search?action=secret.rotated`);
    expect(found.status).toBe(200);
    const events = found.body.data.events as { event_type: string; actor: string; description: string }[];
    expect(events.length, 'search by action must return the one rotation this server has seen').toBe(1);
    expect(events[0]?.event_type).toBe('secret.rotated');
    expect(events[0]?.actor).toBe(ADMIN_USERNAME);
    expect(events[0]?.description).toContain(secretName);
});
