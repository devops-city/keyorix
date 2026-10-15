// web/e2e/real/audit-load-more.spec.ts — AUDIT-LIST-KEYSET-1: the Audit Log
// page pages by cursor (docs/specs/audit-list-keyset.md). The first 100
// events load at once, and "Load more" appends the next page after the last
// loaded row until the server reports no further page, when the button goes
// away. Real backend (scripts/e2e/web-real-smoke.sh), no mocked routes.
import { test, expect, request as apiRequestFactory } from '@playwright/test';
import { ADMIN_USERNAME, ADMIN_PASSWORD, BACKEND_URL, apiLogin, realLogin } from './helpers';

// More events than one page (100) and fewer than the 10,000 the total is
// exact up to, so the whole log can be walked to its end.
const MIN_EVENTS = 130;

test('the audit log appends older events with "Load more" until the end', async ({ page }) => {
    test.setTimeout(120_000);
    const token = await apiLogin(ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
    // Cookie-free Bearer context (see apiLogin's comment on CSRF).
    const api = await apiRequestFactory.newContext({
        baseURL: BACKEND_URL,
        extraHTTPHeaders: { Authorization: `Bearer ${token}` },
    });
    try {
        const auditTotal = async (): Promise<number> => {
            const res = await api.get('/api/v1/audit/logs?page_size=1');
            expect(res.ok()).toBeTruthy();
            return (await res.json()).data.total as number;
        };
        // Top the log up with reads of a seeded secret (each read writes one
        // secret.read event, asynchronously) if this run has not produced
        // enough events yet.
        let total = await auditTotal();
        if (total < MIN_EVENTS) {
            const list = await api.get('/api/v1/secrets');
            expect(list.ok()).toBeTruthy();
            const body = await list.json();
            const secrets = (body.data?.secrets ?? []) as { id: number }[];
            expect(secrets.length).toBeGreaterThan(0);
            for (let i = total; i < MIN_EVENTS; i++) {
                const read = await api.get(`/api/v1/secrets/${secrets[0].id}?include_value=true`);
                expect(read.status()).toBe(200);
            }
            await expect.poll(auditTotal, { timeout: 15_000 }).toBeGreaterThanOrEqual(MIN_EVENTS);
            total = await auditTotal();
        }

        await realLogin(page, ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
        await page.goto('/audit');
        const count = page.getByTestId('audit-loaded-count');
        const rows = page.locator('table tbody tr');
        await expect(count).toContainText('Showing 100 of', { timeout: 15_000 });
        await expect(rows).toHaveCount(100);

        const loadMore = page.getByRole('button', { name: 'Load more' });
        await loadMore.click();
        await expect(rows).not.toHaveCount(100, { timeout: 15_000 });
        expect(await rows.count()).toBeGreaterThan(100);

        // Walk to the end: the button disappears once next_cursor is null, and
        // by then every event is on the page exactly once.
        for (let i = 0; i < 200 && (await loadMore.isVisible()); i++) {
            const before = await rows.count();
            await loadMore.click();
            await expect.poll(() => rows.count(), { timeout: 15_000 }).toBeGreaterThan(before);
        }
        await expect(loadMore).toBeHidden();
        const loaded = await rows.count();
        // The page shows newer events than the total read before the walk
        // (this session's own login and page loads add some), never fewer.
        expect(loaded).toBeGreaterThanOrEqual(total);
        await expect(count).toContainText(`Showing ${loaded.toLocaleString('en-US')} of`);
    } finally {
        await api.dispose();
    }
});
