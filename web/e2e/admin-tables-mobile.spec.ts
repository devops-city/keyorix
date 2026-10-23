// DEMO-WALK-4 finding 3: on a 390 px phone the Groups table had no reachable
// Actions column and the Secrets row actions sat off-screen. The Actions column is
// now pinned (sticky right-0) inside the sideways-scrolling card; this checks the
// action buttons are inside the viewport without any scrolling by the user.
// With KEYORIX_E2E_SHOT_DIR set it also writes screenshots (before/after for the PR).
import { test, expect, Page, Locator } from '@playwright/test';
import { mockApiCatchAll, mockAuthenticated, mockSecretsList } from './mocks';

test.use({ viewport: { width: 390, height: 844 }, hasTouch: true });

async function shot(page: Page, name: string) {
    const dir = process.env.KEYORIX_E2E_SHOT_DIR;
    if (dir) await page.screenshot({ path: `${dir}/${name}.png` });
}

async function expectInViewport(page: Page, target: Locator) {
    await expect(target).toBeVisible();
    const box = await target.boundingBox();
    const vp = page.viewportSize();
    expect(box, 'element has a box').not.toBeNull();
    expect(box!.x).toBeGreaterThanOrEqual(0);
    expect(box!.x + box!.width).toBeLessThanOrEqual(vp!.width);
}

test.describe('admin tables at 390 px', () => {
    test.beforeEach(async ({ page }) => {
        await mockApiCatchAll(page);
        await mockAuthenticated(page);
    });

    test('Groups: Manage roles, Edit and Delete are reachable', async ({ page }) => {
        await page.route(/\/api\/v1\/groups(\?.*)?$/, (route) =>
            route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({
                    data: {
                        groups: [
                            {
                                id: 1,
                                name: 'platform-team',
                                description: 'Platform infrastructure engineers and on-call rotation',
                                member_count: 5,
                                created_at: '2026-01-01T00:00:00Z',
                            },
                        ],
                        total: 1,
                    },
                    message: '',
                    success: true,
                }),
            })
        );
        await page.goto('/admin/groups');
        await expect(page.getByText('platform-team')).toBeVisible();
        await shot(page, 'groups-390');
        for (const title of ['Manage roles', 'Edit group', 'Delete group']) {
            await expectInViewport(page, page.getByTitle(title));
        }
        // and the page itself does not scroll sideways
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
        expect(overflow).toBeLessThanOrEqual(0);
        // the pinned button is really clickable (nothing overlaps it)
        await page.getByTitle('Edit group').click();
        await expect(page.getByRole('dialog')).toBeVisible();
    });

    test('Secrets: row actions are reachable', async ({ page }) => {
        await mockSecretsList(page, [
            {
                id: 1,
                name: 'prod-database-password',
                type: 'password',
                environment_name: 'production',
                status: 'active',
            },
        ]);
        await page.goto('/secrets');
        const row = page.getByRole('row', { name: /prod-database-password/ });
        await expect(row).toBeVisible();
        await shot(page, 'secrets-390');
        const actions = row.locator('td').last().getByRole('button');
        expect(await actions.count()).toBeGreaterThan(0);
        for (let i = 0; i < (await actions.count()); i++) {
            await expectInViewport(page, actions.nth(i));
        }
    });
});
