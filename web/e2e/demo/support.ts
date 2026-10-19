// web/e2e/demo/support.ts -- shared setup for the demo-catalogue Playwright specs (DEMO-E2E-1).
//
// Deliberately NOT a *.spec.ts file: scripts/e2e/web-real-smoke.sh discovers specs with
// `find <dir> -maxdepth 1 -name '*.spec.ts'`, so this module never boots a server group of its own.
//
// These specs live in web/e2e/demo, not web/e2e/real, on purpose: the pull_request and merge_group
// job `web-e2e-real-smoke-shard` runs every spec under e2e/real. The demo journeys are slower (one
// waits for the anomaly detector's first pass) and guard the demo catalogue rather than the web/server
// contract, so they run through `make e2e-web-demo` in the full CI profile only. See the PR body.
//
// Everything here reuses the real suite's helpers (TOTP arithmetic, cookie-free Bearer login, the
// compliant-password generator) instead of copying them.
import { Browser, BrowserContext, Page, request as apiRequestFactory } from '@playwright/test';
import { ADMIN_PASSWORD, ADMIN_USERNAME, BACKEND_URL, apiLogin, realLogin, totpCode } from '../real/helpers';
import { compliantPassword, personalInfoCandidates } from '../real/support/password';

export { ADMIN_PASSWORD, ADMIN_USERNAME, BACKEND_URL, apiLogin, realLogin, totpCode };

const WEB_PORT = process.env.KEYORIX_E2E_WEB_PORT || '18190';
export const WEB_URL = `http://localhost:${WEB_PORT}`;

export const SEED_PROJECT_NAME = process.env.KEYORIX_E2E_PROJECT_NAME as string;
export const LOWPRIV_USERNAME = process.env.KEYORIX_E2E_LOWPRIV_USERNAME as string;
export const LOWPRIV_PASSWORD = process.env.KEYORIX_E2E_LOWPRIV_PASSWORD as string;

export interface Persona {
    username: string;
    password: string;
    id: number;
    displayName: string;
}

// bearer issues one request with a Bearer token from a brand-new, cookie-free context. A reused
// context would carry the session cookie of an earlier login and server/middleware/csrf.go would then
// demand a CSRF header on a state-changing call (see real/helpers.ts apiLogin's comment).
export async function bearer(
    token: string,
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    path: string,
    data?: unknown
): Promise<{ status: number; body: any }> {
    const ctx = await apiRequestFactory.newContext({ baseURL: BACKEND_URL });
    try {
        const res = await ctx.fetch(path, {
            method,
            headers: { Authorization: `Bearer ${token}` },
            ...(data === undefined ? {} : { data }),
        });
        let body: any = null;
        try {
            body = await res.json();
        } catch {
            body = null;
        }
        return { status: res.status(), body };
    } finally {
        await ctx.dispose();
    }
}

// mustBearer is bearer for SETUP: a refusal there is a broken fixture, not a result to assert on.
export async function mustBearer(
    token: string,
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    path: string,
    data?: unknown
) {
    const res = await bearer(token, method, path, data);
    if (res.status >= 300) throw new Error(`setup ${method} ${path} failed: ${res.status} ${JSON.stringify(res.body)}`);
    return res.body;
}

export interface SeedProject {
    id: number;
    // environment name -> id (development, production, staging are created with every project)
    environments: Record<string, number>;
    // secret name -> id of the fixture secrets scripts/e2e/web-real-smoke.sh seeds
    secrets: Record<string, number>;
}

// seedProject reads back the project web-real-smoke.sh seeds (its name is KEYORIX_E2E_PROJECT_NAME).
// Ids are server-assigned, so they are looked up, never assumed.
export async function seedProject(adminToken: string): Promise<SeedProject> {
    const projects = (await mustBearer(adminToken, 'GET', '/api/v1/projects')).data.projects as {
        id: number;
        name: string;
    }[];
    const project = projects.find((p) => p.name === SEED_PROJECT_NAME);
    if (!project) throw new Error(`seeded project ${SEED_PROJECT_NAME} not found among ${projects.map((p) => p.name)}`);
    const envs = (await mustBearer(adminToken, 'GET', `/api/v1/projects/${project.id}/environments`)).data
        .environments as { id: number; name: string }[];
    const secrets = (await mustBearer(adminToken, 'GET', `/api/v1/secrets?project_id=${project.id}`)).data.secrets as {
        id: number;
        name: string;
    }[];
    return {
        id: project.id,
        environments: Object.fromEntries(envs.map((e) => [e.name, e.id])),
        secrets: Object.fromEntries(secrets.map((s) => [s.name, s.id])),
    };
}

// createUser provisions a throwaway user through the admin API with a policy-compliant password
// (the same generator createDedicatedUser uses). It takes the admin's token instead of logging in
// again: every /auth/login spends one of the server's 10 logins per 15 minutes (web-real-smoke.sh).
export async function createUser(adminToken: string, prefix: string, label: string): Promise<Persona> {
    const stamp = Date.now();
    const username = `${prefix}${stamp}`;
    const email = `${username}@example.invalid`;
    const displayName = `${label} ${stamp}`;
    const password = compliantPassword(personalInfoCandidates({ username, email, displayName }));
    const body = await mustBearer(adminToken, 'POST', '/api/v1/users', {
        username,
        email,
        display_name: displayName,
        password,
    });
    return { username, password, id: body.data.id as number, displayName };
}

export async function addProjectMember(adminToken: string, projectId: number, userId: number, role: string) {
    await mustBearer(adminToken, 'POST', `/api/v1/projects/${projectId}/members`, { user_id: userId, role });
}

// newPersonaPage logs `who` in through the real login form in a context of its own, so two people
// can be on screen at once. The caller closes the contexts it collected in `contexts`.
export async function newPersonaPage(
    browser: Browser,
    who: { username: string; password: string },
    contexts: BrowserContext[]
): Promise<Page> {
    const ctx = await browser.newContext({ baseURL: WEB_URL, viewport: { width: 1280, height: 1400 } });
    contexts.push(ctx);
    const page = await ctx.newPage();
    await realLogin(page, who.username, who.password);
    return page;
}

// totpInSteps returns the TOTP code for the 30-second step `steps` after the current one.
//
// WHY THIS EXISTS (no timing sleeps): the server accepts a code from the current step and one step
// either side (validateTOTPStep: deltas 0, -1, +1) and refuses any step it has already accepted for
// that account (MarkTOTPStepUsed: strictly increasing). real/helpers.ts's waitForFreshTotpCode polls
// the wall clock until the NEXT step arrives (up to 30 s of waiting). A code for the step AFTER
// "now" is valid immediately (delta +1, or delta 0/-1 if the step has rolled over in the meantime)
// and is strictly newer than the step an earlier code in the same test used, so no wait is needed:
// enrol with totpInSteps(secret, 0), then log in with totpInSteps(secret, 1). Compute it at the moment
// of use, never earlier, so the +1 window is measured from the submit.
export function totpInSteps(secret: string, steps: number): string {
    return totpCode(secret, Date.now() / 1000 + steps * 30);
}

// openAuditFor loads /audit and returns once the feed has rendered. The audit page loads its feed
// once per visit, so a spec that needs a just-written event to be listed wraps this and the
// assertion in expect(...).toPass() and goes to the page again on each attempt.
export async function openAudit(page: Page) {
    await page.goto('/audit');
    await page.getByPlaceholder('Filter by actor…').waitFor();
}
