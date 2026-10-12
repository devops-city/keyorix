// Self-test for check-api-contract.mjs's matching logic -- a permanent
// regression guard for the checker itself, run under vitest. The real
// contract check (package.json's check:api-contract) runs against actual
// service files and the real spec; this file instead feeds the checker a
// deliberately-wrong synthetic call site, proving the mechanism works
// before it's ever pointed at real code.
import { describe, it, expect } from 'vitest';
import {
    loadSpecOperations,
    findOperation,
    extractCallSites,
    evaluate,
    siteKey,
    KNOWN_VIOLATIONS,
} from './check-api-contract.mjs';

describe('check-api-contract', () => {
    const operations = loadSpecOperations();

    it('loads at least one real operation from openapi.yaml', () => {
        expect(operations.length).toBeGreaterThan(0);
        expect(operations.some((op) => op.operationId === 'authLogin')).toBe(true);
    });

    it('RED: a deliberately wrong path does not match any real operation', () => {
        const fixture = `
            import { apiClient } from './client';
            export const bogusApi = {
                async doThing() {
                    await apiClient.post('/api/v1/this-endpoint-does-not-exist', { x: 1 });
                },
            };
        `;
        const [site] = extractCallSites('fixture.ts', fixture);
        expect(site.method).toBe('POST');
        expect(site.path.template).toBe('/api/v1/this-endpoint-does-not-exist');

        const segments = site.path.template.split('/').filter(Boolean);
        const op = findOperation(operations, site.method, segments);
        expect(op).toBeUndefined(); // the violation this checker exists to catch
    });

    it('GREEN: a real path + method resolves to its real operation', () => {
        const fixture = `
            import { apiClient } from './client';
            export const realApi = {
                async login(username, password) {
                    await apiClient.post('/auth/login', { username, password });
                },
            };
        `;
        const [site] = extractCallSites('fixture.ts', fixture);
        const segments = site.path.template.split('/').filter(Boolean);
        const op = findOperation(operations, site.method, segments);
        expect(op).toBeDefined();
        expect(op.operationId).toBe('authLogin');
    });

    it('a dynamic path segment ("${id}") matches a spec {param} segment', () => {
        const fixture = `
            import { apiClient } from './client';
            export const realApi = {
                async getProject(id) {
                    return apiClient.get(\`/api/v1/projects/\${id}\`);
                },
            };
        `;
        const [site] = extractCallSites('fixture.ts', fixture);
        expect(site.path.template).toBe('/api/v1/projects/{dyn}');
        const segments = site.path.template.split('/').filter(Boolean);
        const op = findOperation(operations, site.method, segments);
        expect(op).toBeDefined();
        expect(op.operationId).toBe('getProject');
    });

    it('a query-string ternary interpolation is dropped, not treated as a path segment', () => {
        const fixture = `
            import { apiClient } from './client';
            export const realApi = {
                async list(includeDeleted) {
                    return apiClient.get(\`/api/v1/projects\${includeDeleted ? '?include_deleted=true' : ''}\`);
                },
            };
        `;
        const [site] = extractCallSites('fixture.ts', fixture);
        expect(site.path.template).toBe('/api/v1/projects');
    });

    it('a required field missing from an inline object-literal body is a violation', () => {
        const fixture = `
            import { apiClient } from './client';
            export const bogusApi = {
                async createProject(name) {
                    await apiClient.post('/api/v1/projects', {});
                },
            };
        `;
        const [site] = extractCallSites('fixture.ts', fixture);
        const segments = site.path.template.split('/').filter(Boolean);
        const op = findOperation(operations, site.method, segments);
        expect(op.operationId).toBe('createProject');
        expect(op.required).toContain('name');
        expect(site.body.keys.has('name')).toBe(false); // the violation
    });

    it('a spread body argument is reported unresolved, not falsely assumed complete', () => {
        const fixture = `
            import { apiClient } from './client';
            export const realApi = {
                async createProject(payload) {
                    await apiClient.post('/api/v1/projects', { ...payload });
                },
            };
        `;
        const [site] = extractCallSites('fixture.ts', fixture);
        expect(site.body.unresolved).toBe(true);
    });

    it('a DELETE with a config.data body unwraps data for the required-fields check', () => {
        const fixture = `
            import { apiClient } from './client';
            export const realApi = {
                async liftLegalHold(reason) {
                    await apiClient.delete('/api/v1/legal-hold', { data: { reason } });
                },
            };
        `;
        const [site] = extractCallSites('fixture.ts', fixture);
        expect(site.body.keys.has('reason')).toBe(true);
    });

    describe('KNOWN_VIOLATIONS keys are stable call-site identities, not line numbers', () => {
        const gapCall = `
            import { apiClient } from './client';
            export const gapApi = {
                async doThing(id) {
                    return apiClient.post(\`/api/v1/not-in-spec/\${id}/thing\`, {});
                },
            };
        `;
        const KEY = 'gap.ts POST /api/v1/not-in-spec/{dyn}/thing';
        const entry = { issue: 'TEST-1', reason: 'fixture gap' };
        const run = (source, known) =>
            evaluate([{ baseName: 'gap.ts', sites: extractCallSites('gap.ts', source) }], operations, known);

        it('every real entry is keyed \`<file> <METHOD> <path>\`, never file:LINE', () => {
            for (const key of Object.keys(KNOWN_VIOLATIONS)) {
                expect(key).toMatch(/^[A-Za-z0-9_]+\.ts (GET|POST|PUT|PATCH|DELETE) \/\S+$/);
            }
        });

        it('siteKey is file + method + path template', () => {
            const [site] = extractCallSites('gap.ts', gapCall);
            expect(siteKey('gap.ts', site)).toBe(KEY);
        });

        it('RED: a new call to an undocumented path that is not listed fails', () => {
            const r = run(gapCall, {});
            expect(r.failures).toHaveLength(1);
            expect(r.failures[0]).toContain(KEY);
        });

        it('GREEN: the same call, once listed under its stable key, is tolerated', () => {
            const r = run(gapCall, { [KEY]: entry });
            expect(r.failures).toEqual([]);
            expect(r.logs).toHaveLength(1);
        });

        it('moving the call down (lines added above it) changes nothing', () => {
            const moved =
                '// a\n// b\n// c\n' +
                gapCall.replace('export const gapApi', 'const unrelated = 1;\n\nexport const gapApi');
            const before = run(gapCall, { [KEY]: entry });
            const after = run(moved, { [KEY]: entry });
            expect(extractCallSites('gap.ts', moved)[0].line).not.toBe(extractCallSites('gap.ts', gapCall)[0].line);
            expect(after.failures).toEqual(before.failures);
            expect(after.failures).toEqual([]);
        });

        it('a stale entry (no violating call left) still fails', () => {
            const r = run('export const x = 1;', { [KEY]: entry });
            expect(r.failures).toHaveLength(1);
            expect(r.failures[0]).toContain('no longer reproduces');
        });

        it('a SECOND call to the same file+method+path is a new call site and still fails', () => {
            const twice = gapCall.replace(
                '},\n            };',
                '},\n                async again(id) {\n                    return apiClient.post(\`/api/v1/not-in-spec/\${id}/thing\`, {});\n                },\n            };'
            );
            expect(extractCallSites('gap.ts', twice)).toHaveLength(2);
            const r = run(twice, { [KEY]: entry });
            expect(r.failures).toHaveLength(1);
            expect(r.failures[0]).toContain('more call sites than');
        });

        it('a different method or path under the same file is not covered by the entry', () => {
            const other = gapCall.replace('apiClient.post', 'apiClient.put');
            const r = run(other, { [KEY]: entry });
            // the PUT call is unlisted (fails) AND the POST entry is stale (fails)
            expect(r.failures).toHaveLength(2);
        });
    });
});
