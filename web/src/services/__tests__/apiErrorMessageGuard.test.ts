// apiErrorMessageGuard.test.ts — SHARE-2's guard for the "raw axios text in a dialog"
// class. A dialog that renders `mutation.error instanceof Error ? mutation.error.message : ...`
// shows axios's own "Request failed with status code 403" for a refused request, and
// the server's reason (`message` in the error body) is lost. The Edit Secret dialog did
// exactly that; 12 sibling alerts in 6 files had the same shape. They now call
// apiErrorMessage (services/client.ts), which prefers the server's reason.
//
// What this recognises: the ternary `<expr>.error instanceof Error ? <expr>.error.message`
// with the same <expr> on both sides, across line breaks, in any non-test .ts/.tsx file
// under src/. That is every shape the 13 fixed sites used. It does NOT recognise a
// renamed local (`const e = m.error; e instanceof Error ? e.message`), or `String(err)`;
// those can still leak axios text and would need their own rule.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const SRC = resolve(import.meta.dirname, '../..');
const RAW_ERROR_MESSAGE = /([\w.]+)\.error\s+instanceof\s+Error\s*\?\s*\1\.error\.message/g;

const sourceFiles = (dir: string): string[] =>
    readdirSync(dir).flatMap((name) => {
        const path = join(dir, name);
        if (statSync(path).isDirectory()) {
            return name === '__tests__' || name === 'test' ? [] : sourceFiles(path);
        }
        return /\.tsx?$/.test(name) && !/\.test\.tsx?$/.test(name) ? [path] : [];
    });

describe('mutation errors are shown with apiErrorMessage (SHARE-2)', () => {
    it('scans a real tree (not vacuous)', () => {
        const files = sourceFiles(SRC);
        expect(files.length).toBeGreaterThan(100);
        expect(files.some((f) => f.endsWith('pages/projects/ProjectSecretsTab.tsx'))).toBe(true);
    });

    it('recognises the shape it guards against', () => {
        const sample = `message={list.editMutation.error instanceof Error\n ? list.editMutation.error.message : 'x'}`;
        expect(sample.match(RAW_ERROR_MESSAGE)).toHaveLength(1);
        expect(`apiErrorMessage(list.editMutation.error, 'x')`.match(RAW_ERROR_MESSAGE)).toBeNull();
    });

    it('no dialog renders `x.error instanceof Error ? x.error.message`', () => {
        const offenders = sourceFiles(SRC).flatMap((file) =>
            [...readFileSync(file, 'utf8').matchAll(RAW_ERROR_MESSAGE)].map(
                (m) =>
                    `${relative(SRC, file)}: ${m[0].replace(/\s+/g, ' ')} -> use apiErrorMessage(${m[1]}.error, fallback)`
            )
        );
        expect(offenders).toEqual([]);
    });
});
