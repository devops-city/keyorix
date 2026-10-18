// INV-WEB-no-native-confirm (#3153): no native confirm() dialog in web/src. The browser's confirm() is
// unthemed, blocks the event loop, and is invisible to anything that does not drive a real
// browser dialog; destructive actions use the in-app dialog (components/ui/useConfirm).
//
// Parsed with the TypeScript compiler API over every non-test .ts/.tsx file under src/.
// Shapes recognised:
//   - a bare call `confirm(...)`
//   - a call or reference through a global object: `window.confirm`, `globalThis.confirm`,
//     `self.confirm`, `top.confirm`, `parent.confirm` (property or ['confirm'] access, so
//     `const c = window.confirm` and `window.confirm.bind(window)` are caught too)
// Not recognised (this test does not see them): indirection through another binding
// (`const w = window; w.confirm()`), `eval`/`Function` string code, a native confirm used by
// code outside src/ (e2e helpers, index.html), and the sibling native dialogs
// `alert()`/`prompt()`, which are out of scope for this guard. A local variable that happens
// to be named `confirm` and is only read (e.g. a form field) is not flagged; calling it is.
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import ts from 'typescript';
import { describe, expect, it } from 'vitest';

const webRoot = resolve(import.meta.dirname, '../../..');
const srcRoot = join(webRoot, 'src');

const GLOBAL_OBJECTS = new Set(['window', 'globalThis', 'self', 'top', 'parent']);

const isTestFile = (rel: string) =>
    /\.test\.tsx?$/.test(rel) || rel.split('/').includes('__tests__') || rel.startsWith('src/test/');

function sourceFiles(dir: string): string[] {
    const out: string[] = [];
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, entry.name);
        if (entry.isDirectory()) {
            out.push(...sourceFiles(full));
        } else if (/\.tsx?$/.test(entry.name) && !entry.name.endsWith('.d.ts')) {
            const rel = relative(webRoot, full).split('\\').join('/');
            if (!isTestFile(rel)) out.push(rel);
        }
    }
    return out;
}

function findNativeConfirms(fileName: string, text: string): string[] {
    const sf = ts.createSourceFile(
        fileName,
        text,
        ts.ScriptTarget.Latest,
        true,
        fileName.endsWith('x') ? ts.ScriptKind.TSX : ts.ScriptKind.TS
    );
    const hits: string[] = [];
    const at = (n: ts.Node, what: string) => {
        const { line } = sf.getLineAndCharacterOfPosition(n.getStart(sf));
        hits.push(`${fileName}:${line + 1}: ${what}`);
    };
    const visit = (n: ts.Node) => {
        if (ts.isCallExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === 'confirm') {
            at(n, `bare confirm(): ${n.getText(sf)}`);
        } else if (
            ts.isPropertyAccessExpression(n) &&
            n.name.text === 'confirm' &&
            ts.isIdentifier(n.expression) &&
            GLOBAL_OBJECTS.has(n.expression.text)
        ) {
            at(n, `${n.expression.text}.confirm`);
        } else if (
            ts.isElementAccessExpression(n) &&
            ts.isStringLiteralLike(n.argumentExpression) &&
            n.argumentExpression.text === 'confirm' &&
            ts.isIdentifier(n.expression) &&
            GLOBAL_OBJECTS.has(n.expression.text)
        ) {
            at(n, `${n.expression.text}['confirm']`);
        }
        ts.forEachChild(n, visit);
    };
    visit(sf);
    return hits;
}

describe('INV-WEB-no-native-confirm: no native confirm() in web/src', () => {
    const files = sourceFiles(srcRoot);

    it('the sweep actually saw the tree (non-vacuity)', () => {
        expect(files.length).toBeGreaterThan(100);
        expect(files).toContain('src/App.tsx');
        // The shared replacement lives in the swept tree and is itself clean.
        expect(files).toContain('src/components/ui/useConfirm.tsx');
    });

    it('no non-test file calls or references a native confirm', () => {
        const violations = files.flatMap((f) => findNativeConfirms(f, readFileSync(join(webRoot, f), 'utf8')));
        expect(violations).toEqual([]);
    });

    // Calibration: each recognised shape is flagged, and the deliberately-allowed shapes
    // are not — proven in-tree, not only on a scratch branch.
    it.each([
        ['window.confirm call', `if (!window.confirm('Sure?')) return;`],
        ['bare call', `if (!confirm('Sure?')) return;`],
        ['globalThis', `globalThis.confirm('x');`],
        ['self', `self.confirm('x');`],
        ['aliased reference', `const ask = window.confirm;`],
        ['bound reference', `const ask = window.confirm.bind(window);`],
        ['element access', `window['confirm']('x');`],
        ['tsx handler', `const el = <button onClick={() => confirm('x') && go()} />;`],
    ])('flags %s', (_name, code) => {
        expect(findNativeConfirms('x.tsx', code)).not.toEqual([]);
    });

    it.each([
        ['in-app hook', `const ok = await requestConfirm({ message: 'Sure?' });`],
        ['form field named confirm', `const [confirm, setConfirm] = useState(''); if (next !== confirm) return;`],
        ['property of another object', `dialog.confirm('x'); options.confirm = 1;`],
        ['string mention', `const s = "window.confirm is not used";`],
        ['onConfirm prop', `<Dialog onConfirm={() => run()} />`],
    ])('allows %s', (_name, code) => {
        expect(findNativeConfirms('x.tsx', code)).toEqual([]);
    });
});
