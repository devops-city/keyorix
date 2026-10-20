// INV-WEB-dialog-contrast (#3153, WEB-PILOT-POLISH-2): the title and message of every modal/dialog
// surface in web/src are readable (WCAG AA, 4.5:1) on the surface they sit on, in BOTH themes.
// #3153's revoke dialog drew a dark title on the dark dialog surface; components/ui/__tests__/
// dialogContrast.test.tsx pins the shared Dialog's tokens. This guard widens that to the tree.
//
// Three parts:
//  1. Inventory (static, over every non-test .ts/.tsx): a file that implements a dialog surface
//     (Radix Dialog import, aria-modal / <dialog> / role="dialog", or a fixed inset-0 z-40/50
//     overlay) must be listed in SURFACES, audited or exempt with a reason. A new dialog that is
//     not listed fails here, so it cannot ship unchecked. Every `<Modal>` in the tree must carry
//     a `title` (rendered by Modal, audited below) or say hideTitleVisually.
//  2. Render audit: each audited surface is rendered and its visible title/message elements are
//     resolved to a colour and a background (test/contrast.ts) in light and dark.
//  3. Calibration: planted dialogs (title colour equal to its background, the #3153 fixed-dark
//     title, an unknown palette class) must make the same audit fail.
// Not covered: text other than titles/messages/search input (button labels, the session
// countdown), icon badges, hover/focus states, and any colour a page applies on top of a dialog
// from outside the dialog components. Sidebar's drawer title is sr-only and NotificationBell's
// overlay is a click-catcher, both exempt below.
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import React from 'react';
import ts from 'typescript';
import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '../../test/test-utils';
import { contrastViolations, isSrOnly, UnresolvableColour, contrastOf, type Theme } from '../../test/contrast';
import { Modal } from '../../components/ui/Modal';
import { Dialog } from '../../components/ui/Dialog';
import { useConfirm } from '../../components/ui/useConfirm';
import { SessionTimeoutWarning } from '../../components/ui/SessionTimeoutWarning';
import { CmdKSearch } from '../../components/ui/CmdKSearch';

vi.mock('../../features/auth', () => ({
    useAuth: () => ({
        isAuthenticated: true,
        sessionTimeLeftMs: 90_000,
        logout: vi.fn(),
        refreshToken: vi.fn(),
    }),
}));
// A stable array: CmdKSearch re-runs an effect when `projects` changes identity.
const noProjects = vi.hoisted(() => [] as unknown[]);
vi.mock('../../features/projects/api', () => ({ useProjects: () => ({ data: noProjects }) }));

const THEMES: Theme[] = ['light', 'dark'];
const webRoot = resolve(import.meta.dirname, '../../..');
const srcRoot = join(webRoot, 'src');

// ---- 1. inventory ---------------------------------------------------------------------------

type Surface = { audited: true; how: string } | { audited: false; reason: string };

const SURFACES: Record<string, Surface> = {
    'src/components/ui/Modal.tsx': { audited: true, how: 'Modal title, and Dialog/useConfirm built on it' },
    'src/components/ui/SessionTimeoutWarning.tsx': { audited: true, how: 'Session Expiring title + message' },
    'src/components/ui/CmdKSearch.tsx': { audited: true, how: 'search input text on the palette surface' },
    'src/components/layout/Sidebar.tsx': {
        audited: false,
        reason: 'mobile drawer: its Dialog.Title is sr-only ("Navigation menu"), no visible title',
    },
    'src/features/notifications/NotificationBell.tsx': {
        audited: false,
        reason: 'not a dialog: a transparent fixed inset-0 click-catcher behind a popover',
    },
};
// Built on Modal: no surface of their own, audited through it. Checked to still be Modal users.
const DERIVED = ['src/components/ui/Dialog.tsx', 'src/components/ui/useConfirm.tsx'];

const isTestFile = (rel: string) =>
    /\.test\.tsx?$/.test(rel) || rel.split('/').includes('__tests__') || rel.startsWith('src/test/');

function sourceFiles(dir: string): string[] {
    const out: string[] = [];
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, entry.name);
        if (entry.isDirectory()) out.push(...sourceFiles(full));
        else if (/\.tsx?$/.test(entry.name) && !entry.name.endsWith('.d.ts')) {
            const rel = relative(webRoot, full).split('\\').join('/');
            if (!isTestFile(rel)) out.push(rel);
        }
    }
    return out;
}

/** Shapes that make a file a dialog surface. See the header: this list is what "every dialog" means here. */
export function isDialogSurface(text: string): boolean {
    return (
        /import\s*\{[^}]*\bDialog\b[^}]*\}\s*from\s*'radix-ui'/.test(text) ||
        /aria-modal|<dialog\b|role="(alert)?dialog"/.test(text) ||
        /fixed inset-0[^'"`]*z-(40|50)|z-(40|50)[^'"`]*fixed inset-0/.test(text)
    );
}

/** `<Modal ...>` elements without a title prop and without hideTitleVisually. */
export function untitledModals(fileName: string, text: string): string[] {
    const sf = ts.createSourceFile(fileName, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    const hits: string[] = [];
    const visit = (n: ts.Node) => {
        if ((ts.isJsxOpeningElement(n) || ts.isJsxSelfClosingElement(n)) && n.tagName.getText(sf) === 'Modal') {
            const names = n.attributes.properties.map((p) => (ts.isJsxAttribute(p) ? p.name.getText(sf) : '...spread'));
            if (!names.includes('title') && !names.includes('hideTitleVisually') && !names.includes('...spread')) {
                hits.push(`${fileName}:${sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1}`);
            }
        }
        ts.forEachChild(n, visit);
    };
    visit(sf);
    return hits;
}

// <Modal>s without a title prop: the heading is drawn by the component inside. Each is listed with
// the file(s) whose headings are audited statically below (headingViolations). A new untitled
// <Modal> must be added here, with its body file, or the inventory test fails.
const UNTITLED_MODALS: Record<string, { count: number; bodyFiles: string[] }> = {
    'src/pages/projects/ProjectSecretsTab.tsx': {
        count: 3,
        bodyFiles: [
            'src/features/secrets/SecretDetailView.tsx',
            'src/pages/projects/SecretsDriftPanel.tsx',
            'src/pages/projects/SecretsRotationPlanPanel.tsx',
        ],
    },
    'src/pages/secrets/SecretsListPage.tsx': { count: 1, bodyFiles: ['src/features/secrets/SecretDetailView.tsx'] },
};

interface Heading {
    where: string;
    tag: string;
    cls: string;
    style: string;
}

/**
 * Headings (h1-h6) with a statically known colour: a string className and/or a literal
 * `style={{ color: '...' }}`. With `onlyInDialogs`, only those inside a Modal/Dialog subtree.
 * A heading whose className is an expression (cn(...), template with holes) is returned with
 * cls "<dynamic>", which the audit treats as a violation (cannot be checked statically).
 */
export function headingsOf(fileName: string, text: string, onlyInDialogs: boolean): Heading[] {
    const sf = ts.createSourceFile(fileName, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    const out: Heading[] = [];
    const visit = (n: ts.Node, inDialog: boolean) => {
        const el = ts.isJsxElement(n) ? n.openingElement : ts.isJsxSelfClosingElement(n) ? n : null;
        let inD = inDialog;
        if (el) {
            const tag = el.tagName.getText(sf);
            if (tag === 'Modal' || tag === 'Dialog') inD = true;
            if (/^h[1-6]$/.test(tag) && (inD || !onlyInDialogs)) {
                let cls = '';
                let style = '';
                for (const p of el.attributes.properties) {
                    if (!ts.isJsxAttribute(p)) continue;
                    const name = p.name.getText(sf);
                    const init = p.initializer;
                    if (name === 'className') {
                        if (init && ts.isStringLiteral(init)) cls = init.text;
                        else if (
                            init &&
                            ts.isJsxExpression(init) &&
                            init.expression &&
                            ts.isNoSubstitutionTemplateLiteral(init.expression)
                        ) {
                            cls = init.expression.text;
                        } else cls = '<dynamic>';
                    } else if (name === 'style' && init && ts.isJsxExpression(init) && init.expression) {
                        const o = init.expression;
                        if (ts.isObjectLiteralExpression(o)) {
                            for (const prop of o.properties) {
                                if (
                                    ts.isPropertyAssignment(prop) &&
                                    prop.name.getText(sf) === 'color' &&
                                    ts.isStringLiteralLike(prop.initializer)
                                ) {
                                    style = `color: ${prop.initializer.text}`;
                                }
                            }
                        }
                    }
                }
                out.push({
                    where: `${fileName}:${sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1}`,
                    tag,
                    cls,
                    style,
                });
            }
        }
        ts.forEachChild(n, (c) => visit(c, inD));
    };
    visit(sf, false);
    return out;
}

/** Each heading is placed on the Modal surface (--bg-surface) and audited in both themes. */
export function headingViolations(headings: Heading[]): string[] {
    return headings.flatMap((h) => {
        if (h.cls === '<dynamic>')
            return [`${h.where}: <${h.tag}> className is not a literal; cannot audit its colour`];
        const surface = document.createElement('div');
        surface.setAttribute('style', 'background-color: var(--bg-surface)');
        const el = document.createElement(h.tag);
        el.setAttribute('class', h.cls);
        el.setAttribute('style', h.style);
        surface.appendChild(el);
        return THEMES.flatMap((theme) => contrastViolations(`${h.where} <${h.tag}>`, el, theme));
    });
}

describe('INV-WEB-dialog-contrast: inventory', () => {
    const files = sourceFiles(srcRoot);
    const text = (f: string) => readFileSync(join(webRoot, f), 'utf8');

    it('the sweep saw the tree (non-vacuity)', () => {
        expect(files.length).toBeGreaterThan(100);
        expect(files).toContain('src/components/ui/Modal.tsx');
    });

    it('every dialog surface in src is listed in SURFACES, and every listed one still is one', () => {
        const found = files.filter((f) => isDialogSurface(text(f))).sort();
        expect(found).toEqual(Object.keys(SURFACES).sort());
    });

    it('Dialog and useConfirm are still built on Modal / Dialog', () => {
        for (const f of DERIVED) expect(text(f)).toMatch(/from '\.\/(Modal|Dialog)'/);
    });

    it('every <Modal> has a title (audited in Modal) or is a registered untitled one', () => {
        const untitled: Record<string, number> = {};
        for (const f of files.filter((f) => /<Modal\b/.test(text(f)))) {
            const n = untitledModals(f, text(f)).length;
            if (n > 0) untitled[f] = n;
        }
        expect(untitled).toEqual(Object.fromEntries(Object.entries(UNTITLED_MODALS).map(([f, u]) => [f, u.count])));
    });

    it('headings drawn inside dialogs, and in the bodies of untitled modals, reach AA in both themes', () => {
        const bodyFiles = [...new Set(Object.values(UNTITLED_MODALS).flatMap((u) => u.bodyFiles))];
        for (const f of bodyFiles) expect(files).toContain(f);
        const headings = [
            ...files.flatMap((f) => (bodyFiles.includes(f) ? [] : headingsOf(f, text(f), true))),
            ...bodyFiles.flatMap((f) => headingsOf(f, text(f), false)),
        ];
        expect(headings.length).toBeGreaterThan(10); // non-vacuity: SecretDetailView alone has a dozen
        expect(headingViolations(headings)).toEqual([]);
    });

    it.each([
        ['Radix Dialog import', `import { Dialog } from 'radix-ui';`, true],
        ['aria-modal', `<div aria-modal="true" />`, true],
        ['native dialog element', `<dialog open />`, true],
        ['full-screen overlay', `<div className="fixed inset-0 z-50 bg-black/40" />`, true],
        ['plain component', `<div className="flex p-4" />`, false],
        ['sticky bar', `<div className="fixed top-0 z-50" />`, false],
    ])('isDialogSurface calibration: %s', (_n, code, expected) => {
        expect(isDialogSurface(code)).toBe(expected);
    });

    it('untitledModals flags a Modal with no title and spares titled / hidden-title ones', () => {
        expect(untitledModals('x.tsx', `const a = <Modal isOpen onClose={f}>x</Modal>;`)).toHaveLength(1);
        expect(untitledModals('x.tsx', `const a = <Modal isOpen title="T" onClose={f}>x</Modal>;`)).toEqual([]);
        expect(untitledModals('x.tsx', `const a = <Modal isOpen hideTitleVisually onClose={f}>x</Modal>;`)).toEqual([]);
    });
});

// ---- 2. render audit ------------------------------------------------------------------------

function visibleHeading(root: HTMLElement, name: string): HTMLElement {
    const h = screen
        .getAllByRole('heading', { name })
        .find((e) => !isSrOnly(e) && (root.contains(e) || root === document.body));
    if (!h) throw new Error(`no visible heading "${name}"`);
    return h;
}

function auditAll(label: string, els: Element[]): string[] {
    return THEMES.flatMap((theme) => els.flatMap((el, i) => contrastViolations(`${label}#${i}`, el, theme)));
}

describe('INV-WEB-dialog-contrast: rendered dialogs reach AA in light and dark', () => {
    it('Modal: title', () => {
        render(
            <Modal isOpen onClose={() => {}} title="Edit project">
                <p>body</p>
            </Modal>
        );
        expect(auditAll('Modal title', [visibleHeading(document.body, 'Edit project')])).toEqual([]);
    });

    it.each(['info', 'warning', 'success', 'danger'] as const)('Dialog (%s): title and message', (type) => {
        render(<Dialog isOpen onClose={() => {}} title="Heads up" message="Something to read." type={type} />);
        const els = [visibleHeading(document.body, 'Heads up'), screen.getByText('Something to read.')];
        expect(auditAll(`Dialog ${type}`, els)).toEqual([]);
    });

    // The dialog #3153 reported: the Sharing page's revoke confirmation, dark theme included.
    it('the Sharing page revoke dialog ("Delete Share"): title and message, both themes', () => {
        render(
            <Dialog
                isOpen
                onClose={() => {}}
                title="Delete Share"
                message={'Are you sure you want to revoke access for "Alice Anderson"?'}
                type="danger"
                confirmText="Revoke"
            />
        );
        const els = [
            visibleHeading(document.body, 'Delete Share'),
            screen.getByText('Are you sure you want to revoke access for "Alice Anderson"?'),
        ];
        expect(auditAll('Revoke share', els)).toEqual([]);
    });

    it('useConfirm: default title and the message', async () => {
        function Harness() {
            const { requestConfirm, confirmDialog } = useConfirm();
            React.useEffect(() => {
                void requestConfirm({ message: 'Remove dave from this project?' });
            }, [requestConfirm]);
            return confirmDialog;
        }
        render(<Harness />);
        const els = [
            await screen.findByRole('heading', { name: 'Please confirm', level: 3 }),
            screen.getByText('Remove dave from this project?'),
        ];
        expect(auditAll('useConfirm', els)).toEqual([]);
    });

    it('SessionTimeoutWarning: title and message', () => {
        render(<SessionTimeoutWarning />);
        const els = [
            screen.getByRole('heading', { name: 'Session Expiring' }),
            screen.getByText(/Your session will expire soon/),
        ];
        expect(auditAll('SessionTimeoutWarning', els)).toEqual([]);
    });

    it('CmdKSearch: the search input text', () => {
        const { container } = render(<CmdKSearch onClose={() => {}} />);
        const input = container.ownerDocument.querySelector('input');
        expect(input).not.toBeNull();
        expect(auditAll('CmdKSearch input', [input!])).toEqual([]);
    });
});

// ---- 3. calibration: the same audit goes red on planted dialogs ----------------------------

// Parsed into a detached document (the resolver only reads attributes and ancestors).
function planted(html: string): HTMLElement {
    return new DOMParser().parseFromString(html, 'text/html').body.querySelector('h3')!;
}

describe('INV-WEB-dialog-contrast: calibration (planted dialogs must fail)', () => {
    it('a title whose colour equals its background (inline tokens) fails in both themes', () => {
        const h = planted(
            `<div style="background-color: var(--bg-surface)"><h3 style="color: var(--bg-surface)">Delete Share</h3></div>`
        );
        for (const theme of THEMES) {
            const v = contrastViolations('planted', h, theme);
            expect(v).toHaveLength(1);
            expect(v[0]).toContain('1.00:1');
        }
    });

    it('a title whose colour equals its background (classes) fails', () => {
        const h = planted(`<div class="bg-surface"><h3 class="text-white">Delete Share</h3></div>`);
        // bg-surface is #ffffff in light: white on white. (In dark it is dark, so white would pass.)
        expect(contrastViolations('planted', h, 'light')).toHaveLength(1);
        expect(contrastViolations('planted', h, 'dark')).toEqual([]);
    });

    it('the #3153 shape (fixed dark-blue title on the dark surface) fails in dark only', () => {
        const h = planted(`<div class="bg-surface"><h3 class="text-blue-900">Delete Share</h3></div>`);
        expect(contrastViolations('planted', h, 'dark')).toHaveLength(1);
        expect(contrastViolations('planted', h, 'light')).toEqual([]);
    });

    it('the same fixed colour with a dark: counterpart passes in both themes', () => {
        const h = planted(`<div class="bg-surface"><h3 class="text-blue-900 dark:text-white">Delete Share</h3></div>`);
        for (const theme of THEMES) expect(contrastViolations('planted', h, theme)).toEqual([]);
    });

    it('a colour class the guard cannot resolve is a violation, not a skip', () => {
        const h = planted(`<div class="bg-surface"><h3 class="text-fuchsia-950">Delete Share</h3></div>`);
        const v = contrastViolations('planted', h, 'dark');
        expect(v).toHaveLength(1);
        expect(v[0]).toContain('unresolvable');
        expect(() => contrastOf(h, 'dark')).toThrow(UnresolvableColour);
    });

    it('static heading audit: the #3153 class string fails, the pair with a dark: counterpart passes', () => {
        const bad = headingsOf('x.tsx', `const a = <Modal><h3 className="text-lg text-blue-900">T</h3></Modal>;`, true);
        expect(headingViolations(bad)).toHaveLength(1);
        const ok = headingsOf(
            'x.tsx',
            `const a = <Modal><h3 className="text-lg text-gray-900 dark:text-white">T</h3></Modal>;`,
            true
        );
        expect(headingViolations(ok)).toEqual([]);
    });

    it('static heading audit: a literal style colour is read, a dynamic className is a violation', () => {
        const styled = headingsOf(
            'x.tsx',
            `const a = <Modal><h4 className="text-xs" style={{ color: 'var(--bg-surface)' }}>T</h4></Modal>;`,
            true
        );
        expect(headingViolations(styled)).toHaveLength(2); // both themes
        const dyn = headingsOf('x.tsx', `const a = <Modal><h3 className={cn('a', b)}>T</h3></Modal>;`, true);
        expect(headingViolations(dyn)[0]).toContain('not a literal');
    });

    it('static heading audit only looks inside dialogs when asked', () => {
        const code = `const a = <div><h3 className="text-blue-900">page</h3><Modal><h3 className="text-base-primary">m</h3></Modal></div>;`;
        expect(headingsOf('x.tsx', code, true)).toHaveLength(1);
        expect(headingsOf('x.tsx', code, false)).toHaveLength(2);
    });

    it('a title on a translucent background is judged on the composited colour', () => {
        const h = planted(
            `<div style="background-color: var(--bg-surface)"><div style="background-color: rgba(245,158,11,0.12)"><h3 style="color: var(--text-primary)">T</h3></div></div>`
        );
        for (const theme of THEMES) expect(contrastViolations('planted', h, theme)).toEqual([]);
    });
});
