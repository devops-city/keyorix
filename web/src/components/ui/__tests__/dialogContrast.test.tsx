// #3153: the revoke dialog's title ("Delete Share") was dark text on the dark dialog surface.
// jsdom has no CSS engine, so this checks the two things that decide it without a browser:
//   1. the Dialog title/message use the theme-token utilities (text-base-primary /
//      text-base-secondary), never a fixed text-gray-*/text-blue-* class;
//   2. in index.css those utilities resolve to --text-primary / --text-secondary, and those
//      tokens reach WCAG AA (4.5:1) on --bg-surface in BOTH themes.
// Not covered: the icon badge colours, and any override a page applies on top of the dialog.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { render, screen } from '../../../test/test-utils';
import { Dialog } from '../Dialog';

const css = readFileSync(resolve(import.meta.dirname, '../../../index.css'), 'utf8');

function themeTokens(theme: 'light' | 'dark'): Record<string, string> {
    const block = css.match(new RegExp(`\\[data-theme='${theme}'\\]\\s*\\{([^}]*)\\}`));
    if (!block?.[1]) throw new Error(`no [data-theme='${theme}'] block in index.css`);
    const out: Record<string, string> = {};
    for (const m of block[1].matchAll(/(--[\w-]+):\s*(#[0-9a-fA-F]{6})/g)) out[m[1]!] = m[2]!;
    return out;
}

function luminance(hex: string): number {
    const [r, g, b] = [1, 3, 5].map((i) => {
        const c = parseInt(hex.slice(i, i + 2), 16) / 255;
        return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
    }) as [number, number, number];
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a: string, b: string): number {
    const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
    return (hi + 0.05) / (lo + 0.05);
}

describe('Dialog title and message contrast (#3153)', () => {
    it('uses the theme-token utilities, not fixed greys', () => {
        render(<Dialog isOpen onClose={() => {}} title="Delete Share" message="Revoke access?" type="danger" />);
        // Two headings carry the title: Radix's sr-only accessible name and the visible h3.
        const title = screen.getAllByRole('heading', { name: 'Delete Share' }).find((h) => h.tagName === 'H3')!;
        const message = screen.getByText('Revoke access?');
        expect(title.className).toContain('text-base-primary');
        expect(message.className).toContain('text-base-secondary');
        expect(title.className).not.toMatch(/text-(gray|slate|zinc|blue)-\d/);
        expect(message.className).not.toMatch(/text-(gray|slate|zinc|blue)-\d/);
    });

    it('the token utilities resolve to the theme text colours', () => {
        expect(css).toMatch(/@utility text-base-primary\s*\{\s*color:\s*var\(--text-primary\);/);
        expect(css).toMatch(/@utility text-base-secondary\s*\{\s*color:\s*var\(--text-secondary\);/);
    });

    it.each(['light', 'dark'] as const)('%s theme: text tokens reach AA contrast on the dialog surface', (theme) => {
        const t = themeTokens(theme);
        expect(contrast(t['--text-primary']!, t['--bg-surface']!)).toBeGreaterThanOrEqual(4.5);
        expect(contrast(t['--text-secondary']!, t['--bg-surface']!)).toBeGreaterThanOrEqual(4.5);
    });

    it('the contrast helper is red on the failure that was reported (dark blue on dark surface)', () => {
        const dark = themeTokens('dark');
        expect(contrast('#1e3a8a', dark['--bg-surface']!)).toBeLessThan(4.5);
    });
});
