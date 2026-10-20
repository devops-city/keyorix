// Colour resolver for the dialog contrast guard (__tests__/structure/dialogContrast.test.tsx).
//
// jsdom has no CSS engine and Tailwind is not compiled under Vitest, so "what colour is this
// title on what background" is answered from the two places the app actually decides it:
//   - inline `style` (color / background-color: var(--token) | #hex | rgb[a]()), and
//   - class names, resolved through index.css: `@utility text-base-primary { color: var(--x) }`,
//     the `@theme` `--color-*` aliases (text-foreground, bg-card, ...), and a small fixed
//     palette (white, black, gray-*, blue-*) for the classes #3153 was about.
// Tokens are read per theme from `[data-theme='light'|'dark']` in index.css. The `dark:` variant
// applies only when theme === 'dark' (index.css: @custom-variant dark -> [data-theme="dark"]).
//
// Fail closed: a colour class or value this module cannot resolve throws UnresolvableColour. It
// is never skipped. Not modelled: other variants (hover:, focus:, sm:), gradients, opacity
// utilities on backgrounds (bg-black/40), CSS cascade order between two classes of the same
// kind (the later one in the class list wins, `dark:` wins over the base class in dark).
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

export type Theme = 'light' | 'dark';
export interface Rgba {
    r: number;
    g: number;
    b: number;
    a: number;
}

export class UnresolvableColour extends Error {}

const css = readFileSync(resolve(import.meta.dirname, '../index.css'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');

function declarations(block: string): Record<string, string> {
    const out: Record<string, string> = {};
    for (const m of block.matchAll(/(--[\w-]+|[\w-]+)\s*:\s*([^;]+);/g)) out[m[1]!] = m[2]!.trim();
    return out;
}

function themeTokens(theme: Theme): Record<string, string> {
    const m = css.match(new RegExp(`\\[data-theme='${theme}'\\]\\s*\\{([^}]*)\\}`));
    if (!m?.[1]) throw new Error(`no [data-theme='${theme}'] block in index.css`);
    return declarations(m[1]);
}

const TOKENS: Record<Theme, Record<string, string>> = { light: themeTokens('light'), dark: themeTokens('dark') };

// `@utility name { color: ...; }` -> name -> { color | background-color }
const UTILITIES = new Map<string, Record<string, string>>();
for (const m of css.matchAll(/@utility\s+([\w-]+)\s*\{([^}]*)\}/g)) UTILITIES.set(m[1]!, declarations(m[2]!));

// `@theme { --color-foo: ... }` -> text-foo / bg-foo
const THEME_COLOURS = new Map<string, string>();
const themeBlock = css.match(/@theme\s*\{([\s\S]*?)\n\}/);
for (const [k, v] of Object.entries(declarations(themeBlock?.[1] ?? ''))) {
    if (k.startsWith('--color-')) THEME_COLOURS.set(k.slice('--color-'.length), v);
}

// Tailwind default palette values for the fixed colours dialogs have used (hex, v3 values).
const PALETTE: Record<string, string> = {
    white: '#ffffff',
    black: '#000000',
    'gray-50': '#f9fafb',
    'gray-100': '#f3f4f6',
    'gray-200': '#e5e7eb',
    'gray-300': '#d1d5db',
    'gray-400': '#9ca3af',
    'gray-500': '#6b7280',
    'gray-600': '#4b5563',
    'gray-700': '#374151',
    'gray-800': '#1f2937',
    'gray-900': '#111827',
    'blue-50': '#eff6ff',
    'blue-100': '#dbeafe',
    'blue-500': '#3b82f6',
    'blue-600': '#2563eb',
    'blue-700': '#1d4ed8',
    'blue-800': '#1e40af',
    'blue-900': '#1e3a8a',
};
const PALETTE_LIKE =
    /^(white|black|(gray|slate|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)-\d{2,3})$/;

export function parseColour(value: string, theme: Theme, depth = 0): Rgba | null {
    const v = value.trim();
    if (depth > 5) throw new UnresolvableColour(`token loop at ${value}`);
    if (v === 'transparent') return { r: 0, g: 0, b: 0, a: 0 };
    const variable = v.match(/^var\(\s*(--[\w-]+)\s*(?:,\s*([^)]+))?\)$/);
    if (variable) {
        const tok = TOKENS[theme][variable[1]!] ?? variable[2];
        if (tok === undefined) throw new UnresolvableColour(`undefined token ${variable[1]} in ${theme} theme`);
        return parseColour(tok, theme, depth + 1);
    }
    const hex = v.match(/^#([0-9a-f]{3}|[0-9a-f]{6}|[0-9a-f]{8})$/i);
    if (hex) {
        let h = hex[1]!;
        if (h.length === 3) h = [...h].map((c) => c + c).join('');
        const n = (i: number) => parseInt(h.slice(i, i + 2), 16);
        return { r: n(0), g: n(2), b: n(4), a: h.length === 8 ? n(6) / 255 : 1 };
    }
    const rgb = v.match(/^rgba?\(\s*(\d+)\s*[, ]\s*(\d+)\s*[, ]\s*(\d+)\s*(?:[,/]\s*([\d.]+%?)\s*)?\)$/);
    if (rgb) {
        const a = rgb[4] === undefined ? 1 : rgb[4].endsWith('%') ? parseFloat(rgb[4]) / 100 : parseFloat(rgb[4]);
        return { r: +rgb[1]!, g: +rgb[2]!, b: +rgb[3]!, a };
    }
    if (v === 'currentColor' || v === 'inherit') return null;
    throw new UnresolvableColour(`cannot parse colour "${value}"`);
}

function classColour(name: string, kind: 'text' | 'bg', theme: Theme): Rgba | null | undefined {
    // undefined = not a colour class of this kind; null = colour class that sets nothing (bg-transparent).
    const alpha = name.match(/^(.*)\/(\d{1,3})$/);
    const base = alpha ? alpha[1]! : name;
    const withAlpha = (c: Rgba | null) => (c && alpha ? { ...c, a: c.a * (parseInt(alpha[2]!, 10) / 100) } : c);
    const util = UTILITIES.get(base);
    if (util) {
        const prop = kind === 'text' ? util['color'] : (util['background-color'] ?? util['background']);
        return prop === undefined ? undefined : withAlpha(parseColour(prop, theme));
    }
    const key = base.slice(kind === 'text' ? 5 : 3);
    if (!base.startsWith(kind === 'text' ? 'text-' : 'bg-')) return undefined;
    if (key === 'transparent') return { r: 0, g: 0, b: 0, a: 0 };
    const themed = THEME_COLOURS.get(key);
    if (themed !== undefined) return withAlpha(parseColour(themed, theme));
    if (PALETTE_LIKE.test(key)) {
        const p = PALETTE[key];
        if (!p) throw new UnresolvableColour(`palette class ${base} is not in the guard's palette; use a theme token`);
        return withAlpha(parseColour(p, theme));
    }
    return undefined; // text-sm, text-center, bg-cover, ...
}

function fromClasses(el: Element, kind: 'text' | 'bg', theme: Theme): Rgba | null | undefined {
    let base: Rgba | null | undefined;
    let dark: Rgba | null | undefined;
    for (const raw of (el.getAttribute('class') ?? '').split(/\s+/).filter(Boolean)) {
        const isDark = raw.startsWith('dark:');
        if (!isDark && raw.includes(':')) continue; // hover:, focus:, sm:, ...
        const c = classColour(isDark ? raw.slice(5) : raw, kind, theme);
        if (c === undefined) continue;
        if (isDark) dark = c;
        else base = c;
    }
    return theme === 'dark' && dark !== undefined ? dark : base;
}

function fromStyle(el: Element, kind: 'text' | 'bg', theme: Theme): Rgba | null | undefined {
    const style = el.getAttribute('style') ?? '';
    const props = kind === 'text' ? ['color'] : ['background-color', 'background'];
    for (const p of props) {
        const m = style.match(new RegExp(`(?:^|;)\\s*${p}\\s*:\\s*([^;]+)`, 'i'));
        if (m?.[1]) return parseColour(m[1], theme);
    }
    return undefined;
}

/** The colour the text of `el` is painted in: nearest own/ancestor inline style or class colour. */
export function textColour(el: Element, theme: Theme): Rgba {
    for (let cur: Element | null = el; cur; cur = cur.parentElement) {
        const c = fromStyle(cur, 'text', theme) ?? fromClasses(cur, 'text', theme);
        if (c) return c;
    }
    return opaque(parseColour('var(--text-primary)', theme)!); // body { color: var(--text-primary) }
}

/** What `el` sits on: its own/ancestor backgrounds composited, down to the page background. */
export function backgroundColour(el: Element, theme: Theme): Rgba {
    const layers: Rgba[] = [];
    for (let cur: Element | null = el; cur; cur = cur.parentElement) {
        const c = fromStyle(cur, 'bg', theme) ?? fromClasses(cur, 'bg', theme);
        if (c && c.a > 0) {
            layers.push(c);
            if (c.a >= 1) break;
        }
    }
    let out = opaque(parseColour('var(--bg-app)', theme)!); // body { background-color: var(--bg-app) }
    for (const l of layers.reverse()) out = blend(l, out);
    return out;
}

function opaque(c: Rgba): Rgba {
    return { ...c, a: 1 };
}

function blend(top: Rgba, under: Rgba): Rgba {
    const mix = (t: number, u: number) => Math.round(t * top.a + u * (1 - top.a));
    return { r: mix(top.r, under.r), g: mix(top.g, under.g), b: mix(top.b, under.b), a: 1 };
}

function luminance(c: Rgba): number {
    const [r, g, b] = [c.r, c.g, c.b].map((v) => {
        const s = v / 255;
        return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
    }) as [number, number, number];
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

export function contrastRatio(a: Rgba, b: Rgba): number {
    const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
    return (hi + 0.05) / (lo + 0.05);
}

export interface ContrastResult {
    ratio: number;
    fg: Rgba;
    bg: Rgba;
}

/** Contrast of `el`'s text against what it sits on, in `theme`. Throws UnresolvableColour, never skips. */
export function contrastOf(el: Element, theme: Theme): ContrastResult {
    const bg = backgroundColour(el, theme);
    const fg = blend(textColour(el, theme), bg);
    return { ratio: contrastRatio(fg, bg), fg, bg };
}

export const AA_TEXT = 4.5;

/** True when `el` or an ancestor is visually hidden (Tailwind sr-only): not a visible title. */
export function isSrOnly(el: Element): boolean {
    for (let cur: Element | null = el; cur; cur = cur.parentElement) {
        if (cur.classList.contains('sr-only')) return true;
    }
    return false;
}

const hex = (c: Rgba) => '#' + [c.r, c.g, c.b].map((v) => v.toString(16).padStart(2, '0')).join('');

/** One line per violation for an element, or [] when it reaches `min`. Unresolvable colours are violations. */
export function contrastViolations(label: string, el: Element, theme: Theme, min = AA_TEXT): string[] {
    try {
        const { ratio, fg, bg } = contrastOf(el, theme);
        return ratio >= min
            ? []
            : [`${label} [${theme}]: ${ratio.toFixed(2)}:1 < ${min} (text ${hex(fg)} on ${hex(bg)})`];
    } catch (e) {
        if (e instanceof UnresolvableColour) return [`${label} [${theme}]: unresolvable colour: ${e.message}`];
        throw e;
    }
}
