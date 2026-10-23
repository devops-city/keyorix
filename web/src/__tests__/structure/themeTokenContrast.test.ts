// WCAG AA (4.5:1, normal text) over the theme token pairs in index.css — DEMO-WALK-4 finding 5:
// light-theme secondary text (--text-muted, gray-400 on white) was 2.5:1. The ratios are computed
// from the tokens by the same resolver as the dialog guard (test/contrast.ts), never eyeballed.
//
// Scope: every text token on every surface it can sit on, plus the semantic colours on their own
// tint. Not covered: hard-coded hex text colours in components (they bypass the tokens), hover and
// focus states, large-text (3:1) and non-text (borders, icons) contrast.
import { describe, expect, it } from 'vitest';
import { contrastRatio, parseColour, type Theme } from '../../test/contrast';

const AA = 4.5;

const ratio = (fg: string, bg: string, theme: Theme) =>
    contrastRatio(parseColour(`var(--${fg})`, theme)!, parseColour(`var(--${bg})`, theme)!);

const SURFACES = ['bg-app', 'bg-surface', 'bg-subtle'];
const PAIRS: Array<[fg: string, bg: string]> = [
    // neutral text on every surface and on the muted fill (inputs, dividers)
    ...['text-primary', 'text-secondary', 'text-muted'].flatMap((fg): Array<[string, string]> =>
        [...SURFACES, 'bg-muted'].map((bg) => [fg, bg])
    ),
    // semantic colours used as text, on the page surfaces
    ...['accent-text', 'danger', 'error', 'success', 'warning'].flatMap((fg): Array<[string, string]> =>
        SURFACES.map((bg) => [fg, bg])
    ),
    // semantic text on its own tint (alerts, badges)
    ['accent-text', 'accent-subtle'],
    ['error', 'error-subtle'],
    ['success', 'success-subtle'],
    ['warning', 'warning-subtle'],
    // button labels
    ['text-inverse', 'accent'],
    ['text-inverse', 'danger'],
];

// Dark-theme pairs that already failed when this guard was added (dark was out of scope for the
// light-theme fix and is deliberately unchanged). Each entry is a ceiling on how bad it may get;
// the stale check below fails when an entry starts passing so it gets deleted.
// Follow-up: raise dark --text-muted (#6b6b76) to >= 4.5:1 (listed in the PR body).
const KNOWN_DARK_FAILURES: Record<string, number> = {
    'text-muted on bg-app': 3.7, // measured 3.76
    'text-muted on bg-surface': 3.4, // measured 3.50
    'text-muted on bg-subtle': 3.2, // measured 3.23
    'text-muted on bg-muted': 2.7, // measured 2.72
};

describe('theme token contrast (WCAG AA 4.5:1)', () => {
    describe.each(['light', 'dark'] as const)('%s theme', (theme) => {
        it.each(PAIRS)('%s on %s', (fg, bg) => {
            const r = ratio(fg, bg, theme);
            const key = `${fg} on ${bg}`;
            const known = theme === 'dark' ? KNOWN_DARK_FAILURES[key] : undefined;
            if (known !== undefined) {
                expect(r, `${key} (dark, known failure) got worse: ${r.toFixed(2)}`).toBeGreaterThanOrEqual(known);
                expect(r, `${key} (dark) now passes AA: remove it from KNOWN_DARK_FAILURES`).toBeLessThan(AA);
            } else {
                expect(r, `${theme}: ${key} is ${r.toFixed(2)}:1`).toBeGreaterThanOrEqual(AA);
            }
        });
    });

    it('calibration: the pre-fix light --text-muted (gray-400 on white) is rejected', () => {
        const r = contrastRatio(parseColour('#9ca3af', 'light')!, parseColour('#ffffff', 'light')!);
        expect(r).toBeLessThan(AA);
        expect(r).toBeGreaterThan(2.4);
    });

    it('calibration: black on white is the 21:1 maximum', () => {
        expect(contrastRatio(parseColour('#000000', 'light')!, parseColour('#ffffff', 'light')!)).toBeCloseTo(21, 5);
    });
});
