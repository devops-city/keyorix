// Calibration for the INV-WEB-05 comparison engine: it must be green on a matching
// pair AND red on each class of drift it claims to catch. A guard nobody has
// watched fail is not a guard (CLAUDE.md), and the real-spec test in
// openapiDrift.test.ts is green on a clean tree, so it cannot show this itself.
import { describe, expect, it } from 'vitest';
import { allowKey, compare, createProgram, exportedInterfaces, toShape } from './openapiDriftLib';

const doc = {
    components: {
        schemas: {
            Thing: {
                type: 'object',
                required: ['id'],
                properties: {
                    id: { type: 'integer' },
                    name: { type: 'string' },
                    band: { type: 'string', enum: ['low', 'high'] },
                    when: { type: 'string', nullable: true },
                    tags: { type: 'array', items: { type: 'string' } },
                },
            },
        },
    },
};

function run(tsBody: string, opts: { allow?: Record<string, string>; request?: boolean } = {}) {
    const f = '/virtual/t.ts';
    const program = createProgram({ [f]: `export interface Thing {\n${tsBody}\n}` });
    const t = exportedInterfaces(program, [f]).get('Thing')!;
    const out: string[] = [];
    const used = new Set<string>();
    compare(
        doc,
        toShape(program.getTypeChecker(), t),
        doc.components.schemas.Thing,
        'Thing',
        opts.allow ?? {},
        used,
        out,
        opts.request
    );
    return { out, used };
}

const GOOD = `id: number; name?: string; band?: 'low' | 'high'; when?: string | null; tags?: string[];`;

describe('openapiDriftLib engine', () => {
    it('green: a matching type reports nothing', () => {
        // when?: string | null  <->  nullable: true ; name? is optional but schema has a required list [id] -> ok
        expect(run(GOOD).out).toEqual([]);
    });

    it('red: a field the server never sends', () => {
        expect(run(GOOD + ' extra: string;').out).toEqual([
            expect.stringContaining('Thing.extra: declared in TS but not in the schema'),
        ]);
    });

    it('red: a field the server sends that TS does not declare', () => {
        expect(run(GOOD.replace(' tags?: string[];', '')).out).toEqual([
            expect.stringContaining('Thing.tags: sent by the server'),
        ]);
    });

    it('red: wrong kind', () => {
        expect(run(GOOD.replace('name?: string', 'name?: number')).out).toEqual([
            expect.stringContaining('Thing.name: TS kind is number'),
        ]);
    });

    it('red: nullability dropped', () => {
        expect(run(GOOD.replace('when?: string | null', 'when?: string')).out).toEqual([
            expect.stringContaining('Thing.when: TS forbids null'),
        ]);
    });

    it('red: enum widened and enum narrowed', () => {
        expect(run(GOOD.replace("'low' | 'high'", "'low' | 'high' | 'mid'")).out).toEqual([
            expect.stringContaining('enum mismatch'),
        ]);
        expect(run(GOOD.replace("band?: 'low' | 'high'", 'band?: string')).out).toEqual([
            expect.stringContaining('not a string-literal union'),
        ]);
    });

    it('red: required-ness disagrees (when the schema declares `required`)', () => {
        expect(run(GOOD.replace('id: number', 'id?: number')).out).toEqual([
            expect.stringContaining('Thing.id: TS optional but schema requires'),
        ]);
        expect(run(GOOD.replace('name?: string', 'name: string')).out).toEqual([
            expect.stringContaining('Thing.name: TS required but schema does not'),
        ]);
    });

    it('request mode: TS may require more than the schema, never less', () => {
        expect(run(GOOD.replace('name?: string', 'name: string'), { request: true }).out).toEqual([]);
        expect(run(GOOD.replace('id: number', 'id?: number'), { request: true }).out).toHaveLength(1);
    });

    it('an exemption suppresses exactly its path and message kind and is recorded as used', () => {
        const r = run(GOOD + ' extra: string;', { allow: { [allowKey('Thing.extra', 'ts-only')]: 'because' } });
        expect(r.out).toEqual([]);
        expect([...r.used]).toEqual(['Thing.extra#ts-only']);
    });

    it('an unneeded exemption is not recorded as used (the caller fails it as stale)', () => {
        expect([...run(GOOD, { allow: { [allowKey('Thing.extra', 'ts-only')]: 'because' } }).used]).toEqual([]);
    });

    // #2868: an exemption used to silence EVERY check on its path, so a second,
    // unrelated drift on an exempted path was invisible. `when` here drifts two
    // ways at once (nullability dropped AND a literal union the schema has no
    // enum for); exempting the first must leave the second reported.
    const TWO_DRIFTS = GOOD.replace('when?: string | null', "when?: 'a' | 'b'");

    it('red: both drifts on one path are reported when nothing is exempted', () => {
        const kinds = run(TWO_DRIFTS).out;
        expect(kinds).toEqual([
            expect.stringContaining('Thing.when: TS forbids null'),
            expect.stringContaining('Thing.when: TS is a literal union'),
        ]);
    });

    it('an exemption for one message kind does not hide a second drift on the same path', () => {
        const r = run(TWO_DRIFTS, { allow: { [allowKey('Thing.when', 'nullable')]: 'because' } });
        expect(r.out).toEqual([expect.stringContaining('Thing.when: TS is a literal union')]);
        expect([...r.used]).toEqual(['Thing.when#nullable']);
    });

    it('an exemption for a different kind than the one that fires does not suppress it and is not used', () => {
        const r = run(GOOD.replace('when?: string | null', 'when?: string'), {
            allow: { [allowKey('Thing.when', 'enum-mismatch')]: 'because' },
        });
        expect(r.out).toEqual([expect.stringContaining('Thing.when: TS forbids null')]);
        expect([...r.used]).toEqual([]);
    });

    it('exempting every kind that fires on a path silences the path', () => {
        const r = run(TWO_DRIFTS, {
            allow: { [allowKey('Thing.when', 'nullable')]: 'a', [allowKey('Thing.when', 'union-no-enum')]: 'b' },
        });
        expect(r.out).toEqual([]);
        expect([...r.used].sort()).toEqual(['Thing.when#nullable', 'Thing.when#union-no-enum']);
    });

    it('a bare path key (the pre-#2868 shape) no longer exempts anything', () => {
        const r = run(GOOD + ' extra: string;', { allow: { 'Thing.extra': 'because' } });
        expect(r.out).toEqual([expect.stringContaining('Thing.extra: declared in TS but not in the schema')]);
        expect([...r.used]).toEqual([]);
    });
});
