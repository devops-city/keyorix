// Calibration for the INV-WEB-05 comparison engine: it must be green on a matching
// pair AND red on each class of drift it claims to catch. A guard nobody has
// watched fail is not a guard (CLAUDE.md), and the real-spec test in
// openapiDrift.test.ts is green on a clean tree, so it cannot show this itself.
import { describe, expect, it } from 'vitest';
import { compare, createProgram, exportedInterfaces, toShape, type Shape } from './openapiDriftLib';

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

    it('an exemption suppresses exactly its field and is recorded as used', () => {
        const r = run(GOOD + ' extra: string;', { allow: { 'Thing.extra#not-in-schema': 'because' } });
        expect(r.out).toEqual([]);
        expect([...r.used]).toEqual(['Thing.extra#not-in-schema']);
    });

    it('an unneeded exemption is not recorded as used (the caller fails it as stale)', () => {
        expect([...run(GOOD, { allow: { 'Thing.extra#not-in-schema': 'because' } }).used]).toEqual([]);
    });
});

// #2868: an exemption written about one finding KIND must not swallow another
// kind at the same path.
describe('openapiDrift exemption granularity (#2868)', () => {
    it('an optionality exemption at a path does not hide a kind mismatch at the same path', () => {
        const shape: Shape = { kind: 'number', nullable: false }; // TS says number
        const schema = { type: 'string' }; // server now sends a string
        const out: string[] = [];
        const used = new Set<string>();
        compare(
            {},
            shape,
            schema,
            'LoginResponse.user_id',
            { 'LoginResponse.user_id': 'present only on the LoginSuccessData branch' },
            used,
            out
        );
        expect(out, 'the kind mismatch was swallowed by an exemption about optionality').not.toEqual([]);
    });
});

describe('openapiDrift exemption kinds (#2868)', () => {
    const runKind = (allow: Record<string, string>) => {
        const out: string[] = [];
        const used = new Set<string>();
        compare({}, { kind: 'number', nullable: false }, { type: 'string' }, 'P.x', allow, used, out);
        return { out, used };
    };

    it('an exemption naming the finding kind suppresses it and is recorded as used', () => {
        const r = runKind({ 'P.x#kind': 'because' });
        expect(r.out).toEqual([]);
        expect([...r.used]).toEqual(['P.x#kind']);
    });

    it('an exemption for a different kind at the same path suppresses nothing and stays unused', () => {
        const r = runKind({ 'P.x#optionality': 'because' });
        expect(r.out).toHaveLength(1);
        expect([...r.used]).toEqual([]);
    });

    it('a legacy bare-path key no longer suppresses anything (it is reported unused as stale)', () => {
        const r = runKind({ 'P.x': 'because' });
        expect(r.out).toHaveLength(1);
        expect([...r.used]).toEqual([]);
    });

    it('optionality and not-in-schema exemptions each suppress only their own finding at one path', () => {
        const out: string[] = [];
        const used = new Set<string>();
        const d = {
            type: 'object',
            required: ['a'],
            properties: { a: { type: 'string' } },
        };
        const program = createProgram({ '/virtual/o.ts': 'export interface O { a?: string; b: string }' });
        const t = exportedInterfaces(program, ['/virtual/o.ts']).get('O')!;
        compare({}, toShape(program.getTypeChecker(), t), d, 'O', { 'O.a#optionality': 'x' }, used, out);
        expect(out).toEqual([expect.stringContaining('O.b: declared in TS but not in the schema')]);
        expect([...used]).toEqual(['O.a#optionality']);
    });
});
