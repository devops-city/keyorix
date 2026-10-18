// Comparison engine for the web/src/types <-> openapi.yaml drift guard
// (INV-WEB-05). Kept separate from the test so the engine itself can be
// calibrated against synthetic red/green cases (openapiDrift.engine.test.ts).
//
// What it compares, per mapped (TS interface, OpenAPI schema) pair, recursively:
//   - field names, in both directions (a field the UI declares that the server
//     never sends; a field the server sends that the UI type does not declare);
//   - JSON kind (string / number / boolean / array / object);
//   - nullability (`nullable: true` <-> `| null`);
//   - enums (`enum: [...]` <-> a string-literal union, as sets);
//   - optionality, but ONLY where the schema declares a `required` list: a spec
//     without `required` says nothing about presence, so it is not compared.
// For a request body (`request = true`) optionality is one-directional: TS may
// require more than the schema, never less.
// What it does NOT compare: string formats, numeric ranges, `description`s, and
// anything under `additionalProperties`/`Record<>` beyond its being an object.
import ts from 'typescript';

export interface Shape {
    kind: 'string' | 'number' | 'boolean' | 'array' | 'object' | 'unknown';
    nullable: boolean;
    literals?: string[];
    items?: Shape;
    record?: boolean;
    props?: Record<string, { optional: boolean; shape: Shape }>;
}

type Schema = Record<string, any>;

export function createProgram(sources: Record<string, string>): ts.Program {
    const options: ts.CompilerOptions = {
        strict: true,
        noEmit: true,
        skipLibCheck: true,
        types: [],
        target: ts.ScriptTarget.ES2022,
        module: ts.ModuleKind.ESNext,
        moduleResolution: ts.ModuleResolutionKind.Bundler,
        jsx: ts.JsxEmit.ReactJSX,
    };
    const host = ts.createCompilerHost(options);
    const origRead = host.readFile.bind(host);
    const origExists = host.fileExists.bind(host);
    const origSF = host.getSourceFile.bind(host);
    host.readFile = (f) => sources[f] ?? origRead(f);
    host.fileExists = (f) => f in sources || origExists(f);
    host.getSourceFile = (f, lang, ...rest) =>
        f in sources ? ts.createSourceFile(f, sources[f]!, lang) : origSF(f, lang, ...rest);
    return ts.createProgram(Object.keys(sources), options, host);
}

/** Every exported interface, by name, across the given program's root files. */
export function exportedInterfaces(program: ts.Program, files: string[]): Map<string, ts.Type> {
    const checker = program.getTypeChecker();
    const out = new Map<string, ts.Type>();
    for (const f of files) {
        const sf = program.getSourceFile(f);
        if (!sf) throw new Error(`source file not found: ${f}`);
        for (const stmt of sf.statements) {
            if (
                ts.isInterfaceDeclaration(stmt) &&
                stmt.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword)
            ) {
                if (out.has(stmt.name.text)) throw new Error(`duplicate exported interface ${stmt.name.text}`);
                out.set(stmt.name.text, checker.getTypeAtLocation(stmt.name));
            }
        }
    }
    return out;
}

export function toShape(checker: ts.TypeChecker, type: ts.Type, seen: ts.Type[] = []): Shape {
    let nullable = false;
    let members: ts.Type[] = type.isUnion() ? type.types : [type];
    members = members.filter((m) => {
        if (m.flags & ts.TypeFlags.Null) {
            nullable = true;
            return false;
        }
        return !(m.flags & ts.TypeFlags.Undefined);
    });
    if (members.length > 0 && members.every((m) => m.flags & ts.TypeFlags.BooleanLiteral)) {
        return { kind: 'boolean', nullable };
    }
    if (members.length > 0 && members.every((m) => m.isStringLiteral())) {
        return { kind: 'string', nullable, literals: members.map((m) => (m as ts.StringLiteralType).value).sort() };
    }
    if (members.length !== 1) return { kind: 'unknown', nullable };
    const t = members[0]!;
    if (t.flags & ts.TypeFlags.StringLike) return { kind: 'string', nullable };
    if (t.flags & ts.TypeFlags.NumberLike) return { kind: 'number', nullable };
    if (t.flags & ts.TypeFlags.BooleanLike) return { kind: 'boolean', nullable };
    if (checker.isArrayType(t)) {
        const el = checker.getTypeArguments(t as ts.TypeReference)[0]!;
        return { kind: 'array', nullable, items: toShape(checker, el, seen) };
    }
    if (t.flags & ts.TypeFlags.Object) {
        if (checker.getIndexInfosOfType(t).length > 0 && checker.getPropertiesOfType(t).length === 0) {
            return { kind: 'object', nullable, record: true };
        }
        if (seen.includes(t)) return { kind: 'object', nullable, record: true };
        const props: NonNullable<Shape['props']> = {};
        for (const p of checker.getPropertiesOfType(t)) {
            const decl = p.valueDeclaration ?? p.declarations?.[0];
            if (!decl) continue;
            props[p.name] = {
                optional: (p.flags & ts.SymbolFlags.Optional) !== 0,
                shape: toShape(checker, checker.getTypeOfSymbolAtLocation(p, decl), [...seen, t]),
            };
        }
        return { kind: 'object', nullable, props };
    }
    return { kind: 'unknown', nullable };
}

function resolve(doc: Schema, s: Schema | undefined): Schema {
    let cur = s ?? {};
    for (let i = 0; cur.$ref && i < 20; i++) {
        const path = String(cur.$ref).replace(/^#\//, '').split('/');
        cur = path.reduce((n: any, k) => n?.[k], doc);
        if (!cur) throw new Error(`unresolvable $ref ${s?.$ref}`);
    }
    return cur;
}

/**
 * flattenUnion collapses a `oneOf`/`anyOf` of object branches into one
 * synthetic object schema, which is the faithful model of how this app's TS
 * types represent such a union: one interface with the fields of every branch,
 * each optional unless every branch requires it.
 *
 * Needed because an OpenAPI union node carries no `type` of its own, so
 * `compare` read it as "schema has no usable type" and the drift test went red
 * on `main` the moment `/auth/login`'s 200 `data` became
 * `oneOf: [LoginSuccessData, MFAChallengeData]` (the mfa_required branch, which
 * the response's own description documents as disambiguated by
 * `data.mfa_required`, never by status code).
 *
 * This does NOT weaken the comparison, which is the whole point:
 *  - properties: the UNION of all branches, so a TS field present in no branch
 *    at all is still reported as "declared in TS but not in the schema";
 *  - required: the INTERSECTION, so a field only some branches require is
 *    correctly optional — a non-optional TS field against it is still flagged
 *    as optionality drift, which is the right answer for a union;
 *  - each property's own type/enum/nullability is still compared, because the
 *    merged property schemas are the branches' own schemas.
 * A branch that is not an object (or a union mixing kinds) is deliberately NOT
 * merged — it falls through to the existing "no usable type" flag rather than
 * being silently accepted.
 */
function flattenUnion(doc: Schema, schema: Schema): Schema | undefined {
    const branches: Schema[] | undefined = schema.oneOf ?? schema.anyOf;
    if (!Array.isArray(branches) || branches.length === 0) return undefined;
    const resolved = branches.map((b) => resolve(doc, b));
    if (!resolved.every((b) => b.type === 'object' || b.properties)) return undefined;

    const properties: Schema = {};
    for (const b of resolved) {
        for (const [name, p] of Object.entries(b.properties ?? {})) {
            // First branch to declare a property wins. Two branches declaring the
            // SAME property with different schemas would make the merge lossy, so
            // surface it rather than pick silently.
            if (name in properties && JSON.stringify(properties[name]) !== JSON.stringify(p)) {
                return undefined;
            }
            properties[name] = p;
        }
    }
    const required = (resolved[0].required ?? []).filter((name: string) =>
        resolved.every((b) => (b.required ?? []).includes(name))
    );
    const nullable = resolved.some((b) => b.nullable === true);
    return { type: 'object', properties, required, ...(nullable ? { nullable: true } : {}) };
}

export type Locator =
    | { schema: string }
    | { response: string }
    | { op: { path: string; method: string; status?: string; request?: boolean }; at?: string[] };

export function locate(doc: Schema, loc: Locator): Schema {
    if ('schema' in loc) {
        const s = doc.components?.schemas?.[loc.schema];
        if (!s) throw new Error(`components.schemas.${loc.schema} not found in openapi.yaml`);
        return s;
    }
    if ('response' in loc) {
        const s = resolve(doc, doc.components?.responses?.[loc.response])?.content?.['application/json']?.schema;
        if (!s) throw new Error(`components.responses.${loc.response} has no application/json schema`);
        return s;
    }
    const { path, method, status = '200', request } = loc.op;
    const op = doc.paths?.[path]?.[method];
    if (!op) throw new Error(`${method.toUpperCase()} ${path} not found in openapi.yaml`);
    const body = request ? op.requestBody : op.responses?.[status];
    let s: Schema | undefined = resolve(doc, body)?.content?.['application/json']?.schema;
    if (!s)
        throw new Error(
            `${method.toUpperCase()} ${path} ${request ? 'request' : status} has no application/json schema`
        );
    for (const k of loc.at ?? []) {
        s = resolve(doc, s).properties?.[k];
        if (!s) throw new Error(`${method.toUpperCase()} ${path}: no property "${k}" on the path ${loc.at!.join('.')}`);
    }
    return s;
}

const KIND: Record<string, Shape['kind']> = {
    string: 'string',
    integer: 'number',
    number: 'number',
    boolean: 'boolean',
    array: 'array',
    object: 'object',
};

/**
 * The kinds of drift message `compare` can produce. An exemption names one
 * (path, kind) pair, so it silences exactly the message it describes and
 * nothing else on that path (#2868).
 */
export type DriftKind =
    | 'no-type' // the schema has no usable "type"
    | 'kind' // TS kind differs from the schema type
    | 'nullable' // TS and schema disagree on null
    | 'enum-not-union' // schema enum, TS is not a string-literal union
    | 'enum-mismatch' // both are enums, with different members
    | 'union-no-enum' // TS literal union, schema declares no enum
    | 'ts-only' // declared in TS, absent from the schema
    | 'schema-only' // in the schema, not declared in TS
    | 'optionality'; // optional/required disagree

/** Exemptions: key is `allowKey(path, kind)` (`<dotted field path>#<kind>`) -> reason. */
export type Allow = Record<string, string>;

export const allowKey = (path: string, kind: DriftKind): string => `${path}#${kind}`;

export function compare(
    doc: Schema,
    shape: Shape,
    rawSchema: Schema,
    at: string,
    allow: Allow,
    used: Set<string>,
    out: string[],
    request = false
): void {
    const resolved = resolve(doc, rawSchema);
    // A oneOf/anyOf of object branches is compared as the merged object the TS
    // side models it with; anything else passes through untouched.
    const schema = flattenUnion(doc, resolved) ?? resolved;
    // One drift message at one path. It is suppressed only by an exemption for
    // exactly this (path, kind); a matching exemption is recorded as used, any
    // other message on the same path is still reported (#2868).
    const flagAt = (path: string, driftKind: DriftKind, msg: string) => {
        const key = allowKey(path, driftKind);
        if (key in allow) used.add(key);
        else out.push(`${path}: ${msg}`);
    };
    const flag = (driftKind: DriftKind, msg: string) => flagAt(at, driftKind, msg);
    const kind = schema.type ? KIND[schema.type] : schema.properties ? 'object' : undefined;
    if (!kind) return flag('no-type', `schema has no usable "type"`);
    if (shape.kind !== kind) return flag('kind', `TS kind is ${shape.kind}, schema type is ${schema.type}`);
    if (shape.nullable !== (schema.nullable === true)) {
        flag(
            'nullable',
            `TS ${shape.nullable ? 'allows' : 'forbids'} null, schema nullable=${schema.nullable === true}`
        );
    }
    if (schema.enum) {
        const want = [...schema.enum].map(String).sort();
        if (!shape.literals) flag('enum-not-union', `schema enum [${want}] but TS is not a string-literal union`);
        else if (JSON.stringify(want) !== JSON.stringify(shape.literals)) {
            flag('enum-mismatch', `enum mismatch: TS [${shape.literals}] vs schema [${want}]`);
        }
    } else if (shape.literals) {
        flag('union-no-enum', `TS is a literal union [${shape.literals}] but the schema declares no enum`);
    }
    if (kind === 'array' && shape.items && schema.items) {
        compare(doc, shape.items, schema.items, `${at}[]`, allow, used, out, request);
    }
    if (kind === 'object' && shape.props && !shape.record) {
        const sProps: Schema = schema.properties ?? {};
        const required: string[] | undefined = schema.required;
        for (const [name, p] of Object.entries(shape.props)) {
            const here = `${at}.${name}`;
            if (!(name in sProps)) {
                flagAt(here, 'ts-only', 'declared in TS but not in the schema (the server never sends it)');
                continue;
            }
            // A request body may be stricter than the server demands (a TS-required
            // field the spec leaves optional is fine); only the reverse is drift.
            const optionalityDrift = request
                ? p.optional && required?.includes(name)
                : required && p.optional === required.includes(name);
            if (optionalityDrift) {
                flagAt(
                    here,
                    'optionality',
                    `TS ${p.optional ? 'optional' : 'required'} but schema ${required.includes(name) ? 'requires' : 'does not require'} it`
                );
            }
            compare(doc, p.shape, sProps[name], here, allow, used, out, request);
        }
        for (const name of Object.keys(sProps)) {
            if (name in shape.props) continue;
            flagAt(`${at}.${name}`, 'schema-only', 'sent by the server (in the schema) but not declared in TS');
        }
    }
}
