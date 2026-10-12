#!/usr/bin/env node
/**
 * Contract test: every apiClient.{get,post,put,patch,delete}(...) call in
 * src/services/*.ts must resolve to a real operation in
 * ../server/http/handlers/openapi.yaml, with a compatible HTTP method --
 * and, where the call site passes a plain object literal as its body, every
 * field the spec marks `required` on that operation's requestBody must be
 * among the literal's keys.
 *
 * Why this exists: #2441 shipped because web/src/services/mfa.ts's
 * activate(code) called `apiClient.post('/api/v1/auth/mfa/activate', { code
 * })` -- an object literal missing `password`, which the real handler
 * requires -- and nothing checked the call site against the contract. This
 * script is that check, run as its own step (see package.json's
 * check:api-contract), independent of whether a generated TS client is
 * actually wired into the calling file yet.
 *
 * Deliberately conservative to avoid false positives, not false negatives:
 *   - A path argument this script can't statically resolve to a literal
 *     template (e.g. a plain identifier/constant lookup like
 *     API_ENDPOINTS.ENVIRONMENTS.LIST) is reported as UNRESOLVED, not
 *     silently skipped and not failed -- see "no silent caps" in the
 *     summary output.
 *   - A body argument that isn't a plain object literal (a variable, a
 *     spread `{...x}`, a function call) skips the required-fields check for
 *     that call (can't prove which keys it has at build time) but still
 *     checks path+method existence.
 *
 * Known, already-tracked violations (a real bug already being fixed by a
 * different in-flight PR, or a pre-existing spec gap not yet closed) are
 * exempted via KNOWN_VIOLATIONS below -- same ratchet shape as
 * server/faultops's knownOpenTolerances: narrowly scoped, names the issue,
 * says when to remove it. A NEW violation not in that list fails the build.
 */

import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import ts from 'typescript';
import { load as loadYaml } from 'js-yaml';

const __dirname = dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = join(__dirname, '..');
const SPEC_PATH = join(WEB_ROOT, '..', 'server', 'http', 'handlers', 'openapi.yaml');
const SERVICES_DIR = join(WEB_ROOT, 'src', 'services');

// ---------------------------------------------------------------------------
// Known, already-tracked violations. Each entry is
// `${file} ${METHOD} ${path template}` -> { issue, reason }, e.g.
// 'secrets.ts POST /api/v1/secrets/{dyn}/transfer-ownership'. The template is
// the call's path as this script resolves it (every `${...}` interpolation
// becomes `{dyn}`, a query-string tail is dropped -- see resolvePathArg), so
// the key does not move when lines above the call are added or removed (it
// used to be file:LINE, which made every parallel PR touching a service file
// conflict). A violation at a call site with this key is downgraded from a
// failure to a logged pending-known entry. An entry tolerates exactly ONE
// call site with that key (`count`, default 1): a second call to the same
// file+method+path is a new call site and fails, as it did under file:LINE.
// Remove the entry once its issue is fixed -- main() fails the build if an
// entry here no longer corresponds to a real violation, so this list can't
// silently outlive the bug it names.
// ---------------------------------------------------------------------------
const SPEC_GAP_REASON =
    'Route is real (verified against server/http/router.go); it is just not yet added to ' +
    'openapi.yaml -- the same pre-existing "145 undocumented operations" backlog ADR-074 ' +
    'describes. Remove this entry once an operation is added for this path+method.';

const KNOWN_VIOLATIONS = {
    'admin.ts GET /api/v1/users/{dyn}/permissions': { issue: 'ADR-074', reason: SPEC_GAP_REASON },
    'admin.ts POST /api/v1/admin/jobs/anomaly-alerts': { issue: 'ADR-074', reason: SPEC_GAP_REASON },
    'admin.ts POST /api/v1/admin/jobs/rotation-reminders': { issue: 'ADR-074', reason: SPEC_GAP_REASON },
    'admin.ts POST /api/v1/admin/jobs/expiry-reminders': { issue: 'ADR-074', reason: SPEC_GAP_REASON },
    'admin.ts POST /api/v1/admin/jobs/compliance-digest': { issue: 'ADR-074', reason: SPEC_GAP_REASON },
    'connect.ts GET /api/v1/connect/connectors': { issue: 'ADR-074', reason: SPEC_GAP_REASON },
    'connect.ts POST /api/v1/connect/{dyn}/secret:read': { issue: 'ADR-074', reason: SPEC_GAP_REASON },
    'connect.ts GET /api/v1/connect/ref-grants': { issue: 'ADR-074', reason: SPEC_GAP_REASON },
    'connect.ts POST /api/v1/connect/ref-grants': { issue: 'ADR-074', reason: SPEC_GAP_REASON },
    'connect.ts DELETE /api/v1/connect/ref-grants/{dyn}': { issue: 'ADR-074', reason: SPEC_GAP_REASON },
    'license.ts GET /api/v1/license/status': { issue: 'ADR-074', reason: SPEC_GAP_REASON },
    'machineIdentities.ts PATCH /api/v1/projects/{dyn}/machine-identities/{dyn}/classification': {
        issue: 'ADR-074',
        reason: SPEC_GAP_REASON,
    },
    'machineIdentities.ts PATCH /api/v1/projects/{dyn}/machine-identities/{dyn}/tokens/{dyn}/classification': {
        issue: 'ADR-074',
        reason: SPEC_GAP_REASON,
    },
    'notificationChannels.ts GET /api/v1/notification-channels/{dyn}/retry-policy': {
        issue: 'ADR-074',
        reason: SPEC_GAP_REASON,
    },
    'notificationChannels.ts PUT /api/v1/notification-channels/{dyn}/retry-policy': {
        issue: 'ADR-074',
        reason: SPEC_GAP_REASON,
    },
    'rbac.ts GET /api/v1/groups/{dyn}/shared-secrets': { issue: 'ADR-074', reason: SPEC_GAP_REASON },
    'secrets.ts POST /api/v1/secrets/{dyn}/transfer-ownership': { issue: 'ADR-074', reason: SPEC_GAP_REASON },
    'users.ts POST /api/v1/users/{dyn}/unlock': { issue: 'ADR-074', reason: SPEC_GAP_REASON },
};

// ---------------------------------------------------------------------------
// Spec loading
// ---------------------------------------------------------------------------

function loadSpecOperations() {
    const doc = loadYaml(readFileSync(SPEC_PATH, 'utf8'));
    const operations = [];
    for (const [specPath, pathItem] of Object.entries(doc.paths ?? {})) {
        for (const method of ['get', 'post', 'put', 'patch', 'delete']) {
            const op = pathItem[method];
            if (!op) continue;
            const requestBody = op.requestBody?.content?.['application/json']?.schema;
            operations.push({
                method: method.toUpperCase(),
                specPath,
                segments: specPath.split('/').filter(Boolean),
                operationId: op.operationId ?? '(no operationId)',
                required: requestBody?.required ?? [],
            });
        }
    }
    return operations;
}

// A spec segment `{foo}` matches ANY call segment (literal or a resolved
// dynamic placeholder, see normalizeCallPath). A literal segment must match
// exactly.
function segmentsMatch(specSegments, callSegments) {
    if (specSegments.length !== callSegments.length) return false;
    return specSegments.every((specSeg, i) => {
        if (specSeg.startsWith('{') && specSeg.endsWith('}')) return true;
        return specSeg === callSegments[i];
    });
}

function findOperation(operations, method, callSegments) {
    return operations.find((op) => op.method === method && segmentsMatch(op.segments, callSegments));
}

// ---------------------------------------------------------------------------
// Call-site extraction (TypeScript AST)
// ---------------------------------------------------------------------------

const HTTP_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete']);

/**
 * Resolves a call's first argument (the path) to a normalized path template
 * ("/api/v1/projects/{dyn}/members") usable for structural matching against
 * spec segments, or returns { unresolved: true } if the argument isn't a
 * literal/template this script can read statically.
 *
 * Works on raw source text rather than full semantic evaluation: every
 * `${...}` interpolation becomes a `{dyn}` placeholder segment, UNLESS its
 * own source text contains a quoted `?` (the query-string-ternary pattern
 * seen in this codebase, e.g. `includeDeleted ? '?include_deleted=true' :
 * ''`), in which case that interpolation and everything after it in the
 * template is treated as a query string and dropped -- OpenAPI paths never
 * include the query string, that's declared separately as `parameters`.
 */
function resolvePathArg(node, sourceFile) {
    if (ts.isStringLiteralLike(node) && !ts.isTemplateExpression(node)) {
        return { template: node.text };
    }
    if (ts.isNoSubstitutionTemplateLiteral(node)) {
        return { template: node.text };
    }
    if (ts.isTemplateExpression(node)) {
        let out = node.head.text;
        for (const span of node.templateSpans) {
            const exprText = span.expression.getText(sourceFile);
            if (/['"]\?/.test(exprText)) {
                // Query-string ternary (or similar) -- stop here, drop the rest.
                return { template: out };
            }
            out += '{dyn}' + span.literal.text;
        }
        return { template: out };
    }
    return { unresolved: true, text: node.getText(sourceFile) };
}

function objectLiteralKeys(node, sourceFile) {
    const keys = new Set();
    for (const prop of node.properties) {
        if (ts.isSpreadAssignment(prop)) {
            return { unresolved: true, text: node.getText(sourceFile) };
        }
        if (ts.isShorthandPropertyAssignment(prop) || ts.isPropertyAssignment(prop)) {
            const name = prop.name;
            if (ts.isIdentifier(name) || ts.isStringLiteral(name)) {
                keys.add(name.text);
                continue;
            }
        }
        // A computed property name, method shorthand, etc. -- can't read
        // statically; be conservative rather than silently assume complete.
        return { unresolved: true, text: node.getText(sourceFile) };
    }
    return { keys };
}

/**
 * Resolves a call's second argument to a Set of literal property keys
 * representing the request BODY, or returns { unresolved: true } when it
 * isn't a plain object literal with statically-readable keys (a spread
 * element, a variable, a call expression, computed keys, etc.) -- in which
 * case the required-fields check is skipped for this call, but path/method
 * checks still run.
 *
 * For DELETE, axios takes a body via a RequestConfig's `data` property
 * (`apiClient.delete(url, { data: {...} })`), not a bare object literal --
 * unwrap that one level before reading keys. A DELETE call with a config
 * object that has no `data` property genuinely has no body.
 */
function resolveBodyKeys(node, method, sourceFile) {
    if (!node) return { keys: new Set() }; // no second arg at all -- nothing required
    if (!ts.isObjectLiteralExpression(node)) {
        return { unresolved: true, text: node.getText(sourceFile) };
    }
    if (method === 'DELETE') {
        const dataProp = node.properties.find(
            (p) => ts.isPropertyAssignment(p) && ts.isIdentifier(p.name) && p.name.text === 'data'
        );
        if (!dataProp) return { keys: new Set() }; // a plain config object (e.g. {params}) -- no body
        if (!ts.isObjectLiteralExpression(dataProp.initializer)) {
            return { unresolved: true, text: node.getText(sourceFile) };
        }
        return objectLiteralKeys(dataProp.initializer, sourceFile);
    }
    return objectLiteralKeys(node, sourceFile);
}

function extractCallSites(filePath, textOverride) {
    const text = textOverride ?? readFileSync(filePath, 'utf8');
    const sourceFile = ts.createSourceFile(filePath, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
    const callSites = [];

    function visit(node) {
        if (
            ts.isCallExpression(node) &&
            ts.isPropertyAccessExpression(node.expression) &&
            ts.isIdentifier(node.expression.expression) &&
            node.expression.expression.text === 'apiClient' &&
            HTTP_METHODS.has(node.expression.name.text)
        ) {
            const method = node.expression.name.text.toUpperCase();
            const line = sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
            const pathArg = node.arguments[0];
            const bodyArg = method === 'GET' ? undefined : node.arguments[1];
            callSites.push({
                file: filePath,
                line,
                method,
                path: pathArg ? resolvePathArg(pathArg, sourceFile) : { unresolved: true, text: '(no path arg)' },
                body: resolveBodyKeys(bodyArg, method, sourceFile),
            });
        }
        ts.forEachChild(node, visit);
    }
    visit(sourceFile);
    return callSites;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

/**
 * The stable identity of a call site for KNOWN_VIOLATIONS: file + HTTP method
 * + resolved path template. Deliberately has no line number.
 */
function siteKey(baseName, site) {
    return `${baseName} ${site.method} ${site.path.template}`;
}

/**
 * Pure core of the check. `files` is [{ baseName, sites }] (sites as returned
 * by extractCallSites); `known` is a KNOWN_VIOLATIONS-shaped map. Returns the
 * failures and log lines instead of printing/exiting so the test file can
 * drive it with synthetic inputs.
 */
function evaluate(files, operations, known) {
    let resolvedCount = 0;
    let unresolvedPathCount = 0;
    let unresolvedBodyCount = 0;
    const failures = [];
    const logs = [];
    const seen = new Map(); // key -> number of violating call sites tolerated or seen

    // Tolerates a violating call site if its key has an entry with room left;
    // otherwise records a failure. Returns nothing.
    const report = (key, where, message, kv) => {
        const n = (seen.get(key) ?? 0) + 1;
        seen.set(key, n);
        if (kv && n <= (kv.count ?? 1)) {
            logs.push(`[api-contract] KNOWN (${kv.issue}) ${key}: ${message} -- ${kv.reason}`);
            return;
        }
        failures.push(
            kv
                ? `${where} (${key}): ${message} -- more call sites than the ${kv.count ?? 1} KNOWN_VIOLATIONS tolerates for this key`
                : `${where} (${key}): ${message}`
        );
    };

    for (const { baseName, sites } of files) {
        for (const site of sites) {
            if (site.path.unresolved) {
                unresolvedPathCount++;
                continue;
            }
            resolvedCount++;

            const key = siteKey(baseName, site);
            const where = `${baseName}:${site.line}`; // for humans only; never a lookup key
            const callSegments = site.path.template.split('/').filter(Boolean);
            const op = findOperation(operations, site.method, callSegments);
            const kv = known[key];

            if (!op) {
                report(
                    key,
                    where,
                    `${site.method} "${site.path.template}" does not match any operation in openapi.yaml`,
                    kv
                );
                continue;
            }

            if (op.required.length === 0) continue; // nothing required -- no body check needed
            if (site.body.unresolved) {
                unresolvedBodyCount++;
                continue; // can't prove the body's keys statically; don't guess
            }
            const missing = op.required.filter((f) => !site.body.keys.has(f));
            if (missing.length > 0) {
                report(
                    key,
                    where,
                    `${op.operationId} requires [${op.required.join(', ')}] but the call's object literal is missing [${missing.join(', ')}]`,
                    kv
                );
            }
        }
    }

    // A KNOWN_VIOLATIONS entry with no violating call site left (fixed, or
    // the call was removed/rewritten) is stale -- fail loudly rather than let
    // an exemption silently outlive its bug.
    for (const k of Object.keys(known)) {
        if (!seen.has(k)) {
            failures.push(
                `${k}: listed in KNOWN_VIOLATIONS (${known[k].issue}) but no longer reproduces -- remove the stale entry`
            );
        }
    }

    return { failures, logs, resolvedCount, unresolvedPathCount, unresolvedBodyCount };
}

function main() {
    const operations = loadSpecOperations();
    const serviceFiles = readdirSync(SERVICES_DIR)
        .filter((f) => f.endsWith('.ts') && !f.endsWith('.test.ts'))
        .map((f) => join(SERVICES_DIR, f));

    const files = serviceFiles.map((file) => ({ baseName: file.split('/').pop(), sites: extractCallSites(file) }));
    const { failures, logs, resolvedCount, unresolvedPathCount, unresolvedBodyCount } = evaluate(
        files,
        operations,
        KNOWN_VIOLATIONS
    );
    for (const l of logs) console.log(l);

    console.log(
        `[api-contract] checked ${resolvedCount} resolved call site(s) across ${serviceFiles.length} service file(s); ` +
            `${unresolvedPathCount} call site(s) had an unresolvable path argument (skipped, not failed); ` +
            `${unresolvedBodyCount} had an unresolvable body argument (path/method checked, required-fields check skipped).`
    );

    if (failures.length > 0) {
        console.error(`[api-contract] FAIL -- ${failures.length} violation(s):`);
        for (const f of failures) console.error(`  - ${f}`);
        process.exit(1);
    }
    console.log('[api-contract] OK');
}

// Only run as a real check when invoked directly (`node
// scripts/check-api-contract.mjs`), not when imported by
// check-api-contract.test.mjs for the exported functions below.
if (import.meta.url === `file://${process.argv[1]}`) {
    main();
}

export {
    loadSpecOperations,
    segmentsMatch,
    findOperation,
    resolvePathArg,
    resolveBodyKeys,
    extractCallSites,
    siteKey,
    evaluate,
    KNOWN_VIOLATIONS,
};
