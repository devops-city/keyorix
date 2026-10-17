#!/usr/bin/env node
/**
 * Generates a production-only CycloneDX SBOM for web/, for embedding
 * coverage of the dashboard baked into keyorix-server via go:embed
 * (ADR-073). Usage: node scripts/build-frontend-sbom.mjs <output-file>
 *
 * Two tools, two failure modes ADR-073 measured against the real files:
 *   - cdxgen must run with NO --type flag. `--type npm` silently drops to
 *     scanning package.json's direct dependencies only (47 components) —
 *     no error, just wrong. Autodetection correctly parses pnpm-lock.yaml
 *     for full transitive resolution (478 components, matching `pnpm list`
 *     exactly).
 *   - cdxgen's own --required-only / scope inference is not production-
 *     accurate for this project (it included eslint and eslint plugins in
 *     a real test run). Production scope is derived here from
 *     `pnpm list --prod`, not from cdxgen's own classification.
 *
 * Filtering the component list alone leaves the `dependencies` graph
 * referencing removed components — schema-valid but semantically broken
 * (471 dangling `dependsOn` entries in ADR-073's own test). This script
 * prunes both.
 */

import {
    accessSync,
    constants as fsConstants,
    existsSync,
    readFileSync,
    writeFileSync,
    unlinkSync,
} from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

function fail(message) {
    console.error(`[frontend-sbom] FAIL: ${message}`);
    process.exit(1);
}

// Sonar S4036: don't let execFileSync search process.env.PATH blindly for
// an executable by bare name. Resolve it ourselves instead, for two
// distinct reasons:
//   1. Reject relative/implicit PATH entries outright (e.g. a bare "."),
//      the classic PATH-injection vector: whoever controls the current
//      working directory controls what runs. Every candidate here must be
//      an absolute, fixed directory.
//   2. Among absolute candidates, PREFER one sitting in a directory this
//      process cannot write to -- if a directory earlier in PATH is
//      writable by us, an attacker with the same privileges could shadow
//      "cdxgen"/"pnpm" there.
//
// (2) is a preference, not a hard requirement, deliberately: GitHub-hosted
// runners make /usr/local/bin (where `npm install -g`/corepack-installed
// pnpm actually land -- verified locally in a standard Node image) legally
// writable by the `runner` user precisely so setup actions can install
// there without sudo. A hard "must be unwriteable" requirement would
// reject that legitimate install and break the script in the exact CI
// environment it needs to run in. A fixed directory allowlist was also
// considered and rejected: pnpm/action-setup's actual install location is
// a versioned runner tool-cache path that isn't reliably predictable.
function resolveTrusted(cmd) {
    const dirs = (process.env.PATH ?? '').split(delimiter).filter(Boolean);
    let writableMatch;
    for (const dir of dirs) {
        if (!dir.startsWith(sep)) continue; // reject relative/implicit entries
        const candidate = `${dir}${sep}${cmd}`;
        if (!existsSync(candidate)) continue;
        try {
            accessSync(dir, fsConstants.W_OK);
            // Writable by us -- usable, but not preferred; keep looking for
            // a better (non-writable-directory) match before falling back.
            writableMatch ??= candidate;
        } catch {
            // Not writable by us -- the preferred, trustworthy case.
            return candidate;
        }
    }
    if (writableMatch) return writableMatch;
    fail(`could not find "${cmd}" in any fixed (absolute) PATH directory`);
    return undefined; // unreachable -- fail() exits the process
}

// Sonar: validate a user-supplied output path before it ever reaches the
// file system, rather than trusting argv directly -- a future caller
// (human or automated) passing an unexpected value (e.g. path traversal
// like "../../../etc/cron.d/x") should get a clear error here, not a
// write wherever that path happens to resolve. Scoped to "must resolve
// somewhere inside the repository root", computed from this script's own
// location (not process.cwd(), which varies -- the Makefile invokes this
// from web/) so the check holds regardless of the caller's cwd.
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');

function validatedOutputPath(rawArg) {
    if (!rawArg) {
        console.error('[frontend-sbom] usage: build-frontend-sbom.mjs <output-file>');
        process.exit(1);
        return undefined; // unreachable -- process.exit() above halts the script
    }
    const resolved = resolve(rawArg);
    if (resolved !== repoRoot && !resolved.startsWith(repoRoot + sep)) {
        fail(`output path resolves outside the repository (${repoRoot}): ${resolved}`);
        return undefined; // unreachable -- fail() exits the process
    }
    return resolved;
}

const outputFile = validatedOutputPath(process.argv[2]);

// 1. Full transitive SBOM via cdxgen, autodetected (no --type — see header).
const rawSbomFile = join(tmpdir(), `cdxgen-raw-${process.pid}.json`);
try {
    execFileSync(
        resolveTrusted('cdxgen'),
        ['--spec-version', '1.6', '--output', rawSbomFile, '.'],
        { stdio: ['ignore', 'ignore', 'inherit'] },
    );
} catch (err) {
    fail(`cdxgen invocation failed: ${err.message}`);
}

let bom;
try {
    bom = JSON.parse(readFileSync(rawSbomFile, 'utf8'));
} catch (err) {
    fail(`could not parse cdxgen output: ${err.message}`);
} finally {
    try {
        unlinkSync(rawSbomFile);
    } catch {
        // best-effort cleanup
    }
}

if (bom.bomFormat !== 'CycloneDX' || bom.specVersion !== '1.6') {
    fail(`cdxgen produced unexpected bomFormat/specVersion: ${bom.bomFormat} ${bom.specVersion}`);
}

// 2. Production-only package set, ground truth from pnpm itself.
let prodTree;
try {
    const raw = execFileSync(
        resolveTrusted('pnpm'),
        ['list', '--prod', '--depth', 'Infinity', '--json'],
        { encoding: 'utf8' },
    );
    prodTree = JSON.parse(raw);
} catch (err) {
    fail(`\`pnpm list --prod --depth Infinity --json\` failed: ${err.message}`);
}

const prodKeys = new Set();
function collect(node) {
    for (const key of ['dependencies', 'devDependencies', 'optionalDependencies']) {
        const deps = node[key];
        if (!deps) continue;
        for (const [name, info] of Object.entries(deps)) {
            prodKeys.add(`${name}@${info.version}`);
            collect(info);
        }
    }
}
for (const pkg of prodTree) collect(pkg);

if (prodKeys.size === 0) {
    fail('pnpm reported zero production dependencies — refusing to emit a suspiciously empty SBOM');
}

// 3. Filter components to the production set. Match on group+name+version
//    (purl), not name alone — scoped packages (@radix-ui/*, etc.) report
//    group and name as separate fields, and a name-only match silently
//    drops every scoped production package (73 of 125 in ADR-073's test).
function componentKey(c) {
    const name = c.group ? `${c.group}/${c.name}` : c.name;
    return `${name}@${c.version}`;
}

const allComponents = bom.components ?? [];
const keptRefs = new Set();
const kept = [];
for (const c of allComponents) {
    if (prodKeys.has(componentKey(c))) {
        kept.push(c);
        if (c['bom-ref']) keptRefs.add(c['bom-ref']);
    }
}

// Fail loudly on any mismatch between the two sources of truth, rather than
// silently shipping an under- or over-counted SBOM.
if (kept.length !== prodKeys.size) {
    const keptKeys = new Set(kept.map(componentKey));
    const missing = [...prodKeys].filter(k => !keptKeys.has(k));
    fail(
        `production package count mismatch: pnpm reports ${prodKeys.size}, matched ${kept.length} ` +
            `in cdxgen output. Missing from cdxgen output: ${missing.join(', ') || '(none — duplicate match?)'}`,
    );
}

// 4. Prune the dependency graph too — not just the component list — or
//    every remaining node keeps `dependsOn` entries pointing at removed
//    dev components (471 dangling refs, unpruned, in ADR-073's test).
const rootRef = bom.metadata?.component?.['bom-ref'];
if (rootRef) keptRefs.add(rootRef);

const prunedDependencies = (bom.dependencies ?? [])
    .filter(dep => keptRefs.has(dep.ref))
    .map(dep => ({
        ...dep,
        dependsOn: (dep.dependsOn ?? []).filter(ref => keptRefs.has(ref)),
    }));

// 5. cdxgen records where each package sits on the build machine
//    (`LocalNodeModulesPath`, an absolute path). That is not part of the
//    component's identity and would publish the builder's directory layout in
//    a release artifact, so drop every property whose value starts with the
//    repository root and refuse to write anything that still mentions it.
for (const c of kept) {
    if (Array.isArray(c.properties)) {
        c.properties = c.properties.filter(p => !(typeof p.value === 'string' && p.value.startsWith(repoRoot)));
        if (c.properties.length === 0) delete c.properties;
    }
}

bom.components = kept;
bom.dependencies = prunedDependencies;

if (JSON.stringify(bom).includes(repoRoot)) {
    fail(`SBOM still contains the build machine's path (${repoRoot}); refusing to write it`);
}

writeFileSync(outputFile, JSON.stringify(bom, null, 2));
console.log(`[frontend-sbom] wrote ${outputFile}: ${kept.length} production components`);
