#!/usr/bin/env node
/**
 * Fails the build if src/types/api-generated.ts is stale relative to
 * ../server/http/handlers/openapi.yaml -- i.e. someone edited the spec (or
 * the committed generated file) without re-running `pnpm generate:api-types`.
 * Regenerates into a scratch path and diffs against the committed file byte
 * for byte, rather than trusting a timestamp or a hand-maintained hash, since
 * either of those can drift independently of the actual content.
 */

import { execFileSync } from 'node:child_process';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const COMMITTED_PATH = 'src/types/api-generated.ts';

let committed;
try {
    committed = readFileSync(COMMITTED_PATH, 'utf8');
} catch (err) {
    console.error('[api-types] could not read %s:', COMMITTED_PATH, err.message);
    console.error('[api-types] run `pnpm generate:api-types` and commit the result.');
    process.exit(1);
}

const scratchDir = mkdtempSync(join(tmpdir(), 'api-types-fresh-'));
const scratchPath = join(scratchDir, 'api-generated.ts');

try {
    execFileSync('pnpm', ['exec', 'openapi-typescript', '../server/http/handlers/openapi.yaml', '-o', scratchPath], {
        stdio: ['ignore', 'ignore', 'inherit'],
    });

    const fresh = readFileSync(scratchPath, 'utf8');

    if (fresh !== committed) {
        console.error(`[api-types] ${COMMITTED_PATH} is STALE relative to server/http/handlers/openapi.yaml.`);
        console.error('[api-types] run `pnpm generate:api-types` in web/ and commit the result.');
        process.exit(1);
    }

    console.log(`[api-types] ${COMMITTED_PATH} is up to date with openapi.yaml.`);
} finally {
    rmSync(scratchDir, { recursive: true, force: true });
}
