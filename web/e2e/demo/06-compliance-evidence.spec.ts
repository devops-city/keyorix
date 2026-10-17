// web/e2e/demo/06-compliance-evidence.spec.ts -- DEMO-E2E-1 journey 6 of 8: the auditor's evidence. The
// demo's compliance act: download the control matrix from the Compliance page, export the signed
// evidence pack, verify the file you hold, and see a tampered copy refused.
//
// WHAT IT GUARDS:
//   1. the Compliance page's "Download CSV" really delivers a file (compliance-controls.csv) with the
//      control matrix, including the "Tamper-evident audit trail" control and its pass/gap status;
//   2. GET /api/v1/compliance/evidence returns a SIGNED pack (signed: true, a canonical filename, a
//      detached signature) whose audit anchor says the chain is valid and checkpointed;
//   3. the pack, written to disk and read back byte for byte, VERIFIES (valid: true);
//   4. one flipped byte, or the right bytes under another filename, is REFUSED (valid: false) -- the
//      negative controls: a verifier that said "valid" to everything would pass step 3;
//   5. the verification itself is audited (compliance.evidence_verified, naming the file and the verdict).
//
// There is no UI control for the evidence pack: it is exported by `keyorix compliance export` and the API
// (this journey drives the API, like the CLI does) and the console offers the control matrix as a CSV.
// The verify request must carry the pack's canonical `filename` -- the signature is bound to it (AUD-009);
// the OpenAPI schema for the verify request does not list that field yet, which this journey reports in
// the PR rather than papers over.
//
// LOGIN BUDGET: harness 1 + admin API 1 + admin UI 1 = 3 of 10.
import { test, expect } from '@playwright/test';
import { readFileSync, writeFileSync } from 'node:fs';
import { ADMIN_PASSWORD, ADMIN_USERNAME, apiLogin, bearer, mustBearer, realLogin } from './support';

test('the control matrix downloads, the evidence pack verifies from disk, and a tampered copy is refused', async ({
    page,
}, testInfo) => {
    test.setTimeout(90_000);
    const adminToken = await apiLogin(ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
    await realLogin(page, ADMIN_USERNAME as string, ADMIN_PASSWORD as string);

    // 1. The Compliance page's CSV download.
    await page.goto('/compliance');
    await expect(page.getByRole('heading', { name: 'Compliance mapping reports' })).toBeVisible({ timeout: 20_000 });
    const downloading = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Download CSV' }).click();
    const download = await downloading;
    expect(download.suggestedFilename()).toBe('compliance-controls.csv');
    const csvPath = testInfo.outputPath('compliance-controls.csv');
    await download.saveAs(csvPath);
    const csv = readFileSync(csvPath, 'utf8').split('\n');
    expect(csv[0], 'the CSV starts with its column header').toMatch(/^id,name,area,status,detail,/);
    expect(csv.length, 'the CSV lists the controls, not just a header').toBeGreaterThan(5);
    const anchorLine = csv.find((l) => l.includes('Tamper-evident audit trail'));
    expect(anchorLine, 'the matrix must include the tamper-evident audit trail control').toBeTruthy();
    expect(anchorLine).toMatch(/,(pass|gap),/);

    // 2. Export the signed evidence pack and keep it as files, as `keyorix compliance export` does.
    const exported = (await mustBearer(adminToken, 'GET', '/api/v1/compliance/evidence')).data as {
        filename: string;
        data_b64: string;
        signature: string;
        signed: boolean;
    };
    expect(exported.signed, 'the pack must be signed (encryption is initialised on this server)').toBe(true);
    expect(exported.filename).toMatch(/^keyorix-evidence-\d{8}T\d{6}Z\.json$/);
    expect(exported.signature).toMatch(/^[^:]+:[0-9a-f]{64}$/);
    const packPath = testInfo.outputPath(exported.filename);
    const sigPath = `${packPath}.sig`;
    writeFileSync(packPath, Buffer.from(exported.data_b64, 'base64'));
    writeFileSync(sigPath, exported.signature);

    const pack = JSON.parse(readFileSync(packPath, 'utf8'));
    expect(pack.generated_at).toBeTruthy();
    expect(pack.audit_anchor.valid, 'the evidence pack must say the audit chain verifies').toBe(true);
    expect(pack.audit_anchor.checkpointed).toBe(true);
    expect(pack.audit_anchor.chained_events).toBeGreaterThan(0);

    // 3. Verify what is on disk, not what the server still has in memory.
    const verify = (bytes: Buffer, filename: string) =>
        bearer(adminToken, 'POST', '/api/v1/compliance/evidence/verify', {
            data_b64: bytes.toString('base64'),
            signature: readFileSync(sigPath, 'utf8'),
            filename,
        });
    const onDisk = readFileSync(packPath);
    const good = await verify(onDisk, exported.filename);
    expect(good.status).toBe(200);
    expect(good.body.data.valid, JSON.stringify(good.body.data)).toBe(true);
    expect(good.body.data.key_version).toBe(good.body.data.current_version);

    // 4. Negative controls: a single changed byte, and the right bytes under another name.
    const tampered = Buffer.from(onDisk);
    tampered[10] = (tampered[10] ?? 0) ^ 0x01;
    const bad = await verify(tampered, exported.filename);
    expect(bad.status).toBe(200);
    expect(bad.body.data.valid, 'a one-byte change must be refused').toBe(false);
    expect(bad.body.data.reason).toMatch(/modified|signature does not match/);

    const renamed = await verify(onDisk, 'keyorix-evidence-19700101T000000Z.json');
    expect(renamed.body.data.valid, 'the signature is bound to the filename').toBe(false);

    // 5. The verification is in the audit log, with the verdict.
    const logs = await bearer(adminToken, 'GET', '/api/v1/audit/logs?page_size=100');
    const verified = (logs.body.data.logs as { event_type: string; description: string }[]).filter(
        (l) => l.event_type === 'compliance.evidence_verified' && l.description.includes(exported.filename)
    );
    expect(verified.map((l) => /valid=(true|false)/.exec(l.description)?.[1]).sort()).toEqual(['false', 'true']);
});
