import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '../../../test/test-utils';
import { CompliancePage } from '../CompliancePage';
import { complianceApi } from '../../../services/compliance';

vi.mock('../../../services/compliance', () => ({
    complianceApi: {
        getPosture: vi.fn(),
        getControls: vi.fn(),
        getSoDViolations: vi.fn(),
        getDigest: vi.fn(),
        placeLegalHold: vi.fn(),
        liftLegalHold: vi.fn(),
        getRiskExceptions: vi.fn(),
        createRiskException: vi.fn(),
        revokeRiskException: vi.fn(),
    },
}));

const mockGet = vi.fn();
vi.mock('../../../services/client', () => ({
    apiClient: { get: (...args: any[]) => mockGet(...args) },
}));

const emptyMatrix = {
    generatedAt: '2026-06-14T10:00:00Z',
    summary: { total: 0, pass: 0, gap: 0, notConfigured: 0 },
    controls: [],
};

const posture = {
    generatedAt: '2026-06-14T10:00:00Z',
    auditIntegrity: { chainVerified: true, chainedEvents: 12, checkpointed: true },
    accessGovernance: {
        projects: 4,
        projectsWithOpenCampaign: 1,
        projectsNeverReviewed: 1,
        openCampaigns: 1,
        pendingItems: 3,
        projectsOverdue: 7,
        dormantRoleGrants: 2,
        sodViolations: 1,
    },
    rotation: { coveredSecrets: 10, overdue: 1, dueSoon: 2 },
    identity: { activeUsers: 5, usersWithSecondFactor: 4, secondFactorPercent: 80 },
    emergencyAccess: { activeActivations: 0, totalActivations: 1 },
    classification: { totalSecrets: 12, public: 1, internal: 4, confidential: 1, restricted: 6, unclassified: 0 },
    anomalies: { unacknowledged: 3, highSeverityOpen: 1 },
    legalHold: { active: false, reason: '' },
    retention: {
        enabled: true,
        anomalyAlertsDays: 90,
        closedAccessReviewsDays: 730,
        breakGlassDays: 365,
        resolvedAccessRequestsDays: 0,
    },
};

describe('CompliancePage posture panel', () => {
    afterEach(() => {
        vi.useRealTimers();
    });

    beforeEach(() => {
        vi.clearAllMocks();
        (complianceApi.getSoDViolations as any).mockResolvedValue([]);
        (complianceApi.getControls as any).mockResolvedValue(emptyMatrix);
        (complianceApi.getRiskExceptions as any).mockResolvedValue([]);
        // Digest hidden by default (403-like); the digest test overrides this.
        (complianceApi.getDigest as any).mockRejectedValue({ response: { status: 403 } });
        // jsdom has no object-URL API; stub it for the CSV download.
        (URL as any).createObjectURL = vi.fn(() => 'blob:mock');
        (URL as any).revokeObjectURL = vi.fn();
    });

    it('renders the live posture tiles when the report loads', async () => {
        (complianceApi.getPosture as any).mockResolvedValue(posture);
        render(<CompliancePage />);

        expect(await screen.findByText('Controls posture')).toBeInTheDocument();
        expect(screen.getByText('80%')).toBeInTheDocument(); // second-factor coverage
        expect(screen.getByText('3/4')).toBeInTheDocument(); // projects reviewed
        expect(screen.getByText('2')).toBeInTheDocument(); // dormant role grants
        expect(screen.getByText('0 / 12')).toBeInTheDocument(); // unclassified / total secrets
        expect(screen.getByText('3 (1 high)')).toBeInTheDocument(); // open anomalies (1 high-severity)
        expect(screen.getByText('7')).toBeInTheDocument(); // projects overdue for recert
        // Data-retention section: configured windows, "Keep" for a 0 window.
        expect(screen.getByText(/Data retention .* enforced/i)).toBeInTheDocument();
        expect(screen.getByText('90d')).toBeInTheDocument(); // anomaly-alerts window
        expect(screen.getByText('Keep')).toBeInTheDocument(); // resolved-requests window = 0
        // The static regulatory cards still render below.
        expect(screen.getByText('NIS2 Directive')).toBeInTheDocument();
    });

    it('lists separation-of-duties violations when present', async () => {
        (complianceApi.getPosture as any).mockResolvedValue(posture);
        (complianceApi.getSoDViolations as any).mockResolvedValue([
            {
                policyName: 'approve-vs-admin',
                username: 'alice',
                email: 'a@x.io',
                permissionA: 'roles.assign',
                permissionB: 'secrets.delete',
            },
        ]);
        render(<CompliancePage />);

        expect(await screen.findByText(/Separation-of-duties violations \(1\)/i)).toBeInTheDocument();
        expect(screen.getByText('alice (a@x.io)')).toBeInTheDocument();
        expect(screen.getByText('roles.assign + secrets.delete')).toBeInTheDocument();
    });

    it('shows a legal-hold banner when a hold is active', async () => {
        (complianceApi.getPosture as any).mockResolvedValue({
            ...posture,
            legalHold: { active: true, reason: 'litigation INC-7' },
        });
        render(<CompliancePage />);
        expect(await screen.findByText(/Legal hold active/i)).toBeInTheDocument();
        expect(screen.getByText(/litigation INC-7/)).toBeInTheDocument();
    });

    it('shows an admin-only note when the caller lacks system.read (403)', async () => {
        (complianceApi.getPosture as any).mockRejectedValue({ response: { status: 403 } });
        render(<CompliancePage />);
        expect(await screen.findByText(/available to administrators/i)).toBeInTheDocument();
    });

    it('renders the compliance mapping reports panel and shows the ENS section card', async () => {
        (complianceApi.getPosture as any).mockResolvedValue(posture);
        render(<CompliancePage />);

        expect(await screen.findByText(/Compliance mapping reports/i)).toBeInTheDocument();
        expect(screen.getByText(/ENS \(Esquema Nacional de Seguridad\)/i)).toBeInTheDocument();
    });

    it('renders the control matrix with status and framework refs', async () => {
        (complianceApi.getPosture as any).mockResolvedValue(posture);
        (complianceApi.getControls as any).mockResolvedValue({
            generatedAt: '2026-06-14T10:00:00Z',
            summary: { total: 2, pass: 1, gap: 1, notConfigured: 0 },
            controls: [
                {
                    id: 'sep',
                    name: 'Separation of duties',
                    area: 'Access governance',
                    status: 'gap',
                    detail: '1 SoD violation',
                    frameworks: { iso27001: ['A.5.3'], soc2: ['CC5.1'], nis2: [], dora: ['Art.5'], ens: ['op.acc.3'] },
                },
                {
                    id: 'mfa',
                    name: 'Second-factor coverage',
                    area: 'Identity',
                    status: 'pass',
                    detail: '100% covered',
                    frameworks: { iso27001: ['A.5.17'], soc2: [], nis2: [], dora: [], ens: [] },
                },
            ],
        });
        render(<CompliancePage />);

        expect(await screen.findByText(/Compliance mapping reports/i)).toBeInTheDocument();
        expect(screen.getByText('2 controls · 1 pass · 1 gap')).toBeInTheDocument();
        expect(screen.getByText(/Separation of duties/)).toBeInTheDocument();
        expect(screen.getByText('ISO A.5.3 · SOC2 CC5.1 · DORA Art.5 · ENS op.acc.3')).toBeInTheDocument();
    });

    it('downloads the control matrix as a CSV blob', async () => {
        (complianceApi.getPosture as any).mockResolvedValue(posture);
        (complianceApi.getControls as any).mockResolvedValue({
            generatedAt: '2026-06-14T10:00:00Z',
            summary: { total: 1, pass: 1, gap: 0, notConfigured: 0 },
            controls: [
                {
                    id: 'mfa',
                    name: 'Second-factor coverage',
                    area: 'Identity',
                    status: 'pass',
                    detail: 'ok',
                    frameworks: { iso27001: ['A.5.17'], soc2: [], nis2: [], dora: [], ens: [] },
                },
            ],
        });
        mockGet.mockResolvedValue({ data: new Blob(['id,name\n'], { type: 'text/csv' }) });
        render(<CompliancePage />);

        fireEvent.click(await screen.findByRole('button', { name: /download csv/i }));
        await waitFor(() =>
            expect(mockGet).toHaveBeenCalledWith('/api/v1/compliance/controls.csv', { responseType: 'blob' })
        );
        expect((URL as any).createObjectURL).toHaveBeenCalled();
    });

    it('renders the on-demand compliance digest with a copy button', async () => {
        (complianceApi.getPosture as any).mockResolvedValue(posture);
        (complianceApi.getDigest as any).mockResolvedValue({
            title: 'Keyorix compliance digest — 1 gap across 11 controls',
            body: 'Controls: 10 pass, 1 gap (of 11).\nClassification: 0 of 12 secrets unclassified.',
        });
        const writeText = vi.fn();
        Object.assign(navigator, { clipboard: { writeText } });
        render(<CompliancePage />);

        expect(await screen.findByText('Compliance digest')).toBeInTheDocument();
        expect(screen.getByText(/1 gap across 11 controls/)).toBeInTheDocument();
        expect(screen.getByText(/10 pass, 1 gap/)).toBeInTheDocument();

        screen.getByRole('button', { name: /copy/i }).click();
        expect(writeText).toHaveBeenCalledWith(expect.stringContaining('Keyorix compliance digest'));
    });

    it('lists active risk exceptions in the register', async () => {
        (complianceApi.getPosture as any).mockResolvedValue(posture);
        (complianceApi.getRiskExceptions as any).mockResolvedValue([
            {
                id: 1,
                title: 'accept SoD during cutover',
                category: 'sod',
                reference: 'alice',
                justification: 'temporary',
                status: 'active',
                expiresAt: '2026-12-31T00:00:00Z',
                createdBy: 9,
            },
        ]);
        render(<CompliancePage />);

        expect(await screen.findByText(/Risk register .* 1 active exception/i)).toBeInTheDocument();
        expect(screen.getByText('accept SoD during cutover')).toBeInTheDocument();
        expect(screen.getByText('temporary')).toBeInTheDocument();
    });

    // NOTE (LegalHoldBanner's `if (!reason.trim()) return;` inside the "Confirm
    // hold" onClick): unreachable through the UI. The button's own `disabled`
    // attribute (`place.isPending || !reason.trim()`) mirrors this guard exactly,
    // and a disabled native <button> never dispatches click events, so the branch
    // can't be exercised by a real (or fireEvent) click. Left uncovered.

    it('places a legal hold and clears the form on success', async () => {
        (complianceApi.getPosture as any).mockResolvedValue(posture);
        (complianceApi.placeLegalHold as any).mockResolvedValue({});
        render(<CompliancePage />);

        fireEvent.click(await screen.findByRole('button', { name: /place hold/i }));
        const confirmBtn = screen.getByRole('button', { name: /confirm hold/i });
        expect(confirmBtn).toBeDisabled(); // reason is still empty

        fireEvent.change(screen.getByPlaceholderText(/reason \(e\.g\. litigation hold/i), {
            target: { value: 'case INC-9' },
        });
        expect(confirmBtn).not.toBeDisabled();
        fireEvent.click(confirmBtn);

        await waitFor(() => expect(complianceApi.placeLegalHold).toHaveBeenCalledWith('case INC-9'));
        // Form collapses back to the "Place hold" button once the mutation succeeds.
        await waitFor(() =>
            expect(screen.queryByPlaceholderText(/reason \(e\.g\. litigation hold/i)).not.toBeInTheDocument()
        );
        expect(screen.getByRole('button', { name: /place hold/i })).toBeInTheDocument();
    });

    it('cancels an in-progress legal-hold placement without submitting', async () => {
        (complianceApi.getPosture as any).mockResolvedValue(posture);
        render(<CompliancePage />);

        fireEvent.click(await screen.findByRole('button', { name: /place hold/i }));
        fireEvent.change(screen.getByPlaceholderText(/reason \(e\.g\. litigation hold/i), {
            target: { value: 'draft reason' },
        });
        fireEvent.click(screen.getByRole('button', { name: /^cancel$/i }));

        expect(screen.queryByPlaceholderText(/reason \(e\.g\. litigation hold/i)).not.toBeInTheDocument();
        expect(screen.getByRole('button', { name: /place hold/i })).toBeInTheDocument();
        expect(complianceApi.placeLegalHold).not.toHaveBeenCalled();
    });

    it('shows an inline error when placing a legal hold fails', async () => {
        (complianceApi.getPosture as any).mockResolvedValue(posture);
        (complianceApi.placeLegalHold as any).mockRejectedValue({
            response: { data: { error: 'Forbidden: system.write required' } },
        });
        render(<CompliancePage />);

        fireEvent.click(await screen.findByRole('button', { name: /place hold/i }));
        fireEvent.change(screen.getByPlaceholderText(/reason \(e\.g\. litigation hold/i), {
            target: { value: 'case-1' },
        });
        fireEvent.click(screen.getByRole('button', { name: /confirm hold/i }));

        expect(await screen.findByText('Forbidden: system.write required')).toBeInTheDocument();
    });

    it('lifts an active legal hold, sending the typed reason (DELETE requires a non-empty one)', async () => {
        (complianceApi.getPosture as any).mockResolvedValue({
            ...posture,
            legalHold: { active: true, reason: 'litigation INC-7' },
        });
        (complianceApi.liftLegalHold as any).mockResolvedValue({});
        render(<CompliancePage />);

        fireEvent.click(await screen.findByRole('button', { name: /lift hold/i }));
        fireEvent.change(screen.getByPlaceholderText(/reason for lifting/i), {
            target: { value: 'litigation closed' },
        });
        fireEvent.click(screen.getByRole('button', { name: /confirm lift/i }));

        await waitFor(() => expect(complianceApi.liftLegalHold).toHaveBeenCalledWith('litigation closed'));
    });

    it('falls back to an em dash when an active legal hold has no recorded reason', async () => {
        (complianceApi.getPosture as any).mockResolvedValue({
            ...posture,
            legalHold: { active: true, reason: '' },
        });
        render(<CompliancePage />);
        expect(await screen.findByText(/Reason: —/)).toBeInTheDocument();
    });

    it('falls back to a generic error message when the legal-hold API returns no error/message fields', async () => {
        (complianceApi.getPosture as any).mockResolvedValue(posture);
        (complianceApi.placeLegalHold as any).mockRejectedValue({});
        render(<CompliancePage />);

        fireEvent.click(await screen.findByRole('button', { name: /place hold/i }));
        fireEvent.change(screen.getByPlaceholderText(/reason \(e\.g\. litigation hold/i), {
            target: { value: 'case-2' },
        });
        fireEvent.click(screen.getByRole('button', { name: /confirm hold/i }));

        expect(await screen.findByText('Action failed.')).toBeInTheDocument();
    });

    it('shows an inline error when lifting a legal hold fails', async () => {
        (complianceApi.getPosture as any).mockResolvedValue({
            ...posture,
            legalHold: { active: true, reason: 'litigation INC-7' },
        });
        (complianceApi.liftLegalHold as any).mockRejectedValue({ response: { data: { message: 'Lift failed.' } } });
        render(<CompliancePage />);

        fireEvent.click(await screen.findByRole('button', { name: /lift hold/i }));
        fireEvent.change(screen.getByPlaceholderText(/reason for lifting/i), { target: { value: 'case-3' } });
        fireEvent.click(screen.getByRole('button', { name: /confirm lift/i }));

        expect(await screen.findByText('Lift failed.')).toBeInTheDocument();
    });

    it('disables Confirm lift until a reason is typed, and Cancel clears the input', async () => {
        (complianceApi.getPosture as any).mockResolvedValue({
            ...posture,
            legalHold: { active: true, reason: 'litigation INC-7' },
        });
        render(<CompliancePage />);

        fireEvent.click(await screen.findByRole('button', { name: /lift hold/i }));
        expect(screen.getByRole('button', { name: /confirm lift/i })).toBeDisabled();

        fireEvent.change(screen.getByPlaceholderText(/reason for lifting/i), { target: { value: 'case-4' } });
        expect(screen.getByRole('button', { name: /confirm lift/i })).not.toBeDisabled();

        fireEvent.click(screen.getByRole('button', { name: /^cancel$/i }));
        expect(screen.queryByPlaceholderText(/reason for lifting/i)).not.toBeInTheDocument();
        expect(screen.getByRole('button', { name: /lift hold/i })).toBeInTheDocument();
    });

    it('shows a generic error when the posture report fails with a non-403 error', async () => {
        (complianceApi.getPosture as any).mockRejectedValue({ response: { status: 500 } });
        render(<CompliancePage />);

        expect(await screen.findByText('Controls posture is currently unavailable.')).toBeInTheDocument();
    });

    it('shows an audit chain that no full re-walk has proven yet as "Not yet proven", not "No"', async () => {
        (complianceApi.getPosture as any).mockResolvedValue({
            ...posture,
            auditIntegrity: {
                chainVerified: false,
                chainedEvents: 12,
                checkpointed: true,
                verificationStatus: 'not_proven',
                reason: 'no full verification has completed yet',
            },
        });
        render(<CompliancePage />);

        expect(await screen.findByText('Not yet proven')).toBeInTheDocument();
        expect(screen.queryByText('Last full chain re-walk')).not.toBeInTheDocument();
    });

    it('shows when the last full chain re-walk completed', async () => {
        (complianceApi.getPosture as any).mockResolvedValue({
            ...posture,
            auditIntegrity: {
                chainVerified: true,
                chainedEvents: 12,
                checkpointed: true,
                verificationStatus: 'valid',
                lastFullVerificationAt: '2026-10-14T03:00:00Z',
            },
        });
        render(<CompliancePage />);

        expect(await screen.findByText('Last full chain re-walk')).toBeInTheDocument();
    });

    it('reflects a degraded posture: failed checks, low second-factor coverage, and disabled retention', async () => {
        (complianceApi.getPosture as any).mockResolvedValue({
            ...posture,
            generatedAt: '',
            auditIntegrity: { chainVerified: false, chainedEvents: 0, checkpointed: false },
            identity: { activeUsers: 5, usersWithSecondFactor: 2, secondFactorPercent: 40 },
            anomalies: { unacknowledged: 0, highSeverityOpen: 0 },
            retention: {
                enabled: false,
                anomalyAlertsDays: 0,
                closedAccessReviewsDays: 0,
                breakGlassDays: 0,
                resolvedAccessRequestsDays: 0,
            },
        });
        render(<CompliancePage />);

        expect(await screen.findByText('Controls posture')).toBeInTheDocument();
        // Audit chain verified + on-box checkpointed both render "No".
        expect(screen.getAllByText('No')).toHaveLength(2);
        expect(screen.getByText('40%')).toBeInTheDocument(); // below the 80% good threshold
        expect(screen.getByText(/Data retention .* not configured/i)).toBeInTheDocument();
        // All retention windows are 0 ("Keep" — retained indefinitely).
        expect(screen.getAllByText('Keep').length).toBeGreaterThanOrEqual(4);
        // No anomalies at all — value renders as a bare "0", no "(N high)" suffix.
        const anomaliesLabel = screen.getByText('Open anomalies (NIS2)');
        expect(anomaliesLabel.parentElement).toHaveTextContent('0');
        expect(anomaliesLabel.parentElement).not.toHaveTextContent('high');
    });

    it('shows the anomaly count without the high-severity suffix when only low-severity items are open', async () => {
        (complianceApi.getPosture as any).mockResolvedValue({
            ...posture,
            anomalies: { unacknowledged: 2, highSeverityOpen: 0 },
        });
        render(<CompliancePage />);

        const anomaliesLabel = await screen.findByText('Open anomalies (NIS2)');
        expect(anomaliesLabel.parentElement).toHaveTextContent('2');
        expect(anomaliesLabel.parentElement).not.toHaveTextContent('high');
    });

    it('renders a SoD violation for a principal with no email on file', async () => {
        (complianceApi.getPosture as any).mockResolvedValue(posture);
        (complianceApi.getSoDViolations as any).mockResolvedValue([
            {
                policyName: 'approve-vs-admin',
                username: 'bob',
                email: '',
                permissionA: 'roles.assign',
                permissionB: 'secrets.delete',
            },
        ]);
        render(<CompliancePage />);

        expect(await screen.findByText(/Separation-of-duties violations \(1\)/i)).toBeInTheDocument();
        expect(screen.getByText('bob')).toBeInTheDocument();
        expect(screen.queryByText(/bob \(/)).not.toBeInTheDocument();
    });

    it('filters the control matrix by framework, shows a per-framework score, remediation note, and empty state', async () => {
        (complianceApi.getPosture as any).mockResolvedValue(posture);
        (complianceApi.getControls as any).mockResolvedValue({
            generatedAt: '2026-06-14T10:00:00Z',
            summary: { total: 3, pass: 2, gap: 1, notConfigured: 0 },
            controls: [
                {
                    id: 'a',
                    name: 'Control A',
                    area: 'Access governance',
                    status: 'pass',
                    detail: 'ok',
                    frameworks: { iso27001: ['A.1'], soc2: [], nis2: [], dora: [], ens: [] },
                },
                {
                    id: 'b',
                    name: 'Control B',
                    area: 'Access governance',
                    status: 'gap',
                    detail: 'needs remediation',
                    frameworks: { iso27001: ['A.2'], soc2: [], nis2: [], dora: [], ens: [] },
                },
                {
                    id: 'c',
                    name: 'Control C',
                    area: 'Operations',
                    status: 'pass',
                    detail: 'ok',
                    frameworks: { iso27001: [], soc2: ['CC1'], nis2: ['Art.21'], dora: [], ens: [] },
                },
            ],
        });
        render(<CompliancePage />);

        expect(await screen.findByText(/Compliance mapping reports/i)).toBeInTheDocument();
        // Control C has no ISO refs but does have NIS2 refs — covers both the missing-ISO and present-NIS2 branches.
        expect(screen.getByText('SOC2 CC1 · NIS2 Art.21')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'ISO 27001' }));
        expect(await screen.findByText('ISO/IEC 27001:2022')).toBeInTheDocument();
        expect(screen.getByText('50%')).toBeInTheDocument(); // 1 pass / 1 gap of the ISO-tagged controls
        expect(screen.getByText(/1 control with gaps require remediation/i)).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'ENS' }));
        expect(await screen.findByText(/No controls mapped to/i)).toBeInTheDocument();
    });

    // NOTE (visibleControls filter, `(c.frameworks[fw] ?? []).length`): the `?? []`
    // fallback is unreachable through the rendered UI. `complianceApi.getControls`
    // (src/services/compliance.ts) always normalizes every framework key to `[]`
    // via its own `??`, and the control type requires all five keys as string[], so
    // a control can never actually reach this component missing one. Forcing a
    // missing key in test data to exercise the fallback instead crashes `refLine`
    // just above (`c.frameworks.iso27001.length` with no guard), which assumes the
    // same invariant. Tried excluding the malformed control from the rendered list
    // by filtering it out on the target framework tab — doesn't help: the panel
    // mounts with `activeFramework` defaulted to `'all'`, which renders (and calls
    // refLine on) every control before any tab click, so the crash happens on the
    // very first render regardless of which framework is later selected. Left
    // uncovered as defensive-only dead code.

    it('uses the warning color for a mid-range per-framework compliance score', async () => {
        (complianceApi.getPosture as any).mockResolvedValue(posture);
        (complianceApi.getControls as any).mockResolvedValue({
            generatedAt: '2026-06-14T10:00:00Z',
            summary: { total: 4, pass: 3, gap: 1, notConfigured: 0 },
            controls: [1, 2, 3]
                .map((n) => ({
                    id: `p${n}`,
                    name: `Pass ${n}`,
                    area: 'Access governance',
                    status: 'pass',
                    detail: 'ok',
                    frameworks: { iso27001: [`A.${n}`], soc2: [], nis2: [], dora: [], ens: [] },
                }))
                .concat({
                    id: 'g1',
                    name: 'Gap 1',
                    area: 'Access governance',
                    status: 'gap',
                    detail: 'needs remediation',
                    frameworks: { iso27001: ['A.4'], soc2: [], nis2: [], dora: [], ens: [] },
                }),
        });
        render(<CompliancePage />);

        fireEvent.click(await screen.findByRole('button', { name: 'ISO 27001' }));
        const score = await screen.findByText('75%'); // 3 pass / 4 total — the 70-89% "warning" band
        expect(score).toHaveStyle({ color: 'var(--warning)' });
    });

    it('pluralizes the remediation note and renders a fallback N/A badge for an unrecognized control status', async () => {
        (complianceApi.getPosture as any).mockResolvedValue(posture);
        (complianceApi.getControls as any).mockResolvedValue({
            generatedAt: '2026-06-14T10:00:00Z',
            summary: { total: 5, pass: 2, gap: 2, notConfigured: 1 },
            controls: [
                {
                    id: '1',
                    name: 'C1',
                    area: 'a',
                    status: 'pass',
                    detail: '',
                    frameworks: { iso27001: ['A.1'], soc2: [], nis2: [], dora: [], ens: [] },
                },
                {
                    id: '2',
                    name: 'C2',
                    area: 'a',
                    status: 'pass',
                    detail: '',
                    frameworks: { iso27001: ['A.2'], soc2: [], nis2: [], dora: [], ens: [] },
                },
                {
                    id: '3',
                    name: 'C3',
                    area: 'a',
                    status: 'gap',
                    detail: '',
                    frameworks: { iso27001: ['A.3'], soc2: [], nis2: [], dora: [], ens: [] },
                },
                {
                    id: '4',
                    name: 'C4',
                    area: 'a',
                    status: 'gap',
                    detail: '',
                    frameworks: { iso27001: ['A.4'], soc2: [], nis2: [], dora: [], ens: [] },
                },
                {
                    // The API contract only documents pass/gap/not_configured, but the matrix
                    // falls back to an "N/A" badge for anything else rather than crashing.
                    id: '5',
                    name: 'C5',
                    area: 'a',
                    status: 'unknown' as any,
                    detail: '',
                    frameworks: { iso27001: ['A.5'], soc2: [], nis2: [], dora: [], ens: [] },
                },
            ],
        });
        render(<CompliancePage />);

        fireEvent.click(await screen.findByRole('button', { name: 'ISO 27001' }));
        expect(await screen.findByText(/2 controls with gaps require remediation/i)).toBeInTheDocument();
        expect(screen.getByText('N/A')).toBeInTheDocument();
    });

    // NOTE (RiskRegisterPanel's `submit`, `if (!form.title.trim() || ...) return;`):
    // unreachable through the UI for the same reason as the legal-hold guard above
    // — the "Record exception" button's `disabled` attribute is the identical
    // condition, so a disabled button never fires the click that would reach the
    // guard. Left uncovered.

    it('opens the add-exception form and keeps submit disabled until the required fields are filled', async () => {
        (complianceApi.getPosture as any).mockResolvedValue(posture);
        render(<CompliancePage />);

        fireEvent.click(await screen.findByRole('button', { name: /add exception/i }));
        const submitBtn = screen.getByRole('button', { name: /record exception/i });
        expect(submitBtn).toBeDisabled();

        fireEvent.change(screen.getByPlaceholderText(/title \(e\.g\. accept sod/i), {
            target: { value: 'temp accept' },
        });
        expect(submitBtn).toBeDisabled(); // still missing justification + expiry

        fireEvent.change(screen.getByRole('combobox'), { target: { value: 'mfa' } });
        fireEvent.change(screen.getByPlaceholderText(/reference \(a user/i), { target: { value: 'alice' } });
        fireEvent.change(screen.getByPlaceholderText(/justification \(recorded for audit\)/i), {
            target: { value: 'reviewed' },
        });
        expect(submitBtn).toBeDisabled(); // still missing an expiry date

        fireEvent.change(screen.getByLabelText(/expires/i), { target: { value: '2026-12-31' } });
        expect(submitBtn).not.toBeDisabled();

        fireEvent.click(screen.getByRole('button', { name: /^cancel$/i }));
        expect(screen.queryByPlaceholderText(/title \(e\.g\. accept sod/i)).not.toBeInTheDocument();
        expect(complianceApi.createRiskException).not.toHaveBeenCalled();
    });

    it('creates a new risk exception and resets the form on success', async () => {
        (complianceApi.getPosture as any).mockResolvedValue(posture);
        (complianceApi.createRiskException as any).mockResolvedValue({});
        render(<CompliancePage />);

        fireEvent.click(await screen.findByRole('button', { name: /add exception/i }));
        fireEvent.change(screen.getByPlaceholderText(/title \(e\.g\. accept sod/i), {
            target: { value: 'accept SoD' },
        });
        fireEvent.change(screen.getByPlaceholderText(/justification \(recorded for audit\)/i), {
            target: { value: 'temporary cutover' },
        });
        fireEvent.change(screen.getByLabelText(/expires/i), { target: { value: '2026-12-31' } });
        fireEvent.click(screen.getByRole('button', { name: /record exception/i }));

        await waitFor(() =>
            expect(complianceApi.createRiskException).toHaveBeenCalledWith(
                {
                    title: 'accept SoD',
                    category: 'sod',
                    reference: '',
                    justification: 'temporary cutover',
                    expiresAt: '2026-12-31T00:00:00Z',
                },
                expect.anything()
            )
        );
        await waitFor(() =>
            expect(screen.queryByRole('button', { name: /record exception/i })).not.toBeInTheDocument()
        );
    });

    it('shows an inline error when creating a risk exception fails', async () => {
        (complianceApi.getPosture as any).mockResolvedValue(posture);
        (complianceApi.createRiskException as any).mockRejectedValue({
            response: { data: { error: 'system.write required' } },
        });
        render(<CompliancePage />);

        fireEvent.click(await screen.findByRole('button', { name: /add exception/i }));
        fireEvent.change(screen.getByPlaceholderText(/title \(e\.g\. accept sod/i), { target: { value: 'x' } });
        fireEvent.change(screen.getByPlaceholderText(/justification \(recorded for audit\)/i), {
            target: { value: 'y' },
        });
        fireEvent.change(screen.getByLabelText(/expires/i), { target: { value: '2026-12-31' } });
        fireEvent.click(screen.getByRole('button', { name: /record exception/i }));

        expect(await screen.findByText('system.write required')).toBeInTheDocument();
    });

    it('falls back to a generic error message when creating a risk exception returns no error/message fields', async () => {
        (complianceApi.getPosture as any).mockResolvedValue(posture);
        (complianceApi.createRiskException as any).mockRejectedValue({});
        render(<CompliancePage />);

        fireEvent.click(await screen.findByRole('button', { name: /add exception/i }));
        fireEvent.change(screen.getByPlaceholderText(/title \(e\.g\. accept sod/i), { target: { value: 'x' } });
        fireEvent.change(screen.getByPlaceholderText(/justification \(recorded for audit\)/i), {
            target: { value: 'y' },
        });
        fireEvent.change(screen.getByLabelText(/expires/i), { target: { value: '2026-12-31' } });
        fireEvent.click(screen.getByRole('button', { name: /record exception/i }));

        expect(await screen.findByText('Action failed.')).toBeInTheDocument();
    });

    it('revokes an active risk exception and falls back for a missing reference/expiry', async () => {
        (complianceApi.getPosture as any).mockResolvedValue(posture);
        (complianceApi.revokeRiskException as any).mockResolvedValue({});
        (complianceApi.getRiskExceptions as any).mockResolvedValue([
            {
                id: 5,
                title: 'no-ref exception',
                category: 'other',
                reference: '',
                justification: 'reviewed',
                status: 'active',
                expiresAt: '',
                createdBy: 1,
            },
        ]);
        render(<CompliancePage />);

        expect(await screen.findByText('no-ref exception')).toBeInTheDocument();
        expect(screen.getByText((_, el) => el?.textContent === 'Expires —')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: /revoke/i }));
        await waitFor(() => expect(complianceApi.revokeRiskException).toHaveBeenCalledWith(5));
    });

    it('resets the digest copy button label back to "Copy" after the confirmation delay', async () => {
        (complianceApi.getPosture as any).mockResolvedValue(posture);
        (complianceApi.getDigest as any).mockResolvedValue({
            title: 'Keyorix compliance digest',
            body: 'Controls: 10 pass, 1 gap.',
        });
        Object.assign(navigator, { clipboard: { writeText: vi.fn() } });
        render(<CompliancePage />);

        // Wait for the async digest to load under real timers first, then switch to fake
        // timers so testing-library's own polling isn't affected by the switch.
        const copyBtn = await screen.findByRole('button', { name: /^copy$/i });

        vi.useFakeTimers();
        await act(async () => {
            fireEvent.click(copyBtn);
        });
        expect(screen.getByRole('button', { name: /^copied$/i })).toBeInTheDocument();

        await act(async () => {
            await vi.advanceTimersByTimeAsync(2000);
        });
        expect(screen.getByRole('button', { name: /^copy$/i })).toBeInTheDocument();
    });
});
