import { apiClient } from './client';

// The deployment controls-posture snapshot (ISO 27001 / SOC 2 / NIS2 / DORA),
// served by GET /api/v1/compliance/posture (gated by system.read).
export interface CompliancePosture {
    generatedAt: string;
    auditIntegrity: {
        chainVerified: boolean;
        chainedEvents: number;
        checkpointed: boolean;
        reason?: string;
        // valid | broken | not_proven (incremental verification); absent from older servers.
        verificationStatus?: string;
        // When the last full re-walk of the chain completed; absent when none has.
        lastFullVerificationAt?: string;
    };
    accessGovernance: {
        projects: number;
        projectsWithOpenCampaign: number;
        projectsNeverReviewed: number;
        openCampaigns: number;
        pendingItems: number;
        projectsOverdue: number;
        dormantRoleGrants: number;
        sodViolations: number;
    };
    rotation: {
        coveredSecrets: number;
        overdue: number;
        dueSoon: number;
    };
    identity: {
        activeUsers: number;
        usersWithSecondFactor: number;
        secondFactorPercent: number;
    };
    emergencyAccess: {
        activeActivations: number;
        totalActivations: number;
    };
    classification: {
        totalSecrets: number;
        public: number;
        internal: number;
        confidential: number;
        restricted: number;
        unclassified: number;
    };
    anomalies: {
        unacknowledged: number;
        highSeverityOpen: number;
    };
    legalHold: {
        active: boolean;
        reason: string;
        placedAt?: string;
    };
    retention: {
        enabled: boolean;
        anomalyAlertsDays: number;
        closedAccessReviewsDays: number;
        breakGlassDays: number;
        resolvedAccessRequestsDays: number;
    };
}

const num = (v: any): number => (typeof v === 'number' ? v : 0);

const normalize = (d: any): CompliancePosture => ({
    generatedAt: d.generated_at ?? d.generatedAt ?? '',
    auditIntegrity: {
        chainVerified: !!d.audit_integrity?.chain_verified,
        chainedEvents: num(d.audit_integrity?.chained_events),
        checkpointed: !!d.audit_integrity?.checkpointed,
        reason: d.audit_integrity?.reason ?? undefined,
        verificationStatus: d.audit_integrity?.verification_status ?? undefined,
        lastFullVerificationAt: d.audit_integrity?.last_full_verification_at ?? undefined,
    },
    accessGovernance: {
        projects: num(d.access_governance?.projects),
        projectsWithOpenCampaign: num(d.access_governance?.projects_with_open_campaign),
        projectsNeverReviewed: num(d.access_governance?.projects_never_reviewed),
        openCampaigns: num(d.access_governance?.open_campaigns),
        pendingItems: num(d.access_governance?.pending_items),
        projectsOverdue: num(d.access_governance?.projects_overdue),
        dormantRoleGrants: num(d.access_governance?.dormant_role_grants),
        sodViolations: num(d.access_governance?.sod_violations),
    },
    rotation: {
        coveredSecrets: num(d.rotation?.covered_secrets),
        overdue: num(d.rotation?.overdue),
        dueSoon: num(d.rotation?.due_soon),
    },
    identity: {
        activeUsers: num(d.identity?.active_users),
        usersWithSecondFactor: num(d.identity?.users_with_second_factor),
        secondFactorPercent: num(d.identity?.second_factor_percent),
    },
    emergencyAccess: {
        activeActivations: num(d.emergency_access?.active_activations),
        totalActivations: num(d.emergency_access?.total_activations),
    },
    classification: {
        totalSecrets: num(d.classification?.total_secrets),
        public: num(d.classification?.public),
        internal: num(d.classification?.internal),
        confidential: num(d.classification?.confidential),
        restricted: num(d.classification?.restricted),
        unclassified: num(d.classification?.unclassified),
    },
    anomalies: {
        unacknowledged: num(d.anomalies?.unacknowledged),
        highSeverityOpen: num(d.anomalies?.high_severity_open),
    },
    legalHold: {
        active: !!d.legal_hold?.active,
        reason: d.legal_hold?.reason ?? '',
        placedAt: d.legal_hold?.placed_at ?? undefined,
    },
    retention: {
        enabled: !!d.retention?.enabled,
        anomalyAlertsDays: num(d.retention?.anomaly_alerts_days),
        closedAccessReviewsDays: num(d.retention?.closed_access_reviews_days),
        breakGlassDays: num(d.retention?.break_glass_days),
        resolvedAccessRequestsDays: num(d.retention?.resolved_access_requests_days),
    },
});

// One separation-of-duties violation (a principal holding a forbidden permission
// pair), served by GET /api/v1/sod/violations (gated by system.read).
export interface SoDViolation {
    policyName: string;
    username: string;
    email?: string;
    permissionA: string;
    permissionB: string;
}

const normalizeViolation = (v: any): SoDViolation => ({
    policyName: v.policy_name ?? v.policyName ?? '',
    username: v.username ?? '',
    email: v.email ?? undefined,
    permissionA: v.permission_a ?? v.permissionA ?? '',
    permissionB: v.permission_b ?? v.permissionB ?? '',
});

// One control in the framework matrix (GET /compliance/controls), mapping a control
// Keyorix enforces to its clause references with a live status.
export interface ControlState {
    id: string;
    name: string;
    area: string;
    status: 'pass' | 'gap' | 'not_configured';
    detail: string;
    frameworks: { iso27001: string[]; soc2: string[]; nis2: string[]; dora: string[]; ens: string[] };
}

export interface ControlMatrix {
    generatedAt: string;
    summary: { total: number; pass: number; gap: number; notConfigured: number };
    controls: ControlState[];
}

const normalizeControl = (c: any): ControlState => ({
    id: c.id ?? '',
    name: c.name ?? '',
    area: c.area ?? '',
    status: c.status ?? 'not_configured',
    detail: c.detail ?? '',
    frameworks: {
        iso27001: c.frameworks?.iso_27001 ?? [],
        soc2: c.frameworks?.soc2 ?? [],
        nis2: c.frameworks?.nis2 ?? [],
        dora: c.frameworks?.dora ?? [],
        ens: c.frameworks?.ens ?? [],
    },
});

const normalizeMatrix = (d: any): ControlMatrix => ({
    generatedAt: d.generated_at ?? d.generatedAt ?? '',
    summary: {
        total: num(d.summary?.total),
        pass: num(d.summary?.pass),
        gap: num(d.summary?.gap),
        notConfigured: num(d.summary?.not_configured),
    },
    controls: (d.controls ?? []).map(normalizeControl),
});

// One governed risk exception (GET /risk-exceptions), with a computed status.
export interface RiskException {
    id: number;
    title: string;
    category: string;
    reference: string;
    justification: string;
    status: 'active' | 'expired' | 'revoked';
    expiresAt: string;
    createdBy: number;
}

const normalizeException = (e: any): RiskException => ({
    id: e.id ?? 0,
    title: e.title ?? '',
    category: e.category ?? 'other',
    reference: e.reference ?? '',
    justification: e.justification ?? '',
    status: e.status ?? 'active',
    expiresAt: e.expires_at ?? e.expiresAt ?? '',
    createdBy: e.created_by ?? e.createdBy ?? 0,
});

export interface RiskExceptionInput {
    title: string;
    category: string;
    reference: string;
    justification: string;
    expiresAt: string; // RFC3339
}

// The on-demand compliance digest (GET /compliance/digest): the human-readable
// summary otherwise broadcast to the notification channels on a schedule.
export interface ComplianceDigest {
    title: string;
    body: string;
}

export const complianceApi = {
    async getPosture(): Promise<CompliancePosture> {
        const response = await apiClient.get('/api/v1/compliance/posture');
        return normalize(response.data.data ?? response.data);
    },

    async getControls(): Promise<ControlMatrix> {
        const response = await apiClient.get('/api/v1/compliance/controls');
        return normalizeMatrix(response.data.data ?? response.data);
    },

    async getRiskExceptions(): Promise<RiskException[]> {
        const response = await apiClient.get('/api/v1/risk-exceptions');
        const list = response.data.data?.exceptions ?? response.data.exceptions ?? [];
        return list.map(normalizeException);
    },

    async getDigest(): Promise<ComplianceDigest> {
        const response = await apiClient.get('/api/v1/compliance/digest');
        const d = response.data.data ?? response.data;
        return { title: d.title ?? '', body: d.body ?? '' };
    },

    async createRiskException(input: RiskExceptionInput): Promise<void> {
        await apiClient.post('/api/v1/risk-exceptions', {
            title: input.title,
            category: input.category,
            reference: input.reference,
            justification: input.justification,
            expires_at: input.expiresAt,
        });
    },

    async revokeRiskException(id: number): Promise<void> {
        await apiClient.delete(`/api/v1/risk-exceptions/${id}`);
    },

    async placeLegalHold(reason: string): Promise<void> {
        await apiClient.post('/api/v1/legal-hold', { reason });
    },

    async liftLegalHold(reason: string): Promise<void> {
        // DELETE with a body is unusual, but genuinely how this route's wire
        // protocol works (server/http/handlers/openapi.yaml's liftLegalHold:
        // LiftLegalHold requires a non-empty reason, mapped to 400 when
        // absent). Previously sent no body at all -- every real "Lift hold"
        // click 400'd.
        await apiClient.delete('/api/v1/legal-hold', { data: { reason } });
    },

    async getSoDViolations(): Promise<SoDViolation[]> {
        const response = await apiClient.get('/api/v1/sod/violations');
        const list = response.data.data?.violations ?? response.data.violations ?? [];
        return list.map(normalizeViolation);
    },
};
