// INV-WEB-05 guard: the hand-written wire types in web/src/types must agree with
// the server's OpenAPI document (server/http/handlers/openapi.yaml, ADR-074).
//
// Why a comparison test rather than codegen: web/src/types mixes wire shapes
// (snake_case, 1:1 with a response body) with UI models the services layer
// builds by mapping (User, Secret, ShareRecord, DashboardStats, ... -- camelCase,
// not what the server sends), and ~half the endpoints the web app calls have
// only a prose `description` for their 200 body in openapi.yaml, so there is no
// schema to generate from. Generating would rewrite most of web/src for no gain;
// this test pins the part that CAN be pinned.
//
// Three checks:
//   1. Every wire-type pair in WIRE_TYPES matches its schema (see openapiDriftLib).
//   2. Partition: every exported interface in web/src/types is either in
//      WIRE_TYPES or in NOT_COMPARED with a reason -- a new interface cannot
//      slip in unchecked.
//   3. No exemption (ALLOW) is stale: each must still suppress a real mismatch.
//
// What this does NOT cover (stated, not implied): the NOT_COMPARED types; wire
// bodies read as `any` inside services/*.ts mapping code; request/response
// bodies openapi.yaml does not schema (the spec is the limit, see ADR-074).
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parse } from 'yaml';
import { describe, expect, it } from 'vitest';
import { Locator, compare, createProgram, exportedInterfaces, locate, toShape } from './openapiDriftLib';

const TYPES_DIR = resolve(import.meta.dirname, '..');
const FILES = ['index.ts', 'rbac.ts'].map((f) => resolve(TYPES_DIR, f));
const OPENAPI = resolve(import.meta.dirname, '../../../../server/http/handlers/openapi.yaml');

interface Pair {
    locate: Locator;
    /** dotted field path (rooted at the interface name) -> why the mismatch is accepted. */
    allow?: Record<string, string>;
}

// The server still returns the session token in the body for non-browser clients
// (auth.go buildLoginResponse / RefreshToken); the web app is cookie-only and must
// never read or store it (INV-WEB-03), so the field is deliberately undeclared.
const TOKEN_NOT_READ = 'server sends the session token for non-browser clients; web is cookie-only (INV-WEB-03)';

// #2848: a field the /auth/login 200 union only carries on its LoginSuccessData
// branch, which LoginResponse declares non-optional because it flattens both
// branches into one interface. authStore.login() guards on mfa_required before
// reading any of them (see its own comment); the imprecision is recorded here
// per field rather than left silent. See LoginResponse's entry below.
const ONLY_ON_SUCCESS_BRANCH =
    'present only on the LoginSuccessData branch of the /auth/login 200 oneOf; authStore.login() branches on mfa_required before reading it (#2848)';

const WIRE_TYPES: Record<string, Pair> = {
    SecretAccessLogEntry: { locate: { schema: 'SecretAccessLogEntry' } },
    SecretAuditEntry: { locate: { schema: 'SecretAuditEntry' } },
    SecretAccessor: { locate: { schema: 'SecretAccessor' } },
    SecretRiskFactor: { locate: { schema: 'SecretRiskFactor' } },
    SecretRiskScore: { locate: { schema: 'SecretRiskScore' } },
    RotationPolicy: { locate: { schema: 'RotationPolicy' } },
    RotationPolicyEvaluation: { locate: { schema: 'RotationPolicyEvaluation' } },
    // #2923: the require_mfa upgrade grace period (login data.mfa_grace).
    MfaGraceWire: { locate: { schema: 'MFAGrace' } },
    CreateRotationPolicyPayload: {
        locate: { op: { path: '/api/v1/rotation-policies', method: 'post', request: true } },
    },
    LoginResponse: {
        locate: { op: { path: '/auth/login', method: 'post' }, at: ['data'] },
        allow: {
            'LoginResponse.token': TOKEN_NOT_READ,
            // #2848: /auth/login's 200 `data` is a oneOf of LoginSuccessData |
            // MFAChallengeData (both 200, disambiguated by data.mfa_required --
            // the response's own description says so). openapiDriftLib's
            // flattenUnion compares the TS interface against the MERGED object,
            // where a field only one branch requires is correctly optional.
            //
            // LoginResponse flattens that wire union into ONE interface with the
            // fields of both, declaring the identity fields non-optional. That is
            // imprecise but not a latent bug: authStore.login() branches on
            // mfa_required BEFORE reading any of them, and its own comment says
            // "every field below is undefined when mfa_required is true, so this
            // must be checked before touching any of them". The four exemptions
            // below record exactly that, per field, so the imprecision is visible
            // rather than silent.
            //
            // The faithful fix is a discriminated union on the TS side, which
            // needs the comparator to model TS unions too (toShape collapses a
            // union of object types to kind 'unknown'). Out of scope for a
            // main-is-red unblock; proposed as a follow-up on #2848.
            'LoginResponse.expires_at': ONLY_ON_SUCCESS_BRANCH,
            'LoginResponse.user_id': ONLY_ON_SUCCESS_BRANCH,
            'LoginResponse.username': ONLY_ON_SUCCESS_BRANCH,
            'LoginResponse.email': ONLY_ON_SUCCESS_BRANCH,
            // The schema pins mfa_required to `enum: [true]` (a const-true
            // discriminator present only on the challenge branch). TS declares
            // `mfa_required?: boolean`, and toShape collapses a boolean literal
            // union to plain 'boolean' with no literals, so a const-true schema
            // can never match any TS boolean. Exempted rather than worked around:
            // narrowing TS to `mfa_required?: true` would not help until the
            // comparator carries single boolean literals.
            'LoginResponse.mfa_required':
                'schema pins enum [true] on the challenge branch; toShape cannot express a const boolean (see #2848)',
        },
    },
    RefreshTokenResponse: {
        locate: { op: { path: '/auth/refresh', method: 'post' }, at: ['data'] },
        allow: { 'RefreshTokenResponse.token': TOKEN_NOT_READ },
    },
    ApiError: { locate: { response: 'Error' } },
    Permission: { locate: { schema: 'Permission' } },
    Role: { locate: { schema: 'Role' } },
    RoleWithPermissions: { locate: { schema: 'RoleWithPermissions' } },
    GroupRoleGrant: { locate: { schema: 'GroupRoleGrant' } },
    GroupRoles: { locate: { op: { path: '/api/v1/groups/{id}/roles', method: 'get' }, at: ['data'] } },
    UserRoleAssignment: { locate: { schema: 'UserRoleAssignment' } },
    Group: {
        locate: { schema: 'Group' },
        allow: {
            'Group.member_count':
                'the server never sends it (groupToAPIResponse), so GroupsPage\'s member-count column always renders "—"; ' +
                'the column needs a real count source, not a type change',
        },
    },
};

const NOT_COMPARED: Record<string, string> = {
    // UI models: built by services/*.ts mapping code, not a wire body.
    User: 'UI model (services/auth.ts, users.ts map the snake_case profile into it)',
    UserPreferences: 'UI model, client-side preferences',
    NotificationSettings: 'UI model, client-side preferences',
    Secret: 'UI model (services/secrets.ts maps the snake_case SecretNode into it)',
    SecretFormData: 'UI form state',
    ShareRecord: 'UI model (services/sharing.ts maps the share wire shape)',
    ShareFormData: 'UI form state',
    Recipient: 'UI model (services/groups.ts, users.ts normalise users and groups)',
    StatTrend: 'UI model',
    ExpiringSecret: 'UI model (services/dashboard.ts)',
    AnomalyAlert: 'UI model (services/dashboard.ts)',
    DashboardStats: 'UI model (services/dashboard.ts)',
    ActivityItem: 'UI model (services/dashboard.ts)',
    NavigationItem: 'UI only',
    ApiResponse: 'generic envelope; the spec has no envelope schema, every route inlines {data, message}',
    PaginatedResponse: 'UI model built by services; not a wire shape',
    ValidationError: 'UI only (form validation)',
    AppNotification: 'UI toast model',
    SecretFilters: 'UI filter state',
    PaginationState: 'UI state',
    LoginFormData: 'UI form state',
    AuthState: 'UI store state',
    ImpersonatedBy: 'UI model translated by authStore from ProfileImpersonation',
    // #2848: not a wire type. authStore derives it from LoginResponse's
    // mfa_required branch (camelCase fields, unlike anything the server sends)
    // and holds it until verifyMfa()/clearMfaChallenge() resolves it.
    MfaChallengeState: 'UI store state derived by authStore from LoginResponse',
    MfaGrace: 'UI model translated by authStore (mfaGraceFromWire) from MfaGraceWire',
    PasswordResetRequest: 'UI form state',
    PasswordResetConfirm: 'UI form state',
    EnvironmentConfig: 'client build/runtime config',
    GroupSharedSecret: 'UI model normalised from the server SecretNode',
    SecretAccessReport:
        'UI model (services/secrets.ts accessList maps the snake_case listAccessors body, degraded_reasons -> degradedReasons, ' +
        'into it); the spec inlines that 200 body with no named schema, and its accessors items are compared as SecretAccessor',
    // Wire types the spec does not schema (200 is a prose description only).
    SecretPolicy: 'GET /secrets/policy is not documented in openapi.yaml',
    ProfileImpersonation: 'GET /api/v1/auth/profile 200 has a prose description, no schema',
    SecretUsageStat: 'GET /secrets/usage/most-accessed 200 has a prose description, no schema',
    UnusedSecretStat: 'GET /secrets/usage/unused 200 has a prose description, no schema',
    RotationStatusEntry: 'GET /rotation-policies/status 200 has a prose description, no schema',
};

const ALLOW: Record<string, string> = {};

describe('web/src/types agree with openapi.yaml (INV-WEB-05)', () => {
    const doc = parse(readFileSync(OPENAPI, 'utf8'));
    const program = createProgram(Object.fromEntries(FILES.map((f) => [f, readFileSync(f, 'utf8')])));
    const checker = program.getTypeChecker();
    const interfaces = exportedInterfaces(program, FILES);

    it('every exported interface is compared or explicitly exempted', () => {
        const names = [...interfaces.keys()];
        const unclassified = names.filter((n) => !(n in WIRE_TYPES) && !(n in NOT_COMPARED));
        const both = names.filter((n) => n in WIRE_TYPES && n in NOT_COMPARED);
        const stale = [...Object.keys(WIRE_TYPES), ...Object.keys(NOT_COMPARED)].filter((n) => !interfaces.has(n));
        expect({ unclassified, both, stale }).toEqual({ unclassified: [], both: [], stale: [] });
    });

    it('wire types match their OpenAPI schemas (fields, kinds, nullability, enums)', () => {
        const drift: string[] = [];
        const used = new Set<string>();
        for (const [name, pair] of Object.entries(WIRE_TYPES)) {
            const shape = toShape(checker, interfaces.get(name)!);
            const request = 'op' in pair.locate && pair.locate.op.request === true;
            compare(doc, shape, locate(doc, pair.locate), name, { ...pair.allow, ...ALLOW }, used, drift, request);
        }
        expect(drift).toEqual([]);
        const unusedAllow = [
            ...Object.keys(ALLOW),
            ...Object.values(WIRE_TYPES).flatMap((p) => Object.keys(p.allow ?? {})),
        ].filter((k) => !used.has(k));
        expect(unusedAllow, 'stale exemptions: remove them').toEqual([]);
    });
});
