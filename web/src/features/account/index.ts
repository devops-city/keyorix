import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { accountApi } from '../../services/account';
import { personalTokensApi, type CreatePersonalTokenBody } from '../../services/personalTokens';
import { mfaApi, type MfaReauthProof } from '../../services/mfa';
import { SENSITIVE_GC_TIME } from '../../lib/queryClient';

const SESSIONS_KEY = 'account-sessions';
const TOKENS_KEY = 'account-tokens';
const MFA_RECOVERY_KEY = 'account-mfa-recovery';

// #2787: the ProfilePage forms (profile, password, session/token revoke, token create)
// read their spinner/disabled state straight off these mutations. With react-query's
// default networkMode ('online') a mutation fired while onlineManager reports offline is
// PAUSED: its promise never settles, isPending stays true, no error is shown and the
// control stays disabled until a reload. 'always' sends the request regardless, so
// offline surfaces as a real network error in the form's own error alert (the API client
// has a request timeout, so nothing else can leave a mutation pending forever).
const NEVER_PAUSE = { networkMode: 'always' } as const;

// ── Profile + password ──────────────────────────────────────────────────────

export const useUpdateProfile = () =>
    useMutation({
        ...NEVER_PAUSE,
        mutationFn: (body: { display_name: string; email: string }) => accountApi.updateProfile(body),
    });

export const useChangePassword = () =>
    useMutation({
        ...NEVER_PAUSE,
        mutationFn: (body: { current_password: string; new_password: string }) => accountApi.changePassword(body),
    });

// ── Active sessions ───────────────────────────────────────────────────────────

export const useSessions = () =>
    useQuery({
        queryKey: [SESSIONS_KEY],
        queryFn: () => accountApi.listSessions(),
        staleTime: 30 * 1000,
    });

export const useRevokeSession = () => {
    const queryClient = useQueryClient();
    return useMutation({
        ...NEVER_PAUSE,
        mutationFn: (id: number) => accountApi.revokeSession(id),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: [SESSIONS_KEY] }),
    });
};

// ── Personal access tokens ─────────────────────────────────────────────────────

export const usePersonalTokens = () =>
    useQuery({
        queryKey: [TOKENS_KEY],
        queryFn: () => personalTokensApi.listTokens(),
        staleTime: 60 * 1000,
    });

export const useCreatePersonalToken = () => {
    const queryClient = useQueryClient();
    return useMutation({
        ...NEVER_PAUSE,
        mutationFn: (body: CreatePersonalTokenBody) => personalTokensApi.createToken(body),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: [TOKENS_KEY] }),
        // G28: the response is a one-time bearer token — don't let react-query's
        // MutationCache retain it for the default 5 minutes after unmount.
        gcTime: SENSITIVE_GC_TIME,
    });
};

export const useRevokePersonalToken = () => {
    const queryClient = useQueryClient();
    return useMutation({
        ...NEVER_PAUSE,
        mutationFn: (id: number) => personalTokensApi.revokeToken(id),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: [TOKENS_KEY] }),
    });
};

// ── MFA (TOTP) self-service ─────────────────────────────────────────────────

// Recovery-code status doubles as the MFA-enabled signal: total === 0 ⇒ MFA off
// (no codes), total > 0 ⇒ enabled with `remaining` unused.
//
// #3155: pass enabled=false while the session is confined to MFA enrolment: the server
// refuses this endpoint (403) there and the answer is already known (no second factor), so
// the page does not ask. It flips on once enrolment completes and the profile stops
// reporting the pending step.
export const useMfaRecoveryStatus = (enabled = true) =>
    useQuery({
        queryKey: [MFA_RECOVERY_KEY],
        queryFn: () => mfaApi.recoveryCodesStatus(),
        staleTime: 30 * 1000,
        enabled,
    });

// G28: enroll returns the TOTP setup secret, and activate returns the freshly
// minted recovery codes — both plaintext. Don't let react-query's MutationCache
// retain either for the default 5 minutes after unmount.
export const useEnrollMfa = () => useMutation({ mutationFn: () => mfaApi.enroll(), gcTime: SENSITIVE_GC_TIME });

export const useActivateMfa = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (vars: { code: string; password: string }) => mfaApi.activate(vars.code, vars.password),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: [MFA_RECOVERY_KEY] }),
        gcTime: SENSITIVE_GC_TIME,
    });
};

export const useDisableMfa = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (proof: MfaReauthProof) => mfaApi.disable(proof),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: [MFA_RECOVERY_KEY] }),
    });
};

export const useRegenerateRecoveryCodes = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (proof: MfaReauthProof) => mfaApi.regenerateRecoveryCodes(proof),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: [MFA_RECOVERY_KEY] }),
        // G28: the response is the freshly minted recovery codes (plaintext).
        gcTime: SENSITIVE_GC_TIME,
    });
};
