import { formatDateTime } from '../../utils/datetime';
import React, { useState } from 'react';
import { useSearchParams } from 'react-router';
import {
    UserIcon,
    ShieldCheckIcon,
    ComputerDesktopIcon,
    KeyIcon,
    TrashIcon,
    ClipboardDocumentIcon,
    CheckIcon,
    PlusIcon,
} from '@heroicons/react/24/outline';
import { useAuthStore } from '../../store/authStore';
import { Button } from '../../components/ui/Button';
import { Input } from '../../components/ui/Input';
import { Alert } from '../../components/ui/Alert';
import { Spinner } from '../../components/ui/Loading';
import { Modal } from '../../components/ui/Modal';
import { copyToClipboard } from '../../utils';
import {
    useUpdateProfile,
    useChangePassword,
    useSessions,
    useRevokeSession,
    usePersonalTokens,
    useCreatePersonalToken,
    useRevokePersonalToken,
} from '../../features/account';
import type { AccountSession } from '../../services/account';
import { buildCreateTokenBody, type PersonalAccessToken } from '../../services/personalTokens';
import { useProjects, useProjectEnvironments } from '../../features/projects/api';
import { useAutoClearOnIdle } from '../../hooks/useAutoClearOnIdle';
import { MfaSection } from '../../features/account/MfaSection';

// Common preset permissions offered when scoping a token (ADR-042). The advanced
// free-text field covers anything beyond these.
const PRESET_PERMISSIONS: { value: string; label: string }[] = [
    { value: 'secrets.read', label: 'Read secrets' },
    { value: 'secrets.write', label: 'Write secrets' },
    { value: 'secrets.delete', label: 'Delete secrets' },
];

const TABS = [
    { id: 'profile', label: 'Basic Info', icon: UserIcon },
    { id: 'security', label: 'Security', icon: ShieldCheckIcon },
    { id: 'sessions', label: 'Active Sessions', icon: ComputerDesktopIcon },
    { id: 'tokens', label: 'API Tokens', icon: KeyIcon },
] as const;

function formatDate(value?: string | null): string {
    if (!value) return '—';
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? '—' : formatDateTime(d);
}

// ── Basic Info ──────────────────────────────────────────────────────────────

const BasicInfoTab: React.FC = () => {
    const { user, setUser } = useAuthStore();
    const [displayName, setDisplayName] = useState(user?.displayName || '');
    const [email, setEmail] = useState(user?.email || '');
    const [saved, setSaved] = useState(false);
    const updateProfile = useUpdateProfile();

    const handleSubmit = (e: React.SubmitEvent<HTMLFormElement>) => {
        e.preventDefault();
        setSaved(false);
        updateProfile.mutate(
            { display_name: displayName, email },
            {
                onSuccess: (p) => {
                    setSaved(true);
                    if (user) {
                        setUser({ ...user, displayName: p.display_name, email: p.email });
                    }
                },
            }
        );
    };

    return (
        <form onSubmit={handleSubmit} className="space-y-6 max-w-xl">
            <div>
                <h3 className="text-lg font-medium" style={{ color: 'var(--text-primary)' }}>
                    Profile Information
                </h3>
                <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                    Update your display name and email address.
                </p>
            </div>

            {updateProfile.isError && (
                <Alert
                    type="error"
                    title="Could not update profile"
                    message={(updateProfile.error as Error)?.message || 'Please try again.'}
                />
            )}
            {saved && !updateProfile.isPending && (
                <Alert type="success" title="Saved" message="Your profile has been updated." />
            )}

            <Input
                label="Display Name"
                type="text"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                required
            />
            <Input label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />

            <div>
                <p className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                    Username
                </p>
                <div
                    className="text-sm px-3 py-2 rounded-md"
                    style={{ color: 'var(--text-muted)', backgroundColor: 'var(--bg-app)' }}
                >
                    {user?.username}
                </div>
                <p className="mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
                    Your username and roles are managed by administrators.
                </p>
            </div>

            <div className="flex justify-end">
                <Button type="submit" disabled={updateProfile.isPending}>
                    {updateProfile.isPending && <Spinner size="sm" className="mr-2" />}
                    Save Changes
                </Button>
            </div>
        </form>
    );
};

// ── Security ────────────────────────────────────────────────────────────────

const SecurityTab: React.FC<{ mfaRequired?: boolean }> = ({ mfaRequired = false }) => {
    const [current, setCurrent] = useState('');
    const [next, setNext] = useState('');
    const [confirm, setConfirm] = useState('');
    const [localError, setLocalError] = useState('');
    const [done, setDone] = useState(false);
    const changePassword = useChangePassword();

    const handleSubmit = (e: React.SubmitEvent<HTMLFormElement>) => {
        e.preventDefault();
        setLocalError('');
        setDone(false);
        if (next !== confirm) {
            setLocalError('New passwords do not match.');
            return;
        }
        if (next.length < 8) {
            setLocalError('New password must be at least 8 characters.');
            return;
        }
        changePassword.mutate(
            { current_password: current, new_password: next },
            {
                onSuccess: () => {
                    setDone(true);
                    setCurrent('');
                    setNext('');
                    setConfirm('');
                    // ADR-025: lift the must-change-password gate now that it's done.
                    useAuthStore.getState().clearPasswordChangeRequired();
                },
            }
        );
    };

    return (
        <div className="space-y-10 max-w-xl">
            <form onSubmit={handleSubmit} className="space-y-6">
                <div>
                    <h3 className="text-lg font-medium" style={{ color: 'var(--text-primary)' }}>
                        Change Password
                    </h3>
                    <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                        Changing your password signs out your other active sessions.
                    </p>
                </div>

                {(localError || changePassword.isError) && (
                    <Alert
                        type="error"
                        title="Could not change password"
                        message={localError || (changePassword.error as Error)?.message || 'Please try again.'}
                    />
                )}
                {done && !changePassword.isPending && (
                    <Alert type="success" title="Password changed" message="Other sessions have been signed out." />
                )}

                <Input
                    label="Current Password"
                    type="password"
                    value={current}
                    onChange={(e) => setCurrent(e.target.value)}
                    required
                />
                <Input
                    label="New Password"
                    type="password"
                    value={next}
                    onChange={(e) => setNext(e.target.value)}
                    required
                />
                <Input
                    label="Confirm New Password"
                    type="password"
                    value={confirm}
                    onChange={(e) => setConfirm(e.target.value)}
                    required
                />
                <div className="flex justify-end">
                    <Button type="submit" disabled={changePassword.isPending}>
                        {changePassword.isPending && <Spinner size="sm" className="mr-2" />}
                        <KeyIcon className="h-4 w-4 mr-2" />
                        Change Password
                    </Button>
                </div>
            </form>

            <MfaSection enrolmentRequired={mfaRequired} />
        </div>
    );
};

// ── Active Sessions ───────────────────────────────────────────────────────────

const SessionsTab: React.FC = () => {
    const { data: sessions, isLoading, isError } = useSessions();
    const revoke = useRevokeSession();

    if (isLoading) {
        return (
            <div className="flex justify-center py-10">
                <Spinner />
            </div>
        );
    }
    if (isError) {
        return <Alert type="error" title="Could not load sessions" message="Please try again." />;
    }

    return (
        <div className="space-y-4">
            <div>
                <h3 className="text-lg font-medium" style={{ color: 'var(--text-primary)' }}>
                    Active Sessions
                </h3>
                <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                    Devices currently signed in to your account. End any session you don't recognise.
                </p>
            </div>

            <div className="space-y-3">
                {(sessions || []).map((s: AccountSession) => (
                    <div
                        key={s.id}
                        className="rounded-lg p-4 flex items-center justify-between"
                        style={{ backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border)' }}
                    >
                        <div className="min-w-0">
                            <div className="flex items-center gap-2">
                                <span className="text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>
                                    {s.user_agent || 'Unknown device'}
                                </span>
                                {s.current && (
                                    <span
                                        className="text-xs font-medium px-2 py-0.5 rounded-full"
                                        style={{ color: 'var(--accent-text)', backgroundColor: 'var(--accent-subtle)' }}
                                    >
                                        Current
                                    </span>
                                )}
                            </div>
                            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                                {s.ip_address || 'unknown IP'} · last active {formatDate(s.last_seen_at)}
                            </p>
                        </div>
                        <Button
                            variant="outline"
                            size="sm"
                            disabled={s.current || revoke.isPending}
                            onClick={() => revoke.mutate(s.id)}
                            title={s.current ? 'You cannot end your current session here' : 'End this session'}
                        >
                            End Session
                        </Button>
                    </div>
                ))}
                {(sessions || []).length === 0 && (
                    <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                        No active sessions.
                    </p>
                )}
            </div>
        </div>
    );
};

// ── API Tokens ────────────────────────────────────────────────────────────────

// ScopeChip renders a token's least-privilege restriction (ADR-042): a project or
// environment confinement, or an allowed permission.
const ScopeChip: React.FC<{ label: string; kind: 'project' | 'env' | 'perm' }> = ({ label, kind }) => {
    const innerChipLabel = kind === 'env' ? `⬢ ${label}` : label;
    const chipLabel = kind === 'project' ? `▣ ${label}` : innerChipLabel;
    return (
        <span
            className="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[11px] font-medium"
            style={{
                fontFamily: kind === 'perm' ? 'var(--font-mono)' : undefined,
                backgroundColor: kind === 'perm' ? 'var(--bg-subtle)' : 'var(--bg-app)',
                color: 'var(--text-secondary)',
                border: '1px solid var(--border)',
            }}
        >
            {chipLabel}
        </span>
    );
};

const TokensTab: React.FC = () => {
    const { data: tokens, isLoading, isError } = usePersonalTokens();
    const { data: projects } = useProjects();
    const createToken = useCreatePersonalToken();
    const revoke = useRevokePersonalToken();

    const [showCreate, setShowCreate] = useState(false);
    const [name, setName] = useState('');
    const [expiresAt, setExpiresAt] = useState('');
    const [newToken, setNewToken] = useState<string | null>(null);
    const [copied, setCopied] = useState(false);

    // ADR-042 least-privilege scoping state.
    const [limited, setLimited] = useState(false);
    const [permissions, setPermissions] = useState<string[]>([]);
    const [extraPermissions, setExtraPermissions] = useState('');
    const [projectScope, setProjectScope] = useState(0);
    const [environmentScope, setEnvironmentScope] = useState(0);
    // Environments to choose from once a project is selected (env confinement is
    // only meaningful within a project, ADR-042).
    const { data: scopeEnvironments } = useProjectEnvironments(projectScope);

    // G28: the token otherwise stays rendered in the modal indefinitely until the
    // user explicitly clicks Done — auto-clear (close the modal) on idle, tab
    // backgrounding, or window blur too.
    useAutoClearOnIdle(() => {
        setNewToken(null);
        setShowCreate(false);
    }, newToken !== null);

    const togglePermission = (value: string) =>
        setPermissions((prev) => (prev.includes(value) ? prev.filter((p) => p !== value) : [...prev, value]));

    // A "limited" token with no permission and no project chosen would silently be
    // unrestricted — guide the user to pick at least one constraint.
    const noConstraintChosen = limited && permissions.length === 0 && !extraPermissions.trim() && projectScope === 0;

    const openCreate = () => {
        setName('');
        setExpiresAt('');
        setNewToken(null);
        setCopied(false);
        setLimited(false);
        setPermissions([]);
        setExtraPermissions('');
        setProjectScope(0);
        setEnvironmentScope(0);
        createToken.reset();
        setShowCreate(true);
    };

    const handleCreate = (e: React.SubmitEvent<HTMLFormElement>) => {
        e.preventDefault();
        const body = buildCreateTokenBody({
            name,
            expiresAt,
            limited,
            permissions,
            extraPermissions,
            projectScope,
            environmentScope,
        });
        createToken.mutate(body, { onSuccess: (res) => setNewToken(res.token) });
    };

    const projectName = (id: number) => projects?.find((p) => p.id === id)?.name ?? `project #${id}`;

    const copy = async () => {
        if (!newToken) return;
        await copyToClipboard(newToken);
        setCopied(true);
    };

    let tokenListContent: React.ReactNode;
    if (isLoading) {
        tokenListContent = (
            <div className="flex justify-center py-10">
                <Spinner />
            </div>
        );
    } else if (isError) {
        tokenListContent = <Alert type="error" title="Could not load tokens" message="Please try again." />;
    } else {
        tokenListContent = (
            <div className="space-y-3">
                {(tokens || []).map((t: PersonalAccessToken) => (
                    <div
                        key={t.id}
                        className="rounded-lg p-4 flex items-center justify-between"
                        style={{
                            backgroundColor: 'var(--bg-surface)',
                            border: '1px solid var(--border)',
                            opacity: t.revoked ? 0.5 : 1,
                        }}
                    >
                        <div className="min-w-0">
                            <div className="flex items-center gap-2">
                                <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
                                    {t.name}
                                </span>
                                <code
                                    className="text-xs"
                                    style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}
                                >
                                    {t.token_prefix}…
                                </code>
                                {t.revoked && (
                                    <span
                                        className="text-xs px-2 py-0.5 rounded-full"
                                        style={{ color: 'var(--text-muted)', backgroundColor: 'var(--bg-app)' }}
                                    >
                                        revoked
                                    </span>
                                )}
                            </div>
                            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                                created {formatDate(t.created_at)} · last used {formatDate(t.last_used_at)} ·{' '}
                                {t.expires_at ? `expires ${formatDate(t.expires_at)}` : 'never expires'}
                            </p>
                            {t.scopes.length > 0 || t.project_scope > 0 || t.environment_scope > 0 ? (
                                <div className="mt-1.5 flex flex-wrap items-center gap-1">
                                    {t.project_scope > 0 && (
                                        <ScopeChip label={projectName(t.project_scope)} kind="project" />
                                    )}
                                    {t.environment_scope > 0 && (
                                        <ScopeChip label={`env #${t.environment_scope}`} kind="env" />
                                    )}
                                    {t.scopes.map((s) => (
                                        <ScopeChip key={s} label={s} kind="perm" />
                                    ))}
                                </div>
                            ) : (
                                <p className="mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
                                    full access (all your permissions)
                                </p>
                            )}
                        </div>
                        {!t.revoked && (
                            <Button
                                variant="outline"
                                size="sm"
                                disabled={revoke.isPending}
                                onClick={() => revoke.mutate(t.id)}
                                title="Revoke this token"
                            >
                                <TrashIcon className="h-4 w-4" />
                            </Button>
                        )}
                    </div>
                ))}
                {(tokens || []).length === 0 && (
                    <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                        You have no personal access tokens yet.
                    </p>
                )}
            </div>
        );
    }

    return (
        <div className="space-y-4">
            <div className="flex items-start justify-between">
                <div>
                    <h3 className="text-lg font-medium" style={{ color: 'var(--text-primary)' }}>
                        Personal Access Tokens
                    </h3>
                    <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                        Tokens authenticate API and CLI requests as you. By default they carry all of your permissions —
                        restrict a token to least privilege when you create it.
                    </p>
                </div>
                <Button size="sm" onClick={openCreate}>
                    <PlusIcon className="h-4 w-4 mr-1.5" />
                    New Token
                </Button>
            </div>

            {tokenListContent}

            <Modal isOpen={showCreate} onClose={() => setShowCreate(false)} title="New Personal Access Token">
                {newToken ? (
                    <div className="space-y-4">
                        <Alert
                            type="warning"
                            title="Copy your token now"
                            message="This is the only time the token will be shown. Store it somewhere safe."
                        />
                        <div
                            className="rounded-md p-3 flex items-center justify-between gap-2"
                            style={{ backgroundColor: 'var(--bg-app)', border: '1px solid var(--border)' }}
                        >
                            <code
                                className="text-sm break-all"
                                style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}
                            >
                                {newToken}
                            </code>
                            <Button variant="outline" size="sm" onClick={copy} title="Copy token">
                                {copied ? (
                                    <CheckIcon className="h-4 w-4" />
                                ) : (
                                    <ClipboardDocumentIcon className="h-4 w-4" />
                                )}
                            </Button>
                        </div>
                        <div className="flex justify-end">
                            <Button onClick={() => setShowCreate(false)}>Done</Button>
                        </div>
                    </div>
                ) : (
                    <form onSubmit={handleCreate} className="space-y-4">
                        {createToken.isError && (
                            <Alert
                                type="error"
                                title="Could not create token"
                                message={(createToken.error as Error)?.message || 'Please try again.'}
                            />
                        )}
                        <Input
                            label="Token name"
                            type="text"
                            placeholder="e.g. ci-pipeline"
                            value={name}
                            onChange={(e) => setName(e.target.value)}
                            required
                        />
                        <Input
                            label="Expires (optional)"
                            type="date"
                            value={expiresAt}
                            onChange={(e) => setExpiresAt(e.target.value)}
                        />

                        {/* ADR-042 least-privilege scoping */}
                        <fieldset className="space-y-2">
                            <legend className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
                                Access
                            </legend>
                            <label className="flex items-start gap-2 cursor-pointer">
                                <input
                                    type="radio"
                                    name="pat-access"
                                    checked={!limited}
                                    onChange={() => setLimited(false)}
                                    className="mt-0.5"
                                />
                                <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                                    <span style={{ color: 'var(--text-primary)' }}>Full access</span> — all of your
                                    current permissions
                                </span>
                            </label>
                            <label className="flex items-start gap-2 cursor-pointer">
                                <input
                                    type="radio"
                                    name="pat-access"
                                    checked={limited}
                                    onChange={() => setLimited(true)}
                                    className="mt-0.5"
                                />
                                <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                                    <span style={{ color: 'var(--text-primary)' }}>Limited access</span> — restrict to
                                    specific permissions and/or one project
                                </span>
                            </label>
                        </fieldset>

                        {limited && (
                            <div
                                className="space-y-3 rounded-md p-3"
                                style={{ backgroundColor: 'var(--bg-app)', border: '1px solid var(--border)' }}
                            >
                                <div>
                                    <p className="text-xs font-medium mb-1.5" style={{ color: 'var(--text-muted)' }}>
                                        Permissions
                                    </p>
                                    <div className="flex flex-wrap gap-3">
                                        {PRESET_PERMISSIONS.map((perm) => (
                                            <label
                                                key={perm.value}
                                                className="flex items-center gap-1.5 cursor-pointer"
                                            >
                                                <input
                                                    type="checkbox"
                                                    checked={permissions.includes(perm.value)}
                                                    onChange={() => togglePermission(perm.value)}
                                                />
                                                <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                                                    {perm.label}{' '}
                                                    <code
                                                        className="text-xs"
                                                        style={{
                                                            color: 'var(--text-muted)',
                                                            fontFamily: 'var(--font-mono)',
                                                        }}
                                                    >
                                                        {perm.value}
                                                    </code>
                                                </span>
                                            </label>
                                        ))}
                                    </div>
                                </div>
                                <Input
                                    label="Additional permissions (optional, comma-separated)"
                                    type="text"
                                    placeholder="e.g. rotation.write, secrets.*"
                                    value={extraPermissions}
                                    onChange={(e) => setExtraPermissions(e.target.value)}
                                />
                                <div>
                                    <label
                                        htmlFor="pat-project-scope"
                                        className="block text-sm font-medium mb-1"
                                        style={{ color: 'var(--text-primary)' }}
                                    >
                                        Project
                                    </label>
                                    <select
                                        id="pat-project-scope"
                                        value={projectScope}
                                        onChange={(e) => {
                                            setProjectScope(Number(e.target.value));
                                            setEnvironmentScope(0); // env belongs to a project — reset on change
                                        }}
                                        className="w-full rounded-md px-3 py-2 text-sm"
                                        style={{
                                            backgroundColor: 'var(--bg-surface)',
                                            border: '1px solid var(--border)',
                                            color: 'var(--text-primary)',
                                        }}
                                    >
                                        <option value={0}>Any project</option>
                                        {(projects ?? []).map((p) => (
                                            <option key={p.id} value={p.id}>
                                                {p.name}
                                            </option>
                                        ))}
                                    </select>
                                </div>
                                {projectScope > 0 && (
                                    <div>
                                        <label
                                            htmlFor="pat-environment-scope"
                                            className="block text-sm font-medium mb-1"
                                            style={{ color: 'var(--text-primary)' }}
                                        >
                                            Environment
                                        </label>
                                        <select
                                            id="pat-environment-scope"
                                            value={environmentScope}
                                            onChange={(e) => setEnvironmentScope(Number(e.target.value))}
                                            className="w-full rounded-md px-3 py-2 text-sm"
                                            style={{
                                                backgroundColor: 'var(--bg-surface)',
                                                border: '1px solid var(--border)',
                                                color: 'var(--text-primary)',
                                            }}
                                        >
                                            <option value={0}>Any environment</option>
                                            {(scopeEnvironments ?? []).map((env) => (
                                                <option key={env.id} value={env.id}>
                                                    {env.name}
                                                </option>
                                            ))}
                                        </select>
                                    </div>
                                )}
                                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                                    A token can never do more than you can — these only narrow it.
                                </p>
                                {noConstraintChosen && (
                                    <p className="text-xs" style={{ color: 'var(--color-warning, #b45309)' }}>
                                        Pick at least one permission or a project, or choose Full access.
                                    </p>
                                )}
                            </div>
                        )}

                        <div className="flex justify-end gap-2">
                            <Button type="button" variant="outline" onClick={() => setShowCreate(false)}>
                                Cancel
                            </Button>
                            <Button
                                type="submit"
                                disabled={createToken.isPending || !name.trim() || noConstraintChosen}
                            >
                                {createToken.isPending && <Spinner size="sm" className="mr-2" />}
                                Create Token
                            </Button>
                        </div>
                    </form>
                )}
            </Modal>
        </div>
    );
};

// ── Page ────────────────────────────────────────────────────────────────────

export const ProfilePage: React.FC = () => {
    // #2924: the MFAEnrollmentRequired redirect lands here as /profile?tab=security&mfa=required.
    const [searchParams] = useSearchParams();
    const mfaRequired = searchParams.get('mfa') === 'required';
    const [activeTab, setActiveTab] = useState<(typeof TABS)[number]['id']>(
        () => TABS.find((t) => t.id === searchParams.get('tab'))?.id ?? 'profile'
    );

    return (
        <div className="p-6 max-w-4xl mx-auto">
            <div className="mb-6">
                <h1 className="text-2xl font-semibold" style={{ color: 'var(--text-primary)' }}>
                    My Account
                </h1>
                <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                    Manage your profile, password, sessions, and API tokens.
                </p>
            </div>

            <div className="border-b mb-6" style={{ borderColor: 'var(--border)' }}>
                <nav className="-mb-px flex gap-6">
                    {TABS.map((tab) => {
                        const Icon = tab.icon;
                        const active = activeTab === tab.id;
                        return (
                            <button
                                type="button"
                                key={tab.id}
                                onClick={() => setActiveTab(tab.id)}
                                className="flex items-center py-3 px-1 border-b-2 font-medium text-sm transition-colors"
                                style={{
                                    borderColor: active ? 'var(--accent)' : 'transparent',
                                    color: active ? 'var(--accent-text)' : 'var(--text-muted)',
                                }}
                            >
                                <Icon className="h-5 w-5 mr-2" />
                                {tab.label}
                            </button>
                        );
                    })}
                </nav>
            </div>

            {activeTab === 'profile' && <BasicInfoTab />}
            {activeTab === 'security' && <SecurityTab mfaRequired={mfaRequired} />}
            {activeTab === 'sessions' && <SessionsTab />}
            {activeTab === 'tokens' && <TokensTab />}
        </div>
    );
};
