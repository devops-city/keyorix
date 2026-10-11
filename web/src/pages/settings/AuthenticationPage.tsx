import { formatGoDuration } from '../../utils/datetime';
import React from 'react';
import { useAuthConfig } from '../../features/dashboard';
import { Spinner } from '../../components/ui';

interface SectionProps {
    title: string;
    note?: string;
    children: React.ReactNode;
}

const Section: React.FC<SectionProps> = ({ title, note, children }) => (
    <div
        className="rounded-xl border overflow-hidden mb-6"
        style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
    >
        <div className="px-6 py-4 border-b" style={{ borderColor: 'var(--border)' }}>
            <h2 className="text-sm font-semibold uppercase tracking-widest" style={{ color: 'var(--text-muted)' }}>
                {title}
            </h2>
        </div>
        <div className="px-6 py-5 space-y-3">
            {children}
            {note && (
                <p className="text-xs pt-1" style={{ color: 'var(--text-muted)' }}>
                    {note}
                </p>
            )}
        </div>
    </div>
);

const Row: React.FC<{ label: string; value: React.ReactNode }> = ({ label, value }) => (
    <div className="flex items-center justify-between">
        <span className="text-sm" style={{ color: 'var(--text-muted)' }}>
            {label}
        </span>
        <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
            {value}
        </span>
    </div>
);

const CapabilityPill: React.FC<{ label: string; active: boolean }> = ({ label, active }) => (
    <span
        className="text-xs px-2.5 py-1 rounded-full font-medium"
        style={
            active
                ? { backgroundColor: 'rgba(34,197,94,0.15)', color: '#16a34a' }
                : { backgroundColor: 'var(--bg-muted)', color: 'var(--text-muted)' }
        }
    >
        {label}
    </span>
);

const formatTTL = (value: string): string => (value === '0s' ? 'No ceiling' : formatGoDuration(value));

export const AuthenticationPage: React.FC = () => {
    const { data: authConfig, isLoading, isError } = useAuthConfig();

    return (
        <div className="max-w-2xl mx-auto px-6 py-8">
            <div className="mb-8">
                <h1 className="text-2xl font-bold tracking-tight" style={{ color: 'var(--text-primary)' }}>
                    Authentication
                </h1>
                <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                    Current authentication policy for this Keyorix server. Set via <code>keyorix.yaml</code> — this page
                    is read-only.
                </p>
            </div>

            {isLoading && (
                <div className="flex justify-center py-12">
                    <Spinner />
                </div>
            )}

            {!isLoading && isError && (
                <div
                    className="rounded-xl border px-6 py-8 text-center text-sm"
                    style={{
                        borderColor: 'var(--border)',
                        backgroundColor: 'var(--bg-surface)',
                        color: 'var(--text-muted)',
                    }}
                >
                    Unable to load authentication configuration. This page requires administrator access, or the server
                    may be unreachable.
                </div>
            )}

            {!isLoading && !isError && authConfig && (
                <>
                    <Section title="Session">
                        <Row label="Access token TTL" value={formatTTL(authConfig.session.access_ttl)} />
                        <Row label="Absolute session ceiling" value={formatTTL(authConfig.session.absolute_ttl)} />
                    </Section>

                    <Section title="Password policy">
                        <Row label="Minimum length" value={authConfig.password_policy.min_length} />
                        <div className="flex flex-wrap gap-1.5 pt-1">
                            <CapabilityPill label="Uppercase" active={authConfig.password_policy.require_uppercase} />
                            <CapabilityPill label="Lowercase" active={authConfig.password_policy.require_lowercase} />
                            <CapabilityPill label="Digit" active={authConfig.password_policy.require_digit} />
                            <CapabilityPill label="Special char" active={authConfig.password_policy.require_special} />
                            <CapabilityPill
                                label="Reject personal info"
                                active={authConfig.password_policy.reject_personal_info}
                            />
                            <CapabilityPill
                                label="Reject common passwords"
                                active={authConfig.password_policy.reject_common_passwords}
                            />
                        </div>
                        <Row label="Password history" value={`${authConfig.password_policy.history_count} passwords`} />
                        <Row
                            label="Maximum age"
                            value={
                                authConfig.password_policy.max_age_days > 0
                                    ? `${authConfig.password_policy.max_age_days} days`
                                    : 'Never expires'
                            }
                        />
                    </Section>

                    <Section title="Login lockout">
                        <Row label="Enabled" value={authConfig.login_lockout.enabled ? 'Yes' : 'No'} />
                        <Row label="Max attempts" value={authConfig.login_lockout.max_attempts} />
                        <Row label="Window" value={formatGoDuration(authConfig.login_lockout.window)} />
                        <Row label="Base cooldown" value={formatGoDuration(authConfig.login_lockout.base_cooldown)} />
                        <Row label="Max cooldown" value={formatGoDuration(authConfig.login_lockout.max_cooldown)} />
                    </Section>

                    <Section title="Multi-factor & passkeys">
                        <Row label="Require MFA (org-wide)" value={authConfig.require_mfa ? 'Yes' : 'No'} />
                        <Row label="WebAuthn / passkeys" value={authConfig.webauthn.enabled ? 'Enabled' : 'Disabled'} />
                        {authConfig.webauthn.enabled && (
                            <>
                                <Row label="Relying party ID" value={authConfig.webauthn.rp_id || '—'} />
                                <Row label="Relying party name" value={authConfig.webauthn.rp_display_name || '—'} />
                            </>
                        )}
                    </Section>

                    <Section
                        title="Single sign-on"
                        {...(authConfig.sso.providers.length > 0
                            ? { note: 'Issuer, client ID, and client secret are never exposed here.' }
                            : {})}
                    >
                        <Row label="Enabled" value={authConfig.sso.enabled ? 'Yes' : 'No'} />
                        {authConfig.sso.providers.length === 0 ? (
                            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                                No SSO providers configured.
                            </p>
                        ) : (
                            <div className="space-y-2 pt-1">
                                {authConfig.sso.providers.map((provider) => (
                                    <div
                                        key={provider.name}
                                        className="flex items-center justify-between px-3 py-2 rounded-lg"
                                        style={{ backgroundColor: 'var(--bg-subtle)' }}
                                    >
                                        <div>
                                            <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
                                                {provider.name}
                                            </p>
                                            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                                                {provider.type}
                                            </p>
                                        </div>
                                        <div className="flex gap-1.5">
                                            {provider.auto_provision && (
                                                <CapabilityPill label="Auto-provision" active />
                                            )}
                                            {provider.group_sync && <CapabilityPill label="Group sync" active />}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}
                    </Section>
                </>
            )}
        </div>
    );
};
