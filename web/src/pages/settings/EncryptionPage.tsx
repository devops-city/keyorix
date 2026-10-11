import React from 'react';
import { useEncryptionConfig } from '../../features/dashboard';
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

export const EncryptionPage: React.FC = () => {
    const { data: encryptionConfig, isLoading, isError } = useEncryptionConfig();

    return (
        <div className="max-w-2xl mx-auto px-6 py-8">
            <div className="mb-8">
                <h1 className="text-2xl font-bold tracking-tight" style={{ color: 'var(--text-primary)' }}>
                    Encryption & Keys
                </h1>
                <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                    Current envelope-encryption configuration for this Keyorix server. Set via <code>keyorix.yaml</code>{' '}
                    — this page is read-only, and key material locations are never shown here.
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
                    Unable to load encryption configuration. This page requires administrator access, or the server may
                    be unreachable.
                </div>
            )}

            {!isLoading && !isError && encryptionConfig && (
                <>
                    <Section title="Encryption">
                        <Row label="Enabled" value={encryptionConfig.enabled ? 'Yes' : 'No'} />
                    </Section>

                    <Section
                        title="Key provider"
                        note="File paths, exec commands, environment variable names, and KMS key IDs are never exposed here."
                    >
                        <Row label="Type" value={encryptionConfig.key_provider.type || 'password (default)'} />
                        {encryptionConfig.key_provider.shamir_commitment && (
                            <Row
                                label="Shamir commitment"
                                value={
                                    <span className="font-mono text-xs">
                                        {encryptionConfig.key_provider.shamir_commitment.slice(0, 16)}…
                                    </span>
                                }
                            />
                        )}
                        <Row label="Fallback providers" value={encryptionConfig.key_provider.fallback_count} />
                    </Section>
                </>
            )}
        </div>
    );
};
