import { formatDateTime } from '../../utils/datetime';
import React from 'react';
import {
    useSystemInfo,
    useSystemMetrics,
    getSystemHealthSeverity,
    HEALTH_STATUS_STYLES,
    parseUptime,
} from '../../features/dashboard';
import { Spinner } from '../../components/ui';
import { isKnownBuildValue } from '../../utils/buildInfo';

const formatBytes = (bytes: number): string => {
    if (!bytes) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    const value = bytes / 1024 ** exponent;
    return `${exponent === 0 ? value : value.toFixed(1)} ${units[exponent]}`;
};

const formatLastGC = (nanosSinceEpoch: number): string => {
    if (!nanosSinceEpoch) return '—';
    return formatDateTime(new Date(nanosSinceEpoch / 1e6), { seconds: true });
};

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

export const SystemHealthPage: React.FC = () => {
    const { data: metrics, isLoading: metricsLoading, isError: metricsError } = useSystemMetrics();
    const { data: sysInfo, isLoading: sysInfoLoading, isError: sysInfoError } = useSystemInfo();

    const isLoading = metricsLoading || sysInfoLoading;
    const hasError = metricsError || sysInfoError;
    const severity = getSystemHealthSeverity(metrics, sysInfo);
    const statusStyle = HEALTH_STATUS_STYLES[severity];

    return (
        <div className="max-w-2xl mx-auto px-6 py-8">
            <div className="mb-8">
                <h1 className="text-2xl font-bold tracking-tight" style={{ color: 'var(--text-primary)' }}>
                    System Health
                </h1>
                <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                    Build, runtime, and configuration info for this Keyorix server. Live traffic and query metrics
                    aren't instrumented in this deployment yet.
                </p>
            </div>

            {isLoading && (
                <div className="flex justify-center py-12">
                    <Spinner />
                </div>
            )}

            {!isLoading && hasError && (
                <div
                    className="rounded-xl border px-6 py-8 text-center text-sm"
                    style={{
                        borderColor: 'var(--border)',
                        backgroundColor: 'var(--bg-surface)',
                        color: 'var(--text-muted)',
                    }}
                >
                    Unable to load system health data. This page requires administrator access, or the server may be
                    unreachable.
                </div>
            )}

            {!isLoading && !hasError && metrics && sysInfo && (
                <>
                    <Section title="Status">
                        <div className="flex items-center justify-between">
                            <span className="text-sm" style={{ color: 'var(--text-muted)' }}>
                                Status
                            </span>
                            <div className="flex items-center gap-1.5">
                                <div className={`w-2 h-2 rounded-full ${statusStyle.dot} animate-pulse`} />
                                <span className={`text-sm font-semibold ${statusStyle.text}`}>{statusStyle.label}</span>
                            </div>
                        </div>
                        <Row label="Uptime" value={parseUptime(metrics.uptime ?? sysInfo.uptime)} />
                        {isKnownBuildValue(sysInfo.environment) && (
                            <Row label="Environment" value={sysInfo.environment} />
                        )}
                    </Section>

                    <Section title="Server">
                        <Row
                            label="Version"
                            value={
                                isKnownBuildValue(sysInfo.version) ? sysInfo.version : 'Development build (unstamped)'
                            }
                        />
                        {isKnownBuildValue(sysInfo.git_commit) && (
                            <Row label="Git commit" value={sysInfo.git_commit.slice(0, 12)} />
                        )}
                        <Row label="Go version" value={sysInfo.go_version || '—'} />
                        <Row label="OS / Arch" value={`${sysInfo.os || '—'} / ${sysInfo.arch || '—'}`} />
                        {isKnownBuildValue(sysInfo.build_time) && (
                            <Row label="Build time" value={formatDateTime(sysInfo.build_time)} />
                        )}
                    </Section>

                    <Section
                        title="Database"
                        note="Live connection and query metrics aren't instrumented on the server yet."
                    >
                        <Row label="Type" value={sysInfo.database?.type || '—'} />
                        {/* A pool of 0/0/0 means the server does not report pool stats, not that there are no connections. */}
                        {(sysInfo.database?.pool?.max_connections ?? 0) > 0 && (
                            <>
                                <Row label="Max connections" value={sysInfo.database.pool.max_connections} />
                                <Row label="Idle connections" value={sysInfo.database.pool.idle_connections} />
                            </>
                        )}
                    </Section>

                    <Section title="Memory & runtime">
                        <Row label="Goroutines" value={metrics.goroutines} />
                        <Row label="Heap in use" value={formatBytes(metrics.memory?.heap_inuse ?? 0)} />
                        <Row label="Heap allocated" value={formatBytes(metrics.memory?.heap_alloc ?? 0)} />
                        <Row label="Total allocated" value={formatBytes(metrics.memory?.total_alloc ?? 0)} />
                        <Row label="GC runs" value={metrics.gc?.num_gc ?? '—'} />
                        <Row label="Total GC pause" value={`${((metrics.gc?.pause_total ?? 0) / 1e6).toFixed(1)}ms`} />
                        <Row label="Last GC" value={formatLastGC(metrics.gc?.last_gc ?? 0)} />
                    </Section>

                    <Section title="Enabled capabilities">
                        <Row label="Encryption method" value={sysInfo.security?.encryption_method || '—'} />
                        <div className="flex flex-wrap gap-1.5 pt-1">
                            <CapabilityPill label="TLS" active={sysInfo.security?.tls_enabled ?? false} />
                            <CapabilityPill label="Encryption" active={sysInfo.features?.encryption_enabled ?? false} />
                            <CapabilityPill label="Audit" active={sysInfo.security?.audit_enabled ?? false} />
                            <CapabilityPill label="RBAC" active={sysInfo.features?.rbac_enabled ?? false} />
                            <CapabilityPill label="gRPC" active={sysInfo.features?.grpc_enabled ?? false} />
                            <CapabilityPill label="Metrics" active={sysInfo.features?.metrics_enabled ?? false} />
                        </div>
                    </Section>
                </>
            )}
        </div>
    );
};
