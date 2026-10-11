import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '../../../test/test-utils';
import { SystemHealthPage } from '../SystemHealthPage';

const useSystemInfo = vi.fn();
const useSystemMetrics = vi.fn();

vi.mock('../../../features/dashboard', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../../../features/dashboard')>();
    return {
        ...actual,
        useSystemInfo: (...args: any[]) => useSystemInfo(...args),
        useSystemMetrics: (...args: any[]) => useSystemMetrics(...args),
    };
});

const sysInfo = {
    version: '1.2.3',
    build_time: 'unknown',
    git_commit: 'abcdef1234567890',
    go_version: 'go1.26.5',
    os: 'linux',
    arch: 'amd64',
    uptime: '2h34m12.456s',
    environment: 'production',
    features: {
        encryption_enabled: true,
        rbac_enabled: true,
        audit_enabled: false,
        tls_enabled: true,
        grpc_enabled: false,
        metrics_enabled: true,
    },
    database: {
        type: 'postgres',
        connected: true,
        version: '',
        pool: { max_connections: 100, active_connections: 2, idle_connections: 10 },
    },
    security: { tls_enabled: true, auth_enabled: true, encryption_method: 'AES-256-GCM', audit_enabled: false },
};

const metrics = {
    memory: {
        alloc: 10_000_000,
        total_alloc: 50_000_000,
        sys: 20_000_000,
        lookups: 0,
        mallocs: 0,
        frees: 0,
        heap_alloc: 8_000_000,
        heap_sys: 15_000_000,
        heap_idle: 2_000_000,
        heap_inuse: 6_000_000,
        heap_released: 0,
        heap_objects: 1000,
        stack_inuse: 500_000,
        stack_sys: 500_000,
    },
    goroutines: 42,
    gc: {
        num_gc: 7,
        pause_total: 1_500_000,
        pause_ns: [],
        next_gc: 12_000_000,
        last_gc: 1_800_000_000_000_000_000,
        gc_cpu_fraction: 0.001,
    },
    http: { requests_total: 0, requests_per_sec: 0, avg_response_time: 0, error_rate: 0, active_connections: 0 },
    database: {
        queries_total: 0,
        queries_per_sec: 0,
        avg_query_time: 0,
        slow_queries: 0,
        connections_active: 0,
        connections_idle: 0,
    },
    secrets: {
        total_secrets: 0,
        active_secrets: 0,
        expired_secrets: 0,
        secrets_created_24h: 0,
        secrets_accessed_24h: 0,
        encryption_ops_24h: 0,
        decryption_ops_24h: 0,
    },
    uptime: '2h34m12.456s',
    timestamp: '2026-01-01T00:00:00Z',
};

beforeEach(() => {
    vi.clearAllMocks();
    useSystemInfo.mockReturnValue({ data: sysInfo, isLoading: false, isError: false });
    useSystemMetrics.mockReturnValue({ data: metrics, isLoading: false, isError: false });
});

describe('SystemHealthPage — loading and error states', () => {
    it('shows a spinner while data is loading', () => {
        useSystemInfo.mockReturnValue({ data: undefined, isLoading: true, isError: false });
        render(<SystemHealthPage />);
        expect(document.querySelector('.animate-spin')).toBeTruthy();
    });

    it('shows an error message when the metrics fetch fails', () => {
        useSystemMetrics.mockReturnValue({ data: undefined, isLoading: false, isError: true });
        render(<SystemHealthPage />);
        expect(screen.getByText(/Unable to load system health data/)).toBeInTheDocument();
    });

    it('shows an error message when the system info fetch fails', () => {
        useSystemInfo.mockReturnValue({ data: undefined, isLoading: false, isError: true });
        render(<SystemHealthPage />);
        expect(screen.getByText(/Unable to load system health data/)).toBeInTheDocument();
    });
});

describe('SystemHealthPage — success state', () => {
    it('shows the computed status and uptime', () => {
        render(<SystemHealthPage />);
        expect(screen.getByText('Healthy')).toBeInTheDocument();
        expect(screen.getByText('2h 34m')).toBeInTheDocument();
        expect(screen.getByText('production')).toBeInTheDocument();
    });

    it('shows server build info', () => {
        render(<SystemHealthPage />);
        expect(screen.getByText('1.2.3')).toBeInTheDocument();
        expect(screen.getByText('abcdef123456')).toBeInTheDocument();
        expect(screen.getByText('go1.26.5')).toBeInTheDocument();
        expect(screen.getByText('linux / amd64')).toBeInTheDocument();
        // An unstamped build time ("unknown") is hidden rather than printed.
        expect(screen.queryByText('unknown')).not.toBeInTheDocument();
        expect(screen.queryByText('Build time')).not.toBeInTheDocument();
    });

    it('shows only the real database fields, never the hardcoded connected/active-connections ones', () => {
        render(<SystemHealthPage />);
        expect(screen.getByText('postgres')).toBeInTheDocument();
        expect(screen.getByText('100')).toBeInTheDocument();
        expect(screen.getByText('10')).toBeInTheDocument();
        expect(screen.queryByText('Connected')).not.toBeInTheDocument();
        expect(screen.queryByText('Active connections')).not.toBeInTheDocument();
    });

    it('never shows HTTP requests or query-metrics cards, since the server does not instrument them', () => {
        render(<SystemHealthPage />);
        expect(screen.queryByText(/requests\/sec/i)).not.toBeInTheDocument();
        expect(screen.queryByText(/queries\/sec/i)).not.toBeInTheDocument();
    });

    it('shows memory and runtime stats', () => {
        render(<SystemHealthPage />);
        expect(screen.getByText('42')).toBeInTheDocument(); // goroutines
        expect(screen.getByText('7')).toBeInTheDocument(); // GC runs
        expect(screen.getByText('5.7 MB')).toBeInTheDocument(); // heap in use
    });

    it('shows enabled-capability pills sourced from features and security', () => {
        render(<SystemHealthPage />);
        expect(screen.getByText('AES-256-GCM')).toBeInTheDocument();
        expect(screen.getByText('TLS')).toBeInTheDocument();
        expect(screen.getByText('Encryption')).toBeInTheDocument();
        expect(screen.getByText('RBAC')).toBeInTheDocument();
        expect(screen.getByText('Audit')).toBeInTheDocument(); // shown even though inactive
    });
});

describe('SystemHealthPage — fallback branches when nested structures are entirely missing', () => {
    it('falls back to dashes/false and uses sysInfo.uptime when metrics substructures are undefined', () => {
        useSystemMetrics.mockReturnValue({
            data: { ...metrics, uptime: undefined, memory: undefined, gc: undefined },
            isLoading: false,
            isError: false,
        });
        useSystemInfo.mockReturnValue({
            data: { ...sysInfo, database: undefined, security: undefined, features: undefined },
            isLoading: false,
            isError: false,
        });
        render(<SystemHealthPage />);

        // metrics.uptime ?? sysInfo.uptime falls back to sysInfo.uptime.
        expect(screen.getByText('2h 34m')).toBeInTheDocument();
        // formatBytes(0) for all three memory rows.
        expect(screen.getAllByText('0 B')).toHaveLength(3);
        // gc undefined -> num_gc dash, pause 0.0ms, last GC dash.
        expect(screen.getAllByText('—').length).toBeGreaterThan(0);
        expect(screen.getByText('0.0ms')).toBeInTheDocument();
        // database undefined -> dashes for type/pool rows.
        expect(screen.getByText('Type')).toBeInTheDocument();
        // security/features undefined -> encryption method dash and all pills inactive.
        expect(screen.getByText('Encryption method')).toBeInTheDocument();
    });

    it('falls back to dashes/false when nested fields are present but empty or falsy', () => {
        useSystemMetrics.mockReturnValue({
            data: {
                ...metrics,
                memory: { ...metrics.memory, heap_inuse: 500, heap_alloc: 0, total_alloc: 0 },
                gc: { ...metrics.gc, num_gc: undefined, pause_total: undefined, last_gc: 0 },
            },
            isLoading: false,
            isError: false,
        });
        useSystemInfo.mockReturnValue({
            data: {
                ...sysInfo,
                environment: '',
                version: '',
                git_commit: '',
                go_version: '',
                os: '',
                arch: '',
                build_time: '',
                database: { type: '', pool: undefined },
                security: { tls_enabled: undefined, audit_enabled: undefined, encryption_method: '' },
                features: {
                    encryption_enabled: undefined,
                    rbac_enabled: undefined,
                    grpc_enabled: undefined,
                    metrics_enabled: undefined,
                },
            },
            isLoading: false,
            isError: false,
        });
        render(<SystemHealthPage />);

        // Small byte count takes the non-toFixed branch of formatBytes.
        expect(screen.getByText('500 B')).toBeInTheDocument();
        expect(screen.getAllByText('0 B')).toHaveLength(2);
        // Every falsy string field renders its dash fallback.
        expect(screen.getAllByText('—').length).toBeGreaterThan(2);
        // Unstamped build fields are hidden, not shown as dashes; the version says so plainly.
        expect(screen.queryByText('Git commit')).not.toBeInTheDocument();
        expect(screen.queryByText('Build time')).not.toBeInTheDocument();
        expect(screen.queryByText('Environment')).not.toBeInTheDocument();
        expect(screen.getByText('Development build (unstamped)')).toBeInTheDocument();
        expect(screen.getByText('— / —')).toBeInTheDocument();
        expect(screen.getByText('0.0ms')).toBeInTheDocument();
    });
});
