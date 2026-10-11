import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '../../../test/test-utils';
import { EncryptionPage } from '../EncryptionPage';

const useEncryptionConfig = vi.fn();

vi.mock('../../../features/dashboard', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../../../features/dashboard')>();
    return {
        ...actual,
        useEncryptionConfig: (...args: any[]) => useEncryptionConfig(...args),
    };
});

const baseEncryptionConfig = {
    enabled: true,
    key_provider: { type: 'aws-kms', shamir_commitment: '', fallback_count: 0 },
};

beforeEach(() => {
    vi.clearAllMocks();
    useEncryptionConfig.mockReturnValue({ data: baseEncryptionConfig, isLoading: false, isError: false });
});

describe('EncryptionPage — loading and error states', () => {
    it('shows a spinner while data is loading', () => {
        useEncryptionConfig.mockReturnValue({ data: undefined, isLoading: true, isError: false });
        render(<EncryptionPage />);
        expect(document.querySelector('.animate-spin')).toBeTruthy();
    });

    it('shows an error message when the fetch fails', () => {
        useEncryptionConfig.mockReturnValue({ data: undefined, isLoading: false, isError: true });
        render(<EncryptionPage />);
        expect(screen.getByText(/Unable to load encryption configuration/)).toBeInTheDocument();
    });
});

describe('EncryptionPage — success state', () => {
    it('shows whether encryption is enabled and the key-provider type', () => {
        render(<EncryptionPage />);
        expect(screen.getByText('Yes')).toBeInTheDocument();
        expect(screen.getByText('aws-kms')).toBeInTheDocument();
        expect(screen.getByText('0')).toBeInTheDocument(); // fallback_count
    });

    it('never shows key material location rows, since the API never returns them', () => {
        render(<EncryptionPage />);
        expect(screen.queryByText('File path')).not.toBeInTheDocument();
        expect(screen.queryByText('Exec command')).not.toBeInTheDocument();
        expect(screen.queryByText('KMS key ID')).not.toBeInTheDocument();
        expect(screen.getByText(/never exposed here/)).toBeInTheDocument();
    });

    it('shows a truncated Shamir commitment only when present', () => {
        render(<EncryptionPage />);
        expect(screen.queryByText('Shamir commitment')).not.toBeInTheDocument();

        useEncryptionConfig.mockReturnValue({
            data: {
                ...baseEncryptionConfig,
                key_provider: { ...baseEncryptionConfig.key_provider, shamir_commitment: 'deadbeef'.repeat(4) },
            },
            isLoading: false,
            isError: false,
        });
        render(<EncryptionPage />);
        expect(screen.getByText('Shamir commitment')).toBeInTheDocument();
        expect(screen.getByText('deadbeefdeadbeef…')).toBeInTheDocument();
    });

    it('shows fallback provider count', () => {
        useEncryptionConfig.mockReturnValue({
            data: {
                ...baseEncryptionConfig,
                key_provider: { ...baseEncryptionConfig.key_provider, fallback_count: 2 },
            },
            isLoading: false,
            isError: false,
        });
        render(<EncryptionPage />);
        expect(screen.getByText('2')).toBeInTheDocument();
    });

    it('shows "No" when encryption is disabled', () => {
        useEncryptionConfig.mockReturnValue({
            data: { ...baseEncryptionConfig, enabled: false },
            isLoading: false,
            isError: false,
        });
        render(<EncryptionPage />);
        expect(screen.getByText('No')).toBeInTheDocument();
        expect(screen.queryByText('Yes')).not.toBeInTheDocument();
    });

    it('names the default (password) provider when the configured type is empty', () => {
        useEncryptionConfig.mockReturnValue({
            data: { ...baseEncryptionConfig, key_provider: { ...baseEncryptionConfig.key_provider, type: '' } },
            isLoading: false,
            isError: false,
        });
        render(<EncryptionPage />);
        expect(screen.getByText('password (default)')).toBeInTheDocument();
        expect(screen.queryByText('aws-kms')).not.toBeInTheDocument();
    });
});
