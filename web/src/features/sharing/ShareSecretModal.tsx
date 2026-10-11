import React, { useState, useEffect, useRef } from 'react';
import { MagnifyingGlassIcon, CheckIcon } from '@heroicons/react/24/outline';
import { Secret } from '../../types';
import { Modal } from '../../components/ui/Modal';
import { Button } from '../../components/ui/Button';
import { Select } from '../../components/ui/Select';
import { Alert } from '../../components/ui/Alert';
import { useShareSecret } from './api';
import { usersApi } from '../../services/users';
import { SHARE_WRITE_LABEL } from '../../utils/sharePermission';

interface ShareSecretModalProps {
    secret: Secret;
    isOpen: boolean;
    onClose: () => void;
    onSuccess?: () => void;
}

interface UserOption {
    id: number;
    username: string;
    display_name: string;
    email: string;
}

const ALL_PERMISSION_OPTIONS = [
    { value: 'read', label: 'Read Only' },
    { value: 'write', label: `Read + ${SHARE_WRITE_LABEL.toLowerCase()}` },
];

// Time-bound (JIT) share presets. 'never' = a permanent share (no expiry sent);
// the rest are durations from now, resolved to an ISO timestamp at submit time.
const EXPIRY_OPTIONS = [
    { value: 'never', label: 'Never (permanent)' },
    { value: '1h', label: '1 hour' },
    { value: '24h', label: '24 hours' },
    { value: '7d', label: '7 days' },
    { value: '30d', label: '30 days' },
];

const EXPIRY_MS: Record<string, number> = {
    '1h': 60 * 60 * 1000,
    '24h': 24 * 60 * 60 * 1000,
    '7d': 7 * 24 * 60 * 60 * 1000,
    '30d': 30 * 24 * 60 * 60 * 1000,
};

// expiresAtFromPreset resolves a preset key to an ISO timestamp, or undefined for
// a permanent share.
export const expiresAtFromPreset = (preset: string, now: number = Date.now()): string | undefined => {
    const ms = EXPIRY_MS[preset];
    return ms ? new Date(now + ms).toISOString() : undefined;
};

export const ShareSecretModal: React.FC<ShareSecretModalProps> = ({ secret, isOpen, onClose, onSuccess }) => {
    const [query, setQuery] = useState('');
    const [results, setResults] = useState<UserOption[]>([]);
    const [selected, setSelected] = useState<UserOption | null>(null);
    const [open, setOpen] = useState(false);
    const [loading, setLoading] = useState(false);
    const [permission, setPermission] = useState<'read' | 'write'>('read');
    const [expiry, setExpiry] = useState('never');
    const [success, setSuccess] = useState(false);
    const inputRef = useRef<HTMLInputElement>(null);
    const listRef = useRef<HTMLDivElement>(null);
    const shareSecret = useShareSecret(secret.id);

    // UX-only signal, not a security boundary: only offer 'write' as a grantable
    // permission when the sharer themselves currently holds write on this secret.
    // The server must still independently enforce this invariant — this list is
    // just what the form presents, not what the API accepts.
    const permissionOptions = ALL_PERMISSION_OPTIONS.filter(
        (opt) => opt.value !== 'write' || secret.permissions.includes('write')
    );

    // Search users as query changes
    useEffect(() => {
        if (!query.trim()) {
            setResults([]);
            return;
        }
        let cancelled = false;
        const timer = setTimeout(async () => {
            setLoading(true);
            try {
                const data = await usersApi.list({ search: query, pageSize: 8 });
                if (!cancelled) setResults((data as any).users ?? []);
            } catch {
                if (!cancelled) setResults([]);
            } finally {
                if (!cancelled) setLoading(false);
            }
        }, 200);
        return () => {
            cancelled = true;
            clearTimeout(timer);
        };
    }, [query]);

    // Close dropdown on outside click
    useEffect(() => {
        const handler = (e: MouseEvent) => {
            if (
                listRef.current &&
                !listRef.current.contains(e.target as Node) &&
                inputRef.current &&
                !inputRef.current.contains(e.target as Node)
            ) {
                setOpen(false);
            }
        };
        document.addEventListener('mousedown', handler);
        return () => document.removeEventListener('mousedown', handler);
    }, []);

    const handleClose = () => {
        setQuery('');
        setResults([]);
        setSelected(null);
        setOpen(false);
        setSuccess(false);
        shareSecret.reset();
        setPermission('read');
        setExpiry('never');
        onClose();
    };

    const handleSelect = (user: UserOption) => {
        setSelected(user);
        setQuery(user.display_name || user.username);
        setOpen(false);
    };

    const handleSubmit = async (e: React.SubmitEvent<HTMLFormElement>) => {
        e.preventDefault();
        if (!selected) return;
        const expiresAt = expiresAtFromPreset(expiry);
        shareSecret.mutate(
            {
                username: selected.username,
                recipientId: selected.id,
                permission,
                ...(expiresAt ? { expiresAt } : {}),
            },
            {
                onSuccess: () => {
                    setSuccess(true);
                    onSuccess?.();
                    setTimeout(handleClose, 1200);
                },
            }
        );
    };

    const dropdownContent =
        results.length === 0 ? (
            <div className="px-4 py-3 text-sm" style={{ color: 'var(--text-muted)' }}>
                No users found for "{query}"
            </div>
        ) : (
            results.map((user) => (
                <button
                    key={user.id}
                    type="button"
                    onClick={() => handleSelect(user)}
                    className="w-full flex items-center gap-3 px-4 py-2.5 text-left transition-colors"
                    style={{ color: 'var(--text-primary)' }}
                    onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.backgroundColor = 'var(--bg-subtle)')}
                    onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.backgroundColor = '')}
                >
                    <div className="shrink-0 h-7 w-7 rounded-full bg-blue-500/20 flex items-center justify-center">
                        <span className="text-xs font-semibold" style={{ color: 'var(--accent-text)' }}>
                            {(user.display_name || user.username).charAt(0).toUpperCase()}
                        </span>
                    </div>
                    <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">{user.display_name || user.username}</p>
                        <p className="text-xs truncate" style={{ color: 'var(--text-muted)' }}>
                            @{user.username} · {user.email}
                        </p>
                    </div>
                </button>
            ))
        );

    return (
        <Modal isOpen={isOpen} onClose={handleClose} title={`Share "${secret.name}"`} size="md">
            <form onSubmit={handleSubmit} className="space-y-4">
                {shareSecret.isError && (
                    <Alert
                        type="error"
                        title="Error"
                        message={
                            shareSecret.error instanceof Error ? shareSecret.error.message : 'Failed to share secret.'
                        }
                    />
                )}
                {success && <Alert type="success" title="Shared!" message="Secret shared successfully." />}

                {/* User search */}
                <div>
                    <label
                        htmlFor="recipient-input"
                        className="block text-sm font-medium mb-1"
                        style={{ color: 'var(--text-secondary)' }}
                    >
                        Recipient
                    </label>
                    <div className="relative">
                        {/* Input */}
                        <div className="relative">
                            <MagnifyingGlassIcon
                                className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 pointer-events-none"
                                style={{ color: 'var(--text-muted)' }}
                            />
                            <input
                                id="recipient-input"
                                ref={inputRef}
                                type="text"
                                placeholder="Search by name or username…"
                                value={query}
                                onChange={(e) => {
                                    setQuery(e.target.value);
                                    setSelected(null);
                                    setOpen(true);
                                }}
                                onFocus={() => {
                                    if (query) setOpen(true);
                                }}
                                disabled={shareSecret.isPending || success}
                                className="w-full pl-9 pr-4 py-2 text-sm rounded-md border focus:outline-hidden focus:ring-2 focus:ring-blue-500"
                                style={{
                                    backgroundColor: 'var(--bg-app)',
                                    color: 'var(--text-primary)',
                                    borderColor: selected ? 'var(--accent)' : 'var(--border-strong)',
                                }}
                            />
                            {selected && (
                                <CheckIcon
                                    className="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4"
                                    style={{ color: 'var(--accent)' }}
                                />
                            )}
                        </div>

                        {/* Dropdown */}
                        {open && query.trim() && (
                            <div
                                ref={listRef}
                                className="absolute z-20 w-full mt-1 rounded-md border shadow-lg overflow-hidden"
                                style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border)' }}
                            >
                                {loading ? (
                                    <div className="px-4 py-3 text-sm" style={{ color: 'var(--text-muted)' }}>
                                        Searching…
                                    </div>
                                ) : (
                                    dropdownContent
                                )}
                            </div>
                        )}
                    </div>
                </div>

                {/* Permission */}
                <div>
                    <label
                        htmlFor="permission-select"
                        className="block text-sm font-medium mb-1"
                        style={{ color: 'var(--text-secondary)' }}
                    >
                        Permission
                    </label>
                    <Select
                        id="permission-select"
                        value={permission}
                        onChange={(e) => setPermission(e.target.value as 'read' | 'write')}
                        options={permissionOptions}
                        disabled={shareSecret.isPending || success}
                    />
                </div>

                {/* Access expiry (time-bound / JIT share) */}
                <div>
                    <label
                        htmlFor="access-expires-select"
                        className="block text-sm font-medium mb-1"
                        style={{ color: 'var(--text-secondary)' }}
                    >
                        Access expires
                    </label>
                    <Select
                        id="access-expires-select"
                        value={expiry}
                        onChange={(e) => setExpiry(e.target.value)}
                        options={EXPIRY_OPTIONS}
                        disabled={shareSecret.isPending || success}
                    />
                    {expiry !== 'never' && (
                        <p className="mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
                            Access is automatically revoked after this period.
                        </p>
                    )}
                </div>

                <div
                    className="flex items-center justify-end space-x-3 pt-4 border-t"
                    style={{ borderColor: 'var(--border)' }}
                >
                    <Button type="button" variant="outline" onClick={handleClose} disabled={shareSecret.isPending}>
                        Cancel
                    </Button>
                    <Button type="submit" disabled={shareSecret.isPending || success || !selected}>
                        {shareSecret.isPending ? 'Sharing…' : 'Share'}
                    </Button>
                </div>
            </form>
        </Modal>
    );
};
