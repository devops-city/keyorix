import React, { useState, useEffect } from 'react';
import { Button } from '../../components/ui/Button';
import { Alert } from '../../components/ui/Alert';
import { useTransferOwnership } from './api';
import { usersApi } from '../../services/users';
import { Recipient } from '../../types';
import { apiErrorMessage } from '../../services/client';

interface TransferOwnershipProps {
    secretId: number;
    currentOwner: string;
    onSuccess?: () => void;
}

// TransferOwnership lets the current owner hand a secret to another user. The server
// enforces that only the current owner (or an authorized caller when the owner is
// gone) may transfer, so this is a thin UI over POST /secrets/{id}/transfer-ownership.
export const TransferOwnership: React.FC<TransferOwnershipProps> = ({ secretId, currentOwner, onSuccess }) => {
    const [open, setOpen] = useState(false);
    const [query, setQuery] = useState('');
    const [results, setResults] = useState<Recipient[]>([]);
    const [selected, setSelected] = useState<Recipient | null>(null);
    const [done, setDone] = useState(false);
    const transfer = useTransferOwnership(secretId);

    // Search users as the query changes (only users can own a secret, not groups).
    useEffect(() => {
        if (!query.trim()) {
            setResults([]);
            return;
        }
        let cancelled = false;
        const timer = setTimeout(async () => {
            try {
                const found = await usersApi.search(query.trim());
                if (!cancelled) setResults(found.filter((r) => r.type === 'user'));
            } catch {
                if (!cancelled) setResults([]);
            }
        }, 200);
        return () => {
            cancelled = true;
            clearTimeout(timer);
        };
    }, [query]);

    const reset = () => {
        setOpen(false);
        setQuery('');
        setResults([]);
        setSelected(null);
        setDone(false);
        transfer.reset();
    };

    const handleTransfer = () => {
        if (!selected) return;
        if (!window.confirm(`Transfer ownership of this secret to ${selected.name}? You will no longer own it.`))
            return;
        transfer.mutate(selected.id, {
            onSuccess: () => {
                setDone(true);
                onSuccess?.();
                setTimeout(reset, 1200);
            },
        });
    };

    if (!open) {
        return (
            <button
                type="button"
                onClick={() => setOpen(true)}
                className="text-xs underline text-blue-600 hover:text-blue-700 dark:text-blue-400"
            >
                Transfer ownership
            </button>
        );
    }

    return (
        <div
            className="mt-2 p-3 rounded-md border"
            style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-subtle)' }}
        >
            {transfer.isError && (
                <Alert
                    type="error"
                    title="Error"
                    message={apiErrorMessage(transfer.error, 'Failed to transfer ownership.')}
                />
            )}
            {done && <Alert type="success" title="Transferred" message="Ownership transferred." />}

            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                Transfer ownership from <span className="font-semibold">{currentOwner}</span> to:
            </label>
            <input
                type="text"
                placeholder="Search by name or username…"
                value={selected ? selected.name : query}
                onChange={(e) => {
                    setQuery(e.target.value);
                    setSelected(null);
                }}
                disabled={transfer.isPending || done}
                className="w-full px-3 py-2 text-sm rounded-md border focus:outline-hidden focus:ring-2 focus:ring-blue-500"
                style={{
                    backgroundColor: 'var(--bg-app)',
                    color: 'var(--text-primary)',
                    borderColor: 'var(--border-strong)',
                }}
            />
            {!selected && results.length > 0 && (
                <div className="mt-1 rounded-md border overflow-hidden" style={{ borderColor: 'var(--border)' }}>
                    {results.map((u) => (
                        <button
                            key={u.id}
                            type="button"
                            onClick={() => {
                                setSelected(u);
                                setResults([]);
                            }}
                            className="w-full text-left px-3 py-2 text-sm hover:bg-blue-500/10"
                            style={{ color: 'var(--text-primary)' }}
                        >
                            {u.name}
                            {u.email ? ` · ${u.email}` : ''}
                        </button>
                    ))}
                </div>
            )}

            <div className="mt-3 flex items-center justify-end space-x-2">
                <Button type="button" variant="outline" size="sm" onClick={reset} disabled={transfer.isPending}>
                    Cancel
                </Button>
                <Button
                    type="button"
                    size="sm"
                    onClick={handleTransfer}
                    disabled={!selected || transfer.isPending || done}
                >
                    {transfer.isPending ? 'Transferring…' : 'Transfer'}
                </Button>
            </div>
        </div>
    );
};
