import React, { useMemo, useState } from 'react';
import { Secret } from '../../types';
import {
    useSecretDependencies,
    useSecretImpact,
    useAddSecretDependency,
    useRemoveSecretDependency,
    useSecrets,
} from './api';
import { Button } from '../../components/ui/Button';
import { useCan } from '../auth/useCan';

// SecretDependenciesSection surfaces the secret dependency graph (ADR-052) on the
// secret detail page: what this secret depends on, what depends on it, the blast
// radius of rotating it, and a control to declare a new dependency. Dependencies are
// confined to the same project + environment, so the candidate picker is scoped to
// matching secrets.
export const SecretDependenciesSection: React.FC<{ secret: Secret }> = ({ secret }) => {
    // Declaring and removing an edge is secrets.write on the server (POST/DELETE
    // /secrets/{id}/dependencies); reading the graph is secrets.read. A read-only role
    // sees the graph without the controls that would end in a 403.
    const canWrite = useCan().writeSecrets;
    const { data: deps } = useSecretDependencies(secret.id);
    const { data: impact } = useSecretImpact(secret.id);
    const { data: secretList } = useSecrets();
    const addDependency = useAddSecretDependency(secret.id);
    const removeDependency = useRemoveSecretDependency(secret.id);

    const [dependsOnId, setDependsOnId] = useState('');
    const [note, setNote] = useState('');
    const [error, setError] = useState('');

    // Candidate dependencies: other secrets in the same project + environment, not
    // already linked in either direction.
    const candidates = useMemo(() => {
        const linked = new Set<number>([
            secret.id,
            ...(deps?.depends_on ?? []).map((e) => e.secret_id),
            ...(deps?.dependents ?? []).map((e) => e.secret_id),
        ]);
        return (secretList?.data ?? []).filter(
            (s: Secret) => !linked.has(s.id) && s.projectId === secret.projectId && s.environment === secret.environment
        );
    }, [secretList, deps, secret]);

    const handleAdd = async () => {
        setError('');
        const target = Number(dependsOnId);
        if (!target) {
            setError('Select a secret this one depends on.');
            return;
        }
        try {
            const trimmed = note.trim();
            await addDependency.mutateAsync(trimmed ? { dependsOnId: target, note: trimmed } : { dependsOnId: target });
            setDependsOnId('');
            setNote('');
        } catch (e: any) {
            setError(e?.response?.data?.error?.message ?? e?.message ?? 'Failed to add dependency.');
        }
    };

    const dependsOn = deps?.depends_on ?? [];
    const dependents = deps?.dependents ?? [];
    const affected = impact?.affected ?? [];

    const edgeRow = (label: string, edgeId: number, edgeNote?: string) => (
        <div
            key={edgeId}
            className="flex items-center justify-between py-2 border-b border-gray-100 dark:border-gray-700 last:border-0"
        >
            <div className="min-w-0">
                <span className="text-sm font-medium text-gray-900 dark:text-white truncate">{label}</span>
                {edgeNote && <span className="ml-2 text-xs text-gray-500 dark:text-gray-400">— {edgeNote}</span>}
            </div>
            {canWrite && (
                <button
                    type="button"
                    onClick={() => removeDependency.mutate(edgeId)}
                    disabled={removeDependency.isPending}
                    className="text-xs text-red-600 hover:text-red-700 dark:text-red-400 disabled:opacity-50"
                >
                    Remove
                </button>
            )}
        </div>
    );

    return (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-1">Dependencies</h3>
            <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
                Relationships used for rotation impact analysis and ordering. Confined to this project &amp;
                environment.
            </p>

            {/* Blast radius */}
            <div className="mb-5 rounded-md bg-gray-50 dark:bg-gray-900/40 px-4 py-3">
                {affected.length === 0 ? (
                    <p className="text-sm text-gray-600 dark:text-gray-300">
                        Rotating this secret affects no other secrets.
                    </p>
                ) : (
                    <>
                        <p className="text-sm font-medium text-gray-900 dark:text-white">
                            Rotating this secret affects {affected.length} other secret
                            {affected.length === 1 ? '' : 's'}:
                        </p>
                        <div className="mt-2 flex flex-wrap gap-2">
                            {affected.map((a) => (
                                <span
                                    key={a.secret_id}
                                    className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-200"
                                    title={`${a.depth} hop${a.depth === 1 ? '' : 's'} away`}
                                >
                                    {a.secret_name}
                                </span>
                            ))}
                        </div>
                    </>
                )}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                    <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Depends on</h4>
                    {dependsOn.length === 0 ? (
                        <p className="text-sm text-gray-400 dark:text-gray-500">Nothing — this secret stands alone.</p>
                    ) : (
                        dependsOn.map((e) => edgeRow(e.secret_name, e.id, e.note))
                    )}
                </div>
                <div>
                    <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Used by</h4>
                    {dependents.length === 0 ? (
                        <p className="text-sm text-gray-400 dark:text-gray-500">No other secret depends on this one.</p>
                    ) : (
                        dependents.map((e) => edgeRow(e.secret_name, e.id, e.note))
                    )}
                </div>
            </div>

            {/* Add a dependency */}
            {canWrite && (
                <div
                    data-testid="add-dependency-form"
                    className="mt-6 pt-5 border-t border-gray-100 dark:border-gray-700"
                >
                    <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Add a dependency</h4>
                    <div className="flex flex-col sm:flex-row gap-2">
                        <select
                            value={dependsOnId}
                            onChange={(e) => setDependsOnId(e.target.value)}
                            className="flex-1 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-3 py-2 text-sm text-gray-900 dark:text-white"
                        >
                            <option value="">This secret depends on…</option>
                            {candidates.map((c) => (
                                <option key={c.id} value={c.id}>
                                    {c.name}
                                </option>
                            ))}
                        </select>
                        <input
                            type="text"
                            value={note}
                            onChange={(e) => setNote(e.target.value)}
                            placeholder="Note (optional)"
                            className="flex-1 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-3 py-2 text-sm text-gray-900 dark:text-white"
                        />
                        <Button onClick={handleAdd} disabled={addDependency.isPending || !dependsOnId}>
                            Add
                        </Button>
                    </div>
                    {candidates.length === 0 && (
                        <p className="mt-2 text-xs text-gray-400 dark:text-gray-500">
                            No eligible secrets in this project &amp; environment to depend on.
                        </p>
                    )}
                    {error && <p className="mt-2 text-xs text-red-600 dark:text-red-400">{error}</p>}
                </div>
            )}
        </div>
    );
};
