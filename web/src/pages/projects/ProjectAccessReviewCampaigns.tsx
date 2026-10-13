import React, { useState } from 'react';
import {
    PlusIcon,
    CheckIcon,
    NoSymbolIcon,
    ClipboardDocumentCheckIcon,
    ArrowDownTrayIcon,
} from '@heroicons/react/24/outline';
import {
    useAccessReviewCampaigns,
    useAccessReviewCampaign,
    useOpenCampaign,
    useDecideCampaignItem,
    useCloseCampaign,
} from '../../features/projects/api';
import { CampaignProgress, AccessReviewItem } from '../../services/projects';
import { apiClient } from '../../services/client';
import { triggerBlobDownload, parseServerDate } from '../../utils';

interface Props {
    projectId: number;
}

// lastUsedInfo renders a user principal's recency (dormant-access signal); empty
// for groups (last-use is not aggregated server-side). Shared with the live review.
export const lastUsedInfo = (e: {
    principalType: string;
    lastUsedAt?: string;
}): { label: string; dormant: boolean } => {
    if (e.principalType !== 'user') return { label: '', dormant: false };
    if (!e.lastUsedAt) return { label: 'never used', dormant: true };
    const days = Math.floor((Date.now() - parseServerDate(e.lastUsedAt).getTime()) / 86_400_000);
    return { label: days <= 0 ? 'used today' : `used ${days}d ago`, dormant: days >= 90 };
};

const progressLabel = (p: CampaignProgress) =>
    `${p.attested + p.revoked}/${p.total} decided · ${p.attested} attested · ${p.revoked} revoked`;

const decisionStyle = (d: string): React.CSSProperties => {
    if (d === 'attested') return { backgroundColor: 'var(--success-subtle)', color: 'var(--success)' };
    if (d === 'revoked') return { backgroundColor: 'var(--error-subtle)', color: 'var(--error)' };
    return { backgroundColor: 'var(--bg-muted)', color: 'var(--text-muted)' };
};

/**
 * Periodic access-recertification campaigns (ISO 27001 A.5.18). Lists a project's
 * campaigns with progress, opens a new one (snapshots current access), and — for an
 * open campaign — lets a reviewer attest/revoke each item and close the cycle as an
 * evidence record.
 */
export const ProjectAccessReviewCampaigns: React.FC<Props> = ({ projectId }) => {
    const { data: campaigns = [], isLoading } = useAccessReviewCampaigns(projectId);
    const openCampaign = useOpenCampaign(projectId);

    const [newName, setNewName] = useState('');
    const [selectedId, setSelectedId] = useState<number | null>(null);
    const [error, setError] = useState('');

    const onError = (err: any) =>
        setError(err?.response?.data?.error ?? err?.response?.data?.message ?? 'Action failed.');

    const handleOpen = () => {
        setError('');
        openCampaign.mutate(newName.trim() || 'Access review', {
            onSuccess: (res) => {
                setNewName('');
                setSelectedId(res.campaign.id);
            },
            onError,
        });
    };

    const campaignListContent =
        campaigns.length === 0 ? (
            <div className="p-8 text-center">
                <ClipboardDocumentCheckIcon className="h-9 w-9 mx-auto mb-2" style={{ color: 'var(--text-muted)' }} />
                <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                    No campaigns yet. Open one to start a recertification cycle.
                </p>
            </div>
        ) : (
            <ul className="divide-y" style={{ borderColor: 'var(--border)' }}>
                {campaigns.map(({ campaign, progress }) => (
                    <li key={campaign.id} className="px-4 py-3">
                        <div className="flex items-center gap-3">
                            <span
                                className="px-2 py-0.5 rounded-full text-xs font-medium shrink-0"
                                style={
                                    campaign.state === 'open'
                                        ? {
                                              backgroundColor: 'var(--accent-subtle)',
                                              color: 'var(--accent-text)',
                                          }
                                        : { backgroundColor: 'var(--bg-muted)', color: 'var(--text-muted)' }
                                }
                            >
                                {campaign.state}
                            </span>
                            <div className="flex-1 min-w-0">
                                <p className="text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>
                                    {campaign.name}
                                </p>
                                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                                    {progressLabel(progress)}
                                </p>
                            </div>
                            <button
                                type="button"
                                onClick={() => setSelectedId(selectedId === campaign.id ? null : campaign.id)}
                                className="px-2.5 py-1 rounded-lg text-xs font-medium shrink-0"
                                style={{ border: '1px solid var(--border)', color: 'var(--text-secondary)' }}
                            >
                                {selectedId === campaign.id ? 'Hide' : 'Review'}
                            </button>
                        </div>
                        {selectedId === campaign.id && (
                            <CampaignDetail projectId={projectId} campaignId={campaign.id} onError={onError} />
                        )}
                    </li>
                ))}
            </ul>
        );

    return (
        <div className="mt-8">
            {/* flex-wrap: on a phone the name field and Open button drop under the text instead of widening the page (#3154). */}
            <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
                <div>
                    <h3 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
                        Recertification campaigns
                    </h3>
                    <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                        Run access reviews on a schedule (A.5.18). Opening a campaign snapshots who has access today;
                        decide each grant, then close it as the audit evidence the review happened.
                    </p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                    <input
                        value={newName}
                        onChange={(e) => setNewName(e.target.value)}
                        placeholder="Campaign name"
                        className="rounded-lg px-2.5 py-1.5 text-sm outline-hidden w-44"
                        style={{
                            backgroundColor: 'var(--bg-app)',
                            border: '1px solid var(--border)',
                            color: 'var(--text-primary)',
                        }}
                    />
                    <button
                        type="button"
                        onClick={handleOpen}
                        disabled={openCampaign.isPending}
                        className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-sm font-medium disabled:opacity-50"
                        style={{ backgroundColor: 'var(--accent)', color: '#fff' }}
                    >
                        <PlusIcon className="h-4 w-4" />
                        Open
                    </button>
                </div>
            </div>

            {error && (
                <div
                    className="rounded-lg px-3 py-2 text-sm mb-3"
                    style={{ backgroundColor: 'var(--error-subtle)', color: 'var(--error)' }}
                >
                    {error}
                </div>
            )}

            <div
                className="rounded-lg border"
                style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
            >
                {isLoading ? (
                    <div className="p-6 space-y-2">
                        {[1, 2].map((i) => (
                            <div
                                key={i}
                                className="h-8 rounded-sm animate-pulse"
                                style={{ backgroundColor: 'var(--bg-muted)' }}
                            />
                        ))}
                    </div>
                ) : (
                    campaignListContent
                )}
            </div>
        </div>
    );
};

interface DetailProps {
    projectId: number;
    campaignId: number;
    onError: (err: any) => void;
}

const itemDetail = (it: AccessReviewItem) => {
    const secretLabel = it.secretName ? `Secret: ${it.secretName}` : '—';
    return it.source === 'role' ? `Role: ${it.roleName || '—'}` : secretLabel;
};

const CampaignDetail: React.FC<DetailProps> = ({ projectId, campaignId, onError }) => {
    const { data, isLoading } = useAccessReviewCampaign(projectId, campaignId);
    const decide = useDecideCampaignItem(projectId, campaignId);
    const close = useCloseCampaign(projectId);
    const [confirmItem, setConfirmItem] = useState<number | null>(null);
    const [csvBusy, setCsvBusy] = useState(false);

    if (isLoading || !data) {
        return <div className="mt-3 h-10 rounded-sm animate-pulse" style={{ backgroundColor: 'var(--bg-muted)' }} />;
    }
    const open = data.campaign.state === 'open';
    const pending = data.progress.pending;

    const onDecide = (itemId: number, action: 'attest' | 'revoke') => {
        decide.mutate({ itemId, action }, { onSuccess: () => setConfirmItem(null), onError });
    };
    const onClose = (force: boolean) => close.mutate({ campaignId, force }, { onError });

    // Download the campaign as a CSV recertification record (server #373) — available for
    // open or closed campaigns so an auditor can archive the signed-off evidence.
    const onDownloadCsv = async () => {
        setCsvBusy(true);
        try {
            const res = await apiClient.get(
                `/api/v1/projects/${projectId}/access-review/campaigns/${campaignId}/export.csv`,
                { responseType: 'blob' }
            );
            triggerBlobDownload(res.data as Blob, `access-review-campaign-${campaignId}.csv`);
        } catch (err: any) {
            onError(err);
        } finally {
            setCsvBusy(false);
        }
    };

    return (
        <div className="mt-3 rounded-lg border" style={{ borderColor: 'var(--border)' }}>
            {data.items.length === 0 ? (
                <p className="p-4 text-sm" style={{ color: 'var(--text-muted)' }}>
                    No items captured.
                </p>
            ) : (
                <ul className="divide-y" style={{ borderColor: 'var(--border)' }}>
                    {data.items.map((it) => {
                        const info = lastUsedInfo(it);
                        return (
                            <li key={it.id} className="flex items-center gap-3 px-3 py-2">
                                <span
                                    className="px-2 py-0.5 rounded-full text-xs font-medium shrink-0 w-20 text-center"
                                    style={decisionStyle(it.decision)}
                                >
                                    {it.decision}
                                </span>
                                <div className="flex-1 min-w-0">
                                    <p className="text-sm truncate" style={{ color: 'var(--text-primary)' }}>
                                        {it.principalType === 'user' && it.email
                                            ? `${it.principalName} (${it.email})`
                                            : it.principalName}
                                    </p>
                                    <p className="text-xs truncate" style={{ color: 'var(--text-muted)' }}>
                                        {itemDetail(it)}
                                        {info.dormant ? ' · dormant' : ''}
                                    </p>
                                </div>
                                {open && it.decision === 'pending' && (
                                    <div className="flex items-center gap-1.5 shrink-0">
                                        <button
                                            type="button"
                                            onClick={() => onDecide(it.id, 'attest')}
                                            disabled={decide.isPending}
                                            className="inline-flex items-center gap-1 px-2 py-1 rounded-lg text-xs font-medium disabled:opacity-50"
                                            style={{
                                                border: '1px solid var(--border)',
                                                color: 'var(--text-secondary)',
                                            }}
                                        >
                                            <CheckIcon className="h-3.5 w-3.5" />
                                            Attest
                                        </button>
                                        {it.source !== 'owner' &&
                                            (confirmItem === it.id ? (
                                                <>
                                                    <button
                                                        type="button"
                                                        onClick={() => onDecide(it.id, 'revoke')}
                                                        disabled={decide.isPending}
                                                        className="px-2 py-1 rounded-lg text-xs font-medium disabled:opacity-50"
                                                        style={{ backgroundColor: 'var(--error)', color: '#fff' }}
                                                    >
                                                        Confirm
                                                    </button>
                                                    <button
                                                        type="button"
                                                        onClick={() => setConfirmItem(null)}
                                                        className="px-1.5 py-1 rounded-lg text-xs"
                                                        style={{ color: 'var(--text-muted)' }}
                                                    >
                                                        Cancel
                                                    </button>
                                                </>
                                            ) : (
                                                <button
                                                    type="button"
                                                    onClick={() => setConfirmItem(it.id)}
                                                    className="inline-flex items-center gap-1 px-2 py-1 rounded-lg text-xs font-medium"
                                                    style={{
                                                        backgroundColor: 'var(--error-subtle)',
                                                        color: 'var(--error)',
                                                    }}
                                                >
                                                    <NoSymbolIcon className="h-3.5 w-3.5" />
                                                    Revoke
                                                </button>
                                            ))}
                                    </div>
                                )}
                            </li>
                        );
                    })}
                </ul>
            )}
            <div className="flex items-center gap-2 px-3 py-2 border-t" style={{ borderColor: 'var(--border)' }}>
                <button
                    type="button"
                    onClick={onDownloadCsv}
                    disabled={csvBusy || data.items.length === 0}
                    className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium disabled:opacity-50"
                    style={{ border: '1px solid var(--border)', color: 'var(--text-secondary)' }}
                >
                    <ArrowDownTrayIcon className="h-3.5 w-3.5" />
                    {csvBusy ? 'Exporting…' : 'Download CSV'}
                </button>
                {open && (
                    <div className="ml-auto flex items-center gap-2">
                        <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                            {pending > 0 ? `${pending} item(s) still pending` : 'All items decided'}
                        </span>
                        {pending > 0 ? (
                            <button
                                type="button"
                                onClick={() => onClose(true)}
                                disabled={close.isPending}
                                className="px-3 py-1.5 rounded-lg text-xs font-medium disabled:opacity-50"
                                style={{ border: '1px solid var(--border)', color: 'var(--text-secondary)' }}
                            >
                                Close anyway
                            </button>
                        ) : (
                            <button
                                type="button"
                                onClick={() => onClose(false)}
                                disabled={close.isPending}
                                className="px-3 py-1.5 rounded-lg text-xs font-medium disabled:opacity-50"
                                style={{ backgroundColor: 'var(--accent)', color: '#fff' }}
                            >
                                Close campaign
                            </button>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
};
