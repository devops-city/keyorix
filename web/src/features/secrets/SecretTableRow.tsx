import React from 'react';
import {
    EyeIcon,
    PencilIcon,
    TrashIcon,
    ShareIcon,
    DocumentDuplicateIcon,
    CheckIcon,
    ArrowPathIcon,
    ClockIcon,
} from '@heroicons/react/24/outline';
import { Secret } from '../../types';
import { useCan } from '../auth/useCan';
import { classificationMeta } from './classification';
import { SECRET_TYPES } from './listConstants';

const formatDate = (d: string | Date) =>
    new Intl.DateTimeFormat('en', { year: 'numeric', month: 'short', day: 'numeric' }).format(new Date(d));

interface SecretTableRowProps {
    secret: Secret;
    isSelected: boolean;
    onToggleSelect: (id: number) => void;
    onView: (secret: Secret) => void;
    onEdit: (secret: Secret) => void;
    onDelete: (secret: Secret) => void;
    onShare: (secret: Secret) => void;
    onRotate: (secret: Secret) => void;
    onAutoRotate?: (secret: Secret) => void;
    onCopy: (secret: Secret) => void;
    copyingId: number | null;
    copiedId: number | null;
    copyErrorId: number | null;
}

import { useUIStore } from '../../store/uiStore';

const TYPE_STYLES: Record<string, { darkBg: string; darkColor: string; lightBg: string; lightColor: string }> = {
    password: {
        darkBg: 'rgba(99,102,241,0.15)',
        darkColor: '#818cf8',
        lightBg: '#e0e7ff',
        lightColor: '#3730a3',
    },
    api_key: {
        darkBg: 'rgba(16,185,129,0.15)',
        darkColor: '#34d399',
        lightBg: '#dcfce7',
        lightColor: '#166534',
    },
    text: {
        darkBg: 'rgba(148,163,184,0.15)',
        darkColor: '#94a3b8',
        lightBg: '#f1f5f9',
        lightColor: '#475569',
    },
    certificate: {
        darkBg: 'rgba(251,191,36,0.15)',
        darkColor: '#fbbf24',
        lightBg: '#fef9c3',
        lightColor: '#854d0e',
    },
    json: {
        darkBg: 'rgba(251,146,60,0.15)',
        darkColor: '#fb923c',
        lightBg: '#ffedd5',
        lightColor: '#9a3412',
    },
};

// The badge text is the filter dropdown's own label ("API Key", not "api_key"), so the
// column and the filter can never disagree. A type the filter does not offer
// (the API's default "generic") is title-cased rather than shown as a raw identifier.
export const typeLabel = (type: string): string =>
    SECRET_TYPES.find((t) => t.value === type && t.value !== 'all')?.label ??
    type.replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase());

const TypeBadge: React.FC<{ type: string }> = ({ type }) => {
    const { theme } = useUIStore();
    const isDark =
        theme === 'dark' || (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    const s = TYPE_STYLES[type] ?? {
        darkBg: 'rgba(148,163,184,0.15)',
        darkColor: '#94a3b8',
        lightBg: '#f1f5f9',
        lightColor: '#475569',
    };
    const label = typeLabel(type);
    return (
        <span
            className="inline-flex items-center px-2 py-0.5 rounded-sm text-xs font-medium tracking-wide"
            style={{ backgroundColor: isDark ? s.darkBg : s.lightBg, color: isDark ? s.darkColor : s.lightColor }}
        >
            {label}
        </span>
    );
};

export const SecretTableRow: React.FC<SecretTableRowProps> = ({
    secret,
    isSelected,
    onToggleSelect,
    onView,
    onEdit,
    onDelete,
    onShare,
    onRotate,
    onAutoRotate,
    onCopy,
    copyingId,
    copiedId,
    copyErrorId,
}) => {
    const can = useCan();
    const copyIcon =
        copiedId === secret.id ? (
            <CheckIcon className="h-4 w-4 text-green-500" />
        ) : (
            <DocumentDuplicateIcon className="h-4 w-4" />
        );

    return (
        <tr className={`hover:bg-subtle ${isSelected ? 'bg-accent-subtle' : ''}`}>
            <td className="px-4 py-4 w-10">
                <input
                    type="checkbox"
                    className="rounded-sm border-base text-blue-600 focus:ring-blue-500"
                    checked={isSelected}
                    onChange={() => onToggleSelect(secret.id)}
                />
            </td>
            <td className="px-6 py-4">
                <div className="text-sm font-medium text-base-primary">{secret.name}</div>
                {secret.tags.length > 0 && (
                    <div className="flex items-center space-x-1 mt-1">
                        {secret.tags.slice(0, 3).map((tag) => (
                            <span
                                key={tag}
                                className="inline-flex items-center px-2 py-0.5 rounded-sm text-xs font-medium bg-subtle text-base-secondary"
                            >
                                {tag}
                            </span>
                        ))}
                        {secret.tags.length > 3 && (
                            <span className="text-xs text-base-muted">+{secret.tags.length - 3} more</span>
                        )}
                    </div>
                )}
            </td>
            <td className="px-6 py-4 whitespace-nowrap">
                <TypeBadge type={secret.type} />
            </td>
            <td className="px-6 py-4 whitespace-nowrap">
                <span
                    className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${classificationMeta(secret.classification ?? '').color}`}
                >
                    {classificationMeta(secret.classification ?? '').label}
                </span>
            </td>
            <td className="px-6 py-4 whitespace-nowrap text-sm text-base-muted">
                <span className="inline-flex items-center px-2 py-0.5 rounded-sm text-xs font-medium bg-subtle text-base-secondary capitalize">
                    {secret.environment || 'production'}
                </span>
            </td>
            <td className="px-6 py-4 whitespace-nowrap text-sm text-base-muted">
                {secret.isShared ? (
                    <div className="flex items-center">
                        <ShareIcon className="h-4 w-4 mr-1 text-green-500" />
                        <span>{secret.shareCount} shares</span>
                    </div>
                ) : (
                    <span>Private</span>
                )}
            </td>
            <td className="px-6 py-4 whitespace-nowrap text-sm text-base-muted">
                <div>
                    <div>{formatDate(secret.lastModified)}</div>
                    <div className="text-xs">by {secret.owner}</div>
                </div>
            </td>
            <td className="px-3 py-4 whitespace-nowrap text-right text-sm font-medium">
                <div className="flex items-center justify-end gap-0.5">
                    <button
                        type="button"
                        onClick={() => onView(secret)}
                        title="View"
                        className="p-1 text-base-muted hover:text-base-primary transition-colors"
                    >
                        <EyeIcon className="h-4 w-4" />
                    </button>
                    {can.writeSecrets && (
                        <button
                            type="button"
                            onClick={() => onEdit(secret)}
                            title="Edit"
                            className="p-1 text-base-muted hover:text-base-primary transition-colors"
                        >
                            <PencilIcon className="h-4 w-4" />
                        </button>
                    )}
                    {can.writeSecrets && (
                        <button
                            type="button"
                            onClick={() => onRotate(secret)}
                            title="Rotate"
                            className="p-1 text-base-muted hover:text-green-600 transition-colors"
                        >
                            <ArrowPathIcon className="h-4 w-4" />
                        </button>
                    )}
                    {onAutoRotate && can.writeSecrets && (
                        <button
                            type="button"
                            onClick={() => onAutoRotate(secret)}
                            title="Automated rotation"
                            className="p-1 text-base-muted hover:text-blue-600 transition-colors"
                        >
                            <ClockIcon className="h-4 w-4" />
                        </button>
                    )}
                    {can.writeSecrets && (
                        <button
                            type="button"
                            onClick={() => onShare(secret)}
                            title="Share"
                            className="p-1 text-base-muted hover:text-blue-600 transition-colors"
                        >
                            <ShareIcon className="h-4 w-4" />
                        </button>
                    )}
                    <button
                        type="button"
                        onClick={() => onCopy(secret)}
                        title="Copy value"
                        disabled={copyingId === secret.id}
                        className={`p-1 transition-colors ${copyErrorId === secret.id ? 'text-red-500' : 'text-base-muted hover:text-base-primary'}`}
                    >
                        {copyingId === secret.id ? (
                            <div className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
                        ) : (
                            copyIcon
                        )}
                    </button>
                    {can.deleteSecrets && (
                        <button
                            type="button"
                            onClick={() => onDelete(secret)}
                            title="Delete"
                            className="p-1 text-base-muted hover:text-red-600 transition-colors"
                        >
                            <TrashIcon className="h-4 w-4" />
                        </button>
                    )}
                </div>
            </td>
        </tr>
    );
};
