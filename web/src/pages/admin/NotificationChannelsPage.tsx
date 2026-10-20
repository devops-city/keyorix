import React, { useState } from 'react';
import { PlusIcon, PencilSquareIcon, TrashIcon, ArrowPathIcon } from '@heroicons/react/24/outline';
import { Button, Modal, Input, Select, Spinner } from '../../components/ui';
import {
    useNotificationChannels,
    useCreateNotificationChannel,
    useUpdateNotificationChannel,
    useDeleteNotificationChannel,
    useRetryPolicy,
    useSetRetryPolicy,
} from '../../features/admin';
import type { NotificationChannel, NotificationChannelPayload } from '../../services/notificationChannels';

// The model's own comment documents this as the canonical set
// (internal/storage/models.go's NotificationChannel.Events field).
const EVENT_OPTIONS = ['secret.rotated', 'anomaly.detected', 'secret.expiring'];

const CHANNEL_TYPES = [
    { value: 'webhook', label: 'Webhook' },
    { value: 'slack', label: 'Slack' },
    { value: 'teams', label: 'Teams' },
    { value: 'email', label: 'Email' },
];

interface ChannelFormData {
    name: string;
    type: string;
    url: string;
    // The stored URL, elided by the server (scheme+host only). Display-only: the
    // edit form never holds the real URL, so a blank url field means "keep it".
    currentUrl: string;
    // True once the user chose "Replace URL" on a channel that already has one.
    replaceUrl: boolean;
    email: string;
    events: Set<string>;
    enabled: boolean;
}

const emptyForm = (): ChannelFormData => ({
    name: '',
    type: 'webhook',
    url: '',
    currentUrl: '',
    replaceUrl: false,
    email: '',
    events: new Set(),
    enabled: true,
});

const formToPayload = (form: ChannelFormData): NotificationChannelPayload => ({
    name: form.name,
    type: form.type,
    enabled: form.enabled,
    events: Array.from(form.events).join(','),
    ...(form.type === 'email' ? { email: form.email } : form.url.trim() ? { url: form.url.trim() } : {}),
});

interface ChannelRowProps {
    channel: NotificationChannel;
    onEdit: (channel: NotificationChannel) => void;
    onDelete: (channel: NotificationChannel) => void;
    onRetryPolicy: (channel: NotificationChannel) => void;
}

const ChannelRow: React.FC<ChannelRowProps> = ({ channel, onEdit, onDelete, onRetryPolicy }) => {
    const events = channel.events
        ? channel.events
              .split(',')
              .map((e) => e.trim())
              .filter(Boolean)
        : [];

    return (
        <tr style={{ borderTop: '1px solid var(--border)' }}>
            <td className="px-4 py-3">
                <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
                    {channel.name}
                </span>
            </td>
            <td className="px-4 py-3">
                <span
                    className="text-xs px-2 py-0.5 rounded-full font-medium capitalize"
                    style={{ backgroundColor: 'var(--bg-subtle)', color: 'var(--text-secondary)' }}
                >
                    {channel.type}
                </span>
            </td>
            <td className="px-4 py-3">
                <span className="text-sm truncate" style={{ color: 'var(--text-secondary)' }}>
                    {channel.type === 'email' ? channel.email : channel.url || '—'}
                </span>
            </td>
            <td className="px-4 py-3">
                {events.length === 0 ? (
                    <span className="text-sm" style={{ color: 'var(--text-muted)' }}>
                        None
                    </span>
                ) : (
                    <div className="flex flex-wrap gap-1">
                        {events.map((e) => (
                            <span
                                key={e}
                                className="text-xs px-2 py-0.5 rounded-full font-medium"
                                style={{ backgroundColor: 'var(--accent-subtle)', color: 'var(--accent-text)' }}
                            >
                                {e}
                            </span>
                        ))}
                    </div>
                )}
            </td>
            <td className="px-4 py-3 text-center">
                <span
                    className="text-xs px-2 py-0.5 rounded-full font-medium"
                    style={
                        channel.enabled
                            ? { backgroundColor: 'rgba(34,197,94,0.15)', color: '#16a34a' }
                            : { backgroundColor: 'var(--bg-muted)', color: 'var(--text-muted)' }
                    }
                >
                    {channel.enabled ? 'Enabled' : 'Disabled'}
                </span>
            </td>
            <td className="px-4 py-3">
                <div className="flex items-center gap-1 justify-end">
                    <button
                        type="button"
                        onClick={() => onRetryPolicy(channel)}
                        className="p-1.5 rounded-md transition-colors"
                        style={{ color: 'var(--text-muted)' }}
                        title="Retry policy"
                        onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.color = 'var(--text-primary)')}
                        onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.color = 'var(--text-muted)')}
                    >
                        <ArrowPathIcon className="h-4 w-4" />
                    </button>
                    <button
                        type="button"
                        onClick={() => onEdit(channel)}
                        className="p-1.5 rounded-md transition-colors"
                        style={{ color: 'var(--text-muted)' }}
                        title="Edit channel"
                        onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.color = 'var(--text-primary)')}
                        onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.color = 'var(--text-muted)')}
                    >
                        <PencilSquareIcon className="h-4 w-4" />
                    </button>
                    <button
                        type="button"
                        onClick={() => onDelete(channel)}
                        className="p-1.5 rounded-md transition-colors"
                        style={{ color: 'var(--text-muted)' }}
                        title="Delete channel"
                        onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.color = '#ef4444')}
                        onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.color = 'var(--text-muted)')}
                    >
                        <TrashIcon className="h-4 w-4" />
                    </button>
                </div>
            </td>
        </tr>
    );
};

interface ChannelFormFieldsProps {
    form: ChannelFormData;
    setForm: React.Dispatch<React.SetStateAction<ChannelFormData>>;
}

const ChannelFormFields: React.FC<ChannelFormFieldsProps> = ({ form, setForm }) => {
    const toggleEvent = (event: string) => {
        setForm((f) => {
            const events = new Set(f.events);
            if (events.has(event)) {
                events.delete(event);
            } else {
                events.add(event);
            }
            return { ...f, events };
        });
    };

    return (
        <div className="space-y-4">
            <Input
                label="Name"
                value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="e.g. platform-alerts"
            />
            <Select
                label="Type"
                options={CHANNEL_TYPES}
                value={form.type}
                onChange={(e) => setForm((f) => ({ ...f, type: e.target.value }))}
                fullWidth
            />
            {form.type === 'email' ? (
                <Input
                    label="Recipient email"
                    type="email"
                    value={form.email}
                    onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))}
                    placeholder="alerts@example.com"
                />
            ) : form.currentUrl && !form.replaceUrl ? (
                // The webhook URL is a credential: the server only ever returns its masked form, so
                // show that (read-only) and offer to replace it rather than a field to edit.
                <div>
                    <span className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                        Webhook URL
                    </span>
                    <div className="flex items-center justify-between gap-3">
                        <span className="text-sm truncate" style={{ color: 'var(--text-muted)' }}>
                            {form.currentUrl}
                        </span>
                        <Button
                            type="button"
                            variant="secondary"
                            size="sm"
                            onClick={() => setForm((f) => ({ ...f, replaceUrl: true }))}
                        >
                            Replace URL
                        </Button>
                    </div>
                </div>
            ) : (
                <div>
                    <Input
                        label="Webhook URL"
                        type="password"
                        autoComplete="off"
                        spellCheck={false}
                        value={form.url}
                        onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))}
                        placeholder="https://..."
                        helperText="The URL is a credential: it is stored encrypted and cannot be shown again."
                    />
                    {form.currentUrl && (
                        <Button
                            type="button"
                            variant="secondary"
                            size="sm"
                            className="mt-2"
                            onClick={() => setForm((f) => ({ ...f, url: '', replaceUrl: false }))}
                        >
                            Keep current URL
                        </Button>
                    )}
                </div>
            )}
            <div>
                <span className="block text-sm font-medium mb-1.5" style={{ color: 'var(--text-secondary)' }}>
                    Events
                </span>
                <div className="space-y-1">
                    {EVENT_OPTIONS.map((event) => (
                        <label key={event} className="flex items-center gap-2 cursor-pointer">
                            <input
                                type="checkbox"
                                checked={form.events.has(event)}
                                onChange={() => toggleEvent(event)}
                                className="h-4 w-4 rounded-sm accent-blue-600"
                            />
                            <span className="text-sm" style={{ color: 'var(--text-primary)' }}>
                                {event}
                            </span>
                        </label>
                    ))}
                </div>
            </div>
            <label className="flex items-center gap-2 cursor-pointer">
                <input
                    type="checkbox"
                    checked={form.enabled}
                    onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.checked }))}
                    className="h-4 w-4 rounded-sm accent-blue-600"
                />
                <span className="text-sm" style={{ color: 'var(--text-primary)' }}>
                    Enabled
                </span>
            </label>
        </div>
    );
};

interface RetryPolicyModalProps {
    channel: NotificationChannel | null;
    onClose: () => void;
}

const RetryPolicyModal: React.FC<RetryPolicyModalProps> = ({ channel, onClose }) => {
    const { data: policy, isLoading } = useRetryPolicy(channel?.id ?? null);
    const setRetryPolicy = useSetRetryPolicy();
    const [maxRetries, setMaxRetries] = useState(0);
    const [retryBackoffMs, setRetryBackoffMs] = useState(0);

    React.useEffect(() => {
        if (policy) {
            setMaxRetries(policy.max_retries);
            setRetryBackoffMs(policy.retry_backoff_ms);
        }
    }, [policy]);

    const handleSave = () => {
        if (!channel) return;
        setRetryPolicy.mutate({
            id: channel.id,
            body: { max_retries: maxRetries, retry_backoff_ms: retryBackoffMs },
        });
    };

    return (
        <Modal isOpen={channel !== null} onClose={onClose} title="Retry Policy" size="sm">
            {isLoading ? (
                <div className="flex justify-center py-8">
                    <Spinner />
                </div>
            ) : (
                <div className="space-y-4">
                    <Input
                        label="Max retries"
                        type="number"
                        min={0}
                        max={10}
                        value={maxRetries}
                        onChange={(e) => setMaxRetries(Number(e.target.value))}
                    />
                    <Input
                        label="Retry backoff (ms)"
                        type="number"
                        min={100}
                        max={60000}
                        value={retryBackoffMs}
                        onChange={(e) => setRetryBackoffMs(Number(e.target.value))}
                    />
                    {setRetryPolicy.isError && (
                        <p className="text-sm text-red-600">Failed to save retry policy. Please try again.</p>
                    )}
                    <div className="flex justify-end gap-2 pt-2">
                        <Button variant="secondary" onClick={onClose}>
                            Cancel
                        </Button>
                        <Button loading={setRetryPolicy.isPending} onClick={handleSave}>
                            Save
                        </Button>
                    </div>
                </div>
            )}
        </Modal>
    );
};

export const NotificationChannelsPage: React.FC = () => {
    const [formData, setFormData] = useState<ChannelFormData>(emptyForm());
    const [createOpen, setCreateOpen] = useState(false);
    const [editChannel, setEditChannel] = useState<NotificationChannel | null>(null);
    const [deleteChannel, setDeleteChannel] = useState<NotificationChannel | null>(null);
    const [retryPolicyChannel, setRetryPolicyChannel] = useState<NotificationChannel | null>(null);

    const { data: channelsData, isLoading: channelsLoading, error: channelsError } = useNotificationChannels();
    const createMutation = useCreateNotificationChannel();
    const updateMutation = useUpdateNotificationChannel();
    const deleteMutation = useDeleteNotificationChannel();

    const channels = channelsData ?? [];

    // Shared between each Modal's onClose and its own Cancel button so the
    // close semantics live in exactly one place per modal.
    const closeCreateModal = () => setCreateOpen(false);
    const closeEditModal = () => setEditChannel(null);
    const closeDeleteModal = () => {
        setDeleteChannel(null);
        deleteMutation.reset();
    };

    const openCreate = () => {
        setFormData(emptyForm());
        createMutation.reset();
        setCreateOpen(true);
    };

    const openEdit = (channel: NotificationChannel) => {
        setFormData({
            name: channel.name,
            type: channel.type,
            url: '',
            currentUrl: channel.url ?? '',
            replaceUrl: false,
            email: channel.email ?? '',
            events: new Set(
                channel.events
                    ? channel.events
                          .split(',')
                          .map((e) => e.trim())
                          .filter(Boolean)
                    : []
            ),
            enabled: channel.enabled,
        });
        updateMutation.reset();
        setEditChannel(channel);
    };

    const openDelete = (channel: NotificationChannel) => {
        deleteMutation.reset();
        setDeleteChannel(channel);
    };

    const handleCreate = () => {
        if (!formData.name.trim()) return;
        createMutation.mutate(formToPayload(formData), { onSuccess: closeCreateModal });
    };

    const handleUpdate = () => {
        if (!editChannel || !formData.name.trim()) return;
        updateMutation.mutate({ id: editChannel.id, body: formToPayload(formData) }, { onSuccess: closeEditModal });
    };

    const handleDelete = () => {
        if (!deleteChannel) return;
        deleteMutation.mutate(deleteChannel.id, {
            onSuccess: closeDeleteModal,
        });
    };

    return (
        <div className="max-w-5xl mx-auto px-6 py-8">
            <div className="mb-6 flex items-start justify-between">
                <div>
                    <h1 className="text-2xl font-bold tracking-tight" style={{ color: 'var(--text-primary)' }}>
                        Notification Channels
                    </h1>
                    <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                        Route rotation, expiry, and anomaly events to webhooks, Slack, Teams, or email.
                    </p>
                </div>
                <Button size="sm" onClick={openCreate}>
                    <PlusIcon className="size-4" />
                    New Channel
                </Button>
            </div>

            <div className="rounded-xl border overflow-hidden" style={{ borderColor: 'var(--border)' }}>
                <table className="w-full text-sm">
                    <thead>
                        <tr style={{ backgroundColor: 'var(--bg-subtle)' }}>
                            <th
                                className="px-4 py-3 text-left text-xs font-medium"
                                style={{ color: 'var(--text-muted)' }}
                            >
                                Name
                            </th>
                            <th
                                className="px-4 py-3 text-left text-xs font-medium"
                                style={{ color: 'var(--text-muted)' }}
                            >
                                Type
                            </th>
                            <th
                                className="px-4 py-3 text-left text-xs font-medium"
                                style={{ color: 'var(--text-muted)' }}
                            >
                                Target
                            </th>
                            <th
                                className="px-4 py-3 text-left text-xs font-medium"
                                style={{ color: 'var(--text-muted)' }}
                            >
                                Events
                            </th>
                            <th
                                className="px-4 py-3 text-center text-xs font-medium"
                                style={{ color: 'var(--text-muted)' }}
                            >
                                Status
                            </th>
                            <th
                                className="px-4 py-3 text-right text-xs font-medium"
                                style={{ color: 'var(--text-muted)' }}
                            >
                                Actions
                            </th>
                        </tr>
                    </thead>
                    <tbody>
                        {channelsLoading && (
                            <tr>
                                <td colSpan={6} className="px-4 py-12 text-center">
                                    <Spinner className="mx-auto" />
                                </td>
                            </tr>
                        )}
                        {channelsError !== null && channelsError !== undefined && (
                            <tr>
                                <td
                                    colSpan={6}
                                    className="px-4 py-8 text-center text-sm"
                                    style={{ color: 'var(--text-muted)' }}
                                >
                                    Failed to load notification channels. Please try again.
                                </td>
                            </tr>
                        )}
                        {!channelsLoading && !channelsError && channels.length === 0 && (
                            <tr>
                                <td
                                    colSpan={6}
                                    className="px-4 py-8 text-center text-sm"
                                    style={{ color: 'var(--text-muted)' }}
                                >
                                    No notification channels yet. Create one to get started.
                                </td>
                            </tr>
                        )}
                        {!channelsLoading &&
                            !channelsError &&
                            channels.map((channel) => (
                                <ChannelRow
                                    key={channel.id}
                                    channel={channel}
                                    onEdit={openEdit}
                                    onDelete={openDelete}
                                    onRetryPolicy={setRetryPolicyChannel}
                                />
                            ))}
                    </tbody>
                </table>
            </div>

            {/* Create Channel */}
            <Modal isOpen={createOpen} onClose={closeCreateModal} title="New Channel">
                <div className="space-y-4">
                    <ChannelFormFields form={formData} setForm={setFormData} />
                    {createMutation.isError && (
                        <p className="text-sm text-red-600">Failed to create channel. Please try again.</p>
                    )}
                    <div className="flex justify-end gap-2 pt-2">
                        <Button variant="secondary" onClick={closeCreateModal}>
                            Cancel
                        </Button>
                        <Button
                            loading={createMutation.isPending}
                            disabled={!formData.name.trim()}
                            onClick={handleCreate}
                        >
                            Create
                        </Button>
                    </div>
                </div>
            </Modal>

            {/* Edit Channel */}
            <Modal isOpen={editChannel !== null} onClose={closeEditModal} title="Edit Channel">
                <div className="space-y-4">
                    <ChannelFormFields form={formData} setForm={setFormData} />
                    {updateMutation.isError && (
                        <p className="text-sm text-red-600">Failed to update channel. Please try again.</p>
                    )}
                    <div className="flex justify-end gap-2 pt-2">
                        <Button variant="secondary" onClick={closeEditModal}>
                            Cancel
                        </Button>
                        <Button
                            loading={updateMutation.isPending}
                            disabled={!formData.name.trim()}
                            onClick={handleUpdate}
                        >
                            Save
                        </Button>
                    </div>
                </div>
            </Modal>

            {/* Retry policy */}
            <RetryPolicyModal channel={retryPolicyChannel} onClose={() => setRetryPolicyChannel(null)} />

            {/* Delete Channel */}
            <Modal isOpen={deleteChannel !== null} onClose={closeDeleteModal} title="Delete Channel" size="sm">
                <div className="space-y-4">
                    <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                        Delete channel <strong style={{ color: 'var(--text-primary)' }}>{deleteChannel?.name}</strong>?
                        This action cannot be undone.
                    </p>
                    {deleteMutation.isError && (
                        <p className="text-sm text-red-600">Failed to delete channel. Please try again.</p>
                    )}
                    <div className="flex justify-end gap-2 pt-2">
                        <Button variant="secondary" onClick={closeDeleteModal}>
                            Cancel
                        </Button>
                        <Button variant="destructive" loading={deleteMutation.isPending} onClick={handleDelete}>
                            Delete
                        </Button>
                    </div>
                </div>
            </Modal>
        </div>
    );
};
