// One place that turns a server audit event type ("mfa.login_verified") or a
// secret-access verb ("versions_list") into customer-facing text. The dashboard
// feed, project Activity tab, Audit page and a secret's "Recent access" panel
// all use it, so a new server event never shows up as a raw identifier on one
// screen and a friendly label on another.

const EVENT_LABELS: Record<string, string> = {
    // Auth
    'auth.login': 'Login',
    'auth.logout': 'Logout',
    'auth.login_failed': 'Login failed',
    'auth.password_changed': 'Password changed',
    'auth.password_reset': 'Password reset',
    'auth.sso_login': 'SSO login',
    'auth.sso_jit_provisioned': 'SSO user provisioned',
    'auth.sso_groups_synced': 'SSO groups synced',
    'auth.sso_roles_synced': 'SSO roles synced',
    'auth.session_reuse_detected': 'Session reuse detected',
    'session.revoked': 'Session revoked',
    // MFA
    'mfa.enrolled': 'MFA enrolled',
    'mfa.activated': 'MFA activated',
    'mfa.disabled': 'MFA disabled',
    'mfa.login_verified': 'MFA login verified',
    'mfa.stepup_verified': 'MFA step-up verified',
    'mfa.reauth_verified': 'MFA re-authentication verified',
    'mfa.recovery_used': 'MFA recovery code used',
    'mfa.recovery_codes_regenerated': 'MFA recovery codes regenerated',
    'mfa.failed': 'MFA failed',
    'mfa.error': 'MFA error',
    // Secrets
    'secret.read': 'Read',
    'secret.metadata_read': 'Metadata read',
    'secret.versions_listed': 'Versions listed',
    'secret.created': 'Created',
    'secret.updated': 'Updated',
    'secret.deleted': 'Deleted',
    'secret.restored': 'Restored',
    'secret.rotated': 'Rotated',
    'secret.rolled_back': 'Rolled back',
    'secret.moved': 'Moved',
    'secret.suspended': 'Suspended',
    'secret.resumed': 'Resumed',
    'secret.shared': 'Shared',
    'secret.share_revoked': 'Share revoked',
    'secret.unshared': 'Unshared',
    'secret.owner_transferred': 'Owner transferred',
    'secret.ownership_transferred': 'Owner transferred',
    'secret.classified': 'Reclassified',
    'secret.acl_granted': 'Access granted',
    'secret.acl_revoked': 'Access revoked',
    'secret.description_updated': 'Description updated',
    'secret.tags_updated': 'Tags updated',
    'secret.auto_rotated': 'Auto-rotated',
    'share.revoked': 'Unshared',
    'share.expired': 'Share expired',
    // Machine identities
    'machine_identity.created': 'Machine identity created',
    'machine_identity.token_issued': 'Machine token issued',
    'machine_identity.token_rotated': 'Machine token rotated',
    'machine_identity.token_revoked': 'Machine token revoked',
    'machine_identity.role_granted': 'Machine role granted',
    'machine_identity.role_removed': 'Machine role removed',
    // Projects, users, invitations
    'project.created': 'Project created',
    'project.updated': 'Project updated',
    'project.deleted': 'Project deleted',
    'project.restored': 'Project restored',
    'user.created': 'User created',
    'user.updated': 'User updated',
    'user.deleted': 'User deleted',
    'user.restored': 'User restored',
    'invitation.created': 'Invitation sent',
    'invitation.accepted': 'Invitation accepted',
    'invitation.revoked': 'Invitation revoked',
    // RBAC
    'role.created': 'Role created',
    'role.updated': 'Role updated',
    'role.deleted': 'Role deleted',
    'role.assigned': 'Role assigned',
    'role.removed': 'Role removed',
    'role.expired': 'Role expired',
    'role.group_assigned': 'Role assigned to group',
    'role.group_removed': 'Role removed from group',
    'permission.assigned': 'Permission granted',
    'permission.removed': 'Permission revoked',
    'group.created': 'Group created',
    'group.updated': 'Group updated',
    'group.deleted': 'Group deleted',
    'group.restored': 'Group restored',
    'group.member_added': 'Added to group',
    'group.member_removed': 'Removed from group',
    // Break-glass, admin
    'break_glass.activated': 'Break-glass activated',
    'break_glass.revoked': 'Break-glass revoked',
    'break_glass.reviewed': 'Break-glass reviewed',
    'admin.backup_created': 'Backup created',
    'admin.restore_completed': 'Restore completed',
};

// Words that must stay upper-case when a fallback label is built from a raw name.
const ACRONYMS = new Set(['mfa', 'sso', 'api', 'pat', 'rbac', 'ip', 'id', 'acl', 'tls', 'oidc', 'saml', 'kek', 'csv']);

/** "mfa.login_verified" -> "MFA login verified". Used only when no curated label exists. */
export function humanizeEventName(raw: string): string {
    const words = raw
        .replace(/[._]+/g, ' ')
        .trim()
        .split(/\s+/)
        .filter(Boolean)
        .map((w) => (ACRONYMS.has(w.toLowerCase()) ? w.toUpperCase() : w.toLowerCase()));
    if (words.length === 0) return raw;
    const first = words[0] as string;
    words[0] = first === first.toUpperCase() ? first : first.charAt(0).toUpperCase() + first.slice(1);
    return words.join(' ');
}

/** Friendly label for a server audit event type. Never returns a dotted/snake_case identifier. */
export function eventLabel(eventType: string | null | undefined, stripPrefix?: string): string {
    if (!eventType) return '—';
    if (EVENT_LABELS[eventType]) return EVENT_LABELS[eventType];
    const bare = stripPrefix && eventType.startsWith(stripPrefix) ? eventType.slice(stripPrefix.length) : eventType;
    return humanizeEventName(bare);
}

// Verbs on a secret's "Recent access" list (server-side access log, no "secret." prefix).
const ACCESS_ACTION_LABELS: Record<string, string> = {
    read: 'Read',
    create: 'Created',
    update: 'Updated',
    rotate: 'Rotated',
    delete: 'Deleted',
    share: 'Shared',
    versions_list: 'Listed versions',
    metadata_read: 'Looked up metadata',
};

export function accessActionLabel(action: string | null | undefined): string {
    if (!action) return '—';
    return ACCESS_ACTION_LABELS[action] ?? EVENT_LABELS[action] ?? humanizeEventName(action);
}
