// What a secret share's permission actually allows. A "write" share lets the
// recipient update the value and metadata and rotate the secret (since #3001); it
// does not let them delete, share or administer it. Showing the bare word "write"
// is ambiguous (it reads as full control), so every place that shows a share-sourced permission uses this.

export const SHARE_WRITE_LABEL = 'Update value/metadata, rotate';

export function sharePermissionLabel(permission: string): string {
    if (permission === 'write') return SHARE_WRITE_LABEL;
    if (permission === 'read') return 'Read Only';
    return permission;
}
