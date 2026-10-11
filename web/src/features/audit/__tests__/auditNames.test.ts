import { describe, it, expect } from 'vitest';
import { resolveAuditIds, toNameMap } from '../auditNames';

const maps = {
    secrets: new Map([[3, 'db-password']]),
    projects: new Map([[5, 'payments']]),
    roles: new Map([[9, 'deployer']]),
    users: new Map([[2, 'bob']]),
    groups: new Map([[4, 'platform']]),
};

describe('resolveAuditIds', () => {
    it('turns the id-only description of an old event into names', () => {
        expect(resolveAuditIds('secret 3 restored', maps)).toBe('secret "db-password" restored');
        expect(resolveAuditIds('project 5 deleted (force=false)', maps)).toBe(
            'project "payments" deleted (force=false)'
        );
        expect(resolveAuditIds('role 9 assigned to user 2', maps)).toBe('deployer assigned to bob');
        expect(resolveAuditIds('user 2 added to group 4', maps)).toBe('bob added to platform');
    });

    it('falls back to "secret #3" for a secret or project that is deleted or not visible', () => {
        expect(resolveAuditIds('secret 77 restored', maps)).toBe('secret #77 restored');
        expect(resolveAuditIds('project 88 restored', maps)).toBe('project #88 restored');
    });

    it('keeps the id for a role, group or user it has no lookup for (not an admin)', () => {
        expect(resolveAuditIds('role 9 assigned to user 2', { secrets: maps.secrets })).toBe(
            'role 9 assigned to user 2'
        );
        // Unresolved within a lookup that did run: still the server's text, never a made-up "#".
        expect(resolveAuditIds('role 999 assigned to user 2', maps)).toBe('role 999 assigned to bob');
    });

    it('does nothing until the secret / project lists have loaded', () => {
        expect(resolveAuditIds('secret 3 restored', {})).toBe('secret 3 restored');
    });

    it('leaves a token alone when a newer event already carries its name', () => {
        const withName = 'secret 3 ("db-password") restored';
        expect(resolveAuditIds(withName, maps)).toBe(withName);
        const rbac = 'role 9 ("deployer") assigned to user 2 ("bob")';
        expect(resolveAuditIds(rbac, maps)).toBe(rbac);
        const grp = 'user 2 ("bob") added to group 4 ("platform")';
        expect(resolveAuditIds(grp, maps)).toBe(grp);
    });

    it('does not touch ids that are not an object reference', () => {
        expect(resolveAuditIds('revoked ACL 3 on something', maps)).toBe('revoked ACL 3 on something');
        expect(resolveAuditIds('', maps)).toBe('');
    });
});

describe('toNameMap', () => {
    it('skips entries with an empty name', () => {
        const m = toNameMap(
            [
                { id: 1, name: 'a' },
                { id: 2, name: '' },
            ],
            (x) => x.id,
            (x) => x.name
        );
        expect([...m.entries()]).toEqual([[1, 'a']]);
    });
});
