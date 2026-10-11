// Audit descriptions name the objects they talk about by id ("secret 3 restored",
// "role 9 assigned to user 2"). Newer events carry the name next to the id
// (`secret 3 ("db-password") restored`, internal/core/audit_refs.go); older stored
// events carry only the id and must not be rewritten (tamper-evident chain), so the
// ids are turned into names at display time, for the objects the viewer may see.

export type NameMap = ReadonlyMap<number, string>;

export interface AuditNameMaps {
    roles?: NameMap | undefined;
    groups?: NameMap | undefined;
    users?: NameMap | undefined;
    secrets?: NameMap | undefined;
    projects?: NameMap | undefined;
}

type Kind = 'role' | 'group' | 'user' | 'secret' | 'project';

// Kinds whose objects every viewer can list (their own secrets / projects). Once that
// list has loaded, an id that is not in it is deleted or not visible to them, so it reads
// "secret #3". Roles, groups and users come from admin-only lookups; an id they do not
// resolve is left as the server wrote it, so the page never claims more than it looked up.
const ALWAYS_LOOKED_UP: ReadonlySet<Kind> = new Set<Kind>(['secret', 'project']);
const QUOTED: ReadonlySet<Kind> = new Set<Kind>(['secret', 'project']);

// A token already followed by ` (` carries its own name (new events); leave it alone.
const ID_TOKEN = /\b(role|group|user|secret|project) (\d+)\b(?! \()/g;

export function resolveAuditIds(description: string, maps: AuditNameMaps): string {
    if (!description) return description;
    return description.replace(ID_TOKEN, (token: string, kind: string, rawId: string) => {
        const k = kind as Kind;
        const id = Number(rawId);
        const map = maps[`${k}s` as keyof AuditNameMaps];
        // No map: the lookup was not made (not allowed, or still loading) -- leave the id as written.
        if (!map) return token;
        const name = map.get(id);
        if (name) return QUOTED.has(k) ? `${k} "${name}"` : name;
        // The lookup was made and the object is not in it: deleted, or not visible to this viewer.
        return ALWAYS_LOOKED_UP.has(k) ? `${k} #${id}` : token;
    });
}

export function toNameMap<T>(items: readonly T[] | undefined, id: (t: T) => number, name: (t: T) => string): NameMap {
    const m = new Map<number, string>();
    (items ?? []).forEach((t) => {
        const n = name(t);
        if (n) m.set(id(t), n);
    });
    return m;
}
