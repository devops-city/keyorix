import type { ProjectEnvironment } from '../../services/projects';

// Which environment a project's Secrets tab opens on when the URL names none.
//
// The old rule was "production, else the first": a project whose only secret lives
// in development opened on "No secrets in production / Create your first secret"
// (DEMO-WALK-3 findings 6 and 36), while the project list said "1 secret". The
// environment list now carries a server-computed secret_count per environment
// (DASH-SIGNALS-1), so pick the first environment (production first, then the
// project's own order) that has any, with no per-environment request. If no
// environment has a secret, or a server predating secret_count sent none,
// production stays the default.

const preferenceOrder = (envs: ProjectEnvironment[]): ProjectEnvironment[] => {
    const prod = envs.filter((e) => e.name.toLowerCase() === 'production');
    return [...prod, ...envs.filter((e) => e.name.toLowerCase() !== 'production')];
};

export interface DefaultEnvironment {
    /** The environment name to open on, or null while the environment list is still loading. */
    name: string | null;
}

export function pickDefaultEnvironment(envs: ProjectEnvironment[]): string {
    const ordered = preferenceOrder(envs);
    const withSecrets = ordered.find((e) => (e.secretCount ?? 0) > 0);
    return (withSecrets ?? ordered[0])?.name ?? 'production';
}

export function useDefaultEnvironment(environments: ProjectEnvironment[], enabled: boolean): DefaultEnvironment {
    if (environments.length === 0) return { name: null };
    if (!enabled) return { name: preferenceOrder(environments)[0]?.name ?? 'production' };
    return { name: pickDefaultEnvironment(environments) };
}
