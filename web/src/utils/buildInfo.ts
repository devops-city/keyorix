// Build/version text must be true or absent. Go's -ldflags defaults ("dev",
// "none", "unknown") mean "this binary was not stamped"; showing them (or a
// hardcoded "v0.1.0") makes a demo look unfinished and misreports what is running.

const UNSTAMPED = new Set(['', 'dev', 'none', 'unknown', 'n/a', 'undefined']);

export function isKnownBuildValue(v: string | null | undefined): v is string {
    return v != null && !UNSTAMPED.has(v.trim().toLowerCase());
}

/** The label for the sidebar/footer: "Keyorix v1.2.3" when the build is stamped, else just "Keyorix". */
export function appVersionLabel(version: string | undefined = import.meta.env.VITE_APP_VERSION): string {
    if (!isKnownBuildValue(version)) return 'Keyorix';
    return `Keyorix ${/^\d/.test(version) ? 'v' : ''}${version}`;
}
