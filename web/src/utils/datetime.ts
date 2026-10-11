import { parseServerDate } from './index';

// The one timestamp format for the whole app: "Oct 10, 2026, 6:43 PM PDT".
// Always carries the viewer's timezone abbreviation so a screenshot or a
// compliance export reading is unambiguous. Zone-less server timestamps are read
// as UTC (see parseServerDate).

function toDate(value: string | Date | null | undefined): Date | null {
    if (value == null || value === '') return null;
    const d = parseServerDate(value);
    return Number.isNaN(d.getTime()) ? null : d;
}

/** "Oct 10, 2026, 6:43 PM PDT" (with `seconds`: "6:43:37 PM PDT"). "—" for empty/invalid input. */
export function formatDateTime(value: string | Date | null | undefined, opts: { seconds?: boolean } = {}): string {
    const d = toDate(value);
    if (!d) return '—';
    return new Intl.DateTimeFormat('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
        ...(opts.seconds ? { second: '2-digit' as const } : {}),
        timeZoneName: 'short',
    }).format(d);
}

/** "Oct 10, 2026" with no time, rendered in the viewer's timezone. */
export function formatDay(value: string | Date | null | undefined): string {
    const d = toDate(value);
    if (!d) return '—';
    return new Intl.DateTimeFormat('en-US', { year: 'numeric', month: 'short', day: 'numeric' }).format(d);
}

/** "1 minute ago" / "5 hours ago"; falls back to the full date-time after 30 days. */
export function formatAgo(value: string | Date | null | undefined, now: number = Date.now()): string {
    const d = toDate(value);
    if (!d) return '—';
    const seconds = Math.floor((now - d.getTime()) / 1000);
    if (seconds < 60) return 'just now';
    const unit = (n: number, name: string) => `${n} ${name}${n === 1 ? '' : 's'} ago`;
    if (seconds < 3600) return unit(Math.floor(seconds / 60), 'minute');
    if (seconds < 86400) return unit(Math.floor(seconds / 3600), 'hour');
    if (seconds < 2592000) return unit(Math.floor(seconds / 86400), 'day');
    return formatDateTime(d);
}

const GO_DURATION_PART = /(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)/g;
const UNIT_SECONDS: Record<string, number> = { ns: 1e-9, us: 1e-6, µs: 1e-6, ms: 1e-3, s: 1, m: 60, h: 3600 };

/**
 * Go time.Duration strings ("24h0m0s", "12h0m0s", "90m0s") -> "24 hours",
 * "1 hour 30 minutes". Anything that is not a Go duration is returned unchanged.
 */
export function formatGoDuration(raw: string | null | undefined): string {
    if (!raw) return '—';
    const s = raw.trim();
    if (!/^(\d+(?:\.\d+)?(ns|us|µs|ms|s|m|h))+$/.test(s)) return raw;
    let total = 0;
    for (const m of s.matchAll(GO_DURATION_PART)) {
        total += Number(m[1]) * (UNIT_SECONDS[m[2] as string] as number);
    }
    if (total === 0) return '0 seconds';
    if (total < 1) return `${Math.round(total * 1000)} ms`;
    const plural = (n: number, w: string) => `${n} ${w}${n === 1 ? '' : 's'}`;
    const secs = Math.round(total);
    // "24 hours", not "1 day": days only once the span is clearly longer than a day.
    const days = secs >= 172800 ? Math.floor(secs / 86400) : 0;
    const hours = Math.floor((secs - days * 86400) / 3600);
    const minutes = Math.floor((secs % 3600) / 60);
    const seconds = secs % 60;
    const parts: string[] = [];
    if (days) parts.push(plural(days, 'day'));
    if (hours) parts.push(plural(hours, 'hour'));
    if (minutes) parts.push(plural(minutes, 'minute'));
    if (seconds) parts.push(plural(seconds, 'second'));
    return parts.join(' ');
}
