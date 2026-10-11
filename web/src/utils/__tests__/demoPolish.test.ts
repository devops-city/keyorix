import { describe, it, expect } from 'vitest';
import { eventLabel, accessActionLabel, humanizeEventName } from '../eventLabels';
import { formatDateTime, formatAgo, formatGoDuration } from '../datetime';
import { isKnownBuildValue, appVersionLabel } from '../buildInfo';
import { paletteShortcutLabel, isMacPlatform, isPaletteShortcut } from '../platform';

describe('eventLabel', () => {
    it.each([
        ['mfa.login_verified', 'MFA login verified'],
        ['secret.restored', 'Restored'],
        ['secret.rolled_back', 'Rolled back'],
        ['machine_identity.token_issued', 'Machine token issued'],
        ['role.assigned', 'Role assigned'],
        ['auth.login', 'Login'],
    ])('%s -> %s', (raw, want) => {
        expect(eventLabel(raw)).toBe(want);
    });

    it('never returns a dotted or snake_case identifier for an event nobody curated', () => {
        const out = eventLabel('vault.some_new_event');
        expect(out).toBe('Vault some new event');
        expect(out).not.toMatch(/[._]/);
        expect(humanizeEventName('sso.saml_acs')).toBe('SSO SAML acs');
    });

    it('handles empty input', () => {
        expect(eventLabel('')).toBe('—');
        expect(eventLabel(undefined)).toBe('—');
    });

    it('labels secret access verbs', () => {
        expect(accessActionLabel('versions_list')).toBe('Listed versions');
        expect(accessActionLabel('read')).toBe('Read');
        expect(accessActionLabel('create')).toBe('Created');
        expect(accessActionLabel('weird_verb')).toBe('Weird verb');
    });
});

describe('formatDateTime', () => {
    it('always carries a timezone name', () => {
        const out = formatDateTime('2026-10-10T18:43:37Z');
        expect(out).toMatch(/Oct 10, 2026/);
        expect(out).toMatch(/\b(UTC|GMT|[A-Z]{2,5}|GMT[+-]\d+)\s*$/);
    });

    it('reads a zone-less server timestamp as UTC', () => {
        const withZ = formatDateTime('2026-10-10T18:43:37Z');
        expect(formatDateTime('2026-10-10 18:43:37')).toBe(withZ);
    });

    it('shows seconds on request and a dash for bad input', () => {
        expect(formatDateTime('2026-10-10T18:43:37Z', { seconds: true })).toMatch(/:37/);
        expect(formatDateTime(null)).toBe('—');
        expect(formatDateTime('not a date')).toBe('—');
    });
});

describe('formatAgo', () => {
    const now = Date.parse('2026-10-10T12:00:00Z');
    const ago = (ms: number) => new Date(now - ms).toISOString();
    it('pluralises correctly', () => {
        expect(formatAgo(ago(65_000), now)).toBe('1 minute ago');
        expect(formatAgo(ago(125_000), now)).toBe('2 minutes ago');
        expect(formatAgo(ago(3_700_000), now)).toBe('1 hour ago');
        expect(formatAgo(ago(2 * 86_400_000), now)).toBe('2 days ago');
        expect(formatAgo(ago(5_000), now)).toBe('just now');
    });
});

describe('formatGoDuration', () => {
    it.each([
        ['24h0m0s', '24 hours'],
        ['12h0m0s', '12 hours'],
        ['1h30m0s', '1 hour 30 minutes'],
        ['15m0s', '15 minutes'],
        ['1m0s', '1 minute'],
        ['720h0m0s', '30 days'],
        ['30s', '30 seconds'],
    ])('%s -> %s', (raw, want) => {
        expect(formatGoDuration(raw)).toBe(want);
    });

    it('passes non-durations through and dashes empties', () => {
        expect(formatGoDuration('forever')).toBe('forever');
        expect(formatGoDuration('')).toBe('—');
    });
});

describe('build info', () => {
    it('treats Go ldflags defaults as unknown', () => {
        for (const v of ['dev', 'none', 'unknown', '', undefined]) expect(isKnownBuildValue(v)).toBe(false);
        expect(isKnownBuildValue('0.96.1')).toBe(true);
    });

    it('never fabricates a version', () => {
        expect(appVersionLabel(undefined)).toBe('Keyorix');
        expect(appVersionLabel('dev')).toBe('Keyorix');
        expect(appVersionLabel('0.96.1')).toBe('Keyorix v0.96.1');
    });
});

describe('platform shortcut', () => {
    it('says Ctrl+K off Apple platforms and ⌘K on them', () => {
        expect(paletteShortcutLabel(false)).toBe('Ctrl+K');
        expect(paletteShortcutLabel(true)).toBe('⌘K');
        expect(isMacPlatform({ platform: 'MacIntel' })).toBe(true);
        expect(isMacPlatform({ platform: 'Linux x86_64', userAgent: 'X11; Linux' })).toBe(false);
        expect(isMacPlatform({ platform: 'Win32' })).toBe(false);
    });

    it('opens on Ctrl+K and Cmd+K, including with caps lock', () => {
        expect(isPaletteShortcut({ key: 'k', ctrlKey: true, metaKey: false })).toBe(true);
        expect(isPaletteShortcut({ key: 'K', ctrlKey: true, metaKey: false })).toBe(true);
        expect(isPaletteShortcut({ key: 'k', ctrlKey: false, metaKey: true })).toBe(true);
        expect(isPaletteShortcut({ key: 'k', ctrlKey: false, metaKey: false })).toBe(false);
    });
});
