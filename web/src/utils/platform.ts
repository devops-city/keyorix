// Platform-aware keyboard hint: the command palette opens on Cmd+K (macOS) or
// Ctrl+K (everywhere else), and the hint must say the one that works.

export function isMacPlatform(
    nav: { platform?: string; userAgent?: string } | undefined = globalThis.navigator
): boolean {
    const p = `${nav?.platform ?? ''} ${nav?.userAgent ?? ''}`;
    return /Mac|iPhone|iPad|iPod/i.test(p);
}

/** "⌘K" on Apple platforms, "Ctrl+K" elsewhere. */
export function paletteShortcutLabel(mac: boolean = isMacPlatform()): string {
    return mac ? '⌘K' : 'Ctrl+K';
}

/** True for the keydown that opens the palette on this platform (Cmd+K on Mac, Ctrl+K otherwise; either is accepted). */
export function isPaletteShortcut(e: Pick<KeyboardEvent, 'key' | 'metaKey' | 'ctrlKey'>): boolean {
    return e.key.toLowerCase() === 'k' && (e.metaKey || e.ctrlKey);
}
