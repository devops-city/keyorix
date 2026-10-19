import { fireEvent, screen, within } from '@testing-library/react';

/**
 * Drive the in-app confirmation dialog (components/ui/useConfirm) the way a user
 * does: find the dialog showing `message`, then click its confirm button or Cancel.
 * Replaces the old `vi.spyOn(window, 'confirm')` pattern.
 */
export async function answerConfirm(message: string | RegExp, answer: 'accept' | 'cancel'): Promise<void> {
    answerConfirmNow(await screen.findByText(message), message, answer);
}

/** Synchronous variant for tests running under fake timers (findBy* polls on timers). */
export function answerConfirmSync(message: string | RegExp, answer: 'accept' | 'cancel'): void {
    answerConfirmNow(screen.getByText(message), message, answer);
}

function answerConfirmNow(text: HTMLElement, message: string | RegExp, answer: 'accept' | 'cancel'): void {
    const dialog = text.closest('[role="dialog"]') as HTMLElement | null;
    if (!dialog) throw new Error(`text ${String(message)} is not inside a role="dialog"`);
    const buttons = within(dialog).getAllByRole('button');
    const isCancel = (b: HTMLElement) => /^cancel$/i.test(b.textContent?.trim() ?? '');
    const target = answer === 'cancel' ? buttons.find(isCancel) : buttons.find((b) => !isCancel(b));
    if (!target) throw new Error(`no ${answer} button in the confirm dialog`);
    fireEvent.click(target);
}

/** The confirm dialog showing `message`, or null. For asserting wording / absence. */
export function queryConfirm(message: string | RegExp): HTMLElement | null {
    const text = screen.queryByText(message);
    return (text?.closest('[role="dialog"]') as HTMLElement | null) ?? null;
}
