import React from 'react';
import { Dialog, type DialogProps } from './Dialog';

export interface ConfirmOptions {
    /** The question shown in the body. Pass the exact wording the old window.confirm used. */
    message: string;
    title?: string;
    confirmText?: string;
    cancelText?: string;
    type?: DialogProps['type'];
}

interface Pending {
    options: ConfirmOptions;
    resolve: (ok: boolean) => void;
}

/**
 * In-app replacement for window.confirm. Render `confirmDialog` once in the
 * component's JSX, then `if (!(await requestConfirm({ message }))) return;`.
 *
 * Native confirm() is unstyled, ignores the theme, blocks the event loop and
 * cannot be driven reliably by browser automation (#3153). The returned function
 * is deliberately not called `confirm`, so that the guard test
 * (src/__tests__/structure/noNativeConfirm.test.ts) can flag every bare confirm( call.
 */
export function useConfirm() {
    const [pending, setPending] = React.useState<Pending | null>(null);
    const pendingRef = React.useRef<Pending | null>(null);

    const settle = React.useCallback((ok: boolean) => {
        const p = pendingRef.current;
        pendingRef.current = null;
        setPending(null);
        p?.resolve(ok);
    }, []);

    const requestConfirm = React.useCallback((options: ConfirmOptions) => {
        // A second request while one is open cancels the first.
        pendingRef.current?.resolve(false);
        return new Promise<boolean>((resolve) => {
            const p = { options, resolve };
            pendingRef.current = p;
            setPending(p);
        });
    }, []);

    // Resolve as cancelled if the owning component unmounts with a dialog open.
    React.useEffect(
        () => () => {
            pendingRef.current?.resolve(false);
            pendingRef.current = null;
        },
        []
    );

    const o = pending?.options;
    const confirmDialog = (
        <Dialog
            isOpen={pending !== null}
            onClose={() => settle(false)}
            onConfirm={() => settle(true)}
            title={o?.title ?? 'Please confirm'}
            message={o?.message ?? ''}
            type={o?.type ?? 'danger'}
            confirmText={o?.confirmText ?? 'Confirm'}
            {...(o?.cancelText && { cancelText: o.cancelText })}
        />
    );

    return { requestConfirm, confirmDialog };
}
