import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '../../../test/test-utils';
import { answerConfirm } from '../../../test/confirm';
import { useConfirm, type ConfirmOptions } from '../useConfirm';

let results: boolean[] = [];

const Harness: React.FC<{ options?: ConfirmOptions }> = ({ options = { message: 'Really?' } }) => {
    const { requestConfirm, confirmDialog } = useConfirm();
    return (
        <div>
            <button onClick={async () => results.push(await requestConfirm(options))}>ask</button>
            <button onClick={async () => results.push(await requestConfirm({ message: 'Second?' }))}>ask2</button>
            {confirmDialog}
        </div>
    );
};

describe('useConfirm', () => {
    it('resolves true on confirm and false on cancel, never touching window.confirm', async () => {
        results = [];
        const nativeSpy = vi.spyOn(window, 'confirm');
        render(<Harness options={{ message: 'Really?', confirmText: 'Do it' }} />);

        fireEvent.click(screen.getByText('ask'));
        expect(await screen.findByRole('button', { name: 'Do it' })).toBeInTheDocument();
        await answerConfirm('Really?', 'accept');
        await waitFor(() => expect(results).toEqual([true]));

        fireEvent.click(screen.getByText('ask'));
        await answerConfirm('Really?', 'cancel');
        await waitFor(() => expect(results).toEqual([true, false]));
        expect(nativeSpy).not.toHaveBeenCalled();
        nativeSpy.mockRestore();
    });

    it('resolves false when dismissed with Escape', async () => {
        results = [];
        render(<Harness />);
        fireEvent.click(screen.getByText('ask'));
        const dialog = await screen.findByRole('dialog');
        fireEvent.keyDown(dialog, { key: 'Escape' });
        await waitFor(() => expect(results).toEqual([false]));
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });

    it('a second request while one is open cancels the first', async () => {
        results = [];
        render(<Harness />);
        fireEvent.click(screen.getByText('ask'));
        await screen.findByText('Really?');
        // Radix marks the page behind the dialog inert; fire the click directly.
        fireEvent.click(screen.getByText('ask2'));
        await waitFor(() => expect(results).toEqual([false]));
        expect(await screen.findByText('Second?')).toBeInTheDocument();
    });

    it('resolves false if the owner unmounts with the dialog open', async () => {
        results = [];
        const { unmount } = render(<Harness />);
        fireEvent.click(screen.getByText('ask'));
        await screen.findByText('Really?');
        unmount();
        await waitFor(() => expect(results).toEqual([false]));
    });
});
