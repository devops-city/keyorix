import React, { useState } from 'react';
import {
    DevicePhoneMobileIcon,
    ShieldCheckIcon,
    ClipboardDocumentIcon,
    CheckIcon,
    ExclamationTriangleIcon,
} from '@heroicons/react/24/outline';
import { Button } from '../../components/ui/Button';
import { Input } from '../../components/ui/Input';
import { Alert } from '../../components/ui/Alert';
import { Spinner } from '../../components/ui/Loading';
import { Modal } from '../../components/ui/Modal';
import { copyToClipboard } from '../../utils';
import { useMfaRecoveryStatus, useEnrollMfa, useActivateMfa, useDisableMfa, useRegenerateRecoveryCodes } from './index';
import { useAutoClearOnIdle } from '../../hooks/useAutoClearOnIdle';
import { useAuthStore } from '../../store/authStore';
import { userOwesMfaEnrolment } from '../auth/setup';

// LOW_CODES_THRESHOLD is when we nudge the user to regenerate recovery codes.
const LOW_CODES_THRESHOLD = 3;

function errMessage(e: unknown, fallback: string): string {
    return (
        (e as { response?: { data?: { message?: string } }; message?: string })?.response?.data?.message ||
        (e as Error)?.message ||
        fallback
    );
}

// RecoveryCodes renders the one-time codes with a copy-all control. The codes are
// shown once after activation/regeneration and never retrievable again.
const RecoveryCodes: React.FC<{ codes: string[] }> = ({ codes }) => {
    const [copied, setCopied] = useState(false);
    const copy = async () => {
        await copyToClipboard(codes.join('\n'));
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
    };
    return (
        <div className="space-y-3">
            <Alert
                type="warning"
                title="Save your recovery codes"
                message="Store these somewhere safe. Each works once if you lose your authenticator, and they will not be shown again."
            />
            <div
                className="grid grid-cols-2 gap-2 rounded-lg p-4 font-mono text-sm"
                style={{ backgroundColor: 'var(--bg-subtle)', border: '1px solid var(--border)' }}
            >
                {codes.map((c) => (
                    <span key={c} style={{ color: 'var(--text-primary)' }}>
                        {c}
                    </span>
                ))}
            </div>
            <Button variant="outline" size="sm" onClick={copy}>
                {copied ? <CheckIcon className="h-4 w-4 mr-2" /> : <ClipboardDocumentIcon className="h-4 w-4 mr-2" />}
                {copied ? 'Copied' : 'Copy all'}
            </Button>
        </div>
    );
};

// EnrollModal walks enrol → activate → show recovery codes.
const EnrollModal: React.FC<{ isOpen: boolean; onClose: () => void }> = ({ isOpen, onClose }) => {
    const enroll = useEnrollMfa();
    const activate = useActivateMfa();
    const [secret, setSecret] = useState('');
    const [uri, setUri] = useState('');
    const [code, setCode] = useState('');
    const [password, setPassword] = useState('');
    const [codes, setCodes] = useState<string[] | null>(null);
    const [error, setError] = useState('');
    // #2738's sibling: same reasoning as ReauthModal's `submitting` — the activation
    // request's pending state must not be read off a mutation object that outlives
    // this dialog, or a request that never settles leaves "Verify & enable" disabled
    // until the page is reloaded.
    const [submitting, setSubmitting] = useState(false);
    const attempt = React.useRef(0);

    // Begin enrolment the first time the modal opens.
    React.useEffect(() => {
        if (isOpen && !secret && !enroll.isPending && !codes) {
            enroll.mutate(undefined, {
                onSuccess: (d) => {
                    setSecret(d.secret);
                    setUri(d.otpauth_uri);
                },
                onError: (e) => setError(errMessage(e, 'Could not begin enrolment.')),
            });
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [isOpen]);

    const reset = () => {
        attempt.current += 1;
        setSecret('');
        setUri('');
        setCode('');
        setPassword('');
        setCodes(null);
        setError('');
        setSubmitting(false);
        // Clear both mutations' own state too, so neither a wedged enrolment nor a
        // wedged activation survives this dialog.
        enroll.reset();
        activate.reset();
    };
    const close = () => {
        const enrolled = codes !== null;
        reset();
        onClose();
        // #3155: enrolling lifts the session's MFA confinement server-side; re-read the profile
        // (pending_steps) so the app unlocks. Only now, not on activation: the session may be
        // setup-only and end here, and the recovery codes must stay visible until dismissed.
        if (enrolled) {
            void useAuthStore.getState().checkAuth();
        }
    };

    // G28: the recovery codes otherwise stay rendered indefinitely until the user
    // explicitly clicks Done/Cancel — auto-clear (close the modal) on idle, tab
    // backgrounding, or window blur too.
    useAutoClearOnIdle(close, codes !== null);

    const submit = (e: React.SubmitEvent<HTMLFormElement>) => {
        e.preventDefault();
        if (submitting) return;
        attempt.current += 1;
        const mine = attempt.current;
        setError('');
        setSubmitting(true);
        const settle = (fn: () => void) => {
            if (attempt.current !== mine) return;
            setSubmitting(false);
            fn();
        };
        // #2441: the backend re-authenticates the caller with the account
        // password during enrolment (MFAEnabled is still false, so the TOTP
        // step-up branch requireReauth would otherwise take doesn't apply yet)
        // — the code alone was never enough.
        activate.mutate(
            { code, password },
            {
                onSuccess: (newCodes) => settle(() => setCodes(newCodes)),
                onError: (err) => settle(() => setError(errMessage(err, 'Invalid code or password. Try again.'))),
            }
        );
    };

    return (
        <Modal isOpen={isOpen} onClose={close} title="Set up two-factor authentication" size="md">
            {codes ? (
                <div className="space-y-4">
                    <RecoveryCodes codes={codes} />
                    <div className="flex justify-end">
                        <Button onClick={close}>Done</Button>
                    </div>
                </div>
            ) : (
                <form onSubmit={submit} className="space-y-4">
                    {error && <Alert type="error" message={error} />}
                    <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                        Add this key to your authenticator app (Google Authenticator, 1Password, …), then enter the
                        6-digit code it shows.
                    </p>
                    {enroll.isPending && !secret ? (
                        <div className="flex justify-center py-6">
                            <Spinner />
                        </div>
                    ) : (
                        <>
                            <div>
                                <p
                                    className="block text-sm font-medium mb-1"
                                    style={{ color: 'var(--text-secondary)' }}
                                >
                                    Setup key
                                </p>
                                <code
                                    data-testid="mfa-setup-key"
                                    className="block break-all rounded-md p-3 text-sm"
                                    style={{
                                        backgroundColor: 'var(--bg-subtle)',
                                        border: '1px solid var(--border)',
                                        color: 'var(--text-primary)',
                                    }}
                                >
                                    {secret}
                                </code>
                                {uri && /^otpauth:\/\//i.test(uri) && (
                                    <a
                                        href={uri}
                                        className="mt-1 inline-block text-xs"
                                        style={{ color: 'var(--accent-text)' }}
                                    >
                                        Open in authenticator app
                                    </a>
                                )}
                            </div>
                            <Input
                                label="6-digit code"
                                inputMode="numeric"
                                autoComplete="one-time-code"
                                placeholder="123456"
                                value={code}
                                onChange={(e) => setCode(e.target.value)}
                            />
                            <Input
                                label="Account password"
                                type="password"
                                autoComplete="current-password"
                                placeholder="Your current password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                            />
                            <div className="flex justify-end gap-2">
                                <Button type="button" variant="outline" onClick={close}>
                                    Cancel
                                </Button>
                                <Button type="submit" disabled={submitting || code.length < 6 || !password}>
                                    {submitting && <Spinner size="sm" className="mr-2" />}
                                    Verify &amp; enable
                                </Button>
                            </div>
                        </>
                    )}
                </form>
            )}
        </Modal>
    );
};

// ReauthModal collects a current authenticator code and runs a sensitive action
// (disable, or regenerate recovery codes). When the action returns codes, they are
// displayed once.
//
// The field is an authenticator code ONLY, not "code or password", because that is
// what the backend accepts here: internal/core's requireReauth refuses the account
// password alone once a second factor is enrolled, and its one password-accepting
// branch additionally requires a live MFAStepUpPurposeReauth grant, which no web
// login flow mints (an ordinary login mints the restricted-secret-read purpose,
// which that branch explicitly rejects). The old label invited exactly the
// submission the server always refuses — #2738. The label changed; the server check
// did not.
//
// isPending is deliberately LOCAL (submitting) rather than the caller's react-query
// mutation flag, and close() resets the caller's mutation too (onReset). #2738: a
// mutation can stay pending indefinitely — react-query pauses a retry while
// onlineManager reports offline, and a paused mutation's promise never settles — and
// because the mutation object lives in the parent, a pending flag read from it
// survived closing and reopening this dialog, leaving the confirm button disabled
// for the rest of the page's lifetime with no error shown and no request sent. Local
// state plus a reset on close means a wedged request can never outlive the dialog
// that started it.
const ReauthModal: React.FC<{
    isOpen: boolean;
    onClose: () => void;
    onReset: () => void;
    isPaused: boolean;
    title: string;
    confirmLabel: string;
    confirmVariant?: 'default' | 'destructive';
    intro: string;
    run: (proof: { code: string }) => Promise<string[] | void>;
}> = ({ isOpen, onClose, onReset, isPaused, title, confirmLabel, confirmVariant = 'default', intro, run }) => {
    const [code, setCode] = useState('');
    const [codes, setCodes] = useState<string[] | null>(null);
    const [error, setError] = useState('');
    const [submitting, setSubmitting] = useState(false);
    // attempt identifies the in-flight submission. Bumped on every submit AND on
    // every close, so a reply that arrives after the user gave up (or after a paused
    // mutation finally resumes) can never write into a dialog that has moved on.
    const attempt = React.useRef(0);

    const close = () => {
        attempt.current += 1;
        setCode('');
        setCodes(null);
        setError('');
        setSubmitting(false);
        onReset();
        onClose();
    };

    // G28: the recovery codes otherwise stay rendered indefinitely until the user
    // explicitly clicks Done/Cancel — auto-clear (close the modal) on idle, tab
    // backgrounding, or window blur too.
    useAutoClearOnIdle(close, codes !== null);

    const submit = async (e: React.SubmitEvent<HTMLFormElement>) => {
        e.preventDefault();
        if (submitting) return;
        attempt.current += 1;
        const mine = attempt.current;
        setError('');
        setSubmitting(true);
        try {
            const result = await run({ code: code.trim() });
            if (attempt.current !== mine) return;
            if (result && result.length) {
                setCodes(result);
            } else {
                close();
            }
        } catch (err) {
            if (attempt.current !== mine) return;
            setError(errMessage(err, 'That code was not accepted. Try a fresh one from your authenticator app.'));
        } finally {
            // close() (success path) and a superseded attempt both already bumped
            // attempt.current; only the attempt still current clears the flag.
            if (attempt.current === mine) setSubmitting(false);
        }
    };

    return (
        <Modal isOpen={isOpen} onClose={close} title={title} size="md">
            {codes ? (
                <div className="space-y-4">
                    <RecoveryCodes codes={codes} />
                    <div className="flex justify-end">
                        <Button onClick={close}>Done</Button>
                    </div>
                </div>
            ) : (
                <form onSubmit={submit} className="space-y-4">
                    {error && <Alert type="error" message={error} />}
                    {/* #2738: react-query PAUSES a mutation while onlineManager reports
                        offline, and a paused mutation's promise never settles — the
                        in-flight state is real, but without this the dialog said nothing
                        at all, which is what made a stuck spinner read as a crash. */}
                    {submitting && isPaused && (
                        <Alert
                            type="warning"
                            message="Waiting for a network connection — this will be sent as soon as you are back online. Cancel to start over."
                        />
                    )}
                    <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                        {intro}
                    </p>
                    <Input
                        label="Authenticator code"
                        inputMode="numeric"
                        autoComplete="one-time-code"
                        maxLength={6}
                        placeholder="123456"
                        value={code}
                        onChange={(e) => setCode(e.target.value)}
                    />
                    <div className="flex justify-end gap-2">
                        <Button type="button" variant="outline" onClick={close}>
                            Cancel
                        </Button>
                        <Button
                            type="submit"
                            variant={confirmVariant}
                            // Exactly six digits: what internal/core's validateTOTPStep
                            // can ever accept (otp.DigitsSix). Anything else — notably
                            // the account password the old label invited — is refused
                            // here rather than spent as a failed attempt against the
                            // per-account lockout requireReauth feeds.
                            disabled={submitting || !/^\d{6}$/.test(code.trim())}
                        >
                            {submitting && <Spinner size="sm" className="mr-2" />}
                            {confirmLabel}
                        </Button>
                    </div>
                </form>
            )}
        </Modal>
    );
};

// MfaSection is the Profile → Security two-factor block: it shows enable/enrol when
// MFA is off, and status + recovery-code management + disable when it is on.
//
// enrolmentRequired (#2924): the user was sent here by an MFAEnrollmentRequired 403
// (security.require_mfa is on and they have no second factor yet). Say why, and don't
// call the expected 403 on the recovery-code status endpoint "could not load".
export const MfaSection: React.FC<{ enrolmentRequired?: boolean }> = ({ enrolmentRequired = false }) => {
    const { user } = useAuthStore();
    const { data: status, isLoading, isError } = useMfaRecoveryStatus(!userOwesMfaEnrolment(user));
    const disable = useDisableMfa();
    const regenerate = useRegenerateRecoveryCodes();
    const [enrolling, setEnrolling] = useState(false);
    const [regenOpen, setRegenOpen] = useState(false);
    const [disableOpen, setDisableOpen] = useState(false);

    const enabled = (status?.total ?? 0) > 0;
    const remaining = status?.remaining ?? 0;
    const total = status?.total ?? 0;
    const lowCodes = enabled && remaining <= LOW_CODES_THRESHOLD;

    const showEnrolmentBanner = enrolmentRequired && !enabled && !isLoading;

    const enabledButton = enabled ? (
        <Button variant="destructive" size="sm" onClick={() => setDisableOpen(true)}>
            Disable
        </Button>
    ) : (
        <Button size="sm" onClick={() => setEnrolling(true)}>
            Enable
        </Button>
    );

    return (
        <div className="pt-8 border-t" style={{ borderColor: 'var(--border)' }}>
            <h3 className="text-lg font-medium" style={{ color: 'var(--text-primary)' }}>
                Two-Factor Authentication
            </h3>

            {showEnrolmentBanner && (
                <div className="mt-4">
                    <Alert
                        type="warning"
                        title="Set up two-factor authentication to continue"
                        message="Your organisation requires two-factor authentication. Click Enable below and add the key to an authenticator app; the rest of the console unlocks as soon as it is active."
                    />
                </div>
            )}

            <div
                className="mt-4 rounded-lg p-5"
                style={{ backgroundColor: 'var(--bg-subtle)', border: '1px solid var(--border)' }}
            >
                <div className="flex items-center justify-between">
                    <div className="flex items-center">
                        <DevicePhoneMobileIcon className="h-7 w-7 mr-4" style={{ color: 'var(--text-muted)' }} />
                        <div>
                            <h4
                                className="text-sm font-medium flex items-center gap-2"
                                style={{ color: 'var(--text-primary)' }}
                            >
                                Authenticator App
                                {enabled && (
                                    <span
                                        className="text-xs font-medium px-2 py-0.5 rounded-full inline-flex items-center gap-1"
                                        style={{
                                            color: 'var(--accent-text)',
                                            backgroundColor: 'var(--accent-subtle)',
                                        }}
                                    >
                                        <ShieldCheckIcon className="h-3.5 w-3.5" />
                                        Enabled
                                    </span>
                                )}
                            </h4>
                            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                                {enabled
                                    ? `${remaining} of ${total} recovery codes remaining`
                                    : 'Add a time-based one-time code (TOTP) as a second factor at login.'}
                            </p>
                        </div>
                    </div>

                    {isLoading ? <Spinner size="sm" /> : enabledButton}
                </div>

                {isError && !enrolmentRequired && (
                    <p className="mt-3 text-sm" style={{ color: 'var(--text-muted)' }}>
                        Could not load two-factor status.
                    </p>
                )}

                {enabled && (
                    <div
                        className="mt-4 pt-4 flex items-center justify-between"
                        style={{ borderTop: '1px solid var(--border)' }}
                    >
                        <div
                            className="flex items-center gap-2 text-sm"
                            style={{ color: lowCodes ? 'var(--warning-text, #b45309)' : 'var(--text-muted)' }}
                        >
                            {lowCodes && <ExclamationTriangleIcon className="h-4 w-4" />}
                            {lowCodes
                                ? 'You are running low on recovery codes.'
                                : 'Recovery codes let you sign in if you lose your device.'}
                        </div>
                        <Button variant="outline" size="sm" onClick={() => setRegenOpen(true)}>
                            Regenerate codes
                        </Button>
                    </div>
                )}
            </div>

            <EnrollModal isOpen={enrolling} onClose={() => setEnrolling(false)} />

            <ReauthModal
                isOpen={regenOpen}
                onClose={() => setRegenOpen(false)}
                onReset={() => regenerate.reset()}
                isPaused={regenerate.isPaused}
                title="Regenerate recovery codes"
                confirmLabel="Regenerate"
                intro="This replaces all of your existing recovery codes with a new set. Confirm with a current 6-digit code from your authenticator app — your password is not accepted here."
                run={(proof) => regenerate.mutateAsync(proof)}
            />

            <ReauthModal
                isOpen={disableOpen}
                onClose={() => setDisableOpen(false)}
                onReset={() => disable.reset()}
                isPaused={disable.isPaused}
                title="Disable two-factor authentication"
                confirmLabel="Disable 2FA"
                confirmVariant="destructive"
                intro="Your account will be protected by your password only. Confirm with a current 6-digit code from your authenticator app — your password is not accepted here."
                run={async (proof) => {
                    await disable.mutateAsync(proof);
                }}
            />
        </div>
    );
};
