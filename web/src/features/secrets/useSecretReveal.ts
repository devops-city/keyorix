import { useState } from 'react';
import { apiErrorMessage } from '../../services/client';
import { secretsApi } from '../../services/secrets';
import { Secret } from '../../types';
import { copyToClipboard } from '../../utils';

export const useSecretReveal = () => {
    const [copyingSecretId, setCopyingSecretId] = useState<number | null>(null);
    const [copiedSecretId, setCopiedSecretId] = useState<number | null>(null);
    const [copyErrorId, setCopyErrorId] = useState<number | null>(null);
    // Why the last copy failed, e.g. the server's "secret has expired; ..." (ERRMAP-1).
    const [copyError, setCopyError] = useState<string | null>(null);

    const handleCopySecretValue = async (secret: Secret) => {
        setCopyingSecretId(secret.id);
        setCopyErrorId(null);
        setCopyError(null);
        try {
            // #2450: GET .../versions never carries a value field (it's version
            // METADATA only) -- the actual plaintext comes from
            // secretsApi.getValue (GET /secrets/{id}?include_value=true).
            const value = await secretsApi.getValue(secret.id);
            await copyToClipboard(value);
            setCopiedSecretId(secret.id);
            setTimeout(() => setCopiedSecretId(null), 2000);
        } catch (err) {
            setCopyErrorId(secret.id);
            setCopyError(apiErrorMessage(err, 'The secret value could not be copied.'));
            // Long enough to read the reason in the button's tooltip.
            setTimeout(() => {
                setCopyErrorId(null);
                setCopyError(null);
            }, 6000);
        } finally {
            setCopyingSecretId(null);
        }
    };

    return { copyingSecretId, copiedSecretId, copyErrorId, copyError, handleCopySecretValue };
};
