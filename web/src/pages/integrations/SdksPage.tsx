import React, { useState } from 'react';
import { Link } from 'react-router';
import { ClipboardDocumentIcon, CheckIcon } from '@heroicons/react/24/outline';
import { copyToClipboard } from '../../utils';
import { ROUTES } from '../../constants';

interface SectionCardProps {
    title: string;
    children: React.ReactNode;
}

const SectionCard: React.FC<SectionCardProps> = ({ title, children }) => (
    <div
        className="rounded-xl border overflow-hidden mb-6"
        style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
    >
        <div className="px-6 py-4 border-b" style={{ borderColor: 'var(--border)' }}>
            <h2 className="text-sm font-semibold uppercase tracking-widest" style={{ color: 'var(--text-muted)' }}>
                {title}
            </h2>
        </div>
        <div className="px-6 py-5 space-y-4">{children}</div>
    </div>
);

const CodeBlock: React.FC<{ code: string }> = ({ code }) => {
    const [copied, setCopied] = useState(false);

    const copy = async () => {
        await copyToClipboard(code);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
    };

    return (
        <div className="relative group">
            <pre
                className="text-xs rounded-lg p-3 overflow-x-auto"
                style={{
                    backgroundColor: 'var(--bg-app)',
                    border: '1px solid var(--border)',
                    color: 'var(--text-primary)',
                }}
            >
                <code>{code}</code>
            </pre>
            <button
                type="button"
                onClick={copy}
                aria-label="Copy to clipboard"
                className="absolute top-2 right-2 p-1.5 rounded-md transition-colors"
                style={{ backgroundColor: 'var(--bg-surface)', color: 'var(--text-muted)' }}
            >
                {copied ? <CheckIcon className="h-4 w-4" /> : <ClipboardDocumentIcon className="h-4 w-4" />}
            </button>
        </div>
    );
};

interface SdkExampleProps {
    language: string;
    install: string;
    snippet: string;
}

const SdkExample: React.FC<SdkExampleProps> = ({ language, install, snippet }) => (
    <div>
        <h3 className="text-sm font-medium mb-2" style={{ color: 'var(--text-primary)' }}>
            {language}
        </h3>
        <div className="space-y-2">
            <CodeBlock code={install} />
            <CodeBlock code={snippet} />
        </div>
    </div>
);

export const SdksPage: React.FC = () => (
    <div className="max-w-2xl mx-auto px-6 py-8">
        <div className="mb-8">
            <h1 className="text-2xl font-bold tracking-tight" style={{ color: 'var(--text-primary)' }}>
                SDKs & CLI
            </h1>
            <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                Fetch secrets directly from your applications and scripts — zero hardcoded credentials.
            </p>
        </div>

        <SectionCard title="CLI">
            <div>
                <p className="text-sm mb-2" style={{ color: 'var(--text-secondary)' }}>
                    Install
                </p>
                <CodeBlock code="curl -L https://raw.githubusercontent.com/keyorixhq/keyorix/main/install.sh | sh" />
            </div>
            <div>
                <p className="text-sm mb-2" style={{ color: 'var(--text-secondary)' }}>
                    Log in to your server (the password is asked for at a hidden prompt, never put on the command line)
                </p>
                <CodeBlock code="keyorix login --server http://your-server:8080 --username admin" />
            </div>
            <div>
                <p className="text-sm mb-2" style={{ color: 'var(--text-secondary)' }}>
                    Create a secret from a file (or add --interactive for a hidden prompt) and run your app with it
                    injected as an environment variable
                </p>
                <CodeBlock
                    code={
                        'keyorix secret create --name db-password --from-file ./db-password.txt\nkeyorix run --env production --var DATABASE_URL=db-password -- node app.js'
                    }
                />
            </div>
            <div
                className="rounded-lg p-3 text-sm"
                style={{ backgroundColor: 'var(--accent-subtle)', color: 'var(--text-secondary)' }}
            >
                Prefer not to use your account password for the CLI or SDKs? Create a{' '}
                <Link to={ROUTES.PROFILE} className="font-medium underline" style={{ color: 'var(--accent-text)' }}>
                    Personal Access Token
                </Link>{' '}
                from Profile → API Tokens and pass it instead — it can be scoped and revoked independently of your
                login.
            </div>
        </SectionCard>

        <SectionCard title="SDKs">
            <SdkExample
                language="Go"
                install="go get github.com/keyorixhq/keyorix-go"
                snippet={
                    'token, _ := keyorix.Login(ctx, "http://your-server:8080", "admin", "password")\n' +
                    'client := keyorix.New("http://your-server:8080", token)\n' +
                    'dbPassword, _ := client.GetSecret(ctx, "db-password", "production")'
                }
            />
            <SdkExample
                language="Python"
                install="pip install keyorix"
                snippet={
                    'token = keyorix.login("http://your-server:8080", "admin", "password")\n' +
                    'client = keyorix.Client("http://your-server:8080", token)\n' +
                    'db_password = client.get_secret("db-password", "production")'
                }
            />
            <SdkExample
                language="Node.js"
                install="npm install keyorix"
                snippet={
                    'const token = await keyorix.login("http://your-server:8080", "admin", "password");\n' +
                    'const client = new keyorix.Client("http://your-server:8080", token);\n' +
                    'const dbPassword = await client.getSecret("db-password", "production");'
                }
            />
        </SectionCard>

        <SectionCard title="API reference">
            <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                Every SDK and the CLI talk to the same REST API. Browse the full, interactive reference on your server
                at{' '}
                <a
                    href="/swagger"
                    target="_blank"
                    rel="noreferrer"
                    className="font-medium underline"
                    style={{ color: 'var(--accent-text)' }}
                >
                    /swagger
                </a>
                {'.'}
            </p>
        </SectionCard>
    </div>
);
