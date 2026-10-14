### Security
- **A deleted machine credential or personal access token is refused immediately on every replica.** Previously a credential row removed after it had authenticated could keep working from the auth cache on other replicas for up to 30 seconds; it is now refused like a revoked token, with the same response as an unknown token.
