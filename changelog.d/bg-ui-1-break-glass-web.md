### Added
- **Break-glass in the web UI (#3148).** Each project has a new **Break-glass** tab. A member requests emergency access with a justification and a lifetime and sees their own activations with status and a live countdown to expiry. Anyone who holds `roles.read` at the project sees every activation (who, when, justification, status), and `roles.assign` adds **Revoke** behind a confirm dialog. A server with break-glass off says "Break-glass is not enabled on this server", a project that requires MFA surfaces the server's MFA refusal with a link to enrolment, and a non-member gets a refusal instead of a list. The server still decides everything; the tab never caches one user's activations for another.

### Documentation
- **Golden path: break-glass on the web.** `docs/demo/GOLDEN-PATH.md` describes the web path next to the CLI commands.

### Testing
- **Real-backend spec for break-glass.** `web/e2e/real/break-glass.spec.ts` drives activate, admin sees it, admin revokes, member sees revoked, and an outsider gets a 403. `scripts/e2e/web-real-smoke.sh` boots the group of a spec carrying `// e2e-server: break_glass=true` with break-glass enabled.
