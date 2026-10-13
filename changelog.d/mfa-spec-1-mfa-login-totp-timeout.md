### Testing
- **Fixed a ~1/3 flake in the real-backend `mfa-login.spec.ts` MFA-login test (#2442).** The test waits up to one full 30s TOTP step for a code the anti-replay counter will accept, which does not fit Playwright's 30s default test timeout; it now has an explicit 90s budget. The anti-replay wait and assertions are unchanged.
