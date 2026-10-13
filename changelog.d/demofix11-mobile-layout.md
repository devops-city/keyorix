### Fixed
- **Main pages no longer scroll sideways at phone width (#3154).** At 390 px the project tab strip, the My Account tab strip, the secret-expiry tabs, the User Management header buttons and the access-review campaign header pushed the whole page wider than the screen (up to 478 px). The tab strips now scroll inside themselves and the two headers wrap.

### Testing
- **`web/e2e/real/mobile-layout.spec.ts`** drives the real UI at 390x844 over the main demo routes and fails when the document scrolls horizontally, naming the elements that stick out (red before this change, green after).
