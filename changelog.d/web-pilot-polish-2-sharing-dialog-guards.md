### Changed
- **Sharing page: Edit and Revoke are disabled on shares you do not own.** The server only lets a secret's owner (who is still a project member) change or revoke its shares, and refuses admins and recipients; the page now says so on the row ("Only the secret's owner can change or revoke its shares") instead of offering an action that ends in a 403. The bulk-select checkbox follows the same rule. Server enforcement is unchanged.

### Fixed
- **Roles modal: the permission group headings are readable.** They used the muted text colour (2.5:1 in the light theme, 3.5:1 in the dark one); they now use the secondary text colour.

### Testing
- **Dialog contrast guard covers every modal and dialog in the web app.** `dialogContrast.test.tsx` inventories all dialog surfaces (new ones must be registered), renders the shared dialogs, the Sharing revoke dialog, the session-timeout warning and the command palette in both themes, and audits the headings drawn inside modals; planted dialogs (title colour equal to its background, the #3153 fixed dark title) fail it. The per-site confirm tests now assert the API is called exactly once.
