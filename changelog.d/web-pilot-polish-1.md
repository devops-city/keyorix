### Changed
- **In-app confirmations replace native `window.confirm`.** Transfer ownership, secret version rollback, machine-identity suspend/revoke, machine-token revoke, dynamic-secret lease revoke (single, retry and all) and project-member removal now ask through the app's own dialog (`components/ui/useConfirm`) with the same wording, instead of a browser dialog (#3153). A structure test (`noNativeConfirm.test.ts`, INV-WEB-no-native-confirm) fails on any new native `confirm`.

### Testing
- **Web regression tests for #3153, #3142 and #2450.** A contrast guard for the revoke dialog's title in both themes, tests recording that Check Drift, Rotation Plan and the Sharing nav stay offered to a read-only role because the server answers them, and a reveal test showing the secret page never decodes a field the versions endpoint does not return.
