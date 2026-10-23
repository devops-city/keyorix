### Documentation
- **CONFIGURATION.md key derivation.** The audit-checkpoint and evidence-pack signing keys are described as KEK-derived (as in the code), not DEK-derived.

### Testing
- **Renamed-settings table cannot drift.** `TestConfigurationDoc_ListsEveryDeprecatedAlias` derives the alias list from `config.DeprecatedSettingAliasPaths()` and requires each pair as a row in docs/CONFIGURATION.md.
