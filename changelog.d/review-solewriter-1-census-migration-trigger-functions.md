### Security

- `storage.database.single_writer`: the fence census now also covers the functions run by the store's own triggers on the security tables (role-permission generation, secret-node cache epoch and suspend marker, audit retention anchor). Replacing one of them, even with an identical definition, makes the server stop trusting its caches within one poll, as replacing a fence function already did.
