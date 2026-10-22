### Testing

- A structural guard (`cache_publish_sites_guard_test.go`) fails when a function publishes into a read-path cache (secret metadata, role-permission, folded-credential memo) without being registered alongside the test that proves its generation stamp is read before the data (the unfinished part of GUARD-6).
