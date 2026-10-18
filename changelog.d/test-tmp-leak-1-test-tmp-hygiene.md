### Testing

- Test runs no longer leave temp files behind: `server` removes its ~99 MB shared `keyorix-server` test binary directory and `internal/auditverify` removes its 1M-row bench fixture when the package's tests finish. A new static guard (`TestNoTestLeaksTempResources`) fails when a `*_test.go` declaration calls `os.MkdirTemp`/`os.CreateTemp` without cleanup (TEST-TMP-LEAK-1).
