package http

import "github.com/keyorixhq/keyorix/internal/storage/store"

// #2685: every WithNamedLock acquisition this package's test suite makes
// through a real LocalStorage panics if it violates storage.NamedLockOrder,
// as internal/core's does (internal/core/named_lock_order_enable_test.go).
func init() { store.EnableNamedLockOrderCheckForTesting() }
