package main

import (
	"log"
	"os"
)

// Process-wide advisory locks whose loss ends the server (fail closed). Each
// guards the whole process, not one critical section: from the moment one is
// gone, something it excludes (an admin command, a second single-writer
// server) can start beside this one, so serving on would run unguarded. A
// lock held for one critical section (WithNamedLock, WithSchedulerLock, ...)
// is not here: its holder's context is cancelled with
// store.ErrAdvisoryLockLost and only that section stops.
const (
	lostPresenceLock    = "the server-presence lock"
	lostSoleWriterLock  = "the single_writer holder lock"
	lostLockShutdownMsg = "ERROR: %s was lost (its database connection died); shutting down so %s cannot run beside this server"
)

// awaitShutdown blocks until a shutdown signal arrives or one of the
// process-wide locks is found lost, and returns which lock was lost ("" for a
// signal). A nil channel never fires (no such lock: SQLite, single_writer
// off). The caller then shuts down gracefully, and exits 1 when a lock was
// lost so the supervisor restarts the process, which takes the lock again or
// refuses to start while its holder runs.
func awaitShutdown(sig <-chan os.Signal, presenceLost, soleWriterLost <-chan struct{}) (lost string) {
	select {
	case <-sig:
		log.Println("Shutdown signal received, gracefully shutting down...")
		return ""
	case <-presenceLost:
		log.Printf(lostLockShutdownMsg, lostPresenceLock, "an admin command")
		return lostPresenceLock
	case <-soleWriterLost:
		log.Printf(lostLockShutdownMsg, lostSoleWriterLock, "a second single-writer server")
		return lostSoleWriterLock
	}
}
