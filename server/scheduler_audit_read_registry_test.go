package main

// scheduler_audit_read_registry_test.go — AUDIT-READER-HYGIENE-1 item 3: every
// scheduler job that reads an audit-sized table (audit_events,
// secret_access_logs) declares what bounds that read.
//
// A job that re-reads audit history on every run costs O(history) per tick and,
// on SQLite, competes with every concurrent write for as long as it reads (the
// recover_admin_alert defect, #3371). The registry below lists each such job
// with its bound; TestSchedulerAuditReads_EveryJobThatReadsAnAuditTableDeclaresItsBound
// derives the set of jobs that can reach a read of one of those tables from the
// code (scheduler_audit_reader_analysis_test.go) and fails when:
//   - a job reaches such a read and has no entry (a new reader, or an existing
//     job that started reading one);
//   - an entry names tables other than the ones the job reaches, or a job that
//     reaches none, or a job that no longer exists (a stale entry);
//   - an entry's bound is not one of the declared kinds.
//
// One file per entry: scheduler_audit_read_entry_<job>_test.go, calling
// registerSchedulerAuditRead from init(). See REGISTRY-ENTRIES.md.

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
)

// auditReadBoundKind is how a job keeps one run's audit read from growing with
// the table's history.
type auditReadBoundKind string

const (
	// boundHighWaterMark: a persisted mark of the last row examined; a run
	// reads only rows above it (and a catch-up walks in id windows).
	boundHighWaterMark auditReadBoundKind = "high-water mark"
	// boundTimeWindow: an indexed time range (event_time >= now - window).
	boundTimeWindow auditReadBoundKind = "time window"
	// boundIDWindow: an id range per run (a segment, a tail after a certified
	// head), read in bounded statements.
	boundIDWindow auditReadBoundKind = "id window"
	// boundConditionalFullWalk: in a configuration named in the entry the job
	// walks the whole table once per run, in bounded statements (no snapshot
	// held across the walk, audit_long_reader_snapshot_test.go). The entry
	// says which configuration and why that is accepted.
	boundConditionalFullWalk auditReadBoundKind = "full walk, conditional"
)

var knownAuditReadBoundKinds = map[auditReadBoundKind]bool{
	boundHighWaterMark: true, boundTimeWindow: true, boundIDWindow: true, boundConditionalFullWalk: true,
}

// schedulerAuditRead is one registry entry.
type schedulerAuditRead struct {
	// Job is the runScheduler/runSchedulerAfter name.
	Job string
	// Tables are the audit-sized tables the job reaches a read of; must equal
	// the derived set.
	Tables []string
	// Bounds: at least one kind; every read the job reaches is covered by one.
	Bounds []auditReadBoundKind
	// Why states, per read, what bounds it (and for a conditional full walk,
	// when it happens).
	Why string
}

var (
	schedulerAuditReadsMu sync.Mutex
	schedulerAuditReads   = map[string]schedulerAuditRead{}
)

// registerSchedulerAuditRead adds one entry; a duplicate job panics at init.
func registerSchedulerAuditRead(e schedulerAuditRead) {
	schedulerAuditReadsMu.Lock()
	defer schedulerAuditReadsMu.Unlock()
	if _, dup := schedulerAuditReads[e.Job]; dup {
		panic(fmt.Sprintf("duplicate schedulerAuditRead entry for job %q", e.Job))
	}
	schedulerAuditReads[e.Job] = e
}

// auditAppendPathReads are reads of audit_events inside the audit append path
// itself: every job that writes an audit event reaches them. Each reads the
// chain head (or the few rows before it) with ORDER BY id DESC LIMIT n, or
// issues no query at all, so they are O(1) in the table's size. Owned by the
// audit write path (OPT-AUDIT-RT-1), not by any job; each name must still be a
// derived reader, or the guard reports it stale.
var auditAppendPathReads = map[string]string{
	"LocalStorage).auditEventsTable":       "GORM DryRun: resolves the table name, issues no query",
	"LocalStorage).commitBatchAttemptTx$1": "chain head: SELECT entry_hash ... ORDER BY id DESC LIMIT 1, under the append lock",
	"LocalStorage).logAuditEventDirect$1":  "chain head: SELECT entry_hash ... ORDER BY id DESC LIMIT 1, under the append lock",
	"LocalStorage).runAuditPipeline":       "pipelined chain head: SELECT id, entry_hash ... ORDER BY id DESC LIMIT 1",
}

// TestSchedulerAuditReads_EveryJobThatReadsAnAuditTableDeclaresItsBound is the
// guard described in this file's header.
func TestSchedulerAuditReads_EveryJobThatReadsAnAuditTableDeclaresItsBound(t *testing.T) {
	a := loadAuditReadAnalysis(t)

	// The derivation must see the readers it exists to see, or every check
	// below passes vacuously.
	derived := map[string]bool{}
	for fn := range a.readers {
		derived[readerName(fn)] = true
	}
	for _, must := range []string{
		"LocalStorage).VerifyAuditChainSegment", "LocalStorage).GetAuditLogs",
		"LocalStorage).ListSecretAccessLogs", "LocalStorage).lastUserActivityByEventTypes",
	} {
		if !derived[must] {
			t.Errorf("the reader derivation no longer finds %s: the guard would be vacuous", must)
		}
	}
	for name := range auditAppendPathReads {
		if !derived[name] {
			t.Errorf("auditAppendPathReads entry %s is not a derived audit reader any more: remove it", name)
		}
	}
	if len(a.jobs) < 15 {
		t.Fatalf("found only %d scheduler jobs: the job discovery is broken", len(a.jobs))
	}

	jobs := map[string]bool{}
	for _, j := range a.jobs {
		if jobs[j.name] {
			t.Errorf("scheduler job %q is started twice", j.name)
		}
		jobs[j.name] = true
		tables := map[string]bool{}
		var readers []string
		for r, ts := range a.reached[j.name] {
			if _, ok := auditAppendPathReads[r]; ok {
				continue
			}
			readers = append(readers, r)
			for _, tb := range ts {
				tables[tb] = true
			}
		}
		sort.Strings(readers)
		got := sortedKeys(tables)
		e, ok := schedulerAuditReads[j.name]
		switch {
		case len(got) == 0 && ok:
			t.Errorf("scheduler job %q (%s) reaches no audit-sized read any more: remove its schedulerAuditRead entry", j.name, j.pos)
		case len(got) == 0:
		case !ok:
			path := a.paths[j.name][readers[0]]
			t.Errorf("scheduler job %q (%s) reads %v and has no schedulerAuditRead entry declaring its bound.\n"+
				"Add scheduler_audit_read_entry_%s_test.go (see REGISTRY-ENTRIES.md). Readers reached: %v\nOne path:\n  %s",
				j.name, j.pos, got, j.name, readers, strings.Join(path, "\n  "))
		default:
			want := append([]string(nil), e.Tables...)
			sort.Strings(want)
			if strings.Join(want, ",") != strings.Join(got, ",") {
				t.Errorf("scheduler job %q: entry declares tables %v, the job reaches reads of %v (via %v)", j.name, want, got, readers)
			}
			checkAuditReadEntry(t, e)
			t.Logf("%s: %v bounded by %v (readers %v)", j.name, got, e.Bounds, readers)
		}
	}
	for job := range schedulerAuditReads {
		if !jobs[job] {
			t.Errorf("schedulerAuditRead entry for %q names no runScheduler/runSchedulerAfter job: remove it", job)
		}
	}
}

func checkAuditReadEntry(t *testing.T, e schedulerAuditRead) {
	t.Helper()
	if len(e.Bounds) == 0 {
		t.Errorf("entry %q declares no bound", e.Job)
	}
	for _, b := range e.Bounds {
		if !knownAuditReadBoundKinds[b] {
			t.Errorf("entry %q: unknown bound kind %q", e.Job, b)
		}
	}
	if strings.TrimSpace(e.Why) == "" {
		t.Errorf("entry %q: Why must say what bounds each read", e.Job)
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
