// local_folded_credential_memo.go — storage.database.single_writer's
// authoritative read path (docs/specs/single-writer-cache.md §1.5).
//
// On a warm machine-token secret read the folded credential statement
// (local_folded_credential.go) is the one statement the request path runs
// besides the audit write: it confirms the credential and its identity state,
// the node stamp, the machine's roles at the node's scope, the role->permission
// generation and the schedule/versions state. Every table it reads is fenced
// (TestFoldedCredentialSQL_ReadsOnlyFencedTables), so in a single-writer server
// its answer can change only through a write this process makes (seen by the
// tracker: the generation moves) or one the fence refused. While the guard is
// authoritative, this memo serves the statement's last answer for the same
// text and binds instead of running it again.
//
// Nothing about any decision moves: the memo returns the same scanned rows
// the statement returned, and every caller judges them with the same code
// (revoked / expiry against the request's clock / identity state in
// CurrentMachineTokenRestriction, the node-stamp confirmation, the role and
// generation reads, the schedule window). The statement reads no clock; every
// time-dependent check is evaluated on each request in Go.
//
// Fail closed: no authority, a lapsed lease, a write in flight or finished
// since the fill, or an entry older than foldMemoTTL means the statement runs.
// A fill that overlapped any write is not stored.
package store

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/keyorixhq/keyorix/internal/solewriter/swstate"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	foldMemoMax = 1 << 15
	// foldMemoTTL bounds how long an answer can sit in memory (an
	// exposure/memory bound, not a correctness one).
	foldMemoTTL = 5 * time.Minute
)

type foldMemoEntry struct {
	gen      uint64
	storedAt time.Time
	cred     models.MachineIdentityCredential
	state    string
	nodeRows []readPathPrefetchRow
	hasNode  bool
}

type foldMemo struct {
	mu      sync.Mutex
	entries map[string]foldMemoEntry
}

func newFoldMemo() *foldMemo { return &foldMemo{entries: map[string]foldMemoEntry{}} }

func foldMemoKey(q string, args []any) string {
	var b strings.Builder
	b.WriteString(q)
	for _, a := range args {
		b.WriteByte(0)
		fmt.Fprint(&b, a)
	}
	return b.String()
}

func (m *foldMemo) get(key string, now time.Time) (foldMemoEntry, bool) {
	if m == nil {
		return foldMemoEntry{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[key]
	if ok && now.Sub(e.storedAt) >= foldMemoTTL {
		delete(m.entries, key)
		return foldMemoEntry{}, false
	}
	return e, ok
}

func (m *foldMemo) set(key string, e foldMemoEntry) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.entries[key]; !ok && len(m.entries) >= foldMemoMax {
		for k := range m.entries { // drop an arbitrary eighth
			if len(m.entries) < foldMemoMax-foldMemoMax/8 {
				break
			}
			delete(m.entries, k)
		}
	}
	m.entries[key] = e
}

// foldedStatement returns the folded statement's scanned answer: from the
// memo when the single-writer guard vouches for it, otherwise by running
// query (and memoizing the result when the guard allows).
func (ls *LocalStorage) foldedStatement(ctx context.Context, q string, args []any, wantScheduleVersion bool,
	query func() (rowScanner, func(), error),
) (*models.MachineIdentityCredential, string, []readPathPrefetchRow, bool) {
	auth := swstate.Get()
	if auth == nil || !auth.Authoritative() || ls.foldMemo == nil {
		return runFoldedStatement(query, wantScheduleVersion)
	}
	key := foldMemoKey(q, args)
	now := time.Now()
	if e, ok := ls.foldMemo.get(key, now); ok && auth.Valid(e.gen) {
		c := e.cred // a copy per request
		var rows []readPathPrefetchRow
		if e.hasNode {
			rows = append([]readPathPrefetchRow(nil), e.nodeRows...)
		}
		return &c, e.state, rows, true
	}
	fill := auth.BeginFill()
	c, state, rows, ok := runFoldedStatement(query, wantScheduleVersion)
	if ok && fill.Store() {
		ls.foldMemo.set(key, foldMemoEntry{gen: fill.Gen(), storedAt: now, cred: *c, state: state,
			nodeRows: append([]readPathPrefetchRow(nil), rows...), hasNode: rows != nil})
	}
	return c, state, rows, ok
}

func runFoldedStatement(query func() (rowScanner, func(), error), wantScheduleVersion bool) (*models.MachineIdentityCredential, string, []readPathPrefetchRow, bool) {
	rows, closeRows, err := query()
	if err != nil {
		return nil, "", nil, false
	}
	defer closeRows()
	return scanFoldedCredentialRows(rows, wantScheduleVersion)
}

// FoldMemoLenForTest is the number of memoized answers.
func (ls *LocalStorage) FoldMemoLenForTest() int {
	if ls.foldMemo == nil {
		return 0
	}
	ls.foldMemo.mu.Lock()
	defer ls.foldMemo.mu.Unlock()
	return len(ls.foldMemo.entries)
}
