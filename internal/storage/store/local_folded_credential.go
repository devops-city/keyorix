// local_folded_credential.go — the live machine-credential re-check, widened
// to read one secret's node in the same statement (PERF-LEVER2).
//
// On a machine-token cache hit for a secret read, the auth middleware asks for
// the fold by putting a ReadPathPrefetch with a fold target on the request
// (storage.NewReadPathPrefetchFolding). GetMachineIdentityCredentialWithIdentityStateByHash
// then runs ONE statement:
//
//   - the credential and identity-state columns, exactly credentialLookupRawQuery's
//     select list, FROM/JOIN and WHERE, scanned into the same fields in the same order;
//   - LEFT JOIN secret_nodes n on the fold target, plus the node read's select
//     list and joins (readPathPrefetchParts: stamp, trigger proof, roles at the
//     warm entry's scope, generation, and schedule/versions when asked).
//
// The credential comes back to the caller exactly as the plain statement would
// return it, and the caller judges it with the same code at the same point; a
// missing or deleted secret only makes the node columns NULL. Nothing here
// decides anything about the credential.
//
// The node answers are parked on the carrier (ParkNodeStamp) for the machine
// whose credential was read, and only when the node row was found. GetSecret
// takes them for that secret only, once, and serves the warm entry only when
// the parked stamp equals the cached generation, the trigger was proven in this
// statement, and the entry is the one whose scope the roles were read for
// (getCachedSecret). Any other outcome is today's path.
//
// When the fold cannot run (a transaction-scoped store, the node cache off or
// cold for that secret) or the statement fails or finds no credential row, the
// plain credential statement runs instead and its answer is returned. So the
// fold can never turn an error into a cached-snapshot answer: the caller only
// ever sees the plain statement's error.
package store

import (
	"context"
	"database/sql"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// foldedNodeState is the parked node read (PrefetchedNodeStamp.State).
type foldedNodeState struct {
	stamp nodeStampRead
	// entryGeneration is the generation of the warm entry whose scope the
	// roles were read at.
	entryGeneration nodeGeneration
	perm            *storage.PrefetchedPermission
	sched           *storage.PrefetchedScheduleVersion
}

// foldedCredentialSQL returns the folded statement: credentialLookupRawQuery's
// select list, then readPathPrefetchParts' cols on a LEFT JOIN of the target
// node, then its joins. Built once per shape (readPathPrefetchSQLs). Its bind
// order is: the trigger name, the secret id (the LEFT JOIN), the machine id,
// the node's project and environment, the generation key, the secret id
// (schedule/version only) and the token hash.
func foldedCredentialSQL(triggerExpr, genExpr string, wantScheduleVersion bool) string {
	key := readPathPrefetchSQLKey{folded: true, triggerExpr: triggerExpr, genExpr: genExpr, wantScheduleVersion: wantScheduleVersion}
	return cachedReadPathSQL(key, func(p readPathPrefetchParts) string {
		return `SELECT c.id, c.machine_identity_id, c.name, c.token_hash, c.token_prefix,
       c.allowed_c_id_rs, c.last_used_at, c.expires_at, c.revoked, c.created_at,
       c.classification, m.state AS identity_state, ` + p.cols +
			"\nFROM machine_identity_credentials c\nJOIN machine_identities m ON m.id = c.machine_identity_id" +
			"\nLEFT JOIN secret_nodes n ON n.id = ? AND n.deleted_at IS NULL\n" + p.joins +
			"\nWHERE c.token_hash = ?"
	})
}

// foldedCredentialArgs is foldedCredentialSQL's binds, in its bind order.
func foldedCredentialArgs(pf *storage.ReadPathPrefetch, secretID uint, node *models.SecretNode, hash string) []any {
	args := make([]any, 0, 8)
	return append(readPathPrefetchJoinArgs(append(args, SecretNodeCacheEpochTrigger, secretID), pf, secretID, node), hash)
}

// getMachineCredentialFolded runs the folded statement. ok is false when it
// cannot or did not answer (the caller then runs the plain statement); the
// returned node state is nil when the secret's row was not found.
func (ls *LocalStorage) getMachineCredentialFolded(ctx context.Context, hash string, pf *storage.ReadPathPrefetch, secretID uint) (*models.MachineIdentityCredential, string, *foldedNodeState, bool) {
	if ls.rawStmts == nil || !ls.cacheEnabled {
		return nil, "", nil, false
	}
	cached, ok := ls.secretMetaCache.getNode(secretID)
	if !ok || cached.node == nil {
		return nil, "", nil, false
	}
	q := foldedCredentialSQL(nodeTriggerExistsExpr(ls.db), rolePermGenerationExpr(ls.db, "gen"), pf.WantScheduleVersion)
	args := foldedCredentialArgs(pf, secretID, cached.node, hash)
	query := func() (rowScanner, func(), error) {
		if ls.nativeReads != nil {
			// Postgres: the same statement on the native pool (native_reads.go).
			nrows, err := ls.queryNative(ctx, q, args)
			if err != nil {
				return nil, nil, err
			}
			return nrows, nrows.Close, nil
		}
		srows, err := ls.db.WithContext(ctx).Raw(q, args...).Rows()
		if err != nil {
			return nil, nil, err
		}
		return srows, func() { _ = srows.Close() }, nil
	}
	// single_writer: the statement's last answer when the guard vouches for
	// it (local_folded_credential_memo.go); otherwise the statement runs.
	c, identityState, nodeRows, ok := ls.foldedStatement(ctx, q, args, pf.WantScheduleVersion, query)
	if !ok {
		// No credential row (or a failure): the plain statement answers, with
		// its own error.
		return nil, "", nil, false
	}
	if nodeRows == nil {
		return c, identityState, nil, true
	}
	stamp, perm, sched := readPathPrefetchFromRows(pf, secretID, cached.node, nodeRows)
	return c, identityState, &foldedNodeState{stamp: stamp, entryGeneration: cached.generation, perm: perm, sched: sched}, true
}

// scanFoldedCredentialRows reads every row of the folded statement: the
// credential (the same on every row) and the node rows, nil when the LEFT JOIN
// found no node. ok is false on a scan failure or when there was no row.
func scanFoldedCredentialRows(rows rowScanner, wantScheduleVersion bool) (*models.MachineIdentityCredential, string, []readPathPrefetchRow, bool) {
	var (
		c             models.MachineIdentityCredential
		identityState string
		nodeRows      []readPathPrefetchRow
		nodeFound     bool
		n             int
	)
	for rows.Next() {
		var r readPathPrefetchRow
		var tail readPathPrefetchTail
		// Times through sql.NullTime, as the plain statement scans them
		// (assignCredentialTimes); the node columns are NULL when the
		// LEFT JOIN found no node.
		var lastUsedAt, expiresAt, createdAt sql.NullTime
		var cacheEpoch sql.NullInt64
		var trigger sql.NullBool
		dest := tail.dest([]any{
			&c.ID, &c.MachineIdentityID, &c.Name, &c.TokenHash, &c.TokenPrefix,
			&c.AllowedCIDRs, &lastUsedAt, &expiresAt, &c.Revoked, &createdAt,
			&c.Classification, &identityState,
			&cacheEpoch, &trigger,
		}, &r, wantScheduleVersion)
		if err := rows.Scan(dest...); err != nil {
			return nil, "", nil, false
		}
		if err := assignCredentialTimes(&c, lastUsedAt, expiresAt, createdAt); err != nil {
			return nil, "", nil, false
		}
		tail.finish(&r)
		n++
		if cacheEpoch.Valid {
			nodeFound = true
			r.CacheEpoch = cacheEpoch.Int64
			r.TriggerPresent = trigger.Valid && trigger.Bool
			nodeRows = append(nodeRows, r)
		}
	}
	if rows.Err() != nil || n == 0 {
		return nil, "", nil, false
	}
	if !nodeFound {
		return &c, identityState, nil, true
	}
	return &c, identityState, nodeRows, true
}

// foldedCredentialLookup runs the fold the request asked for, if any. handled
// is false when the plain statement must answer.
func (ls *LocalStorage) foldedCredentialLookup(ctx context.Context, hash string) (*models.MachineIdentityCredential, string, bool) {
	pf := storage.ReadPathPrefetchFrom(ctx)
	if pf == nil {
		return nil, "", false
	}
	secretID := pf.TakeFoldTarget()
	if secretID == 0 {
		return nil, "", false
	}
	cred, state, node, ok := ls.getMachineCredentialFolded(ctx, hash, pf, secretID)
	if !ok {
		return nil, "", false
	}
	// Parked only for the machine the carrier was built for, and only if it is
	// the machine this credential belongs to.
	if node != nil && cred.MachineIdentityID == pf.MachineID {
		pf.ParkNodeStamp(&storage.PrefetchedNodeStamp{SecretID: secretID, MachineID: pf.MachineID, State: node})
	}
	return cred, state, true
}

// takeFoldedNodeHit serves the warm entry from the parked node read when it
// confirms the entry (see the file header). Called by getCachedSecret.
func takeFoldedNodeHit(pf *storage.ReadPathPrefetch, id uint, cached secretNodeCacheEntry) bool {
	ns := pf.TakeNodeStamp(id, pf.MachineID)
	if ns == nil {
		return false
	}
	st, ok := ns.State.(*foldedNodeState)
	if !ok || !st.stamp.found || !st.stamp.trusted ||
		st.stamp.generation != cached.generation || st.entryGeneration != cached.generation {
		return false
	}
	pf.Park(st.perm, st.sched)
	return true
}
