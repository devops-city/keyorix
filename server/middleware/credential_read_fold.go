// credential_read_fold.go — on a machine-token cache hit for
// GET /api/v1/secrets/{id}, ask the live credential re-check (INV-MW-02) to
// read that secret's node in the same statement (PERF-LEVER2; storage side:
// internal/storage/store/local_folded_credential.go).
//
// Nothing about the credential verdict moves: serveAuthCacheHit still calls
// CurrentMachineTokenRestriction at the same point, which judges the returned
// credential with the same code, and the deny/evict and CIDR branches below it
// are unchanged. The fold only changes which statement the storage runs and
// parks the node answers for the scoped-permission gate's GetSecret.
//
// The gate: a fold is asked for only when THIS replica has served THIS machine
// a successful read of THIS secret within validTokenTTL (foldMarks). So what
// the re-check runs for a token, a revoked one included, depends only on that
// principal's own history here, never on whether the secret exists or on other
// principals' traffic warming the node cache. An unknown token never reaches
// serveAuthCacheHit at all.
//
// The mark is necessary, not sufficient: the storage side also needs the secret's
// node in THIS replica's node cache (getMachineCredentialFolded's
// secretMetaCache.getNode, internal/storage/store/local_folded_credential.go),
// and falls back to the plain re-check when it is absent. So whether a marked
// read folds can depend on that cache state (an eviction, or another principal's
// write having invalidated the entry). REVIEW-LEVER2 accepted this: the folded
// and plain statements differ by sub-millisecond, the response is identical
// either way (TestFoldedCredentialCheck_RefusesExactlyAsUnfolded), and the
// caller is a principal that already read this secret here. No behaviour hangs
// on it.
package middleware

import (
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// secretReadPath is the one route folded. Anything else, including a trailing
// slash or a non-numeric id, is not.
var secretReadPath = regexp.MustCompile(`^/api/v1/secrets/([0-9]{1,10})$`)

// credentialReadFoldOff turns the fold off (tests compare both modes).
var credentialReadFoldOff atomic.Bool

// SetCredentialReadFoldForTest turns the fold on or off and returns a function
// restoring the previous setting.
func SetCredentialReadFoldForTest(enabled bool) (restore func()) {
	prev := credentialReadFoldOff.Swap(!enabled)
	return func() { credentialReadFoldOff.Store(prev) }
}

// ResetCredentialReadFoldMarksForTest forgets every (machine, secret) mark.
func ResetCredentialReadFoldMarksForTest() { foldMarks.reset() }

// secretReadPathID returns the secret id of a GET /api/v1/secrets/{id} request,
// parsed as scopePathUint parses it.
func secretReadPathID(r *http.Request) (uint, bool) {
	if r.Method != http.MethodGet {
		return 0, false
	}
	m := secretReadPath.FindStringSubmatch(r.URL.Path)
	if m == nil {
		return 0, false
	}
	v, err := strconv.ParseUint(m[1], 10, 32)
	if err != nil || v == 0 {
		return 0, false
	}
	return uint(v), true
}

type foldMarkKey struct{ machine, secret uint }

// foldMarkSet is a bounded set of (machine, secret) marks, each valid for
// validTokenTTL after the read that set it.
type foldMarkSet struct {
	mu    sync.Mutex
	marks map[foldMarkKey]time.Time
}

const foldMarkMax = 1 << 16

var foldMarks = &foldMarkSet{marks: map[foldMarkKey]time.Time{}}

func (s *foldMarkSet) has(k foldMarkKey, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.marks[k]
	if ok && !now.Before(exp) {
		delete(s.marks, k)
		return false
	}
	return ok
}

func (s *foldMarkSet) add(k foldMarkKey, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.marks[k]; !ok && len(s.marks) >= foldMarkMax {
		for mk, exp := range s.marks {
			if !now.Before(exp) {
				delete(s.marks, mk)
			}
		}
		// Still full: drop an arbitrary eighth. A dropped mark only means the
		// next read of that secret is not folded.
		for mk := range s.marks {
			if len(s.marks) < foldMarkMax-foldMarkMax/8 {
				break
			}
			delete(s.marks, mk)
		}
	}
	s.marks[k] = now.Add(validTokenTTL)
}

func (s *foldMarkSet) reset() {
	s.mu.Lock()
	s.marks = map[foldMarkKey]time.Time{}
	s.mu.Unlock()
}

// credentialReadFoldTarget reports whether this cache-hit request may fold,
// and for which secret.
func credentialReadFoldTarget(r *http.Request, machineID uint) (uint, bool) {
	if credentialReadFoldOff.Load() {
		return 0, false
	}
	id, ok := secretReadPathID(r)
	if !ok || !foldMarks.has(foldMarkKey{machine: machineID, secret: id}, time.Now()) {
		return 0, false
	}
	return id, true
}

// serveMarkingSecretRead serves next and, when the response is a success,
// marks (machine, secret) so this machine's next read of it may fold.
func serveMarkingSecretRead(next http.Handler, w http.ResponseWriter, r *http.Request, machineID, secretID uint) {
	sw := &statusCaptureWriter{ResponseWriter: w}
	next.ServeHTTP(sw, r)
	if sw.status >= 200 && sw.status < 300 {
		foldMarks.add(foldMarkKey{machine: machineID, secret: secretID}, time.Now())
	}
}
