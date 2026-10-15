package middleware

import (
	"fmt"
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
)

// SecretValueReadRoute describes one REST route that discloses a secret value,
// for AuditSecretValueReadDenials.
type SecretValueReadRoute struct {
	// Path is the core.SecretReadPath* constant recorded on the audit row.
	Path string
	// Target names what the caller asked for (the {id} path parameter, the ref
	// query, the project or environment). Computed only for a refused request.
	Target func(*http.Request) core.SecretReadDenialTarget
	// DisclosesValue, when set, says whether this request reads the value at
	// all (GET /secrets/{id} does only with include_value=true). Nil: always.
	DisclosesValue func(*http.Request) bool
}

// AuditSecretValueReadDenials audits every refused request of a value-disclosing
// route (#3273). It goes OUTERMOST on the route, before the scoped-permission
// gate, so a refusal by the gate, the handler or core is seen alike: it puts a
// core.SecretReadDenialNote on the context, the layer that refuses notes the
// reason class, and once the response is a refusal this records one
// secret.read Success=false row through core's aggregator.
//
// A response counts as refused when a layer noted a reason and the status is
// 4xx/5xx, or, with no note, when it is 403 (forbidden) or 404 (not_found). A
// 400 for an unparseable target, a 401, and a 5xx nobody noted (an audit-write
// failure on the success path, for one) are not read refusals. Read and copy
// in core record their own refusals and mark the note, so nothing is written
// twice. The response itself is never changed, and a failed audit write never
// turns the refusal into anything else.
//
// On a successful request the cost is one context value and the status
// capture; the aggregator and storage are touched only on refusal.
func AuditSecretValueReadDenials(route SecretValueReadRoute) func(http.Handler) http.Handler {
	if route.Path == "" || route.Target == nil {
		panic("AuditSecretValueReadDenials: Path and Target are required")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if route.DisclosesValue != nil && !route.DisclosesValue(r) {
				next.ServeHTTP(w, r)
				return
			}
			ctx, note := core.WithSecretReadDenialNote(r.Context(), route.Path)
			sw := &statusCaptureWriter{ResponseWriter: w}
			next.ServeHTTP(sw, r.WithContext(ctx))
			if sw.succeeded() {
				return
			}
			fallback := refusalFromStatus(sw.status)
			if fallback == "" && !noted(note) {
				return
			}
			userCtx := GetUserFromContext(r.Context())
			cs := GetCoreServiceFromContext(r.Context())
			if userCtx == nil || cs == nil {
				return
			}
			actor := core.SecretReadDenialActor{
				UserID: userCtx.UserID, Username: userCtx.Username,
				IP: clientIP(r), UA: r.Header.Get("User-Agent"),
			}
			cs.RecordNotedSecretReadDenial(core.DetachedAuditContext(ctx), note, actor, route.Target(r), fallback)
		})
	}
}

// refusalFromStatus is the reason for a refusal no layer noted.
func refusalFromStatus(status int) core.SecretReadDenialReason {
	switch status {
	case http.StatusForbidden:
		return core.SecretReadDeniedForbidden
	case http.StatusNotFound:
		return core.SecretReadDeniedNotFound
	default:
		return ""
	}
}

func noted(n *core.SecretReadDenialNote) bool { return n.Reason() != "" }

// IncludeValueRequested is DisclosesValue for GET /secrets/{id}: only
// include_value=true reads the value.
func IncludeValueRequested(r *http.Request) bool {
	return r.URL.Query().Get("include_value") == "true"
}

// SecretValueReadByID is a route whose target is the secret named by the idParam
// path parameter. An unparseable id gives a zero target (the request is a 400
// anyway, never a refusal).
func SecretValueReadByID(path, idParam string, disclosesValue func(*http.Request) bool) SecretValueReadRoute {
	return SecretValueReadRoute{Path: path, DisclosesValue: disclosesValue, Target: func(r *http.Request) core.SecretReadDenialTarget {
		id, _ := scopePathUint(r, idParam)
		return core.SecretReadDenialTarget{SecretID: id}
	}}
}

// SecretValueReadByRef is GET /secrets/value?ref=project/environment/name.
func SecretValueReadByRef(path string) SecretValueReadRoute {
	return SecretValueReadRoute{Path: path, Target: func(r *http.Request) core.SecretReadDenialTarget {
		return core.SecretReadDenialTarget{Ref: "ref:" + r.URL.Query().Get("ref")}
	}}
}

// SecretValueReadByPathParam is a route whose target is a project or
// environment path parameter (render, environment copy and clone): the refused
// read is recorded against "<kind>:<value>".
func SecretValueReadByPathParam(path, kind, param string) SecretValueReadRoute {
	return SecretValueReadRoute{Path: path, Target: func(r *http.Request) core.SecretReadDenialTarget {
		v, _ := scopePathUint(r, param)
		return core.SecretReadDenialTarget{Ref: fmt.Sprintf("%s:%d", kind, v)}
	}}
}
