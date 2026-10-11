package middleware

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/keyorixhq/keyorix/internal/core"
)

// RefuseRestrictedPATUngatedWrites refuses a restricted personal access token on
// every ungated write that core's restricted-PAT table marks refused (ADR-042,
// PAT-GUARD-3): 403 with the table entry's sentinel text, before the handler runs.
// Unrestricted PATs, sessions, machine tokens and reads pass untouched, as does any
// route the table does not list (a permission-gated route, where Authorize applies
// the restriction).
//
// routes is the router this middleware is installed on and prefix its mount path
// ("/api/v1"). The middleware runs before that router has matched, so it asks the
// router which pattern the request will match and looks up "<METHOD> <prefix><pattern>",
// the same key noPermissionGateAllowlist and the table use. Must run after
// Authentication, which puts the restriction on the request.
func RefuseRestrictedPATUngatedWrites(routes chi.Routes, prefix string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				next.ServeHTTP(w, r)
				return
			}
			u := GetUserFromContext(r.Context())
			if u == nil || u.PATRestriction == nil {
				next.ServeHTTP(w, r)
				return
			}
			path := r.URL.Path
			if rctx := chi.RouteContext(r.Context()); rctx != nil && rctx.RoutePath != "" {
				path = rctx.RoutePath
			} else {
				path = strings.TrimPrefix(path, prefix)
			}
			pattern := routes.Find(chi.NewRouteContext(), r.Method, path)
			// A nested r.Route("/x", ...) registers its root as "/x/"; the route
			// keys spell it "/x".
			if len(pattern) > 1 {
				pattern = strings.TrimSuffix(pattern, "/")
			}
			if pattern != "" {
				if err := core.RestrictedPATWriteRefusal(r.Method + " " + prefix + pattern); err != nil {
					forbiddenResponse(w, err.Error())
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
