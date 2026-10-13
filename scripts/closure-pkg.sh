#!/bin/bash
# closure-pkg.sh — sourced by check-closures.sh and gen-security-closures-tsv.sh.
# Not run directly.
#
# Decides which Go module a closure row's `package` column belongs to, so the
# checker runs `go test` in the right module. The repo is several modules (root,
# cli/, operator/, migrate/, devtools/*); `go test ./cli/...` from the root fails
# ("directory prefix cli does not contain main module"), which is why a claim on a
# cli/ package could not be verified before.
#
# Accepted form: `./<path>` relative to the repo root, e.g. `./internal/core`
# (root module) or `./cli/internal/apiclient` (cli module). Everything else is
# refused, never skipped (fail closed):
#   - a bare path (`internal/core`, `cli/cmd`): Go resolves it inside GOROOT;
#   - a path with a `.`, `..` or `...` segment or a character outside [A-Za-z0-9_.-]
#     (a wildcard could hide a package that no longer exists);
#   - a directory that does not exist;
#   - a directory inside a module this checker has no runner for (operator/, migrate/,
#     devtools/*, ...): an unknown module is a failure, not a silent pass.
#
# closure_pkg_resolve REPO_ROOT PKG sets CLOSURE_MOD_DIR (module directory relative
# to REPO_ROOT, "." for the root module) and CLOSURE_MOD_PKG (the package argument to
# pass to `go test` from inside that directory). It returns 1 and sets
# CLOSURE_PKG_ERR when the package is refused. For the root module
# CLOSURE_MOD_PKG is PKG unchanged.

# shellcheck disable=SC2034  # CLOSURE_* results are read by the sourcing scripts
# Modules a closure row may name. Add a module here only together with a self-test case.
CLOSURE_KNOWN_MODULES=". cli"

closure_pkg_resolve() {
    local root="$1" pkg="$2" rel seg dir mod known ok
    CLOSURE_MOD_DIR="" CLOSURE_MOD_PKG="" CLOSURE_PKG_ERR=""

    case "$pkg" in
        ./*) ;;
        *) CLOSURE_PKG_ERR="package '$pkg' must be written ./<path> relative to the repo root (a bare path is resolved by Go inside GOROOT)"; return 1 ;;
    esac
    rel="${pkg#./}"
    if [ -z "$rel" ] || [[ "$rel" == */ ]] || [[ "$rel" == *//* ]] || [[ ! "$rel" =~ ^[A-Za-z0-9_./-]+$ ]]; then
        CLOSURE_PKG_ERR="package '$pkg' is not a plain ./<dir>/<dir> path"; return 1
    fi
    local -a segs
    IFS=/ read -ra segs <<<"$rel"
    for seg in "${segs[@]}"; do
        if [ -z "$seg" ] || [[ "$seg" =~ ^\.+$ ]]; then
            CLOSURE_PKG_ERR="package '$pkg' has a '$seg' path segment (no wildcards or parent references)"; return 1
        fi
    done
    if [ ! -d "$root/$rel" ]; then
        CLOSURE_PKG_ERR="package directory '$pkg' does not exist"; return 1
    fi

    # Nearest enclosing go.mod, walking up from the package directory.
    dir="$rel"
    while :; do
        if [ -f "$root/$dir/go.mod" ]; then mod="$dir"; break; fi
        case "$dir" in
            */*) dir="${dir%/*}" ;;
            *)   mod="."; break ;;
        esac
    done
    if [ "$mod" = "." ] && [ ! -f "$root/go.mod" ]; then
        CLOSURE_PKG_ERR="no go.mod found above '$pkg'"; return 1
    fi

    ok=false
    for known in $CLOSURE_KNOWN_MODULES; do
        [ "$known" = "$mod" ] && ok=true
    done
    if [ "$ok" != true ]; then
        CLOSURE_PKG_ERR="package '$pkg' is in module '$mod', which check-closures.sh cannot run (known: $CLOSURE_KNOWN_MODULES)"; return 1
    fi

    CLOSURE_MOD_DIR="$mod"
    if [ "$mod" = "." ]; then
        CLOSURE_MOD_PKG="$pkg"
    elif [ "$rel" = "$mod" ]; then
        CLOSURE_MOD_PKG="."
    else
        CLOSURE_MOD_PKG="./${rel#"$mod"/}"
    fi
    return 0
}
