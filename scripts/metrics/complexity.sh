#!/usr/bin/env bash
# complexity.sh: measure how complex Keyorix is at a git ref, as one row of numbers.
#
#   scripts/metrics/complexity.sh [--json | --tsv] [--groups LIST] [--image]
#                                 [--surface-out DIR] [--keep] [ref]
#
# ref defaults to HEAD. The ref is exported with `git archive` into a temporary
# directory (a clean copy: no working-tree changes, no .git), measured there and
# removed again. No network except the Go module cache filling (set GOPROXY=off for strict offline once cached); the
# npm numbers come from the committed lockfile, nothing is installed.
# Deterministic: the same ref gives the same counts and sizes. The two timing
# and memory numbers (STARTUP) vary with the machine and are the only exception.
#
# Output: a vertical `name  value` table (default), one JSON object (--json), or a
# header line plus one row (--tsv). Progress goes to stderr, results to stdout.
#
# Options:
#   --groups LIST      comma list of: code,deps,artefacts,startup,surface,internal
#                      (default: all). `surface` is the fast, build-light one.
#   --image            also build the container image (needs a working docker;
#                      otherwise the image size is reported as skipped).
#   --surface-out DIR  write the NAME of every config key, env var, CLI command,
#                      CLI flag, API operation and gRPC method to DIR/*.txt, for
#                      complexity-diff.sh.
#   --keep             keep the temporary copy and print its path (debugging).
#
# ------------------------------------------------------------------------------
# METRIC DEFINITIONS (one line each; docs/operations/complexity-metrics.md repeats them)
#
# CODE (whole repository, generated files and testdata/ excluded, and
#       scripts/metrics/ itself excluded so the tool does not measure itself)
#   code_go_lines            Go lines in non-test files (*.go not *_test.go)
#   code_go_test_lines       Go lines in *_test.go files
#   code_go_packages         directories holding at least one non-test, non-generated Go file
#   code_go_files_over_800   non-test Go files longer than 800 lines
#   code_ts_lines            TypeScript/TSX lines under web/ outside tests
#   code_ts_test_lines       TypeScript/TSX lines under web/ in *.test.* / *.spec.* / e2e/ / __tests__/
#   code_shell_lines         lines in scripts/**/*.sh
#   "Generated" = a "// Code generated ... DO NOT EDIT" line (Go) or a DO NOT EDIT /
#   @generated / auto-generated marker (TS) in the first lines of the file.
#
# DEPENDENCIES
#   deps_go_direct           distinct non-keyorix Go modules required directly (go list -m all, not Indirect)
#   deps_go_total            distinct non-keyorix Go modules in the build list (go list -m all)
#                            both over the root, cli/ and migrate/ modules together
#   deps_npm_direct          direct dependencies of web/ (dependencies+devDependencies+optional, pnpm-lock.yaml)
#   deps_npm_total           distinct name@version entries in the lockfile's packages section
#
# ARTEFACTS (linux/amd64, CGO_ENABLED=0, -trimpath, -ldflags "-s -w": the `make release` flags)
#   artefact_server_bytes    keyorix-server binary. Built with the committed placeholder web UI:
#                            the real dashboard bundle (needs pnpm + network) is NOT embedded, so this is
#                            the server without its UI. Compare refs with each other, not with a release asset.
#   artefact_cli_bytes       keyorix CLI binary (cli/ module)
#   artefact_image_bytes     container image size from `docker build -f server/Dockerfile`, or "skipped"
#
# STARTUP (host-native server build, fresh SQLite install in a temp dir made by
#          admin init + admin encryption init + admin migrate, that ref baseline config, loopback)
#   startup_health_ms        median of 5 starts, from process start to the first HTTP 200 on /health
#   startup_peak_rss_kb      peak resident set size (kernel getrusage) of one server that stayed up
#                            10 s idle after becoming healthy, in KiB
#
# USER-FACING SURFACE
#   surface_config_keys              leaf keys of the internal/config Config struct tree (reflection, cfgkeys helper)
#   surface_config_keys_no_default   of those, keys still zero after loading an empty config AND absent from the
#                                    baseline config `admin init` writes (defaults applied later, at the
#                                    use site, are invisible to this and count as "no default")
#   surface_env_vars                 distinct environment variables read by non-test Go code
#                                    (os.Getenv / os.LookupEnv / secretenv.Lookup[Checked]; name a string literal or constant)
#   surface_cli_commands, surface_cli_flags       commands and local flags of the `keyorix` CLI (--help recursion)
#   surface_admin_commands, surface_admin_flags   same for `keyorix-server admin`
#   surface_api_operations           path x HTTP method pairs in server/http/handlers/openapi.yaml
#   surface_grpc_methods             rpc methods in server/proto/*.proto
#   surface_doc_pages                user-facing doc pages (EASE-H2H-1 rule): README.md, docs/SELF_HOSTING*.md,
#                                    docs/operator/, docs/operations/, guides and references
#                                    (docs/*guide*.md, docs/*reference*.md, docs/security/*guide*.md),
#                                    not ADRs / findings / specs / security internals / TESTING_GUIDE.md
#
# INTERNAL WEIGHT
#   internal_guard_tests        Go test functions named *Guard*, *Sweep* or *Completeness*
#   internal_fuzz_targets       Go Fuzz* functions in test files
#   internal_faultops_entries   entries in the server/faultops registries: register*(...) calls in the per-entry
#                               files plus findingDoc: rows of the older literal-table layout
#   internal_adrs               docs/adr-NNN-*.md files
# ------------------------------------------------------------------------------
set -euo pipefail
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"

FORMAT=text
GROUPS_WANTED="code,deps,artefacts,startup,surface,internal"
WITH_IMAGE=0
SURFACE_OUT=""
KEEP=0
REF=HEAD

while [ $# -gt 0 ]; do
  case "$1" in
    --json) FORMAT=json ;;
    --tsv) FORMAT=tsv ;;
    --groups) GROUPS_WANTED="${2:?--groups needs a list}"; shift ;;
    --image) WITH_IMAGE=1 ;;
    --surface-out) SURFACE_OUT="${2:?--surface-out needs a directory}"; shift ;;
    --keep) KEEP=1 ;;
    -h|--help) sed -n '2,/^# -----/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "complexity.sh: unknown option $1 (try --help)" >&2; exit 2 ;;
    *) REF="$1" ;;
  esac
  shift
done

log() { echo "[metrics] $*" >&2; }
want() { case ",$GROUPS_WANTED," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

SHA="$(git -C "$REPO" rev-parse --verify "${REF}^{commit}" 2>/dev/null)" || {
  echo "complexity.sh: '$REF' is not a commit in $REPO. Fetch it first (git fetch origin --tags) or pass another ref." >&2
  exit 2
}
LABEL="$(git -C "$REPO" describe --tags --always "$SHA" 2>/dev/null || echo "$SHA")"
COMMIT_DATE="$(git -C "$REPO" show -s --format=%cs "$SHA")"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/complexity.XXXXXX")"
cleanup() {
  if [ "$KEEP" = 1 ]; then log "kept $TMP"; else rm -rf "$TMP"; fi
}
trap cleanup EXIT
WT="$TMP/tree"
BIN="$TMP/bin"
mkdir -p "$WT" "$BIN"
ROWS="$TMP/rows.tsv"
: > "$ROWS"
if [ -n "$SURFACE_OUT" ]; then mkdir -p "$SURFACE_OUT"; fi

emit() { printf '%s\t%s\n' "$1" "$2" >> "$ROWS"; }

log "measuring $LABEL ($SHA, $COMMIT_DATE); groups: $GROUPS_WANTED"
log "exporting the ref to a temporary copy"
git -C "$REPO" archive "$SHA" | tar -x -C "$WT"

export GOFLAGS="-buildvcs=false" GOTELEMETRY=off
goenv_hint() {
  echo "complexity.sh: a Go build/list failed. If GOPROXY=off is set and a module is missing from the module cache, unset it once so the cache can fill, then rerun." >&2
}

# ---- helper binaries ---------------------------------------------------------
need_surfacewalk=0
for g in deps startup surface internal; do want "$g" && need_surfacewalk=1; done
if [ "$need_surfacewalk" = 1 ]; then
  log "building the surfacewalk helper"
  go -C "$REPO" build -o "$BIN/surfacewalk" ./scripts/metrics/surfacewalk
fi

# ---- CODE --------------------------------------------------------------------
# count_lines KIND LISTFILE -> "nontest test files over800 dirs"
count_lines() {
  awk -v kind="$1" -v list="$2" '
    function generated(line) {
      if (kind == "go") return line ~ /^\/\/ Code generated .* DO NOT EDIT/
      if (kind == "ts") return tolower(line) ~ /do not edit|@generated|auto-?generated/
      return 0
    }
    BEGIN {
      limit = (kind == "go") ? 30 : 10
      while ((getline f < list) > 0) {
        n = 0; gen = 0
        while ((getline line < f) > 0) { n++; if (n <= limit && generated(line)) gen = 1 }
        close(f)
        if (gen) continue
        if (kind == "go")      test = (f ~ /_test\.go$/)
        else if (kind == "ts") test = (f ~ /\.(test|spec)\.tsx?$/ || f ~ /\/e2e\// || f ~ /\/__tests__\//)
        else                   test = 0
        if (test) { tl += n } else {
          nl += n; nf++
          if (n > 800) big++
          d = f; sub(/\/[^\/]*$/, "", d); dirs[d] = 1
        }
      }
      nd = 0; for (d in dirs) nd++
      printf "%d %d %d %d %d\n", nl, tl, nf, big, nd
    }' /dev/null
}

if want code; then
  log "CODE: counting lines"
  EXCL=(-not -path '*/node_modules/*' -not -path '*/testdata/*' -not -path '*/vendor/*' -not -path '*/dist/*' -not -path "$WT/scripts/metrics/*" -not -path '*/.git/*')
  find "$WT" -type f -name '*.go' "${EXCL[@]}" | sort > "$TMP/go.list"
  read -r nl tl _ big nd < <(count_lines go "$TMP/go.list")
  emit code_go_lines "$nl"; emit code_go_test_lines "$tl"; emit code_go_packages "$nd"; emit code_go_files_over_800 "$big"

  find "$WT/web" -type f \( -name '*.ts' -o -name '*.tsx' \) "${EXCL[@]}" 2>/dev/null | sort > "$TMP/ts.list" || true
  read -r nl tl _ _ _ < <(count_lines ts "$TMP/ts.list")
  emit code_ts_lines "$nl"; emit code_ts_test_lines "$tl"

  find "$WT/scripts" -type f -name '*.sh' "${EXCL[@]}" 2>/dev/null | sort > "$TMP/sh.list" || true
  read -r nl tl _ _ _ < <(count_lines sh "$TMP/sh.list")
  emit code_shell_lines "$nl"
fi

# ---- DEPENDENCIES ------------------------------------------------------------
if want deps; then
  log "DEPENDENCIES: go list -m all for the root, cli and migrate modules"
  : > "$TMP/gomods.all"; : > "$TMP/gomods.direct"
  for m in . cli migrate; do
    [ -f "$WT/$m/go.mod" ] || continue
    if ! (cd "$WT/$m" && GOWORK=off go list -m -f '{{.Path}} {{.Version}} {{.Main}} {{.Indirect}}' all) > "$TMP/gomods.$$.out" 2> "$TMP/gomods.err"; then
      cat "$TMP/gomods.err" >&2; goenv_hint; exit 1
    fi
    awk '$1 !~ /^github.com\/keyorixhq\/keyorix/ && $3 != "true" { print $1 " " $2 }' "$TMP/gomods.$$.out" >> "$TMP/gomods.all"
    awk '$1 !~ /^github.com\/keyorixhq\/keyorix/ && $3 != "true" && $4 != "true" { print $1 }' "$TMP/gomods.$$.out" >> "$TMP/gomods.direct"
  done
  emit deps_go_direct "$(sort -u "$TMP/gomods.direct" | wc -l | tr -d ' ')"
  emit deps_go_total "$(sort -u "$TMP/gomods.all" | wc -l | tr -d ' ')"

  if [ -f "$WT/web/pnpm-lock.yaml" ]; then
    "$BIN/surfacewalk" npmlock -file "$WT/web/pnpm-lock.yaml" > "$TMP/npm.txt"
    emit deps_npm_direct "$(grep -c '^direct ' "$TMP/npm.txt" || true)"
    emit deps_npm_total "$(grep -c '^package ' "$TMP/npm.txt" || true)"
  else
    log "no web/pnpm-lock.yaml at this ref: npm counts reported as n/a"
    emit deps_npm_direct n/a; emit deps_npm_total n/a
  fi
fi

# ---- ARTEFACTS ---------------------------------------------------------------
size_of() { wc -c < "$1" | tr -d ' '; }
if want artefacts; then
  log "ARTEFACTS: building linux/amd64 server (release flags)"
  rflags=(-trimpath -ldflags "-s -w")
  (cd "$WT" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build "${rflags[@]}" -o "$BIN/server_linux_amd64" ./server) || { goenv_hint; exit 1; }
  emit artefact_server_bytes "$(size_of "$BIN/server_linux_amd64")"
  log "ARTEFACTS: building linux/amd64 CLI (release flags)"
  (cd "$WT/cli" && GOWORK=off GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build "${rflags[@]}" -o "$BIN/cli_linux_amd64" .) || { goenv_hint; exit 1; }
  emit artefact_cli_bytes "$(size_of "$BIN/cli_linux_amd64")"
  if [ "$WITH_IMAGE" = 1 ] && docker info >/dev/null 2>&1; then
    log "ARTEFACTS: docker build (this can take minutes)"
    tag="keyorix-metrics:${SHA:0:12}"
    (cd "$WT" && docker build -q -f server/Dockerfile -t "$tag" .) >/dev/null
    emit artefact_image_bytes "$(docker image inspect -f '{{.Size}}' "$tag")"
    docker image rm "$tag" >/dev/null 2>&1 || true
  else
    if [ "$WITH_IMAGE" = 1 ]; then log "docker is not usable here: image size skipped"; else log "image size skipped (a docker build is not cheap; pass --image to include it)"; fi
    emit artefact_image_bytes skipped
  fi
fi

# ---- host-native binaries (startup + surface) -------------------------------
build_native() {
  [ -x "$BIN/server_native" ] && return 0
  log "building host-native server and CLI"
  (cd "$WT" && go build -o "$BIN/server_native" ./server) || { goenv_hint; exit 1; }
  (cd "$WT/cli" && GOWORK=off go build -o "$BIN/cli_native" .) || { goenv_hint; exit 1; }
}

# ---- STARTUP -----------------------------------------------------------------
if want startup; then
  build_native
  log "STARTUP: creating a fresh SQLite install"
  INSTALL="$TMP/install"; mkdir -p "$INSTALL"
  MASTER="metrics-master-passphrase-$$-0123456789"
  run_admin() { (cd "$INSTALL" && env -i PATH="$PATH" HOME="$INSTALL" KEYORIX_MASTER_PASSWORD="$MASTER" "$BIN/server_native" admin "$@") > "$INSTALL/admin.log" 2>&1 || { echo "complexity.sh: 'admin $*' failed:" >&2; tail -n 15 "$INSTALL/admin.log" >&2; exit 1; }; }
  run_admin init
  run_admin encryption init
  run_admin migrate
  PORT=$(( 20000 + (RANDOM % 30000) ))
  tries=0
  while curl -sk -m 1 -o /dev/null "https://127.0.0.1:$PORT/health" 2>/dev/null && [ "$tries" -lt 20 ]; do PORT=$(( 20000 + (RANDOM % 30000) )); tries=$((tries+1)); done
  # first `port: "8080"` is server.http.port in the baseline config
  sed -i.bak "1,/^    port: \"8080\"/s/^    port: \"8080\"/    port: \"$PORT\"/" "$INSTALL/keyorix.yaml"
  rm -f "$INSTALL/keyorix.yaml.bak"
  grep -q "^    port: \"$PORT\"" "$INSTALL/keyorix.yaml" || { echo "complexity.sh: could not set the server port in the baseline config; its layout changed" >&2; exit 1; }
  log "STARTUP: 5 starts, then 10 s idle (about a minute)"
  "$BIN/surfacewalk" startup -bin "$BIN/server_native" -dir-run "$INSTALL" -url "127.0.0.1:$PORT/health" \
    -runs 5 -idle 10s -env-var "KEYORIX_MASTER_PASSWORD=$MASTER" -env-var "KEYORIX_CONFIG_PATH=$INSTALL/keyorix.yaml" > "$TMP/startup.txt"
  emit startup_health_ms "$(awk '$1=="median_ms"{print $2}' "$TMP/startup.txt")"
  emit startup_peak_rss_kb "$(awk '$1=="peak_rss_kb"{print $2}' "$TMP/startup.txt")"
fi

# ---- USER-FACING SURFACE -----------------------------------------------------
list_out() { # NAME FILE: copy a name list to --surface-out when asked
  if [ -n "$SURFACE_OUT" ]; then sort -u "$2" > "$SURFACE_OUT/$1.txt"; fi
}

if want surface; then
  build_native
  log "SURFACE: config keys (reflection over internal/config)"
  mkdir -p "$WT/scripts/metrics/cfgkeys"
  for f in "$SCRIPT_DIR"/cfgkeys/*.go; do
    case "$f" in *_test.go) ;; *) cp "$f" "$WT/scripts/metrics/cfgkeys/" ;; esac
  done
  (cd "$WT" && go build -o "$BIN/cfgkeys" ./scripts/metrics/cfgkeys) || { goenv_hint; exit 1; }
  "$BIN/cfgkeys" > "$TMP/cfgkeys.tsv"
  emit surface_config_keys "$(wc -l < "$TMP/cfgkeys.tsv" | tr -d ' ')"
  emit surface_config_keys_no_default "$(grep -c "	no-default$" "$TMP/cfgkeys.tsv" || true)"
  cut -f1 "$TMP/cfgkeys.tsv" > "$TMP/cfgkeys.names"; list_out config_keys "$TMP/cfgkeys.names"
  grep "	no-default$" "$TMP/cfgkeys.tsv" | cut -f1 > "$TMP/cfgkeys.nodefault.names" || true
  list_out config_keys_no_default "$TMP/cfgkeys.nodefault.names"

  log "SURFACE: environment variables read"
  "$BIN/surfacewalk" env -root "$WT" -dirs internal,server,cli,migrate,cmd,pkg > "$TMP/env.txt"
  emit surface_env_vars "$(wc -l < "$TMP/env.txt" | tr -d ' ')"; list_out env_vars "$TMP/env.txt"

  log "SURFACE: CLI commands and flags (--help recursion)"
  "$BIN/surfacewalk" cobra -bin "$BIN/cli_native" > "$TMP/cli.txt"
  grep '^cmd ' "$TMP/cli.txt" | sed 's/^cmd /keyorix /' > "$TMP/cli.cmds" || true
  grep '^flag ' "$TMP/cli.txt" | sed 's/^flag /keyorix /' > "$TMP/cli.flags" || true
  emit surface_cli_commands "$(wc -l < "$TMP/cli.cmds" | tr -d ' ')"
  emit surface_cli_flags "$(wc -l < "$TMP/cli.flags" | tr -d ' ')"
  list_out cli_commands "$TMP/cli.cmds"; list_out cli_flags "$TMP/cli.flags"

  log "SURFACE: server admin commands and flags"
  "$BIN/surfacewalk" cobra -bin "$BIN/server_native" -prefix admin > "$TMP/admin.txt"
  grep '^cmd ' "$TMP/admin.txt" | sed 's/^cmd /keyorix-server admin /' > "$TMP/admin.cmds" || true
  grep '^flag ' "$TMP/admin.txt" | sed -e 's/^flag (root) /keyorix-server admin /' -e 's/^flag /keyorix-server admin /' > "$TMP/admin.flags" || true
  emit surface_admin_commands "$(wc -l < "$TMP/admin.cmds" | tr -d ' ')"
  emit surface_admin_flags "$(wc -l < "$TMP/admin.flags" | tr -d ' ')"
  list_out admin_commands "$TMP/admin.cmds"; list_out admin_flags "$TMP/admin.flags"

  log "SURFACE: API operations, gRPC methods, doc pages"
  "$BIN/surfacewalk" openapi -file "$WT/server/http/handlers/openapi.yaml" > "$TMP/api.txt"
  emit surface_api_operations "$(wc -l < "$TMP/api.txt" | tr -d ' ')"; list_out api_operations "$TMP/api.txt"
  "$BIN/surfacewalk" grpc -dir "$WT/server/proto" > "$TMP/grpc.txt"
  emit surface_grpc_methods "$(wc -l < "$TMP/grpc.txt" | tr -d ' ')"; list_out grpc_methods "$TMP/grpc.txt"

  (cd "$WT" && find . -type f -name '*.md' -not -path '*/node_modules/*' | sed 's|^\./||' | sort) | awk '
    function lower(s) { return tolower(s) }
    {
      p = $0; base = p; sub(/^.*\//, "", base); lb = lower(base)
      keep = 0
      if (p == "README.md") keep = 1
      else if (p ~ /^docs\/SELF_HOSTING[^\/]*\.md$/) keep = 1
      else if (p ~ /^docs\/operator\// || p ~ /^docs\/operations\//) keep = 1
      else if (p ~ /^docs\/[^\/]*\.md$/ && base !~ /^adr-/ && base != "TESTING_GUIDE.md" && (lb ~ /guide/ || lb ~ /reference/)) keep = 1
      else if (p ~ /^docs\/security\/[^\/]*\.md$/ && lb ~ /guide/) keep = 1
      if (keep) print p
    }' > "$TMP/docs.txt"
  emit surface_doc_pages "$(wc -l < "$TMP/docs.txt" | tr -d ' ')"; list_out doc_pages "$TMP/docs.txt"
fi

# ---- INTERNAL WEIGHT ---------------------------------------------------------
if want internal; then
  log "INTERNAL WEIGHT: guards, fuzz targets, faultops registry, ADRs"
  find "$WT" -type f -name '*_test.go' -not -path '*/node_modules/*' -not -path '*/testdata/*' -not -path '*/vendor/*' -not -path "$WT/scripts/metrics/*" | sort > "$TMP/tests.list"
  # xargs may split the list into several grep runs; each prints its own matches and we count lines.
  xargs grep -hE '^func Test[A-Za-z0-9_]*(Guard|Sweep|Completeness)[A-Za-z0-9_]*\(' < "$TMP/tests.list" | wc -l | tr -d ' ' > "$TMP/guards.n" || true
  emit internal_guard_tests "$(cat "$TMP/guards.n")"
  xargs grep -hE '^func Fuzz[A-Za-z0-9_]*\(' < "$TMP/tests.list" | wc -l | tr -d ' ' > "$TMP/fuzz.n" || true
  emit internal_fuzz_targets "$(cat "$TMP/fuzz.n")"
  if [ -d "$WT/server/faultops" ]; then
    reg=$(cat "$WT"/server/faultops/*_test.go 2>/dev/null | grep -cE '^[[:space:]]+register[A-Za-z]+\(' || true)
    lit=$(grep -cE 'findingDoc:' "$WT/server/faultops/fuzz_storage_fault_operations_test.go" 2>/dev/null || true)
    emit internal_faultops_entries "$(( ${reg:-0} + ${lit:-0} ))"
  else
    emit internal_faultops_entries 0
  fi
  emit internal_adrs "$(find "$WT/docs" -maxdepth 1 -type f -name 'adr-[0-9]*.md' | wc -l | tr -d ' ')"
fi

# ---- output ------------------------------------------------------------------
is_number() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }
case "$FORMAT" in
  text)
    printf '# Keyorix complexity at %s (%s, %s)\n' "$LABEL" "$SHA" "$COMMIT_DATE"
    awk -F'\t' '{ printf "%-32s %s\n", $1, $2 }' "$ROWS"
    ;;
  tsv)
    { printf 'ref\tcommit'; cut -f1 "$ROWS" | while read -r k; do printf '\t%s' "$k"; done; printf '\n'
      printf '%s\t%s' "$LABEL" "$SHA"; cut -f2 "$ROWS" | while read -r v; do printf '\t%s' "$v"; done; printf '\n'; }
    ;;
  json)
    printf '{"ref":"%s","commit":"%s","commit_date":"%s"' "$LABEL" "$SHA" "$COMMIT_DATE"
    while IFS=$'\t' read -r k v; do
      if is_number "$v"; then printf ',"%s":%s' "$k" "$v"; else printf ',"%s":"%s"' "$k" "$v"; fi
    done < "$ROWS"
    printf '}\n'
    ;;
esac
log "done: $LABEL"
