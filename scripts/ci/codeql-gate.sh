#!/usr/bin/env bash
# CodeQL merge-queue gate (CODEQL-QUEUE-1).
#
# In the merge queue codeql.yml analyses with `upload: never`: the SARIF upload
# ran after GitHub had already deleted the gh-readonly-queue/* branch and failed
# with "ref ... not found in this repository" (~40 queue entries a day). With no
# upload there are no code-scanning results on the merge group, so this script
# is the gate: it reads the SARIF files the analysis wrote to disk and fails when
# a HIGH-or-worse result (rule security-severity >= 7.0, GitHub's own "high"
# threshold) is not already a known code-scanning alert on main: open, or
# dismissed.
#
# Dismissed = accepted risk. A human reviewed the alert in the Security tab and
# dismissed it (won't fix / false positive); the analysis still writes such a
# finding into the SARIF on every run, so treating only state=open as known made
# every dismissed finding "new" and failed nearly every queue entry (18 Oct).
# Only state=fixed alerts are ignored: a fixed finding that reappears is new.
#
# "Already known on main" is matched by (rule id, file path), not by line: a
# line-exact match would call every pre-existing alert "new" whenever a queue
# entry shifts the line. The consequence is that a SECOND instance of a known
# rule in a file that already has an alert is not caught here; it is caught
# after merge, when the push-to-main run uploads and the new alert appears in
# the Security tab. Everything else (a new rule, or an old rule in a new file)
# fails the queue entry.
#
# Fails closed: unreadable SARIF, no SARIF at all, or an alerts-API failure with
# high results present is an error, never a pass.
#
# Usage: codeql-gate.sh <sarif-dir>
# Env:   GH_TOKEN, REPO (owner/name) -- to read main's open and dismissed alerts.
#        GATE_RETRY_SLEEP -- test hook: seconds per retry step (default 5).
#        GATE_BASELINE_TSV -- test hook: a file of "ruleId<TAB>path" lines used
#        instead of the API.
set -euo pipefail

dir=${1:?usage: codeql-gate.sh <sarif-dir>}
threshold=7.0

shopt -s nullglob
files=("$dir"/*.sarif)
if [ "${#files[@]}" -eq 0 ]; then
  echo "codeql-gate: no .sarif files in $dir -- the analysis wrote nothing; failing closed" >&2
  exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
: > "$work/high.tsv"

for f in "${files[@]}"; do
  # rule id -> security-severity, over driver rules and extension rules; one
  # TSV row per result at or above the threshold: ruleId, path, line, severity.
  jq -r --argjson thr "$threshold" '
    .runs[]
    | ([ (.tool.driver.rules // [])[], ((.tool.extensions // [])[] | (.rules // [])[]) ]
       | map({key: .id, value: ((.properties["security-severity"] // "0") | tonumber)})
       | from_entries) as $sev
    | (.results // [])[]
    | select(($sev[.ruleId] // 0) >= $thr)
    | [.ruleId,
       (.locations[0].physicalLocation.artifactLocation.uri // "?"),
       ((.locations[0].physicalLocation.region.startLine // 0) | tostring),
       (($sev[.ruleId]) | tostring)]
    | @tsv' "$f" >> "$work/high.tsv"
done

total=$(wc -l < "$work/high.tsv" | tr -d ' ')
echo "codeql-gate: ${#files[@]} SARIF file(s), $total result(s) with security-severity >= $threshold"
if [ "$total" -eq 0 ]; then
  exit 0
fi

if [ -n "${GATE_BASELINE_TSV:-}" ]; then
  cp "$GATE_BASELINE_TSV" "$work/known.tsv"
else
  : "${REPO:?REPO is required}"
  : > "$work/known.tsv"
  # Both states count as "known on main": open = tracked, dismissed = a human
  # already decided (won't fix / false positive). fixed alerts do not count.
  for state in open dismissed; do
    ok=""
    for attempt in 1 2 3; do
      if gh api --paginate "repos/$REPO/code-scanning/alerts?state=$state&ref=refs/heads/main&per_page=100" \
        --jq '.[] | [.rule.id, .most_recent_instance.location.path] | @tsv' > "$work/alerts-$state.tsv"; then
        ok=1
        break
      fi
      echo "codeql-gate: alerts API ($state) attempt $attempt failed" >&2
      sleep $((attempt * ${GATE_RETRY_SLEEP:-5}))
    done
    if [ -z "$ok" ]; then
      echo "codeql-gate: cannot read main's $state alerts; failing closed" >&2
      exit 1
    fi
    cat "$work/alerts-$state.tsv" >> "$work/known.tsv"
  done
fi

bad=0
while IFS=$'\t' read -r rule path line sev; do
  if ! grep -qxF "$(printf '%s\t%s' "$rule" "$path")" "$work/known.tsv"; then
    echo "::error file=$path,line=$line::CodeQL high-severity result $rule (security-severity $sev) is not an open or dismissed alert on main"
    bad=1
  fi
done < "$work/high.tsv"

if [ "$bad" -ne 0 ]; then
  exit 1
fi
echo "codeql-gate: every high-severity result is already an open or dismissed alert on main"
