#!/usr/bin/env bash
# lib-http.sh -- shared curl wrappers for the DAST rig that keep credentials off argv.
# An argv is readable by every local user through ps and /proc, so a bearer token or a
# login JSON must never be a curl argument (SCRIPTS-SECRETS-2; the guard is
# cli/cmd/docs_no_literal_secrets_test.go). Source this, then call:
#
#   dast_post_json URL JSON [curl args...]   JSON travels on stdin (--data-binary @-)
#   dast_curl_bearer TOKEN [curl args...]    the token travels in a 0600 `-H @file`
#   dast_post_json_bearer TOKEN URL JSON [curl args...]   both of the above
#
# Both pass the extra curl args straight through and return curl's exit status.

dast_post_json() {
    local url="$1" json="$2"
    shift 2
    printf '%s' "$json" | curl -X POST "$url" -H 'Content-Type: application/json' --data-binary @- "$@"
}

dast_curl_bearer() {
    local token="$1" hdr rc=0
    shift
    hdr="$(mktemp)" # mktemp creates the file mode 0600
    printf 'Authorization: Bearer %s\n' "$token" >"$hdr"
    curl -H "@$hdr" "$@" || rc=$?
    rm -f "$hdr"
    return "$rc"
}

dast_post_json_bearer() {
    local token="$1" url="$2" json="$3" hdr rc=0
    shift 3
    hdr="$(mktemp)"
    printf 'Authorization: Bearer %s\n' "$token" >"$hdr"
    printf '%s' "$json" | curl -X POST "$url" -H "@$hdr" -H 'Content-Type: application/json' --data-binary @- "$@" || rc=$?
    rm -f "$hdr"
    return "$rc"
}
