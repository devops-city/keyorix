#!/usr/bin/env bash
# scripts/demo/image-stamp.sh — which source tree was the demo image built from? (#3149)
#
# Sourced by up.sh (not executable on its own). An image tag such as
# keyorix-demo:airgap outlives the checkout that built it: after a `git pull` the
# old image still exists, `docker image inspect` succeeds, and the stale server
# then rejects the flags the current scripts pass ("unknown flag: --dev"). So the
# image is labelled at build time with a fingerprint of the working tree and up.sh
# compares that label to the checkout before reusing it.
#
# The fingerprint is the HEAD commit plus, when tracked files differ from HEAD or
# untracked source files exist, a hash of those changes. It deliberately ignores
# server/webui/dist (rebuilt by populate-webui-dist on every build, so it would
# make every image look stale), docs, changelog fragments and CI config (none of
# which the image contains).

DEMO_IMAGE_LABEL="io.keyorix.demo.source"

# Pathspecs excluded from the fingerprint.
_demo_fp_excludes=(':!server/webui/dist' ':!docs' ':!changelog.d' ':!.github' ':!*.md')

# demo_source_fingerprint [ROOT] prints the fingerprint of ROOT's working tree
# (default $REPO_ROOT), or nothing and returns 1 when ROOT is not a git checkout.
demo_source_fingerprint() {
  local root="${1:-$REPO_ROOT}" head diff untracked
  head="$(git -C "$root" rev-parse --short=12 HEAD 2>/dev/null)" || return 1
  diff="$(git -C "$root" diff HEAD -- . "${_demo_fp_excludes[@]}" 2>/dev/null | git hash-object --stdin)" || return 1
  untracked="$(git -C "$root" ls-files -o --exclude-standard -- . "${_demo_fp_excludes[@]}" 2>/dev/null \
    | git -C "$root" hash-object --stdin-paths 2>/dev/null | git hash-object --stdin)" || return 1
  # git hash-object of empty input: same value for "no diff" and "no untracked files".
  local empty
  empty="$(printf '' | git hash-object --stdin)"
  if [ "$diff" = "$empty" ] && [ "$untracked" = "$empty" ]; then
    printf '%s' "$head"
  else
    printf '%s+dirty-%s' "$head" "$(printf '%s%s' "$diff" "$untracked" | git hash-object --stdin | cut -c1-10)"
  fi
}

# demo_image_label IMAGE prints IMAGE's source label ("" when absent), or returns
# 1 when the image does not exist.
demo_image_label() {
  docker image inspect -f "{{ index .Config.Labels \"$DEMO_IMAGE_LABEL\" }}" "$1" 2>/dev/null
}
