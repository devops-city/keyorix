#!/usr/bin/env python3
"""scripts/ci/select-affected.py -- merge_group test selection (CI-SELECT-1).

The merge queue used to run every job and all 22 -race test-suite legs for
every entry (~295 job-minutes). This script decides, from the entry's diff
against github.event.merge_group.base_sha (the queue entry ahead of it, or
main -- so the diff is that one PR), which root-module packages the change
can affect and which path-gated jobs have touched inputs, so the rest finish
in seconds. push to main, the nightly schedule and a plain workflow_dispatch
never call it: they keep the full suite (see ci.yml's `select` job).

Usage:
  select-affected.py --base <sha> [--head <rev>] [--github-output <file>]
                     [--summary <file>] [--json]

Prints a human summary on stderr. With --github-output, appends
mode/reason/legs/gate_* lines in GITHUB_OUTPUT format. With --json, prints
the whole decision as JSON on stdout. Every failure path (git, go list, an
unexpected exception) degrades to mode=full: when in doubt, run everything.

Rule (same shape as test-quick's scripts/ci-test-quick.py and sbin/kaffected,
made more conservative because this one gates main):

1. FULL when any changed path is: a go.mod/go.sum/go.work/go.work.sum of any
   module; internal/testutil/**; .github/workflows/ci.yml; scripts/ci/** (this
   script and the guard runner); scripts/ci-test-legs.sh or
   scripts/ci-test-quick.py (leg definitions); a generated-code input (*.proto,
   buf*.yaml, a generator program directory named gen or *gen, or a .go file
   with a //go:generate line at either end of the diff).
2. Otherwise every changed file is mapped to the root-module package whose
   directory is its nearest ancestor (so testdata/, embedded files and other
   non-Go files in a package directory select that package). It is a CODE
   seed when compiled code changed (a non-test .go file, or a file the
   package's //go:embed patterns cover) and a TEST seed otherwise (a _test.go
   file, testdata/, INVARIANTS.md, ...).
3. Every changed file is also matched against the string literals of every
   package's Go files: a package whose literals name the file's basename (not
   for .go files: main.go names nothing), its path, or a
   directory above it (a one-word directory such as "docs" only for files
   outside every package) is selected too -- a code seed when the literal is in non-test
   code, a test seed when it is only in _test.go files. This is how tests
   that read docs/, scripts/, deploy/, QUICK_START.md and the like are found;
   it over-selects on generic names, never under-selects on a named path.
4. Affected = all seeds + every package that depends on a CODE seed (go
   list's transitive Deps, plus direct TestImports/XTestImports and one hop
   through their Deps) -- the test-quick rule. A test seed adds only itself:
   _test.go files compile into their own package's test binary and nothing
   imports them.
5. Static source-scanning guards are NOT chosen here: ci.yml's repo-guards job
   runs every one of them (scripts/ci/run-guards.sh) whatever changed.

Not covered, by design: a test that builds a path at run time from pieces no
single literal names (rule 3 sees each piece separately, so a bare "docs" or
"scripts" literal still selects it), and a test that reads another package's
Go source as text (that is a static guard: rule 5). The nightly full run on
main is the backstop for anything this misses.
"""
import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys

MODULE = "github.com/keyorixhq/keyorix"
SERVER_MAIN = MODULE + "/server"  # what server/Dockerfile and the smokes build

FULL_BASENAMES = {"go.mod", "go.sum", "go.work", "go.work.sum"}
FULL_PREFIXES = (
    "internal/testutil/",
    "scripts/ci/",
)
FULL_EXACT = {
    ".github/workflows/ci.yml",
    "scripts/ci-test-legs.sh",
    "scripts/ci-test-quick.py",
    "buf.yaml",
    "buf.gen.yaml",
    "buf.work.yaml",
}
GENERATOR_DIR = re.compile(r"(^|/)[a-z0-9_-]*gen/")
# Separate Go modules: their files never belong to a root-module package.
OTHER_MODULES = ("cli/", "operator/", "migrate/", "devtools/vacuum/")
# Go string literals: interpreted "..." (with escapes) and raw `...`.
LITERAL = re.compile(r'"((?:[^"\\\n]|\\.)*)"|`([^`]*)`')
GLOB_CHARS = set("*?[")


def log(msg):
    print(msg, file=sys.stderr)


def one_line(value):
    """value on a single line: a newline or CR in a GITHUB_OUTPUT value would
    end it early and let the rest parse as another key=value line."""
    return " ".join(str(value).replace("\r", "\n").split("\n")).strip()


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout


def file_at(rev, path):
    """path's content at rev; rev None is the working tree (--changed mode)."""
    if rev is None:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return ""
    try:
        return subprocess.run(["git", "show", f"{rev}:{path}"], capture_output=True, text=True, check=True).stdout
    except subprocess.CalledProcessError:
        return ""


def changed_files(base, head):
    # --no-renames: a moved file shows up under both its old and its new path,
    # so a rename can never hide the package it left.
    out = git("diff", "--name-only", "--no-renames", base, head)
    return sorted({line.strip() for line in out.splitlines() if line.strip()})


def full_reason(changed, base, head):
    for f in changed:
        if os.path.basename(f) in FULL_BASENAMES:
            return f"{f} changed (dependency graph)"
        if f in FULL_EXACT:
            return f"{f} changed (CI selection/leg definition or generated-code input)"
        if f.startswith(FULL_PREFIXES):
            return f"{f} changed (shared test helpers or CI scripts)"
        if f.endswith(".proto"):
            return f"{f} changed (generated-code input)"
        if f.endswith(".go") and GENERATOR_DIR.search(f):
            return f"{f} changed (code generator)"
    for f in changed:
        if f.endswith(".go"):
            for rev in (base, head):
                if "//go:generate" in file_at(rev, f):
                    return f"{f} has a //go:generate directive (generated-code input)"
    return None


def load_packages():
    out = subprocess.run(
        ["go", "list", "-e", "-json=ImportPath,Dir,Deps,TestImports,XTestImports,GoFiles,CgoFiles,TestGoFiles,XTestGoFiles,IgnoredGoFiles,EmbedPatterns", "./..."],
        capture_output=True, text=True, check=True,
    ).stdout
    packages, dec, i = {}, json.JSONDecoder(), 0
    while i < len(out):
        obj, end = dec.raw_decode(out, i)
        # `go list ./...` names the dependencies of ./server (a main package
        # another package's tests import) as variants: "internal/core
        # [github.com/keyorixhq/keyorix/server]". Strip the bracket, or no
        # changed package would ever match server's Deps.
        for key in ("Deps", "TestImports", "XTestImports"):
            if obj.get(key):
                obj[key] = [d.split(" [", 1)[0] for d in obj[key]]
        packages[obj["ImportPath"]] = obj
        i = end
        while i < len(out) and out[i].isspace():
            i += 1
    return packages


def normalize(lit):
    """Repo-relative form of a path-like literal.

    Drops ./ and ../ components and any leading component that is a format
    verb or template ("%s/docs/x.tsv" -> docs/x.tsv), so a literal is
    compared the way the test resolves it from the repository root."""
    parts = [p for p in lit.replace("\\", "/").split("/") if p not in ("", ".", "..")]
    while parts and any(c in parts[0] for c in "%${"):
        parts = parts[1:]
    return parts


def literal_index(files):
    """(components, paths) for the string literals of the given files.

    components: every path component of every literal (matched against a
    changed file's basename). paths: every literal as a normalized path,
    globs cut back to their directory (matched as a prefix of a changed
    file: "docs" selects all of docs/, "docs/x.tsv" only that file)."""
    comps, paths = set(), set()
    for path in files:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        for m in LITERAL.finditer(text):
            lit = m.group(1) if m.group(1) is not None else m.group(2)
            if not lit or len(lit) > 300 or "\n" in lit:
                continue
            parts = normalize(lit)
            if not parts:
                continue
            comps.update(parts)
            if GLOB_CHARS & set(parts[-1]):
                parts = parts[:-1]
            if parts:
                paths.add("/".join(parts))
    return comps, paths


def references(index, path, outside_packages, by_basename=True):
    """True when a literal names the file itself (basename), the file's path,
    or a directory above it -- the ways a test reaches a data file.

    A one-component directory literal ("docs", "scripts") only counts for a
    file outside every package: inside internal/ or server/ the same bare
    words are error codes and role names ("internal", "server"), and a
    package directory's own files are already selected through rule 2.
    by_basename=False (any .go file) matches by path only: main.go or
    types.go names nothing in particular."""
    comps, paths = index
    if by_basename and os.path.basename(path) in comps:
        return True
    d = path
    while d:
        if d in paths and (outside_packages or "/" in d):
            return True
        d = os.path.dirname(d)
    return False


def module_go_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ("node_modules", ".git", "testdata")]
        for fn in filenames:
            if fn.endswith(".go"):
                yield os.path.join(dirpath, fn)


def leg_packages():
    script = 'source scripts/ci-test-legs.sh; for l in $(all_leg_names); do echo "== $l"; pkgs_for_leg "$l"; done'
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True).stdout
    legs, cur = {}, None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("== "):
            cur = line[3:]
            legs[cur] = []
        elif line and cur:
            legs[cur].append(line)
    if len(legs) < 10:
        raise RuntimeError(f"ci-test-legs.sh listed only {len(legs)} legs")
    return legs


SHARDED_SINGLE_PACKAGE = re.compile(r"^(handlers|http|encryption|faultops|storage-store)-\d+$")


def fuzz_reach_packages():
    """The ./pkg column of scripts/fuzzing/harness-acceptance.sh's TARGETS."""
    try:
        text = open("scripts/fuzzing/harness-acceptance.sh", encoding="utf-8").read()
    except OSError:
        return None
    pkgs = set(re.findall(r"^\s*'Fuzz[A-Za-z0-9_]+;\./([^;']+);", text, re.M))
    return {f"{MODULE}/{p}" for p in pkgs} or None


def decide(base, head, changed=None):
    if changed is None:
        changed = changed_files(base, head)
    decision = {"base": base, "head": head, "changed": changed}
    reason = full_reason(changed, base, head)
    if reason:
        return {**decision, "mode": "full", "reason": reason}
    if not changed:
        return {**decision, "mode": "full", "reason": "empty diff (unexpected for a merge group)"}

    packages = load_packages()
    repo = os.getcwd()
    dir_to_pkg = {}
    for imp, obj in packages.items():
        rel = os.path.relpath(obj.get("Dir", ""), repo)
        if rel != "." and not rel.startswith(".."):
            dir_to_pkg[rel] = imp

    def owning_package(path):
        if path.startswith(OTHER_MODULES):
            return None
        d = os.path.dirname(path)
        while d:
            if d in dir_to_pkg:
                return dir_to_pkg[d]
            d = os.path.dirname(d)
        return None

    # Two kinds of seed. A CODE seed is a package whose compiled code changed
    # (a non-test .go file, or a file its //go:embed patterns cover): every
    # package that imports it is affected too. A TEST seed is a package where
    # only test inputs changed (a _test.go file, testdata/, INVARIANTS.md,
    # anything not embedded): _test.go files compile into that package's own
    # test binary and nothing else, so its importers cannot see the change.
    code_seeds, test_seeds, why = set(), set(), {}

    def seed(pkg, code, reason):
        (code_seeds if code else test_seeds).add(pkg)
        why.setdefault(pkg, reason)

    def embedded(obj, rel):
        for pat in obj.get("EmbedPatterns") or []:
            pat = pat[len("all:"):] if pat.startswith("all:") else pat
            if fnmatch.fnmatchcase(rel, pat):
                return True
            parts = pat.split("/")
            while parts and GLOB_CHARS & set(parts[-1]):
                parts = parts[:-1]
            root = "/".join(parts)
            if root and (rel == root or rel.startswith(root + "/")):
                return True
        return False

    readers_needed = []
    for f in changed:
        pkg = owning_package(f)
        if pkg:
            obj = packages[pkg]
            rel = os.path.relpath(os.path.join(repo, f), obj["Dir"])
            if f.endswith("_test.go"):
                seed(pkg, False, f"test file {f}")
            elif f.endswith(".go"):
                seed(pkg, True, f"code file {f}")
            elif embedded(obj, rel):
                seed(pkg, True, f"embedded file {f}")
            else:
                seed(pkg, False, f"test input {f}")
        # Every changed file goes through rule 3, .go files too: a test may
        # read another package's source as text by path.
        readers_needed.append((f, pkg is None, not f.endswith(".go")))

    # Rule 3: packages whose Go literals name a changed file by path. A
    # literal in non-test code may be read at run time by any importer's
    # tests, so that is a code seed; a literal only in _test.go files is a
    # test seed.
    if readers_needed:
        for imp, obj in packages.items():
            code_files = [os.path.join(obj["Dir"], n) for k in ("GoFiles", "CgoFiles") for n in (obj.get(k) or [])]
            test_files = [os.path.join(obj["Dir"], n) for k in ("TestGoFiles", "XTestGoFiles") for n in (obj.get(k) or [])]
            code_index, test_index = literal_index(code_files), literal_index(test_files)
            code_hit = next((f for f, outside, by_base in readers_needed if references(code_index, f, outside, by_base)), None)
            if code_hit:
                seed(imp, True, f"its code names {code_hit}")
                continue
            test_hit = next((f for f, outside, by_base in readers_needed if references(test_index, f, outside, by_base)), None)
            if test_hit:
                seed(imp, False, f"its tests name {test_hit}")

    # security-closure rows: the pg-gated ones are only proven in the core-1
    # leg's check-closures step (ci.yml test-suite), so a change to the ledger
    # or its checker must run that leg.
    if any(f.startswith("docs/security-closures.d/") or f == "scripts/check-closures.sh" for f in changed):
        seed(MODULE + "/internal/core", False, "security-closure ledger or checker changed (core-1 leg proves pg-gated rows)")

    seeds = code_seeds | test_seeds
    affected = set(seeds)
    for imp, obj in packages.items():
        if imp in affected:
            continue
        if set(obj.get("Deps") or []) & code_seeds:
            affected.add(imp)
            continue
        timps = set((obj.get("TestImports") or []) + (obj.get("XTestImports") or []))
        if timps & code_seeds or any(code_seeds & set((packages.get(q) or {}).get("Deps") or []) for q in timps):
            affected.add(imp)

    legs = {}
    all_legs = leg_packages()
    for leg, pkgs in all_legs.items():
        hit = sorted(set(pkgs) & affected)
        if not hit:
            continue
        legs[leg] = "*" if SHARDED_SINGLE_PACKAGE.match(leg) else " ".join(hit)

    def touched(pred):
        return any(pred(f) for f in changed)

    # The server binary changed when compiled code it links changed: a CODE
    # seed among ./server and its Deps. A test seed there (a _test.go file,
    # testdata, a docs file its tests read) does not touch the image the
    # boot/demo/web smokes run. No ./server package at all: open the gates.
    server_obj = packages.get(SERVER_MAIN)
    server = server_obj is None or bool(code_seeds & ({SERVER_MAIN} | set(server_obj.get("Deps") or [])))
    web = touched(lambda f: f.startswith("web/"))
    cli = touched(lambda f: f.startswith("cli/"))
    image = touched(lambda f: f in ("server/Dockerfile", ".dockerignore", "web/Dockerfile", "web/.dockerignore", "Makefile"))
    helm = touched(lambda f: f.startswith(("deploy/helm/", ".github/testdata/helm")))
    golangci = touched(lambda f: f == ".golangci.yml")

    def module_readers(mod):
        files = list(module_go_files(mod))
        index = literal_index(files)
        return touched(lambda f: not f.startswith(mod + "/") and references(index, f, owning_package(f) is None))

    fuzz_files = [f for f in changed if f.endswith(".go") and any(
        re.search(r"^func Fuzz", file_at(rev, f), re.M) for rev in (base, head))]
    reach_pkgs = fuzz_reach_packages()

    gates = {
        "helm": helm,
        "helm_boot": helm or server or web or image,
        "docker_boot": server or web or image or touched(lambda f: f.startswith(("docker-compose", "keyorix.docker.yaml", "scripts/selfhost/"))),
        "demo": server or web or cli or image or touched(lambda f: f.startswith(("scripts/demo/", "scripts/totpgen/", "scripts/airgap-e2e.sh"))),
        "web_e2e": server or web or cli or image or touched(lambda f: f.startswith("scripts/e2e/")),
        "operator": golangci or touched(lambda f: f.startswith("operator/")) or module_readers("operator"),
        "migrate": golangci or touched(lambda f: f.startswith("migrate/")) or module_readers("migrate"),
        "fuzz_targets": bool(fuzz_files) or touched(lambda f: f.startswith("scripts/fuzzing/")),
        "fuzz_reach": reach_pkgs is None or bool(reach_pkgs & affected) or touched(lambda f: f.startswith("scripts/fuzzing/")),
    }
    return {
        **decision,
        "mode": "selected",
        "reason": f"{len(changed)} changed file(s) select {len(seeds)} package(s), {len(affected)} affected with importers",
        "seeds": {p: why[p] for p in sorted(seeds)},
        "affected": sorted(affected),
        "legs": legs,
        "total_legs": len(all_legs),
        "gates": gates,
        "fuzz_files": fuzz_files,
    }


ALL_GATES = ("helm", "helm_boot", "docker_boot", "demo", "web_e2e", "operator", "migrate", "fuzz_targets", "fuzz_reach")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base")
    ap.add_argument("--head", default="HEAD")
    # Testing hook (scripts/ci/select_affected_test.go): decide for this file
    # list against the working tree instead of a git diff.
    ap.add_argument("--changed", nargs="*")
    # Testing hook: raise this message as if decide() had failed, to pin the
    # fail-safe path (mode=full) and the single-line GITHUB_OUTPUT contract.
    ap.add_argument("--inject-failure")
    ap.add_argument("--github-output")
    ap.add_argument("--summary")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if args.changed is not None:
        args.base, args.head = None, None
        log(f"select-affected: {len(args.changed)} file(s) given with --changed")
    elif not args.base:
        ap.error("--base is required (or --changed for a test)")
    else:
        log(f"select-affected: diffing {args.base}..{args.head}")
    try:
        if args.inject_failure is not None:
            raise RuntimeError(args.inject_failure)
        d = decide(args.base, args.head, args.changed)
    except Exception as exc:  # fail safe: an error here must never skip a test
        d = {"base": args.base, "head": args.head, "changed": [], "mode": "full", "reason": f"selection failed ({type(exc).__name__}: {exc}); running everything"}

    if d["mode"] == "full":
        d["gates"] = {g: True for g in ALL_GATES}
        d["legs"] = {}
    log(f"select-affected: mode={d['mode']}: {one_line(d['reason'])}")
    if d["mode"] == "selected":
        log(f"select-affected: {len(d['legs'])} of {d['total_legs']} test-suite legs run:{', '.join(sorted(d['legs'])) or '(none)'}")
        for p, w in d["seeds"].items():
            log(f"  selected {p}: {w}")
    log("select-affected: gates " + " ".join(f"{g}={'run' if d['gates'][g] else 'skip'}" for g in ALL_GATES))

    if args.github_output:
        with open(args.github_output, "a", encoding="utf-8") as fh:
            fh.write(f"mode={one_line(d['mode'])}\n")
            fh.write(f"reason={one_line(d['reason'])}\n")
            fh.write(f"legs={one_line(json.dumps(d['legs'], separators=(',', ':'), sort_keys=True))}\n")
            for g in ALL_GATES:
                fh.write(f"gate_{g}={'true' if d['gates'][g] else 'false'}\n")
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write(f"### merge_group selection: {d['mode']}\n\n{one_line(d['reason'])}\n\n")
            if d["mode"] == "selected":
                fh.write(f"Changed files: {len(d['changed'])}. Test-suite legs that run ({len(d['legs'])}/{d['total_legs']}):{', '.join(sorted(d['legs'])) or 'none'}.\n\n")
                fh.write("| gate | decision |\n|---|---|\n")
                for g in ALL_GATES:
                    fh.write(f"| {g} | {'run' if d['gates'][g] else 'skip (inputs untouched)'} |\n")
                fh.write("\n<details><summary>Selected packages and why</summary>\n\n")
                for p, w in d["seeds"].items():
                    fh.write(f"- `{p}`: {w}\n")
                fh.write(f"\n{len(d['affected'])} affected packages including importers.\n\n</details>\n")
    if args.json:
        print(json.dumps(d, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
