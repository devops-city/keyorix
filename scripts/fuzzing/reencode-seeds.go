//go:build ignore

// reencode-seeds.go migrates FuzzStorageFaultOperations' committed seed corpus
// from the legacy index-addressed format to the v2 key-addressed format
// (server/faultops/seed_v2_test.go), in one step:
//
//  1. re-encodes every legacy seed under
//     server/faultops/testdata/fuzz/FuzzStorageFaultOperations/ as v2
//     (TestReencodeLegacySeedsToV2 with REENCODE_SEEDS_V2=1): each seed is
//     encoded from what it was WRITTEN for (server/faultops/testdata/
//     seed_v1_history, recovered from git history), or from seedIntent where
//     that table overrides it; a seed with no history row is refused;
//  2. switches the three decode call sites (the fuzz loop, the REPLAY_HEX
//     tracer, the corpus pin test) from decodeFuzzOp to decodeFuzzOpAny —
//     one line each, refusing if a site does not match exactly once;
//  3. runs the v2 guards and the pin test to confirm the result.
//
// Step 2 edits server/faultops/fuzz_storage_fault_operations_test.go, a
// serialized hotspot file, and step 1 rewrites seed files: run this ONLY as
// the coordinator, in a quiet merge window, then commit everything together.
// Idempotent: already-v2 seeds are skipped and already-switched call sites
// are left alone, so a second run changes nothing.
//
// Usage (repo root):
//
//	go run scripts/fuzzing/reencode-seeds.go            # migrate
//	go run scripts/fuzzing/reencode-seeds.go -dry-run   # report call-site state only
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	legacyCall = "decoded, ok := decodeFuzzOp(data)"
	v2Call     = "decoded, ok := decodeFuzzOpAny(data)"
)

var callSites = []string{
	"server/faultops/fuzz_storage_fault_operations_test.go",
	"server/faultops/replay_test.go",
	"server/faultops/opcatalog_corpus_pin_test.go",
}

func main() {
	dry := flag.Bool("dry-run", false, "report what would change, write nothing")
	flag.Parse()

	root, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	must(err, "locating repo root")
	if err := os.Chdir(strings.TrimSpace(string(root))); err != nil {
		must(err, "chdir to repo root")
	}

	// Validate every call site before writing anything.
	type site struct {
		path    string
		src     string
		pending bool
	}
	var sites []site
	for _, p := range callSites {
		b, err := os.ReadFile(p)
		must(err, "reading "+p)
		s := string(b)
		legacy, v2 := strings.Count(s, legacyCall), strings.Count(s, v2Call)
		switch {
		case legacy == 1 && v2 == 0:
			sites = append(sites, site{p, s, true})
		case legacy == 0 && v2 == 1:
			sites = append(sites, site{p, s, false})
		default:
			fail(fmt.Sprintf("%s: expected exactly one %q (or one %q if already migrated), found %d and %d — "+
				"the file changed shape; update callSites/this tool before migrating", p, legacyCall, v2Call, legacy, v2))
		}
	}
	for _, s := range sites {
		state := "already v2"
		if s.pending {
			state = "will switch to decodeFuzzOpAny"
		}
		fmt.Printf("call site %s: %s\n", s.path, state)
	}
	if *dry {
		return
	}

	// 1. Re-encode the corpus (reads seeds with the legacy decoder, so it must
	//    run before the call sites switch — it does not depend on them).
	run([]string{"REENCODE_SEEDS_V2=1"}, "go", "test", "-count=1", "-v",
		"-run", "^TestReencodeLegacySeedsToV2$", "./server/faultops/")

	// 2. Switch the call sites.
	for _, s := range sites {
		if !s.pending {
			continue
		}
		out := strings.Replace(s.src, legacyCall, v2Call, 1)
		must(os.WriteFile(s.path, []byte(out), 0o644), "writing "+s.path)
		fmt.Printf("switched %s\n", s.path)
	}

	// 3. Verify.
	run(nil, "go", "test", "-count=1", "-run",
		"^(TestCommittedV2Seeds_Resolve|TestCommittedV2Seeds_RequireV2Decoder|TestSeedIntent_TableResolves|TestReportSeedIntentDrift|TestSeedV2_RoundTripAndUniqueHashes|TestOpcatalogCorpusFilesTargetPinnedOps)$",
		"./server/faultops/")
	fmt.Println("ok: corpus is v2; commit", filepath.Join("server", "faultops"), "(seeds + the three call sites) together.",
		"Then run the full `go test ./server/faultops/` before pushing.")
}

func run(env []string, name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		fail(fmt.Sprintf("%s %s: %v", name, strings.Join(args, " "), err))
	}
}

func must(err error, what string) {
	if err != nil {
		fail(what + ": " + err.Error())
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "FAIL:", msg)
	os.Exit(1)
}
