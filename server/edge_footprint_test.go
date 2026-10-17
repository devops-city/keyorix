package main

// edge_footprint_test.go -- EDGE-1 footprint guard. A small board has a fixed
// amount of flash and RAM, and both only ever grow by accident: a new
// dependency, a package-level cache, a goroutine that starts at boot. This
// measures the two numbers a device is sized by, against a budget kept in
// scripts/edge/footprint-budget.tsv (set about 20% over the value when the
// guard was added, per platform and build profile):
//
//   - the size of the release binary (CGO_ENABLED=0, -trimpath, -s -w, full and
//     the air-gapped profile -tags noaws,noazure,nogcp), cross-built when the
//     target is not the host;
//   - the peak resident set size (RSS) of the server idle: started on a freshly
//     initialised SQLite install, healthy, no traffic for a few seconds, then
//     stopped; the peak includes the start-up spike.
//
// What it does not say: how much memory the server needs UNDER LOAD (this is the
// idle floor; a loaded server needs more, see docs/runtime-tuning.md), and it is
// a regression tripwire, not a benchmark. RSS is only checked for the host
// platform and only where the budget file has a value for it; a platform with no
// value yet is skipped loudly, never silently passed.
//
// Print the current values (to refresh the budget): scripts/edge/footprint.sh --print
// The set of targets built is KEYORIX_FOOTPRINT_TARGETS (comma list of
// goos/goarch, default: the host).

import (
	"bufio"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type footprintBudget struct {
	maxBinary int64 // bytes; 0 = no budget yet
	maxRSSKiB int64 // KiB; 0 = no budget yet
}

// loadFootprintBudget parses scripts/edge/footprint-budget.tsv:
// platform <TAB> profile <TAB> max_binary_bytes <TAB> max_idle_rss_kib ("-" = none).
func loadFootprintBudget(t *testing.T) map[string]footprintBudget {
	t.Helper()
	f, err := os.Open(filepath.Join(findServerRepoRoot(t), "scripts", "edge", "footprint-budget.tsv")) //nolint:gosec // repo file
	if err != nil {
		t.Fatalf("footprint budget: %v", err)
	}
	defer func() { _ = f.Close() }()
	out := map[string]footprintBudget{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) != 4 {
			t.Fatalf("footprint-budget.tsv: want 4 tab-separated columns, got %d in %q", len(cols), line)
		}
		num := func(s string) int64 {
			if s == "-" {
				return 0
			}
			n, err := strconv.ParseInt(s, 10, 64)
			if err != nil || n <= 0 {
				t.Fatalf("footprint-budget.tsv: %q is neither a positive integer nor '-': %v", s, err)
			}
			return n
		}
		key := cols[0] + " " + cols[1]
		if _, dup := out[key]; dup {
			t.Fatalf("footprint-budget.tsv: duplicate row for %s", key)
		}
		out[key] = footprintBudget{maxBinary: num(cols[2]), maxRSSKiB: num(cols[3])}
	}
	return out
}

func footprintTargets() []string {
	if v := os.Getenv("KEYORIX_FOOTPRINT_TARGETS"); v != "" {
		return strings.Split(v, ",")
	}
	return []string{runtime.GOOS + "/" + runtime.GOARCH}
}

var footprintProfiles = map[string][]string{
	"full":   nil,
	"airgap": {"-tags", "noaws,noazure,nogcp"},
}

func footprintPrint() bool { return os.Getenv("KEYORIX_FOOTPRINT_PRINT") == "1" }

// buildReleaseServer builds ./server the way the release does (Makefile
// release-build) and returns the path and size in bytes.
func buildReleaseServer(t *testing.T, platform, profile string) (string, int64) {
	t.Helper()
	goos, goarch, ok := strings.Cut(platform, "/")
	if !ok {
		t.Fatalf("KEYORIX_FOOTPRINT_TARGETS entry %q is not goos/goarch", platform)
	}
	out := filepath.Join(t.TempDir(), "keyorix-server")
	args := append([]string{"build", "-trimpath", "-ldflags", "-s -w", "-o", out}, footprintProfiles[profile]...)
	cmd := exec.Command("go", append(args, "./server")...) //nolint:gosec // fixed arguments
	cmd.Dir = findServerRepoRoot(t)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
	if goarch == "arm" {
		cmd.Env = append(cmd.Env, "GOARM=7") // linux/arm means armv7 (32-bit Raspberry Pi OS)
	}
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s %s: %v\n%s", platform, profile, err, b)
	}
	st, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	return out, st.Size()
}

func TestEdgeFootprint_BinarySize(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the server")
	}
	budget := loadFootprintBudget(t)
	profiles := make([]string, 0, len(footprintProfiles))
	for p := range footprintProfiles {
		profiles = append(profiles, p)
	}
	sort.Strings(profiles)
	for _, platform := range footprintTargets() {
		for _, profile := range profiles {
			t.Run(platform+"/"+profile, func(t *testing.T) {
				_, size := buildReleaseServer(t, platform, profile)
				b, has := budget[platform+" "+profile]
				if footprintPrint() {
					t.Logf("FOOTPRINT-PRINT binary %s %s %d", platform, profile, size)
					return
				}
				if !has || b.maxBinary == 0 {
					t.Fatalf("no binary-size budget for %s %s in scripts/edge/footprint-budget.tsv (measured %d bytes): add a row ~20%% above the measured value", platform, profile, size)
				}
				t.Logf("binary %s %s: %d bytes (budget %d)", platform, profile, size, b.maxBinary)
				if size > b.maxBinary {
					t.Errorf("%s %s binary is %d bytes, over the budget of %d. If the growth is intended, raise the row in scripts/edge/footprint-budget.tsv in the same PR and say why; otherwise find what linked in",
						platform, profile, size, b.maxBinary)
				}
			})
		}
	}
}

// peakRSSKiB is the peak resident set size of a process that has exited,
// from its rusage, in KiB. getrusage reports bytes on macOS and KiB elsewhere.
// Peak rather than a live sample: it needs no `ps` or /proc, so it is the same
// measurement on every platform, and it includes the start-up spike, which is
// what a device must have room for.
func peakRSSKiB(t *testing.T, ps *os.ProcessState) int64 {
	t.Helper()
	ru, ok := ps.SysUsage().(*syscall.Rusage)
	if !ok || ru == nil {
		t.Fatalf("no rusage for the exited server (%T)", ps.SysUsage())
	}
	if runtime.GOOS == "darwin" {
		return int64(ru.Maxrss) / 1024
	}
	return int64(ru.Maxrss)
}

func TestEdgeFootprint_IdleRSS(t *testing.T) {
	if testing.Short() {
		t.Skip("starts the server")
	}
	platform := runtime.GOOS + "/" + runtime.GOARCH
	budget := loadFootprintBudget(t)
	b := budget[platform+" full"]
	if !footprintPrint() && b.maxRSSKiB == 0 {
		t.Skipf("no idle-RSS budget for %s yet (pending a measured baseline on that platform: run scripts/edge/footprint.sh --print there and add the row)", platform)
	}

	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=edge-footprint-test-passphrase")
	for _, args := range [][]string{
		{"init", "--dev", "--config", "./keyorix.yaml"},
		{"encryption", "init", "--config", "./keyorix.yaml"},
		{"migrate", "--config", "./keyorix.yaml"},
	} {
		if out, err := runAdmin(t, bin, dir, env, args...); err != nil {
			t.Fatalf("admin %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	port := freeTCPPort(t)
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	raw, err := os.ReadFile(cfgPath) //nolint:gosec // test path
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Replace(string(raw), `port: "8080"`, `port: "`+port+`"`, 1)
	if text == string(raw) {
		t.Fatal("config template no longer has the 8080 port line this test rewrites")
	}
	if err := os.WriteFile(cfgPath, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin) //nolint:gosec // this suite's own binary
	cmd.Dir, cmd.Env = dir, append(env, "KEYORIX_CONFIG_PATH=./keyorix.yaml")
	logf, err := os.Create(filepath.Join(dir, "server.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logf.Close() }()
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	defer func() { _ = cmd.Process.Kill(); <-exited }()

	deadline := time.Now().Add(45 * time.Second)
	healthy := false
	for time.Now().Before(deadline) && !healthy {
		select {
		case <-exited:
			log, _ := os.ReadFile(filepath.Join(dir, "server.log")) //nolint:gosec // test path
			t.Fatalf("server exited before becoming healthy:\n%s", log)
		default:
		}
		if resp, err := http.Get("http://127.0.0.1:" + port + "/health"); err == nil { //nolint:gosec,noctx // loopback test URL
			_ = resp.Body.Close()
			healthy = resp.StatusCode == http.StatusOK
		}
		if !healthy {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if !healthy {
		t.Fatal("server never became healthy")
	}

	// Idle: start-up work (the schedulers' first tick, GC of init garbage) settles,
	// nothing else is asked of the server, then it is stopped the way a service
	// manager stops it and its peak resident size is read.
	time.Sleep(8 * time.Second)
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-exited:
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		<-exited
	}
	rss := peakRSSKiB(t, cmd.ProcessState)
	if footprintPrint() {
		t.Logf("FOOTPRINT-PRINT rss %s full %d", platform, rss)
		return
	}
	t.Logf("idle peak RSS %s: %d KiB (budget %d KiB)", platform, rss, b.maxRSSKiB)
	if rss > b.maxRSSKiB {
		t.Errorf("peak RSS of a started, idle server is %d KiB, over the budget of %d KiB. If the growth is intended, raise the row in scripts/edge/footprint-budget.tsv in the same PR and say why; otherwise find what allocates at start-up",
			rss, b.maxRSSKiB)
	}
}

func TestFootprintBudgetFile_IsWellFormed(t *testing.T) {
	budget := loadFootprintBudget(t)
	if len(budget) == 0 {
		t.Fatal("footprint-budget.tsv has no rows")
	}
	for key := range budget {
		platform, profile, ok := strings.Cut(key, " ")
		if !ok || !strings.Contains(platform, "/") {
			t.Errorf("row %q: want '<goos>/<goarch> <profile>'", key)
		}
		if _, known := footprintProfiles[profile]; !known {
			t.Errorf("row %q: unknown profile %q (known: full, airgap)", key, profile)
		}
	}
}
