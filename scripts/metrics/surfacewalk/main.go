// Command surfacewalk lists the user-facing surface of a Keyorix source tree
// or build, one name per line, for scripts/metrics/complexity.sh.
//
// It is deliberately independent of the repository's own packages (it only reads
// files and runs binaries), so the same source measures every historical ref.
//
//	surfacewalk cobra   -bin PATH [-prefix admin]   commands and flags, by --help recursion
//	surfacewalk openapi -file openapi.yaml          "METHOD /path" per operation
//	surfacewalk grpc    -dir server/proto           "Service/Method" per rpc
//	surfacewalk env     -root DIR [-dirs a,b,c]     environment variable names read
//	surfacewalk npmlock -file pnpm-lock.yaml        direct and total packages
//	surfacewalk startup -bin B -dir-run D -url U    time to first 200 (median of runs) and idle peak RSS
//
// Progress and skips go to stderr; stdout carries only the data lines.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: surfacewalk cobra|openapi|grpc|env|npmlock|startup [flags]")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "surfacewalk %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}

func run(sub string, args []string) error {
	fs := flag.NewFlagSet(sub, flag.ContinueOnError)
	bin := fs.String("bin", "", "cobra: binary to walk")
	prefix := fs.String("prefix", "", "cobra: space-separated subcommand path to start from")
	file := fs.String("file", "", "openapi/npmlock: input file")
	dir := fs.String("dir", "", "grpc: directory searched for .proto files")
	root := fs.String("root", "", "env: repository root")
	dirs := fs.String("dirs", "", "env: comma-separated directories under -root to scan")
	workDir := fs.String("dir-run", "", "startup: working directory of the server (holds its config and data)")
	url := fs.String("url", "", "startup: health URL to poll")
	runs := fs.Int("runs", 5, "startup: number of starts")
	idle := fs.Duration("idle", 10*time.Second, "startup: idle window for the RSS sample")
	timeout := fs.Duration("timeout", 60*time.Second, "startup: give up on one start after this long")
	var envs multiFlag
	fs.Var(&envs, "env-var", "startup: KEY=VALUE for the server process (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var (
		lines []string
		err   error
	)
	switch sub {
	case "cobra":
		lines, err = cobraLines(*bin, strings.Fields(*prefix))
	case "openapi":
		lines, err = openapiOps(*file)
	case "grpc":
		lines, err = grpcMethods(*dir)
	case "env":
		var unresolved int
		lines, unresolved, err = envVars(*root, strings.Split(*dirs, ","))
		if err == nil && unresolved > 0 {
			fmt.Fprintf(os.Stderr, "surfacewalk env: %d lookups use a name that is not a string literal or a same-package/unique constant; not counted\n", unresolved)
		}
	case "npmlock":
		lines, err = npmLock(*file)
	case "startup":
		abs, aerr := filepath.Abs(*bin)
		if aerr != nil {
			return aerr
		}
		var res startupResult
		res, err = measureStartup(startupParams{
			Bin: abs, Dir: *workDir, URL: *url, Runs: *runs, Idle: *idle, Timeout: *timeout,
			Env: append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + *workDir}, envs...),
		})
		if err == nil {
			for _, ms := range res.ReadyMS {
				lines = append(lines, fmt.Sprintf("ready_ms %d", ms))
			}
			lines = append(lines, fmt.Sprintf("median_ms %d", res.medianMS()), fmt.Sprintf("peak_rss_kb %d", res.PeakRSSKB))
		}
	default:
		return fmt.Errorf("unknown subcommand %q", sub)
	}
	if err != nil {
		return err
	}
	for _, l := range lines {
		fmt.Println(l)
	}
	return nil
}
