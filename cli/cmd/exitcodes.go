package cmd

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

// Process exit codes. They are part of the CLI's contract (scripts branch on them) and
// are documented in `keyorix --help`; TestExitCodesAreDocumented keeps that text and
// this list in step.
const (
	exitOK         = 0
	exitFailure    = 1 // the server or the command refused the request (conflict, validation, 5xx, ...)
	exitUsage      = 2 // bad flags or arguments; nothing was sent to the server
	exitAuth       = 3 // not logged in, or the server rejected the session (HTTP 401)
	exitPermission = 4 // logged in but not allowed (HTTP 403)
	exitNotFound   = 5 // the thing asked about does not exist (HTTP 404)
	exitUnreach    = 6 // the server could not be reached: network, TLS certificate refused, redirect
)

const exitCodesHelp = `Exit codes:
  0  success
  1  the request was refused or failed (conflict, validation error, server error); "doctor": a check failed
  2  usage error: unknown command, bad or missing flag or argument
  3  not logged in, or the session was rejected (HTTP 401): run "keyorix login"
  4  permission denied (HTTP 403)
  5  not found (HTTP 404)
  6  the server could not be reached (network, TLS certificate refused, redirect)`

// exitError attaches an exit code to an error without changing its text.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func withExitCode(code int, err error) error {
	if err == nil {
		return nil
	}
	return &exitError{code: code, err: err}
}

// usageErrorf is fmt.Errorf for a mistake in the flags or arguments the user gave.
func usageErrorf(format string, a ...any) error {
	return withExitCode(exitUsage, fmt.Errorf(format, a...))
}

// statusExitCode maps an HTTP status the server answered with to an exit code.
func statusExitCode(status int) int {
	switch status {
	case http.StatusUnauthorized:
		return exitAuth
	case http.StatusForbidden:
		return exitPermission
	case http.StatusNotFound:
		return exitNotFound
	}
	return exitFailure
}

// classifyError returns the exit code for err and the message to print. reachedBody
// says whether the command's own code had started: an error before that point is a
// problem with how the CLI was invoked.
func classifyError(err error, reachedBody bool) (code int, msg string) {
	if err == nil {
		return exitOK, ""
	}
	if te, ok := apiclient.DescribeTransportError(err); ok {
		return exitUnreach, te
	}
	if ee, ok := errors.AsType[*exitError](err); ok {
		return ee.code, err.Error()
	}
	if !reachedBody {
		return exitUsage, err.Error()
	}
	return exitFailure, err.Error()
}

// statusHint is the " Next step: ..." suffix for an HTTP status that has one fixed
// remedy whatever the endpoint. action is what was being attempted: the sign-in
// flows get none for 401, since "log in again" is not an answer to a wrong password.
func statusHint(action string, status int) string {
	switch status {
	case http.StatusUnauthorized:
		switch {
		case strings.HasPrefix(action, "login"), strings.Contains(action, "second-factor"),
			strings.HasPrefix(action, "MFA"), strings.HasPrefix(action, "change password"),
			strings.HasPrefix(action, "bootstrap"):
			return ""
		}
		return " Next step: run `keyorix login` to sign in again (the session may have expired or been revoked)."
	case http.StatusForbidden:
		return " Next step: you do not have permission for this; ask a project admin, or request access with `keyorix request access`."
	}
	return ""
}

// Run executes the CLI with args (os.Args[1:] when nil), prints a failure to stderr
// as one readable message and returns the process exit code. A panic is reported as
// an internal error with a one-line pointer instead of a Go stack trace; set
// KEYORIX_DEBUG=1 to see the trace.
func Run(args []string, stderr io.Writer) (code int) {
	defer func() {
		if r := recover(); r != nil {
			_, _ = fmt.Fprintf(stderr, "Error: internal error: %v\nThis is a bug in keyorix. Re-run with KEYORIX_DEBUG=1 for a stack trace and report it with the output of `keyorix version`.\n", r)
			if os.Getenv("KEYORIX_DEBUG") == "1" {
				_, _ = fmt.Fprintf(stderr, "%s\n", debug.Stack())
			}
			code = exitFailure
		}
	}()
	if args != nil {
		rootCmd.SetArgs(args)
	}
	bodyStarted = false
	err := Execute()
	if err == nil {
		return exitOK
	}
	code, msg := classifyError(err, bodyStarted)
	_, _ = fmt.Fprintln(stderr, "Error:", msg)
	if code == exitUsage && !strings.Contains(msg, "--help") {
		_, _ = fmt.Fprintln(stderr, "Run with --help for usage.")
	}
	return code
}

// bodyStarted is set by the first thing rootCmd's PersistentPreRunE does, which runs
// after cobra has parsed the flags and validated the arguments; an error returned
// before then is a usage error.
var bodyStarted bool

// rootPreRun marks the command body as started, then checks required flags itself
// (cobra checks them after the pre-run hooks) so that a missing one is also a usage
// error rather than a generic failure.
func rootPreRun(cmd *cobra.Command, _ []string) error {
	bodyStarted = true
	cmd.SilenceUsage = true
	if err := cmd.ValidateRequiredFlags(); err != nil {
		return withExitCode(exitUsage, err)
	}
	if err := cmd.ValidateFlagGroups(); err != nil {
		return withExitCode(exitUsage, err)
	}
	return nil
}

// groupRun is the body of a command that only groups subcommands. Cobra treats such a
// command as not runnable and prints its help for ANY arguments, so a typo like
// `keyorix secret lst` exited 0 with a screen of help. Making the group runnable lets
// it refuse what it does not know.
func groupRun(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return cmd.Help()
	}
	msg := fmt.Sprintf("unknown command %q for %q", args[0], cmd.CommandPath())
	if s := cmd.SuggestionsFor(args[0]); len(s) > 0 {
		msg += "\n\nDid you mean this?\n\t" + strings.Join(s, "\n\t")
	}
	return usageErrorf("%s\nRun '%s --help' for the list of commands", msg, cmd.CommandPath())
}

var applyErrorPolishOnce sync.Once

// applyErrorPolish makes a mistyped subcommand of a group an error. Called from
// Execute (and tests) once the command tree is built.
func applyErrorPolish() {
	applyErrorPolishOnce.Do(func() { applyGroupArgs(rootCmd) })
}

// noPositionalArgs is Args for a leaf command whose Use shows no positional argument:
// cobra's default accepts and silently drops them, so `keyorix secret get 42` ran with
// no --id and failed on that, far from the real mistake.
func noPositionalArgs(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return nil
	}
	return usageErrorf("unexpected argument %q: %q takes none, pass values as flags (see `%s --help`)",
		args[0], cmd.CommandPath(), cmd.CommandPath())
}

func applyGroupArgs(c *cobra.Command) {
	for _, s := range c.Commands() {
		applyGroupArgs(s)
	}
	if c != rootCmd && c.HasSubCommands() && !c.Runnable() {
		c.RunE = groupRun
		return
	}
	if !c.HasSubCommands() && c.Args == nil && !strings.ContainsAny(c.Use, "<[") {
		c.Args = noPositionalArgs
	}
}
