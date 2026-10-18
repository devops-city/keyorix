package cmd

import (
	"os"
	"strings"
	"sync"

	"github.com/spf13/cobra"
)

// The rule: a secret is never accepted as a flag or a positional argument, because
// argv is visible to every local user through ps and /proc and stays in shell history
// and CI logs. Every command that takes a secret reads it from a hidden prompt, from
// stdin, from a file, or from a KEYORIX_*[_FILE] environment variable.
//
// refusedSecretFlags lists the string flags that carry a secret. They are hidden from --help
// and refused when given, naming the safe way to supply the same value. The refusal is
// one wrapper over the whole tree (applySecretFlagPolicy), so it covers every flag in
// the list the same way and a command cannot forget it.
//
// KEYORIX_ALLOW_INSECURE_SECRET_FLAGS=1 turns the refusal back into the old warning, for
// scripts that have not been moved yet. It exists to migrate, not to stay on.
type secretFlag struct {
	Command string // command path without the leading "keyorix "
	Flag    string
	Instead string // what to do instead, in a sentence fragment
}

// #nosec G101 -- the NAME of an environment variable, not a credential.
const allowInsecureSecretFlagsEnv = "KEYORIX_ALLOW_INSECURE_SECRET_FLAGS"

var refusedSecretFlags = []secretFlag{
	{"login", "password", "set KEYORIX_PASSWORD (or KEYORIX_PASSWORD_FILE), or leave the flag out to be prompted"},
	{"login", "mfa-code", "set KEYORIX_MFA_CODE (or KEYORIX_MFA_CODE_FILE), or leave the flag out to be prompted"},
	{"mfa activate", "password", "set KEYORIX_PASSWORD (or KEYORIX_PASSWORD_FILE), or leave the flag out to be prompted"},
	{"mfa activate", "code", "set KEYORIX_MFA_CODE (or KEYORIX_MFA_CODE_FILE), or leave the flag out to be prompted"},
	{"mfa stepup", "code", "set KEYORIX_MFA_CODE (or KEYORIX_MFA_CODE_FILE), or leave the flag out to be prompted"},
	{"change-password", "current-password", "set KEYORIX_CURRENT_PASSWORD (or KEYORIX_CURRENT_PASSWORD_FILE), or leave the flag out to be prompted"},
	{"change-password", "new-password", "set KEYORIX_NEW_PASSWORD (or KEYORIX_NEW_PASSWORD_FILE), or leave the flag out to be prompted"},
	{"system init", "admin-password", "set KEYORIX_ADMIN_PASSWORD (or KEYORIX_ADMIN_PASSWORD_FILE), or leave the flag out to be prompted"},
	{"system init", "bootstrap-token", "set KEYORIX_BOOTSTRAP_TOKEN (or KEYORIX_BOOTSTRAP_TOKEN_FILE)"},
	{"user create", "password", "set KEYORIX_INITIAL_PASSWORD (or KEYORIX_INITIAL_PASSWORD_FILE), leave the flag out to be prompted, or use --setup-link or --one-time-password"},
	{"secret create", "value", "use --from-file <relative path> (or --from-file - to read stdin), or --interactive for a hidden prompt"},
	{"secret update", "value", "use --from-file <relative path> (or --from-file - to read stdin), or --interactive for a hidden prompt"},
	{"secret rotate", "value", "leave the flag out: the value is read from a hidden prompt, or from stdin when it is piped"},
	// A webhook URL is a credential: its path carries the token (Slack, Teams).
	{"notification channel add", "url", "use --url-file <relative path> (or --url-file - to read stdin)"},
	{"notification channel update", "url", "use --url-file <relative path> (or --url-file - to read stdin)"},
}

// notSecretFlags are string flags and positional arguments whose NAME looks like a
// secret but whose value is not one. Every entry says why; TestSecretFlagsAreAllClassified
// fails for a secret-looking name that is in neither list, so a new `--api-key` has to be
// either refused or explained here.
//
// #nosec G101 -- flag names and one-line reasons, no credentials.
var notSecretFlags = map[string]string{
	"trust keygen --key-id":                                       "a public key identifier",
	"config get <key>":                                            "the name of a CLI setting",
	"config set <key> <value>":                                    "the only setting is ca_file, a path (requireConfigKey)",
	"config unset <key>":                                          "the name of a CLI setting",
	"license install <token-file>":                                "path to a license file; the license is a signed token, verified offline",
	"machine token revoke <name|id> <token-id>":                   "a numeric token ID, not the token",
	"pat revoke <token-id>":                                       "a numeric token ID, not the token",
	"secret acl list <secret-id>":                                 "a numeric ID",
	"secret blast-radius <secret-id>":                             "a numeric ID",
	"secret cert <secret-id>":                                     "a numeric ID",
	"secret clear-schedule <secret-id>":                           "a numeric ID",
	"secret comment add <secret-id> <version-id> <comment>":       "a comment is visible metadata on the version, not a secret value",
	"secret comment delete <secret-id> <version-id> <comment-id>": "numeric IDs",
	"secret comment list <secret-id> <version-id>":                "numeric IDs",
	"secret deps add <secret-id> <depends-on-id>":                 "numeric IDs",
	"secret deps impact <secret-id>":                              "a numeric ID",
	"secret deps list <secret-id>":                                "a numeric ID",
	"secret deps rm <secret-id> <edge-id>":                        "numeric IDs",
	"secret explain <key-name>":                                   "the name of an environment variable, e.g. AWS_SECRET_ACCESS_KEY",
	"secret fix <key-name>":                                       "the name of an environment variable",
	"secret get-schedule <secret-id>":                             "a numeric ID",
	"secret set-schedule <secret-id>":                             "a numeric ID",
	"share self-remove <secret-id>":                               "a numeric ID",
}

var applySecretFlagPolicyOnce sync.Once

// applySecretFlagPolicy hides every flag in refusedSecretFlags and makes its command refuse the
// flag. Called from Execute (and tests) once the whole tree is built.
func applySecretFlagPolicy() {
	applySecretFlagPolicyOnce.Do(func() {
		byCommand := map[string][]secretFlag{}
		for _, sf := range refusedSecretFlags {
			byCommand[sf.Command] = append(byCommand[sf.Command], sf)
		}
		var walk func(c *cobra.Command)
		walk = func(c *cobra.Command) {
			for _, s := range c.Commands() {
				walk(s)
			}
			flags := byCommand[strings.TrimPrefix(c.CommandPath(), rootCmd.Name()+" ")]
			if len(flags) == 0 {
				return
			}
			for _, sf := range flags {
				if f := c.Flags().Lookup(sf.Flag); f != nil {
					f.Hidden = true
				}
			}
			switch {
			case c.RunE != nil:
				run := c.RunE
				c.RunE = func(cmd *cobra.Command, args []string) error {
					if err := refuseSecretFlags(cmd, flags); err != nil {
						return err
					}
					return run(cmd, args)
				}
			case c.Run != nil:
				run := c.Run
				c.Run = nil
				c.RunE = func(cmd *cobra.Command, args []string) error {
					if err := refuseSecretFlags(cmd, flags); err != nil {
						return err
					}
					run(cmd, args)
					return nil
				}
			}
		}
		walk(rootCmd)
	})
}

// refuseSecretFlags fails when one of the command's secret flags was given. It names the
// flag and the safe way to give the value; it never repeats the value.
func refuseSecretFlags(cmd *cobra.Command, flags []secretFlag) error {
	if os.Getenv(allowInsecureSecretFlagsEnv) == "1" {
		return nil // the command's own warnInsecureFlag still warns
	}
	for _, sf := range flags {
		if cmd.Flags().Changed(sf.Flag) {
			return usageErrorf("--%s is not accepted: a secret on the command line is visible to other users through ps "+
				"and stays in your shell history and CI logs. Instead: %s. (Scripts not yet moved can set %s=1 to get a "+
				"warning instead of this error.)", sf.Flag, sf.Instead, allowInsecureSecretFlagsEnv)
		}
	}
	return nil
}
