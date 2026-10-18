package crypto

import (
	"fmt"
	"strconv"

	"github.com/spf13/pflag"
)

// RegisterPassphraseFlags registers --{prefix}passphrase-fd/-file/-stdin on
// fs, backed by src, and returns the three flag names so the caller can mark
// them mutually exclusive (cobra.Command.MarkFlagsMutuallyExclusive takes the
// *cobra.Command, not a *pflag.FlagSet, so that step can't be done here).
// prefix is "" for the primary passphrase or "new-" for a second one. Uses a
// custom pflag.Value for the fd flag (not a plain IntVar) so src.FDSet is set
// if and only if the flag was actually passed — see PassphraseSource.FDSet's
// doc for why FD's zero value can't be used as a stand-in for "not set" (0 is
// stdin, a legitimate explicit choice).
//
// Moved here from internal/cli/common (which re-exports it) so a caller with
// no CLI-package dependency — e.g. server/admin, or this package's own
// internal/encryptionops consumer — can register these flags without pulling
// in internal/cli/common's much larger, CLI-specific dependency surface
// (internal/core, internal/storage, internal/delivery, internal/i18n).
func RegisterPassphraseFlags(fs *pflag.FlagSet, src *PassphraseSource, prefix, human string) (fdFlag, fileFlag, stdinFlag string) {
	fdFlag = prefix + "passphrase-fd"
	fileFlag = prefix + "passphrase-file"
	stdinFlag = prefix + "passphrase-stdin"
	fs.Var(&passphraseFDValue{dest: &src.FD, set: &src.FDSet}, fdFlag,
		"Read the "+human+" from this already-open file descriptor")
	fs.StringVar(&src.FilePath, fileFlag, "",
		"Read the "+human+" from this file (refused if group- or world-readable, or owned by anyone but you or root)")
	fs.BoolVar(&src.Stdin, stdinFlag, false,
		"Read the "+human+" from stdin")
	return fdFlag, fileFlag, stdinFlag
}

// passphraseFDValue implements pflag.Value for the --*passphrase-fd flag.
// Unlike pflag.IntVar, Set is only ever called when the flag is actually
// present on the command line, so *set becomes true exactly when the
// operator passed the flag — including --passphrase-fd=0, which a plain
// IntVar-backed `FD > 0` check couldn't distinguish from "not passed".
type passphraseFDValue struct {
	dest *int
	set  *bool
}

func (v *passphraseFDValue) String() string {
	if v.dest == nil {
		return "0"
	}
	return strconv.Itoa(*v.dest)
}

func (v *passphraseFDValue) Set(s string) error {
	n, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("invalid file descriptor %q: %w", s, err)
	}
	*v.dest = n
	*v.set = true
	return nil
}

func (v *passphraseFDValue) Type() string { return "int" }
