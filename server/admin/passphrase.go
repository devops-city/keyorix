package admin

import (
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/spf13/cobra"
)

// registerPassphraseFlags adds the SAME byte-based master-passphrase source
// flags server/main.go's own main() registers (ADR-099): fd (strongest --
// never touches argv, an env var, or a path this process opens by name; the
// usual answer for systemd's LoadCredential=), file, and stdin. Never argv
// directly (task requirement 4) -- there is deliberately no --passphrase
// flag here, matching the server binary's own flag set exactly.
func registerPassphraseFlags(cmd *cobra.Command, src *crypto.PassphraseSource) {
	// RegisterPassphraseFlags, not IntVar: the fd is only honoured when
	// src.FDSet is true, which only its custom flag value sets, so a plain
	// IntVar silently ignored --passphrase-fd.
	crypto.RegisterPassphraseFlags(cmd.Flags(), src, "", "master passphrase")
}
