// Package credstore persists the thin CLI's credentials. ADR-108 PR 0 decision
// (Andrei, 2026-09-23, docs/cli-split-inventory.md §4): one storage mechanism only -- no
// set-remote/use-local, no CWD-relative config file, no separate "connections" list. The
// default is a plaintext file at 0600 in the user config dir; an OS-keychain-backed
// implementation of the same Store interface is a later option, not decided here.
package credstore

// Credentials is everything the CLI needs to reach a server: the base URL and a bearer
// token (a long-lived API key/PAT, not a short-lived session -- there is no refresh flow,
// matching today's CLI per docs/cli-split-inventory.md §4). ActiveProject is the one piece
// of non-credential CLI state that survives the PR 0 collapse to a single file (docs/
// cli-split-inventory.md §4/§7 PR 6): the old CLI's separate `~/.keyorix/cli.yaml` carried
// it alongside Mode/Client/Connections, all of which PR 0 already dropped as dead or
// superseded; ActiveProject is the one field of that old file with a live caller (`project
// use`/`current`, and every project-scoped command's `--project` default) that PR 0's
// initial cut had no command needing yet. It lives here, in the ONE storage mechanism, not
// a second file -- the same "one storage mechanism only" decision PR 0 made for credentials.
type Credentials struct {
	ServerURL     string `yaml:"server_url"`
	Token         string `yaml:"token"`
	ActiveProject string `yaml:"active_project,omitempty"`
	// CAFile is the PEM CA/certificate file the CLI trusts for ServerURL's TLS certificate
	// (SECURE-DEFAULT-1: `keyorix-server admin init` generates a self-signed one). Set by
	// `keyorix config set ca_file` or by a successful `keyorix login` that used one. Not a
	// secret: it is a path to a public certificate.
	CAFile string `yaml:"ca_file,omitempty"`
}

// Store loads and saves Credentials. FileStore is the only implementation today; a future
// KeychainStore would implement this same interface with no caller-side change.
type Store interface {
	// Save persists c, replacing anything previously stored.
	Save(c Credentials) error
	// Load returns the stored credentials. It returns an error if none are stored, or if
	// the backing storage looks tampered with (e.g. a credentials file with permissions
	// wider than 0600) -- callers must treat that as "not logged in," not silently proceed
	// with whatever could be read.
	Load() (Credentials, error)
	// Clear removes any stored credentials. Clearing when none exist is not an error.
	Clear() error
}
