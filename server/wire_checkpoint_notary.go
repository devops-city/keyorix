package main

import (
	"crypto/x509"
	"fmt"
	"log"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/notary"
	"github.com/keyorixhq/keyorix/internal/secretenv"
)

// loadCertPool reads a PEM bundle from path and returns a cert pool of its
// certificates (the TSA trust anchor for verifying checkpoint anchors).
func loadCertPool(path string) (*x509.CertPool, error) {
	pem, err := secretenv.ReadRegularFile("CA bundle", path) // operator-configured trusted CA bundle path; a FIFO is refused, not waited on
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no PEM certificates found in %s", path)
	}
	return pool, nil
}

// wireCheckpointNotary wires external-notary anchoring of audit checkpoints when
// enabled (ADR-029): each written checkpoint gets an independent RFC 3161
// timestamp the server cannot forge. Anchoring is best-effort and only
// meaningful when checkpoints are written (which requires encryption).
func wireCheckpointNotary(cfg *config.Config, coreService *core.KeyorixCore) error {
	cn := cfg.Audit.CheckpointNotary
	if !cn.Enabled {
		return nil
	}
	if cn.URL == "" {
		log.Printf("Audit checkpoint notary enabled but no url set; skipping external anchoring")
		return nil
	}
	// NewRFC3161 validates the URL is https (or http to a loopback host, for
	// local testing) — fail closed at startup rather than silently accepting a
	// plaintext TSA URL that would leak every anchored checkpoint hash (and any
	// rogue-response substitution) to a network attacker on the path.
	tsa, err := notary.NewRFC3161(cn.URL, cn.GetTimeout())
	if err != nil {
		return fmt.Errorf("audit.checkpoint_notary: %w", err)
	}
	coreService.SetCheckpointNotary(tsa)
	// Load the TSA trust anchor (and its verifier — internal/notary.VerifyReceipt
	// is a free function, not a TimestampNotary method, so ADR-109 wires it
	// separately; see ports.VerifyReceiptFunc) used to VERIFY stored anchors.
	// Without it, anchoring still records each checkpoint's raw RFC 3161 receipt
	// — that token remains valid, portable proof an independent party holding
	// the TSA's root cert can check out-of-box (#182) — but THIS server cannot
	// re-verify it locally, and must not present a merely-recorded anchor as
	// though it were one this server actually checked against a root of trust.
	// Deliberately not fail-closed here (unlike the URL-scheme check above):
	// anchoring-without-local-verification is a legitimate, intentional
	// configuration (see CheckpointNotaryConfig.CACertPath's doc comment) —
	// the trust root can be wired in later, or verification can be done
	// entirely off-box. Instead, the unverifiable state is surfaced explicitly
	// on every checkpoint-verification read (KeyorixCore.CheckpointAnchorVerifiable,
	// AuditChainVerification.AnchorTrustRootConfigured) so a caller/auditor can
	// always tell a recorded-but-unverifiable anchor apart from a verified one.
	if cn.CACertPath == "" {
		log.Printf("Audit checkpoint external anchoring enabled (rfc3161, url=%s) — WARNING: no ca_cert_path set, stored anchors are recorded but CANNOT be locally verified (checkpoint reads will report them as unverified)", cn.URL)
		return nil
	}
	roots, err := loadCertPool(cn.CACertPath)
	if err != nil {
		log.Printf("Audit checkpoint notary: failed to load ca_cert_path %q (%v) — anchors cannot be verified", cn.CACertPath, err)
		return nil
	}
	coreService.SetCheckpointAnchorRoots(roots, notary.VerifyReceipt)
	log.Printf("Audit checkpoint external anchoring enabled (rfc3161, url=%s, timeout=%s, trust anchor=%s)", cn.URL, cn.GetTimeout(), cn.CACertPath)
	return nil
}
