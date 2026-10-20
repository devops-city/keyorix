// consistency.go — the boot-time key-file-set consistency check (ADR-112,
// follow-up from #2400). #2400 made a single RESTORE operation atomic: every
// file in the key-material set it installs is either all written or none
// are. What it does not (and cannot) catch is a set assembled across
// MULTIPLE operations — a second, partial restore; a manually copied-in
// file; one file restored from an older backup than its neighbors. This
// file adds the missing boot-time check for exactly that.
package keyfiles

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
)

// keySetMtimeTolerance is how far apart two files WITHIN THE SAME key-file
// group (see keyEstablishingGroups) may be modified before
// VerifyKeySetConsistency flags the group as mixed from different
// generations. Generous on purpose: every legitimate path that writes a whole
// group together writes it within one operation, seconds apart at most.
//
// BEST-EFFORT, and deliberately not claimed as a guarantee anywhere —
// docs/adr-conformance-enforced.d/ only asserts the presence/absence half.
// An mtime gap is weak evidence in BOTH directions:
//
//   - A set genuinely assembled from two different backups usually shows NO
//     gap. `cp`, `install`, `docker cp` and `kubectl cp` all stamp the
//     destination with the current time, so the most common ways an operator
//     hand-assembles a key directory erase exactly the signal this looks for.
//     (`cp -p`, `rsync -a` and `tar -xp` do preserve mtimes, which is the
//     narrow case where it helps.)
//   - mtime is freely writable by anyone who can write the file, so it is no
//     evidence at all against a deliberate attacker.
//
// So this catches an honest mistake in a preserving-copy workflow, and
// nothing more. The real fix is an atomically written key-set manifest
// (generation id plus per-file hash) verified at boot — see #2900 — which
// does not depend on filesystem metadata at all.
const keySetMtimeTolerance = 24 * time.Hour

// allProviders returns the primary key provider followed by its fallbacks.
// It deliberately appends without a precomputed capacity: a `1+len(...)`
// size computation feeding make() is flagged by CodeQL as a possible
// allocation-size overflow, and the saving is irrelevant for a handful of
// providers.
func allProviders(enc *config.EncryptionConfig) []config.KeyProviderConfig {
	providers := []config.KeyProviderConfig{enc.KeyProvider}
	return append(providers, enc.KeyProvider.Fallbacks...)
}

// RequiredKeyFilePaths returns every on-disk key-material path enc's config
// requires to exist as a consistent set: the salt, the DEK, and (for the
// primary provider and each fallback, one level — matching Registry's own
// documented choice) the KMS/TPM wrapped-key blob and Shamir share files.
//
// Unlike Registry (registry.go), which only includes an OPTIONAL file (the
// .pending rotation-staging siblings) when it is CURRENTLY present, every
// path this function returns is unconditional: it names what the config
// says MUST exist, regardless of whether it currently does.
// VerifyKeySetConsistency needs exactly that distinction to tell "a
// legitimately-absent optional file" apart from "a required file missing
// from an otherwise-present set" — Registry's own return value can't make
// that distinction once an optional file has already been filtered out.
func RequiredKeyFilePaths(enc *config.EncryptionConfig, baseDir string) ([]string, error) {
	if enc == nil {
		return nil, nil
	}
	var paths []string
	seen := make(map[string]bool)
	add := func(label, path string) error {
		if path == "" {
			return nil
		}
		clean, err := SafePath(label, path)
		if err != nil {
			return err
		}
		full := resolve(baseDir, clean)
		if seen[full] {
			return nil
		}
		seen[full] = true
		paths = append(paths, full)
		return nil
	}
	if err := add("KEK salt", enc.SaltPath); err != nil {
		return nil, err
	}
	if err := add("DEK", enc.DEKPath); err != nil {
		return nil, err
	}
	providers := allProviders(enc)
	for i := range providers {
		kp := &providers[i]
		if writeCapableProviderTypes[kp.Type] {
			if err := add(kp.Type+" wrapped KEK", kp.WrappedKeyPath); err != nil {
				return nil, err
			}
		}
		if kp.Type == "shamir" {
			for j, share := range kp.ShamirShareFiles {
				if err := add(fmt.Sprintf("shamir share file [%d]", j), share); err != nil {
					return nil, err
				}
			}
		}
	}
	return paths, nil
}

// keyFileGroup is a set of key files that one provisioning operation writes
// TOGETHER, and whose members therefore have no legitimate reason to differ
// in age. label names the group for the error message.
type keyFileGroup struct {
	label string
	paths []string
}

// keyEstablishingGroups partitions the required key files into the groups a
// single operation actually writes, which is what the mtime check compares
// within.
//
// Grouping per OPERATION, not across the whole set, is the correction to this
// check's first shape. Comparing every KEK-establishing file against the
// oldest one in the set produced a false refusal on an ordinary, documented
// rotation: commitNewKEKFiles (`keyorix-server admin encryption rotate-kek`) rewrites only
// the salt and the DEK, so a deployment with a passphrase KEK plus a
// KMS/TPM/Shamir fallback leaves that fallback's wrapped-key blob at its
// original age. Weeks later the gap exceeds any tolerance and the server
// refuses to boot, having been asked to do nothing unusual. A check that
// fails closed on an intended operation does not make a deployment safer; it
// gets switched off.
//
// The groups, and why each is one operation:
//
//   - the KEK salt, alone. It is written by first-boot ensureSaltExists and
//     rewritten by commitNewKEKFiles, neither of which touches any provider
//     blob. One member, so nothing to compare — correct, not a gap: the
//     salt's age genuinely carries no information about any other file's.
//   - each write-capable provider's wrapped-KEK blob, alone. Each provider
//     re-wraps its own blob on its own schedule.
//   - each Shamir provider's share files, together. The split writes all
//     shares in one operation, so shares from different generations in one
//     provider really is an inconsistent set — and this is the only group
//     with more than one member, i.e. the only place the mtime check can
//     still say anything.
//
// The DEK is excluded entirely: RotateDEKWithSweep re-wraps it under the SAME
// KEK on its own schedule (ADR-046, or a manual `rotate-dek`) without
// touching anything else, so its age is independent by design.
func keyEstablishingGroups(enc *config.EncryptionConfig, baseDir string) ([]keyFileGroup, error) {
	if enc == nil {
		return nil, nil
	}
	resolveOne := func(label, path string) (string, error) {
		if path == "" {
			return "", nil
		}
		clean, err := SafePath(label, path)
		if err != nil {
			return "", err
		}
		return resolve(baseDir, clean), nil
	}

	var groups []keyFileGroup
	saltFull, err := resolveOne("KEK salt", enc.SaltPath)
	if err != nil {
		return nil, err
	}
	if saltFull != "" {
		groups = append(groups, keyFileGroup{label: "KEK salt", paths: []string{saltFull}})
	}

	providers := allProviders(enc)
	for i := range providers {
		kp := &providers[i]
		if writeCapableProviderTypes[kp.Type] {
			full, rerr := resolveOne(kp.Type+" wrapped KEK", kp.WrappedKeyPath)
			if rerr != nil {
				return nil, rerr
			}
			if full != "" {
				groups = append(groups, keyFileGroup{
					label: fmt.Sprintf("%s wrapped KEK (provider %d)", kp.Type, i),
					paths: []string{full},
				})
			}
		}
		if kp.Type == "shamir" && len(kp.ShamirShareFiles) > 0 {
			shares := make([]string, 0, len(kp.ShamirShareFiles))
			for j, share := range kp.ShamirShareFiles {
				full, rerr := resolveOne(fmt.Sprintf("shamir share file [%d]", j), share)
				if rerr != nil {
					return nil, rerr
				}
				if full != "" {
					shares = append(shares, full)
				}
			}
			if len(shares) > 0 {
				groups = append(groups, keyFileGroup{
					label: fmt.Sprintf("shamir share set (provider %d)", i),
					paths: shares,
				})
			}
		}
	}
	return groups, nil
}

// VerifyKeySetConsistency is the boot-time key-file-set consistency check.
// Two checks, with deliberately different strengths — and the difference is
// the point, because only one of them is sound enough to be claimed in
// docs/adr-conformance-enforced.d/:
//
//  1. PRESENCE/ABSENCE (the real guarantee). The installed key files must
//     either ALL be present (an already-provisioned deployment) or ALL be
//     absent (a fresh install, about to generate them) — never a PARTIAL set,
//     which no legitimate provisioning path produces. Decidable from os.Stat
//     alone, and unfoolable by how the files were put there.
//
//  2. SAME-GROUP MTIME (best-effort only, NOT a guarantee). Within each group
//     of files one operation writes together (keyEstablishingGroups), ages
//     must fall within keySetMtimeTolerance of the group's oldest. See
//     keySetMtimeTolerance for why this is weak evidence in both directions:
//     plain cp/install/docker cp/kubectl cp erase the signal, and mtime is
//     writable by anyone who can write the file. It is kept because it costs
//     nothing and does catch an honest mistake in a preserving-copy workflow.
//     The mixed-generation guarantee it used to be presented as is gone from
//     the ledger (Andrei, 2026-10-06); #2900 tracks the manifest that can
//     actually provide one.
//
// A leftover "*.pending" rotation-staging sibling is deliberately NOT part of
// the required set (RequiredKeyFilePaths never adds one, unlike Registry), so
// an interrupted rotation cannot be misread as a partial set. The converse —
// detecting that an interrupted rotation left the ACTIVE set incoherent, e.g.
// commitNewKEKFiles crashing after the DEK rename but before the salt rename —
// is out of scope here and is explicitly part of #2900: the two on-disk states
// that matter (harmless abandoned staging vs. a DEK that no longer unwraps
// under the on-disk salt) are indistinguishable from file presence and mtimes
// alone, and need the manifest's per-file hashes to tell apart. Guarded by
// TestVerifyKeySetConsistency_LeftoverPendingFiles_AreNotAPartialSet.
//
// Both checks fail closed, with every file path named — the ADR's own
// wording ("fail closed with a clear message naming the files"). Called
// unconditionally at boot (server/main.go), not gated behind
// security.enable_file_permission_check: a partial key set is not a "weaker
// but working" state the way that flag's other checks guard — it is already
// broken, just not yet in a way that has surfaced.
func VerifyKeySetConsistency(enc *config.EncryptionConfig, baseDir string) error {
	if enc == nil {
		return nil
	}
	paths, err := RequiredKeyFilePaths(enc, baseDir)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return nil
	}

	infos := make(map[string]os.FileInfo, len(paths))
	var present, missing []string
	for _, p := range paths {
		info, statErr := os.Stat(p)
		if statErr != nil {
			missing = append(missing, p)
			continue
		}
		present = append(present, p)
		infos[p] = info
	}

	if len(missing) > 0 && len(present) > 0 {
		sort.Strings(present)
		sort.Strings(missing)
		return fmt.Errorf(
			"key material is an incomplete set: present (%s); missing (%s) — this is not a state any "+
				"provisioning path produces; restore the full set from one backup, or remove the partial "+
				"files and let first-boot generation recreate them",
			strings.Join(present, ", "), strings.Join(missing, ", "))
	}
	if len(present) == 0 {
		return nil // fresh install — first-boot generation will create these shortly
	}

	groups, err := keyEstablishingGroups(enc, baseDir)
	if err != nil {
		return err
	}
	var mismatched []string
	for _, g := range groups {
		if len(g.paths) < 2 {
			continue // one file's age says nothing about any other's
		}
		var oldestPath string
		var oldest time.Time
		for _, p := range g.paths {
			info, ok := infos[p]
			if !ok {
				continue // not in the fully-present set checked above (defensive)
			}
			if oldest.IsZero() || info.ModTime().Before(oldest) {
				oldest = info.ModTime()
				oldestPath = p
			}
		}
		if oldestPath == "" {
			continue
		}
		for _, p := range g.paths {
			info, ok := infos[p]
			if !ok {
				continue
			}
			if gap := info.ModTime().Sub(oldest); gap > keySetMtimeTolerance {
				mismatched = append(mismatched, fmt.Sprintf("%s: %s (modified %s, %s after %s)",
					g.label, p, info.ModTime().Format(time.RFC3339), gap.Round(time.Minute), oldestPath))
			}
		}
	}
	if len(mismatched) > 0 {
		sort.Strings(mismatched)
		return fmt.Errorf(
			"key material group looks mixed from different generations: %s — this is a BEST-EFFORT mtime "+
				"heuristic (see keySetMtimeTolerance): if these files genuinely belong together, it is a "+
				"false positive and you can touch(1) them to a common time; otherwise restore the whole "+
				"group from a single backup",
			strings.Join(mismatched, "; "))
	}
	return nil
}
