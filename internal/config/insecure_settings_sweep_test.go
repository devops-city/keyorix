// insecure_settings_sweep_test.go — the half of ADR-112's opt-out rule that
// looks OUTWARD, at Config, instead of inward at the registry.
//
// The coordinator's 2026-10-06 review named the gap precisely: the registry's
// own structural test validates only entries ALREADY in the registry, and since
// every entry's Name is a synthetic insecure_-prefixed path whether or not the
// YAML key was renamed, that test passes no matter what Config grows next to
// it. "There is no violation count for an exception to be excluded from,
// because no sweep of the config surface exists." This file is that sweep.
//
// It has two nets, because one is provably not enough:
//
//  1. A LEXICAL net over every leaf in Config's YAML surface: a key whose name
//     reads like an opt-out (allow_, disable, skip_, unsafe, insecure_,
//     keyless) must be covered by a registry entry's SourcePaths or carry a
//     written exemption. This catches the common shape and names the offender
//     exactly.
//
//  2. A SET ratchet over the same surface (testdata/config_surface_leaves.txt).
//     This is not belt-and-braces: half the known exceptions prove the lexical
//     net cannot see them — membership.validation_mode,
//     storage.database.ssl_mode, credential_delivery.mode,
//     credential_delivery.smtp.tls, notifications.email.tls,
//     server.http.metrics_token and server.http.max_request_body_bytes are
//     all security-weakening in some value, and not one of them contains a word a pattern list would flag. A
//     new field of that kind would sail straight through net 1. Net 2 cannot
//     miss it: ANY added, removed or renamed leaf anywhere in Config fails, and
//     the failure message states the two legitimate ways to resolve it.
//
// What this does NOT claim: that it can tell a weakening setting from a benign
// one by itself. Net 1 guesses from the name and net 2 refuses to guess at all,
// forcing a human classification on every addition. That is the whole design —
// the thing being prevented is a weakening setting entering the codebase with
// NOBODY having looked at it, not a wrong guess about which it is.
package config

import (
	"fmt"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
)

// configLeaf is one scalar (non-struct) field on Config's YAML surface.
type configLeaf struct {
	Path string       // dotted YAML path, slices flattened (no [] marker)
	Kind reflect.Kind // the leaf's Go kind, for the failure message's benefit
}

// configSurfaceLeaves walks Config and returns every leaf YAML path.
//
// Slices and pointers are flattened to their element type, so a per-provider
// setting appears once as sso.providers.insecure_trust_saml_asserted_email
// rather than being invisible behind the slice — that is the same path spelling the registry's
// SourcePaths use. `yaml:"-"` fields are skipped: they are never settable from
// a config file, so they are not part of the opt-out surface (that is how
// SecurityConfig.EnableFilePermissionCheckImplicitDefault, a derived field,
// stays out of this sweep).
//
// Recursion stops on a type already on the current path, which is what keeps
// KeyProviderConfig.Fallbacks ([]KeyProviderConfig, self-referential) from
// expanding forever. One level is the right depth anyway, and not an
// approximation chosen here: keyProviderChain and internal/keyfiles.Registry
// both already read exactly one level of Fallbacks, so a deeper nesting is not
// a live configuration shape.
func configSurfaceLeaves() []configLeaf {
	var leaves []configLeaf
	var walk func(t reflect.Type, prefix string, onPath map[reflect.Type]bool)
	walk = func(t reflect.Type, prefix string, onPath map[reflect.Type]bool) {
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct || onPath[t] {
			return
		}
		onPath[t] = true
		defer delete(onPath, t)

		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" { // unexported: not YAML-settable
				continue
			}
			name := strings.Split(f.Tag.Get("yaml"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = strings.ToLower(f.Name)
			}
			path := name
			if prefix != "" {
				path = prefix + "." + name
			}
			ft := f.Type
			for ft.Kind() == reflect.Pointer || ft.Kind() == reflect.Slice || ft.Kind() == reflect.Array {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				walk(ft, path, onPath)
				continue
			}
			leaves = append(leaves, configLeaf{Path: path, Kind: ft.Kind()})
		}
	}
	walk(reflect.TypeOf(Config{}), "", map[reflect.Type]bool{})
	sort.Slice(leaves, func(i, j int) bool { return leaves[i].Path < leaves[j].Path })
	return leaves
}

// optOutLookingSubstrings are the lexical patterns net 1 matches against a
// leaf's LAST path segment. Deliberately matched on the leaf only: a parent
// segment like "allowlist_sync" would otherwise flag every field beneath it.
var optOutLookingSubstrings = []string{
	"insecure_",
	"allow_",
	"_allow",
	"disable",
	"skip_",
	"unsafe",
	"keyless",
}

// sweepExemptions are leaves net 1 flags that are NOT security-weakening opt-
// outs, each with the reason. An exemption is a claim a reviewer can check at
// its source, which is why each one says what the field actually does rather
// than just "not applicable".
var sweepExemptions = map[string]string{
	"membership.domain_allowlist": "an ALLOWLIST is a restriction, not an opt-out: setting it narrows which " +
		"email domains may self-register. Its empty value is the permissive one, but 'open registration' is " +
		"already covered as a weakening by membership.validation_mode (the insecure_skip_membership_review " +
		"entry) — registering this field too would audit the same posture twice under two names.",
}

// registryCoveredPaths is the set of config paths some registry entry's
// SourcePaths claims.
func registryCoveredPaths() map[string][]string {
	covered := map[string][]string{}
	for _, e := range InsecureSettingsRegistry {
		for _, p := range e.SourcePaths {
			covered[p] = append(covered[p], e.Name)
		}
	}
	return covered
}

func looksLikeOptOut(path string) bool {
	leaf := path
	if i := strings.LastIndex(path, "."); i >= 0 {
		leaf = path[i+1:]
	}
	for _, s := range optOutLookingSubstrings {
		if strings.Contains(leaf, s) {
			return true
		}
	}
	return false
}

// TestConfigSurface_EveryOptOutLookingSettingIsRegisteredOrExempt is net 1.
//
// RED on adding a bool field tagged yaml:"allow_anything"
// to any struct reachable from Config without touching anything else: the test
// names the exact path and refuses to pass until it is either registered or
// exempted with a reason.
func TestConfigSurface_EveryOptOutLookingSettingIsRegisteredOrExempt(t *testing.T) {
	covered := registryCoveredPaths()
	var unlisted []string
	for _, l := range configSurfaceLeaves() {
		if !looksLikeOptOut(l.Path) {
			continue
		}
		if len(covered[l.Path]) > 0 {
			continue
		}
		if _, ok := sweepExemptions[l.Path]; ok {
			continue
		}
		unlisted = append(unlisted, fmt.Sprintf("%s (%s)", l.Path, l.Kind))
	}
	if len(unlisted) > 0 {
		t.Errorf("found %d config setting(s) whose name reads as a security opt-out but which no "+
			"InsecureSettingsRegistry entry covers and which carry no exemption:\n  %s\n\n"+
			"ADR-112's opt-out rule says a security-weakening setting must be visible: warned about at "+
			"start-up, present in the start-to-start settings diff, and reported as a deviation by the "+
			"posture report. All three read InsecureSettingsRegistry, so an unregistered setting is in "+
			"effect SILENTLY. Resolve it one of two ways, both of which are a decision someone made on "+
			"purpose:\n"+
			"  (a) add an InsecureSettingsRegistry entry whose SourcePaths names this path, or\n"+
			"  (b) add it to sweepExemptions with a reason saying why it is not an opt-out.",
			len(unlisted), strings.Join(unlisted, "\n  "))
	}
}

// TestConfigSurface_RegistrySourcePathsAllExist stops the registry's side of
// the link from rotting. A SourcePaths entry naming a field that no longer
// exists would silently stop covering anything, and net 1 would go on passing
// because the (now absent) path is no longer swept either — a carve-out that
// quietly covers nothing is worse than no carve-out, because it still reads as
// coverage.
func TestConfigSurface_RegistrySourcePathsAllExist(t *testing.T) {
	real := map[string]bool{}
	for _, l := range configSurfaceLeaves() {
		real[l.Path] = true
	}
	for _, e := range InsecureSettingsRegistry {
		t.Run(e.Name, func(t *testing.T) {
			if len(e.SourcePaths) == 0 {
				t.Fatalf("entry %q has no SourcePaths — nothing ties it to a real config field, so the "+
					"sweep cannot tell whether the setting it describes still exists", e.Name)
			}
			for _, p := range e.SourcePaths {
				// The walk stops at a recursive type, so it never lists the
				// fallbacks[] copies of KeyProviderConfig's leaves. Such a path is
				// real iff its primary spelling is and KeyProviderConfig really
				// carries a Fallbacks []KeyProviderConfig (one level, as
				// keyProviderChain reads it).
				if primary, ok := strings.CutPrefix(p, "storage.encryption.key_provider.fallbacks."); ok {
					sf, found := reflect.TypeOf(KeyProviderConfig{}).FieldByName("Fallbacks")
					if !found || sf.Type != reflect.TypeOf([]KeyProviderConfig(nil)) || !strings.HasPrefix(sf.Tag.Get("yaml"), "fallbacks") {
						t.Errorf("SourcePaths entry %q needs KeyProviderConfig.Fallbacks []KeyProviderConfig under yaml key fallbacks", p)
					}
					p = "storage.encryption.key_provider." + primary
				}
				if !real[p] {
					t.Errorf("SourcePaths entry %q does not exist on Config's YAML surface (renamed? removed? "+
						"typo?) — fix the path, or drop the entry if the setting is gone", p)
				}
			}
		})
	}
}

// TestConfigSurface_ExemptionsAreLive keeps sweepExemptions honest in the other
// direction: an exemption for a path that no longer exists, or that no longer
// even looks like an opt-out, is dead weight that reads as a reviewed decision.
func TestConfigSurface_ExemptionsAreLive(t *testing.T) {
	real := map[string]bool{}
	for _, l := range configSurfaceLeaves() {
		real[l.Path] = true
	}
	for path, reason := range sweepExemptions {
		if reason == "" {
			t.Errorf("exemption %q has no reason", path)
		}
		if !real[path] {
			t.Errorf("exemption %q names a config path that no longer exists — remove it", path)
		} else if !looksLikeOptOut(path) {
			t.Errorf("exemption %q is never flagged by the sweep (its name no longer reads as an opt-out), "+
				"so the exemption does nothing — remove it", path)
		}
	}
}

// configSurfaceGolden is net 2's ratchet: the sorted set of every leaf path
// on Config's YAML surface, one per line.
//
// Update it ONLY together with the classification the failure message asks for.
// Editing the file to make CI green, with no entry added to either
// InsecureSettingsRegistry or sweepExemptions and nothing written down, is the
// one way to defeat this check — and it is exactly the decision this file
// exists to force someone to make in the open. Because it is a SET, the edit
// itself shows a reviewer which paths appeared and disappeared.
const configSurfaceGolden = "testdata/config_surface_leaves.txt"

// configSurfaceDrift compares the live leaf set against the golden one and
// returns the paths present only in got (added) and only in want (removed).
//
// A set comparison, not a count: the coordinator's 2026-10-08 review defeated
// the earlier len() ratchet with one change that added a non-lexical opt-out
// (bypass_approval_workflow) and hid an existing leaf (yaml:"-") at the same
// time — the count stayed 304 and every sweep test passed.
// TestConfigSurface_RatchetCatchesACountPreservingSwap pins that shape.
func configSurfaceDrift(got, want []string) (added, removed []string) {
	inWant := make(map[string]bool, len(want))
	for _, p := range want {
		inWant[p] = true
	}
	inGot := make(map[string]bool, len(got))
	for _, p := range got {
		inGot[p] = true
		if !inWant[p] {
			added = append(added, p)
		}
	}
	for _, p := range want {
		if !inGot[p] {
			removed = append(removed, p)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func readConfigSurfaceGolden(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(configSurfaceGolden)
	if err != nil {
		t.Fatalf("reading %s: %v", configSurfaceGolden, err)
	}
	var paths []string
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			paths = append(paths, line)
		}
	}
	return paths
}

func liveConfigSurfacePaths() []string {
	leaves := configSurfaceLeaves()
	paths := make([]string, len(leaves))
	for i, l := range leaves {
		paths[i] = l.Path
	}
	return paths
}

// TestConfigSurface_LeafSetRatchet is net 2: the net for a weakening setting
// whose NAME gives nothing away.
//
// Seven of the known exceptions are proof this is needed rather than
// decorative — membership.validation_mode, storage.database.ssl_mode,
// credential_delivery.mode, credential_delivery.smtp.tls,
// notifications.email.tls, server.http.metrics_token and
// server.http.max_request_body_bytes are each weakening in some value and
// none of them contains a word net 1 looks for (an eighth,
// sso.providers.trust_asserted_email, became visible to net 1 when #2899
// renamed it to insecure_trust_saml_asserted_email). An eighth of the same kind, added tomorrow, would pass net 1 silently.
//
// This check cannot be silently passed: any added, removed or renamed leaf
// anywhere in Config fails it, including a swap that keeps the count.
func TestConfigSurface_LeafSetRatchet(t *testing.T) {
	added, removed := configSurfaceDrift(liveConfigSurfacePaths(), readConfigSurfaceGolden(t))
	if len(added) == 0 && len(removed) == 0 {
		return
	}
	t.Errorf("Config's YAML surface differs from %s.\n  added:   %v\n  removed: %v\n\n"+
		"This is ADR-112's opt-out rule asking one question about every ADDED path: can any value of "+
		"it weaken security?\n"+
		"  - YES -> add an InsecureSettingsRegistry entry whose SourcePaths names it. It then gets the "+
		"start-up warning, the settings-diff audit and the posture report automatically; no call site to "+
		"wire up.\n"+
		"  - NO  -> add the path to %s, and say so in the commit message.\n"+
		"A REMOVED path that a registry entry covered means that weakening is no longer audited under its "+
		"old name: check the entry's SourcePaths moved with it.\n\n"+
		"The name-based sweep (TestConfigSurface_EveryOptOutLookingSettingIsRegisteredOrExempt) is not a "+
		"substitute for answering this: validation_mode, ssl_mode, mode, tls, metrics_token and "+
		"max_request_body_bytes are all registered weakenings whose names it cannot see.",
		configSurfaceGolden, added, removed, configSurfaceGolden)
}

// TestConfigSurface_RatchetCatchesACountPreservingSwap is the calibration for
// net 2, on a synthetic surface so it needs no edit to Config: the reviewer's
// bypass (one non-lexical opt-out added, one existing leaf hidden, net count
// unchanged) must be reported as drift in BOTH directions.
func TestConfigSurface_RatchetCatchesACountPreservingSwap(t *testing.T) {
	want := liveConfigSurfacePaths()
	got := make([]string, 0, len(want))
	for _, p := range want {
		if p != "security.auto_fix_file_permissions" {
			got = append(got, p)
		}
	}
	got = append(got, "security.bypass_approval_workflow")
	if len(got) != len(want) {
		t.Fatalf("fixture must preserve the leaf count (got %d, want %d)", len(got), len(want))
	}
	if looksLikeOptOut("security.bypass_approval_workflow") {
		t.Fatalf("fixture must be invisible to net 1, or it does not exercise net 2")
	}

	added, removed := configSurfaceDrift(got, want)
	if len(added) != 1 || added[0] != "security.bypass_approval_workflow" {
		t.Errorf("a count-preserving swap must report the added path; got added=%v", added)
	}
	if len(removed) != 1 || removed[0] != "security.auto_fix_file_permissions" {
		t.Errorf("a count-preserving swap must report the removed path; got removed=%v", removed)
	}

	// And the known-good direction: an unchanged surface is not drift.
	if a, r := configSurfaceDrift(want, want); len(a) != 0 || len(r) != 0 {
		t.Errorf("an unchanged surface must not be drift; got added=%v removed=%v", a, r)
	}
}

// derivedFieldExemptions are derived (yaml:"-") Config fields that no registry
// entry claims through DerivedInputs, each with the reason. Same contract as
// sweepExemptions: a claim a reviewer can check at its source.
var derivedFieldExemptions = map[string]string{
	"DeprecatedSettingWarnings": "text only: the start-up warnings resolveDeprecatedAliases collected for old keys " +
		"it already translated to the current insecure_ key before decoding. It changes no setting's value or " +
		"effect, so no InEffect/Value could depend on it (server/main.go warnDeprecatedSettingAliases only logs it).",
}

// configDerivedFields returns every yaml:"-" field reachable from Config, as
// <yaml path of its parent>.<GoFieldName> -- the spelling DerivedInputs uses.
// Same walk as configSurfaceLeaves, inverted: these are exactly the fields
// that walk skips.
func configDerivedFields() []string {
	var out []string
	var walk func(t reflect.Type, prefix string, onPath map[reflect.Type]bool)
	walk = func(t reflect.Type, prefix string, onPath map[reflect.Type]bool) {
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct || onPath[t] {
			return
		}
		onPath[t] = true
		defer delete(onPath, t)
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" {
				continue
			}
			name := strings.Split(f.Tag.Get("yaml"), ",")[0]
			if name == "-" {
				p := f.Name
				if prefix != "" {
					p = prefix + "." + f.Name
				}
				out = append(out, p)
				continue
			}
			if name == "" {
				name = strings.ToLower(f.Name)
			}
			path := name
			if prefix != "" {
				path = prefix + "." + name
			}
			walk(f.Type, path, onPath)
		}
	}
	walk(reflect.TypeOf(Config{}), "", map[reflect.Type]bool{})
	sort.Strings(out)
	return out
}

// unclaimedDerivedFields returns the derived fields neither claimed by an
// entry's DerivedInputs nor exempted, and the DerivedInputs naming no real
// derived field.
func unclaimedDerivedFields(registry []InsecureSetting, derived []string, exempt map[string]string) (unclaimed, dangling []string) {
	real := map[string]bool{}
	for _, d := range derived {
		real[d] = true
	}
	claimed := map[string]bool{}
	for _, e := range registry {
		for _, d := range e.DerivedInputs {
			claimed[d] = true
			if !real[d] {
				dangling = append(dangling, e.Name+": "+d)
			}
		}
	}
	for _, d := range derived {
		if _, ok := exempt[d]; !claimed[d] && !ok {
			unclaimed = append(unclaimed, d)
		}
	}
	return unclaimed, dangling
}

// TestConfigSurface_DerivedFieldRatchet is the derived-state half of the
// config-surface sweep (#2908). configSurfaceLeaves skips yaml:"-" fields
// because a config file cannot set them -- but Load() and the boot path set
// them, and some change what a setting DOES. The ADR-112 grace period lives in
// two of them (EnableFilePermissionCheckImplicitDefault/UpgradeGrace): the
// registry entry read only the YAML bool, so a grace-period deployment that
// only warned was reported as clean everywhere. Every derived field must now
// be claimed by an entry's DerivedInputs or exempted with a reason, and every
// DerivedInputs must name a real derived field.
func TestConfigSurface_DerivedFieldRatchet(t *testing.T) {
	derived := configDerivedFields()
	unclaimed, dangling := unclaimedDerivedFields(InsecureSettingsRegistry, derived, derivedFieldExemptions)
	if len(unclaimed) > 0 {
		t.Errorf("derived (yaml:\"-\") Config field(s) no InsecureSettingsRegistry entry reads and no exemption "+
			"explains: %v\n\nA derived field can change what a security setting does without any config-file "+
			"change (#2908: the ADR-112 grace period). Either add it to the DerivedInputs of the entry whose "+
			"InEffect/Value must reflect it, or add it to derivedFieldExemptions with a reason.", unclaimed)
	}
	if len(dangling) > 0 {
		t.Errorf("DerivedInputs naming no derived Config field (renamed? removed?): %v", dangling)
	}
	for d, reason := range derivedFieldExemptions {
		if reason == "" {
			t.Errorf("derived-field exemption %q has no reason", d)
		}
		if !slices.Contains(derived, d) {
			t.Errorf("derived-field exemption %q names no derived Config field -- remove it", d)
		}
	}

	// Calibration, both directions: the #2908 shape (the entry stops claiming
	// the grace field) must be reported; the live registry must not be.
	var stripped []InsecureSetting
	for _, e := range InsecureSettingsRegistry {
		e.DerivedInputs = slices.DeleteFunc(slices.Clone(e.DerivedInputs), func(d string) bool {
			return d == "security.EnableFilePermissionCheckUpgradeGrace"
		})
		stripped = append(stripped, e)
	}
	if got, _ := unclaimedDerivedFields(stripped, derived, derivedFieldExemptions); !slices.Contains(got, "security.EnableFilePermissionCheckUpgradeGrace") {
		t.Errorf("calibration: an entry that stops claiming the grace field must be reported; got %v", got)
	}
	if !slices.Contains(derived, "security.EnableFilePermissionCheckUpgradeGrace") {
		t.Errorf("calibration: the walk must see the derived grace field; got %v", derived)
	}
}
