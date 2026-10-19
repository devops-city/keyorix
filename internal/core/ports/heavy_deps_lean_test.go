package ports

// CORE-DECOUPLE-LEAN-1: cobra and yaml.v3 left internal/core's closure. cobra (and
// its only importer pflag) came in through internal/securefiles, which declared an
// unused FilePermsCmd; yaml.v3 through internal/secrettemplate, whose
// EscapeYAMLString/RenderYAML moved to internal/secrettemplate/yamlescape.
func init() {
	registerForbiddenHeavyDep("github.com/spf13/", "CORE-DECOUPLE-LEAN-1: cobra/pflag, core does not use a CLI framework")
	registerForbiddenHeavyDep("gopkg.in/yaml.v3", "CORE-DECOUPLE-LEAN-1: YAML helpers live in internal/secrettemplate/yamlescape")
}
