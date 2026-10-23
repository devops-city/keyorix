package docsdrift

import (
	"regexp"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// aliasTableRow matches a renamed-settings table row of docs/CONFIGURATION.md:
// | `old.path` | `new.path` |
var aliasTableRow = regexp.MustCompile("(?m)^\\| `([^`]+)` \\| `([^`]+)` \\|\\s*$")

// missingAliasRows returns the "old -> new" pairs in want that doc's table does
// not list.
func missingAliasRows(doc string, want [][2]string) []string {
	have := map[[2]string]bool{}
	for _, m := range aliasTableRow.FindAllStringSubmatch(doc, -1) {
		have[[2]string{m[1], m[2]}] = true
	}
	var missing []string
	for _, p := range want {
		if !have[p] {
			missing = append(missing, p[0]+" -> "+p[1])
		}
	}
	return missing
}

// TestConfigurationDoc_ListsEveryDeprecatedAlias derives the alias list from
// config.DeprecatedSettingAliasPaths (the table Load rewrites) and requires each
// pair as a row of the renamed-settings table in docs/CONFIGURATION.md. It
// checks that code aliases are documented; a row for a removed alias is not
// flagged (TestDocsConfigKeysExist covers key existence).
func TestConfigurationDoc_ListsEveryDeprecatedAlias(t *testing.T) {
	want := config.DeprecatedSettingAliasPaths()
	if len(want) == 0 {
		t.Fatal("no deprecated aliases returned; the guard would be vacuous")
	}
	for _, m := range missingAliasRows(readDoc(t, "docs/CONFIGURATION.md"), want) {
		t.Errorf("docs/CONFIGURATION.md renamed-settings table lacks the row %s", m)
	}
}

func TestConfigurationDocAliasCheckCatchesPlantedError(t *testing.T) {
	doc := "| `a.old` | `a.insecure_new` |\n| `b.old` | `b.insecure_new` |\n"
	got := missingAliasRows(doc, [][2]string{{"a.old", "a.insecure_new"}, {"c.old", "c.insecure_new"}})
	if len(got) != 1 || !strings.HasPrefix(got[0], "c.old") {
		t.Fatalf("missing = %v, want only c.old", got)
	}
}
