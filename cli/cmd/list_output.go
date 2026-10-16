package cmd

// -o/--output table|json|yaml for the commands that list things. The table is each
// command's own human layout; json and yaml carry the same records as an array (or, where
// the server pages the list, as an object with the page's total), and an empty list is
// `[]`, never the sentence the table prints.

var (
	projectListFormat string
	userListFormat    string
	groupListFormat   string
	machineListFormat string
	patListFormat     string
	requestListFormat string
	channelListFormat string
	shareListFormat   string
	roleListFormat    string
)

func init() {
	addOutputFlag(projectListCmd, &projectListFormat)
	addOutputFlag(userListCmd, &userListFormat)
	addOutputFlag(groupListCmd, &groupListFormat)
	addOutputFlag(machineListCmd, &machineListFormat)
	addOutputFlag(patListCmd, &patListFormat)
	addOutputFlag(requestListCmd, &requestListFormat)
	addOutputFlag(channelListCmd, &channelListFormat)
	addOutputFlag(shareListCmd, &shareListFormat)
	addOutputFlag(rbacListRolesCmd, &roleListFormat)
}

// emitList prints items as json or yaml, or calls table for the human layout. A nil slice
// is rendered as an empty array.
func emitList[T any](format string, items []T, table func() error) error {
	if format == outputTable {
		return table()
	}
	if items == nil {
		items = []T{}
	}
	return printStructured(format, items)
}
