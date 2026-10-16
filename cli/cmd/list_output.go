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

	rotationListFormat, dynListFormat, patExpiredFormat, folderListFormat, envListFormat   string
	rejectionListFormat, tokenListFormat, bindingListFormat, anomalyListFormat             string
	escalationListFormat, userRolesFormat, permsFormat, groupRolesFormat, inviteListFormat string
	aclListFormat, templateListFormat, sodListFormat, riskListFormat, commentListFormat    string
	campaignListFormat, depsListFormat                                                     string
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
	addOutputFlag(rotListCmd, &rotationListFormat)
	addOutputFlag(dynListCmd, &dynListFormat)
	addOutputFlag(patListExpiredCmd, &patExpiredFormat)
	addOutputFlag(secretFolderListCmd, &folderListFormat)
	addOutputFlag(envListCmd, &envListFormat)
	addOutputFlag(rejectionTemplatesListCmd, &rejectionListFormat)
	addOutputFlag(machineTokenListCmd, &tokenListFormat)
	addOutputFlag(machineBindingListCmd, &bindingListFormat)
	addOutputFlag(anomalyListCmd, &anomalyListFormat)
	addOutputFlag(escalationListCmd, &escalationListFormat)
	addOutputFlag(rbacListUserRolesCmd, &userRolesFormat)
	addOutputFlag(rbacListPermissionsCmd, &permsFormat)
	addOutputFlag(rbacListGroupRolesCmd, &groupRolesFormat)
	addOutputFlag(inviteListCmd, &inviteListFormat)
	addOutputFlag(secretACLListCmd, &aclListFormat)
	addOutputFlag(secretTemplateListCmd, &templateListFormat)
	addOutputFlag(sodPolicyListCmd, &sodListFormat)
	addOutputFlag(riskListCmd, &riskListFormat)
	addOutputFlag(versionCommentListCmd, &commentListFormat)
	addOutputFlag(accessReviewCampaignListCmd, &campaignListFormat)
	addOutputFlag(secretDepsListCmd, &depsListFormat)
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
