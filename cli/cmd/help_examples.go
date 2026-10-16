package cmd

import (
	"strings"
	"sync"

	"github.com/spf13/cobra"
)

// helpExamples is the `Examples` section of `keyorix <command> --help` for every
// leaf command, keyed by the command path without the leading "keyorix ".
//
// It is one table rather than an Example field per command so the whole surface is
// reviewable in one place; help_examples_test.go is what keeps it honest: every leaf
// command must have an entry, every entry must name a real command, and every
// example line must parse against that command's own flags (a renamed or removed
// flag turns the test red instead of leaving a stale example in --help).
//
// Examples never put a secret value on the command line (the CLI prompts, or reads
// KEYORIX_* environment variables / files, for those); the test enforces that too.
// A command that already sets its own Example keeps it.
var helpExamples = map[string]string{
	"access-review attest": `# Attest that a role grant is still needed
keyorix access-review attest --project-id 3 --source role --role-id 4 --principal-id 12`,
	"access-review revoke": `# Revoke a user's role grant found during a review
keyorix access-review revoke --project-id 3 --source role --role-id 4 --principal-id 12`,
	"access-review campaign open": `keyorix access-review campaign open --project-id 3 --name "Q4 2026 access recertification"`,
	"access-review campaign list": `keyorix access-review campaign list --project-id 3`,
	"access-review campaign show": `keyorix access-review campaign show --project-id 3 --campaign-id 7`,
	"access-review campaign decide": `keyorix access-review campaign decide --project-id 3 --campaign-id 7 --item-id 41 --action attest
keyorix access-review campaign decide --project-id 3 --campaign-id 7 --item-id 42 --action revoke --reason "left the team"`,
	"access-review campaign close": `keyorix access-review campaign close --project-id 3 --campaign-id 7`,

	"anomalies list":        `keyorix anomalies list --unacknowledged`,
	"anomalies acknowledge": `keyorix anomalies acknowledge 17`,
	"anomalies config get":  `keyorix anomalies config get`,
	"anomalies config set": `# Treat 22:00-06:00 New York time as off-hours
keyorix anomalies config set --off-hours-enabled --off-hours-start 22 --off-hours-end 6 --off-hours-timezone America/New_York`,
	"anomalies escalation create": `keyorix anomalies escalation create --name page-oncall --min-severity high --after-minutes 15 --channels 1,2`,
	"anomalies escalation delete": `keyorix anomalies escalation delete 3`,
	"anomalies escalation list":   `keyorix anomalies escalation list`,
	"anomalies escalation run":    `keyorix anomalies escalation run`,

	"audit checkpoint": `keyorix audit checkpoint`,
	"audit export": `# Export the whole audit trail as NDJSON
keyorix audit export --all > audit.ndjson
# ...or as CSV, from a point in time
keyorix audit export --all --csv --since 2026-10-01T00:00:00Z > audit.csv`,
	"audit logs": `keyorix audit logs --limit 20
keyorix audit logs --project-id 3 --event-type secret.read --since 2026-10-01T00:00:00Z`,
	"audit migrate-chain-encoding": `# Preview first; nothing is written without --confirm
keyorix audit migrate-chain-encoding
keyorix audit migrate-chain-encoding --confirm`,
	"audit search": `keyorix audit search --action secret.read --actor alice --success false
keyorix audit search --resource-type secret --resource-id 42`,
	"audit verify": `# Check the audit hash chain
keyorix audit verify
# Walk the whole chain on the server and print the result as JSON
keyorix audit verify --full --json`,

	"billing report": `keyorix billing report --from 2026-09-01T00:00:00Z --to 2026-10-01T00:00:00Z
keyorix billing report --from 2026-09-01T00:00:00Z --to 2026-10-01T00:00:00Z --project-id 3,5 --format json`,

	"break-glass activate": `keyorix break-glass activate --project-id 3 --justification "prod outage INC-1234" --ttl 2h`,
	"break-glass list":     `keyorix break-glass list --project-id 3`,
	"break-glass revoke":   `keyorix break-glass revoke --project-id 3 --activation-id 9`,

	"bundle import": `keyorix bundle import update-1.4.0.bundle --dest /var/lib/keyorix/updates --installed-version 1.3.2 --license /etc/keyorix/license.token`,
	"bundle verify": `keyorix bundle verify update-1.4.0.bundle --installed-version 1.3.2`,

	"change-password": `# Prompts for the current and the new password
keyorix change-password`,

	"compliance controls": `keyorix compliance controls
keyorix compliance controls --csv --output controls.csv`,
	"compliance credential-trends": `keyorix compliance credential-trends --days 90`,
	"compliance digest": `keyorix compliance digest
keyorix compliance digest --send`,
	"compliance export":              `keyorix compliance export --output evidence-pack.json`,
	"compliance inventory":           `keyorix compliance inventory --project 3 --output inventory.csv`,
	"compliance permission-baseline": `keyorix compliance permission-baseline --format json --output baseline.json`,
	"compliance permission-changes":  `keyorix compliance permission-changes --since 2026-10-01T00:00:00Z --limit 200`,
	"compliance report":              `keyorix compliance report`,
	"compliance rotation-by-backend": `keyorix compliance rotation-by-backend`,
	"compliance verify":              `keyorix compliance verify --file evidence-pack.json --sig evidence-pack.json.sig`,

	"config get":   `keyorix config get ca_file`,
	"config set":   `keyorix config set ca_file /etc/keyorix/ca.pem`,
	"config unset": `keyorix config unset ca_file`,

	"dynamic-secret classify":   `keyorix dynamic-secret classify 5 --level confidential`,
	"dynamic-secret create":     `keyorix dynamic-secret create --project-id 3 --name orders-db --backend postgres --default-ttl 3600 --max-ttl 14400`,
	"dynamic-secret get-config": `keyorix dynamic-secret get-config 5`,
	"dynamic-secret issue": `# Issue a short-lived credential from config 5 (valid for 15 minutes)
keyorix dynamic-secret issue 5 --ttl 900`,
	"dynamic-secret leases":     `keyorix dynamic-secret leases 5`,
	"dynamic-secret list":       `keyorix dynamic-secret list --project-id 3`,
	"dynamic-secret renew":      `keyorix dynamic-secret renew 21 --ttl 900`,
	"dynamic-secret revoke":     `keyorix dynamic-secret revoke 21`,
	"dynamic-secret revoke-all": `keyorix dynamic-secret revoke-all 5 --yes`,

	"group add-member":    `keyorix group add-member platform-team --user alice`,
	"group create":        `keyorix group create --name platform-team --description "Platform engineers"`,
	"group delete":        `keyorix group delete platform-team --force`,
	"group get":           `keyorix group get platform-team`,
	"group list":          `keyorix group list`,
	"group members":       `keyorix group members platform-team`,
	"group remove-member": `keyorix group remove-member platform-team --user alice`,
	"group update":        `keyorix group update platform-team --description "Platform and SRE"`,

	"hygiene": `keyorix hygiene
keyorix hygiene --expiring-days 14 --stale-days 60`,

	"invite list":   `keyorix invite list --project payments`,
	"invite resend": `keyorix invite resend --project payments --id 12`,
	"invite revoke": `keyorix invite revoke --project payments --id 12`,
	"invite send":   `keyorix invite send --project payments --email bob@example.com --role developer`,

	"legal-hold lift":   `keyorix legal-hold lift --reason "case closed, matter 2026-17"`,
	"legal-hold place":  `keyorix legal-hold place --reason "litigation hold, matter 2026-17"`,
	"legal-hold status": `keyorix legal-hold status`,

	"license install": `keyorix license install license.token --dest /etc/keyorix/license.token`,
	"license status":  `keyorix license status --license /etc/keyorix/license.token`,

	"login": `# Prompts for the password (and the MFA code, if the account has MFA)
keyorix login --server https://keyorix.example.com --username alice`,
	"logout": `keyorix logout`,

	"machine audit": `keyorix machine audit --format csv`,
	"machine binding add": `# Let a GitHub Actions workflow authenticate as this machine identity
keyorix machine binding add ci-deployer --project payments --issuer https://token.actions.githubusercontent.com --subject repo:acme/payments:ref:refs/heads/main`,
	"machine binding list":      `keyorix machine binding list ci-deployer --project payments`,
	"machine binding rm":        `keyorix machine binding rm ci-deployer 4 --project payments`,
	"machine create":            `keyorix machine create --project payments --name ci-deployer --type ci --classification internal`,
	"machine describe":          `keyorix machine describe ci-deployer --project payments`,
	"machine grant-role":        `keyorix machine grant-role ci-deployer --project payments --role developer`,
	"machine list":              `keyorix machine list --project payments`,
	"machine migrate-from-user": `keyorix machine migrate-from-user svc-deploy --project payments --type ci`,
	"machine reactivate":        `keyorix machine reactivate ci-deployer --project payments`,
	"machine revoke":            `keyorix machine revoke ci-deployer --project payments`,
	"machine revoke-role":       `keyorix machine revoke-role ci-deployer --project payments --role developer`,
	"machine roles":             `keyorix machine roles ci-deployer --project payments`,
	"machine suspend":           `keyorix machine suspend ci-deployer --project payments`,
	"machine token issue": `# The token is shown once; store it straight into your CI system
keyorix machine token issue ci-deployer --project payments --name github-actions --expires-in-days 90`,
	"machine token list":    `keyorix machine token list ci-deployer --project payments`,
	"machine token revoke":  `keyorix machine token revoke ci-deployer 4 --project payments`,
	"machine token-hygiene": `keyorix machine token-hygiene --days 60`,

	"mfa activate": `# Prompts for the authenticator code and your password
keyorix mfa activate`,
	"mfa enroll": `# Prints the authenticator setup secret; then run: keyorix mfa activate
keyorix mfa enroll`,
	"mfa stepup": `# Prompts for a fresh authenticator or recovery code
keyorix mfa stepup`,

	"notification channel add": `keyorix notification channel add ops-slack --type slack --url https://hooks.slack.com/services/T000/B000/XXXX --events secret.rotated,anomaly.detected
keyorix notification channel add secops-mail --type email --email secops@example.com`,
	"notification channel delete": `keyorix notification channel delete ops-slack --confirm`,
	"notification channel get":    `keyorix notification channel get ops-slack`,
	"notification channel list":   `keyorix notification channel list`,
	"notification channel update": `keyorix notification channel update ops-slack --events secret.rotated --enabled`,

	"pat cleanup-expired": `keyorix pat cleanup-expired`,
	"pat create": `# A read-only token for one project, valid until the end of the year
keyorix pat create --name ci-readonly --scope secrets.read --project-id 3 --expires 2026-12-31`,
	"pat hygiene":      `keyorix pat hygiene --days 60`,
	"pat list":         `keyorix pat list`,
	"pat list-expired": `keyorix pat list-expired`,
	"pat revoke":       `keyorix pat revoke 8`,

	"project create":          `keyorix project create --name payments --description "Payments platform" --envs development,staging,production`,
	"project current":         `keyorix project current`,
	"project describe":        `keyorix project describe payments`,
	"project env clone":       `keyorix project env clone staging qa --project payments`,
	"project env create":      `keyorix project env create --name qa --project payments`,
	"project env delete":      `keyorix project env delete 9 --project payments --confirm`,
	"project env list":        `keyorix project env list --project payments`,
	"project environments":    `keyorix project environments 3`,
	"project health":          `keyorix project health payments --limit 10`,
	"project hygiene":         `keyorix project hygiene 3`,
	"project list":            `keyorix project list`,
	"project resume-secrets":  `keyorix project resume-secrets --id 3`,
	"project stats":           `keyorix project stats payments --format json`,
	"project suspend-secrets": `keyorix project suspend-secrets --id 3 --reason "suspected CI compromise"`,
	"project use": `# Make "payments" the default for later commands
keyorix project use payments`,

	"rbac assign-role": `keyorix rbac assign-role --user alice@example.com --role developer --project payments
# Time-bound grant
keyorix rbac assign-role --user alice@example.com --role admin --project payments --ttl 4h`,
	"rbac assign-role-to-group":   `keyorix rbac assign-role-to-group --group platform-team --role developer --project payments`,
	"rbac audit-logs":             `keyorix rbac audit-logs --limit 20`,
	"rbac check-permission":       `keyorix rbac check-permission --user alice@example.com --permission secrets.read`,
	"rbac export-matrix":          `keyorix rbac export-matrix --format csv --output rbac-matrix.csv`,
	"rbac list-group-roles":       `keyorix rbac list-group-roles --group platform-team`,
	"rbac list-permissions":       `keyorix rbac list-permissions --user alice@example.com`,
	"rbac list-roles":             `keyorix rbac list-roles`,
	"rbac list-user-roles":        `keyorix rbac list-user-roles --user alice@example.com`,
	"rbac remove-role":            `keyorix rbac remove-role --user alice@example.com --role developer --project payments`,
	"rbac remove-role-from-group": `keyorix rbac remove-role-from-group --group platform-team --role developer --project payments`,

	"request access":                     `keyorix request access --project payments --role developer --reason "on-call this week"`,
	"request bulk-approve":               `keyorix request bulk-approve --ids 4,5,6`,
	"request bulk-reject":                `keyorix request bulk-reject --ids 7,8 --reason "no business need"`,
	"request list":                       `keyorix request list --project payments`,
	"request rejection-templates add":    `keyorix request rejection-templates add --name no-need --reason "No business need for this access"`,
	"request rejection-templates delete": `keyorix request rejection-templates delete 2`,
	"request rejection-templates list":   `keyorix request rejection-templates list`,
	"request review": `keyorix request review --project payments --id 4 --action approve --ttl 8h
keyorix request review --project payments --id 5 --action reject --reason "ask your manager first"`,
	"request secret-access": `keyorix request secret-access --ref payments/production/STRIPE_KEY --reason "debugging INC-1234"`,
	"request withdraw":      `keyorix request withdraw --project payments --id 4`,

	"risk add":     `keyorix risk add --title "Shared admin account" --category mfa --justification "vendor limitation" --expires 2027-01-31T00:00:00Z`,
	"risk approve": `keyorix risk approve --id 3`,
	"risk list":    `keyorix risk list --all`,
	"risk revoke":  `keyorix risk revoke --id 3`,

	"rotation create": `keyorix rotation create --name prod-90d --scope project --project-id 3 --interval-days 90 --alert-days-before 14`,
	"rotation delete": `keyorix rotation delete 2`,
	"rotation list":   `keyorix rotation list --project-id 3`,
	"rotation order":  `keyorix rotation order 3`,
	"rotation plan": `keyorix rotation plan 3
keyorix rotation plan --all-projects`,
	"rotation show":   `keyorix rotation show 2`,
	"rotation status": `keyorix rotation status --project-id 3`,

	"run": `# Run a command with secrets injected as environment variables
keyorix run --project payments --env production --var DB_PASSWORD=payments/production/DB_PASSWORD -- ./server`,

	"secret access":     `keyorix secret access --id 42`,
	"secret access-log": `keyorix secret access-log --id 42 --days 7`,
	"secret acl grant":  `keyorix secret acl grant --secret 42 --user 12 --perm secrets.read`,
	"secret acl list":   `keyorix secret acl list 42`,
	"secret acl revoke": `keyorix secret acl revoke --secret 42 --acl 5`,
	"secret audit":      `keyorix secret audit --id 42 --limit 20`,
	"secret auto-rotate": `# Rotate secret 42 automatically with a generated 32-character value
keyorix secret auto-rotate --id 42 --length 32
keyorix secret auto-rotate --id 42 --off`,
	"secret blast-radius": `keyorix secret blast-radius 42`,
	"secret bulk-delete": `# Preview, then confirm
keyorix secret bulk-delete --project 3 --env 2 --names OLD_KEY,UNUSED_TOKEN
keyorix secret bulk-delete --project 3 --env 2 --names OLD_KEY,UNUSED_TOKEN --confirm`,
	"secret bulk-rename": `# Dry run; add --apply to rename
keyorix secret bulk-rename --project 3 --rename 42=DB_PASSWORD --rename 43=DB_USER`,
	"secret bulk-rotate":      `keyorix secret bulk-rotate --project 3 --classification confidential --confirm`,
	"secret cert":             `keyorix secret cert 42`,
	"secret classify":         `keyorix secret classify --id 42 --level confidential`,
	"secret clear-schedule":   `keyorix secret clear-schedule 42`,
	"secret comment add":      `keyorix secret comment add 42 3 "rotated after the 2026-10 incident"`,
	"secret comment delete":   `keyorix secret comment delete 42 3 7`,
	"secret comment list":     `keyorix secret comment list 42 3`,
	"secret copy":             `keyorix secret copy --id 42 --to-environment 2 --name DB_PASSWORD_COPY`,
	"secret copy-environment": `keyorix secret copy-environment --project 3 --from-environment 1 --to-environment 2`,
	"secret create": `# Prompts for the value on a hidden line
keyorix secret create --project 3 --environment 2 --name DB_PASSWORD --interactive
# Or read it from a file
keyorix secret create --project 3 --environment 2 --name TLS_KEY --from-file ./tls.key`,
	"secret delete": `keyorix secret delete --id 42
keyorix secret delete --project 3 --environment 2 --name DB_PASSWORD --force`,
	"secret deps add": `# Secret 42 depends on secret 40
keyorix secret deps add 42 40 --note "uses the same database"`,
	"secret deps impact": `keyorix secret deps impact 42`,
	"secret deps list":   `keyorix secret deps list 42`,
	"secret deps rm":     `keyorix secret deps rm 42 6`,
	"secret description": `keyorix secret description --id 42 --set "Primary orders database password"`,
	"secret diff":        `keyorix secret diff DB_PASSWORD 2 3 --project 3 --environment 2`,
	"secret expiring":    `keyorix secret expiring --project 3 --days 14`,
	"secret explain":     `keyorix secret explain AWS_SECRET_ACCESS_KEY`,
	"secret export": `keyorix secret export --project 3 --env 2 --format dotenv --output .env
keyorix secret export --project 3 --env 2 --format json`,
	"secret fix": `# Preview what would be moved out of source into .env
keyorix secret fix AWS_SECRET_ACCESS_KEY --path ./src`,
	"secret folder create": `keyorix secret folder create --project 3 --environment 2 --name databases`,
	"secret folder delete": `keyorix secret folder delete --id 5`,
	"secret folder list":   `keyorix secret folder list --project 3`,
	"secret get": `keyorix secret get --id 42
# Read the value by reference
keyorix secret get --ref payments/production/DB_PASSWORD`,
	"secret get-schedule": `keyorix secret get-schedule 42`,
	"secret import":       `keyorix secret import --project 3 --env 2 --file .env --format dotenv --dry-run`,
	"secret info":         `keyorix secret info --id 42`,
	"secret list": `keyorix secret list --project payments
keyorix secret list --project payments --format json`,
	"secret move":              `keyorix secret move --id 42 --to 5`,
	"secret name-conformance":  `keyorix secret name-conformance --project 3`,
	"secret orphaned":          `keyorix secret orphaned --project 3`,
	"secret ownership-history": `keyorix secret ownership-history --id 42`,
	"secret quota-report":      `keyorix secret quota-report`,
	"secret reassign-owner":    `keyorix secret reassign-owner --project 3 --from 12 --to 15`,
	"secret render":            `keyorix secret render config.tmpl --project 3 --output config.yaml`,
	"secret restore":           `keyorix secret restore --id 42`,
	"secret resume":            `keyorix secret resume --id 42`,
	"secret rollback":          `keyorix secret rollback --id 42 --version 2`,
	"secret rotate": `# Prompts for the new value
keyorix secret rotate --id 42`,
	"secret rotation-simulate": `keyorix secret rotation-simulate --id 42`,
	"secret scan": `keyorix secret scan ./src
keyorix secret scan --staged --severity high`,
	"secret score": `keyorix secret score --id 42`,
	"secret set-schedule": `# Allow reads on weekdays, 08:00-18:00 UTC
keyorix secret set-schedule 42 --days mon,tue,wed,thu,fri --start-hour 8 --end-hour 18`,
	"secret suspend":         `keyorix secret suspend --id 42 --reason "suspected leak"`,
	"secret tags":            `keyorix secret tags --id 42 --set db,prod`,
	"secret template create": `keyorix secret template create --name db-credential --classification confidential --tags db --rotation-hint-days 90`,
	"secret template delete": `keyorix secret template delete db-credential`,
	"secret template get":    `keyorix secret template get db-credential`,
	"secret template list":   `keyorix secret template list`,
	"secret trash":           `keyorix secret trash --project 3`,
	"secret update": `# Prompts for the new value
keyorix secret update --id 42 --interactive
keyorix secret update --id 42 --expires 2027-01-31T00:00:00Z`,
	"secret versions": `keyorix secret versions --id 42 --format json`,

	"share create":         `keyorix share create --secret-id 42 --recipient-id 12 --permission read --ttl 24h`,
	"share group-shares":   `keyorix share group-shares --group-id 4`,
	"share list":           `keyorix share list --secret-id 42`,
	"share revoke":         `keyorix share revoke --share-id 9`,
	"share self-remove":    `keyorix share self-remove 42`,
	"share shared-secrets": `keyorix share shared-secrets`,
	"share update":         `keyorix share update --share-id 9 --permission write --ttl 48h`,

	"sod policy create": `keyorix sod policy create --name no-assign-and-delete --permission-a roles.assign --permission-b secrets.delete`,
	"sod policy delete": `keyorix sod policy delete --id 2`,
	"sod policy list":   `keyorix sod policy list`,
	"sod violations":    `keyorix sod violations`,

	"status": `# Shows the server, who you are logged in as, and version compatibility
keyorix status`,

	"system info": `keyorix system info`,
	"system init": `# First-run bootstrap of a new server; prompts for the admin password
keyorix system init --server https://keyorix.example.com --admin-username admin --admin-email admin@example.com`,
	"system role-expiry-check":  `keyorix system role-expiry-check`,
	"system token-expiry-check": `keyorix system token-expiry-check`,

	"trust keygen": `keyorix trust keygen --purpose update --key-id update-2026 --dir ./keys`,

	"usage show": `keyorix usage show --days 30
keyorix usage show --project-id 3 --format json`,

	"user create": `# Prompts for an initial password (or use --setup-link / --one-time-password)
keyorix user create --username bob --email bob@example.com --setup-link`,
	"user delete":                    `keyorix user delete --id 12`,
	"user force-password-reset":      `keyorix user force-password-reset --id 12`,
	"user get":                       `keyorix user get --email bob@example.com`,
	"user list":                      `keyorix user list --page 1 --page-size 50`,
	"user reactivate":                `keyorix user reactivate --id 12`,
	"user reissue-one-time-password": `keyorix user reissue-one-time-password bob`,
	"user resend-setup-link":         `keyorix user resend-setup-link --id 12`,
	"user revoke-sessions":           `keyorix user revoke-sessions --id 12`,
	"user suspend":                   `keyorix user suspend --id 12`,
	"user suspend-inactive": `# Preview first
keyorix user suspend-inactive --days 90 --dry-run`,
	"user update": `keyorix user update --id 12 --display-name "Bob Jones"`,

	"version": `keyorix version`,
}

var applyHelpExamplesOnce sync.Once

// applyHelpExamples fills in Example on every leaf command that does not set its
// own. Called from Execute (and from tests) once the whole command tree is built;
// it is not an init() because Go runs init functions in file-name order and the
// subcommands register themselves from many files.
func applyHelpExamples() {
	applyHelpExamplesOnce.Do(func() {
		var walk func(c *cobra.Command)
		walk = func(c *cobra.Command) {
			if c.Example == "" {
				if ex, ok := helpExamples[strings.TrimPrefix(c.CommandPath(), rootCmd.Name()+" ")]; ok {
					c.Example = indentExample(ex)
				}
			}
			for _, s := range c.Commands() {
				walk(s)
			}
		}
		walk(rootCmd)
	})
}

// indentExample indents every line two spaces, the layout cobra expects for Example.
func indentExample(ex string) string {
	lines := strings.Split(strings.TrimSpace(ex), "\n")
	for i, l := range lines {
		lines[i] = "  " + l
	}
	return strings.Join(lines, "\n")
}
