package main

// DESIGN-COMPUTE §15.1's commands held to ur's registry (CSURF-M11-02): every form §15.1 gives, with the task that
// builds it, is a registered command whose docopt usage holds the form's words, else it is listed unbuilt, so a form
// two plans each left to the other fails here rather than shipping missing. A form is the words after ur that select
// it and the options §15.1 writes for it: it is registered when the command its first word names has usage lines whose
// command words are the form's, those lines' options together holding the form's. The unbuilt list is the areas' to
// shrink: no compute area edits this file (CONTRACTS C-29), so a form registered and still listed passes, and the
// review phase prunes the list; an entry naming no form fails.
//
// The forms follow §15.1 as the owner's answers leave it: the web search is `ur web-search`, beside the index search's
// `ur search` (compute-plan-ur-search-collision, QD-1382); `ur connect`'s service forms share the command with
// enrollment, told apart by their arguments (compute-plan-ur-connect-collision, QD-1381); bare `ur agents` lists,
// `ur agents <task>` still searching (compute-plan-ur-agents-ls, QD-1380). §28's support commands, which §15.1 lists
// beside compute's, are held too. And `ur native-host`, the extension's relay to ur daemon, relays no compute method
// (compute-plan-native-host-compute, QD-1253).

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// One §15.1 form: the command words after ur, then the options §15.1 writes for it, each without its value, and the
// task that builds it.
type urComputeCommandForm struct {
	form  string
	owner string
}

// §15.1's forms, by its rows.
var urComputeCommandDesign = []urComputeCommandForm{
	// the Harness in the terminal (§7.11), its RPC and management (§7.10), and its history (§24.6, §24.7, §24.10)
	{form: "harness --agent --model --json", owner: "HARN-M11-09"},
	{form: "harness --enclave", owner: "HARN-M14-03"},
	{form: "harness rpc --session --new --harness", owner: "HARN-M14-02"},
	{form: "harness rpc --manage", owner: "HARN-M14-02"},
	{form: "harness ls --enclave --live --json", owner: "HARN-M14-04"},
	{form: "harness export", owner: "CTXH-M11-05"},
	{form: "harness runs --agent --size", owner: "CTXH-M11-06"},
	{form: "harness show --call", owner: "CTXH-M11-04"},
	{form: "harness continue --at --model", owner: "CTXH-M11-05"},
	{form: "harness continue --enclave", owner: "CTXH-M14-01"},
	// the catalog, local models and the person's models key (§6.3, §6.5, §16.4)
	{form: "models --local --tee --provider", owner: "INFER-M11-08"},
	{form: "models pull", owner: "INFER-M11-08"},
	{form: "models settings", owner: "INFER-M11-08"},
	{form: "models set --default --tee-only --sign-in-mail --allow --harness --tier", owner: "INFER-M11-08"},
	{form: "infer --model", owner: "INFER-M11-08"},
	// disclosures (§2.8)
	{form: "disclosures --json", owner: "CTRUST-M11-01"},
	{form: "disclosures ack", owner: "CTRUST-M12-01"},
	{form: "disclosures ack --network", owner: "CTRUST-M12-02"},
	// the gateway (§8)
	{form: "gateway status", owner: "GW-M12-02"},
	{form: "gateway token --harness", owner: "GW-M12-02"},
	{form: "gateway grants", owner: "GW-M12-02"},
	{form: "gateway config", owner: "GW-M12-07"},
	{form: "gateway run", owner: "GW-M12-08"},
	{form: "install-harness --gateway", owner: "GW-M12-07"},
	// the compute balance (§9, §16.4, §21.9)
	{form: "compute status", owner: "BAL-M12-18"},
	{form: "compute buy", owner: "BAL-M12-18"},
	{form: "compute redeem", owner: "BAL-M12-18"},
	{form: "compute auto-renew threshold", owner: "BAL-M12-18"},
	{form: "compute auto-renew monthly", owner: "BAL-M12-18"},
	{form: "compute auto-renew off", owner: "BAL-M12-18"},
	{form: "compute charges", owner: "BAL-M12-18"},
	{form: "compute statement --month", owner: "BAL-M12-18"},
	{form: "compute refund", owner: "BAL-M12-18"},
	{form: "compute budget", owner: "BAL-M12-18"},
	{form: "compute budget raise --day --month --run", owner: "BAL-M12-18"},
	{form: "compute spend --by --json", owner: "BAL-M12-18"},
	{form: "compute terms --json", owner: "BAL-M13-03"},
	{form: "compute terms accept", owner: "BAL-M13-03"},
	// enclaves and the indexer enclave (§11, §11.10), attaching and their SSH (§7.10, §12)
	{form: "enclave create --shape --egress", owner: "ENC-M14-27"},
	{form: "enclave create --role", owner: "ENC-M14-27"},
	{form: "mail indexer grant", owner: "ENC-M14-27"},
	{form: "mail indexer revoke", owner: "ENC-M14-27"},
	{form: "enclave ls", owner: "ENC-M14-27"},
	{form: "enclave show", owner: "ENC-M14-27"},
	{form: "enclave stop", owner: "ENC-M14-27"},
	{form: "enclave start", owner: "ENC-M14-27"},
	{form: "enclave rm", owner: "ENC-M14-27"},
	{form: "enclave egress", owner: "ENC-M14-27"},
	{form: "enclave keeper", owner: "ENC-M14-27"},
	{form: "enclave held", owner: "ENC-M14-27"},
	{form: "enclave release", owner: "ENC-M14-27"},
	{form: "enclave attach", owner: "ENC-M14-27"},
	{form: "enclave ssh", owner: "ENC-M14-27"},
	// the bundled SSH (§12) and git (§13)
	{form: "ssh", owner: "SSH-M14-05"},
	{form: "ssh config", owner: "SSH-M14-06"},
	{form: "ssh agent", owner: "SSH-M14-06"},
	{form: "ssh known-hosts", owner: "SSH-M14-06"},
	{form: "git", owner: "GIT-M13-07"},
	// the recURd skill (§20)
	{form: "agents ls", owner: "SKILL-M11-08"},
	{form: "agents send", owner: "SKILL-M11-08"},
	{form: "agents broadcast", owner: "SKILL-M11-08"},
	{form: "agents inbox --thread", owner: "SKILL-M11-08"},
	{form: "agents reply", owner: "SKILL-M11-08"},
	// web search (§21.6), under a verb of its own (QD-1382), and web fetch (§22)
	{form: "web-search --objective --mode --json", owner: "SRCH-M13-11"},
	{form: "fetch --json", owner: "FETCH-M13-03"},
	// listeners (§26.6 to §26.8)
	{form: "listeners --json --all --device", owner: "LSTN-M13-13"},
	{form: "listeners label --type", owner: "LSTN-M13-13"},
	{form: "listeners label --clear", owner: "LSTN-M13-13"},
	{form: "listeners hide", owner: "LSTN-M13-13"},
	{form: "listeners hide --device", owner: "LSTN-M13-13"},
	{form: "listeners unhide", owner: "LSTN-M13-13"},
	{form: "listeners refresh", owner: "LSTN-M13-13"},
	// calendars (§23.6 to §23.9)
	{form: "calendar link set --caldav --user --ics --egress", owner: "MAILCAL-M13-04"},
	{form: "calendar link set --google --microsoft --connection", owner: "MAILCAL-M13-12"},
	{form: "calendar link ls", owner: "MAILCAL-M13-04"},
	{form: "calendar link rm", owner: "MAILCAL-M13-04"},
	{form: "calendar link default", owner: "MAILCAL-M13-04"},
	{form: "calendar reconcile --applied --send", owner: "MAILCAL-M13-07"},
	{form: "calendar --from --to --calendar --json", owner: "MAILCAL-M13-10"},
	{form: "approve --events", owner: "MAILCAL-M13-06"},
	// connected services (§25.4 to §25.8), beside enrollment's ur connect (QD-1381)
	{form: "connect --feature --label", owner: "CONN-M13-10"},
	{form: "connect --add", owner: "CONN-M13-10"},
	{form: "connect --here", owner: "CONN-M13-10"},
	{form: "connect --issuer --client-id --api-host --scope --label", owner: "CONN-M13-10"},
	{form: "connect --egress", owner: "CONN-M13-10"},
	{form: "connections ls --json", owner: "CONN-M13-10"},
	{form: "connections show", owner: "CONN-M13-10"},
	{form: "disconnect", owner: "CONN-M13-10"},
	// automatic approvals (§27.9, §27.10)
	{form: "approvals --json", owner: "SAFE-M13-10"},
	{form: "approvals mode --kind", owner: "SAFE-M13-10"},
	{form: "approvals digest --day --json", owner: "SAFE-M13-11"},
	// the support conversation and its log (§28.4, §28.6, §28.7)
	{form: "support --json", owner: "support-skill"},
	{form: "support show", owner: "support-skill"},
	{form: "support send --re --kind --logs --attach", owner: "support-skill"},
	{form: "support watch --notes", owner: "support-skill"},
	{form: "support logs --sent", owner: "support-skill"},
	{form: "support export", owner: "support-skill"},
	{form: "support delete", owner: "support-skill"},
	{form: "support settings", owner: "support-skill"},
	{form: "support set --agents --agent-logs", owner: "support-skill"},
	{form: "support report", owner: "support-skill"},
}

// The forms whose owners have not registered them. Each area's command task builds its own; this file's lines are
// the review phase's to prune (C-29).
var urComputeCommandUnbuilt = []string{
	// registered, and refused until HARN-M14-03's attach lands (cmd_harness.go's urHarnessAttachEntry)
	"harness --enclave",
	"harness rpc --session --new --harness",
	"harness rpc --manage",
	"harness ls --enclave --live --json",
	"harness continue --enclave",
	"disclosures ack --network",
	"gateway status",
	"gateway token --harness",
	"gateway grants",
	"gateway config",
	"gateway run",
	"install-harness --gateway",
	"compute terms --json",
	"compute terms accept",
	"enclave create --shape --egress",
	"enclave create --role",
	"mail indexer grant",
	"mail indexer revoke",
	"enclave ls",
	"enclave show",
	"enclave stop",
	"enclave start",
	"enclave rm",
	"enclave egress",
	"enclave keeper",
	"enclave held",
	"enclave release",
	"enclave attach",
	"enclave ssh",
	"ssh",
	"ssh config",
	"ssh agent",
	"ssh known-hosts",
	"git",
	"web-search --objective --mode --json",
	"fetch --json",
	"listeners --json --all --device",
	"listeners label --type",
	"listeners label --clear",
	"listeners hide",
	"listeners hide --device",
	"listeners unhide",
	"listeners refresh",
	"calendar link set --caldav --user --ics --egress",
	"calendar link set --google --microsoft --connection",
	"calendar link ls",
	"calendar link rm",
	"calendar link default",
	"calendar reconcile --applied --send",
	"calendar --from --to --calendar --json",
	"approve --events",
	"connect --feature --label",
	"connect --add",
	"connect --here",
	"connect --issuer --client-id --api-host --scope --label",
	"connect --egress",
	"connections ls --json",
	"connections show",
	"disconnect",
	"approvals --json",
	"approvals mode --kind",
	"approvals digest --day --json",
}

// A command word of a usage line or a form: lowercase letters, digits and hyphens, as ur's commands are spelled.
var urComputeCommandWordPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// A form's command words and its options.
func urComputeFormWords(form string) ([]string, []string) {
	words := []string{}
	options := []string{}
	for _, field := range strings.Fields(form) {
		if strings.HasPrefix(field, "-") {
			options = append(options, field)
		} else {
			words = append(words, field)
		}
	}
	return words, options
}

// A usage line's command words, the literal words after ur before its first argument, option or group, and the
// names of its options, each without its value: `ur compute budget raise <agent> (--day=<usd> | --month=<usd>)` has the
// words compute, budget and raise and the options --day and --month. Nil words for a line that is not ur's.
func urComputeUsageWords(line string) ([]string, []string) {
	fields := strings.Fields(line)
	if len(fields) == 0 || fields[0] != urProgramName {
		return nil, nil
	}
	index := 1
	words := []string{}
	for ; index < len(fields) && urComputeCommandWordPattern.MatchString(fields[index]); index += 1 {
		words = append(words, fields[index])
	}
	options := []string{}
	for _, field := range fields[index:] {
		for _, part := range strings.Split(field, "|") {
			part = strings.TrimSuffix(strings.Trim(part, "[]()"), "...")
			part = strings.Trim(part, "[]()")
			if !strings.HasPrefix(part, "-") || strings.Trim(part, "-") == "" {
				continue
			}
			name, _, _ := strings.Cut(part, "=")
			options = append(options, name)
		}
	}
	return words, options
}

// Whether commands registers form: its first word's command has usage lines whose command words are the form's, and
// those lines' options together hold the form's, since docopt writes a form's alternatives on lines of their own.
func urComputeFormRegistered(commands map[string]*urCommand, form string) bool {
	words, options := urComputeFormWords(form)
	if len(words) == 0 {
		return false
	}
	command := commands[words[0]]
	if command == nil {
		return false
	}
	found := false
	lineOptions := []string{}
	for _, line := range strings.Split(command.usage, "\n") {
		lineWords, eachOptions := urComputeUsageWords(line)
		if !slices.Equal(lineWords, words) {
			continue
		}
		found = true
		lineOptions = append(lineOptions, eachOptions...)
	}
	if !found {
		return false
	}
	for _, option := range options {
		if !slices.Contains(lineOptions, option) {
			return false
		}
	}
	return true
}

// Where commands and the tables differ: a form neither registered nor listed unbuilt, a listed entry naming no form,
// and a form twice or with no owner. A form registered and still listed passes (C-29).
func urComputeCommandFindings(commands map[string]*urCommand, design []urComputeCommandForm, unbuilt []string) []string {
	findings := []string{}
	forms := []string{}
	for _, entry := range design {
		if slices.Contains(forms, entry.form) {
			findings = append(findings, "ur "+entry.form+" is in the table twice")
		}
		forms = append(forms, entry.form)
		if entry.owner == "" {
			findings = append(findings, "ur "+entry.form+" has no owner")
		}
		if !urComputeFormRegistered(commands, entry.form) && !slices.Contains(unbuilt, entry.form) {
			findings = append(findings, "ur "+entry.form+" ("+entry.owner+") is neither registered nor listed unbuilt")
		}
	}
	for _, form := range unbuilt {
		if !slices.Contains(forms, form) {
			findings = append(findings, "ur "+form+" is listed unbuilt and is no §15.1 form")
		}
	}
	return findings
}

// Every §15.1 form is registered with its words or listed unbuilt, against ur's own registry.
func TestComputeCommandsAreRegisteredOrUnbuilt(t *testing.T) {
	for _, finding := range urComputeCommandFindings(urCommands, urComputeCommandDesign, urComputeCommandUnbuilt) {
		t.Error(finding)
	}
	for _, form := range urComputeCommandUnbuilt {
		if urComputeFormRegistered(urCommands, form) {
			t.Logf("ur %s is registered and still listed unbuilt, for the review phase to prune", form)
		}
	}
}

// The web search never takes the index search's verb (QD-1382), and no form names a command enrollment or the index
// search would take for its own: a planted `ur search --objective` form fails though ur search is registered.
func TestComputeWebSearchKeepsItsOwnVerb(t *testing.T) {
	for _, entry := range urComputeCommandDesign {
		if words, _ := urComputeFormWords(entry.form); words[0] == "search" {
			t.Errorf("ur %s takes the index search's verb", entry.form)
		}
	}
	planted := []urComputeCommandForm{{form: "search --objective --mode", owner: "PLANTED-1"}}
	findings := urComputeCommandFindings(urCommands, planted, nil)
	if len(findings) != 1 || !strings.Contains(findings[0], "ur search --objective --mode (PLANTED-1) is neither registered") {
		t.Errorf("a web search form on ur search: %v", findings)
	}
}

// A planted command whose usage lacks a form's words or options fails; a form whose options sit on two lines of the
// same words passes, as does one registered and still listed; a form under another command's words fails, and so
// does a listed entry naming no form.
func TestComputeCommandsFailAPlantedGap(t *testing.T) {
	commands := map[string]*urCommand{
		"gateway": {name: "gateway", usage: "  ur gateway status [--json]\n  ur gateway grants"},
		"models": {name: "models", usage: "  ur models set [--default=<name>] [--allow=<glob>...] [--network=<net>]\n" +
			"  ur models set --harness=<h> --tier=<t> <name> [--network=<net>]"},
		"compute": {name: "compute", usage: "  ur compute budget raise <agent> (--day=<usd> | --month=<usd>) [--network=<net>]"},
	}
	design := []urComputeCommandForm{
		{form: "gateway status", owner: "PLANTED-1"},
		{form: "gateway token --harness", owner: "PLANTED-2"},
		{form: "gateway grants --json", owner: "PLANTED-3"},
		{form: "models set --default --allow --harness --tier", owner: "PLANTED-4"},
		{form: "compute budget raise --day --month --run", owner: "PLANTED-5"},
		{form: "compute raise --day", owner: "PLANTED-6"},
		{form: "listeners", owner: "PLANTED-7"},
	}
	findings := urComputeCommandFindings(commands, design, []string{"gateway status", "listeners", "listeners ls"})
	wants := []string{
		"ur gateway token --harness (PLANTED-2) is neither registered nor listed unbuilt",
		"ur gateway grants --json (PLANTED-3) is neither registered nor listed unbuilt",
		"ur compute budget raise --day --month --run (PLANTED-5) is neither registered nor listed unbuilt",
		"ur compute raise --day (PLANTED-6) is neither registered nor listed unbuilt",
		"ur listeners ls is listed unbuilt and is no §15.1 form",
	}
	slices.Sort(findings)
	slices.Sort(wants)
	if !slices.Equal(findings, wants) {
		t.Errorf("findings %q, want %q", findings, wants)
	}
	if !urComputeFormRegistered(commands, "models set --default --allow --harness --tier") {
		t.Error("a form whose options sit on two lines of its words is not registered")
	}
}

// The families of the daemon's compute methods, by the prefix each area's methods take.
var testComputeDaemonMethodPrefixes = []string{
	"harness.", "compute.", "models.", "infer.", "gateway.", "enclave.", "enclaves.", "ssh.", "git.", "agents.",
	"websearch.", "web_search.", "fetch.", "listeners.", "calendar.", "connections.", "connect.", "safety.", "support.",
}

// ur native-host relays no compute method to the extension (compute-plan-native-host-compute, QD-1253): its allow-list
// names none, so each is refused as any unlisted method is, until the extension's Worker returns from Later.
func TestNativeHostRelaysNoCompute(t *testing.T) {
	for _, method := range nativeHostRelayedMethods {
		if slices.ContainsFunc(testComputeDaemonMethodPrefixes, func(prefix string) bool { return strings.HasPrefix(method, prefix) }) {
			t.Errorf("ur native-host relays %s, a compute method", method)
		}
	}
	for _, method := range []string{"harness.prompt", "compute.balance", "models.list", "infer.run", "agents.send", "support.send"} {
		if slices.Contains(nativeHostRelayedMethods, method) {
			t.Errorf("ur native-host relays %s", method)
		}
		if !slices.ContainsFunc(testComputeDaemonMethodPrefixes, func(prefix string) bool { return strings.HasPrefix(method, prefix) }) {
			t.Errorf("%s is in no compute family", method)
		}
	}
}

// A usage line's words and options, as the forms read them.
func TestComputeUsageWords(t *testing.T) {
	cases := []struct {
		line    string
		words   []string
		options []string
	}{
		{"  ur compute auto-renew off (threshold | monthly) [--network=<net>]", []string{"compute", "auto-renew", "off"}, []string{"--network"}},
		{"  ur approve [<approval_id>] [--deny | --revoke] [--uses=<n>]", []string{"approve"}, []string{"--deny", "--revoke", "--uses"}},
		{"  ur models [--local | --tee | --provider=<p>] [--json]", []string{"models"}, []string{"--local", "--tee", "--provider", "--json"}},
		{"  ur models set [--allow=<glob>...] [--network=<net>]", []string{"models", "set"}, []string{"--allow", "--network"}},
		{"  ur evs ls <repo_id> [-l] [--ref=<ref>]... [<path>...]", []string{"evs", "ls"}, []string{"-l", "--ref"}},
		{"  ur gateway run <h> -- <command>...", []string{"gateway", "run"}, []string{}},
		{"  git credential", nil, nil},
	}
	for _, test := range cases {
		words, options := urComputeUsageWords(test.line)
		if !slices.Equal(words, test.words) || !slices.Equal(options, test.options) {
			t.Errorf("%q: words %q, options %q", test.line, words, options)
		}
	}
}
