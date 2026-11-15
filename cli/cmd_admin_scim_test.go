// ur admin scim-token (QD-828): issue and remove are each one admin token's command, POST /network/scim-token with
// its body exactly, under the all scope; the issue prints its bearer once with the base URL; a replay's answer says to
// issue again; a model's refusal fails the run; and the part takes no default word, since an issue retires the IdP's
// bearer.

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// issue and remove each run one token's command, POST /network/scim-token, with {} and {"remove":true}; --device takes
// the device grant; the all scope; and each says what it did.
func TestAdminScimTokenIsOneTokensCommand(t *testing.T) {
	runs := installTestUrAdminRun(t, func(command *sidecar.AdminCommand) string {
		if strings.Contains(string(command.Body), `"remove"`) {
			return `{"scim_on":false,"removed":true}`
		}
		return `{"scim_bearer":"ur-scim-synthetic-bearer","scim_url":"https://api.example/scim/v2/n","scim_on":true}`
	})
	cli, stdout, _ := newTestUrCli("")
	cases := []struct {
		args   []string
		body   string
		device bool
		says   string
	}{
		{args: []string{"ur", "admin", "scim-token", "issue"}, body: `{}`, says: "its bearer, shown once, for the IdP alone: ur-scim-synthetic-bearer"},
		{args: []string{"ur", "admin", "scim-token", "issue", "--device"}, body: `{}`, device: true, says: "SCIM base URL https://api.example/scim/v2/n"},
		{args: []string{"ur", "admin", "scim-token", "remove"}, body: `{"remove":true}`, says: "SCIM is off"},
	}
	for _, c := range cases {
		before := len(*runs)
		stdout.Reset()
		if code := cli.main(context.Background(), c.args); code != urExitOk {
			t.Errorf("%v: exit %d", c.args, code)
			continue
		}
		if len(*runs) != before+1 {
			t.Errorf("%v ran %d commands", c.args, len(*runs)-before)
			continue
		}
		run := (*runs)[len(*runs)-1]
		if run.command.Method != "POST" || run.command.Path != "/network/scim-token" || string(run.command.Body) != c.body || run.device != c.device {
			t.Errorf("%v ran %s %s %s (device %v)", c.args, run.command.Method, run.command.Path, run.command.Body, run.device)
		}
		if urcliCommandScope(run.command) != "all" {
			t.Errorf("%v would ask %s", c.args, urcliCommandScope(run.command))
		}
		if !strings.Contains(stdout.String(), c.says) {
			t.Errorf("%v does not say %q:\n%s", c.args, c.says, stdout.String())
		}
	}
}

// A replay's answer carries no bearer, which the server never keeps, and the part says to issue again; a removal with
// SCIM off says so; a model's refusal fails the run and prints no bearer; and with no word the part runs nothing,
// since an issue would retire the IdP's bearer.
func TestAdminScimTokenAnswersWithoutTheBearerSayWhatToDo(t *testing.T) {
	runs := installTestUrAdminRun(t, func(command *sidecar.AdminCommand) string {
		if strings.Contains(string(command.Body), `"remove"`) {
			return `{"scim_on":false}`
		}
		return `{"scim_url":"https://api.example/scim/v2/n","scim_on":true}`
	})
	cli, stdout, _ := newTestUrCli("")
	if code := cli.main(context.Background(), []string{"ur", "admin", "scim-token", "issue"}); code != urExitOk || !strings.Contains(stdout.String(), "run ur admin scim-token issue again") {
		t.Errorf("a replayed issue: exit %d: %s", code, stdout.String())
	}
	stdout.Reset()
	if code := cli.main(context.Background(), []string{"ur", "admin", "scim-token", "remove"}); code != urExitOk || !strings.Contains(stdout.String(), "SCIM was off already") {
		t.Errorf("a removal with SCIM off: exit %d: %s", code, stdout.String())
	}
	before := len(*runs)
	if code := cli.main(context.Background(), []string{"ur", "admin", "scim-token"}); code == urExitOk || len(*runs) != before {
		t.Errorf("no word: exit %d, %d runs", code, len(*runs)-before)
	}

	refused := installTestUrAdminRun(t, func(command *sidecar.AdminCommand) string {
		return `{"scim_on":false,"error":{"message":"Only a team network has a SCIM bearer."}}`
	})
	stdout.Reset()
	if code := cli.main(context.Background(), []string{"ur", "admin", "scim-token", "issue"}); code == urExitOk || len(*refused) != 1 || strings.Contains(stdout.String(), "shown once") {
		t.Errorf("a refusal: exit %d, %d runs: %s", code, len(*refused), stdout.String())
	}
}
