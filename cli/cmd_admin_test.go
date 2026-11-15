// ur admin's Team parts (TEAM-M6-08; D-TEAM-7): each command is one admin token's, by PKCE or with --device the device
// grant, its method, path and body exactly the command run; ur-cli asks all for a Team command and auth_keys for v0's
// key; ur admin members remove shows the plan, and on a yes the server's denial and then the MemberRevoke, which a no
// never reaches, and which a member the server denied already still gets; and the act method is a Confirm one, so MCP
// and unconfirmed calls never reach it.

package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One command a test's ur-cli ran, and whether by the device grant.
type testUrAdminRun struct {
	command *sidecar.AdminCommand
	device  bool
}

// Replaces ur-cli's run for a test: each command is recorded, and answered by answer.
func installTestUrAdminRun(t *testing.T, answer func(command *sidecar.AdminCommand) string) *[]testUrAdminRun {
	t.Helper()
	runs := &[]testUrAdminRun{}
	previous := urAdminRunCommand
	urAdminRunCommand = func(ctx context.Context, cli *urCli, command *sidecar.AdminCommand, device bool) ([]byte, error) {
		*runs = append(*runs, testUrAdminRun{command: command, device: device})
		return []byte(answer(command)), nil
	}
	t.Cleanup(func() { urAdminRunCommand = previous })
	return runs
}

// Each Team command runs as exactly one token's command, its method, path and body the command; --device takes the
// device grant; ur-cli asks the all scope for each and auth_keys for v0's key alone; a model's refusal fails the run.
func TestEachAdminTeamCommandIsOneTokensCommand(t *testing.T) {
	runs := installTestUrAdminRun(t, func(command *sidecar.AdminCommand) string {
		switch command.Path {
		case "/network/members":
			return `{"members":[{"member_id":"` + sidecar.NewId().String() + `","role":"admin","email":"admin@example.com"}]}`
		case "/network/oauth-clients":
			if command.Method == "POST" {
				return `{"client_id":"ur-oauth-x","client_secret":"ur_sk_y","scopes":["auth_keys","logs:read"]}`
			}
			return `{"oauth_clients":[]}`
		}
		return `{}`
	})
	cli, stdout, _ := newTestUrCli("")
	oauthClientId := sidecar.NewId()
	cases := []struct {
		args   []string
		method string
		path   string
		body   map[string]any
		device bool
	}{
		{args: []string{"ur", "admin", "members"}, method: "GET", path: "/network/members"},
		{args: []string{"ur", "admin", "members", "list", "--device"}, method: "GET", path: "/network/members", device: true},
		{args: []string{"ur", "admin", "members", "invite", "new.person@example.com", "--role=auditor", "--expire-days=3"}, method: "POST", path: "/network/member-invite",
			body: map[string]any{"email": "new.person@example.com", "role": "auditor", "expire_days": float64(3)}},
		{args: []string{"ur", "admin", "oauth-clients"}, method: "GET", path: "/network/oauth-clients"},
		{args: []string{"ur", "admin", "oauth-clients", "create", "--scopes=auth_keys,logs:read"}, method: "POST", path: "/network/oauth-clients",
			body: map[string]any{"scopes": []any{"auth_keys", "logs:read"}}},
		{args: []string{"ur", "admin", "oauth-clients", "revoke", oauthClientId.String()}, method: "POST", path: "/network/oauth-client-revoke",
			body: map[string]any{"oauth_client_id": oauthClientId.String()}},
		{args: []string{"ur", "admin", "scim-changes"}, method: "GET", path: "/network/scim-changes"},
	}
	for _, c := range cases {
		before := len(*runs)
		if code := cli.main(context.Background(), c.args); code != urExitOk {
			t.Errorf("%v: exit %d", c.args, code)
			continue
		}
		if len(*runs) != before+1 {
			t.Errorf("%v ran %d commands", c.args, len(*runs)-before)
			continue
		}
		run := (*runs)[len(*runs)-1]
		if run.command.Method != c.method || run.command.Path != c.path || run.device != c.device {
			t.Errorf("%v ran %s %s (device %v)", c.args, run.command.Method, run.command.Path, run.device)
		}
		if c.body == nil && len(run.command.Body) != 0 {
			t.Errorf("%v sent a body %s", c.args, run.command.Body)
		}
		if c.body != nil {
			body := map[string]any{}
			if err := json.Unmarshal(run.command.Body, &body); err != nil || len(body) != len(c.body) {
				t.Errorf("%v sent %s", c.args, run.command.Body)
			}
			for key, value := range c.body {
				if encoded, _ := json.Marshal(body[key]); string(encoded) != mustJson(t, value) {
					t.Errorf("%v sent %s = %s", c.args, key, encoded)
				}
			}
		}
		if urcliCommandScope(run.command) != "all" {
			t.Errorf("%v would ask %s", c.args, urcliCommandScope(run.command))
		}
	}
	if !strings.Contains(stdout.String(), "ur_sk_y") || !strings.Contains(stdout.String(), "admin@example.com") {
		t.Errorf("the output: %s", stdout.String())
	}
	login, err := urcliLoginCommand()
	if err != nil || urcliCommandScope(login) != "auth_keys" {
		t.Errorf("v0's key asks %s", urcliCommandScope(login))
	}

	refused := installTestUrAdminRun(t, func(command *sidecar.AdminCommand) string {
		return `{"error":{"message":"Only the team's Owners and Admins may manage its OAuth clients."}}`
	})
	if code := cli.main(context.Background(), []string{"ur", "admin", "oauth-clients", "create", "--scopes=all"}); code == urExitOk || len(*refused) != 1 {
		t.Errorf("a refusal: exit %d, %d runs", code, len(*refused))
	}
}

func mustJson(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// A daemon target whose member plan and signatures a test sets.
type testUrAdminMembersTarget struct {
	testUrDaemonTarget
	plan  *sidecar.MemberRevokePlan
	signs []sidecar.Id
}

func (self *testUrAdminMembersTarget) planMemberRevoke(memberId sidecar.Id) (*sidecar.MemberRevokePlan, error) {
	plan := *self.plan
	plan.MemberId = memberId
	return &plan, nil
}

func (self *testUrAdminMembersTarget) signMemberRevoke(ctx context.Context, memberId sidecar.Id) (*sidecar.MemberRevocation, error) {
	self.signs = append(self.signs, memberId)
	return &sidecar.MemberRevocation{Entry: &bridge.AuthPin{Version: 42}}, nil
}

// ur admin members remove: the plan on the terminal; a no runs nothing; a yes runs the server's denial once, then the
// daemon signs the MemberRevoke; and a member the server denied already, as SCIM's active=false does, still gets its
// MemberRevoke.
func TestAdminMembersRemoveDeniesThenSigns(t *testing.T) {
	deviceId, agentId, repoId := sidecar.NewId(), sidecar.NewId(), sidecar.NewId()
	target := &testUrAdminMembersTarget{plan: &sidecar.MemberRevokePlan{
		Role: bridge.MemberRole_MEMBER_ROLE_MEMBER, Signatures: 1,
		DeviceIds: []sidecar.Id{deviceId}, AgentIds: []sidecar.Id{agentId}, ReposRotating: []sidecar.Id{repoId},
	}}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, _ := newTestUrCli(daemon.socketPath)
	answer := `{"member_id":"x","signature_owed":true,"deactivated_client_count":1}`
	runs := installTestUrAdminRun(t, func(command *sidecar.AdminCommand) string { return answer })
	memberId := sidecar.NewId()

	tty := &testTty{lines: []string{"n"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), []string{"ur", "admin", "members", "remove", memberId.String()}); code != urExitOk || len(*runs) != 0 || len(target.signs) != 0 {
		t.Fatalf("a no: exit %d, %d runs, %d signs", code, len(*runs), len(target.signs))
	}
	shown := tty.written.String()
	for _, want := range []string{memberId.String(), deviceId.String(), agentId.String(), repoId.String(), "autogroup:admin", "the signed MemberRevoke is the removal"} {
		if !strings.Contains(shown, want) {
			t.Errorf("the plan does not show %q:\n%s", want, shown)
		}
	}

	tty = &testTty{lines: []string{"yes"}}
	if code := cli.main(context.Background(), []string{"ur", "admin", "members", "remove", memberId.String()}); code != urExitOk {
		t.Fatalf("a yes: exit %d: %s", code, stdout.String())
	}
	if len(*runs) != 1 || (*runs)[0].command.Path != "/network/member-remove" || len(target.signs) != 1 || target.signs[0] != memberId {
		t.Fatalf("a yes: %d runs, signs %v", len(*runs), target.signs)
	}
	if !strings.Contains(stdout.String(), "landed at 42") {
		t.Errorf("the output: %s", stdout.String())
	}

	answer = `{"error":{"message":"` + urAdminNoSuchMember + `"}}`
	tty = &testTty{lines: []string{"yes"}}
	if code := cli.main(context.Background(), []string{"ur", "admin", "members", "remove", memberId.String()}); code != urExitOk || len(target.signs) != 2 {
		t.Fatalf("a member denied already: exit %d, signs %v", code, target.signs)
	}
}

// The act method is a Confirm method: only a confirmed control call runs it; the plan is not.
func TestAdminMemberMethodsAreConfirmOnly(t *testing.T) {
	methods := urAdminMemberMethods(&testUrAdminMembersTarget{})
	confirmed := map[string]bool{}
	for _, method := range methods {
		confirmed[method.Name] = method.Confirm
	}
	if !confirmed[urMethodAdminMemberAct] || confirmed[urMethodAdminMemberPlan] {
		t.Errorf("the methods' confirmations: %v", confirmed)
	}
	if methods := urAdminMemberMethods(&testUrDaemonTarget{}); len(methods) != 0 {
		t.Error("a target with no Sidecar serves the members methods")
	}
}
