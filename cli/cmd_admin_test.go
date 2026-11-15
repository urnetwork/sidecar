// ur admin's Team parts (TEAM-M6-08; D-TEAM-7): each command is one admin token's, by PKCE or with --device the device
// grant, its method, path and body exactly the command run; ur-cli asks all for a Team command and auth_keys for v0's
// key; ur admin members remove shows the plan, and on a yes the server's denial and then the MemberRevoke, which a no
// never reaches, and which a member the server denied already still gets; the act method is a Confirm one, so MCP
// and unconfirmed calls never reach it; ur admin idp add refuses a client secret before any consent; and an answer a
// replay gave without its credential says how to make another.

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

	// a replay's answer carries no secret, which the server never keeps
	installTestUrAdminRun(t, func(command *sidecar.AdminCommand) string {
		return `{"client_id":"ur-oauth-x","scopes":["auth_keys"]}`
	})
	stdout.Reset()
	if code := cli.main(context.Background(), []string{"ur", "admin", "oauth-clients", "create", "--scopes=auth_keys"}); code != urExitOk || !strings.Contains(stdout.String(), "revoke this client and create another") {
		t.Errorf("a replayed creation: exit %d: %s", code, stdout.String())
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

// A daemon target whose member plan and signatures a test sets; pending answers a signed MemberRevoke whose post goes
// again.
type testUrAdminMembersTarget struct {
	testUrDaemonTarget
	plan    *sidecar.MemberRevokePlan
	signs   []sidecar.Id
	pending bool
}

func (self *testUrAdminMembersTarget) planMemberRevoke(memberId sidecar.Id) (*sidecar.MemberRevokePlan, error) {
	plan := *self.plan
	plan.MemberId = memberId
	return &plan, nil
}

func (self *testUrAdminMembersTarget) signMemberRevoke(ctx context.Context, memberId sidecar.Id) (*sidecar.MemberRevocation, error) {
	self.signs = append(self.signs, memberId)
	if self.pending {
		return &sidecar.MemberRevocation{Pending: true}, sidecar.ErrSidecarActPending
	}
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

	// signed and kept, its post's answer lost: the decision is made, and ur says the post goes again
	target.pending = true
	tty = &testTty{lines: []string{"yes"}}
	if code := cli.main(context.Background(), []string{"ur", "admin", "members", "remove", memberId.String()}); code != urExitOk || !strings.Contains(stdout.String(), "its post goes again") {
		t.Fatalf("a pending MemberRevoke: exit %d: %s", code, stdout.String())
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

// The IdP, domain, audit webhook and admin event parts: each is one token's command, its method, path and body
// exactly the command run, under the all scope; --device takes the device grant.
func TestAdminIdpDomainAndAuditCommandsAreOneTokensCommand(t *testing.T) {
	webhookId := sidecar.NewId()
	runs := installTestUrAdminRun(t, func(command *sidecar.AdminCommand) string {
		switch command.Path {
		case "/network/idp":
			return `{"idp_id":"` + sidecar.NewId().String() + `"}`
		case "/network/domain-add":
			return `{"domain":{"domain":"corp.example","txt_name":"_urnetwork-challenge.corp.example","txt_value":"challenge-value","verified":false}}`
		case "/network/domain-verify":
			return `{"domain":{"domain":"corp.example","txt_name":"_urnetwork-challenge.corp.example","txt_value":"challenge-value","verified":true}}`
		case "/network/domain-remove":
			return `{"removed":true}`
		case "/network/audit-webhook":
			if strings.Contains(string(command.Body), `"url"`) {
				return `{"webhook_id":"` + webhookId.String() + `","signing_key":"synthetic-signing-key","webhooks":[]}`
			}
			return `{"webhooks":[{"webhook_id":"` + webhookId.String() + `","url":"https://siem.example/hook","delivered_seq":7}]}`
		case "/network/admin-events":
			return `{"events":[{"seq":1,"event_time":"2026-11-15T09:00:00Z","actor_kind":"user","actor_id":"a","action":"domain.add","target_kind":"domain","result":"ok","chain_sha256":"00ff"}],"more":true}`
		}
		return `{}`
	})
	cli, stdout, _ := newTestUrCli("")
	cases := []struct {
		args   []string
		method string
		path   string
		body   map[string]any
		device bool
	}{
		{args: []string{"ur", "admin", "idp", "add", "--issuer=https://idp.example", "--client-id=synthetic-client"}, method: "POST", path: "/network/idp",
			body: map[string]any{"issuer": "https://idp.example", "client_id": "synthetic-client", "client_auth": "private_key_jwt"}},
		{args: []string{"ur", "admin", "domains", "add", "corp.example"}, method: "POST", path: "/network/domain-add", body: map[string]any{"domain": "corp.example"}},
		{args: []string{"ur", "admin", "domains", "verify", "corp.example", "--device"}, method: "POST", path: "/network/domain-verify", body: map[string]any{"domain": "corp.example"}, device: true},
		{args: []string{"ur", "admin", "domains", "remove", "corp.example"}, method: "POST", path: "/network/domain-remove", body: map[string]any{"domain": "corp.example"}},
		{args: []string{"ur", "admin", "audit-webhook"}, method: "POST", path: "/network/audit-webhook", body: map[string]any{}},
		{args: []string{"ur", "admin", "audit-webhook", "list"}, method: "POST", path: "/network/audit-webhook", body: map[string]any{}},
		{args: []string{"ur", "admin", "audit-webhook", "add", "https://siem.example/hook"}, method: "POST", path: "/network/audit-webhook", body: map[string]any{"url": "https://siem.example/hook"}},
		{args: []string{"ur", "admin", "audit-webhook", "remove", webhookId.String()}, method: "POST", path: "/network/audit-webhook", body: map[string]any{"remove_webhook_id": webhookId.String()}},
		{args: []string{"ur", "admin", "events"}, method: "GET", path: "/network/admin-events"},
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
	for _, want := range []string{
		"publish TXT _urnetwork-challenge.corp.example with the value challenge-value",
		"corp.example is verified",
		"removed corp.example",
		"https://siem.example/hook delivered through seq 7",
		"its signing key, shown once, for the receiver alone: synthetic-signing-key",
		"chain head 00ff at seq 1",
		"more events follow",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("the output does not say %q:\n%s", want, stdout.String())
		}
	}
}

// ur admin idp add refuses a client_secret IdP before any consent, so its secret never reaches the authorization URL
// or the consent page, and takes no secret on its command line at all.
func TestAdminIdpAddRefusesAClientSecretBeforeAnyConsent(t *testing.T) {
	runs := installTestUrAdminRun(t, func(command *sidecar.AdminCommand) string { return `{}` })
	cli, _, stderr := newTestUrCli("")
	if code := cli.main(context.Background(), []string{"ur", "admin", "idp", "add", "--issuer=https://idp.example", "--client-id=c", "--client-auth=client_secret"}); code == urExitOk || len(*runs) != 0 {
		t.Fatalf("a client_secret IdP: exit %d, %d runs", code, len(*runs))
	}
	if !strings.Contains(stderr.String(), "from the console") {
		t.Errorf("the refusal: %s", stderr.String())
	}
	if code := cli.main(context.Background(), []string{"ur", "admin", "idp", "add", "--issuer=https://idp.example", "--client-id=c", "--client-secret=synthetic"}); code == urExitOk || len(*runs) != 0 {
		t.Fatalf("a secret on the command line: exit %d, %d runs", code, len(*runs))
	}
}

// A replay's answer carries no invite bearer and no webhook signing key, which the server never keeps, and the part
// says how to make another; a domain the server could not verify shows the record to publish and fails the run.
func TestAdminAnswersWithoutTheirCredentialSayWhatToDo(t *testing.T) {
	installTestUrAdminRun(t, func(command *sidecar.AdminCommand) string {
		switch command.Path {
		case "/network/member-invite":
			return `{"invite_id":"` + sidecar.NewId().String() + `","expire_time":"2026-11-22T09:00:00Z"}`
		case "/network/audit-webhook":
			return `{"webhook_id":"` + sidecar.NewId().String() + `","webhooks":[]}`
		case "/network/domain-verify":
			return `{"domain":{"domain":"corp.example","txt_name":"_urnetwork-challenge.corp.example","txt_value":"challenge-value","verified":false},"error":{"message":"The TXT record was not found. DNS changes can take a while to appear."}}`
		}
		return `{}`
	})
	cli, stdout, _ := newTestUrCli("")
	if code := cli.main(context.Background(), []string{"ur", "admin", "members", "invite", "new.person@example.com"}); code != urExitOk || !strings.Contains(stdout.String(), "invite the person again") {
		t.Errorf("a replayed invite: exit %d: %s", code, stdout.String())
	}
	stdout.Reset()
	if code := cli.main(context.Background(), []string{"ur", "admin", "audit-webhook", "add", "https://siem.example/hook"}); code != urExitOk || !strings.Contains(stdout.String(), "remove this webhook and add another") {
		t.Errorf("a replayed webhook: exit %d: %s", code, stdout.String())
	}
	stdout.Reset()
	if code := cli.main(context.Background(), []string{"ur", "admin", "domains", "verify", "corp.example"}); code == urExitOk || !strings.Contains(stdout.String(), "publish TXT _urnetwork-challenge.corp.example") {
		t.Errorf("a domain not verified: exit %d: %s", code, stdout.String())
	}
}
