package main

// ur admin scopes (admin_scopes_cmd.go; QD-1163): add sends nothing with no terminal or on a no, and goes confirmed on a
// yes carrying the label and its one owner; a binding naming both owners, neither or a member that is no member_id
// refuses before anything is asked; with no word the verified base's scopes print; and add is a Confirm method, the
// show not. Synthetic values only.

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A stand-in daemon's admin scopes methods: what each was sent, and the scopes the show answers.
type testUrAdminScopesStand struct {
	stateLock sync.Mutex
	calls     []string
	confirmed []bool
	params    []json.RawMessage
	show      *urAdminScopesReply
}

func (self *testUrAdminScopesStand) methods() []*sidecar.DaemonMethod {
	answer := func(name string, confirm bool, reply func(params *urAdminScopesParams) any) *sidecar.DaemonMethod {
		return &sidecar.DaemonMethod{Name: name, Confirm: confirm, Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			params := &urAdminScopesParams{}
			if err := decodeUrParams(call, params); err != nil {
				return nil, err
			}
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.calls = append(self.calls, name)
			self.confirmed = append(self.confirmed, call.Confirmed)
			self.params = append(self.params, append(json.RawMessage{}, call.Params...))
			return reply(params), nil
		}}
	}
	return []*sidecar.DaemonMethod{
		answer(urMethodAdminScopesShow, false, func(params *urAdminScopesParams) any { return self.show }),
		answer(urMethodAdminScopesAdd, true, func(params *urAdminScopesParams) any {
			return &urAdminScopesReply{Scopes: []*urAdminScope{{Label: params.Label, MemberId: params.Member}}}
		}),
	}
}

func (self *testUrAdminScopesStand) recorded() ([]string, []bool, []json.RawMessage) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.calls), slices.Clone(self.confirmed), slices.Clone(self.params)
}

// A ur over a stand-in daemon serving stand's methods, and what it printed.
func testUrAdminScopesCli(t *testing.T, stand *testUrAdminScopesStand) (*urCli, *bytes.Buffer) {
	t.Helper()
	daemon := startTestUrDaemon(t, shortTestDirectory(t), func(daemon *sidecar.Daemon) {
		for _, method := range stand.methods() {
			if err := daemon.RegisterMethod(method); err != nil {
				t.Fatal(err)
			}
		}
	})
	cli, stdout, _ := newTestUrCli(daemon.socketPath)
	return cli, stdout
}

// add sends nothing with no terminal or on a no, and on a yes goes confirmed with the label and the member alone,
// after the person was told the binding never changes.
func TestUrAdminScopesAddSignsOnlyAfterAYes(t *testing.T) {
	stand := &testUrAdminScopesStand{}
	cli, stdout := testUrAdminScopesCli(t, stand)
	member := sidecar.NewId()
	args := []string{"ur", "admin", "scopes", "add", "crew", "--member=" + member.String()}
	if code := cli.main(context.Background(), args); code != urExitFailed {
		t.Fatalf("with no terminal: exit %d", code)
	}
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"no"}}, nil }
	if code := cli.main(context.Background(), args); code != urExitFailed {
		t.Fatalf("on a no: exit %d", code)
	}
	if calls, _, _ := stand.recorded(); len(calls) != 0 {
		t.Fatalf("unconfirmed, it sent %v", calls)
	}
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"yes"}}, nil }
	if code := cli.main(context.Background(), args); code != urExitOk {
		t.Fatalf("on a yes: exit %d", code)
	}
	calls, confirmed, params := stand.recorded()
	if !slices.Equal(calls, []string{urMethodAdminScopesAdd}) || !confirmed[0] {
		t.Fatalf("on a yes it sent %v, confirmed %v", calls, confirmed)
	}
	sent := &urAdminScopesParams{}
	if err := json.Unmarshal(params[0], sent); err != nil || *sent != (urAdminScopesParams{Label: "crew", Member: member.String()}) {
		t.Fatalf("it asked %+v: %v", sent, err)
	}
	if text := stdout.String(); !strings.Contains(text, "first binding never changes") || !strings.Contains(text, "filed crew member "+member.String()) {
		t.Errorf("it printed:\n%s", text)
	}
}

// A binding naming both owners, neither, or a member that is no member_id refuses before anything is asked or sent.
func TestUrAdminScopesAddRefusesABindingBeforeAsking(t *testing.T) {
	stand := &testUrAdminScopesStand{}
	cli, _ := testUrAdminScopesCli(t, stand)
	asked := false
	cli.openTty = func() (urTty, error) { asked = true; return &testTty{lines: []string{"y"}}, nil }
	for _, args := range [][]string{
		{"ur", "admin", "scopes", "add", "crew", "--member=" + sidecar.NewId().String(), "--tag=ops"},
		{"ur", "admin", "scopes", "add", "crew", "--member=not-an-id"},
		{"ur", "admin", "scopes", "add", "crew"},
	} {
		if code := cli.main(context.Background(), args); code == urExitOk || asked {
			t.Fatalf("%v: exit %d, asked %v", args, code, asked)
		}
	}
	if calls, _, _ := stand.recorded(); len(calls) != 0 {
		t.Fatalf("it sent %v", calls)
	}
}

// With no word the verified base's scopes print, unconfirmed, and none says so.
func TestUrAdminScopesListsTheVerifiedScopes(t *testing.T) {
	member := sidecar.NewId()
	stand := &testUrAdminScopesStand{show: &urAdminScopesReply{Scopes: []*urAdminScope{{Label: "crew", MemberId: member.String()}, {Label: "ops-unit", TagId: "tag-atom"}}}}
	cli, stdout := testUrAdminScopesCli(t, stand)
	if code := cli.main(context.Background(), []string{"ur", "admin", "scopes"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	if calls, confirmed, _ := stand.recorded(); !slices.Equal(calls, []string{urMethodAdminScopesShow}) || confirmed[0] {
		t.Fatalf("it sent %v, confirmed %v", calls, confirmed)
	}
	if text := stdout.String(); !strings.Contains(text, "crew member "+member.String()) || !strings.Contains(text, "ops-unit tag tag-atom") {
		t.Errorf("it printed:\n%s", text)
	}
	stand.stateLock.Lock()
	stand.show = &urAdminScopesReply{Scopes: []*urAdminScope{}}
	stand.stateLock.Unlock()
	if code := cli.main(context.Background(), []string{"ur", "admin", "scopes", "list"}); code != urExitOk || !strings.Contains(stdout.String(), "binds none") {
		t.Errorf("no scope printed:\n%s", stdout.String())
	}
}

// add is a Confirm method, so only a person's confirmed control call runs it, never MCP; the show is not. A target
// hosting no network serves neither.
func TestUrAdminScopesAddIsConfirmOnly(t *testing.T) {
	confirmed := map[string]bool{}
	for _, method := range urAdminScopesMethods(&urDaemonNetwork{daemon: &sidecar.Daemon{}}) {
		confirmed[method.Name] = method.Confirm
	}
	if len(confirmed) != 2 || !confirmed[urMethodAdminScopesAdd] || confirmed[urMethodAdminScopesShow] {
		t.Errorf("the methods' confirmations: %v", confirmed)
	}
	if methods := urAdminScopesMethods(&testUrDaemonTarget{}); len(methods) != 0 {
		t.Error("a target with no network serves the scopes methods")
	}
}
