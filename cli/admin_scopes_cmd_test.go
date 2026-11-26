package main

// ur admin scopes (admin_scopes_cmd.go; QD-1163): add sends nothing with no terminal or on a no, and goes confirmed on a
// yes carrying the label and its one owner; a binding naming both owners, neither or a member that is no member_id
// refuses before anything is asked; with no word the verified base's scopes print; and add is a Confirm method, the
// show not. The list names on stderr the ServiceSettings record holding the scopes where its signer no longer stands
// (QD-1207), or that it could not say, its stdout the scopes' lines alone. Synthetic values only.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

// The list names the carried ServiceSettings record on stderr, its signer, the signer's member, why it no longer stands
// and who files another, while stdout is the scopes' lines alone; a list whose record could not be read says so on
// stderr; and one whose record's signer stands adds nothing, with no scope bound as with one.
func TestUrAdminScopesNamesTheCarriedRecordOnStderr(t *testing.T) {
	settings, _ := testUrAdminCarried()
	member := sidecar.NewId()
	stand := &testUrAdminScopesStand{show: &urAdminScopesReply{Scopes: []*urAdminScope{{Label: "crew", MemberId: member.String()}}, Carried: settings}}
	daemon := startTestUrDaemon(t, shortTestDirectory(t), func(daemon *sidecar.Daemon) {
		for _, method := range stand.methods() {
			if err := daemon.RegisterMethod(method); err != nil {
				t.Fatal(err)
			}
		}
	})
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "admin", "scopes"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	if text := stdout.String(); text != "crew member "+member.String()+"\n" {
		t.Errorf("stdout is not the scopes' lines alone:\n%s", text)
	}
	carriedLine := "ur admin scopes: the ServiceSettings record holding the scopes stands under a signer who no longer stands until " +
		"another is filed: service_settings: signed by " + settings.SignerId.String() + " of member " + settings.MemberId.String() +
		", revoked at position 42, its member no longer the network's; an Owner or Admin files another: ur admin settings with any option\n"
	if text := stderr.String(); text != carriedLine {
		t.Errorf("stderr reads\n%s\nwant\n%s", text, carriedLine)
	}

	for _, c := range []struct {
		show   *urAdminScopesReply
		stdout string
		stderr string
	}{
		{
			show:   &urAdminScopesReply{Scopes: []*urAdminScope{}, CarriedUnknown: true},
			stdout: "no Team scope: the network's verified base binds none\n",
			stderr: "ur admin scopes: whether the ServiceSettings record holding the scopes stands under a standing signer is not known " +
				"here, since this device could not read the config head's records now\n",
		},
		{
			show:   &urAdminScopesReply{Scopes: []*urAdminScope{{Label: "crew", MemberId: member.String()}}},
			stdout: "crew member " + member.String() + "\n",
		},
		{
			show:   &urAdminScopesReply{Scopes: []*urAdminScope{}},
			stdout: "no Team scope: the network's verified base binds none\n",
		},
	} {
		stdout.Reset()
		stderr.Reset()
		stand.stateLock.Lock()
		stand.show = c.show
		stand.stateLock.Unlock()
		if code := cli.main(context.Background(), []string{"ur", "admin", "scopes", "list"}); code != urExitOk || stdout.String() != c.stdout || stderr.String() != c.stderr {
			t.Errorf("%+v: exit %d, stdout\n%s\nstderr\n%s", c.show, code, stdout.String(), stderr.String())
		}
	}
}

// The shows' listing takes the ServiceSettings record alone: carried VersioningRules is ur admin versioning's, a
// listing of none gives none, and one that fails gives not known.
func TestUrAdminCarriedServiceSettingsTakesTheSettingsRecord(t *testing.T) {
	settings, rules := testUrAdminCarried()
	for _, c := range []struct {
		lister  *testUrAdminCarriedLister
		carried *sidecar.ConfigCarriedRecord
		unknown bool
	}{
		{lister: &testUrAdminCarriedLister{records: []*sidecar.ConfigCarriedRecord{rules, settings}}, carried: settings},
		{lister: &testUrAdminCarriedLister{records: []*sidecar.ConfigCarriedRecord{rules}}},
		{lister: &testUrAdminCarriedLister{records: []*sidecar.ConfigCarriedRecord{}}},
		{lister: &testUrAdminCarriedLister{records: []*sidecar.ConfigCarriedRecord{nil, settings}}, carried: settings},
		{lister: &testUrAdminCarriedLister{err: errors.New("the head is not cached and evs does not answer")}, unknown: true},
	} {
		carried, unknown := urAdminCarriedServiceSettings(context.Background(), c.lister)
		if carried != c.carried || unknown != c.unknown || c.lister.calls != 1 {
			t.Errorf("%+v gave %+v, unknown %t, after %d calls", c.lister.records, carried, unknown, c.lister.calls)
		}
	}
	if line := urAdminCarriedServiceSettingsLine("these settings", nil, false); line != "" {
		t.Errorf("a standing signer's record reads %q", line)
	}
}
