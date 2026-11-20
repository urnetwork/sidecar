package main

// ur admin settings (admin_settings_cmd.go; §7.9's Settings fields): the change sends nothing with no terminal or on a
// no, and goes confirmed on a yes carrying exactly the options given; a value other than on or off refuses before
// anything is asked; with no option the settings print; and the change is a Confirm method, the show not.

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

// A stand-in daemon's admin settings methods: what each was sent, and the settings they answer.
type testUrAdminSettingsStand struct {
	stateLock sync.Mutex
	calls     []string
	confirmed []bool
	params    []json.RawMessage
	show      *urAdminSettingsReply
}

func (self *testUrAdminSettingsStand) methods() []*sidecar.DaemonMethod {
	answer := func(name string, confirm bool, reply func(params *urAdminSettingsParams) any) *sidecar.DaemonMethod {
		return &sidecar.DaemonMethod{Name: name, Confirm: confirm, Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			params := &urAdminSettingsParams{}
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
		answer(urMethodAdminSettingsShow, false, func(params *urAdminSettingsParams) any { return self.show }),
		answer(urMethodAdminSettings, true, func(params *urAdminSettingsParams) any {
			return &urAdminSettingsReply{Team: true, MailStrict: "off", RecordCost: params.RecordCost, RecordRequired: params.RecordRequired}
		}),
	}
}

func (self *testUrAdminSettingsStand) recorded() ([]string, []bool, []json.RawMessage) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.calls), slices.Clone(self.confirmed), slices.Clone(self.params)
}

// A ur over a stand-in daemon serving stand's methods, and what it printed.
func testUrAdminSettingsCli(t *testing.T, stand *testUrAdminSettingsStand) (*urCli, *bytes.Buffer) {
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

// The change sends nothing with no terminal or on a no, and on a yes goes confirmed with the options given alone.
func TestUrAdminSettingsSignsOnlyAfterAYes(t *testing.T) {
	stand := &testUrAdminSettingsStand{}
	cli, stdout := testUrAdminSettingsCli(t, stand)
	args := []string{"ur", "admin", "settings", "--record-cost=off", "--record-required=on"}
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
	tty := &testTty{lines: []string{"yes"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), args); code != urExitOk {
		t.Fatalf("on a yes: exit %d", code)
	}
	calls, confirmed, params := stand.recorded()
	if !slices.Equal(calls, []string{urMethodAdminSettings}) || !confirmed[0] {
		t.Fatalf("on a yes it sent %v, confirmed %v", calls, confirmed)
	}
	sent := &urAdminSettingsParams{}
	if err := json.Unmarshal(params[0], sent); err != nil || *sent != (urAdminSettingsParams{RecordCost: "off", RecordRequired: "on"}) {
		t.Fatalf("it asked %+v: %v", sent, err)
	}
	if question := tty.written.String(); !strings.Contains(question, "record_cost off, record_required on") {
		t.Errorf("the question: %q", question)
	}
	if text := stdout.String(); !strings.Contains(text, "record_cost:     off: per-run cost totals go to each member's vault alone") ||
		!strings.Contains(text, "record_required: on") {
		t.Errorf("it printed:\n%s", text)
	}
}

// A value other than on or off refuses as the options parse: nothing is asked or sent.
func TestUrAdminSettingsRefusesAValueBeforeAsking(t *testing.T) {
	stand := &testUrAdminSettingsStand{}
	cli, _ := testUrAdminSettingsCli(t, stand)
	asked := false
	cli.openTty = func() (urTty, error) { asked = true; return &testTty{lines: []string{"y"}}, nil }
	for _, args := range [][]string{
		{"ur", "admin", "settings", "--record-cost=maybe"},
		{"ur", "admin", "settings", "--mail-strict=true"},
		{"ur", "admin", "settings", "--record-required=1"},
	} {
		if code := cli.main(context.Background(), args); code == urExitOk || asked {
			t.Fatalf("%v: exit %d, asked %v", args, code, asked)
		}
	}
	if calls, _, _ := stand.recorded(); len(calls) != 0 {
		t.Fatalf("it sent %v", calls)
	}
}

// With no option the settings print as the device honors them, a head it cannot open saying so.
func TestUrAdminSettingsShowsTheSettings(t *testing.T) {
	stand := &testUrAdminSettingsStand{show: &urAdminSettingsReply{Team: true, MailStrict: "off", RecordCost: "on", RecordRequired: "off"}}
	cli, stdout := testUrAdminSettingsCli(t, stand)
	if code := cli.main(context.Background(), []string{"ur", "admin", "settings"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	if calls, confirmed, _ := stand.recorded(); !slices.Equal(calls, []string{urMethodAdminSettingsShow}) || confirmed[0] {
		t.Fatalf("it sent %v, confirmed %v", calls, confirmed)
	}
	if text := stdout.String(); !strings.Contains(text, "record_cost:     on: per-run cost totals go to each member's vault and the team record") ||
		!strings.Contains(text, "mail_strict:     off") || !strings.Contains(text, "record_required: off") {
		t.Errorf("it printed:\n%s", text)
	}
	stand.stateLock.Lock()
	stand.show = &urAdminSettingsReply{Team: true, Unknown: true}
	stand.stateLock.Unlock()
	if code := cli.main(context.Background(), []string{"ur", "admin", "settings"}); code != urExitOk || !strings.Contains(stdout.String(), "not known here") {
		t.Errorf("an unknown head printed:\n%s", stdout.String())
	}
}

// The change is a Confirm method, so only a person's confirmed control call runs it, never MCP; the show is not. A
// target hosting no network serves neither.
func TestUrAdminSettingsChangeIsConfirmOnly(t *testing.T) {
	confirmed := map[string]bool{}
	for _, method := range urAdminSettingsMethods(&urDaemonNetwork{daemon: &sidecar.Daemon{}}) {
		confirmed[method.Name] = method.Confirm
	}
	if len(confirmed) != 2 || !confirmed[urMethodAdminSettings] || confirmed[urMethodAdminSettingsShow] {
		t.Errorf("the methods' confirmations: %v", confirmed)
	}
	if methods := urAdminSettingsMethods(&testUrDaemonTarget{}); len(methods) != 0 {
		t.Error("a target with no network serves the settings methods")
	}
	if change, err := urAdminSettingsChangeOf(&urAdminSettingsParams{RecordCost: "on", MailStrict: "off"}); err != nil ||
		change.RecordCost == nil || !*change.RecordCost || change.MailStrict == nil || *change.MailStrict || change.RecordRequired != nil {
		t.Errorf("the change of on and off: %+v %v", change, err)
	}
}
