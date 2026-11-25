package main

// ur admin settings (admin_settings_cmd.go; §7.9's Settings fields): the change sends nothing with no terminal or on a
// no, and goes confirmed on a yes carrying exactly the options given; a value other than on or off refuses before
// anything is asked; with no option the settings print; and the change is a Confirm method, the show not. --feature
// (DESIGN-COMPUTE §16.6, CACL-M11-03) likewise: confirmed on a yes alone, through its own Confirm method, the question
// naming what would pause; a name that is no feature's, a feature this device may not turn on and one already on each
// ask nothing and send no turning-on.

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
		answer(urMethodAdminSettingsFeature, true, func(params *urAdminSettingsParams) any {
			return &sidecar.AuthFeatureStatus{Name: params.Feature, On: true, Implemented: true, Supported: true, SupportKnown: true}
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

// The change and the turning-on are Confirm methods, so only a person's confirmed control call runs them, never MCP;
// the show is not. A target hosting no network serves none.
func TestUrAdminSettingsChangeIsConfirmOnly(t *testing.T) {
	confirmed := map[string]bool{}
	for _, method := range urAdminSettingsMethods(&urDaemonNetwork{daemon: &sidecar.Daemon{}}) {
		confirmed[method.Name] = method.Confirm
	}
	if len(confirmed) != 3 || !confirmed[urMethodAdminSettings] || !confirmed[urMethodAdminSettingsFeature] || confirmed[urMethodAdminSettingsShow] {
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

// A show whose agent_repos this device may turn on, two sidecars pausing at it, and whose other features it may not.
func testUrAdminSettingsFeatureShow(pausing []sidecar.Id, admins []sidecar.Id) *urAdminSettingsReply {
	return &urAdminSettingsReply{
		Team: true, MailStrict: "off", RecordCost: "on", RecordRequired: "off",
		Features: []*sidecar.AuthFeatureStatus{
			{Name: "agent_repos", Implemented: true, Supported: true, SupportKnown: true, MayTurnOn: true, AdminMemberIds: admins, PausingSidecarIds: pausing, PausingKnown: true},
			{Name: "compute_policy", Implemented: true, Supported: false, SupportKnown: true, AdminMemberIds: admins},
			{Name: "listeners", Implemented: false, SupportKnown: true, AdminMemberIds: admins},
			{Name: "enclaves", On: true, Implemented: true, Supported: true, SupportKnown: true, AdminMemberIds: admins},
		},
	}
}

// --feature sends no turning-on with no terminal or on a no; on a yes it goes confirmed, through admin.settings.feature,
// with the feature and nothing else, and the question says it stays on and names the sidecars that would pause.
func TestUrAdminSettingsFeatureSignsOnlyAfterAYes(t *testing.T) {
	pausing := []sidecar.Id{sidecar.NewId(), sidecar.NewId()}
	stand := &testUrAdminSettingsStand{show: testUrAdminSettingsFeatureShow(pausing, []sidecar.Id{sidecar.NewId()})}
	cli, stdout := testUrAdminSettingsCli(t, stand)
	args := []string{"ur", "admin", "settings", "--feature=agent_repos"}
	if code := cli.main(context.Background(), args); code != urExitFailed {
		t.Fatalf("with no terminal: exit %d", code)
	}
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"no"}}, nil }
	if code := cli.main(context.Background(), args); code != urExitFailed {
		t.Fatalf("on a no: exit %d", code)
	}
	if calls, _, _ := stand.recorded(); slices.Contains(calls, urMethodAdminSettingsFeature) {
		t.Fatalf("unconfirmed, it sent %v", calls)
	}
	tty := &testTty{lines: []string{"yes"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), args); code != urExitOk {
		t.Fatalf("on a yes: exit %d", code)
	}
	calls, confirmed, params := stand.recorded()
	last := len(calls) - 1
	if calls[last] != urMethodAdminSettingsFeature || !confirmed[last] || slices.Contains(calls[:last], urMethodAdminSettingsFeature) || slices.Contains(calls, urMethodAdminSettings) {
		t.Fatalf("on a yes it sent %v, confirmed %v", calls, confirmed)
	}
	sent := &urAdminSettingsParams{}
	if err := json.Unmarshal(params[last], sent); err != nil || *sent != (urAdminSettingsParams{Feature: "agent_repos"}) {
		t.Fatalf("it asked %+v: %v", sent, err)
	}
	question := tty.written.String()
	if !strings.Contains(question, "Turn on agent_repos") || !strings.Contains(question, "stays on") ||
		!strings.Contains(question, pausing[0].String()) || !strings.Contains(question, pausing[1].String()) {
		t.Errorf("the question: %q", question)
	}
	if text := stdout.String(); !strings.Contains(text, "agent_repos filed") || !strings.Contains(text, "agent_repos:    on") {
		t.Errorf("it printed:\n%s", text)
	}
}

// A name that is no feature's refuses as the options parse; a feature this device may not turn on refuses saying why,
// the network's Owners and Admins named where only they can; a feature already on says so. None asks anything or sends
// a turning-on.
func TestUrAdminSettingsFeatureRefusesBeforeAsking(t *testing.T) {
	admin := sidecar.NewId()
	stand := &testUrAdminSettingsStand{show: testUrAdminSettingsFeatureShow(nil, []sidecar.Id{admin})}
	cli, stdout := testUrAdminSettingsCli(t, stand)
	asked := false
	cli.openTty = func() (urTty, error) { asked = true; return &testTty{lines: []string{"y"}}, nil }
	if code := cli.main(context.Background(), []string{"ur", "admin", "settings", "--feature=everything"}); code == urExitOk || asked {
		t.Fatalf("a name that is no feature's: exit %d, asked %v", code, asked)
	}
	if calls, _, _ := stand.recorded(); len(calls) != 0 {
		t.Fatalf("a name that is no feature's sent %v", calls)
	}
	for _, c := range []struct {
		feature string
		why     string
	}{
		{feature: "compute_policy", why: "the services serving this network do not implement it yet"},
		{feature: "listeners", why: "this release does not implement it"},
	} {
		code := cli.main(context.Background(), []string{"ur", "admin", "settings", "--feature=" + c.feature})
		if code == urExitOk || asked {
			t.Fatalf("%s: exit %d, asked %v", c.feature, code, asked)
		}
	}
	// a device that is no Owner's or Admin's names who can
	stand.stateLock.Lock()
	stand.show.Features[0].MayTurnOn = false
	stand.show.Features[0].Supported = true
	stand.stateLock.Unlock()
	errOut := &bytes.Buffer{}
	cli.stderr = errOut
	if code := cli.main(context.Background(), []string{"ur", "admin", "settings", "--feature=agent_repos"}); code == urExitOk || asked ||
		!strings.Contains(errOut.String(), admin.String()) {
		t.Fatalf("a Member's device: exit %d, asked %v, said %q", code, asked, errOut.String())
	}
	if code := cli.main(context.Background(), []string{"ur", "admin", "settings", "--feature=enclaves"}); code != urExitOk || asked ||
		!strings.Contains(stdout.String(), "enclaves is on for this network already") {
		t.Fatalf("a feature already on: exit %d, asked %v, printed %q", code, asked, stdout.String())
	}
	if calls, _, _ := stand.recorded(); slices.Contains(calls, urMethodAdminSettingsFeature) {
		t.Fatalf("a refused feature sent %v", calls)
	}
}

// With no option the features print with whether this device may turn each on, and why not.
func TestUrAdminSettingsShowsTheFeatures(t *testing.T) {
	pausing := []sidecar.Id{sidecar.NewId()}
	stand := &testUrAdminSettingsStand{show: testUrAdminSettingsFeatureShow(pausing, []sidecar.Id{sidecar.NewId()})}
	cli, stdout := testUrAdminSettingsCli(t, stand)
	if code := cli.main(context.Background(), []string{"ur", "admin", "settings"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	text := stdout.String()
	for _, line := range []string{
		"agent_repos:    off: ur admin settings --feature agent_repos turns it on; these sidecars would pause until they update: " + pausing[0].String(),
		"compute_policy: off: not offered: the services serving this network do not implement it yet",
		"listeners:      off: not offered: this release does not implement it",
		"enclaves:       on\n",
	} {
		if !strings.Contains(text, line) {
			t.Errorf("it printed no %q:\n%s", line, text)
		}
	}
}
