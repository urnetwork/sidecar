package main

// ur disclosures (cmd_disclosures.go; CTRUST-M11-01, CTRUST-M12-01, CTRUST-M12-02): the list of the newest verified
// policy's disclosures, each id's version, summary and what it asks before, in the terminal's locale, its --json shape,
// policy_unavailable with no policy, ur harness's prompt texts, the person's acknowledgment on /dev/tty, an Owner's or
// Admin's for the network and its removal, and ur status's lines for a tagged sidecar; on a stand-in of the daemon's
// disclosure methods over a real registry built from the root's fixture line (testdata/disclosure/).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A source a test sets the newest policy of.
type testUrDisclosureSource struct {
	stateLock sync.Mutex
	policy    *sidecar.ComputePolicy
}

func (self *testUrDisclosureSource) Newest() *sidecar.ComputePolicy {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.policy
}

// A policy at version 3 carrying the root's fixture line, engy and SayGM direct and Chutes AP.
func testUrDisclosurePolicy(t *testing.T) *sidecar.ComputePolicy {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "disclosure", "disclosures.json"))
	if err != nil {
		t.Fatal(err)
	}
	disclosures := []*sidecar.ComputePolicyDisclosure{}
	if err := json.Unmarshal(data, &disclosures); err != nil {
		t.Fatal(err)
	}
	return &sidecar.ComputePolicy{
		Version:   3,
		Providers: []*sidecar.ComputePolicyProvider{{Id: "chutes", Label: sidecar.ComputeLabelAp}},
		Direct: sidecar.ComputePolicyDirectLine{Providers: []*sidecar.ComputePolicyDirect{
			{Slug: "engy"}, {Slug: "saygm"},
		}},
		Disclosures: disclosures,
	}
}

// Stand-ins of the daemon's disclosure methods over a registry: what each call was sent, and the person's
// acknowledgments, which the list carries as the daemon's component fills them.
type testUrDisclosureStand struct {
	registry *sidecar.ComputeDisclosureRegistry

	stateLock sync.Mutex
	calls     []string
	params    []json.RawMessage
	confirmed []bool
	// by id, the version acknowledged
	acknowledged map[string]uint32
	// by id, whether its lines are marked changed
	changed map[string]bool
	// what ack answers in turn, the last again once they run out; none records the acknowledgment
	ackReplies []*sidecar.DaemonComputeDisclosureActReply
	// by id, the network's acknowledgment ack_network recorded, which the list names as an Owner's taken entry
	networks map[string]*sidecar.DaemonComputeDisclosureNetworkActParams
	// what ack_network answers in place of recording, as the daemon refuses a Member's device
	networkErr error
}

// The methods as the daemon answers them, the list's unavailable reply included, without their network rule, since the
// test daemon hosts no network: the list over the registry, and ack and open recording what the person did.
func (self *testUrDisclosureStand) methods() []*sidecar.DaemonMethod {
	return []*sidecar.DaemonMethod{
		{
			Name: sidecar.DaemonMethodComputeDisclosureList,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				self.record(sidecar.DaemonMethodComputeDisclosureList, call)
				params := &sidecar.DaemonComputeDisclosureListParams{}
				if err := json.Unmarshal(call.Params, params); err != nil {
					return nil, err
				}
				list, err := self.registry.List(params.Locale)
				if errors.Is(err, sidecar.ErrComputeDisclosurePolicyUnavailable) {
					return &sidecar.ComputeDisclosureList{Disclosures: []*sidecar.ComputeDisclosureView{}, Unavailable: sidecar.ComputeDisclosureCodePolicyUnavailable}, nil
				}
				if err != nil {
					return nil, err
				}
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				for _, view := range list.Disclosures {
					view.Scope, view.Acknowledged, view.Changed = sidecar.ComputeDisclosureScopePerson, self.acknowledged[view.Id], self.changed[view.Id]
					view.Covered = !view.Asks || view.Version <= view.Acknowledged
					if network := self.networks[view.Id]; network != nil {
						view.Network = &sidecar.ComputeNetworkDisclosure{Id: view.Id, Version: network.Version, Locale: network.Locale,
							MemberId: testUrDisclosureOwner, SidecarId: testUrDisclosureOwnerDevice, PinVersion: 40,
							SignedAtMs: 1796083200000, Taken: true, Stands: view.Version <= network.Version}
					}
				}
				return list, nil
			},
		},
		{
			Name:    sidecar.DaemonMethodComputeDisclosureAckNetwork,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				self.record(sidecar.DaemonMethodComputeDisclosureAckNetwork, call)
				params := &sidecar.DaemonComputeDisclosureNetworkActParams{}
				if err := json.Unmarshal(call.Params, params); err != nil {
					return nil, err
				}
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				if self.networkErr != nil {
					return nil, self.networkErr
				}
				if self.networks == nil {
					self.networks = map[string]*sidecar.DaemonComputeDisclosureNetworkActParams{}
				}
				self.networks[params.Id] = params
				return &sidecar.DaemonComputeDisclosureActReply{Id: params.Id, Version: params.Version}, nil
			},
		},
		{
			Name:    sidecar.DaemonMethodComputeDisclosureRemoveNetwork,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				self.record(sidecar.DaemonMethodComputeDisclosureRemoveNetwork, call)
				params := &sidecar.DaemonComputeDisclosureRemoveParams{}
				if err := json.Unmarshal(call.Params, params); err != nil {
					return nil, err
				}
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				delete(self.networks, params.Id)
				return &sidecar.DaemonComputeDisclosureActReply{Id: params.Id}, nil
			},
		},
		{
			Name:    sidecar.DaemonMethodComputeDisclosureAck,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				self.record(sidecar.DaemonMethodComputeDisclosureAck, call)
				params := &sidecar.DaemonComputeDisclosureActParams{}
				if err := json.Unmarshal(call.Params, params); err != nil {
					return nil, err
				}
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				if 0 < len(self.ackReplies) {
					reply := self.ackReplies[0]
					if 1 < len(self.ackReplies) {
						self.ackReplies = self.ackReplies[1:]
					}
					return reply, nil
				}
				if self.acknowledged == nil {
					self.acknowledged = map[string]uint32{}
				}
				self.acknowledged[params.Id] = params.Version
				return &sidecar.DaemonComputeDisclosureActReply{Id: params.Id, Version: params.Version}, nil
			},
		},
		{
			Name:    sidecar.DaemonMethodComputeDisclosureOpen,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				self.record(sidecar.DaemonMethodComputeDisclosureOpen, call)
				params := &sidecar.DaemonComputeDisclosureActParams{}
				if err := json.Unmarshal(call.Params, params); err != nil {
					return nil, err
				}
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				delete(self.changed, params.Id)
				return &sidecar.DaemonComputeDisclosureActReply{Id: params.Id, Version: params.Version}, nil
			},
		},
	}
}

func (self *testUrDisclosureStand) record(method string, call *sidecar.DaemonCall) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.calls = append(self.calls, method)
	self.params = append(self.params, append(json.RawMessage{}, call.Params...))
	self.confirmed = append(self.confirmed, call.Confirmed)
}

func (self *testUrDisclosureStand) recorded() ([]string, []json.RawMessage, []bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.calls), slices.Clone(self.params), slices.Clone(self.confirmed)
}

// A ur over a daemon serving stand's methods, its environment env, with no terminal.
func testUrDisclosureCli(t *testing.T, stand *testUrDisclosureStand, env map[string]string) (*urCli, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	daemon := startTestUrDaemon(t, shortTestDirectory(t), func(daemon *sidecar.Daemon) {
		for _, method := range stand.methods() {
			if err := daemon.RegisterMethod(method); err != nil {
				t.Fatal(err)
			}
		}
	})
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	cli.getenv = func(name string) string { return env[name] }
	return cli, stdout, stderr
}

// A stand over a registry of source.
func newTestUrDisclosureStand(t *testing.T, source *testUrDisclosureSource) *testUrDisclosureStand {
	t.Helper()
	registry, err := sidecar.NewComputeDisclosureRegistry(&sidecar.ComputeDisclosureRegistryArgs{Source: source})
	if err != nil {
		t.Fatal(err)
	}
	return &testUrDisclosureStand{registry: registry}
}

// inference:local's line from the fixture policy, each id with its version and what it asks before; LANG's locale
// reaches the daemon and its German line shows; --json is the list's shape.
func TestUrDisclosuresListsLocal(t *testing.T) {
	policy := testUrDisclosurePolicy(t)
	stand := newTestUrDisclosureStand(t, &testUrDisclosureSource{policy: policy})
	cli, stdout, stderr := testUrDisclosureCli(t, stand, map[string]string{})
	if code := cli.main(t.Context(), []string{"ur", "disclosures"}); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	local := policy.Disclosures[0].English()
	for _, want := range []string{
		"inference:local  version 1  asks nothing\n    " + local.Summary + "\n",
		"inference:engy  version 1  none: not in a TEE  asks before the first call  not acknowledged\n",
		"inference:chutes  version 1  AP: in a TEE, chutes trusted  asks nothing\n",
		"search:parallel  version 1  asks before the first search  not acknowledged\n    Parallel reads this search and may train on it; URnetwork does not see it\n",
		"support:urnetwork  version 1  asks before the first message you or your agents send to support  not acknowledged\n",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("the list lacks %q:\n%s", want, stdout.String())
		}
	}
	calls, params, confirmed := stand.recorded()
	if !slices.Equal(calls, []string{sidecar.DaemonMethodComputeDisclosureList}) || confirmed[0] || string(params[0]) != `{}` {
		t.Errorf("the call %v %s %v", calls, params, confirmed)
	}

	// the terminal's locale, LC_ALL before LANG, and the German test translation
	german := newTestUrDisclosureStand(t, &testUrDisclosureSource{policy: policy})
	cli, stdout, _ = testUrDisclosureCli(t, german, map[string]string{"LANG": "en_US.UTF-8", "LC_ALL": "de_DE.UTF-8"})
	if code := cli.main(t.Context(), []string{"ur", "disclosures", "--in=acme"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stdout.String(), "    "+policy.Disclosures[0].Text("de").Summary+"\n") {
		t.Errorf("no German line:\n%s", stdout.String())
	}
	if _, params, _ := german.recorded(); string(params[0]) != `{"network":"acme","locale":"de_DE.UTF-8"}` {
		t.Errorf("the params %s", params[0])
	}

	// --json is the list as the daemon answers it
	cli, stdout, _ = testUrDisclosureCli(t, stand, map[string]string{})
	if code := cli.main(t.Context(), []string{"ur", "disclosures", "--json"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	list := &sidecar.ComputeDisclosureList{}
	decoder := json.NewDecoder(strings.NewReader(stdout.String()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(list); err != nil {
		t.Fatal(err)
	}
	if list.PolicyVersion != 3 || list.Unavailable != "" || len(list.Disclosures) != len(policy.Disclosures) {
		t.Fatalf("the json %+v", list)
	}
	view := list.Disclosures[0]
	if view.Id != "inference:local" || view.Version != 1 || view.Asks || view.Summary != local.Summary ||
		!slices.Equal(view.Exposed, local.Exposed) || !slices.Equal(view.Private, local.Private) || view.Locale != "en" {
		t.Errorf("inference:local in json %+v", view)
	}
	for _, key := range []string{`"id"`, `"version"`, `"revision"`, `"grace_days"`, `"since_ms"`, `"locale"`, `"asks"`, `"asks_text"`, `"summary"`, `"exposed"`, `"private"`, `"policy_version"`} {
		if !strings.Contains(stdout.String(), key) {
			t.Errorf("the json lacks %s", key)
		}
	}
}

// With no verified policy, ur disclosures says policy_unavailable and fails, listing nothing.
func TestUrDisclosuresPolicyUnavailable(t *testing.T) {
	stand := newTestUrDisclosureStand(t, &testUrDisclosureSource{})
	cli, stdout, stderr := testUrDisclosureCli(t, stand, map[string]string{})
	if code := cli.main(t.Context(), []string{"ur", "disclosures"}); code != urExitFailed {
		t.Fatalf("exit %d", code)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), sidecar.ComputeDisclosureCodePolicyUnavailable) {
		t.Errorf("stdout %q stderr %q", stdout.String(), stderr.String())
	}
}

// ur harness's disclosure prompt reads its line and its whole text from the daemon, only at the current version.
func TestUrDisclosuresHarnessTexts(t *testing.T) {
	policy := testUrDisclosurePolicy(t)
	stand := newTestUrDisclosureStand(t, &testUrDisclosureSource{policy: policy})
	cli, _, _ := testUrDisclosureCli(t, stand, map[string]string{})
	texts, _ := urHarnessDisclosureEntry(cli, "")
	line, err := texts.Line(t.Context(), "inference:engy")
	if err != nil || line != policy.Disclosures[2].English().Summary {
		t.Errorf("the line %q, %v", line, err)
	}
	text, err := texts.Text(t.Context(), "inference:engy", 1)
	if err != nil || !strings.HasPrefix(text, "inference:engy · version 1 · none: not in a TEE · asks before the first call\nSummary: ") {
		t.Errorf("the text %q, %v", text, err)
	}
	if _, err := texts.Text(t.Context(), "inference:engy", 2); !errors.Is(err, sidecar.ErrDisclosureChanged) {
		t.Errorf("another version: %v", err)
	}
	if _, err := texts.Line(t.Context(), "inference:nobody"); !errors.Is(err, sidecar.ErrComputeDisclosureNotCarried) {
		t.Errorf("an id not carried: %v", err)
	}
}

// ur disclosures ack prints the whole text on /dev/tty, records its opening, and on "I understand" sends the Confirm
// method for the version shown; the list then names the acknowledgment, and "changed" where the lines are marked.
func TestUrDisclosuresAckOnTty(t *testing.T) {
	policy := testUrDisclosurePolicy(t)
	stand := newTestUrDisclosureStand(t, &testUrDisclosureSource{policy: policy})
	stand.changed = map[string]bool{"inference:engy": true}
	cli, stdout, stderr := testUrDisclosureCli(t, stand, map[string]string{})
	tty := &testTty{lines: []string{"I understand"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(t.Context(), []string{"ur", "disclosures", "ack", "inference:engy", "--in=acme"}); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if stdout.String() != "acknowledged inference:engy version 1\n" {
		t.Errorf("stdout %q", stdout.String())
	}
	engy := policy.Disclosures[2].English()
	shown := tty.written.String()
	for _, line := range append(append([]string{"inference:engy · version 1 · none: not in a TEE · asks before the first call",
		"Summary: " + engy.Summary, "Could be exposed", "Private"}, engy.Exposed...), engy.Private...) {
		if !strings.Contains(shown, line) {
			t.Errorf("the terminal was not shown %q", line)
		}
	}
	calls, params, confirmed := stand.recorded()
	if !slices.Equal(calls, []string{sidecar.DaemonMethodComputeDisclosureList, sidecar.DaemonMethodComputeDisclosureOpen, sidecar.DaemonMethodComputeDisclosureAck}) ||
		!confirmed[1] || !confirmed[2] {
		t.Fatalf("the calls %v, confirmed %v", calls, confirmed)
	}
	if string(params[2]) != `{"network":"acme","id":"inference:engy","version":1}` {
		t.Errorf("the ack's params %s", params[2])
	}
	// the list names it acknowledged, and no longer changed
	cli, stdout, _ = testUrDisclosureCli(t, stand, map[string]string{})
	if code := cli.main(t.Context(), []string{"ur", "disclosures"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stdout.String(), "inference:engy  version 1  none: not in a TEE  asks before the first call  acknowledged\n") {
		t.Errorf("the list after the acknowledgment:\n%s", stdout.String())
	}

	// a grace's coverage and a changed mark, as the daemon lists them
	stand.acknowledged = map[string]uint32{"search:parallel": 1}
	stand.changed = map[string]bool{"search:parallel": true}
	policy.Disclosure("search:parallel").Version = 2
	cli, stdout, _ = testUrDisclosureCli(t, stand, map[string]string{})
	if code := cli.main(t.Context(), []string{"ur", "disclosures"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stdout.String(), "search:parallel  version 2  asks before the first search  acknowledged at version 1 only  changed\n") {
		t.Errorf("the list with an older acknowledgment:\n%s", stdout.String())
	}

	// anything but "I understand" records nothing
	declined := newTestUrDisclosureStand(t, &testUrDisclosureSource{policy: testUrDisclosurePolicy(t)})
	cli, _, stderr = testUrDisclosureCli(t, declined, map[string]string{})
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"yes"}}, nil }
	if code := cli.main(t.Context(), []string{"ur", "disclosures", "ack", "inference:engy"}); code != urExitFailed ||
		!strings.Contains(stderr.String(), "not acknowledged") {
		t.Fatalf("yes: exit %d %s", code, stderr.String())
	}
	if calls, _, _ := declined.recorded(); slices.Contains(calls, sidecar.DaemonMethodComputeDisclosureAck) {
		t.Fatalf("a declined text was acknowledged: %v", calls)
	}

	// a version that changed while it was shown records nothing, and says to run it again
	changed := newTestUrDisclosureStand(t, &testUrDisclosureSource{policy: testUrDisclosurePolicy(t)})
	changed.ackReplies = []*sidecar.DaemonComputeDisclosureActReply{{Id: "inference:engy", Refusal: sidecar.ComputeDisclosureCodeChanged}}
	cli, _, stderr = testUrDisclosureCli(t, changed, map[string]string{})
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"i understand"}}, nil }
	if code := cli.main(t.Context(), []string{"ur", "disclosures", "ack", "inference:engy"}); code != urExitFailed ||
		!strings.Contains(stderr.String(), "disclosure_changed") || !strings.Contains(stderr.String(), "again") {
		t.Fatalf("a changed version: exit %d %s", code, stderr.String())
	}
	// an id the policy does not carry is refused before anything is shown
	cli, _, stderr = testUrDisclosureCli(t, changed, map[string]string{})
	if code := cli.main(t.Context(), []string{"ur", "disclosures", "ack", "inference:nobody"}); code != urExitFailed ||
		!strings.Contains(stderr.String(), "carries no disclosure") {
		t.Fatalf("an id not carried: exit %d %s", code, stderr.String())
	}
}

// Without a terminal, ur disclosures ack refuses and sends no acknowledgment.
func TestUrDisclosuresAckRefusedWithoutTerminal(t *testing.T) {
	stand := newTestUrDisclosureStand(t, &testUrDisclosureSource{policy: testUrDisclosurePolicy(t)})
	cli, _, stderr := testUrDisclosureCli(t, stand, map[string]string{})
	if code := cli.main(t.Context(), []string{"ur", "disclosures", "ack", "inference:engy"}); code != urExitFailed ||
		!strings.Contains(stderr.String(), "terminal") {
		t.Fatalf("exit %d %s", code, stderr.String())
	}
	if calls, _, _ := stand.recorded(); slices.Contains(calls, sidecar.DaemonMethodComputeDisclosureAck) || slices.Contains(calls, sidecar.DaemonMethodComputeDisclosureOpen) {
		t.Fatalf("calls without a terminal: %v", calls)
	}
}

// The daemon's own Confirm methods, as the root builds them, without their network rule: refused unconfirmed and to a
// caller under a harness process, which it reads from the peer's pid, before the acknowledgment's backend runs.
func TestUrDisclosuresAckRefusedUnderHarness(t *testing.T) {
	acked := []string{}
	stateLock := sync.Mutex{}
	underHarness := true
	methods := sidecar.DaemonComputeDisclosureMethods(&sidecar.DaemonComputeDisclosureBackends{
		Ack: func(ctx context.Context, running *sidecar.Sidecar, args *sidecar.ComputeDisclosureAckArgs) error {
			stateLock.Lock()
			defer stateLock.Unlock()
			acked = append(acked, args.Id)
			return nil
		},
		Open: func(ctx context.Context, running *sidecar.Sidecar, id string, version uint32) error { return nil },
		UnderHarness: func(ctx context.Context, call *sidecar.DaemonCall) bool {
			stateLock.Lock()
			defer stateLock.Unlock()
			return underHarness
		},
	})
	daemon := startTestUrDaemon(t, shortTestDirectory(t), func(daemon *sidecar.Daemon) {
		for _, method := range methods {
			copied := *method
			handler := method.Handler
			copied.Network = false
			copied.Handler = func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				// the network rule's Sidecar, which the backends here do not read
				call.Sidecar = &sidecar.Sidecar{}
				return handler(ctx, call)
			}
			if err := daemon.RegisterMethod(&copied); err != nil {
				t.Fatal(err)
			}
		}
	})
	cli, _, _ := newTestUrCli(daemon.socketPath)
	params := &sidecar.DaemonComputeDisclosureActParams{Id: "inference:engy", Version: 1}
	if err := urDisclosureAck(t.Context(), cli, params); err == nil || !strings.Contains(err.Error(), "harness process") {
		t.Fatalf("under a harness: %v", err)
	}
	reply := &sidecar.DaemonComputeDisclosureActReply{}
	if err := cli.callDaemon(t.Context(), sidecar.DaemonMethodComputeDisclosureAck, params, false, reply); err == nil {
		t.Fatal("an unconfirmed call was taken")
	}
	if len(acked) != 0 {
		t.Fatalf("acknowledged %v", acked)
	}
	func() {
		stateLock.Lock()
		defer stateLock.Unlock()
		underHarness = false
	}()
	if err := urDisclosureAck(t.Context(), cli, params); err != nil {
		t.Fatalf("the person's act: %v", err)
	}
	if !slices.Equal(acked, []string{"inference:engy"}) {
		t.Fatalf("acknowledged %v", acked)
	}
}

// A command about to use what a disclosure covers: nothing where it is covered or asks nothing; the text and the
// question at a terminal; disclosure_required naming the fix without one.
func TestUrAskDisclosureOnTty(t *testing.T) {
	stand := newTestUrDisclosureStand(t, &testUrDisclosureSource{policy: testUrDisclosurePolicy(t)})
	cli, _, _ := testUrDisclosureCli(t, stand, map[string]string{})
	if err := urAskDisclosureOnTty(t.Context(), cli, "", "inference:chutes"); err != nil {
		t.Fatalf("an id that asks nothing: %v", err)
	}
	err := urAskDisclosureOnTty(t.Context(), cli, "", "search:parallel")
	if err == nil || !strings.HasPrefix(err.Error(), sidecar.ComputeDisclosureCodeRequired) || !strings.Contains(err.Error(), "ur disclosures ack search:parallel") {
		t.Fatalf("no terminal: %v", err)
	}
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"I understand"}}, nil }
	if err := urAskDisclosureOnTty(t.Context(), cli, "", "search:parallel"); err != nil {
		t.Fatalf("at a terminal: %v", err)
	}
	// covered now: nothing asked
	cli.openTty = func() (urTty, error) { return nil, errors.New("no terminal") }
	if err := urAskDisclosureOnTty(t.Context(), cli, "", "search:parallel"); err != nil {
		t.Fatalf("covered: %v", err)
	}
	calls, _, _ := stand.recorded()
	if count := len(slices.DeleteFunc(calls, func(call string) bool { return call != sidecar.DaemonMethodComputeDisclosureAck })); count != 1 {
		t.Fatalf("%d acknowledgments, want 1", count)
	}
}

// ur harness acknowledges only where ur reads the person's lines from a terminal; without one its prompt shows the
// text and takes no acknowledgment.
func TestUrDisclosuresHarnessAckNeedsTerminal(t *testing.T) {
	stand := newTestUrDisclosureStand(t, &testUrDisclosureSource{policy: testUrDisclosurePolicy(t)})
	cli, _, _ := testUrDisclosureCli(t, stand, map[string]string{})
	if texts, acker := urHarnessDisclosureEntry(cli, ""); texts == nil || acker != nil {
		t.Fatalf("without a terminal: %v, %v", texts, acker)
	}
	cli.openTty = func() (urTty, error) { return &testTty{}, nil }
	_, acker := urHarnessDisclosureEntry(cli, "acme")
	if acker == nil {
		t.Fatal("no acknowledgment at a terminal")
	}
	if err := acker.Ack(t.Context(), "inference:engy", 1); err != nil {
		t.Fatal(err)
	}
	calls, params, confirmed := stand.recorded()
	if calls[len(calls)-1] != sidecar.DaemonMethodComputeDisclosureAck || !confirmed[len(confirmed)-1] ||
		string(params[len(params)-1]) != `{"network":"acme","id":"inference:engy","version":1}` {
		t.Fatalf("the acknowledgment %v %s %v", calls, params, confirmed)
	}
}

// The Owner and the device the stand-in's network acknowledgments name.
var (
	testUrDisclosureOwner       = sidecar.Id{0x0a, 0x01}
	testUrDisclosureOwnerDevice = sidecar.Id{0x0a, 0x02}
)

// ur disclosures ack <id> --network prints the whole text on /dev/tty and, on "I understand", sends the Confirm method
// compute.disclosure.ack_network with the version, locale and revision shown, German here; the list then names the
// network's acknowledgment under the id, who gave it on which device and when.
func TestUrDisclosuresAckNetwork(t *testing.T) {
	policy := testUrDisclosurePolicy(t)
	stand := newTestUrDisclosureStand(t, &testUrDisclosureSource{policy: policy})
	cli, stdout, stderr := testUrDisclosureCli(t, stand, map[string]string{"LANG": "de_DE.UTF-8"})
	tty := &testTty{lines: []string{"I understand"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(t.Context(), []string{"ur", "disclosures", "ack", "inference:local", "--network", "--in=acme"}); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if stdout.String() != "acknowledged inference:local version 1 for the network\n" {
		t.Errorf("stdout %q", stdout.String())
	}
	if !strings.Contains(tty.written.String(), "Summary: "+policy.Disclosures[0].Text("de").Summary) ||
		!strings.Contains(tty.written.String(), "for the network's tagged and cloud sidecars") {
		t.Errorf("the terminal was shown:\n%s", tty.written.String())
	}
	calls, params, confirmed := stand.recorded()
	if !slices.Equal(calls, []string{sidecar.DaemonMethodComputeDisclosureList, sidecar.DaemonMethodComputeDisclosureOpen,
		sidecar.DaemonMethodComputeDisclosureAckNetwork}) || !confirmed[2] {
		t.Fatalf("the calls %v, confirmed %v", calls, confirmed)
	}
	if string(params[2]) != `{"network":"acme","id":"inference:local","version":1,"locale":"de","revision":0}` {
		t.Errorf("the act's params %s", params[2])
	}
	cli, stdout, _ = testUrDisclosureCli(t, stand, map[string]string{})
	if code := cli.main(t.Context(), []string{"ur", "disclosures"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	want := "    for the network: version 1, by member " + testUrDisclosureOwner.String() + " on device " + testUrDisclosureOwnerDevice.String() +
		" at 2026-12-01T00:00:00Z, covering\n"
	if !strings.Contains(stdout.String(), want) {
		t.Errorf("the list lacks %q:\n%s", want, stdout.String())
	}
	// anything but "I understand" sends nothing
	declined := newTestUrDisclosureStand(t, &testUrDisclosureSource{policy: testUrDisclosurePolicy(t)})
	cli, _, stderr = testUrDisclosureCli(t, declined, map[string]string{})
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"ok"}}, nil }
	if code := cli.main(t.Context(), []string{"ur", "disclosures", "ack", "inference:engy", "--network"}); code != urExitFailed ||
		!strings.Contains(stderr.String(), "not acknowledged") {
		t.Fatalf("declined: exit %d %s", code, stderr.String())
	}
	if calls, _, _ := declined.recorded(); slices.Contains(calls, sidecar.DaemonMethodComputeDisclosureAckNetwork) {
		t.Fatalf("a declined text was acknowledged: %v", calls)
	}
}

// Without a terminal the network's acknowledgment is refused and nothing is sent; on a Member's device the daemon's
// refusal, naming who can, is what ur says, and nothing is recorded.
func TestUrDisclosuresAckNetworkRefusedForMember(t *testing.T) {
	stand := newTestUrDisclosureStand(t, &testUrDisclosureSource{policy: testUrDisclosurePolicy(t)})
	cli, _, stderr := testUrDisclosureCli(t, stand, map[string]string{})
	if code := cli.main(t.Context(), []string{"ur", "disclosures", "ack", "inference:engy", "--network"}); code != urExitFailed ||
		!strings.Contains(stderr.String(), "terminal") {
		t.Fatalf("no terminal: exit %d %s", code, stderr.String())
	}
	if calls, _, _ := stand.recorded(); slices.Contains(calls, sidecar.DaemonMethodComputeDisclosureAckNetwork) {
		t.Fatalf("calls without a terminal: %v", calls)
	}
	stand.networkErr = fmt.Errorf("%w: this device's member is no Owner or Admin; one of the network's Owners or Admins acknowledges for it",
		sidecar.ErrNetworkDisclosureRefused)
	cli, _, stderr = testUrDisclosureCli(t, stand, map[string]string{})
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"I understand"}}, nil }
	if code := cli.main(t.Context(), []string{"ur", "disclosures", "ack", "inference:engy", "--network"}); code != urExitFailed ||
		!strings.Contains(stderr.String(), "no Owner or Admin") {
		t.Fatalf("a Member's device: exit %d %s", code, stderr.String())
	}
	if len(stand.networks) != 0 {
		t.Fatalf("a refused act recorded %v", stand.networks)
	}
}

// ur disclosures remove <id> --network takes the network's acknowledgment out once the person confirms on /dev/tty,
// and sends nothing on any other answer.
func TestUrDisclosuresRemoveNetwork(t *testing.T) {
	stand := newTestUrDisclosureStand(t, &testUrDisclosureSource{policy: testUrDisclosurePolicy(t)})
	stand.networks = map[string]*sidecar.DaemonComputeDisclosureNetworkActParams{"inference:engy": {Id: "inference:engy", Version: 1}}
	cli, _, stderr := testUrDisclosureCli(t, stand, map[string]string{})
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"no"}}, nil }
	if code := cli.main(t.Context(), []string{"ur", "disclosures", "remove", "inference:engy", "--network"}); code != urExitFailed ||
		!strings.Contains(stderr.String(), "not removed") || len(stand.networks) != 1 {
		t.Fatalf("declined: exit %d %s", code, stderr.String())
	}
	cli, stdout, stderr := testUrDisclosureCli(t, stand, map[string]string{})
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"yes"}}, nil }
	if code := cli.main(t.Context(), []string{"ur", "disclosures", "remove", "inference:engy", "--network", "--in=acme"}); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	calls, params, confirmed := stand.recorded()
	if calls[len(calls)-1] != sidecar.DaemonMethodComputeDisclosureRemoveNetwork || !confirmed[len(confirmed)-1] ||
		string(params[len(params)-1]) != `{"network":"acme","id":"inference:engy"}` || len(stand.networks) != 0 ||
		stdout.String() != "removed the network's acknowledgment of inference:engy\n" {
		t.Fatalf("the removal: %v %s, %q", calls, params[len(params)-1], stdout.String())
	}
}

// ur status names, on a tagged or cloud sidecar, each network acknowledgment it relies on: its version, who gave it on
// which device and when, and whether it covers a use, in its grace or not at all; nothing on a member's device.
func TestUrStatusNamesNetworkDisclosures(t *testing.T) {
	networkId := sidecar.Id{0x0b}
	entry := func(id string, mutate func(entry *sidecar.ComputeNetworkDisclosure)) *sidecar.ComputeNetworkDisclosure {
		network := &sidecar.ComputeNetworkDisclosure{Id: id, Version: 1, MemberId: testUrDisclosureOwner, SidecarId: testUrDisclosureOwnerDevice,
			SignedAtMs: 1796083200000, Taken: true, Stands: true}
		if mutate != nil {
			mutate(network)
		}
		return network
	}
	list := &sidecar.ComputeDisclosureList{Disclosures: []*sidecar.ComputeDisclosureView{
		{Id: "inference:engy", Version: 1, Asks: true, Scope: sidecar.ComputeDisclosureScopeNetwork, Network: entry("inference:engy", nil)},
		{Id: "search:parallel", Version: 2, Asks: true, Scope: sidecar.ComputeDisclosureScopeNetwork, Network: entry("search:parallel",
			func(network *sidecar.ComputeNetworkDisclosure) {
				network.InGrace, network.GraceEndMs = true, 1797292800000
			})},
		{Id: "inference:saygm", Version: 3, Asks: true, Scope: sidecar.ComputeDisclosureScopeNetwork, Network: entry("inference:saygm",
			func(network *sidecar.ComputeNetworkDisclosure) { network.Stands = false })},
		{Id: "listeners:publish", Version: 1, Asks: true, Scope: sidecar.ComputeDisclosureScopeNetwork, Network: entry("listeners:publish",
			func(network *sidecar.ComputeNetworkDisclosure) {
				network.Taken, network.Stands, network.Refusal = false, false, "signer"
			})},
		{Id: "inference:local", Version: 1, Scope: sidecar.ComputeDisclosureScopeNetwork},
	}}
	by := "by member " + testUrDisclosureOwner.String() + " on device " + testUrDisclosureOwnerDevice.String() + " at 2026-12-01T00:00:00Z"
	want := []string{
		"disclosure: network " + networkId.String() + " inference:engy acknowledged for the network, version 1, " + by + ", covering",
		"disclosure: network " + networkId.String() + " search:parallel acknowledged for the network, version 1, " + by +
			", covering through version 2's grace, until 2026-12-15T00:00:00Z",
		"disclosure: network " + networkId.String() + " inference:saygm acknowledged for the network, version 1, " + by + ", covering no use of version 3",
		"disclosure: network " + networkId.String() + " listeners:publish acknowledged for the network, version 1, " + by + ", not taken (signer)",
	}
	if got := urStatusDisclosureLines(networkId, list); !slices.Equal(got, want) {
		t.Errorf("the lines:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, view := range list.Disclosures {
		view.Scope = sidecar.ComputeDisclosureScopePerson
	}
	if got := urStatusDisclosureLines(networkId, list); len(got) != 0 {
		t.Errorf("a member's device: %v", got)
	}
}
