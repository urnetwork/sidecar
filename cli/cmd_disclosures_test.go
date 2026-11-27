package main

// ur disclosures (cmd_disclosures.go; CTRUST-M11-01): the list of the newest verified policy's disclosures, each id's
// version, summary and what it asks before, in the terminal's locale, its --json shape, policy_unavailable with no
// policy, and ur harness's prompt texts; on a stand-in of the daemon's list method over a real registry built from the
// root's fixture line (testdata/disclosure/).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

// Stand-ins of the daemon's disclosure methods over a registry: what each call was sent.
type testUrDisclosureStand struct {
	registry *sidecar.ComputeDisclosureRegistry

	stateLock sync.Mutex
	calls     []string
	params    []json.RawMessage
	confirmed []bool
}

// The list method as the daemon answers it, its unavailable reply included, without its network rule, since the test
// daemon hosts no network.
func (self *testUrDisclosureStand) methods() []*sidecar.DaemonMethod {
	return []*sidecar.DaemonMethod{{
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
			return list, err
		},
	}}
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
		"inference:engy  version 1  none: not in a TEE  asks before the first call\n",
		"inference:chutes  version 1  AP: in a TEE, chutes trusted  asks nothing\n",
		"search:parallel  version 1  asks before the first search\n    Parallel reads this search and may train on it; URnetwork does not see it\n",
		"support:urnetwork  version 1  asks before the first message you or your agents send to support\n",
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
