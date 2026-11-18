//go:build !ios_extension

// QD-1032's switch on a device (acl_prefix_settings.go's Enabled): with the defaults, which every composition takes, an
// EvsClient judges no push against a repo's rule sets, whatever rows its state holds, as 16.2.12's release that does
// not enforce reads a ruled repo: a breach reads as evs has it, by head, by number and in History, with no alarm and
// nothing journalled; a write asks the writer's local refusal nothing; and no repair, pin push or status is answered,
// each refusal naming the deferral. The filer signs nothing. NewEvsComponent installs the dark defaults where no
// composition installed a judge, and keeps a judge a composition installed. The rules' own tests run the judge with
// the switch on (evs_prefix_test.go, evs_prefix_repair_test.go).

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
)

// A filer whose settings keep the rules dark signs nothing, refusing before it reads its sidecar, its state or its
// origin.
func TestAclPrefixRulesFilerSignsNothingWhileDark(t *testing.T) {
	request := &AclPrefixRulesRequest{RepoId: NewId(), Change: AclPrefixRulesLift}
	for _, settings := range []*AclPrefixSettings{nil, DefaultAclPrefixSettings()} {
		filer := NewAclPrefixRulesFiler(&AclPrefixRulesFilerArgs{Settings: settings})
		for _, origin := range []SidecarActOrigin{SidecarActConfirmed, SidecarActMcp} {
			if _, err := filer.File(context.Background(), request, origin, nil); !errors.Is(err, ErrAclPrefixRulesDeferred) {
				t.Errorf("a dark filer, origin %v: %v", origin, err)
			}
		}
	}
	// on, the same filer goes on to its own checks
	on := NewAclPrefixRulesFiler(&AclPrefixRulesFilerArgs{Settings: testAclPrefixSettingsOn()})
	if _, err := on.File(context.Background(), request, SidecarActConfirmed, nil); !errors.Is(err, ErrSidecarActNoAuthority) {
		t.Errorf("a filer running the rules with no sidecar: %v", err)
	}
}

// A reader whose rules are dark over a repo whose rows hold a set: the breach reads as evs's newest by head, by number
// and in History, nothing is ignored, alarmed or journalled, and the repair, the pin pushes and the status refuse,
// naming the deferral. A reader running the rules over the same world ignores the breach.
func TestEvsClientJudgesNothingWhileThePrefixRulesAreDark(t *testing.T) {
	test := newEvsPrefixTest(t)
	test.file(5, AclPrefixSetOpened, "agents/build")
	test.world.push(&evsTestChange{path: "src/main.go", content: []byte("good")})
	breach := test.pushAs(test.held, &evsTestChange{path: "src/main.go", content: []byte("bad one")})
	ctx := context.Background()

	dark := test.world.reader(t, evsTestId("dark reader"))
	dark.client.EnablePrefixRules(&EvsPrefixRulesArgs{
		Sets: func(ctx context.Context, repoId Id) ([]*AclPrefixRuleSet, error) { return slices.Clone(test.sets), nil },
	})
	if dark.client.PrefixRulesEnabled() || dark.client.prefixJudge() != nil || dark.client.installedPrefixJudge() == nil {
		t.Fatal("a judge on the default settings runs the rules")
	}
	content, info, err := test.read(dark, "src/main.go")
	if err != nil || content != "bad one" || info.Version != 2 || info.IgnoredAbove != 0 || info.RuleState != "" {
		t.Fatalf("the breach at launch: %q %+v %v", content, info, err)
	}
	repo := dark.client.Repo(test.world.repoId)
	out := &bytes.Buffer{}
	if _, err := repo.ReadHead(ctx, &EvsReadArgs{Path: "src/main.go", Version: breach}, out); err != nil || out.String() != "bad one" {
		t.Errorf("the breach by number: %q %v", out, err)
	}
	history, err := repo.History(ctx, &EvsReadArgs{Path: "src/main.go"})
	if err != nil || len(history.Versions) != 2 {
		t.Fatalf("history %+v %v", history, err)
	}
	for _, version := range history.Versions {
		if version.Ignored {
			t.Errorf("version %d marked ignored", version.Version)
		}
	}
	if alarms := evsPrefixTestAlarms(dark); len(alarms) != 0 {
		t.Errorf("alarms %+v", alarms)
	}
	if units, err := dark.client.PrefixIgnored(nil); err != nil || len(units) != 0 {
		t.Errorf("the journal %v %v", units, err)
	}
	if record, ok, err := dark.client.pins.ReadRecord(test.world.repoId, test.world.refId, "src/main.go"); err != nil || (ok && (record.Accepted != nil || record.IgnoredThrough != 0)) {
		t.Errorf("the record %+v %v", record, err)
	}
	if _, err := dark.client.RepairPrefix(ctx, &EvsPrefixRepairArgs{RepoId: test.world.repoId, ByHand: true}); !errors.Is(err, ErrEvsPrefixRepairOff) || !errors.Is(err, ErrAclPrefixRulesDeferred) {
		t.Errorf("a repair: %v", err)
	}
	if _, err := repo.RepairPath(ctx, nil, "src/main.go"); !errors.Is(err, ErrEvsPrefixRepairOff) || !errors.Is(err, ErrAclPrefixRulesDeferred) {
		t.Errorf("a path's repair: %v", err)
	}
	if _, err := dark.client.PrefixRulesStatus(ctx, test.world.repoId); !errors.Is(err, ErrAclPrefixRulesDeferred) {
		t.Errorf("the status: %v", err)
	}
	if _, err := dark.client.PinPushRules(ctx, test.world.repoId, 5); !errors.Is(err, ErrAclPrefixRulesDeferred) {
		t.Errorf("the pin pushes: %v", err)
	}
	if err := dark.client.RetryPrefixPinPushes(ctx); err != nil {
		t.Errorf("the owed pin pushes: %v", err)
	}

	ruled := test.reader("ruled reader")
	if content, info, err := test.read(ruled, "src/main.go"); err != nil || content != "good" || info.IgnoredAbove != 1 {
		t.Fatalf("the breach under the rules: %q %+v %v", content, info, err)
	}
}

// A writer whose rules are dark asks its local refusal nothing and writes a path its rules would refuse.
func TestEvsWriterAsksNoPrefixRefusalWhileDark(t *testing.T) {
	test := newEvsPrefixWriterTest(t)
	writer := test.writer
	asked := 0
	writer.test.client.EnablePrefixRules(&EvsPrefixRulesArgs{
		Sets: func(ctx context.Context, repoId Id) ([]*AclPrefixRuleSet, error) { return slices.Clone(test.sets), nil },
		AllowWrite: func(write *AclPrefixWrite) AclPrefixWriteDecision {
			asked += 1
			return AclPrefixWriteDecision{AclDecision: AclDecision{Reason: AclReasonPrefixRule}, Detail: AclPrefixDetailRefused, Path: "src/other.go"}
		},
	})
	if _, err := writer.write(t, "src/other.go", []byte("written")); err != nil {
		t.Fatalf("a write at launch: %v", err)
	}
	if asked != 0 {
		t.Fatalf("the local refusal was asked %d times", asked)
	}
}

// NewEvsComponent installs the dark defaults on a client no composition gave a judge, and keeps the judge a composition
// installed, its settings with it.
func TestEvsComponentKeepsTheCompositionsPrefixSettings(t *testing.T) {
	world := newEvsTestWorld(t)
	bare := world.reader(t, evsTestId("bare reader"))
	if bare.client.installedPrefixJudge() != nil || bare.client.PrefixRulesEnabled() {
		t.Fatal("a client no composition enabled holds a judge, or runs the rules")
	}
	NewEvsComponent(bare.client)
	if bare.client.installedPrefixJudge() == nil || bare.client.PrefixRulesEnabled() {
		t.Fatal("the component's defaults")
	}
	composed := world.reader(t, evsTestId("composed reader"))
	composed.client.EnablePrefixRules(&EvsPrefixRulesArgs{Settings: testAclPrefixSettingsOn(), Repair: true})
	installed := composed.client.installedPrefixJudge()
	NewEvsComponent(composed.client)
	if composed.client.installedPrefixJudge() != installed || !composed.client.PrefixRulesEnabled() || !installed.args.Repair {
		t.Fatal("the component replaced the composition's judge")
	}
}
