//go:build !ios_extension

// Readers of a ruled repo (EVS1-M6-04; DESIGN-DETAILS 16.6's evs_prefix_test.go), over the stand-in evs of
// evs_world_test.go: a general repo's main ref whose rows hold a rule set that names the world's own writer, an
// admin, for every path and a second writer, held, for agents/build alone. What held writes outside its prefix is a
// breach: evs commits it, and a reader under the rules ignores it.

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A world under prefix rules.
type evsPrefixTest struct {
	t     *testing.T
	world *evsTestWorld
	admin *evsTestSigner
	held  *evsTestSigner
	sets  []*AclPrefixRuleSet
}

// A world whose repo admits two writers and holds no set yet.
func newEvsPrefixTest(t *testing.T) *evsPrefixTest {
	t.Helper()
	return newEvsPrefixTestOn(t, newEvsTestWorld(t))
}

// newEvsPrefixTest over a world a test made.
func newEvsPrefixTestOn(t *testing.T, world *evsTestWorld) *evsPrefixTest {
	t.Helper()
	admin := world.signer
	held := newEvsTestSigner("held writer")
	world.config.identityKeys[held.sidecarId] = held.publicKey()
	world.config.writers = append(world.config.writers, held.sidecarId)
	world.config.rows = map[Id]*bridge.SidecarRow{
		admin.sidecarId: {SidecarId: admin.sidecarId.Bytes()},
		held.sidecarId:  {SidecarId: held.sidecarId.Bytes()},
	}
	return &evsPrefixTest{t: t, world: world, admin: admin, held: held}
}

// Files a set at a log position, in a state: opened, it names the admin for every path and held for heldPaths. Every
// push after it pins that position.
func (self *evsPrefixTest) file(at uint64, state AclPrefixSetState, heldPaths ...string) {
	rules := []*protocol.PrefixRule{{Subject: self.admin.sidecarId.Bytes(), Action: protocol.PrefixAction_PREFIX_ACTION_WRITE}}
	for _, path := range heldPaths {
		names := [][]byte{}
		for _, name := range strings.Split(path, "/") {
			names = append(names, []byte(name))
		}
		rules = append(rules, &protocol.PrefixRule{Subject: self.held.sidecarId.Bytes(), Path: names, Action: protocol.PrefixAction_PREFIX_ACTION_WRITE})
	}
	set := &AclPrefixRuleSet{At: at, Signer: self.admin.sidecarId, State: state}
	if state == AclPrefixSetOpened {
		set.Rules = AclPrefixSortRules(rules)
	}
	self.world.config.repo.PrefixRules = append(self.world.config.repo.PrefixRules, &protocol.AclRepoPrefixRulesRow{At: at, Signer: self.admin.sidecarId.Bytes()})
	self.sets = append(self.sets, set)
	self.world.authVersion = at
}

// A push by signer.
func (self *evsPrefixTest) pushAs(signer *evsTestSigner, changes ...*evsTestChange) uint64 {
	self.t.Helper()
	self.world.signer = signer
	defer func() { self.world.signer = self.admin }()
	return self.world.push(changes...)
}

// A reader of the world under its rules.
func (self *evsPrefixTest) reader(label string) *evsTestClient {
	self.t.Helper()
	reader := self.world.reader(self.t, evsTestId(label))
	self.enable(reader)
	return reader
}

// Enables the rules on a client, its sets the test's, with the switch on that keeps them dark at launch (QD-1032).
func (self *evsPrefixTest) enable(reader *evsTestClient) {
	reader.client.EnablePrefixRules(&EvsPrefixRulesArgs{
		Sets:     func(ctx context.Context, repoId Id) ([]*AclPrefixRuleSet, error) { return slices.Clone(self.sets), nil },
		Settings: testAclPrefixSettingsOn(),
	})
}

// A head read of path.
func (self *evsPrefixTest) read(reader *evsTestClient, path string) (string, *EvsFileInfo, error) {
	out := &bytes.Buffer{}
	info, err := reader.client.Repo(self.world.repoId).ReadHead(context.Background(), &EvsReadArgs{Path: path}, out)
	return out.String(), info, err
}

// The prefix_rule alarms a client raised.
func evsPrefixTestAlarms(reader *evsTestClient) []SidecarEvent {
	alarms := []SidecarEvent{}
	for _, event := range reader.eventsOf(SidecarEventEvsAlarm) {
		if event.EvsAlarm == SidecarEvsAlarmPrefixRule {
			alarms = append(alarms, event)
		}
	}
	return alarms
}

// EVS_PREFIX_RULE's detail, empty for any other error.
func evsPrefixTestDetail(err error) EvsPrefixDetail {
	var ruleErr *EvsPrefixRuleError
	if errors.As(err, &ruleErr) && errors.Is(err, ErrEvsPrefixRule) {
		return ruleErr.Detail
	}
	return ""
}

// A newest version the rules allow reads as evs has it: the admin's anywhere, held's under its prefix, and a version
// pinned below the first set, which no set binds.
func TestEvsPrefixAllowedNewestReadsAsEvsHasIt(t *testing.T) {
	test := newEvsPrefixTest(t)
	test.pushAs(test.held, &evsTestChange{path: "src/old.go", content: []byte("before any set")})
	test.file(5, AclPrefixSetOpened, "agents/build")
	test.world.push(&evsTestChange{path: "src/main.go", content: []byte("admin")})
	test.pushAs(test.held, &evsTestChange{path: "agents/build/out", content: []byte("built")})
	reader := test.reader("reader")
	for path, want := range map[string]string{"src/main.go": "admin", "agents/build/out": "built", "src/old.go": "before any set"} {
		content, info, err := test.read(reader, path)
		if err != nil || content != want || info.IgnoredAbove != 0 || info.RuleState != "" {
			t.Errorf("%s: %q %+v %v", path, content, info, err)
		}
	}
	if alarms := evsPrefixTestAlarms(reader); len(alarms) != 0 {
		t.Errorf("alarms %+v", alarms)
	}
}

// One and two ignored versions: the read shows the newest allowed version with the count over it and alarms once,
// naming the signer, the version and the push; a second read takes the record and raises no second alarm; the record's
// entry, which says what evs was shown, is evs's newest all along.
func TestEvsPrefixIgnoredVersionsWalkBackToTheAllowedOne(t *testing.T) {
	test := newEvsPrefixTest(t)
	test.file(5, AclPrefixSetOpened, "agents/build")
	test.world.push(&evsTestChange{path: "src/main.go", content: []byte("good")})
	breach := test.pushAs(test.held, &evsTestChange{path: "src/main.go", content: []byte("bad one")})
	reader := test.reader("reader")
	content, info, err := test.read(reader, "src/main.go")
	if err != nil || content != "good" || info.Version != 1 || info.IgnoredAbove != 1 || info.SignerSidecarId != test.admin.sidecarId {
		t.Fatalf("one ignored version: %q %+v %v", content, info, err)
	}
	alarms := evsPrefixTestAlarms(reader)
	if len(alarms) != 1 {
		t.Fatalf("alarms %+v", alarms)
	}
	alarm := alarms[0]
	if alarm.EvsAlarmDetail != SidecarEvsAlarmDetailIgnored || alarm.Path != "src/main.go" || *alarm.SidecarId != test.held.sidecarId ||
		alarm.Version != breach || alarm.PushId == nil || alarm.Count != 1 || *alarm.RepoId != test.world.repoId || *alarm.RefId != test.world.refId {
		t.Errorf("the alarm %+v", alarm)
	}
	record, ok, err := reader.client.pins.ReadRecord(test.world.repoId, test.world.refId, "src/main.go")
	if err != nil || !ok || record.EntryVersion != 2 || record.PinVersion != 2 || record.IgnoredThrough != 2 ||
		record.Accepted == nil || record.Accepted.Version != 1 || record.Accepted.IgnoredAbove != 1 {
		t.Fatalf("the record %+v %v", record, err)
	}
	// from the record: the same content, and no walk's alarm, even past the alarm's interval
	reader.clock.advance(2 * time.Minute)
	content, info, err = test.read(reader, "src/main.go")
	if err != nil || content != "good" || info.IgnoredAbove != 1 {
		t.Fatalf("the second read: %q %+v %v", content, info, err)
	}
	if alarms := evsPrefixTestAlarms(reader); len(alarms) != 1 {
		t.Fatalf("a second alarm: %+v", alarms)
	}
	// a second breach over the first
	test.pushAs(test.held, &evsTestChange{path: "src/main.go", content: []byte("bad two")})
	content, info, err = test.read(reader, "src/main.go")
	if err != nil || content != "good" || info.IgnoredAbove != 2 {
		t.Fatalf("two ignored versions: %q %+v %v", content, info, err)
	}
	// the admin writes over them: evs's newest is allowed again, and the record forgets the walk
	test.world.push(&evsTestChange{path: "src/main.go", content: []byte("good again")})
	content, info, err = test.read(reader, "src/main.go")
	if err != nil || content != "good again" || info.IgnoredAbove != 0 || info.Version != 4 {
		t.Fatalf("an allowed version over the breach: %q %+v %v", content, info, err)
	}
	record, _, _ = reader.client.pins.ReadRecord(test.world.repoId, test.world.refId, "src/main.go")
	if record.IgnoredThrough != 0 || record.Accepted == nil || record.Accepted.Version != 4 {
		t.Errorf("the record after it %+v", record)
	}
}

// The walk goes under WalkBackVersionCount ignored versions and no further: 64 are walked, the 65th answers
// EVS_PREFIX_RULE with detail depth and shows nothing.
func TestEvsPrefixWalksBackAtMostItsDepth(t *testing.T) {
	test := newEvsPrefixTest(t)
	test.file(5, AclPrefixSetOpened, "agents/build")
	test.world.push(&evsTestChange{path: "src/main.go", content: []byte("good")})
	for i := 0; i < 64; i += 1 {
		test.pushAs(test.held, &evsTestChange{path: "src/main.go", content: []byte(fmt.Sprint("bad ", i))})
	}
	reader := test.reader("reader")
	content, info, err := test.read(reader, "src/main.go")
	if err != nil || content != "good" || info.IgnoredAbove != 64 {
		t.Fatalf("64 ignored versions: %q %+v %v", content, info, err)
	}
	test.pushAs(test.held, &evsTestChange{path: "src/main.go", content: []byte("bad 64")})
	deep := test.reader("deep reader")
	content, _, err = test.read(deep, "src/main.go")
	if evsPrefixTestDetail(err) != EvsPrefixDetailDepth || content != "" {
		t.Fatalf("65 ignored versions: %q %v", content, err)
	}
	var ruleErr *EvsPrefixRuleError
	if errors.As(err, &ruleErr); ruleErr.Path != "src/main.go" || strings.Contains(err.Error(), "main.go") {
		t.Errorf("the refusal carries the path and its text does not: %q %q", ruleErr.Path, err)
	}
	depth := 0
	for _, alarm := range evsPrefixTestAlarms(deep) {
		if alarm.EvsAlarmDetail == SidecarEvsAlarmDetailDepth {
			depth += 1
		}
	}
	if depth != 0 && len(evsPrefixTestAlarms(deep)) != 1 {
		t.Errorf("alarms %+v", evsPrefixTestAlarms(deep))
	}
	// a smaller depth is a setting, not a constant
	shallow := test.world.reader(t, evsTestId("shallow reader"))
	settings := testAclPrefixSettingsOn()
	settings.WalkBackVersionCount = 0
	shallow.client.EnablePrefixRules(&EvsPrefixRulesArgs{
		Sets:     func(ctx context.Context, repoId Id) ([]*AclPrefixRuleSet, error) { return test.sets, nil },
		Settings: settings,
	})
	if _, _, err := test.read(shallow, "src/main.go"); evsPrefixTestDetail(err) != EvsPrefixDetailDepth {
		t.Errorf("a depth of 0: %v", err)
	}
}

// A removal ignored at the path, and at a directory above it: the removal's own token path, a prefix of the path's,
// is what is judged, and the file reads as it stood. The same removals by the admin read absent.
func TestEvsPrefixIgnoredRemovalsAtThePathAndAbove(t *testing.T) {
	test := newEvsPrefixTest(t)
	world := test.world
	test.file(5, AclPrefixSetOpened, "agents/build")
	world.push(&evsTestChange{path: "", children: []string{"src"}}, &evsTestChange{path: "src", children: []string{"main.go", "util.go"}},
		&evsTestChange{path: "src/main.go", content: []byte("main")}, &evsTestChange{path: "src/util.go", content: []byte("util")})
	// at the path
	test.pushAs(test.held, &evsTestChange{path: "src/main.go"})
	reader := test.reader("reader")
	content, info, err := test.read(reader, "src/main.go")
	if err != nil || content != "main" || info.IgnoredAbove != 1 {
		t.Fatalf("a removal ignored at the path: %q %+v %v", content, info, err)
	}
	// at the directory above: evs answers the child with the directory's removal, as it does for a removed prefix
	removed := test.pushAs(test.held, &evsTestChange{path: "src"})
	removingPush := world.commits[removed-1].parsed.Push.GetPushId()
	func() {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		util := world.paths["src/util.go"]
		util.removal = &protocol.EvsRemovalMarker{PushId: removingPush, RemovalVersion: removed, PathVersion: util.newest + 1}
		util.newest += 1
	}()
	content, info, err = test.read(reader, "src/util.go")
	if err != nil || content != "util" || info.IgnoredAbove != 1 {
		t.Fatalf("a removal ignored at the directory above: %q %+v %v", content, info, err)
	}
	if alarms := evsPrefixTestAlarms(reader); len(alarms) == 0 || *alarms[0].SidecarId != test.held.sidecarId {
		t.Errorf("alarms %+v", alarms)
	}
	// the admin's removal is followed
	world.push(&evsTestChange{path: "", children: []string{"docs"}}, &evsTestChange{path: "docs", children: []string{"a"}},
		&evsTestChange{path: "docs/a", content: []byte("a")})
	world.push(&evsTestChange{path: "docs/a"})
	if _, _, err := test.read(reader, "docs/a"); !errors.Is(err, ErrEvsPathAbsent) {
		t.Errorf("an allowed removal: %v", err)
	}
}

// A path a breach created is effectively absent, at the first read and from the record, and a listing of its
// directory leaves its row out once the record holds it so.
func TestEvsPrefixBreachCreatedPathIsAbsent(t *testing.T) {
	test := newEvsPrefixTest(t)
	world := test.world
	test.file(5, AclPrefixSetOpened, "agents/build")
	world.push(&evsTestChange{path: "", children: []string{"src"}}, &evsTestChange{path: "src", children: []string{"main.go"}},
		&evsTestChange{path: "src/main.go", content: []byte("main")})
	test.pushAs(test.held, &evsTestChange{path: "src", children: []string{"planted.go"}}, &evsTestChange{path: "src/planted.go", content: []byte("planted")})
	test.pushAs(test.held, &evsTestChange{path: "src/planted.go", content: []byte("planted twice")})
	reader := test.reader("reader")
	for range 2 {
		if content, _, err := test.read(reader, "src/planted.go"); !errors.Is(err, ErrEvsPathAbsent) || content != "" {
			t.Fatalf("a breach-created path: %q %v", content, err)
		}
	}
	record, ok, err := reader.client.pins.ReadRecord(world.repoId, world.refId, "src/planted.go")
	if err != nil || !ok || record.Accepted == nil || !record.Accepted.Absent || record.Accepted.IgnoredAbove != 2 || record.IgnoredThrough != 3 {
		t.Fatalf("the record %+v %v", record, err)
	}
	listing, err := reader.client.Repo(world.repoId).List(context.Background(), &EvsReadArgs{Path: "src"})
	if err != nil || len(listing.Entries) != 1 || string(listing.Entries[0].Name) != "main.go" {
		t.Fatalf("the listing %+v %v", listing, err)
	}
}

// evs answers collected below an ignored version, or holds nothing there: a head reader holds no copy of the
// accepted content, so the read answers EVS_PREFIX_RULE with detail unavailable and shows nothing.
func TestEvsPrefixCollectedBelowAnIgnoredVersionIsUnavailable(t *testing.T) {
	test := newEvsPrefixTest(t)
	world := test.world
	test.file(5, AclPrefixSetOpened, "agents/build")
	evsTestWriteVersionless(world, "data.bin", []byte("accepted"), false)
	world.signer = test.held
	evsTestWriteVersionless(world, "data.bin", []byte("replaced by a breach"), false)
	world.signer = test.admin
	world.collectedPaths = map[string]bool{"data.bin": true}
	reader := evsTestFormat2Reader(t, world)
	test.enable(reader)
	content, _, err := test.read(reader, "data.bin")
	if evsPrefixTestDetail(err) != EvsPrefixDetailUnavailable || content != "" {
		t.Fatalf("collected below an ignored version: %q %v", content, err)
	}
	unavailable := false
	for _, alarm := range evsPrefixTestAlarms(reader) {
		unavailable = unavailable || alarm.EvsAlarmDetail == SidecarEvsAlarmDetailUnavailable || alarm.EvsAlarmDetail == SidecarEvsAlarmDetailIgnored
	}
	if !unavailable {
		t.Errorf("no alarm: %+v", reader.eventsOf(SidecarEventEvsAlarm))
	}
}

// Under a set this device cannot read, pending or a later release's, a read returns the record's accepted version,
// marked held or update, and nothing above it; a device that holds no accepted version shows nothing.
func TestEvsPrefixPendingAndNewerSetsReturnTheRecordsVersion(t *testing.T) {
	for _, held := range []struct {
		state  AclPrefixSetState
		name   string
		detail EvsPrefixDetail
	}{
		{state: AclPrefixSetPending, name: "held", detail: EvsPrefixDetailPending},
		{state: AclPrefixSetNewer, name: "update", detail: EvsPrefixDetailUpdate},
	} {
		test := newEvsPrefixTest(t)
		test.file(5, AclPrefixSetOpened, "agents/build")
		test.world.push(&evsTestChange{path: "src/main.go", content: []byte("accepted")})
		reader := test.reader("reader")
		if content, _, err := test.read(reader, "src/main.go"); err != nil || content != "accepted" {
			t.Fatalf("%s: before the set: %q %v", held.name, content, err)
		}
		test.file(9, held.state)
		test.world.push(&evsTestChange{path: "src/main.go", content: []byte("under a set nobody here can read")})
		content, info, err := test.read(reader, "src/main.go")
		if err != nil || content != "accepted" || info.Version != 1 || info.RuleState != held.name {
			t.Errorf("%s: %q %+v %v", held.name, content, info, err)
		}
		fresh := test.reader("fresh reader")
		if content, _, err := test.read(fresh, "src/main.go"); evsPrefixTestDetail(err) != held.detail || content != "" {
			t.Errorf("%s: a device with no accepted version: %q %v", held.name, content, err)
		}
		// the set arrives: the newest version is its admin's
		test.sets[1] = &AclPrefixRuleSet{At: 9, Signer: test.admin.sidecarId, State: AclPrefixSetOpened,
			Rules: []*protocol.PrefixRule{{Subject: test.admin.sidecarId.Bytes(), Action: protocol.PrefixAction_PREFIX_ACTION_WRITE}}}
		if content, info, err := test.read(reader, "src/main.go"); err != nil || content != "under a set nobody here can read" || info.RuleState != "" {
			t.Errorf("%s: once the set opens: %q %+v %v", held.name, content, info, err)
		}
	}
}

// A listing judges the deltas after evs's folded table: an ignored one is not applied, and alarms; the table cached
// for lookups stays evs's own.
func TestEvsPrefixListLeavesOutAnIgnoredDelta(t *testing.T) {
	test := newEvsPrefixTest(t)
	world := test.world
	test.file(5, AclPrefixSetOpened, "agents/build")
	world.push(&evsTestChange{path: "", children: []string{"src"}}, &evsTestChange{path: "src", children: []string{"main.go"}},
		&evsTestChange{path: "src/main.go", content: []byte("main")})
	reader := test.reader("reader")
	repo := reader.client.Repo(world.repoId)
	names := func(listing *EvsListing) string {
		listed := []string{}
		for _, entry := range listing.Entries {
			listed = append(listed, string(entry.Name))
		}
		return strings.Join(listed, ",")
	}
	// the breach's delta, which evs has not folded: the reply carries it after the table
	breach := test.pushAs(test.held, &evsTestChange{path: "src", children: []string{"planted.go"}}, &evsTestChange{path: "src/planted.go", content: []byte("planted")})
	var delta *protocol.EvsIndexVersion
	func() {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		src := world.paths["src"]
		src.rows = src.rows[:1]
		delta = &protocol.EvsIndexVersion{PushId: src.versions[2].pushId, CommitVersion: breach, EntryVersion: src.versions[2].entryBytes}
	}()
	// called under the world's lock
	world.mutatePath = func(reply *protocol.EvsReadPathReply) {
		if reply.GetNames() == nil {
			return
		}
		reply.NamesThrough = 1
		reply.Deltas = []*protocol.EvsIndexVersion{delta}
	}
	listing, err := repo.List(context.Background(), &EvsReadArgs{Path: "src"})
	if err != nil || names(listing) != "main.go" {
		t.Fatalf("the listing with an ignored delta: %v %v", listing, err)
	}
	alarms := evsPrefixTestAlarms(reader)
	if len(alarms) != 1 || alarms[0].Path != "src" || *alarms[0].SidecarId != test.held.sidecarId || alarms[0].Version != breach {
		t.Errorf("alarms %+v", alarms)
	}
	if row := reader.client.epochs.cachedListing(world.repoId, world.refId, listing.HeadVersion, "src").rows["planted.go"]; row == nil {
		t.Errorf("the lookup's table lost a row evs holds")
	}
	// a reader no composition enabled the rules on keeps them dark, the launch default (QD-1032): it sees evs's table,
	// the breach's row in it, and alarms nothing
	plain := newEvsTestWorldCopyReader(t, world)
	plainListing, err := plain.client.Repo(world.repoId).List(context.Background(), &EvsReadArgs{Path: "src"})
	if err != nil || names(plainListing) != "main.go,planted.go" {
		t.Errorf("a client with the rules dark on a ruled repo: %v %v", plainListing, err)
	}
	if alarms := evsPrefixTestAlarms(plain); len(alarms) != 0 {
		t.Errorf("a client with the rules dark alarmed %+v", alarms)
	}
}

// A client no composition enabled the rules on, reading a repo whose rows hold a set.
func newEvsTestWorldCopyReader(t *testing.T, world *evsTestWorld) *evsTestClient {
	t.Helper()
	return world.reader(t, evsTestId("unruled reader"))
}

// History lists every version, the ignored ones marked with their signer.
func TestEvsPrefixHistoryMarksIgnoredVersions(t *testing.T) {
	test := newEvsPrefixTest(t)
	test.file(5, AclPrefixSetOpened, "agents/build")
	test.world.push(&evsTestChange{path: "src/main.go", content: []byte("one")})
	test.pushAs(test.held, &evsTestChange{path: "src/main.go", content: []byte("two")})
	test.world.push(&evsTestChange{path: "src/main.go", content: []byte("three")})
	test.pushAs(test.held, &evsTestChange{path: "src/main.go"})
	reader := test.reader("reader")
	history, err := reader.client.Repo(test.world.repoId).History(context.Background(), &EvsReadArgs{Path: "src/main.go"})
	if err != nil || len(history.Versions) != 4 {
		t.Fatalf("history %+v %v", history, err)
	}
	marks := []string{}
	for _, version := range history.Versions {
		mark := fmt.Sprint(version.Version)
		if version.Ignored {
			mark += " ignored by " + version.SignerSidecarId.String()
		}
		marks = append(marks, mark)
	}
	held := test.held.sidecarId.String()
	if got, want := strings.Join(marks, "; "), "4 ignored by "+held+"; 3; 2 ignored by "+held+"; 1"; got != want {
		t.Errorf("marks %q, want %q", got, want)
	}
	// a version asked for by number that this device ignores is not shown
	out := &bytes.Buffer{}
	_, err = reader.client.Repo(test.world.repoId).ReadHead(context.Background(), &EvsReadArgs{Path: "src/main.go", Version: 2}, out)
	if evsPrefixTestDetail(err) != EvsPrefixDetailRefused || out.Len() != 0 {
		t.Errorf("an ignored version by number: %q %v", out, err)
	}
	out.Reset()
	if _, err = reader.client.Repo(test.world.repoId).ReadHead(context.Background(), &EvsReadArgs{Path: "src/main.go", Version: 3}, out); err != nil || out.String() != "three" {
		t.Errorf("an allowed version by number: %q %v", out, err)
	}
}

// No change event for an ignored change: a statement whose every change this device ignores raises the alarm and no
// event, and the next allowed one raises its event.
func TestEvsPrefixNoChangeEventForAnIgnoredChange(t *testing.T) {
	test := newEvsPrefixTest(t)
	world := test.world
	test.file(5, AclPrefixSetOpened, "agents/build")
	leases := newEvsTestLeases(world)
	subscriber := newEvsSubscribeTest(t, world, leases, newEvsTestStore(t))
	test.enable(subscriber)
	subscriber.client.subscriber.random = func(limit time.Duration) time.Duration { return limit / 2 }
	world.push(&evsTestChange{path: "src/main.go", content: []byte("one")})
	ctx := context.Background()
	own := &evsTestChanges{}
	if _, err := subscriber.client.Repo(world.repoId).Subscribe(ctx, &EvsSubscribeArgs{RefName: EvsMainRefName, Paths: []string{"src", "agents"}, Changes: own.add}); err != nil {
		t.Fatal(err)
	}
	subscriber.clock.advance(subscriber.client.settings.SubscribeRereadDelay)
	subscriber.client.subscriber.runDue(ctx)
	breach := test.pushAs(test.held, &evsTestChange{path: "src/main.go", content: []byte("breach")})
	world.hint(subscriber, 100)
	subscriber.client.subscriber.runDue(ctx)
	if versions := own.versions(); slices.Contains(versions, breach) {
		t.Fatalf("a change event for an ignored change: %v", versions)
	}
	alarms := evsPrefixTestAlarms(subscriber)
	if len(alarms) != 1 || alarms[0].Version != breach || alarms[0].Path != "" || *alarms[0].SidecarId != test.held.sidecarId {
		t.Fatalf("alarms %+v", alarms)
	}
	subscriber.clock.advance(time.Second)
	allowed := test.pushAs(test.held, &evsTestChange{path: "agents/build/out", content: []byte("built")})
	world.hint(subscriber, 101)
	subscriber.client.subscriber.runDue(ctx)
	if change := own.last(); change == nil || change.Version != allowed || !slices.Equal(change.Paths, []string{"agents"}) {
		t.Fatalf("the allowed change %+v", own.last())
	}
}

// A read record stored before Accepted and IgnoredThrough were kept reads as none, which only walks again; and what
// a walk notes survives the store.
func TestEvsPrefixRecordStoredBeforeReadsAsNone(t *testing.T) {
	test := newEvsPrefixTest(t)
	world := test.world
	test.file(5, AclPrefixSetOpened, "agents/build")
	world.push(&evsTestChange{path: "src/main.go", content: []byte("good")})
	test.pushAs(test.held, &evsTestChange{path: "src/main.go", content: []byte("bad")})
	store := newEvsTestStore(t)
	old := []*evsReadRecordRecord{{RefId: world.refId.String(), Path: "src/main.go", EntryVersion: 1, PinVersion: 0, UsedAtMs: 1}}
	data, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	if err := aclPrefixWriteStoreFile(store, evsReadDirectory+world.repoId.String(), data); err != nil {
		t.Fatal(err)
	}
	pins := NewEvsPinStore(store, DefaultEvsSettings())
	record, ok, err := pins.ReadRecord(world.repoId, world.refId, "src/main.go")
	if err != nil || !ok || record.Accepted != nil || record.IgnoredThrough != 0 {
		t.Fatalf("an old record %+v %v", record, err)
	}
	// a client on that store walks, alarms once, and keeps what it found
	first := newEvsTestClient(t, world, store)
	first.client.args.Gkm = world.gkm
	first.client.args.Config = func() GkmAuthView { return world.config }
	test.enable(first)
	if content, info, err := test.read(first, "src/main.go"); err != nil || content != "good" || info.IgnoredAbove != 1 {
		t.Fatalf("the walk: %q %+v %v", content, info, err)
	}
	if alarms := evsPrefixTestAlarms(first); len(alarms) != 1 {
		t.Fatalf("alarms %+v", alarms)
	}
	// a second client on the same store, as after a restart: the record, no walk, no alarm
	second := newEvsTestClient(t, world, store)
	second.client.args.Gkm = world.gkm
	second.client.args.Config = func() GkmAuthView { return world.config }
	test.enable(second)
	if content, info, err := test.read(second, "src/main.go"); err != nil || content != "good" || info.IgnoredAbove != 1 {
		t.Fatalf("after a restart: %q %+v %v", content, info, err)
	}
	if alarms := evsPrefixTestAlarms(second); len(alarms) != 0 {
		t.Fatalf("an alarm from the record: %+v", alarms)
	}
}

// The alarm: one event for each (repo, ref, signer) in AlarmInterval, the next carrying the first path and the count
// of what was judged since; another signer has its own; set_void and set_newer once a set a device, across a restart.
func TestEvsPrefixAlarmOneEventASignerAMinuteWithTheCount(t *testing.T) {
	test := newEvsPrefixTest(t)
	world := test.world
	other := newEvsTestSigner("another held writer")
	world.config.identityKeys[other.sidecarId] = other.publicKey()
	world.config.writers = append(world.config.writers, other.sidecarId)
	world.config.rows[other.sidecarId] = &bridge.SidecarRow{SidecarId: other.sidecarId.Bytes()}
	test.file(5, AclPrefixSetOpened, "agents/build")
	paths := []string{"a", "b", "c", "d"}
	for _, path := range paths {
		world.push(&evsTestChange{path: path, content: []byte("good")})
		test.pushAs(test.held, &evsTestChange{path: path, content: []byte("bad")})
	}
	world.push(&evsTestChange{path: "e", content: []byte("good")})
	test.pushAs(other, &evsTestChange{path: "e", content: []byte("bad")})
	reader := test.reader("reader")
	for _, path := range paths[:3] {
		if content, _, err := test.read(reader, path); err != nil || content != "good" {
			t.Fatalf("%s: %q %v", path, content, err)
		}
	}
	alarms := evsPrefixTestAlarms(reader)
	if len(alarms) != 1 || alarms[0].Path != "a" || alarms[0].Count != 1 {
		t.Fatalf("within the interval: %+v", alarms)
	}
	// another signer's breach is its own event
	if _, _, err := test.read(reader, "e"); err != nil {
		t.Fatal(err)
	}
	if alarms = evsPrefixTestAlarms(reader); len(alarms) != 2 || *alarms[1].SidecarId != other.sidecarId {
		t.Fatalf("another signer: %+v", alarms)
	}
	// past the interval the next event names the first path judged since the last and counts them all
	reader.clock.advance(DefaultAclPrefixSettings().AlarmInterval)
	if _, _, err := test.read(reader, "d"); err != nil {
		t.Fatal(err)
	}
	alarms = evsPrefixTestAlarms(reader)
	if len(alarms) != 3 || alarms[2].Path != "b" || alarms[2].Count != 3 || *alarms[2].SidecarId != test.held.sidecarId {
		t.Fatalf("past the interval: %+v", alarms)
	}
	for _, alarm := range alarms {
		if alarm.EvsAlarmDetail != SidecarEvsAlarmDetailIgnored {
			t.Errorf("detail %s", alarm.EvsAlarmDetail)
		}
	}

	// a void set and a newer one: once a set a device, with the row's signer and its position, across a restart
	voided := newEvsPrefixTest(t)
	voided.file(5, AclPrefixSetOpened, "agents/build")
	voided.file(7, AclPrefixSetVoid)
	voided.file(8, AclPrefixSetNewer)
	voided.world.push(&evsTestChange{path: "x", content: []byte("x")})
	store := newEvsTestStore(t)
	details := func() []string {
		client := newEvsTestClient(t, voided.world, store)
		client.client.args.Gkm = voided.world.gkm
		client.client.args.Config = func() GkmAuthView { return voided.world.config }
		voided.enable(client)
		for range 2 {
			if _, _, err := voided.read(client, "x"); evsPrefixTestDetail(err) != EvsPrefixDetailUpdate {
				t.Fatalf("under a newer set: %v", err)
			}
		}
		details := []string{}
		for _, alarm := range evsPrefixTestAlarms(client) {
			if alarm.PushId != nil || *alarm.SidecarId != voided.admin.sidecarId {
				t.Errorf("a set's alarm %+v", alarm)
			}
			details = append(details, fmt.Sprint(alarm.EvsAlarmDetail, "@", alarm.Version))
		}
		return details
	}
	if got := details(); !slices.Equal(got, []string{"set_void@7", "set_newer@8"}) {
		t.Fatalf("the sets' alarms %v", got)
	}
	if got := details(); len(got) != 0 {
		t.Fatalf("after a restart: %v", got)
	}
}

// Head mode on a shared git-mode branch that a held signer created over its own branch (16.2.6; QD-801): a path the
// ref holds an entry for is judged by that entry's push, so a file the creating push wrote outside the prefixes is
// ignored and one under them is shown; a path it holds no entry for answers ErrEvsOverlayBase from ReadHead, List and
// History, with and without a set in force, and no read of the base ref follows.
func TestEvsPrefixHeadModeJudgesAnOverlaysEntriesAndFollowsNoBase(t *testing.T) {
	for _, ruled := range []bool{true, false} {
		test := newEvsPrefixTest(t)
		world := test.world
		if ruled {
			test.file(5, AclPrefixSetOpened, "agents/build")
		}
		own := world.otherRef([]byte("ur/held/work"))
		own.push(&evsTestChange{path: "inherited.go", content: []byte("on the base")})
		baseReads := own.readCount()
		shared := world.otherRef([]byte("feature"))
		shared.signer, shared.authVersion = test.held, world.authVersion
		shared.base = &protocol.EvsOverlay{RefId: own.refId.Bytes(), Version: 1}
		shared.push(&evsTestChange{path: "src/evil.go", content: []byte("outside the prefixes")},
			&evsTestChange{path: "agents/build/out", content: []byte("under them")})
		reader := test.reader("reader")
		repo := reader.client.Repo(world.repoId)
		ctx := context.Background()
		read := func(path string) (string, error) {
			out := &bytes.Buffer{}
			_, err := repo.ReadHead(ctx, &EvsReadArgs{RefName: []byte("feature"), Path: path}, out)
			return out.String(), err
		}
		if content, err := read("agents/build/out"); err != nil || content != "under them" {
			t.Errorf("ruled %t: an entry under the prefixes: %q %v", ruled, content, err)
		}
		content, err := read("src/evil.go")
		if ruled && (!errors.Is(err, ErrEvsPathAbsent) || content != "") {
			t.Errorf("an entry the creating push wrote outside the prefixes: %q %v", content, err)
		}
		if !ruled && (err != nil || content != "outside the prefixes") {
			t.Errorf("with no set in force: %q %v", content, err)
		}
		if _, err := read("inherited.go"); !errors.Is(err, ErrEvsOverlayBase) {
			t.Errorf("ruled %t: ReadHead of an inherited path: %v", ruled, err)
		}
		if _, err := repo.List(ctx, &EvsReadArgs{RefName: []byte("feature"), Path: "inherited"}); !errors.Is(err, ErrEvsOverlayBase) {
			t.Errorf("ruled %t: List of an inherited path: %v", ruled, err)
		}
		if _, err := repo.History(ctx, &EvsReadArgs{RefName: []byte("feature"), Path: "inherited.go"}); !errors.Is(err, ErrEvsOverlayBase) {
			t.Errorf("ruled %t: History of an inherited path: %v", ruled, err)
		}
		if reads := own.readCount(); reads != baseReads {
			t.Errorf("ruled %t: %d reads of the base ref", ruled, reads-baseReads)
		}
	}
}

// A replay that holds each push whole, as the mirror and export do: each change is judged with its entry, a
// directory's delta against the table the fold holds; the allowed changes are folded, the ignored ones journalled
// {ref, path, version, kind} once, with one alarm a push carrying its count.
func TestEvsPrefixReplayJournalsIgnoredEvents(t *testing.T) {
	test := newEvsPrefixTest(t)
	world := test.world
	test.file(5, AclPrefixSetOpened, "agents/build")
	world.push(&evsTestChange{path: "", children: []string{"src", "agents"}}, &evsTestChange{path: "src", children: []string{"main.go", "gone.go"}},
		&evsTestChange{path: "src/main.go", content: []byte("main\n")}, &evsTestChange{path: "src/gone.go", content: []byte("gone\n")},
		&evsTestChange{path: "agents", children: []string{"build"}})
	// held writes under its prefix, with the row that leads to its file
	test.pushAs(test.held, &evsTestChange{path: "agents/build", children: []string{"out"}}, &evsTestChange{path: "agents/build/out", content: []byte("built\n")})
	// a breach: a write, a creation with its row, and a removal
	breach := test.pushAs(test.held, &evsTestChange{path: "src", children: []string{"planted.go"}}, &evsTestChange{path: "src/main.go", content: []byte("breached\n")},
		&evsTestChange{path: "src/planted.go", content: []byte("planted\n")}, &evsTestChange{path: "src/gone.go"})
	reader := test.reader("replayer")
	repo := reader.client.Repo(world.repoId)
	ctx := context.Background()
	judge := reader.client.prefixJudge()
	head, err := repo.pinnedHead(ctx, world.refId)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := repo.verifiedHistory(ctx, head)
	if err != nil {
		t.Fatal(err)
	}
	fold := newEvsPrefixFold()
	keys := newEvsReadKeys(repo)
	journalled := []*EvsPrefixIgnored{}
	for _, statement := range verified.Statements {
		payload, err := repo.pushPayload(ctx, verified, statement)
		if err != nil {
			t.Fatal(err)
		}
		ignored, err := judge.foldPush(ctx, repo, world.refId, keys, fold, statement, payload)
		if err != nil {
			t.Fatal(err)
		}
		journalled = append(journalled, ignored...)
	}
	units := []string{}
	for _, unit := range journalled {
		if unit.CommitVersion != breach || unit.SignerSidecarId != test.held.sidecarId || unit.RefId != world.refId || !unit.Named {
			t.Errorf("a unit %+v", unit)
		}
		units = append(units, fmt.Sprint(unit.Kind, " ", unit.Path))
	}
	slices.Sort(units)
	if want := []string{"create src/planted.go", "names src", "remove src/gone.go", "write src/main.go"}; !slices.Equal(units, want) {
		t.Fatalf("journalled %v, want %v", units, want)
	}
	if fold.Through != breach {
		t.Errorf("folded through %d", fold.Through)
	}
	standing := []string{}
	for _, node := range fold.Nodes {
		if node.Standing {
			standing = append(standing, string(bytes.Join(node.Names, []byte("/"))))
		}
	}
	slices.Sort(standing)
	if want := []string{"agents", "agents/build", "agents/build/out", "src", "src/gone.go", "src/main.go"}; !slices.Equal(standing, want) {
		t.Errorf("the fold follows %v, want %v", standing, want)
	}
	alarms := evsPrefixTestAlarms(reader)
	if len(alarms) != 1 || alarms[0].Count != 4 || alarms[0].Version != breach {
		t.Errorf("alarms %+v", alarms)
	}
	// the journal takes each unit once and gives it back in order; a settled unit leaves it
	if err := judge.journalAdd(world.repoId, journalled); err != nil {
		t.Fatal(err)
	}
	if err := judge.journalAdd(world.repoId, journalled[:2]); err != nil {
		t.Fatal(err)
	}
	listed, err := reader.client.PrefixIgnored(nil)
	if err != nil || len(listed) != 4 {
		t.Fatalf("the journal %+v %v", listed, err)
	}
	if err := judge.journalRemove(world.repoId, listed[:3]); err != nil {
		t.Fatal(err)
	}
	if listed, err = reader.client.PrefixIgnored(&world.repoId); err != nil || len(listed) != 1 {
		t.Fatalf("the journal after a repair %+v %v", listed, err)
	}
}
