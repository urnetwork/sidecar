//go:build !ios_extension

// Writers of a ruled repo (EVS1-M6-05; DESIGN-DETAILS 16.6's evs_plan_test.go and evs_prefix_repair_test.go bullets),
// on the push stand-in of evs_plan_test.go over a world under prefix rules (evs_prefix_test.go): the writing device is
// the world's admin, a second writer is held to agents/build, and what held writes outside it is a breach.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A writer of a world under prefix rules, with the local refusal's seam scripted.
type evsPrefixWriterTest struct {
	*evsPrefixTest
	writer *evsTestWriter
	// the paths AllowWrite drew, and the decision it answers: nil allows
	asked  []string
	refuse *AclPrefixWriteDecision
}

// A ruled writer whose set, at position 5, holds the second writer to agents/build; the writing device's installed
// pin is the set's position, so its pushes are under the set.
func newEvsPrefixWriterTest(t *testing.T) *evsPrefixWriterTest {
	t.Helper()
	writer := newEvsTestWriter(t)
	test := &evsPrefixWriterTest{evsPrefixTest: newEvsPrefixTestOn(t, writer.world), writer: writer}
	test.file(5, AclPrefixSetOpened, "agents/build")
	writer.world.config.setPin(5)
	writer.test.client.EnablePrefixRules(&EvsPrefixRulesArgs{
		Sets: func(ctx context.Context, repoId Id) ([]*AclPrefixRuleSet, error) { return slices.Clone(test.sets), nil },
		AllowWrite: func(write *AclPrefixWrite) AclPrefixWriteDecision {
			if write.Paths != nil {
				for path := range write.Paths {
					test.asked = append(test.asked, path)
				}
			}
			if test.refuse != nil {
				return *test.refuse
			}
			return AclPrefixWriteDecision{AclDecision: AclDecision{Allowed: true, Reason: AclReasonPrefixRule}}
		},
	})
	return test
}

// A breach: held writes path at evs, outside its prefix, through the world.
func (self *evsPrefixWriterTest) breach(path string, content []byte) uint64 {
	self.t.Helper()
	self.writer.server.know(path)
	return self.pushAs(self.held, &evsTestChange{path: path, content: content, segment: true})
}

// A reader under the rules that reaches the writer's evs.
func (self *evsPrefixWriterTest) ruledReader(label string) *evsTestClient {
	reader := self.reader(label)
	reader.client.args.Gkm = self.writer.gkm
	reader.client.args.Transport = &evsTestTransport{handler: self.writer.server}
	reader.client.http.transport = wrapSidecarApiTransport(reader.client.args.Transport)
	return reader
}

// The local refusal runs before any request: a refused path ends the write with EVS_PREFIX_RULE, the path and the
// detail, with nothing read, uploaded or posted; so does a device with no seam to ask through, as pending.
func TestEvsPrefixWriteRefusedBeforeAnyRequest(t *testing.T) {
	test := newEvsPrefixWriterTest(t)
	writer := test.writer
	if _, err := writer.write(t, "src/main.go", []byte("allowed")); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(test.asked, []string{"src/main.go"}) {
		t.Fatalf("asked %q", test.asked)
	}
	reads, posts, uploads := writer.world.readCount(), len(writer.server.postedPushIds(t)), len(writer.server.uploads)
	for _, detail := range []AclPrefixDetail{AclPrefixDetailRefused, AclPrefixDetailPending, AclPrefixDetailUpdate} {
		test.refuse = &AclPrefixWriteDecision{AclDecision: AclDecision{Reason: AclReasonPrefixRule}, Detail: detail, Path: "src/other.go"}
		_, err := writer.write(t, "src/other.go", evsTestContent("refused", 64*1024))
		var ruleErr *EvsPrefixRuleError
		if !errors.Is(err, ErrEvsPrefixRule) || !errors.As(err, &ruleErr) || string(ruleErr.Detail) != detail.String() || ruleErr.Path != "src/other.go" {
			t.Errorf("%s: %v", detail, err)
		}
	}
	// a device whose composition gave it no engine to ask
	bare := newEvsTestClient(t, writer.server, newEvsTestStore(t))
	bare.client.args.Gkm, bare.client.args.Sign = writer.gkm, writer.world.signer.sign
	bare.client.args.Config = func() GkmAuthView { return writer.world.config }
	bare.client.args.Identity = writer.test.client.args.Identity
	bare.client.EnablePrefixRules(nil)
	_, err := bare.client.Repo(writer.world.repoId).Write(context.Background(), &EvsWriteArgs{Path: "src/bare.go", Content: bytes.NewReader([]byte("x")), Size: 1})
	if evsPrefixTestDetail(err) != EvsPrefixDetailPending {
		t.Errorf("a device with no seam: %v", err)
	}
	if writer.world.readCount() != reads || len(writer.server.postedPushIds(t)) != posts || len(writer.server.uploads) != uploads {
		t.Errorf("a refused write sent a request: %d reads, %d posts, %d uploads", writer.world.readCount()-reads,
			len(writer.server.postedPushIds(t))-posts, len(writer.server.uploads)-uploads)
	}
}

// The repair form: over a version this device ignores a write is one checkpoint and no diff, on evs's newest as its
// base_entry_version and prev_push_id; the caller's IfVersion is the effective version's number; the parent's delta
// states the path's row again; and every reader under the rules then reads the repair, with the breach marked in
// History.
func TestEvsPrefixWriteOverAnIgnoredVersionTakesTheRepairForm(t *testing.T) {
	test := newEvsPrefixWriterTest(t)
	writer := test.writer
	good := evsTestContent("good", 64*1024)
	if _, err := writer.write(t, "src/main.go", good); err != nil {
		t.Fatal(err)
	}
	breached := bytes.Clone(good)
	breached[100] ^= 0xff
	breachVersion := test.breach("src/main.go", breached)
	breachEntry := writer.entry(t, "src/main.go")
	plans := []*EvsWritePlan{}
	writer.test.client.SetWritePlanHook(func(ctx context.Context, plan *EvsWritePlan) error {
		plans = append(plans, plan)
		return nil
	})
	// held to the breach's number, which this device does not follow: a conflict, nothing sent
	posts := len(writer.server.postedPushIds(t))
	if _, err := writer.writeHeld("src/main.go", breachEntry.GetVersion(), "over the breach"); err == nil {
		t.Fatalf("a write held to an ignored version went through")
	} else if _, conflict := evsPlannedConflict(err); !conflict {
		t.Fatalf("a write held to an ignored version: %v", err)
	}
	if len(writer.server.postedPushIds(t)) != posts {
		t.Fatalf("a conflicting write posted")
	}
	// held to the effective version, with one byte changed from it: a diff would be small, and none is sent
	repaired := bytes.Clone(good)
	repaired[200] ^= 0xff
	plans = nil
	result, err := writer.repo.WritePaths(context.Background(), &EvsWritePathsArgs{Writes: []*EvsPathWrite{{
		Path: "src/main.go", Content: bytes.NewReader(repaired), IfVersion: evsTestUint64(1),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	var planned, parent *EvsPlannedPath
	for _, path := range plans[len(plans)-1].Paths {
		switch path.Path {
		case "src/main.go":
			planned = path
		case "src":
			parent = path
		}
	}
	if planned == nil || !planned.Repair || planned.Checkpoint != EvsCheckpointRepair || planned.BaseEntryVersion != breachEntry.GetVersion() ||
		!bytes.Equal(planned.PrevPushId, breachEntry.GetPushId()) || planned.PrevCommitVersion != breachVersion {
		t.Fatalf("the repair's plan %+v", planned)
	}
	for _, link := range planned.Chain {
		if link.Kept != nil || link.Record == nil || link.Record.Kind == protocol.EvsRecordKind_EVS_RECORD_DIFF {
			t.Errorf("a repair's chain keeps or diffs against the ignored version: %+v", link)
		}
	}
	if parent == nil || len(parent.Names) != 1 || len(parent.RemovedTokens) != 0 {
		t.Fatalf("the parent's delta does not state the row again: %+v", parent)
	}
	entry := writer.entry(t, "src/main.go")
	if entry.GetVersion() != breachEntry.GetVersion()+1 || !bytes.Equal(entry.GetPrevPushId(), breachEntry.GetPushId()) {
		t.Errorf("the repair's entry: version %d", entry.GetVersion())
	}
	reader := test.ruledReader("reader")
	content, info, err := test.read(reader, "src/main.go")
	if err != nil || !bytes.Equal([]byte(content), repaired) || info.IgnoredAbove != 0 || info.Version != result.PathVersions[0] {
		t.Fatalf("the repair read back: %+v %v", info, err)
	}
	history, err := reader.client.Repo(writer.world.repoId).History(context.Background(), &EvsReadArgs{Path: "src/main.go"})
	if err != nil || len(history.Versions) != 3 || history.Versions[0].Ignored || !history.Versions[1].Ignored || history.Versions[2].Ignored {
		t.Fatalf("history %+v %v", history, err)
	}
	// an allowed version stands again: the next write is no repair
	plans = nil
	if _, err := writer.writeHeld("src/main.go", entry.GetVersion(), "after the repair"); err != nil {
		t.Fatal(err)
	}
	for _, path := range plans[len(plans)-1].Paths {
		if path.Repair {
			t.Errorf("a write over an allowed version planned as a repair: %s", path.Path)
		}
	}
}

// A creation where evs holds a removal this device ignores: the file this device still follows is written again as a
// creation over the removal, held to the effective version, and its row is stated again.
func TestEvsPrefixWriteOverAnIgnoredRemovalCreatesAgain(t *testing.T) {
	test := newEvsPrefixWriterTest(t)
	writer := test.writer
	if _, err := writer.write(t, "src/main.go", []byte("good")); err != nil {
		t.Fatal(err)
	}
	test.pushAs(test.held, &evsTestChange{path: "src/main.go"})
	reader := test.ruledReader("reader")
	if content, info, err := test.read(reader, "src/main.go"); err != nil || content != "good" || info.IgnoredAbove != 1 {
		t.Fatalf("before the repair: %q %+v %v", content, info, err)
	}
	if _, err := writer.repo.WritePaths(context.Background(), &EvsWritePathsArgs{Writes: []*EvsPathWrite{{
		Path: "src/main.go", Content: bytes.NewReader([]byte("good")), IfVersion: evsTestUint64(1),
	}}}); err != nil {
		t.Fatal(err)
	}
	after := test.ruledReader("reader after")
	if content, info, err := test.read(after, "src/main.go"); err != nil || content != "good" || info.IgnoredAbove != 0 {
		t.Fatalf("after the repair: %q %+v %v", content, info, err)
	}
}

// A pointer to value.
func evsTestUint64(value uint64) *uint64 {
	return &value
}

// The gate's refusal of a creating push, met by a device the newer state holds to a prefix (16.2.9; QD-803): the one
// follow installs the state with the set, the write is planned again there, the local refusal answers
// EVS_PREFIX_RULE, and no second statement is sent.
func TestEvsPrefixFollowAfterAClosedGateMeetsTheNewerSet(t *testing.T) {
	test := newEvsPrefixWriterTest(t)
	writer := test.writer
	writer.world.config.setPin(4)
	follows := 0
	writer.test.client.args.ConfigFollow = func(ctx context.Context) error {
		follows += 1
		writer.world.config.setPin(5)
		test.refuse = &AclPrefixWriteDecision{AclDecision: AclDecision{Reason: AclReasonPrefixRule}, Detail: AclPrefixDetailRefused, Path: "src/main.go"}
		return nil
	}
	writer.server.pushRefusals = evsTestClosedGate(1)
	_, err := writer.write(t, "src/main.go", []byte("outside the prefix"))
	var ruleErr *EvsPrefixRuleError
	if !errors.As(err, &ruleErr) || ruleErr.Detail != EvsPrefixDetailRefused || ruleErr.Path != "src/main.go" {
		t.Fatalf("the write: %v", err)
	}
	if statements, _ := writer.server.sentCounts(); statements != 1 || follows != 1 {
		t.Fatalf("%d statements, %d follows", statements, follows)
	}
}

// Enables the rules on the writer again with settings and the repair runner on, as a desktop's composition does.
func (self *evsPrefixWriterTest) enableRepairs(settings *AclPrefixSettings) *evsPrefixJudge {
	self.writer.test.client.EnablePrefixRules(&EvsPrefixRulesArgs{
		Sets: func(ctx context.Context, repoId Id) ([]*AclPrefixRuleSet, error) { return slices.Clone(self.sets), nil },
		AllowWrite: func(write *AclPrefixWrite) AclPrefixWriteDecision {
			if self.refuse != nil {
				return *self.refuse
			}
			return AclPrefixWriteDecision{AclDecision: AclDecision{Allowed: true, Reason: AclReasonPrefixRule}}
		},
		Settings: settings,
		Repair:   true,
	})
	return self.writer.test.client.prefixJudge()
}

// Journals an ignored event of path as this device's mirror would, at the writer's clock.
func (self *evsPrefixWriterTest) journal(judge *evsPrefixJudge, kind EvsPrefixIgnoredKind, path string, commitVersion uint64) *EvsPrefixIgnored {
	self.t.Helper()
	world := self.writer.world
	world.stateLock.Lock()
	pushId := Id(world.commits[commitVersion-1].parsed.Push.GetPushId())
	world.stateLock.Unlock()
	unit := &EvsPrefixIgnored{
		RepoId: world.repoId, RefId: world.refId, Path: path, Named: true, Version: commitVersion, CommitVersion: commitVersion,
		PushId: pushId, SignerSidecarId: self.held.sidecarId, Kind: kind, AtMs: self.writer.test.clock.Now().UnixMilli(),
	}
	if err := judge.journalAdd(world.repoId, []*EvsPrefixIgnored{unit}); err != nil {
		self.t.Fatal(err)
	}
	return unit
}

// The runner over a journal (16.2.8's table): nothing before RepairDelay and the unit's share of RepairJitter; then a
// breach-created path is removed, a removed file is created again from the effective content, a versionless file's
// accepted content is written again, and a versioned file a breach replaced waits until RepairDepth ignored versions
// lie over it, or until `ur evs repair` asks by hand. A second runner that comes after finds the newest event allowed
// and drops its unit with no push. A device that does not repair runs none.
func TestEvsPrefixRepairRunnerRepairsEachClassWhenDue(t *testing.T) {
	test := newEvsPrefixWriterTest(t)
	writer := test.writer
	ctx := context.Background()
	repoId := writer.world.repoId
	if _, err := writer.test.client.RepairPrefix(ctx, &EvsPrefixRepairArgs{RepoId: repoId}); !errors.Is(err, ErrEvsPrefixRepairOff) {
		t.Fatalf("a device that does not repair: %v", err)
	}
	settings := DefaultAclPrefixSettings()
	judge := test.enableRepairs(settings)
	for _, path := range []string{"src/replaced.go", "src/gone.go", "src/versionless.bin"} {
		if _, err := writer.write(t, path, []byte("good "+path)); err != nil {
			t.Fatal(err)
		}
	}
	replaced := test.breach("src/replaced.go", []byte("breached"))
	writer.server.know("src/gone.go")
	gone := test.pushAs(test.held, &evsTestChange{path: "src/gone.go"})
	versionless := test.breach("src/versionless.bin", []byte("breached"))
	planted := test.breach("src/planted.go", []byte("planted"))
	test.journal(judge, EvsPrefixIgnoredWrite, "src/replaced.go", replaced)
	test.journal(judge, EvsPrefixIgnoredRemove, "src/gone.go", gone)
	test.journal(judge, EvsPrefixIgnoredWrite, "src/versionless.bin", versionless)
	test.journal(judge, EvsPrefixIgnoredCreate, "src/planted.go", planted)
	// the versionless unit's class is its journalled mark
	units, _ := judge.journal(repoId)
	units[2].Versionless = true
	if err := judge.journalWrite(repoId, units); err != nil {
		t.Fatal(err)
	}
	statements, _ := writer.server.sentCounts()
	// before the delay: nothing
	writer.test.clock.advance(settings.RepairDelay - time.Second)
	result, err := writer.test.client.RepairPrefix(ctx, &EvsPrefixRepairArgs{RepoId: repoId})
	if err != nil || result.PushCount != 0 || result.WaitingCount != 4 || result.SettledCount != 0 {
		t.Fatalf("before the delay: %+v %v", result, err)
	}
	// past the delay and the whole jitter: three classes repair at once, the versioned replacement waits
	writer.test.clock.advance(settings.RepairJitter + time.Second)
	result, err = writer.test.client.RepairPrefix(ctx, &EvsPrefixRepairArgs{RepoId: repoId})
	if err != nil || result.PushCount != 3 || result.SettledCount != 3 || result.WaitingCount != 1 {
		t.Fatalf("when due: %+v %v", result, err)
	}
	if after, _ := writer.server.sentCounts(); after != statements+3 {
		t.Fatalf("%d statements for three repairs", after-statements)
	}
	reader := test.ruledReader("reader")
	for _, path := range []string{"src/gone.go", "src/versionless.bin"} {
		if content, info, err := test.read(reader, path); err != nil || content != "good "+path || info.IgnoredAbove != 0 {
			t.Errorf("%s after its repair: %q %+v %v", path, content, info, err)
		}
	}
	if _, _, err := test.read(reader, "src/planted.go"); !errors.Is(err, ErrEvsPathAbsent) {
		t.Errorf("a breach-created path after its repair: %v", err)
	}
	if content, info, err := test.read(reader, "src/replaced.go"); err != nil || content != "good src/replaced.go" || info.IgnoredAbove != 1 {
		t.Errorf("a versioned file under the depth: %q %+v %v", content, info, err)
	}
	// by hand, for the one path, whatever the depth says
	result, err = writer.test.client.RepairPrefix(ctx, &EvsPrefixRepairArgs{RepoId: repoId, Path: "src/replaced.go", ByHand: true})
	if err != nil || result.PushCount != 1 || result.SettledCount != 1 || result.WaitingCount != 0 {
		t.Fatalf("by hand: %+v %v", result, err)
	}
	after := test.ruledReader("reader after")
	if content, info, err := test.read(after, "src/replaced.go"); err != nil || content != "good src/replaced.go" || info.IgnoredAbove != 0 {
		t.Errorf("after the repair by hand: %q %+v %v", content, info, err)
	}
	if left, err := writer.test.client.PrefixIgnored(&repoId); err != nil || len(left) != 0 {
		t.Fatalf("the journal after the repairs: %+v %v", left, err)
	}
	// a second runner's unit of a path already repaired: dropped with no push
	test.journal(judge, EvsPrefixIgnoredRemove, "src/gone.go", gone)
	writer.test.clock.advance(settings.RepairDelay + settings.RepairJitter)
	statements, _ = writer.server.sentCounts()
	result, err = writer.test.client.RepairPrefix(ctx, &EvsPrefixRepairArgs{RepoId: repoId})
	if err != nil || result.PushCount != 0 || result.SettledCount != 1 {
		t.Fatalf("a second runner: %+v %v", result, err)
	}
	if again, _ := writer.server.sentCounts(); again != statements {
		t.Fatalf("a second runner pushed")
	}
}

// The jitter is a share of RepairJitter by SHA-256(sidecar_id || push id): the same for one device and push, inside
// the jitter, and different between devices; a unit is due at its delay plus that share and not a moment before.
func TestEvsPrefixRepairJitterSpreadsTheCandidates(t *testing.T) {
	jitter := 5 * time.Minute
	pushId := evsTestId("a breach's push")
	shares := map[time.Duration]bool{}
	for _, label := range []string{"one", "two", "three", "four"} {
		share := evsPrefixRepairJitter(evsTestId("device "+label), pushId, jitter)
		if share < 0 || jitter <= share || share != evsPrefixRepairJitter(evsTestId("device "+label), pushId, jitter) {
			t.Errorf("device %s: %s", label, share)
		}
		shares[share] = true
	}
	if len(shares) != 4 {
		t.Errorf("four devices share %d times", len(shares))
	}
	if evsPrefixRepairJitter(evsTestId("device one"), pushId, 0) != 0 {
		t.Errorf("no jitter is no wait")
	}
	test := newEvsPrefixWriterTest(t)
	writer := test.writer
	settings := DefaultAclPrefixSettings()
	judge := test.enableRepairs(settings)
	if _, err := writer.write(t, "src/gone.go", []byte("good")); err != nil {
		t.Fatal(err)
	}
	writer.server.know("src/gone.go")
	gone := test.pushAs(test.held, &evsTestChange{path: "src/gone.go"})
	unit := test.journal(judge, EvsPrefixIgnoredRemove, "src/gone.go", gone)
	share := evsPrefixRepairJitter(writer.test.client.args.Identity().SidecarId, unit.PushId, settings.RepairJitter)
	writer.test.clock.advance(settings.RepairDelay + share - time.Millisecond)
	ctx := context.Background()
	if result, err := writer.test.client.RepairPrefix(ctx, &EvsPrefixRepairArgs{RepoId: unit.RepoId}); err != nil || result.PushCount != 0 || result.WaitingCount != 1 {
		t.Fatalf("a moment before its share: %+v %v", result, err)
	}
	writer.test.clock.advance(time.Millisecond)
	if result, err := writer.test.client.RepairPrefix(ctx, &EvsPrefixRepairArgs{RepoId: unit.RepoId}); err != nil || result.PushCount != 1 {
		t.Fatalf("at its share: %+v %v", result, err)
	}
}

// The bounds, for each repo and device: past RepairPushCount pushes in RepairPushWindow, or RepairByteCount bytes in
// RepairByteWindow, the units wait in the journal; and a device the rules hold to a prefix repairs only under it,
// asked before any request.
func TestEvsPrefixRepairKeepsItsBoundsAndItsPrefixes(t *testing.T) {
	test := newEvsPrefixWriterTest(t)
	writer := test.writer
	ctx := context.Background()
	repoId := writer.world.repoId
	settings := DefaultAclPrefixSettings()
	settings.RepairPushCount = 1
	settings.RepairJitter = 0
	judge := test.enableRepairs(settings)
	paths := []string{"src/a.go", "src/b.go", "src/c.go"}
	for _, path := range paths {
		if _, err := writer.write(t, path, []byte("good "+path)); err != nil {
			t.Fatal(err)
		}
		writer.server.know(path)
		test.journal(judge, EvsPrefixIgnoredRemove, path, test.pushAs(test.held, &evsTestChange{path: path}))
	}
	writer.test.clock.advance(settings.RepairDelay)
	// a device held to a prefix the paths lie outside: nothing sent, every unit kept
	test.refuse = &AclPrefixWriteDecision{AclDecision: AclDecision{Reason: AclReasonPrefixRule}, Detail: AclPrefixDetailRefused, Path: "src/a.go"}
	statements, _ := writer.server.sentCounts()
	result, err := writer.test.client.RepairPrefix(ctx, &EvsPrefixRepairArgs{RepoId: repoId})
	if err != nil || result.PushCount != 0 || result.WaitingCount != 3 {
		t.Fatalf("a held device: %+v %v", result, err)
	}
	if after, _ := writer.server.sentCounts(); after != statements {
		t.Fatalf("a held device sent %d statements", after-statements)
	}
	test.refuse = nil
	// one push an hour
	result, err = writer.test.client.RepairPrefix(ctx, &EvsPrefixRepairArgs{RepoId: repoId})
	if err != nil || result.PushCount != 1 || result.WaitingCount != 2 {
		t.Fatalf("the push bound: %+v %v", result, err)
	}
	if result, err = writer.test.client.RepairPrefix(ctx, &EvsPrefixRepairArgs{RepoId: repoId}); err != nil || result.PushCount != 0 || result.WaitingCount != 2 {
		t.Fatalf("inside the push window: %+v %v", result, err)
	}
	if left, err := writer.test.client.PrefixIgnored(&repoId); err != nil || len(left) != 2 {
		t.Fatalf("the dirty paths listed: %+v %v", left, err)
	}
	// the byte bound, once the push window passed
	writer.test.clock.advance(settings.RepairPushWindow)
	settings.RepairByteCount = 4
	if result, err = writer.test.client.RepairPrefix(ctx, &EvsPrefixRepairArgs{RepoId: repoId}); err != nil || result.PushCount != 0 || result.WaitingCount != 2 {
		t.Fatalf("the byte bound: %+v %v", result, err)
	}
	settings.RepairByteCount = 1 << 20
	if result, err = writer.test.client.RepairPrefix(ctx, &EvsPrefixRepairArgs{RepoId: repoId}); err != nil || result.PushCount != 1 || result.WaitingCount != 1 {
		t.Fatalf("under the byte bound: %+v %v", result, err)
	}
	// by hand: without the bounds
	if result, err = writer.test.client.RepairPrefix(ctx, &EvsPrefixRepairArgs{RepoId: repoId, ByHand: true}); err != nil || result.PushCount != 1 || result.WaitingCount != 0 {
		t.Fatalf("by hand past the bound: %+v %v", result, err)
	}
}

// The pin push of a file-mode ref (16.2.9): a statement with no change on the head at the installed pin, which every
// reader under the rules allows with no walk and no alarm; nothing for a name with no head.
func TestEvsPrefixPinPushCommitsNoChangeAtTheInstalledPin(t *testing.T) {
	test := newEvsPrefixWriterTest(t)
	writer := test.writer
	ctx := context.Background()
	if result, err := writer.repo.PinPush(ctx, nil); err != nil || result.Skipped != EvsPinPushSkipNoHead {
		t.Fatalf("a name with no head: %+v %v", result, err)
	}
	if statements, _ := writer.server.sentCounts(); statements != 0 {
		t.Fatalf("a pin push to no head sent %d statements", statements)
	}
	writer.world.config.setPin(4)
	if _, err := writer.write(t, "src/main.go", []byte("under the older pin")); err != nil {
		t.Fatal(err)
	}
	writer.world.config.setPin(5)
	result, err := writer.repo.PinPush(ctx, nil)
	if err != nil || result.Skipped != "" || result.Version != 2 {
		t.Fatalf("the pin push: %+v %v", result, err)
	}
	if pins := evsTestPostedPins(t, writer.server); !slices.Equal(pins, []uint64{4, 5}) {
		t.Fatalf("the pins posted %v", pins)
	}
	writer.world.stateLock.Lock()
	pinned := writer.world.commits[1].parsed
	writer.world.stateLock.Unlock()
	if pinned.Push.GetChangeCount() != 0 || len(pinned.Changes) != 0 {
		t.Fatalf("a pin push with %d changes", pinned.Push.GetChangeCount())
	}
	reader := test.ruledReader("reader")
	content, info, err := test.read(reader, "src/main.go")
	if err != nil || content != "under the older pin" || info.IgnoredAbove != 0 || info.HeadVersion != 2 {
		t.Fatalf("a reader after the pin push: %q %+v %v", content, info, err)
	}
	if alarms := evsPrefixTestAlarms(reader); len(alarms) != 0 {
		t.Errorf("alarms %+v", alarms)
	}
}

// The filer's pin pushes (16.2.9; QD-802, QD-803): with this device's log behind the set, one follow, and where it
// still does not hold the set every unbound ref waits, owed in the journal, with nothing sent; once the log holds it,
// a ref whose head's pin is below the set takes a pin push, a ref already pinned at or above it takes none, a deleted
// ref is listed as held at its re-creation, and the journal sends what it owed and then drops it. `show`'s status
// lists the same bindings.
func TestEvsPrefixPinPushesBindEachSharedRef(t *testing.T) {
	test := newEvsPrefixWriterTest(t)
	writer := test.writer
	world := writer.world
	ctx := context.Background()
	client := writer.test.client
	// main below the set; notes at it; old deleted
	world.config.setPin(4)
	if _, err := writer.write(t, "src/main.go", []byte("main")); err != nil {
		t.Fatal(err)
	}
	notes := world.otherRef([]byte("notes"))
	old := world.otherRef([]byte("old"))
	world.config.setPin(5)
	writer.server.know("notes.md", "old.md")
	if _, err := writer.repo.WritePaths(ctx, &EvsWritePathsArgs{RefName: []byte("notes"), Writes: []*EvsPathWrite{{Path: "notes.md", Content: bytes.NewReader([]byte("notes"))}}}); err != nil {
		t.Fatal(err)
	}
	world.config.setPin(4)
	if _, err := writer.repo.WritePaths(ctx, &EvsWritePathsArgs{RefName: []byte("old"), Writes: []*EvsPathWrite{{Path: "old.md", Content: bytes.NewReader([]byte("old"))}}}); err != nil {
		t.Fatal(err)
	}
	old.stateLock.Lock()
	old.deleted = true
	old.stateLock.Unlock()
	evsPrefixTestSealName(t, notes, "notes")
	evsPrefixTestSealName(t, old, "old")
	world.config.setPin(4)
	// the log is behind the set, and one follow does not move it
	follows := 0
	client.args.ConfigFollow = func(ctx context.Context) error {
		follows += 1
		return nil
	}
	statements, _ := writer.server.sentCounts()
	refs, err := client.PinPushRules(ctx, world.repoId, 5)
	if err != nil || follows != 1 {
		t.Fatalf("behind the set: %v, %d follows", err, follows)
	}
	bindings := evsPrefixTestBindings(refs)
	if bindings["main"] != EvsPrefixWaiting || bindings["notes"] != EvsPrefixBound || bindings["old"] != EvsPrefixDeleted {
		t.Fatalf("behind the set: %v", bindings)
	}
	if after, _ := writer.server.sentCounts(); after != statements {
		t.Fatalf("a pin push sent below the set")
	}
	status, err := client.PrefixRulesStatus(ctx, world.repoId)
	if err != nil {
		t.Fatal(err)
	}
	if bindings := evsPrefixTestBindings(status.Refs); bindings["main"] != EvsPrefixUnbound || bindings["notes"] != EvsPrefixBound || bindings["old"] != EvsPrefixDeleted {
		t.Fatalf("show's refs: %v", bindings)
	}
	if status.NewestAt != 5 || len(status.Sets) != 1 {
		t.Fatalf("show's sets: %+v", status)
	}
	// the log moves past the set; within the retry interval the journal sends nothing, past it the owed pin push,
	// to main alone, and drops it
	world.config.setPin(5)
	if err := client.RetryPrefixPinPushes(ctx); err != nil {
		t.Fatal(err)
	}
	if after, _ := writer.server.sentCounts(); after != statements {
		t.Fatalf("the journal sent within its interval")
	}
	writer.test.clock.advance(DefaultAclPrefixSettings().PinPushRetryInterval)
	if err := client.RetryPrefixPinPushes(ctx); err != nil {
		t.Fatal(err)
	}
	if after, _ := writer.server.sentCounts(); after != statements+1 {
		t.Fatalf("%d statements for one owed pin push", after-statements)
	}
	if pins := evsTestPostedPins(t, writer.server); pins[len(pins)-1] != 5 {
		t.Fatalf("the pin push's pin %v", pins)
	}
	if entries, err := client.args.Store.List(evsPrefixPinDirectory); err != nil || len(entries) != 0 {
		t.Fatalf("the journal after the pin push: %v %v", entries, err)
	}
	status, err = client.PrefixRulesStatus(ctx, world.repoId)
	if err != nil {
		t.Fatal(err)
	}
	if bindings := evsPrefixTestBindings(status.Refs); bindings["main"] != EvsPrefixBound || bindings["old"] != EvsPrefixDeleted {
		t.Fatalf("show's refs after the pin push: %v", bindings)
	}
	// a second filing's pin pushes find every ref bound: nothing more is sent
	if _, err := client.PinPushRules(ctx, world.repoId, 5); err != nil {
		t.Fatal(err)
	}
	if after, _ := writer.server.sentCounts(); after != statements+1 {
		t.Fatalf("a bound ref took another pin push")
	}
}

// Each ref's binding by its name.
func evsPrefixTestBindings(refs []*EvsPrefixRef) map[string]EvsPrefixBinding {
	bindings := map[string]EvsPrefixBinding{}
	for _, ref := range refs {
		bindings[string(ref.Name)] = ref.Binding
	}
	return bindings
}

// The repair form with no edit for one path, which the DROP builder calls (16.2.7 as amended, 10.2.4): with one
// ignored version over a versioned file, below RepairDepth, the effective content is written back at once as one
// checkpoint; it keeps 16.2.8's who, so a device that does not repair, and one that does not mirror the ref, write
// nothing, and the planner refuses a path the rules do not give this device.
func TestEvsPrefixRepairPathWritesBackUnderTheDepth(t *testing.T) {
	test := newEvsPrefixWriterTest(t)
	writer := test.writer
	ctx := context.Background()
	if _, err := writer.repo.RepairPath(ctx, nil, "src/main.go"); !errors.Is(err, ErrEvsPrefixRepairOff) {
		t.Fatalf("a device that does not repair: %v", err)
	}
	test.enableRepairs(DefaultAclPrefixSettings())
	good := evsTestContent("good", 64*1024)
	if _, err := writer.write(t, "src/main.go", good); err != nil {
		t.Fatal(err)
	}
	breached := bytes.Clone(good)
	breached[10] ^= 0xff
	test.breach("src/main.go", breached)
	if _, err := writer.repo.RepairPath(ctx, nil, "src/main.go"); !errors.Is(err, ErrEvsPrefixRepairOff) {
		t.Fatalf("a device that does not mirror the ref: %v", err)
	}
	test.mirrorRef()
	statements, _ := writer.server.sentCounts()
	result, err := writer.repo.RepairPath(ctx, nil, "src/main.go")
	if err != nil || result.PushCount != 1 {
		t.Fatalf("the repair: %+v %v", result, err)
	}
	if after, _ := writer.server.sentCounts(); after != statements+1 {
		t.Fatalf("%d statements for one repair", after-statements)
	}
	reader := test.ruledReader("reader")
	content, info, err := test.read(reader, "src/main.go")
	if err != nil || !bytes.Equal([]byte(content), good) || info.IgnoredAbove != 0 {
		t.Fatalf("after the repair: %+v %v", info, err)
	}
	// written back already: nothing more
	if result, err := writer.repo.RepairPath(ctx, nil, "src/main.go"); err != nil || result.PushCount != 0 {
		t.Fatalf("a path whose newest version is allowed: %+v %v", result, err)
	}
	// a path the rules do not give this device
	breached[11] ^= 0xff
	test.breach("src/main.go", breached)
	test.refuse = &AclPrefixWriteDecision{AclDecision: AclDecision{Reason: AclReasonPrefixRule}, Detail: AclPrefixDetailRefused, Path: "src/main.go"}
	if _, err := writer.repo.RepairPath(ctx, nil, "src/main.go"); evsPrefixTestDetail(err) != EvsPrefixDetailRefused {
		t.Fatalf("a path refused to this device: %v", err)
	}
}

// The planner's local refusal covers a rekey of a shared git-mode ref (8.2.10 as amended): a path outside the device's
// prefixes is EVS_PREFIX_RULE before any request.
func TestEvsPrefixRekeyOfAGitModeRefRefusedBeforeAnyRequest(t *testing.T) {
	test := newEvsPrefixWriterTest(t)
	writer := test.writer
	writer.world.stateLock.Lock()
	writer.world.mode = protocol.EvsRefMode_EVS_REF_GIT
	writer.world.stateLock.Unlock()
	reads, posts := writer.world.readCount(), len(writer.server.postedPushIds(t))
	test.refuse = &AclPrefixWriteDecision{AclDecision: AclDecision{Reason: AclReasonPrefixRule}, Detail: AclPrefixDetailRefused, Path: "src/main.go"}
	_, err := writer.repo.WritePaths(context.Background(), &EvsWritePathsArgs{Writes: []*EvsPathWrite{{
		Path: "src/main.go", Content: bytes.NewReader([]byte("rekeyed")), IfVersion: evsTestUint64(1), ForceCheckpoint: true,
	}}})
	if evsPrefixTestDetail(err) != EvsPrefixDetailRefused {
		t.Fatalf("a rekey outside the prefixes: %v", err)
	}
	if !slices.Equal(test.asked, []string{"src/main.go"}) {
		t.Fatalf("asked %q", test.asked)
	}
	if writer.world.readCount() != reads || len(writer.server.postedPushIds(t)) != posts {
		t.Fatalf("a refused rekey sent a request")
	}
}

// Seals name as the head of other, a ref of world, carries it, as evs keeps a creating push's payload section 15.
func evsPrefixTestSealName(t *testing.T, other *evsTestWorld, name string) {
	t.Helper()
	keys := evsTestKeys(t, other.repoId, max(1, other.generation))
	sealed, err := EvsSealRefName(keys.manifest, other.refId, []byte(name))
	if err != nil {
		t.Fatal(err)
	}
	other.stateLock.Lock()
	defer other.stateLock.Unlock()
	other.sealedRefName = sealed
}

// Records that the writer's device mirrors the world's ref, as its mirror's first sync would.
func (self *evsPrefixWriterTest) mirrorRef() {
	self.t.Helper()
	mirror, err := self.writer.test.client.Mirror(self.writer.world.repoId)
	if err != nil {
		self.t.Fatal(err)
	}
	if err := mirror.RaiseRef(&EvsMirrorRef{RefId: self.writer.world.refId, Version: 1, MirroredAt: self.writer.test.clock.Now()}); err != nil {
		self.t.Fatal(err)
	}
}

// An ephemeral sidecar runs no repair, by its timer, by hand or for one path, whatever its composition says (16.2.8's
// who), and the daemon's prefix timer passes a due unit and an owed pin push on a device that repairs.
func TestEvsPrefixRepairPassesOnTheTimerAndNeverOnAnEphemeralSidecar(t *testing.T) {
	test := newEvsPrefixWriterTest(t)
	writer := test.writer
	ctx := context.Background()
	repoId := writer.world.repoId
	settings := DefaultAclPrefixSettings()
	judge := test.enableRepairs(settings)
	if _, err := writer.write(t, "src/gone.go", []byte("good")); err != nil {
		t.Fatal(err)
	}
	writer.server.know("src/gone.go")
	gone := test.pushAs(test.held, &evsTestChange{path: "src/gone.go"})
	test.journal(judge, EvsPrefixIgnoredRemove, "src/gone.go", gone)
	test.mirrorRef()
	writer.world.config.stateLock.Lock()
	ownRow := writer.world.config.rows[test.admin.sidecarId]
	ownRow.Ephemeral = true
	writer.world.config.stateLock.Unlock()
	writer.test.clock.advance(settings.RepairDelay + settings.RepairJitter)
	if _, err := writer.test.client.RepairPrefix(ctx, &EvsPrefixRepairArgs{RepoId: repoId, ByHand: true}); !errors.Is(err, ErrEvsPrefixRepairOff) {
		t.Fatalf("an ephemeral sidecar by hand: %v", err)
	}
	if _, err := writer.repo.RepairPath(ctx, nil, "src/gone.go"); !errors.Is(err, ErrEvsPrefixRepairOff) {
		t.Fatalf("an ephemeral sidecar's one path: %v", err)
	}
	statements, _ := writer.server.sentCounts()
	writer.test.client.passPrefixRepair(ctx)
	if after, _ := writer.server.sentCounts(); after != statements {
		t.Fatalf("an ephemeral sidecar's timer repaired")
	}
	writer.world.config.stateLock.Lock()
	ownRow.Ephemeral = false
	writer.world.config.stateLock.Unlock()
	writer.test.client.passPrefixRepair(ctx)
	if after, _ := writer.server.sentCounts(); after != statements+1 {
		t.Fatalf("%d statements for the timer's repair", after-statements)
	}
	if units, err := judge.journal(repoId); err != nil || len(units) != 0 {
		t.Fatalf("the journal after the timer's pass: %v %v", units, err)
	}
	reader := test.ruledReader("reader")
	if content, info, err := test.read(reader, "src/gone.go"); err != nil || content != "good" || info.IgnoredAbove != 0 {
		t.Fatalf("after the timer's repair: %q %+v %v", content, info, err)
	}
}

// `ur evs rules`' subjects read against the verified state and the config head's names (16.2.2, 16.2.9): sidecar:,
// user:, tag: and the four autogroups name their atoms; group: is refused with its members' user: subjects; any other
// form, an autogroup a rule cannot name, a name the head does not hold, and a user: with no head at all are refused.
// Each atom prints back as the form that names it.
func TestEvsPrefixSubjectsReadAgainstTheHead(t *testing.T) {
	net, ci, _ := newTestConfigTagNet(t)
	laptop := net.admitMemberDevice("prefix subject laptop")
	group := testConfigId("prefix subject group")
	net.withAclRows(func(rows *protocol.AclRows) {
		rows.Atoms = append(rows.Atoms, &protocol.AclAtom{Atom: group.Bytes(), MemberIds: [][]byte{laptop.memberId.Bytes()}})
	})
	state := net.log.State()
	local := &AclLocalPolicy{Names: []AclLocalName{
		{Id: ci, Text: "tag:ci"},
		{Id: group, Text: "group:eng"},
		{Id: AclDerivedAtom(AclDerivedAtomMember, laptop.memberId.Bytes()), Text: "user:laptop@example.com"},
	}}
	for _, c := range []struct {
		text string
		want Id
	}{
		{text: "sidecar:" + laptop.sidecarId.String(), want: laptop.sidecarId},
		{text: "user:laptop@example.com", want: laptop.memberId},
		{text: "tag:ci", want: ci},
		{text: "autogroup:sidecar", want: AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SIDECAR)},
		{text: "autogroup:member", want: AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER)},
		{text: "autogroup:tagged", want: AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_TAGGED)},
		{text: "autogroup:ephemeral", want: AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_EPHEMERAL)},
	} {
		if got, err := evsPrefixSubjectOf(state, local, c.text); err != nil || got != c.want {
			t.Errorf("%s: %s %v", c.text, got, err)
		}
		if text := evsPrefixSubjectText(state, local, c.want); text != c.text {
			t.Errorf("%s prints as %q", c.want, text)
		}
	}
	var groupErr *EvsPrefixGroupSubjectError
	if _, err := evsPrefixSubjectOf(state, local, "group:eng"); !errors.As(err, &groupErr) || !errors.Is(err, ErrEvsPrefixSubject) ||
		groupErr.Group != "eng" || !slices.Equal(groupErr.Members, []string{"user:laptop@example.com"}) {
		t.Errorf("a group: %v", err)
	}
	for _, text := range []string{"tag:nope", "user:nobody@example.com", "autogroup:admin", "role:admin", "sidecar:nope", "nocolon", "tag:"} {
		if _, err := evsPrefixSubjectOf(state, local, text); !errors.Is(err, ErrEvsPrefixSubject) {
			t.Errorf("%q: %v", text, err)
		}
	}
	if _, err := evsPrefixSubjectOf(state, nil, "user:laptop@example.com"); !errors.Is(err, ErrEvsPrefixSubject) {
		t.Errorf("a user: with no head: %v", err)
	}
	if text := evsPrefixSubjectText(state, local, testConfigId("nobody")); !strings.HasPrefix(text, "id:") {
		t.Errorf("an unknown atom prints as %q", text)
	}
}
