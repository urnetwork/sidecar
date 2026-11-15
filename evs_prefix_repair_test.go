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
