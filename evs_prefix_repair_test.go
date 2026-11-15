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
