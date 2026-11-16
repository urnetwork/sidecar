package fault

// FI-15's oracle (fi15.go) on T2: mutants built by hand in fi1_test.go's hand world, each a push committed through
// evsservice.HeadStore past the 5g a correct evs would refuse it at, caught at its commit; a read reply showing a
// version above its head, caught as the world's transport would record it; and a healthy run on the evs world's
// instances, its readers' replies recorded, through removals, re-creations, a directory, folds and a marker
// collection, which reads clean at every step.

import (
	"context"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

type fi15World struct {
	*fiHandWorld
	main sidecar.Id
	// the token paths the schedule names, by name
	tokens map[string]sidecar.EvsTokenPath
}

func newFi15World(t *testing.T) *fi15World {
	return &fi15World{fiHandWorld: newFiHandWorld(t), main: sidecar.NewId(), tokens: map[string]sidecar.EvsTokenPath{}}
}

// A file path's token path, one component, made at first use.
func (self *fi15World) token(name string) sidecar.EvsTokenPath {
	if tokenPath, ok := self.tokens[name]; ok {
		return tokenPath
	}
	tokenPath := sidecar.EvsTokenPath{sidecar.NewEvsRandomToken()}
	self.tokens[name] = tokenPath
	return tokenPath
}

// One change a hand push makes: a file write at version, or a removal when version is 0.
type fi15Change struct {
	name             string
	baseEntryVersion uint64
	version          uint64
}

// A step's action committing a push on main, based at base (the head when base is negative), making changes, past
// every check evs would run.
func (self *fi15World) push(base int, changes ...*fi15Change) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		chains := self.chains[self.main]
		if chains == nil {
			chains = [][32]byte{sidecar.EvsChainStart(self.repoId, self.main)}
			self.chains[self.main] = chains
		}
		baseVersion := uint64(len(chains) - 1)
		if 0 <= base {
			baseVersion = uint64(base)
		}
		pushId := sidecar.NewId()
		planned := []*sidecar.EvsPlannedChange{}
		for _, change := range changes {
			plannedChange := &sidecar.EvsPlannedChange{TokenPath: self.token(change.name), BaseEntryVersion: change.baseEntryVersion}
			if 0 < change.version {
				entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.EvsEntryVersion{
					Version: change.version, PushId: pushId.Bytes(), BaseVersion: baseVersion, TimeMs: net.Clock().Now().UnixMilli(),
					Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), PaddedSize: 4096, SealedFields: []byte("sealed fields"),
					Chain: []*protocol.EvsLocator{{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: []byte("inline record")}},
				})
				if err != nil {
					return err
				}
				plannedChange.EntryVersion = entryBytes
			}
			planned = append(planned, plannedChange)
		}
		built, err := sidecar.NewEvsStatementBuilder(self.admin.Sign).Build(&sidecar.EvsPushPlan{
			RepoId: self.repoId, RefId: self.main, RefKind: protocol.EvsRefKind_EVS_REF_SHARED, RefMode: protocol.EvsRefMode_EVS_REF_FILE,
			PushId: pushId, BaseVersion: baseVersion, BaseChain: chains[baseVersion],
			Generation: 1, GroupId: self.groupId, GenerationCommitment: self.repoKey.Commitment(), PathEpoch: 1,
			Auth: self.view.Pin(), SignerSidecarId: self.admin.SidecarId, ClientId: sidecar.NewId(),
			TimeMs: net.Clock().Now().UnixMilli(), SealedMetadata: []byte("sealed metadata"), Changes: planned,
		})
		if err != nil {
			return err
		}
		push := &fiHandPush{refId: self.main, statement: built.Statement, payload: built.Payload, signerId: self.admin.SidecarId}
		if err := self.writeRecord(ctx, push); err != nil {
			return err
		}
		return self.commit(ctx, push)
	}
}

func fi15Checks() []Invariant {
	return []Invariant{FI(15)}
}

// x written, changed, removed and created again by the rules, then changed on its new version: clean at every step.
func TestFi15ReadsAHandHistoryByTheRulesClean(t *testing.T) {
	world := newFi15World(t)
	steps := []*Step{
		{Actor: "writerA", Action: world.push(-1, &fi15Change{name: "x", version: 1})},
		{Actor: "writerA", Action: world.push(-1, &fi15Change{name: "x", baseEntryVersion: 1, version: 2}, &fi15Change{name: "y", version: 2})},
		// removed at v3, one past its last: 3
		{Actor: "writerA", Action: world.push(-1, &fi15Change{name: "x", baseEntryVersion: 2})},
		// created again on base 3: max(3, 3) + 1
		{Actor: "writerA", Action: world.push(-1, &fi15Change{name: "x", version: 4})},
		// a disjoint push based before the creation, landing within its base range
		{Actor: "writerB", Action: world.push(3, &fi15Change{name: "y", baseEntryVersion: 2, version: 3})},
		{Actor: "writerA", Action: world.push(-1, &fi15Change{name: "x", baseEntryVersion: 4, version: 5})},
	}
	fiRequirePass(t, Run(t.Context(), &Schedule{Id: "fi15-by-the-rules", Steps: steps, Check: fi15Checks()}, world.net))
}

// A creation at a version that is not max(b, m) + 1: caught at its commit.
func TestFi15CatchesACreationAtTheWrongVersion(t *testing.T) {
	world := newFi15World(t)
	steps := []*Step{
		{Actor: "writerA", Action: world.push(-1, &fi15Change{name: "y", version: 1})},
		{Actor: "writerA", Action: world.push(-1, &fi15Change{name: "y", baseEntryVersion: 1, version: 2})},
		// x created on base 2, never written: 3 by the rule, written 7
		{Actor: "writerA", Action: world.push(-1, &fi15Change{name: "x", version: 7})},
	}
	result := Run(t.Context(), &Schedule{Id: "fi15-wrong-creation", Steps: steps, Check: fi15Checks()}, world.net)
	fiRequireViolation(t, result, 2, "FI-15", "written at version 7, the versions rule's 3")
}

// A path's versions restarting after its removal's marker was collected: a creation that took b + 1 from a base below
// the removal, as an evs that lost m would, at or below what the path held. Caught at the commit.
func TestFi15CatchesAVersionRestartAfterACollection(t *testing.T) {
	world := newFi15World(t)
	steps := []*Step{
		{Actor: "writerA", Action: world.push(-1, &fi15Change{name: "x", version: 1})},
		{Actor: "writerA", Action: world.push(-1, &fi15Change{name: "x", baseEntryVersion: 1, version: 2})},
		{Actor: "writerA", Action: world.push(-1, &fi15Change{name: "x", baseEntryVersion: 2, version: 3})},
		// removed at v4: version 4
		{Actor: "writerA", Action: world.push(-1, &fi15Change{name: "x", baseEntryVersion: 3})},
		// created again from base 1, with m read as gone: version 2, a restart
		{Actor: "writerB", Action: world.push(1, &fi15Change{name: "x", version: 2})},
	}
	result := Run(t.Context(), &Schedule{Id: "fi15-restart", Steps: steps, Check: fi15Checks()}, world.net)
	fiRequireViolation(t, result, 4, "FI-15", "written at version 2, the versions rule's 5")
	fiRequireViolation(t, result, 4, "FI-15", "at or below the 4 it held: its versions restart")
}

// A push based before x's removal, changing x on its old version, committing after the removal: caught at the commit
// by the CAS, which reads x absent.
func TestFi15CatchesAPushBasedBeforeARemovalCommittingAfterIt(t *testing.T) {
	world := newFi15World(t)
	steps := []*Step{
		{Actor: "writerA", Action: world.push(-1, &fi15Change{name: "x", version: 1})},
		{Actor: "writerB", Action: world.push(-1, &fi15Change{name: "x", baseEntryVersion: 1})},
		// writerA's change of x on version 1, planned at v1, lands at v3
		{Actor: "writerA", Action: world.push(1, &fi15Change{name: "x", baseEntryVersion: 1, version: 2})},
	}
	result := Run(t.Context(), &Schedule{Id: "fi15-before-removal", Steps: steps, Check: fi15Checks()}, world.net)
	fiRequireViolation(t, result, 2, "FI-15", "written on base 1, its newest version 0: the path-level CAS")
}

// A lost update: two pushes on one base both changing x commit, the second over the first's version. Caught.
func TestFi15CatchesTwoChangesOnOneBase(t *testing.T) {
	world := newFi15World(t)
	steps := []*Step{
		{Actor: "writerA", Action: world.push(-1, &fi15Change{name: "x", version: 1})},
		{Actor: "writerA", Action: world.push(1, &fi15Change{name: "x", baseEntryVersion: 1, version: 2})},
		{Actor: "writerB", Action: world.push(1, &fi15Change{name: "x", baseEntryVersion: 1, version: 2})},
	}
	result := Run(t.Context(), &Schedule{Id: "fi15-lost-update", Steps: steps, Check: fi15Checks()}, world.net)
	fiRequireViolation(t, result, 2, "FI-15", "written on base 1, its newest version 2: the path-level CAS")
}

// A listing whose directory delta committed above the head it was served at, as an evs that read a newer entry would
// send it: caught once the ledger holds the reply.
func TestFi15CatchesAListingShowingAVersionAboveItsHead(t *testing.T) {
	result := fi15ListingRun(t, 1)
	fiRequireViolation(t, result, 2, "FI-15", "served a delta committed at 2, above the head: a listing showing a version above its head")
}

// Its twin: the same reply at the head that holds the delta reads clean.
func TestFi15TakesAListingAtTheHeadOfItsDelta(t *testing.T) {
	fiRequirePass(t, fi15ListingRun(t, 2))
}

// Two versions of x, then the root's listing with a delta committed at v2, served at headVersion.
func fi15ListingRun(t *testing.T, headVersion uint64) *Result {
	world := newFi15World(t)
	steps := []*Step{
		{Actor: "writerA", Action: world.push(-1, &fi15Change{name: "x", version: 1})},
		{Actor: "writerA", Action: world.push(-1, &fi15Change{name: "x", baseEntryVersion: 1, version: 2})},
		{Actor: "reader", Action: func(ctx context.Context, net *Net) error {
			LedgerOf(net).RecordRead(&LedgerRead{
				Actor: "reader", Instance: "evsr", Ref: HistoryRef{RepoId: world.repoId, RefId: world.main},
				HeadVersion: headVersion, RefMode: protocol.EvsRefMode_EVS_REF_FILE, CurrentEpoch: 1,
				Paths: []*protocol.EvsReadPathReply{{
					TokenPath: sidecar.EvsTokenPath{}.Components(),
					Names:     &protocol.EvsNameTable{},
					Deltas:    []*protocol.EvsIndexVersion{{PushId: sidecar.NewId().Bytes(), CommitVersion: 2}},
				}},
			})
			return nil
		}},
	}
	return Run(t.Context(), &Schedule{Id: "fi15-listing-above-head", Steps: steps, Check: fi15Checks()}, world.net)
}

// A file read served a version newer than the newest through the head it names: caught.
func TestFi15CatchesAReadServingAVersionNewerThanItsHead(t *testing.T) {
	world := newFi15World(t)
	var newest *protocol.EvsIndexVersion
	steps := []*Step{
		{Actor: "writerA", Action: world.push(-1, &fi15Change{name: "x", version: 1})},
		{Actor: "writerA", Action: world.push(-1, &fi15Change{name: "x", baseEntryVersion: 1, version: 2})},
		{Actor: "reader", Action: func(ctx context.Context, net *Net) error {
			// v2's own version of x, as its record holds it, served at head v1
			cluster := world.cluster
			head, err := world.heads.ReadCluster(ctx, cluster, world.repoId, world.main)
			if err != nil {
				return err
			}
			entries, err := sidecar.DecodeEvsWindow(head.Head.GetWindow())
			if err != nil || len(entries) < 2 {
				return fmt.Errorf("the window holds %d entries: %v", len(entries), err)
			}
			entryBytes, err := proto.Marshal(&protocol.EvsEntryVersion{Version: 2, PushId: entries[1].PushId.Bytes(), Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE)})
			if err != nil {
				return err
			}
			newest = &protocol.EvsIndexVersion{PushId: entries[1].PushId.Bytes(), CommitVersion: 2, EntryVersion: entryBytes}
			LedgerOf(net).RecordRead(&LedgerRead{
				Actor: "reader", Instance: "evsr", Ref: HistoryRef{RepoId: world.repoId, RefId: world.main},
				HeadVersion: 1, RefMode: protocol.EvsRefMode_EVS_REF_FILE, CurrentEpoch: 1,
				Paths: []*protocol.EvsReadPathReply{{TokenPath: world.token("x").Components(), Version: newest}},
			})
			return nil
		}},
	}
	result := Run(t.Context(), &Schedule{Id: "fi15-read-newer", Steps: steps, Check: fi15Checks()}, world.net)
	fiRequireViolation(t, result, 2, "FI-15", "served a version committed at 2, above the head")
	fiRequireViolation(t, result, 2, "FI-15", "served version 2", "its newest through v1 is version 1")
}

// The evs world's instances and readers through changes, removals, re-creations and a directory, a fold, a page of
// writes past a removal's base range and a marker collection, then the re-creation past it: every check reads clean,
// the readers' replies held to the replay (FS-58's collection clauses, on a correct build). writerB, whose reads
// never walked x.txt's removal, creates it again.
func TestFi15ReadsAWorldRunThroughACollectionClean(t *testing.T) {
	fi15WorldRun(t, "writerB")
}

// The same run with writerA, which removed x.txt, creating it again after the collection took the removal's marker
// (QD-879; question test-m2-04-recreate-after-collection): writerA's pin is older than its own removal, so its plan's
// read walks the removing statement, and evs serves it the removal from the window, where its marker served it
// before; the write commits at max(b, m) + 1 and no device alarms.
func TestFi15TheRemoverCreatesItsPathAgainAfterACollection(t *testing.T) {
	fi15WorldRun(t, "writerA")
}

// FI-15's healthy run on the evs world, creator creating x.txt again after the collection. Between the collection
// and that creation writerB, whose pin is past the removal, and the reader, whose pin is older than it, read x.txt:
// evs answers the first absent and the second its removal, from the window.
func fi15WorldRun(t *testing.T, creator string) {
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	world := NewEvsWorld(net, nil)
	removedAt := uint64(0)
	var pastReads, walkedReads, creatorReads []*LedgerRead
	// action, keeping the read replies evs served during it
	reading := func(reads *[]*LedgerRead, action func(ctx context.Context, net *Net) error) func(ctx context.Context, net *Net) error {
		return func(ctx context.Context, net *Net) error {
			before := len(LedgerOf(net).Reads())
			err := action(ctx, net)
			*reads = LedgerOf(net).Reads()[before:]
			return err
		}
	}
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: world.Write("writerA", "x.txt", EvsWorldContent("fi15 x 1", 200))},
		{Actor: "writerB", Action: world.Write("writerB", "docs/a.txt", EvsWorldContent("fi15 docs/a", 200))},
		{Actor: "writerA", Action: world.Write("writerA", "x.txt", EvsWorldContent("fi15 x 2", 200))},
		{Actor: "reader", Action: world.Verify("reader", "x.txt", "docs/a.txt")},
		{Actor: "reader", Action: world.VerifyListing("reader", "docs", "a.txt")},
		{Actor: "writerA", Action: world.Remove("writerA", "x.txt")},
		{Actor: "reader", Action: world.Verify("reader", "x.txt")},
		{Actor: "writerA", Action: world.Write("writerA", "x.txt", EvsWorldContent("fi15 x 3", 200))},
		{Actor: "writerB", Action: world.Write("writerB", "docs/b.txt", EvsWorldContent("fi15 docs/b", 200))},
		{Actor: "writerB", Action: world.Remove("writerB", "docs/a.txt")},
		{Actor: "reader", Action: world.VerifyListing("reader", "docs", "b.txt")},
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			if err := world.Remove("writerA", "x.txt")(ctx, net); err != nil {
				return err
			}
			version, _, err := world.CommittedVersion("writerA", "x.txt")
			removedAt = version
			return err
		}},
		{Actor: "writerB", Action: world.WriteMany("writerB", "n/%03d.txt", 0, 35)},
		{Actor: "writerB", Action: world.WriteMany("writerB", "n/%03d.txt", 35, 35)},
		{Actor: "folder", Action: world.Fold("evs1")},
		// raises folded_through past x's removal by a base range
		{Actor: "writerA", Action: world.Write("writerA", "y.txt", EvsWorldContent("fi15 y", 200))},
		{Actor: "collector", Action: world.CollectMarkers()},
		// writerB's pin is past the removal, the reader's older than it
		{Actor: "writerB", Action: reading(&pastReads, world.Verify("writerB", "x.txt"))},
		{Actor: "reader", Action: reading(&walkedReads, world.Verify("reader", "x.txt"))},
		{Actor: creator, Action: reading(&creatorReads, world.Write(creator, "x.txt", EvsWorldContent("fi15 x 4", 200)))},
		{Actor: "reader", Action: world.Verify("reader", "x.txt", "y.txt", "docs/b.txt")},
		{Actor: "reader", Action: world.VerifyCached("reader", "x.txt", "y.txt")},
		{Actor: "reader", Action: world.VerifyListing("reader", "docs", "b.txt")},
	}
	fiRequirePass(t, Run(t.Context(), &Schedule{Id: "fi15-world-" + creator, Steps: steps, Check: world.Checks(FI(2), FI(15))}, net))
	reads := LedgerOf(net).Reads()
	pathCount := 0
	for _, read := range reads {
		pathCount += len(read.Paths)
	}
	if len(reads) == 0 || pathCount == 0 {
		t.Fatalf("the ledger holds %d reads of %d paths, so FI-15's read clause judged nothing", len(reads), pathCount)
	}
	// what evs served of x.txt once its marker was gone
	removals := func(reads []*LedgerRead) (removalCount int, absentCount int) {
		for _, read := range reads {
			for _, path := range read.Paths {
				switch removal := path.GetRemoval(); {
				case removal != nil && removal.GetRemovalVersion() == removedAt:
					removalCount += 1
				case removal == nil && path.GetVersion() == nil && path.GetNames() == nil && len(path.GetDeltas()) == 0:
					absentCount += 1
				}
			}
		}
		return removalCount, absentCount
	}
	if removedAt == 0 {
		t.Fatal("x.txt's removal committed nowhere")
	}
	if removalCount, absentCount := removals(pastReads); removalCount != 0 || absentCount == 0 {
		t.Fatalf("writerB, pinned past x.txt's removal at %d, was served it %d times and absent %d times", removedAt, removalCount, absentCount)
	}
	if removalCount, _ := removals(walkedReads); removalCount == 0 {
		t.Fatalf("the reader, pinned below x.txt's removal at %d, was not served it from the window", removedAt)
	}
	removalCount, absentCount := removals(creatorReads)
	switch {
	case creator == "writerA" && removalCount == 0:
		t.Fatalf("writerA, which removed x.txt at %d, was not served its removal from the window", removedAt)
	case creator == "writerB" && (removalCount != 0 || absentCount == 0):
		t.Fatalf("writerB, pinned past x.txt's removal at %d, was served it %d times and absent %d times", removedAt, removalCount, absentCount)
	}
	version, _, err := world.CommittedVersion(creator, "x.txt")
	if err != nil {
		t.Fatal(err)
	}
	head, err := world.Head(t.Context())
	if err != nil || head == nil {
		t.Fatalf("main's head: %v", err)
	}
	if version != head.GetVersion() {
		t.Fatalf("x.txt's last write committed at %d, not at main's head %d", version, head.GetVersion())
	}
}
