package fault

// FI-16, FI-17 and FI-27 (fi16.go, fi17.go, fi27.go), the git-lfs clauses of FI-9 (fi9_lfs.go) and the clauses of FI-1
// and FI-5 they lift (TEST-M10-01), on T2:
//
//   - fiFormat2World: fi1_test.go's hand world with its repo at format 2 and the Net's gates admitting it with both
//     modes on, writing versionless and kept versions with the format's own builders, each kind-5 segment uploaded
//     with its 48 B header, and committing through evsservice.HeadStore, so a step's fault reaches the head write. A
//     purge here is a step's DELETE standing for a purger: the healthy one waits out the allowance after the
//     replacing commit's 200, and each mutant is the bug it names;
//   - the drop world (fs_drop_world_test.go) on a Net: the real drop job's resolve, mark, verify and deletes, its
//     batches evacuated by the real evacuator and its horizon the nightly pass's, which is FS-90's healthy run read by
//     the oracle after every step, and each mutant a DELETE the job would not issue;
//   - FS-72's migration and rollback schedules with FI-16 and FI-27 beside their own checks, FI-17 among them now
//     that it is bound (fs72Checks);
//   - stock git repositories for FI-9's git-lfs clauses, with the store recorded as a world would record it.
//
// A mutant asserts the run fails at its step, on the invariant and text it names, and its healthy prefix passes every
// check before it.

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// See the file header.
type fiFormat2World struct {
	*fiHandWorld
	segment sidecar.BlobCluster
	// each token path's newest path version, by its key string
	pathVersions map[string]uint64
}

// What one change of a push writes; nil removes its path.
type fiFormat2Entry struct {
	versioning uint32
	// labels of kind-5 segments the push uploads, which this version names
	uploads []string
	// ids of kind-5 segments this version names that an earlier push uploaded
	cites [][]byte
	// labels of kind-1 segments the push uploads, which this version names
	kind1 []string
	// a mutant's: the push its kind-5 uploads' headers name, nil for the push's own
	headerPushId *sidecar.Id
}

// One change of a push.
type fiFormat2Change struct {
	path  sidecar.EvsTokenPath
	entry *fiFormat2Entry
}

// A built push and the ids of what it uploaded, by label.
type fiFormat2Push struct {
	push *fiHandPush
	ids  map[string][]byte
}

func newFiFormat2World(t *testing.T, kind protocol.RepoKind) *fiFormat2World {
	t.Helper()
	hand := newFiHandWorld(t)
	ctx := t.Context()
	key := sidecar.EvsRepoObjectKey(hand.repoId)
	info, err := hand.cluster.Head(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	repoBytes, err := proto.Marshal(&protocol.EvsRepoObject{
		RepoId: hand.repoId.Bytes(), Kind: kind, State: protocol.EvsRepoState_EVS_REPO_ACTIVE,
		Format: sidecar.EvsRepoFormat2, NetworkId: hand.networkId.Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	// repo/ raised to format 2, as a migration's If-Match leaves it (§11.6's format row)
	if _, err := hand.cluster.PutIfMatch(ctx, key, info.Etag, repoBytes, nil); err != nil {
		t.Fatal(err)
	}
	segment, err := hand.net.Host().Blobs.SegmentCluster()
	if err != nil {
		t.Fatal(err)
	}
	fiFormat2SetModes(t, hand.net, hand.networkId, "on", "on")
	return &fiFormat2World{fiHandWorld: hand, segment: segment, pathVersions: map[string]uint64{}}
}

// The Net's gates: evs and format 2 open to the network, with these modes.
func fiFormat2SetModes(t *testing.T, net *Net, networkId sidecar.Id, purge string, drop string) {
	t.Helper()
	network := connect.Id(networkId).String()
	gates := fmt.Sprintf("sidecar:\n  evs: {enabled: true, networks: [%q]}\n  format2: {enabled: true, networks: [%q], percent: 0, purge: %q, drop: %q}\n", network, network, purge, drop)
	if err := net.Fakes().Gates.Set(gates); err != nil {
		t.Fatal(err)
	}
}

// A kind-5 segment of 4,096 B whose header names pushId: format 2, flags 0, the repo, generation 1 and the push (EVS-
// FORMAT.md's kind-5 header), filler after it; the oracles read no further than the header. Its id is its SHA-256.
func (self *fiFormat2World) kind5Segment(pushId sidecar.Id, label string) ([]byte, []byte) {
	segment := append([]byte("URvs"), 2, 0, 0, 0)
	segment = append(segment, self.repoId.Bytes()...)
	segment = binary.BigEndian.AppendUint64(segment, 1)
	segment = append(segment, pushId.Bytes()...)
	filler := sha256.Sum256([]byte("fi format 2 segment " + label))
	for len(segment) < 4096 {
		segment = append(segment, filler[:]...)
	}
	segment = segment[:4096]
	id := sha256.Sum256(segment)
	return segment, id[:]
}

// Builds and uploads a format-2 push of changes on refId at its head, its record written, not yet committed.
func (self *fiFormat2World) build(ctx context.Context, refId sidecar.Id, changes []*fiFormat2Change) (*fiFormat2Push, error) {
	chains := self.chains[refId]
	if chains == nil {
		chains = [][sha256.Size]byte{sidecar.EvsChainStart(self.repoId, refId)}
		self.chains[refId] = chains
	}
	baseVersion := uint64(len(chains) - 1)
	pushId := sidecar.NewId()
	now := self.net.Clock().Now()
	built := &fiFormat2Push{ids: map[string][]byte{}}
	planned := []*sidecar.EvsPlannedChange{}
	newObjects := []*sidecar.EvsNewObject{}
	upload := func(label string, segment []byte, id []byte) error {
		if _, err := self.segment.PutIfNoneMatch(ctx, evsOracleSegmentKey(self.repoId, id), segment, nil); err != nil && !errors.Is(err, sidecar.ErrBlobPrecondition) {
			return err
		}
		built.ids[label] = id
		newObjects = append(newObjects, &sidecar.EvsNewObject{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT, Id: id, PaddedSize: uint64(len(segment)), UploadDay: uint32(now.Unix() / 86400)})
		return nil
	}
	for _, change := range changes {
		pathKey := change.path.KeyString()
		base := self.pathVersions[pathKey]
		self.pathVersions[pathKey] = base + 1
		if change.entry == nil {
			planned = append(planned, &sidecar.EvsPlannedChange{TokenPath: change.path, BaseEntryVersion: base})
			continue
		}
		entry := &protocol.EvsEntryVersion{
			Version: base + 1, PushId: pushId.Bytes(), BaseVersion: baseVersion, TimeMs: now.UnixMilli(),
			Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), PaddedSize: 4096, SealedFields: []byte("sealed fields " + pathKey),
			Versioning: change.entry.versioning,
		}
		for _, label := range change.entry.uploads {
			headerPushId := pushId
			if change.entry.headerPushId != nil {
				headerPushId = *change.entry.headerPushId
			}
			segment, id := self.kind5Segment(headerPushId, label)
			if err := upload(label, segment, id); err != nil {
				return nil, err
			}
			entry.Chain = append(entry.Chain, &protocol.EvsLocator{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT), Id: id, Offset: 120, Length: 1024})
		}
		for _, id := range change.entry.cites {
			entry.Chain = append(entry.Chain, &protocol.EvsLocator{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT), Id: id, Offset: 120, Length: 1024})
		}
		for _, label := range change.entry.kind1 {
			segment := []byte(strings.Repeat("kind-1 segment "+label+" ", 64))
			id := sha256.Sum256(segment)
			if err := upload(label, segment, id[:]); err != nil {
				return nil, err
			}
			entry.Chain = append(entry.Chain, &protocol.EvsLocator{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT), Id: id[:], Offset: 104, Length: 512})
		}
		entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
		if err != nil {
			return nil, err
		}
		planned = append(planned, &sidecar.EvsPlannedChange{TokenPath: change.path, BaseEntryVersion: base, EntryVersion: entryBytes})
	}
	plan := &sidecar.EvsPushPlan{
		RepoId: self.repoId, RefId: refId, RefKind: protocol.EvsRefKind_EVS_REF_SHARED, RefMode: protocol.EvsRefMode_EVS_REF_FILE,
		PushId: pushId, BaseVersion: baseVersion, BaseChain: chains[baseVersion],
		Generation: 1, GroupId: self.groupId, GenerationCommitment: self.repoKey.Commitment(), PathEpoch: 1,
		Auth: self.view.Pin(), SignerSidecarId: self.admin.SidecarId, ClientId: sidecar.NewId(),
		TimeMs: now.UnixMilli(), SealedMetadata: []byte("sealed metadata"), Changes: planned, NewObjects: newObjects,
	}
	statementPush, err := sidecar.NewEvsStatementBuilder(self.admin.Sign).BuildFormat2(plan)
	if err != nil {
		return nil, err
	}
	built.push = &fiHandPush{refId: refId, statement: statementPush.Statement, payload: statementPush.Payload, signerId: self.admin.SidecarId}
	if err := self.writeRecord(ctx, built.push); err != nil {
		return nil, err
	}
	return built, nil
}

// A step action: changes built and committed on refId, the push kept in into.
func (self *fiFormat2World) push(refId sidecar.Id, into **fiFormat2Push, changes ...*fiFormat2Change) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		built, err := self.build(ctx, refId, changes)
		if err != nil {
			return err
		}
		if into != nil {
			*into = built
		}
		return self.commit(ctx, built.push)
	}
}

// A step action: changes built and their head write sent, its answer lost (the step's fault), which the writer leaves
// unknown and nothing rereads.
func (self *fiFormat2World) pushUnknown(refId sidecar.Id, into **fiFormat2Push, changes ...*fiFormat2Change) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		built, err := self.build(ctx, refId, changes)
		if err != nil {
			return err
		}
		*into = built
		var unknown *sidecar.BlobUnknownError
		if err := self.commit(ctx, built.push); !errors.As(err, &unknown) {
			return fmt.Errorf("the head write ended %v, not unknown", err)
		}
		return nil
	}
}

// A step action: changes built and their head write refused before it applied (the step's fault).
func (self *fiFormat2World) pushRefused(refId sidecar.Id, into **fiFormat2Push, changes ...*fiFormat2Change) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		built, err := self.build(ctx, refId, changes)
		if err != nil {
			return err
		}
		*into = built
		if err := self.commit(ctx, built.push); err == nil {
			return errors.New("the head write committed")
		}
		return nil
	}
}

// A step action: the DELETE of the segment label names in *built, as a purger issues it, unconditional.
func (self *fiFormat2World) deleteSegment(built **fiFormat2Push, label string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		id := (*built).ids[label]
		if id == nil {
			return fmt.Errorf("no segment %q", label)
		}
		return self.segment.Delete(ctx, evsOracleSegmentKey(self.repoId, id))
	}
}

// A step action: the segment label names in *built stored again, as a stale re-seed writes it back.
func (self *fiFormat2World) restoreSegment(built **fiFormat2Push, label string, headerPushId sidecar.Id) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		segment, id := self.kind5Segment(headerPushId, label)
		if hex.EncodeToString(id) != hex.EncodeToString((*built).ids[label]) {
			return errors.New("the restored bytes are not the segment's")
		}
		_, err := self.segment.PutIfNoneMatch(ctx, evsOracleSegmentKey(self.repoId, id), segment, nil)
		return err
	}
}

// A step action: a hold covering the network placed now, for 90 days.
func (self *fiFormat2World) placeHold(caseId sidecar.Id) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		now := net.Clock().Now()
		return sidecartest.PlaceHold(ctx, net.Host().Blobs, &sidecar.HoldRecord{
			NetworkId: self.networkId, CaseId: caseId, Kind: sidecar.HoldKindPreserve2703f,
			Scope: sidecar.HoldScopeRepos(self.repoId), PlaceTime: now, ExpireTime: now.Add(90 * 24 * time.Hour),
		})
	}
}

func fiFormat2Run(t *testing.T, world *fiFormat2World, id string, steps []*Step, checks ...Invariant) *Result {
	t.Helper()
	if len(checks) == 0 {
		checks = []Invariant{FI(1), FI(16), FI(17), FI(27)}
	}
	return Run(t.Context(), &Schedule{Id: id, Steps: steps, Check: checks}, world.net)
}

func fiRequireClean(t *testing.T, result *Result) {
	t.Helper()
	if result.Err != nil {
		t.Fatalf("a healthy run failed: %s", result)
	}
}

// A versionless path x: version 1 on its kind-5 segment s1, version 2 replacing it on s2, both committed.
func fiFormat2Replaced(world *fiFormat2World, main sidecar.Id, first **fiFormat2Push, second **fiFormat2Push) []*Step {
	x := sidecar.EvsTokenPath{sidecar.NewEvsRandomToken()}
	versionless := uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS)
	return []*Step{
		{Actor: "writerA", Action: world.push(main, first, &fiFormat2Change{path: x, entry: &fiFormat2Entry{versioning: versionless, uploads: []string{"s1"}}})},
		{Actor: "writerA", Action: world.push(main, second, &fiFormat2Change{path: x, entry: &fiFormat2Entry{versioning: versionless, uploads: []string{"s2"}}})},
	}
}

// The healthy purge: the replaced version's segment deleted once 60 s have passed since its replacement's 200. FI-1
// excuses it, FI-16 takes it, and the newest version keeps its content.
func TestFi16TakesAPurgeAfterTheAllowance(t *testing.T) {
	world := newFiFormat2World(t, protocol.RepoKind_REPO_KIND_GENERAL)
	var first, second *fiFormat2Push
	steps := append(fiFormat2Replaced(world, sidecar.NewId(), &first, &second),
		&Step{Advance: 61 * time.Second},
		&Step{Actor: "purge", Action: world.deleteSegment(&first, "s1")},
	)
	fiRequireClean(t, fiFormat2Run(t, world, "fi16-healthy", steps))
}

// A purge 30 s after the replacement's 200, inside the readers' allowance.
func TestFi16CatchesAPurgeBeforeTheAllowance(t *testing.T) {
	world := newFiFormat2World(t, protocol.RepoKind_REPO_KIND_GENERAL)
	var first, second *fiFormat2Push
	steps := append(fiFormat2Replaced(world, sidecar.NewId(), &first, &second),
		&Step{Advance: 30 * time.Second},
		&Step{Actor: "purge", Action: world.deleteSegment(&first, "s1")},
	)
	fiRequireViolation(t, fiFormat2Run(t, world, "fi16-early", steps), 3, "FI-16", "inside the 1m0s allowance")
}

// A purge on an unknown outcome: the replacing push's head write landed with its answer lost, and the purge went 61 s
// later with no process having seen the commit.
func TestFi16CatchesAPurgeOnAnUnknownOutcome(t *testing.T) {
	world := newFiFormat2World(t, protocol.RepoKind_REPO_KIND_GENERAL)
	main := sidecar.NewId()
	x := sidecar.EvsTokenPath{sidecar.NewEvsRandomToken()}
	versionless := uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS)
	var first, second *fiFormat2Push
	steps := []*Step{
		{Actor: "writerA", Action: world.push(main, &first, &fiFormat2Change{path: x, entry: &fiFormat2Entry{versioning: versionless, uploads: []string{"s1"}}})},
		{
			Actor:  "writerA",
			Fault:  &FaultPlan{Op: sidecartest.FaultOpPut, KeyPrefix: evsOracleRepoPrefix("head/", world.repoId), Result: ApplyThenDrop},
			Action: world.pushUnknown(main, &second, &fiFormat2Change{path: x, entry: &fiFormat2Entry{versioning: versionless, uploads: []string{"s2"}}}),
		},
		{Advance: 61 * time.Second},
		{Actor: "purge", Action: world.deleteSegment(&first, "s1")},
	}
	fiRequireViolation(t, fiFormat2Run(t, world, "fi16-unknown", steps, FI(16)), 3, "FI-16", "answered to no process", "an unknown push purges nothing")
}

// A purge for a refused push: the replacing push's head write failed before it applied, so the version it would have
// replaced is still its path's newest.
func TestFi16CatchesAPurgeOfARefusedPushsCandidate(t *testing.T) {
	world := newFiFormat2World(t, protocol.RepoKind_REPO_KIND_GENERAL)
	main := sidecar.NewId()
	x := sidecar.EvsTokenPath{sidecar.NewEvsRandomToken()}
	versionless := uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS)
	var first, second *fiFormat2Push
	steps := []*Step{
		{Actor: "writerA", Action: world.push(main, &first, &fiFormat2Change{path: x, entry: &fiFormat2Entry{versioning: versionless, uploads: []string{"s1"}}})},
		{
			Actor:  "writerA",
			Fault:  &FaultPlan{Op: sidecartest.FaultOpPut, KeyPrefix: evsOracleRepoPrefix("head/", world.repoId), Result: FailBeforeApply},
			Action: world.pushRefused(main, &second, &fiFormat2Change{path: x, entry: &fiFormat2Entry{versioning: versionless, uploads: []string{"s2"}}}),
		},
		{Advance: 61 * time.Second},
		{Actor: "purge", Action: world.deleteSegment(&first, "s1")},
	}
	result := fiFormat2Run(t, world, "fi16-refused", steps)
	fiRequireViolation(t, result, 3, "FI-16", "its path's newest", "nothing is purged before its replacing version commits")
	fiRequireViolation(t, result, 3, "FI-1", "does not hold")
}

// A hold placed while s1 existed keeps it: the purge's DELETE under it fails.
func TestFi16CatchesADeleteUnderAHold(t *testing.T) {
	world := newFiFormat2World(t, protocol.RepoKind_REPO_KIND_GENERAL)
	main := sidecar.NewId()
	var first, second *fiFormat2Push
	replaced := fiFormat2Replaced(world, main, &first, &second)
	steps := []*Step{
		replaced[0],
		{Advance: time.Minute},
		{Actor: "api", Action: world.placeHold(sidecar.NewId())},
		{Advance: time.Minute},
		replaced[1],
		{Advance: 61 * time.Second},
		{Actor: "purge", Action: world.deleteSegment(&first, "s1")},
	}
	fiRequireViolation(t, fiFormat2Run(t, world, "fi16-hold", steps), 6, "FI-16", "kept it, since it existed at the placement")
}

// A hold placed before s1 existed keeps nothing of it: content created after placement is purged as usual (owner
// decision 133), the twin of the hold mutant.
func TestFi16TakesAPurgeOfWhatCameAfterAHold(t *testing.T) {
	world := newFiFormat2World(t, protocol.RepoKind_REPO_KIND_GENERAL)
	var first, second *fiFormat2Push
	steps := []*Step{
		{Actor: "api", Action: world.placeHold(sidecar.NewId())},
		{Advance: time.Minute},
	}
	steps = append(steps, fiFormat2Replaced(world, sidecar.NewId(), &first, &second)...)
	steps = append(steps, &Step{Advance: 61 * time.Second}, &Step{Actor: "purge", Action: world.deleteSegment(&first, "s1")})
	fiRequireClean(t, fiFormat2Run(t, world, "fi16-after-hold", steps))
}

// Under §19.11's purge: observe nothing deletes.
func TestFi16CatchesAPurgeUnderObserve(t *testing.T) {
	world := newFiFormat2World(t, protocol.RepoKind_REPO_KIND_GENERAL)
	fiFormat2SetModes(t, world.net, world.networkId, "observe", "on")
	var first, second *fiFormat2Push
	steps := append(fiFormat2Replaced(world, sidecar.NewId(), &first, &second),
		&Step{Advance: 61 * time.Second},
		&Step{Actor: "purge", Action: world.deleteSegment(&first, "s1")},
	)
	fiRequireViolation(t, fiFormat2Run(t, world, "fi16-observe", steps, FI(16)), 3, "FI-16", "purge mode read observe")
}

// Purged content never returns: a stale re-seed writing s1 back after a check found it gone fails.
func TestFi16CatchesPurgedContentReturning(t *testing.T) {
	world := newFiFormat2World(t, protocol.RepoKind_REPO_KIND_GENERAL)
	var first, second *fiFormat2Push
	steps := append(fiFormat2Replaced(world, sidecar.NewId(), &first, &second),
		&Step{Advance: 61 * time.Second},
		&Step{Actor: "purge", Action: world.deleteSegment(&first, "s1")},
		&Step{Actor: "reseed", Action: func(ctx context.Context, net *Net) error {
			return world.restoreSegment(&first, "s1", sidecar.Id(first.push.statement.Push.GetPushId()))(ctx, net)
		}},
	)
	fiRequireViolation(t, fiFormat2Run(t, world, "fi16-returns", steps, FI(16)), 4, "FI-16", "is stored again: purged content never returns")
}

// The newest version's content deleted: FI-16's own clause names it, beside FI-1.
func TestFi16CatchesTheNewestVersionsContentDeleted(t *testing.T) {
	world := newFiFormat2World(t, protocol.RepoKind_REPO_KIND_GENERAL)
	x := sidecar.EvsTokenPath{sidecar.NewEvsRandomToken()}
	var first *fiFormat2Push
	steps := []*Step{
		{Actor: "writerA", Action: world.push(sidecar.NewId(), &first, &fiFormat2Change{path: x, entry: &fiFormat2Entry{versioning: uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS), uploads: []string{"s1"}}})},
		{Advance: 61 * time.Second},
		{Actor: "purge", Action: world.deleteSegment(&first, "s1")},
	}
	result := fiFormat2Run(t, world, "fi16-newest", steps, FI(16))
	fiRequireViolation(t, result, 2, "FI-16", "every path's newest committed version keeps all its content")
}

// A version naming a kind-5 segment another path introduced: never by another path.
func TestFi17CatchesAKind5CitationFromAnotherPath(t *testing.T) {
	world := newFiFormat2World(t, protocol.RepoKind_REPO_KIND_GENERAL)
	main := sidecar.NewId()
	x, y := sidecar.EvsTokenPath{sidecar.NewEvsRandomToken()}, sidecar.EvsTokenPath{sidecar.NewEvsRandomToken()}
	versionless := uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS)
	var first, second *fiFormat2Push
	steps := []*Step{
		{Actor: "writerA", Action: world.push(main, &first, &fiFormat2Change{path: x, entry: &fiFormat2Entry{versioning: versionless, uploads: []string{"s1"}}})},
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			return world.push(main, &second, &fiFormat2Change{path: y, entry: &fiFormat2Entry{versioning: versionless, cites: [][]byte{first.ids["s1"]}}})(ctx, net)
		}},
	}
	fiRequireViolation(t, fiFormat2Run(t, world, "fi17-another-path", steps, FI(17)), 1, "FI-17", "versionless content is never named by another path")
}

// Its path's next version naming an unchanged kind-5 segment in turn, and a rename target of the push removing the
// path naming it: both allowed (§11.7's cite row).
func TestFi17TakesACitationInTurnAndARenameTarget(t *testing.T) {
	world := newFiFormat2World(t, protocol.RepoKind_REPO_KIND_GENERAL)
	main := sidecar.NewId()
	x, y := sidecar.EvsTokenPath{sidecar.NewEvsRandomToken()}, sidecar.EvsTokenPath{sidecar.NewEvsRandomToken()}
	versionless := uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS)
	var first, second, third *fiFormat2Push
	steps := []*Step{
		{Actor: "writerA", Action: world.push(main, &first, &fiFormat2Change{path: x, entry: &fiFormat2Entry{versioning: versionless, uploads: []string{"s1"}}})},
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			return world.push(main, &second, &fiFormat2Change{path: x, entry: &fiFormat2Entry{versioning: versionless, cites: [][]byte{first.ids["s1"]}, uploads: []string{"s2"}}})(ctx, net)
		}},
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			return world.push(main, &third, &fiFormat2Change{path: x}, &fiFormat2Change{path: y, entry: &fiFormat2Entry{versioning: versionless, cites: [][]byte{first.ids["s1"], second.ids["s2"]}}})(ctx, net)
		}},
	}
	fiRequireClean(t, fiFormat2Run(t, world, "fi17-in-turn", steps))
}

// The push removing x names its segment in two new versions: each removed path's segment is named by at most one.
func TestFi17CatchesARemovedPathsSegmentNamedTwice(t *testing.T) {
	world := newFiFormat2World(t, protocol.RepoKind_REPO_KIND_GENERAL)
	main := sidecar.NewId()
	x, y, z := sidecar.EvsTokenPath{sidecar.NewEvsRandomToken()}, sidecar.EvsTokenPath{sidecar.NewEvsRandomToken()}, sidecar.EvsTokenPath{sidecar.NewEvsRandomToken()}
	versionless := uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS)
	var first, second *fiFormat2Push
	steps := []*Step{
		{Actor: "writerA", Action: world.push(main, &first, &fiFormat2Change{path: x, entry: &fiFormat2Entry{versioning: versionless, uploads: []string{"s1"}}})},
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			cites := [][]byte{first.ids["s1"]}
			return world.push(main, &second, &fiFormat2Change{path: x},
				&fiFormat2Change{path: y, entry: &fiFormat2Entry{versioning: versionless, cites: cites}},
				&fiFormat2Change{path: z, entry: &fiFormat2Entry{versioning: versionless, cites: cites}})(ctx, net)
		}},
	}
	fiRequireViolation(t, fiFormat2Run(t, world, "fi17-twice", steps, FI(17)), 1, "FI-17", "in 2 new versions, past one")
}

// A kind-5 upload whose header names another push than its introducing one.
func TestFi17CatchesAKind5HeaderNamingAnotherPush(t *testing.T) {
	world := newFiFormat2World(t, protocol.RepoKind_REPO_KIND_GENERAL)
	other := sidecar.NewId()
	steps := []*Step{
		{Actor: "writerA", Action: world.push(sidecar.NewId(), nil, &fiFormat2Change{path: sidecar.EvsTokenPath{sidecar.NewEvsRandomToken()}, entry: &fiFormat2Entry{
			versioning: uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS), uploads: []string{"s1"}, headerPushId: &other,
		}})},
	}
	fiRequireViolation(t, fiFormat2Run(t, world, "fi17-header", steps, FI(17)), 0, "FI-17", "a kind-5 segment names its introducing push")
}

// Versioning 1 in a config repo, whose replaying readers verify authority from every version.
func TestFi17CatchesVersioningInAConfigRepo(t *testing.T) {
	world := newFiFormat2World(t, protocol.RepoKind_REPO_KIND_CONFIG)
	steps := []*Step{
		{Actor: "writerA", Action: world.push(sidecar.NewId(), nil, &fiFormat2Change{path: sidecar.EvsTokenPath{sidecar.NewEvsRandomToken()}, entry: &fiFormat2Entry{
			versioning: uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS), uploads: []string{"s1"},
		}})},
	}
	fiRequireViolation(t, fiFormat2Run(t, world, "fi17-config", steps, FI(17)), 0, "FI-17", "versioning 1 in a REPO_KIND_CONFIG repo")
}

// Versioning 2 under no index root the schedule named fails closed; under the named root it passes.
func TestFi17HoldsVersioning2ToANamedIndexRoot(t *testing.T) {
	for _, named := range []bool{false, true} {
		world := newFiFormat2World(t, protocol.RepoKind_REPO_KIND_GENERAL)
		main := sidecar.NewId()
		root := sidecar.EvsTokenPath{sidecar.NewEvsRandomToken()}
		if named {
			SetFi17IndexRoots(world.net, world.repoId, &Fi17IndexRoot{RefId: main, TokenPath: root, PathEpoch: 1})
		}
		steps := []*Step{
			{Actor: "indexer", Action: world.push(main, nil, &fiFormat2Change{path: append(sidecar.EvsTokenPath{root[0]}, sidecar.NewEvsRandomToken()), entry: &fiFormat2Entry{
				versioning: uint32(protocol.EvsVersioning_EVS_VERSIONING_INDEX), uploads: []string{"shard"},
			}})},
		}
		result := fiFormat2Run(t, world, "fi17-index-root", steps, FI(17))
		if named {
			fiRequireClean(t, result)
		} else {
			fiRequireViolation(t, result, 0, "FI-17", "versioning 2 under no index root")
		}
		world.net.Close()
	}
}

// Content a version written with versioning 0 names, deleted with no drop listing it: kept forever (FI-17's kept
// clause), and FI-27 names the DELETE too.
func TestFi17CatchesKeptContentDeleted(t *testing.T) {
	world := newFiFormat2World(t, protocol.RepoKind_REPO_KIND_GENERAL)
	main := sidecar.NewId()
	x := sidecar.EvsTokenPath{sidecar.NewEvsRandomToken()}
	var first, second *fiFormat2Push
	steps := []*Step{
		{Actor: "writerA", Action: world.push(main, &first, &fiFormat2Change{path: x, entry: &fiFormat2Entry{kind1: []string{"k1"}}})},
		{Actor: "writerA", Action: world.push(main, &second, &fiFormat2Change{path: x, entry: &fiFormat2Entry{versioning: uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS), uploads: []string{"s2"}}})},
		{Advance: 61 * time.Second},
		{Actor: "purge", Action: world.deleteSegment(&first, "k1")},
	}
	result := fiFormat2Run(t, world, "fi17-kept", steps, FI(17), FI(27))
	fiRequireViolation(t, result, 3, "FI-17", "written with versioning 0, names it")
	fiRequireViolation(t, result, 3, "FI-27", "no committed drop of the repo lists that version")
}

// FS-72's migration and its race-free twin, and its rollback and forward-only twin, read clean with FI-16 and FI-27
// beside the checks they name, FI-17 among them.
func TestFi16AndFi27ReadFs72sSchedulesClean(t *testing.T) {
	if !sidecartest.HooksLinked {
		t.Skip("FS-72's schedules hold evs at barriers, which need the sidecar_testhooks build")
	}
	for _, builder := range []Builder{Fs72Migration, Fs72MigrationRaceFree, Fs72Rollback, Fs72RollbackForwardOnly} {
		// one Net at a time: a hooks build installs its hooks per open Net
		func() {
			net := sidecartest.NewNet(t.Context(), nil)
			defer net.Close()
			schedule := builder(net)
			if !evsChecksName(schedule.Check, "FI-17") {
				t.Fatalf("%s does not check FI-17, which is bound", schedule.Id)
			}
			schedule.Check = append(schedule.Check, FI(16), FI(27))
			if result := Run(t.Context(), schedule, net); result.Err != nil {
				t.Fatalf("%s: %s", schedule.Id, result)
			}
		}()
	}
}

// Whether checks name the invariant.
func evsChecksName(checks []Invariant, id string) bool {
	for _, check := range checks {
		if check.Id() == id {
			return true
		}
	}
	return false
}

// FS-90's drop world on a Net: x's two versions name d1 and d2, the first shares s1 with y; the drop lists x's two
// versions. Built before the schedule, so the first check reads it whole.
type fiDropWorld struct {
	*fs90History
	net *Net
	x   sidecar.EvsTokenPath
	// x's two entry versions, which the drop lists
	first, second []byte
	// the ref version the DROP committed at
	dropVersion uint64
	// closes the Net once, before a test's next world opens one
	close func()
}

func newFiDropWorld(t *testing.T, listSecond bool) *fiDropWorld {
	t.Helper()
	net := sidecartest.NewNet(t.Context(), nil)
	closed := false
	t.Cleanup(func() {
		if !closed {
			net.Close()
		}
	})
	world := newFsDropWorldOn(t, net)
	history := &fs90History{world: world, refA: fsDropId16("ref a"), dropId: fsDropId16("drop x"), d1: fsDropSegment("d1"), d2: fsDropSegment("d2"), s1: fsDropSegment("s1")}
	drop := &fiDropWorld{fs90History: history, net: net, x: fsDropPath("x"), close: func() {
		if !closed {
			closed = true
			net.Close()
		}
	}}
	drop.first = world.write(history.refA, drop.x, 0, &fsDropEntry{segments: [][32]byte{history.d1, history.s1}})
	drop.second = world.write(history.refA, drop.x, 1, &fsDropEntry{segments: [][32]byte{history.d2}})
	world.write(history.refA, fsDropPath("y"), 0, &fsDropEntry{segments: [][32]byte{history.s1}})
	listed := [][]byte{drop.first, drop.second}
	if !listSecond {
		// a mutant's list, missing x's second version
		listed = [][]byte{drop.first}
	}
	world.drop(history.refA, history.dropId, []*protocol.EvsDropPath{fsDropPathOf(3, 1, nil, fsDropSource(1, drop.x))}, [][][]byte{listed})
	drop.dropVersion = world.refs[history.refA].head.Version()
	return drop
}

// Commits a cancel of the drop on its ref, as an admin's DROP of action 2 commits before not_before_ms less 60 s.
func (self *fiDropWorld) cancel(t *testing.T) {
	t.Helper()
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.EvsDropHistory{
		DropId: fsDropId16("cancel x").Bytes(), Action: 2, CancelsDropId: self.dropId.Bytes(), CancelsVersion: self.dropVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	self.world.commit(self.refA, protocol.EvsRefMode_EVS_REF_FILE, &fsDropPush{flags: uint32(protocol.EvsPushFlag_EVS_PUSH_DROP), dropBody: body})
}

// A step action: the clock moved 50 h on, past the drop's start and every batch's evacuation age.
func (self *fiDropWorld) ripen() func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		self.world.clock.Advance(50 * time.Hour)
		self.world.horizon.horizon = self.world.clock.Now()
		return nil
	}
}

// A step action: one hourly evacuation of the repo's cluster at format 2, as taskworker runs it.
func (self *fiDropWorld) evacuate() func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		settings := evsservice.DefaultEvsSettings()
		settings.InstanceFormat = sidecar.EvsRepoFormat2
		evacuator, err := evsservice.NewEvacuator(net.Host(), &evsservice.EvacuatorDeps{
			Settings: evsservice.DefaultEvacuatorSettings(), EvsSettings: settings,
			Format2: evsservice.NewFormat2Gate(net.Host()), Usage: &evsWorldStoredDeltas{},
		})
		if err != nil {
			return err
		}
		_, err = evacuator.Run(ctx, "meta-1")
		return err
	}
}

// A step action: the drop job run to its end, the clock moved to each wake it asks for.
func (self *fiDropWorld) runJob() func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		job := self.world.job("evs-a")
		for range 20 {
			self.world.hddKnown()
			result, err := job.Run(self.world.ctx, "meta-1", self.world.repoId)
			if err != nil {
				return err
			}
			if result.Ended || result.Next.IsZero() {
				return nil
			}
			if wait := result.Next.Sub(self.world.clock.Now()); 0 < wait {
				self.world.clock.Advance(wait)
			}
		}
		return errors.New("the job did not end in 20 runs")
	}
}

// A step action: the DELETE of a segment, naming its LastModified as a job does unless unconditional.
func (self *fiDropWorld) deleteSegment(id [32]byte, named bool) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		key := evsservice.SegmentKey(self.world.repoId, id)
		if named {
			info, err := self.world.segment.Head(ctx, key)
			if err != nil {
				return err
			}
			ctx = sidecar.WithBlobUnmodified(ctx, info.LastModified)
		}
		return self.world.segment.Delete(ctx, key)
	}
}

func fiDropRun(t *testing.T, world *fiDropWorld, id string, steps []*Step) *Result {
	t.Helper()
	return Run(t.Context(), &Schedule{Id: id, Steps: steps, Check: []Invariant{FI(5), FI(16), FI(17), FI(27)}}, world.net)
}

// FS-90's healthy run read after every step: the job deletes d1 and d2, which only the listed versions name, keeps
// s1, which y names, and each DELETE meets FI-27's four conditions.
func TestFi27ReadsAHealthyDropJobClean(t *testing.T) {
	world := newFiDropWorld(t, true)
	steps := []*Step{
		{Actor: "clock", Action: world.ripen()},
		{Actor: "taskworker", Action: world.evacuate()},
		{Actor: "taskworker", Action: world.runJob()},
	}
	fiRequireClean(t, fiDropRun(t, world, "fi27-healthy", steps))
	if world.world.stored(world.d1) || world.world.stored(world.d2) || !world.world.stored(world.s1) {
		t.Fatalf("d1 %t, d2 %t, s1 %t", world.world.stored(world.d1), world.world.stored(world.d2), world.world.stored(world.s1))
	}
}

// A segment a surviving version names deleted: y names s1, and no drop lists y.
func TestFi27CatchesASegmentASurvivingVersionNamesDeleted(t *testing.T) {
	world := newFiDropWorld(t, true)
	steps := []*Step{
		{Actor: "clock", Action: world.ripen()},
		{Actor: "taskworker", Action: world.evacuate()},
		{Actor: "taskworker", Action: world.runJob()},
		{Actor: "taskworker", Action: world.deleteSegment(world.s1, true)},
	}
	fiRequireViolation(t, fiDropRun(t, world, "fi27-surviving", steps), 3, "FI-27", "no committed drop of the repo lists that version")
}

// A drop whose list misses x's second version is resolve's {mismatch} and executes nothing: a job that deleted d1 on
// its strength fails.
func TestFi27CatchesADropListMissingAVersion(t *testing.T) {
	world := newFiDropWorld(t, false)
	steps := []*Step{
		{Actor: "clock", Action: world.ripen()},
		{Actor: "taskworker", Action: world.evacuate()},
		{Actor: "taskworker", Action: world.deleteSegment(world.d1, true)},
	}
	fiRequireViolation(t, fiDropRun(t, world, "fi27-list", steps), 2, "FI-27", "is refused {mismatch}")
}

// A stale job instance deleting after its lease: the job ended, a concurrent push stored d1's bytes again and a new
// version names them, and the stale instance's DELETE, naming no LastModified, takes the adopter's segment.
func TestFi27CatchesAStaleJobDeletingAfterItsLease(t *testing.T) {
	world := newFiDropWorld(t, true)
	refB := fsDropId16("ref b")
	steps := []*Step{
		{Actor: "clock", Action: world.ripen()},
		{Actor: "taskworker", Action: world.evacuate()},
		{Actor: "taskworker", Action: world.runJob()},
		{Actor: "writerB", Action: func(ctx context.Context, net *Net) error {
			world.world.write(refB, fsDropPath("z"), 0, &fsDropEntry{segments: [][32]byte{world.d1}})
			return nil
		}},
		{Advance: time.Minute},
		{Actor: "stale-job", Action: world.deleteSegment(world.d1, false)},
	}
	result := fiDropRun(t, world, "fi27-stale", steps)
	fiRequireViolation(t, result, 5, "FI-27", "no committed drop of the repo lists that version")
	fiRequireViolation(t, result, 5, "FI-27", "names no LastModified")
}

// A DELETE before evacuation's horizon passed the object's LastModified + 24 h 2 min: its batches still stand.
func TestFi27CatchesADeleteBeforeTheHorizon(t *testing.T) {
	world := newFiDropWorld(t, true)
	steps := []*Step{
		{Actor: "clock", Action: world.ripen()},
		{Actor: "taskworker", Action: world.deleteSegment(world.d1, true)},
	}
	fiRequireViolation(t, fiDropRun(t, world, "fi27-horizon", steps), 1, "FI-27", "evacuation's horizon", "had not passed its LastModified")
}

// A DELETE under a hold placed while the object existed.
func TestFi27CatchesADeleteUnderAHold(t *testing.T) {
	world := newFiDropWorld(t, true)
	steps := []*Step{
		{Actor: "api", Action: func(ctx context.Context, net *Net) error {
			now := net.Clock().Now()
			return sidecartest.PlaceHold(ctx, net.Host().Blobs, &sidecar.HoldRecord{
				NetworkId: world.world.networkId, CaseId: fsDropId16("hold case"), Kind: sidecar.HoldKindPreserve2703f,
				Scope: sidecar.HoldScopeNetwork(), PlaceTime: now, ExpireTime: now.Add(90 * 24 * time.Hour),
			})
		}},
		{Actor: "clock", Action: world.ripen()},
		{Actor: "taskworker", Action: world.evacuate()},
		{Actor: "taskworker", Action: world.deleteSegment(world.d1, true)},
	}
	fiRequireViolation(t, fiDropRun(t, world, "fi27-hold", steps), 3, "FI-27", "stood when the DELETE issued, and the object existed at its placement")
}

// A dropped object stored again: FI-27 and FI-5 both fail, unless a close report names the drop as re-seeded from a
// stale mirror.
func TestFi27AndFi5CatchADroppedObjectReturning(t *testing.T) {
	for _, reported := range []bool{false, true} {
		world := newFiDropWorld(t, true)
		if reported {
			RecordCloseReport(world.net, &CloseReport{IncidentId: sidecar.NewId(), Drops: []*CloseReportDrop{{RepoId: world.world.repoId, DropId: world.dropId.Bytes()}}})
		}
		steps := []*Step{
			{Actor: "clock", Action: world.ripen()},
			{Actor: "taskworker", Action: world.evacuate()},
			{Actor: "taskworker", Action: world.runJob()},
			{Actor: "reseed", Action: func(ctx context.Context, net *Net) error {
				world.world.storeSegment(world.d1, 1000)
				return nil
			}},
		}
		result := fiDropRun(t, world, "fi27-returns", steps)
		world.close()
		if reported {
			fiRequireClean(t, result)
			continue
		}
		fiRequireViolation(t, result, 3, "FI-27", "is stored again: deleted content never returns")
		fiRequireViolation(t, result, 3, "FI-5", "is stored again: deleted content never returns")
	}
}

// A cancelled drop deletes nothing.
func TestFi27CatchesACancelledDropDeleting(t *testing.T) {
	world := newFiDropWorld(t, true)
	world.cancel(t)
	steps := []*Step{
		{Actor: "clock", Action: world.ripen()},
		{Actor: "taskworker", Action: world.evacuate()},
		{Actor: "taskworker", Action: world.deleteSegment(world.d1, true)},
	}
	fiRequireViolation(t, fiDropRun(t, world, "fi27-cancelled", steps), 2, "FI-27", "is cancelled")
}

// A repository at dir with a commit of files, every git setting the host might hold kept out, its date fixed. Returns
// the commit's oid and its tree's.
func fi9LfsCommit(t *testing.T, dir string, files map[string]string) (string, string) {
	t.Helper()
	git := func(args ...string) string {
		command := exec.Command("git", append([]string{"-C", dir}, args...)...)
		command.Env = append(os.Environ(),
			"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "HOME="+dir,
			"GIT_AUTHOR_NAME=fi9", "GIT_AUTHOR_EMAIL=fi9@example.com", "GIT_COMMITTER_NAME=fi9", "GIT_COMMITTER_EMAIL=fi9@example.com",
			"GIT_AUTHOR_DATE=2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-01-01T00:00:00Z",
		)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, output)
		}
		return strings.TrimSpace(string(output))
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		git("init", "-q", "-b", "main")
	}
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git("add", "-A")
	git("commit", "-q", "--allow-empty", "-m", "fi9 lfs")
	return git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}")
}

// A git-lfs v1 pointer to content, and its oid.
func fi9LfsPointer(content []byte) (string, string) {
	digest := sha256.Sum256(content)
	oid := hex.EncodeToString(digest[:])
	return fmt.Sprintf("%s\noid sha256:%s\nsize %d\n", gitLfsPointerVersionLine, oid, len(content)), oid
}

// A ledger holding one acknowledged push of main at the commit, its export, and then each store in order.
func fi9LfsLedger(dir string, commit string, tree string, stores ...map[string][]byte) *GitLedger {
	ledger := NewGitLedger()
	ledger.RecordPush(&GitPush{Actor: "lfs", Updates: []*GitPushUpdate{{Ref: "refs/heads/main", Source: "HEAD", New: commit, Tree: tree, Status: GitPushOk, Summary: "[new branch]"}}})
	ledger.RecordExport(filepath.Join(dir, ".git"))
	for _, store := range stores {
		ledger.RecordLfsStore(store)
	}
	return ledger
}

func fi9LfsGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git on this host")
	}
}

// A tip whose pointer's object ur/lfs holds after the push reads clean; one whose object it lacks fails.
func TestFi9LfsHoldsATipToTheObjectsItRequires(t *testing.T) {
	fi9LfsGit(t)
	content := []byte("an lfs object's bytes\n")
	pointer, oid := fi9LfsPointer(content)
	dir := t.TempDir()
	commit, tree := fi9LfsCommit(t, dir, map[string]string{".gitattributes": "*.bin filter=lfs diff=lfs merge=lfs -text\n", "data/a.bin": pointer})
	if err := CheckGitPushes(fi9LfsLedger(dir, commit, tree, map[string][]byte{oid: content}), true); err != nil {
		t.Fatalf("a tip whose object the store holds: %v", err)
	}
	err := CheckGitPushes(fi9LfsLedger(dir, commit, tree, map[string][]byte{}), true)
	if err == nil || !strings.Contains(err.Error(), "a git-mode tip commits only once ur/lfs holds every git-lfs object it requires") {
		t.Fatalf("a tip committed without its object: %v", err)
	}
	err = CheckGitPushes(fi9LfsLedger(dir, commit, tree), true)
	if err == nil || !strings.Contains(err.Error(), "no ur/lfs store was recorded after it") {
		t.Fatalf("a push no store record follows: %v", err)
	}
}

// A store record after the push that lacks an object the current tip requires: a prune removed it.
func TestFi9LfsCatchesAPruneOfAnObjectATipRequires(t *testing.T) {
	fi9LfsGit(t)
	content := []byte("pruned too soon\n")
	pointer, oid := fi9LfsPointer(content)
	dir := t.TempDir()
	commit, tree := fi9LfsCommit(t, dir, map[string]string{".gitattributes": "*.bin filter=lfs -text\n", "a.bin": pointer})
	err := CheckGitPushes(fi9LfsLedger(dir, commit, tree, map[string][]byte{oid: content}, map[string][]byte{}), true)
	if err == nil || !strings.Contains(err.Error(), "no prune removes an object a current tip requires") {
		t.Fatalf("a prune of a current tip's object: %v", err)
	}
}

// R(c) reads .gitattributes: a pointer's bytes at a path no filter=lfs covers, or one a deeper file unsets, require
// nothing; a store object whose bytes do not hash to its oid fails.
func TestFi9LfsReadsAttributesAndHashes(t *testing.T) {
	fi9LfsGit(t)
	content := []byte("not lfs\n")
	pointer, oid := fi9LfsPointer(content)
	dir := t.TempDir()
	commit, tree := fi9LfsCommit(t, dir, map[string]string{
		".gitattributes": "*.bin filter=lfs -text\n", "notes.txt": pointer, "keep/.gitattributes": "*.bin -filter\n", "keep/b.bin": pointer,
	})
	repository, err := OpenGitRepository(filepath.Join(dir, ".git"))
	if err != nil {
		t.Fatal(err)
	}
	required, err := GitLfsRequires(repository, commit, DefaultGitLfsSettings())
	if err != nil {
		t.Fatal(err)
	}
	if len(required) != 0 {
		t.Fatalf("required %v, want nothing", required)
	}
	err = CheckGitPushes(fi9LfsLedger(dir, commit, tree, map[string][]byte{oid: []byte("other bytes\n")}), true)
	if err == nil || !strings.Contains(err.Error(), "whose content hashes to") {
		t.Fatalf("a store object that does not hash to its oid: %v", err)
	}
}

// git-lfs's pointer format, as the spec writes it.
func TestFi9LfsParsesPointers(t *testing.T) {
	pointer, oid := fi9LfsPointer([]byte("x"))
	if parsedOid, size, ok := ParseGitLfsPointer([]byte(pointer)); !ok || parsedOid != oid || size != 1 {
		t.Fatalf("%q read as %s %d %t", pointer, parsedOid, size, ok)
	}
	for _, bad := range []string{
		strings.TrimSuffix(pointer, "\n"),
		strings.Replace(pointer, gitLfsPointerVersionLine, "version 1", 1),
		strings.Replace(pointer, "sha256:", "sha1:", 1),
		strings.Replace(pointer, "size 1", "size 01", 1),
		gitLfsPointerVersionLine + "\nsize 1\noid sha256:" + oid + "\n",
	} {
		if _, _, ok := ParseGitLfsPointer([]byte(bad)); ok {
			t.Fatalf("%q read as a pointer", bad)
		}
	}
}
