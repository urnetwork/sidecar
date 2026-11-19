package fault

// FI-5's oracle (fi5.go) on T2, through fi1_test.go's hand world: pushes built with the format's own builders and
// committed through evsservice.HeadStore, repo/ moved as §11.12's routes and shred move it, and the access log's
// RepoDelete and RepoRestore named as each becomes current. Each mutant changes the store the way the bug it stands
// for would, and its run must fail at that step on FI-5, its healthy prefix passing every check before it; each twin
// passes. FS-6's schedules name FI(5) too (fs6.go), so its phases read clean on the evs world under the hooks.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// FI-5 alone after every step: a site's loss below reads as missing heads to FI-1, which is FI-1's to judge.
func fi5Run(t *testing.T, world *fiHandWorld, id string, steps []*Step) *Result {
	t.Helper()
	return Run(t.Context(), &Schedule{Id: id, Steps: steps, Check: []Invariant{FI(5)}}, world.net)
}

// Names the access log's next position for the hand world: its fixture with deletion as the repo's newest
// RepoDelete, nil for none.
func (self *fiHandWorld) nameDeletion(deletion *protocol.AclRepoDeletionRow) {
	rows := sidecartest.FakeGkmAuthRows(&protocol.AclRepo{
		RepoId: self.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL,
		Admins:   []*protocol.AclRepoAdminRow{{SidecarId: self.admin.SidecarId.Bytes()}},
		Deletion: deletion,
	})
	rows.Sidecars = self.fixture.Rows.Sidecars
	rows.Members = self.fixture.Rows.Members
	self.fixture.Rows = rows
	self.view = self.log.Append(self.fixture)
	SetAuthorizationView(self.net, self.networkId, self.view)
}

// A step action: names the next position of the access log (nameDeletion).
func (self *fiHandWorld) logDeletion(deletion *protocol.AclRepoDeletionRow) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		self.nameDeletion(deletion)
		return nil
	}
}

// A step action: repo/ rewritten If-Match in state under deletionId, its state_ms the clock's now, as §11.12's routes
// and the shred write it.
func (self *fiHandWorld) moveRepo(state protocol.EvsRepoState, deletionId sidecar.Id) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		key := sidecar.EvsRepoObjectKey(self.repoId)
		info, err := self.cluster.Head(ctx, key)
		if err != nil {
			return err
		}
		object := &protocol.EvsRepoObject{
			RepoId: self.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, State: state,
			StateMs: net.Clock().Now().UnixMilli(), Format: sidecar.EvsRepoFormat1, NetworkId: self.networkId.Bytes(),
		}
		if deletionId != (sidecar.Id{}) {
			object.DeletionId = deletionId.Bytes()
		}
		repoBytes, err := proto.Marshal(object)
		if err != nil {
			return err
		}
		_, err = self.cluster.PutIfMatch(ctx, key, info.Etag, repoBytes, nil)
		return err
	}
}

// The bytes key holds on the hand world's cluster, read under an inspecting context; nil for none.
func (self *fiHandWorld) bytesOf(ctx context.Context, key string) ([]byte, error) {
	object, err := self.cluster.Get(sidecartest.InspectContext(ctx), key)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer object.Body.Close()
	body := new(bytes.Buffer)
	if _, err := body.ReadFrom(object.Body); err != nil {
		return nil, err
	}
	return body.Bytes(), nil
}

// Writes key with body whatever it holds: If-Match over an object there, If-None-Match otherwise.
func (self *fiHandWorld) overwrite(ctx context.Context, key string, body []byte) error {
	info, err := self.cluster.Head(ctx, key)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		_, err = self.cluster.PutIfNoneMatch(ctx, key, body, nil)
		return err
	}
	if err != nil {
		return err
	}
	_, err = self.cluster.PutIfMatch(ctx, key, info.Etag, body, nil)
	return err
}

// An ERASE of slotId's key on the erasure ref signed by the repo admin and committed, then the slot rewritten without
// the key, as hand world's erase does, returning the push for a re-seed to replay.
func (self *fiHandWorld) erasePush(ctx context.Context, slotId sidecar.Id, keyIndex uint16) (*fiHandPush, error) {
	push, err := self.build(sidecar.EvsErasureRefId(self.repoId), protocol.EvsRefKind_EVS_REF_ERASURE, uint32(protocol.EvsPushFlag_EVS_PUSH_ERASE), self.admin,
		sidecar.NewId(), nil, nil, nil, []*sidecar.EvsErasedKey{{SlotId: slotId, KeyIndex: keyIndex}})
	if err != nil {
		return nil, err
	}
	if err := self.writeRecord(ctx, push); err != nil {
		return nil, err
	}
	if err := self.commit(ctx, push); err != nil {
		return nil, err
	}
	key := evsOracleSlotKey(self.repoId, slotId.Bytes())
	slotBytes, err := self.bytesOf(ctx, key)
	if err != nil {
		return nil, err
	}
	rewritten, _, err := sidecar.EvsSlotWithoutKeys(slotBytes, []uint32{uint32(keyIndex)})
	if err != nil {
		return nil, err
	}
	return push, self.overwrite(ctx, key, rewritten)
}

// Every object of every cluster deleted: the site lost, as §19.10's site-loss rows begin.
func (self *fiHandWorld) loseSite(ctx context.Context, net *Net) error {
	blobs := net.Host().Blobs
	clusterIds := append([]string{}, blobs.MetadataClusterIds()...)
	segment, err := blobs.SegmentCluster()
	if err != nil {
		return err
	}
	clusterIds = append(clusterIds, segment.ClusterId())
	for _, clusterId := range clusterIds {
		cluster, err := blobs.Cluster(clusterId)
		if err != nil {
			return err
		}
		keys, err := fiKeys(ctx, cluster, "")
		if err != nil {
			return err
		}
		for _, info := range keys {
			if err := cluster.Delete(ctx, info.Key); err != nil && !errors.Is(err, sidecar.ErrBlobNotFound) {
				return err
			}
		}
	}
	return nil
}

// What a stale mirror re-seeds after a site's loss (§19.10's repos step): the repo placed afresh and active, its
// group's gen/1, then pushes replayed in order under their own statements, and last its slot copies as the mirror
// holds them.
func (self *fiHandWorld) reseed(ctx context.Context, generationBytes []byte, pushes []*fiHandPush, slots map[sidecar.Id][]byte) error {
	placeBytes, err := (&sidecar.EvsRepoPlace{ClusterId: self.cluster.ClusterId(), CreatorSidecarId: self.admin.SidecarId}).Marshal()
	if err != nil {
		return err
	}
	if _, err := self.cluster.PutIfNoneMatch(ctx, sidecar.EvsPlaceKey(self.repoId), placeBytes, nil); err != nil {
		return err
	}
	repoBytes, err := proto.Marshal(&protocol.EvsRepoObject{
		RepoId: self.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, State: protocol.EvsRepoState_EVS_REPO_ACTIVE,
		Format: sidecar.EvsRepoFormat1, NetworkId: self.networkId.Bytes(),
	})
	if err != nil {
		return err
	}
	if _, err := self.cluster.PutIfNoneMatch(ctx, sidecar.EvsRepoObjectKey(self.repoId), repoBytes, nil); err != nil {
		return err
	}
	if _, err := self.cluster.PutIfNoneMatch(ctx, sidecar.GkmGenerationPath(self.groupId, 1), generationBytes, nil); err != nil {
		return err
	}
	self.chains = map[sidecar.Id][][sha256.Size]byte{}
	for _, push := range pushes {
		if self.chains[push.refId] == nil {
			self.chains[push.refId] = [][sha256.Size]byte{sidecar.EvsChainStart(self.repoId, push.refId)}
		}
		if err := self.writeRecord(ctx, push); err != nil {
			return err
		}
		if err := self.commit(ctx, push); err != nil {
			return err
		}
	}
	for slotId, body := range slots {
		if err := self.overwrite(ctx, evsOracleSlotKey(self.repoId, slotId.Bytes()), body); err != nil {
			return err
		}
	}
	return nil
}

// A shred as §11.12's phases leave it, under deletionId: every object of the repo's families and its group's gkm
// objects deleted, then the tombstone written.
func (self *fiHandWorld) shredAll(ctx context.Context, net *Net) error {
	for _, prefix := range []string{evsOracleRepoPrefix("slot/", self.repoId), evsOracleRepoPrefix("head/", self.repoId), "gkm/" + sidecar.EvsKeyId(self.groupId) + "/"} {
		keys, err := fiKeys(ctx, self.cluster, prefix)
		if err != nil {
			return err
		}
		for _, info := range keys {
			if err := self.cluster.Delete(ctx, info.Key); err != nil {
				return err
			}
		}
	}
	return nil
}

// A shred's claim is final: repo/ written back to active after shredding, as a restore whose CAS took a shredding
// object would, fails at that write.
func TestFi5CatchesARestoreAfterAShreddingClaim(t *testing.T) {
	world := newFiHandWorld(t)
	deletionId := sidecar.NewId()
	world.nameDeletion(&protocol.AclRepoDeletionRow{DeletionId: deletionId.Bytes(), Now: true, DeletedAt: 2})
	main := sidecar.NewId()
	steps := []*Step{
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			_, _, err := world.slotPush(ctx, main, false)
			return err
		}},
		{Actor: "writerB", Action: world.moveRepo(protocol.EvsRepoState_EVS_REPO_SHREDDING, deletionId)},
		{Actor: "writerA", Action: world.moveRepo(protocol.EvsRepoState_EVS_REPO_ACTIVE, sidecar.Id{})},
	}
	fiRequireViolation(t, fi5Run(t, world, "fi5-restore-after-claim", steps), 2, "FI-5", "a shred's claim is final")
}

// The twin: the claim followed by its shred to the tombstone reads clean at every step.
func TestFi5TakesAShredToItsTombstone(t *testing.T) {
	world := newFiHandWorld(t)
	deletionId := sidecar.NewId()
	world.nameDeletion(&protocol.AclRepoDeletionRow{DeletionId: deletionId.Bytes(), Now: true, DeletedAt: 2})
	main := sidecar.NewId()
	steps := []*Step{
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			_, _, err := world.slotPush(ctx, main, false)
			return err
		}},
		{Actor: "writerB", Action: world.moveRepo(protocol.EvsRepoState_EVS_REPO_SHREDDING, deletionId)},
		{Advance: 20 * time.Second},
		{Actor: "shred", Action: world.shredAll},
		{Advance: 10 * time.Minute},
		{Actor: "shred", Action: world.moveRepo(protocol.EvsRepoState_EVS_REPO_SHREDDED, deletionId)},
	}
	fiRequirePass(t, fi5Run(t, world, "fi5-shred-to-tombstone", steps))
}

// A shredded repo's slot written back after its tombstone, as a straggler or a stale re-seed's upload would, fails.
func TestFi5CatchesAShreddedObjectWrittenBack(t *testing.T) {
	world := newFiHandWorld(t)
	deletionId := sidecar.NewId()
	world.nameDeletion(&protocol.AclRepoDeletionRow{DeletionId: deletionId.Bytes(), Now: true, DeletedAt: 2})
	main := sidecar.NewId()
	var slotId sidecar.Id
	var slotBytes []byte
	steps := []*Step{
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			var err error
			slotId, _, err = world.slotPush(ctx, main, false)
			if err != nil {
				return err
			}
			slotBytes, err = world.bytesOf(ctx, evsOracleSlotKey(world.repoId, slotId.Bytes()))
			return err
		}},
		{Actor: "writerB", Action: world.moveRepo(protocol.EvsRepoState_EVS_REPO_SHREDDING, deletionId)},
		{Actor: "shred", Action: world.shredAll},
		{Actor: "shred", Action: world.moveRepo(protocol.EvsRepoState_EVS_REPO_SHREDDED, deletionId)},
		{Actor: "evs1", Action: func(ctx context.Context, net *Net) error {
			return world.overwrite(ctx, evsOracleSlotKey(world.repoId, slotId.Bytes()), slotBytes)
		}},
	}
	fiRequireViolation(t, fi5Run(t, world, "fi5-shredded-written-back", steps), 4, "FI-5", "is written after its shred's tombstone", "a shredded object never returns")
}

// A slot the shred deleted while the repo showed shredding, written back before the tombstone, fails: what the
// shred deleted stays deleted.
func TestFi5CatchesAShredDeleteUndoneBeforeTheTombstone(t *testing.T) {
	world := newFiHandWorld(t)
	deletionId := sidecar.NewId()
	world.nameDeletion(&protocol.AclRepoDeletionRow{DeletionId: deletionId.Bytes(), Now: true, DeletedAt: 2})
	main := sidecar.NewId()
	var slotId sidecar.Id
	var slotBytes []byte
	steps := []*Step{
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			var err error
			slotId, _, err = world.slotPush(ctx, main, false)
			if err != nil {
				return err
			}
			slotBytes, err = world.bytesOf(ctx, evsOracleSlotKey(world.repoId, slotId.Bytes()))
			return err
		}},
		{Actor: "writerB", Action: world.moveRepo(protocol.EvsRepoState_EVS_REPO_SHREDDING, deletionId)},
		{Actor: "shred", Action: world.shredAll},
		{Actor: "evs1", Action: func(ctx context.Context, net *Net) error {
			return world.overwrite(ctx, evsOracleSlotKey(world.repoId, slotId.Bytes()), slotBytes)
		}},
	}
	fiRequireViolation(t, fi5Run(t, world, "fi5-shred-delete-undone", steps), 3, "FI-5", "was deleted while the repo showed shredding", "is stored again")
}

// A shredded repo placed again by a stale re-seed after a site's loss fails, though the site took its tombstone
// with it: FI-5 keeps the shred across the loss.
func TestFi5CatchesAShreddedRepoReseededAfterASiteLoss(t *testing.T) {
	world := newFiHandWorld(t)
	deletionId := sidecar.NewId()
	world.nameDeletion(&protocol.AclRepoDeletionRow{DeletionId: deletionId.Bytes(), Now: true, DeletedAt: 2})
	main := sidecar.NewId()
	var push *fiHandPush
	var slotId sidecar.Id
	var slotBytes, generationBytes []byte
	steps := []*Step{
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			var err error
			slotId, push, err = world.slotPush(ctx, main, false)
			if err != nil {
				return err
			}
			if slotBytes, err = world.bytesOf(ctx, evsOracleSlotKey(world.repoId, slotId.Bytes())); err != nil {
				return err
			}
			generationBytes, err = world.bytesOf(ctx, sidecar.GkmGenerationPath(world.groupId, 1))
			return err
		}},
		{Actor: "writerB", Action: world.moveRepo(protocol.EvsRepoState_EVS_REPO_SHREDDING, deletionId)},
		{Actor: "shred", Action: world.shredAll},
		{Actor: "shred", Action: world.moveRepo(protocol.EvsRepoState_EVS_REPO_SHREDDED, deletionId)},
		{Actor: "site", Action: world.loseSite},
		{Actor: "mirror", Action: func(ctx context.Context, net *Net) error {
			return world.reseed(ctx, generationBytes, []*fiHandPush{push}, map[sidecar.Id][]byte{slotId: slotBytes})
		}},
	}
	result := fi5Run(t, world, "fi5-shredded-reseeded", steps)
	fiRequireViolation(t, result, 5, "FI-5", "across a site's loss and its re-seed", "the shredded tombstone stays")
	fiRequireViolation(t, result, 5, "FI-5", "placed again after a site's loss", "a shredded object never returns")
}

// A slot key an authorized ERASE destroyed, put back in its slot, fails: the tombstone outlives the step.
func TestFi5CatchesAResurrectedErasedKey(t *testing.T) {
	world := newFiHandWorld(t)
	main := sidecar.NewId()
	var slotId sidecar.Id
	var slotBytes []byte
	steps := []*Step{
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			var err error
			slotId, _, err = world.slotPush(ctx, main, false)
			if err != nil {
				return err
			}
			slotBytes, err = world.bytesOf(ctx, evsOracleSlotKey(world.repoId, slotId.Bytes()))
			return err
		}},
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			_, err := world.erasePush(ctx, slotId, 0)
			return err
		}},
		// a later push of the repo, so the resurrection is not the step after the erasure
		{Actor: "writerB", Action: func(ctx context.Context, net *Net) error {
			_, _, err := world.slotPush(ctx, main, false)
			return err
		}},
		{Actor: "evs1", Action: func(ctx context.Context, net *Net) error {
			return world.overwrite(ctx, evsOracleSlotKey(world.repoId, slotId.Bytes()), slotBytes)
		}},
	}
	fiRequireViolation(t, fi5Run(t, world, "fi5-resurrected-erased", steps), 3, "FI-5", "which an ERASE in its history destroyed, is in its slot again")
}

// An ERASE committed whose slot rewrite has not happened yet is not a return: the key was never found gone.
func TestFi5TakesAnEraseWhoseRewriteIsPending(t *testing.T) {
	world := newFiHandWorld(t)
	main := sidecar.NewId()
	var slotId sidecar.Id
	steps := []*Step{
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			var err error
			slotId, _, err = world.slotPush(ctx, main, false)
			return err
		}},
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			push, err := world.build(sidecar.EvsErasureRefId(world.repoId), protocol.EvsRefKind_EVS_REF_ERASURE, uint32(protocol.EvsPushFlag_EVS_PUSH_ERASE), world.admin,
				sidecar.NewId(), nil, nil, nil, []*sidecar.EvsErasedKey{{SlotId: slotId, KeyIndex: 0}})
			if err != nil {
				return err
			}
			if err := world.writeRecord(ctx, push); err != nil {
				return err
			}
			return world.commit(ctx, push)
		}},
		{Actor: "reconciler", Action: func(ctx context.Context, net *Net) error {
			key := evsOracleSlotKey(world.repoId, slotId.Bytes())
			slotBytes, err := world.bytesOf(ctx, key)
			if err != nil {
				return err
			}
			rewritten, _, err := sidecar.EvsSlotWithoutKeys(slotBytes, []uint32{0})
			if err != nil {
				return err
			}
			return world.overwrite(ctx, key, rewritten)
		}},
	}
	fiRequirePass(t, fi5Run(t, world, "fi5-erase-rewrite-pending", steps))
}

// The stale re-seed's run (§19.10's site loss, §11.12's residual): a committed slot of two keys, an ERASE of key 0,
// the site lost, and a stale mirror re-seeding the slot push and its copy of the slot from before the erasure. With
// replayErase the re-seed replays the ERASE too; with clean the mirror's slot copy leaves the erased key out, as a
// re-seed does when it holds the ERASE; report names the repo in a close report.
func fi5StaleReseedRun(t *testing.T, replayErase bool, clean bool, report bool) *Result {
	t.Helper()
	world := newFiHandWorld(t)
	main := sidecar.NewId()
	var slotId sidecar.Id
	var slotPush, erase *fiHandPush
	var staleSlotBytes, generationBytes []byte
	steps := []*Step{
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			var err error
			slotId, slotPush, err = world.slotPush(ctx, main, false)
			if err != nil {
				return err
			}
			if staleSlotBytes, err = world.bytesOf(ctx, evsOracleSlotKey(world.repoId, slotId.Bytes())); err != nil {
				return err
			}
			generationBytes, err = world.bytesOf(ctx, sidecar.GkmGenerationPath(world.groupId, 1))
			return err
		}},
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			var err error
			erase, err = world.erasePush(ctx, slotId, 0)
			return err
		}},
		{Actor: "site", Action: world.loseSite},
		{Actor: "mirror", Action: func(ctx context.Context, net *Net) error {
			if report {
				RecordCloseReport(net, &CloseReport{IncidentId: sidecar.NewId(), BelowPin: []*CloseReportBelowPin{
					{RepoId: world.repoId, RefId: sidecar.EvsErasureRefId(world.repoId), Version: 0},
				}})
			}
			pushes := []*fiHandPush{slotPush}
			if replayErase {
				pushes = append(pushes, erase)
			}
			slotBytes := staleSlotBytes
			if clean {
				rewritten, _, err := sidecar.EvsSlotWithoutKeys(staleSlotBytes, []uint32{0})
				if err != nil {
					return err
				}
				slotBytes = rewritten
			}
			return world.reseed(ctx, generationBytes, pushes, map[sidecar.Id][]byte{slotId: slotBytes})
		}},
	}
	return fi5Run(t, world, "fi5-stale-reseed", steps)
}

// A stale re-seed bringing back an erased key, with the ERASE lost with the site and no close report naming the
// repo, fails: the residual is a named exception.
func TestFi5CatchesAStaleReseedOfAnErasedKey(t *testing.T) {
	fiRequireViolation(t, fi5StaleReseedRun(t, false, false, false), 3, "FI-5", "with no ERASE in its history, and no close report names the repo")
}

// The same return, named by the incident's close report as §11.12's residual, passes.
func TestFi5TakesAStaleReseedTheCloseReportNames(t *testing.T) {
	fiRequirePass(t, fi5StaleReseedRun(t, false, false, true))
}

// A re-seed whose history holds the ERASE and still serves the erased key fails, close report or not: evs applies
// every ERASE it holds before it serves a slot.
func TestFi5CatchesAReseedServingAKeyItsHistoryErases(t *testing.T) {
	fiRequireViolation(t, fi5StaleReseedRun(t, true, false, true), 3, "FI-5", "which an ERASE in its history destroyed, is in its slot again")
}

// A re-seed whose slot copy leaves the erased key out reads clean with no close report.
func TestFi5TakesAReseedWithoutTheErasedKey(t *testing.T) {
	fiRequirePass(t, fi5StaleReseedRun(t, true, true, false))
}

// The lifecycle's run: a committed slot, the repo deleted under a restorable RepoDelete at the clock's time, then
// tail's steps. tail reads the slot's id through its pointer once the first step has run.
func fi5LifecycleRun(t *testing.T, world *fiHandWorld, deletionId sidecar.Id, tail func(slotId *sidecar.Id, deletedTimeMs int64) []*Step) *Result {
	t.Helper()
	main := sidecar.NewId()
	slotId := &sidecar.Id{}
	deletedTimeMs := world.net.Clock().Now().UnixMilli()
	steps := []*Step{
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			var err error
			*slotId, _, err = world.slotPush(ctx, main, false)
			return err
		}},
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			world.nameDeletion(&protocol.AclRepoDeletionRow{DeletionId: deletionId.Bytes(), DeletedAt: 2, DeletedTimeMs: deletedTimeMs})
			return world.moveRepo(protocol.EvsRepoState_EVS_REPO_DELETED, deletionId)(ctx, net)
		}},
	}
	return fi5Run(t, world, "fi5-lifecycle", append(steps, tail(slotId, deletedTimeMs)...))
}

// A restore the access log takes, its closure whole, reads clean.
func TestFi5TakesARestoreTheLogTakes(t *testing.T) {
	world := newFiHandWorld(t)
	deletionId := sidecar.NewId()
	result := fi5LifecycleRun(t, world, deletionId, func(slotId *sidecar.Id, deletedTimeMs int64) []*Step {
		return []*Step{
			{Advance: 24 * time.Hour},
			{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
				world.nameDeletion(&protocol.AclRepoDeletionRow{DeletionId: deletionId.Bytes(), DeletedAt: 2, RestoredAt: 3, DeletedTimeMs: deletedTimeMs})
				return world.moveRepo(protocol.EvsRepoState_EVS_REPO_ACTIVE, sidecar.Id{})(ctx, net)
			}},
		}
	})
	fiRequirePass(t, result)
}

// A restore with no RepoRestore in the access log fails: log first.
func TestFi5CatchesARestoreTheLogNeverTook(t *testing.T) {
	world := newFiHandWorld(t)
	deletionId := sidecar.NewId()
	result := fi5LifecycleRun(t, world, deletionId, func(slotId *sidecar.Id, deletedTimeMs int64) []*Step {
		return []*Step{
			{Actor: "writerA", Action: world.moveRepo(protocol.EvsRepoState_EVS_REPO_ACTIVE, sidecar.Id{})},
		}
	})
	fiRequireViolation(t, result, 2, "FI-5", "which the access log never restores")
}

// A restored repo whose slot lost a key while it was deleted, as a shred step run against a deleted repo would
// leave it, fails at the restore.
func TestFi5CatchesARestoredRepoMissingASlotKey(t *testing.T) {
	world := newFiHandWorld(t)
	deletionId := sidecar.NewId()
	result := fi5LifecycleRun(t, world, deletionId, func(slotId *sidecar.Id, deletedTimeMs int64) []*Step {
		return []*Step{
			{Actor: "shred", Action: func(ctx context.Context, net *Net) error {
				key := evsOracleSlotKey(world.repoId, slotId.Bytes())
				slotBytes, err := world.bytesOf(ctx, key)
				if err != nil {
					return err
				}
				rewritten, _, err := sidecar.EvsSlotWithoutKeys(slotBytes, []uint32{1})
				if err != nil {
					return err
				}
				return world.overwrite(ctx, key, rewritten)
			}},
			{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
				world.nameDeletion(&protocol.AclRepoDeletionRow{DeletionId: deletionId.Bytes(), DeletedAt: 2, RestoredAt: 3, DeletedTimeMs: deletedTimeMs})
				return world.moveRepo(protocol.EvsRepoState_EVS_REPO_ACTIVE, sidecar.Id{})(ctx, net)
			}},
		}
	})
	fiRequireViolation(t, result, 3, "FI-5", "without key 1", "a restored repo holds its whole key closure")
}

// A restored repo whose group lost its gen/ object while deleted fails at the restore.
func TestFi5CatchesARestoredRepoMissingItsGeneration(t *testing.T) {
	world := newFiHandWorld(t)
	deletionId := sidecar.NewId()
	result := fi5LifecycleRun(t, world, deletionId, func(slotId *sidecar.Id, deletedTimeMs int64) []*Step {
		return []*Step{
			{Actor: "shred", Action: func(ctx context.Context, net *Net) error {
				return world.cluster.Delete(ctx, sidecar.GkmGenerationPath(world.groupId, 1))
			}},
			{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
				world.nameDeletion(&protocol.AclRepoDeletionRow{DeletionId: deletionId.Bytes(), DeletedAt: 2, RestoredAt: 3, DeletedTimeMs: deletedTimeMs})
				return world.moveRepo(protocol.EvsRepoState_EVS_REPO_ACTIVE, sidecar.Id{})(ctx, net)
			}},
		}
	})
	fiRequireViolation(t, result, 3, "FI-5", sidecar.GkmGenerationPath(world.groupId, 1), "a restored repo holds its whole key closure")
}

// The start on time, 7 d 10 min after the entry, with the log holding no RepoRestore, reads clean.
func TestFi5TakesAStartOnTime(t *testing.T) {
	world := newFiHandWorld(t)
	deletionId := sidecar.NewId()
	result := fi5LifecycleRun(t, world, deletionId, func(slotId *sidecar.Id, deletedTimeMs int64) []*Step {
		return []*Step{
			{Advance: 7*24*time.Hour + 10*time.Minute},
			{Actor: "shred", Action: world.moveRepo(protocol.EvsRepoState_EVS_REPO_SHREDDING, deletionId)},
		}
	})
	fiRequirePass(t, result)
}

// A start that claims a deletion the access log restores fails: restore and start both won as the log says.
func TestFi5CatchesAStartOfADeletionTheLogRestores(t *testing.T) {
	world := newFiHandWorld(t)
	deletionId := sidecar.NewId()
	result := fi5LifecycleRun(t, world, deletionId, func(slotId *sidecar.Id, deletedTimeMs int64) []*Step {
		return []*Step{
			{Actor: "writerA", Action: world.logDeletion(&protocol.AclRepoDeletionRow{DeletionId: deletionId.Bytes(), DeletedAt: 2, RestoredAt: 3, DeletedTimeMs: deletedTimeMs})},
			{Advance: 7*24*time.Hour + 10*time.Minute},
			{Actor: "shred", Action: world.moveRepo(protocol.EvsRepoState_EVS_REPO_SHREDDING, deletionId)},
		}
	})
	fiRequireViolation(t, result, 4, "FI-5", "which the access log restores: exactly one of restore and start wins")
}

// A start a day after the entry, before §11.12's 7 d 10 min, fails: a restore could still win.
func TestFi5CatchesAStartBeforeItsTime(t *testing.T) {
	world := newFiHandWorld(t)
	deletionId := sidecar.NewId()
	result := fi5LifecycleRun(t, world, deletionId, func(slotId *sidecar.Id, deletedTimeMs int64) []*Step {
		return []*Step{
			{Advance: 24 * time.Hour},
			{Actor: "shred", Action: world.moveRepo(protocol.EvsRepoState_EVS_REPO_SHREDDING, deletionId)},
		}
	})
	fiRequireViolation(t, result, 3, "FI-5", "the shred's start claimed deletion", "before §11.12's")
}

// A drop table alone fails nothing now that FI-5's dropped-object clause reads FI-27's bound (TEST-M10-01): a format-1
// repo, which runs no drop, holds none to it, and fi_format2_test.go's drop world holds a returned dropped object.
func TestFi5ReadsADropTableThroughFi27(t *testing.T) {
	world := newFiHandWorld(t)
	main := sidecar.NewId()
	steps := []*Step{
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			_, _, err := world.slotPush(ctx, main, false)
			return err
		}},
		{Actor: "drops", Action: func(ctx context.Context, net *Net) error {
			_, err := world.cluster.PutIfNoneMatch(ctx, evsOracleRepoPrefix("drops/", world.repoId)+"_", []byte("a drop table"), nil)
			return err
		}},
	}
	result := fi5Run(t, world, "fi5-drop-table", steps)
	if result.Err != nil {
		t.Fatalf("a drop table alone failed FI-5: %v", result.Err)
	}
}
