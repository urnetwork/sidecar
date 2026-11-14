package fault

// FI-4's oracle (fi4.go) on T2: a ladder written by hand in fi1_test.go's hand world, its gen/ objects signed by the
// repo's admin, whom the state admits, so a step can write what gkm would refuse; and gkm's own world (gkmschedule),
// its clients rotating and reporting what they hold. Each mutant is caught at its step; the healthy runs read clean.

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/gkmschedule"
)

type fi4World struct {
	*fiHandWorld
	// each generation's key, from gen/1
	keys map[uint64]*sidecar.EvsRepoKey
}

// The hand world, gen/1 signed again by the repo's admin in place of the fixture's stranger.
func newFi4World(t *testing.T) *fi4World {
	hand := newFiHandWorld(t)
	world := &fi4World{fiHandWorld: hand, keys: map[uint64]*sidecar.EvsRepoKey{1: hand.repoKey}}
	key := sidecar.GkmGenerationPath(hand.groupId, 1)
	object, err := hand.cluster.Get(hand.ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(object.Body)
	object.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	generation, err := DecodeStoreGeneration(body)
	if err != nil {
		t.Fatal(err)
	}
	signedBytes, err := world.sign(generation.Rotate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hand.cluster.PutIfMatch(hand.ctx, key, object.Etag, signedBytes, nil); err != nil {
		t.Fatal(err)
	}
	return world
}

// rotate's gen/ bytes, signed by the repo's admin.
func (self *fi4World) sign(rotate *protocol.GenRotate) ([]byte, error) {
	signed, err := sidecar.SignGenRotate(rotate, self.admin.Sign)
	if err != nil {
		return nil, err
	}
	return proto.Marshal(signed)
}

// A step's action writing gen/<g> for the next generation, as a rotator's claim does.
func (self *fi4World) rotate(ctx context.Context, net *Net) error {
	newest := uint64(len(self.keys))
	holders := sha256.Sum256([]byte(fmt.Sprintf("fi4 holders %d", newest+1)))
	key, rotate, err := self.keys[newest].NextGeneration(&sidecar.GkmGenerationArgs{
		Cause: sidecar.GkmCauseRequest, Auth: self.view.Pin(), Time: net.Clock().Now(), HoldersSha256: holders[:],
	})
	if err != nil {
		return err
	}
	signedBytes, err := self.sign(rotate)
	if err != nil {
		return err
	}
	if _, err := self.cluster.PutIfNoneMatch(ctx, sidecar.GkmGenerationPath(self.groupId, newest+1), signedBytes, nil); err != nil {
		return err
	}
	self.keys[newest+1] = key
	return nil
}

// A step's action recording that holder holds generation, under commitment, or the key's own when nil.
func (self *fi4World) hold(holder string, generation uint64, commitment []byte) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		if commitment == nil {
			commitment = self.keys[generation].Commitment()
		}
		LedgerOf(net).RecordKeyHolding(&KeyHolding{Holder: holder, GroupId: self.groupId, Generation: generation, Commitment: commitment})
		return nil
	}
}

// A step's action writing epoch's object with a header naming generation, with or without a GenWrap.
func (self *fi4World) epoch(epoch uint64, generation uint64, genWrap bool) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		object := &protocol.GkmEpochObject{Header: &protocol.GkmCommitHeader{Generation: generation}}
		if genWrap {
			object.GenWrap = []byte("a GenWrap")
		}
		objectBytes, err := proto.Marshal(object)
		if err != nil {
			return err
		}
		_, err = self.cluster.PutIfNoneMatch(ctx, gkmservice.GkmEpochKey(self.groupId, epoch), objectBytes, nil)
		return err
	}
}

func fi4Checks() []Invariant {
	return []Invariant{FI(4)}
}

// Three generations, two holders converging and rising, a recovery self-join's generation-0 header among the epochs:
// clean at every step.
func TestFi4ReadsALadderClean(t *testing.T) {
	world := newFi4World(t)
	steps := []*Step{
		{Actor: "a", Action: world.epoch(0, 1, true)},
		{Actor: "a", Action: world.hold("a", 1, nil)},
		{Actor: "a", Action: world.rotate},
		{Actor: "a", Action: world.epoch(1, 2, true)},
		{Actor: "b", Action: world.hold("b", 2, nil)},
		{Actor: "recovery", Action: world.epoch(2, 0, false)},
		{Actor: "a", Action: world.rotate},
		{Actor: "a", Action: world.epoch(3, 3, true)},
		{Actor: "a", Action: world.hold("a", 3, nil)},
		{Actor: "b", Action: world.hold("b", 3, nil)},
	}
	fiRequirePass(t, Run(t.Context(), &Schedule{Id: "fi4-ladder", Steps: steps, Check: fi4Checks()}, world.net))
}

// gen/2 written again naming another parent: caught as two parents for one generation.
func TestFi4CatchesTwoParentsForOneGeneration(t *testing.T) {
	world := newFi4World(t)
	steps := []*Step{
		{Actor: "a", Action: world.rotate},
		{Actor: "d", Action: func(ctx context.Context, net *Net) error {
			key := sidecar.GkmGenerationPath(world.groupId, 2)
			object, err := world.cluster.Get(ctx, key)
			if err != nil {
				return err
			}
			body, err := io.ReadAll(object.Body)
			object.Body.Close()
			if err != nil {
				return err
			}
			generation, err := DecodeStoreGeneration(body)
			if err != nil {
				return err
			}
			other := sha256.Sum256([]byte("another parent"))
			generation.Rotate.ParentCommitment = other[:]
			signedBytes, err := world.sign(generation.Rotate)
			if err != nil {
				return err
			}
			_, err = world.cluster.PutIfMatch(ctx, key, object.Etag, signedBytes, nil)
			return err
		}},
	}
	result := Run(t.Context(), &Schedule{Id: "fi4-two-parents", Steps: steps, Check: fi4Checks()}, world.net)
	fiRequireViolation(t, result, 1, "FI-4", "gen/2 changed since an earlier check read it")
	fiRequireViolation(t, result, 1, "FI-4", "gen/2 names another parent than gen/1's commitment: two parents for one generation")
}

// A holder reporting generation 1 after 2: caught as a reader regressing.
func TestFi4CatchesAReaderRegressing(t *testing.T) {
	world := newFi4World(t)
	steps := []*Step{
		{Actor: "a", Action: world.rotate},
		{Actor: "b", Action: world.hold("b", 2, nil)},
		{Actor: "b", Action: world.hold("b", 1, nil)},
	}
	result := Run(t.Context(), &Schedule{Id: "fi4-regress", Steps: steps, Check: fi4Checks()}, world.net)
	fiRequireViolation(t, result, 2, "FI-4", "b holds generation 1 of group", "after 2: a reader regressed")
}

// A holder holding generation 2 under a commitment gen/2 does not hold: caught as not converging.
func TestFi4CatchesAHolderOffTheLadder(t *testing.T) {
	world := newFi4World(t)
	forked := sha256.Sum256([]byte("a forked commitment"))
	steps := []*Step{
		{Actor: "a", Action: world.rotate},
		{Actor: "b", Action: world.hold("b", 2, forked[:])},
	}
	result := Run(t.Context(), &Schedule{Id: "fi4-off-ladder", Steps: steps, Check: fi4Checks()}, world.net)
	fiRequireViolation(t, result, 1, "FI-4", "under another commitment than gen/2's: it did not converge on the one ladder")
}

// gen/2 signed by a key no state admits: caught.
func TestFi4CatchesAnUnauthenticatedGeneration(t *testing.T) {
	world := newFi4World(t)
	steps := []*Step{
		{Actor: "a", Action: func(ctx context.Context, net *Net) error {
			holders := sha256.Sum256([]byte("fi4 forged holders"))
			_, rotate, err := world.keys[1].NextGeneration(&sidecar.GkmGenerationArgs{
				Cause: sidecar.GkmCauseRequest, Auth: world.view.Pin(), Time: net.Clock().Now(), HoldersSha256: holders[:],
			})
			if err != nil {
				return err
			}
			generationBytes, err := StoreViewFixtureGeneration(rotate)
			if err != nil {
				return err
			}
			_, err = world.cluster.PutIfNoneMatch(ctx, sidecar.GkmGenerationPath(world.groupId, 2), generationBytes, nil)
			return err
		}},
	}
	result := Run(t.Context(), &Schedule{Id: "fi4-unauthenticated", Steps: steps, Check: fi4Checks()}, world.net)
	fiRequireViolation(t, result, 0, "FI-4", "gen/2 is signed by", "whom no named state admits")
}

// gen/2 deleted while its repo stands: caught as a generation that regressed.
func TestFi4CatchesAGenerationDeleted(t *testing.T) {
	world := newFi4World(t)
	steps := []*Step{
		{Actor: "a", Action: world.rotate},
		{Actor: "gc", Action: func(ctx context.Context, net *Net) error {
			return world.cluster.Delete(ctx, sidecar.GkmGenerationPath(world.groupId, 2))
		}},
	}
	result := Run(t.Context(), &Schedule{Id: "fi4-deleted", Steps: steps, Check: fi4Checks()}, world.net)
	fiRequireViolation(t, result, 1, "FI-4", "gen/2, which an earlier check read, is gone: a generation regressed")
}

// An epoch whose header names generation 1 after one named 2, with a GenWrap, so no recovery self-join: caught.
func TestFi4CatchesAHeaderRegressing(t *testing.T) {
	world := newFi4World(t)
	steps := []*Step{
		{Actor: "a", Action: world.rotate},
		{Actor: "a", Action: world.epoch(1, 2, true)},
		{Actor: "a", Action: world.epoch(2, 1, true)},
	}
	result := Run(t.Context(), &Schedule{Id: "fi4-header", Steps: steps, Check: fi4Checks()}, world.net)
	fiRequireViolation(t, result, 2, "FI-4", "names generation 1 below the 2 an earlier epoch named: a header regressed")
}

// gkm's own world: a leaf's rotation and its reader converging on gen/2, each reporting what its client holds, with
// the world's authorization state named: clean at every step.
func TestFi4ReadsAGkmWorldClean(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	run := newFsKeysRun(net)
	var world *fi4GkmWorld
	steps := []*Step{
		run.step("setup", func(ctx context.Context) {
			world = newFi4GkmWorld(run, net)
		}),
		run.step("a", func(ctx context.Context) {
			world.inner.Again("a's rotation", func() error {
				_, err := world.a.Client.RotateRepo(ctx, world.inner.RepoId)
				return err
			})
			world.report(ctx, "a", world.a)
		}),
		run.step("b", func(ctx context.Context) {
			world.inner.Again("b's sync", func() error { return world.b.Client.SyncRepo(ctx, world.inner.RepoId) })
			world.report(ctx, "b", world.b)
		}),
		run.cleanup(),
	}
	fiRequirePass(t, Run(t.Context(), &Schedule{Id: "fi4-gkm-world", Steps: steps, Check: fi4Checks()}, net))
	holdings := LedgerOf(net).KeyHoldings()
	if len(holdings) != 2 || holdings[0].Generation != 2 || holdings[1].Generation != 2 {
		t.Fatalf("the ledger holds %d holdings, not a's and b's of generation 2: the rotation proves nothing", len(holdings))
	}
}

// gkm's world of one repo with two leaves, a and b, created by a with b added, the world's state named for FI-4.
type fi4GkmWorld struct {
	inner *gkmschedule.FsKeysWorld
	net   *Net
	a     *gkmschedule.FsKeysDevice
	b     *gkmschedule.FsKeysDevice
}

func newFi4GkmWorld(run *fsKeysRun, net *Net) *fi4GkmWorld {
	inner := run.world(protocol.RepoKind_REPO_KIND_GENERAL)
	world := &fi4GkmWorld{inner: inner, net: net}
	world.a = inner.AddMember("a", false)
	world.b = inner.AddMember("b", false)
	inner.Grant(true, world.a, world.b)
	inner.Admin(world.a)
	inner.Advance()
	inner.Publish()
	inner.Create(world.a)
	inner.AddPending(world.a)
	SetAuthorizationView(net, sidecar.Id(inner.NetworkId), inner.Log.Tip())
	return world
}

// Records what device's client holds as the repo's current generation, as its holder reports it.
func (self *fi4GkmWorld) report(ctx context.Context, holder string, device *gkmschedule.FsKeysDevice) {
	key, err := device.Client.CurrentRepoKey(ctx, self.inner.RepoId)
	if err != nil {
		self.inner.Fail("%s's current key: %v", holder, err)
	}
	LedgerOf(self.net).RecordKeyHolding(&KeyHolding{Holder: holder, GroupId: self.inner.GroupId, Generation: key.Generation(), Commitment: key.Commitment()})
}
