package sidecartest

// FS-106's page Worker case, the MLS legs, on the real subset (KEYS-M4-01): a page Worker is a read_only leaf, so
// everything it sends is a path-only commit or an external one. Its leaf joins by a Welcome under its last-resort
// KeyPackage, which the join reports; it commits a path at once; it loses epochs and comes back from one GroupInfo by
// an external commit that removes its old leaf, found by the GroupInfo's roster; a third leaf resyncs from the
// GroupInfo the Worker's own path-only commit carries; members adopt each; and a shred drops its state while the
// epoch it reached still holds back any join at or below it (I-16).
//
// The longest step is logged as this leg measures it. The 50 ms bound is the wasm leg's, where the flows yield
// between such steps (gkm_yield.go): a single MLS operation is one step, and its time on wasm at each group size is
// that leg's run of this test and of the groups harness. The whole schedule on gkm, with r scopes, acks, the
// refused group-info write and epoch retention, is FS-106's own (KEYS-M2-29), and the root's gkm_stale_test.go runs
// the Worker's upkeep and FS-97's leaf legs through the client on a fake of gkm's routes.

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// One step of the Worker's case, timed.
type pageWorkerSteps struct {
	t       *testing.T
	longest time.Duration
	name    string
}

func (self *pageWorkerSteps) run(name string, step func() error) {
	self.t.Helper()
	start := time.Now()
	if err := step(); err != nil {
		self.t.Fatalf("%s: %v", name, err)
	}
	if elapsed := time.Since(start); self.longest < elapsed {
		self.longest, self.name = elapsed, name
	}
}

// The members' groups agree on one epoch.
func pageWorkerAgree(t *testing.T, label string, members ...*groupsBenchSidecar) {
	t.Helper()
	for _, member := range members[1:] {
		if member.group.Epoch() != members[0].group.Epoch() || !bytes.Equal(member.group.EpochAuthenticator(), members[0].group.EpochAuthenticator()) {
			t.Fatalf("%s: the members hold epochs %d and %d", label, members[0].group.Epoch(), member.group.Epoch())
		}
	}
}

// An external commit by sidecar from groupInfo, removing its own old leaf as the GroupInfo's roster shows it.
func pageWorkerResync(joiner *groupsBenchSidecar, groupInfo []byte) (sidecar.MlsStagedCommit, error) {
	reader, ok := joiner.engine.(sidecar.MlsGroupInfoReader)
	if !ok {
		return nil, errors.New("the engine reads no GroupInfo")
	}
	_, _, roster, err := reader.GroupInfoRoster(groupInfo)
	if err != nil {
		return nil, err
	}
	args := &sidecar.MlsCommitArgs{Path: true, AuthenticatedData: []byte("resync")}
	for _, member := range roster {
		if member.SidecarId == joiner.signer.SidecarId {
			args.Removes = []uint32{member.LeafIndex}
		}
	}
	if len(args.Removes) != 1 {
		return nil, errors.New("the GroupInfo's roster does not show the joiner's old leaf")
	}
	return joiner.engine.JoinExternal(groupInfo, args)
}

func TestAPageWorkersLeafOnTheRealSubset(t *testing.T) {
	steps := &pageWorkerSteps{t: t}
	admissions := &groupsBenchAdmissions{sidecarIdKeys: map[sidecar.Id]ed25519.PublicKey{}}
	devices := []*groupsBenchSidecar{}
	for len(devices) < 10 {
		device, err := admissions.sidecar()
		if err != nil {
			t.Fatal(err)
		}
		devices = append(devices, device)
	}
	creator, worker, third := devices[0], devices[1], devices[2]
	groupId := sidecar.NewId()
	var err error
	creator.group, err = creator.engine.CreateGroup(groupId, &sidecar.MlsUrGroup{RepoId: sidecar.NewId(), Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	if err != nil {
		t.Fatal(err)
	}
	// the Worker's one-time KeyPackages are spent: it is added through its last-resort one
	adds := [][]byte{}
	for _, device := range devices[1:] {
		keyPackage, err := device.engine.CreateKeyPackage(device == worker)
		if err != nil {
			t.Fatal(err)
		}
		if keyPackage.LastResort != (device == worker) {
			t.Fatalf("a KeyPackage's last-resort flag")
		}
		adds = append(adds, keyPackage.Encoded)
	}
	staged, err := creator.group.Commit(&sidecar.MlsCommitArgs{Adds: adds, AuthenticatedData: []byte("add")})
	if err != nil {
		t.Fatal(err)
	}
	welcome := staged.Welcome()
	groupInfo, err := staged.GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	if creator.group, err = staged.Adopt(); err != nil {
		t.Fatal(err)
	}
	for _, device := range []*groupsBenchSidecar{worker, third} {
		steps.run("a Welcome join", func() error {
			pending, err := device.engine.JoinWelcome(welcome)
			if err != nil {
				return err
			}
			lastResort, ok := pending.(sidecar.MlsLastResortJoin)
			if !ok || lastResort.LastResort() != (device == worker) {
				return errors.New("the join does not say which KeyPackage opened its Welcome")
			}
			device.group, err = pending.Complete(groupInfo)
			return err
		})
	}
	members := []*groupsBenchSidecar{creator, worker, third}
	pageWorkerAgree(t, "after the joins", members...)

	// the path a last-resort join owes, which is all a read_only leaf ever commits
	var workerGroupInfo []byte
	steps.run("the Worker's path-only commit", func() error {
		staged, err := worker.group.Commit(&sidecar.MlsCommitArgs{Path: true, AuthenticatedData: []byte("path")})
		if err != nil {
			return err
		}
		if len(staged.Added()) != 0 || len(staged.Removed()) != 0 || staged.Committer().SidecarId != worker.signer.SidecarId {
			return errors.New("a path-only commit that changes the roster")
		}
		if workerGroupInfo, err = staged.GroupInfo(); err != nil {
			return err
		}
		message := staged.Message()
		if worker.group, err = staged.Adopt(); err != nil {
			return err
		}
		// the third leaf misses it
		return groupsBenchFollow([]*groupsBenchSidecar{creator}, worker, message)
	})
	pageWorkerAgree(t, "after the Worker's path", creator, worker)

	// a third leaf resyncs from the sealed GroupInfo the Worker's path-only commit carries
	steps.run("a resync from the Worker's GroupInfo", func() error {
		external, err := pageWorkerResync(third, workerGroupInfo)
		if err != nil {
			return err
		}
		message := external.Message()
		if third.group, err = external.Adopt(); err != nil {
			return err
		}
		return groupsBenchFollow([]*groupsBenchSidecar{creator, worker}, third, message)
	})
	pageWorkerAgree(t, "after the third leaf's resync", members...)
	if count := len(creator.group.Roster()); count != 10 {
		t.Fatalf("a resync left %d leaves", count)
	}

	// the Worker loses two epochs and comes back by an external commit
	for count := 0; count < 2; count += 1 {
		if _, err := groupsBenchPathCommit([]*groupsBenchSidecar{creator, third}, creator); err != nil {
			t.Fatal(err)
		}
	}
	lostAt := worker.group.Epoch()
	current, err := creator.group.GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	steps.run("the Worker's resync", func() error {
		external, err := pageWorkerResync(worker, current)
		if err != nil {
			return err
		}
		if len(external.Removed()) != 1 || external.Removed()[0].SidecarId != worker.signer.SidecarId {
			return errors.New("the resync does not remove the Worker's old leaf")
		}
		message := external.Message()
		if worker.group, err = external.Adopt(); err != nil {
			return err
		}
		return groupsBenchFollow([]*groupsBenchSidecar{creator, third}, worker, message)
	})
	pageWorkerAgree(t, "after the Worker's resync", members...)
	if worker.group.Epoch() != lostAt+3 || len(worker.group.Roster()) != 10 {
		t.Fatalf("the Worker's resync: epoch %d after %d, %d leaves", worker.group.Epoch(), lostAt, len(worker.group.Roster()))
	}

	// a shred drops the Worker's state of the group, and the epoch it reached still holds back a join below it
	forgetter, ok := worker.engine.(sidecar.MlsGroupForgetter)
	if !ok {
		t.Fatal("the engine drops no group's state")
	}
	if err := forgetter.ForgetGroup(groupId); err != nil {
		t.Fatal(err)
	}
	if _, err := worker.engine.LoadGroup(groupId); !errors.Is(err, sidecar.ErrMlsGroupUnknown) {
		t.Fatalf("a group's state after a shred: %v", err)
	}
	if err := forgetter.ForgetGroup(groupId); err != nil {
		t.Errorf("a second shred: %v", err)
	}
	if stale, err := pageWorkerResync(worker, workerGroupInfo); err == nil {
		if _, err := stale.Adopt(); err == nil {
			t.Errorf("a join to an epoch below the one reached, after a shred")
		}
	}
	if _, err := creator.engine.LoadGroup(groupId); err != nil {
		t.Errorf("another sidecar's state after the Worker's shred: %v", err)
	}
	t.Logf("the longest step on this leg: %s, %s; the wasm leg's bound between yields is 50 ms", steps.name, steps.longest)
}

// §18.10's threads row inside one MLS operation: a page Worker's engine calls its yield between the steps of the
// loops that grow with the group, each leaf of a tree it validates at a join and at a resync and each path secret it
// seals under blank parents, so no operation holds the Worker's one thread for the whole of a large group; an engine
// given no yield calls none.
func TestAPageWorkersEngineYieldsInsideAnMlsOperation(t *testing.T) {
	const leafCount = 32
	admissions := &groupsBenchAdmissions{sidecarIdKeys: map[sidecar.Id]ed25519.PublicKey{}}
	creator, err := admissions.sidecar()
	if err != nil {
		t.Fatal(err)
	}
	yieldCount := 0
	worker, err := admissions.sidecarWithYield(func() { yieldCount += 1 })
	if err != nil {
		t.Fatal(err)
	}
	creator.group, err = creator.engine.CreateGroup(sidecar.NewId(), &sidecar.MlsUrGroup{RepoId: sidecar.NewId(), Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	if err != nil {
		t.Fatal(err)
	}
	adds := [][]byte{}
	for index := 1; index < leafCount; index += 1 {
		joiner := worker
		if 1 < index {
			if joiner, err = admissions.sidecar(); err != nil {
				t.Fatal(err)
			}
		}
		keyPackage, err := joiner.engine.CreateKeyPackage(false)
		if err != nil {
			t.Fatal(err)
		}
		adds = append(adds, keyPackage.Encoded)
	}
	staged, err := creator.group.Commit(&sidecar.MlsCommitArgs{Adds: adds, AuthenticatedData: []byte("add")})
	if err != nil {
		t.Fatal(err)
	}
	groupInfo, err := staged.GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	welcome := staged.Welcome()
	if creator.group, err = staged.Adopt(); err != nil {
		t.Fatal(err)
	}
	if yieldCount != 0 {
		t.Fatalf("an engine given no yield called the Worker's %d times", yieldCount)
	}
	pending, err := worker.engine.JoinWelcome(welcome)
	if err != nil {
		t.Fatal(err)
	}
	if worker.group, err = pending.Complete(groupInfo); err != nil {
		t.Fatal(err)
	}
	if yieldCount < leafCount {
		t.Errorf("a join that validates %d leaves yielded %d times", leafCount, yieldCount)
	}
	// a path under blank parents seals to every other leaf
	yieldCount = 0
	if _, err := groupsBenchPathCommit([]*groupsBenchSidecar{creator, worker}, worker); err != nil {
		t.Fatal(err)
	}
	if yieldCount < leafCount-1 {
		t.Errorf("a path sealed to %d leaves yielded %d times", leafCount-1, yieldCount)
	}
	// a resync validates the tree again
	current, err := creator.group.GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	yieldCount = 0
	external, err := pageWorkerResync(worker, current)
	if err != nil {
		t.Fatal(err)
	}
	external.Discard()
	if yieldCount < leafCount {
		t.Errorf("a resync from a tree of %d leaves yielded %d times", leafCount, yieldCount)
	}
}
