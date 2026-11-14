package gkmschedule

// FS-106 on T2 and T3 (KEYS-M2-29; §7.9's read_only row, §10.6's scopes, D-TEAM-24, I-4, FI-2): key upkeep under r
// through the retention horizon, 35 days on the fake clock, on the real subset against gkmservice's engine.
//
// A read_only fixture device w (the page Worker at M4) and a reader-only member device r are leaves of a 10-leaf
// repo, and their tokens hold only r. Each day every leaf takes what gkm holds, commits its path-only self-update
// when one is due, and w and r ack the epoch they adopted; w and r upload a ReaderKey every 6 days and refill their
// KeyPackages once. w, then r, loses its epoch and resyncs by external commit. gkm takes each of these and every
// member adopts them, raising nothing. A third leaf then resyncs from the sealed GroupInfo w's last path-only commit
// carries, and the reconciler's sweep on day 35 deletes the epochs past 30 days, which w's and r's acks passed.
//
// Then what read_only loses: r's group-info write lands and w's is refused, as are w's wraps, its claims of a
// generation and of a KeyPackage and its Welcomes, under r and under an rw token it could not hold; an agent's epoch
// PUT is refused; and w's commit carrying an Add, which gkm cannot see into, is refused by the members, who alarm
// naming w.
//
// FsKeysScheduleParkedReaderKeyWaits is the last row: a parked device's ReaderKey upload is refused until its lift.

import (
	"encoding/hex"
	"net/http"
	"strconv"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The world's repo scope of role, as a token names it.
func (self *FsKeysWorld) repoScope(role string) string {
	return "repo:" + self.RepoId.String() + ":" + role
}

// A gkm path under the world's group.
func (self *FsKeysWorld) groupPath(suffix string) string {
	return "/gkm/groups/" + sidecar.EvsKeyId(self.GroupId) + "/" + suffix
}

// Every leaf takes what gkm holds, so each adopts the others' commits.
func (self *FsKeysWorld) syncLeaves(leaves []*FsKeysDevice) {
	self.t.Helper()
	for _, leaf := range leaves {
		self.Again(leaf.Label+"'s sync", func() error { return leaf.Client.SyncRepo(self.Ctx, self.RepoId) })
	}
}

// The device acks every group it is a leaf of at the epoch it adopted, as upkeep does daily: how many it acked.
func (self *FsKeysDevice) ack() int {
	world := self.world
	world.t.Helper()
	ackGroups := self.Client.AckGroups()
	for _, ackGroup := range ackGroups {
		world.Again(self.Label+"'s ack", func() error {
			return self.Api.Ack(world.Ctx, ackGroup.RepoId, ackGroup.GroupId, ackGroup.Epoch)
		})
	}
	return len(ackGroups)
}

// The device loses its epoch and resyncs by external commit: the epoch its commit made.
func (self *FsKeysWorld) resyncByExternalCommit(device *FsKeysDevice) uint64 {
	self.t.Helper()
	before := self.NewestEpoch()
	device.LoseMlsState()
	device.Take(self.Log.Tip())
	self.Again(device.Label+"'s resync", func() error { return device.Client.SyncRepo(self.Ctx, self.RepoId) })
	epoch := self.NewestEpoch()
	if epoch != before+1 {
		self.t.Fatalf("%s's resync made no external commit: the newest epoch %d, %d before", device.Label, epoch, before)
	}
	group, err := device.Mls.LoadGroup(self.GroupId)
	if err != nil || group.Epoch() != epoch {
		self.t.Fatalf("%s does not hold the epoch its resync made: %v", device.Label, err)
	}
	return epoch
}

// FS-106: see the file header.
func FsKeysScheduleKeyUpkeepUnderR(t FsKeysT, newWorld FsKeysNewWorld) {
	world := newWorld(protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.AddMember("a", false)
	writers := []*FsKeysDevice{a}
	for _, label := range []string{"b", "c", "d", "e", "f", "g", "h"} {
		writers = append(writers, world.AddMember(label, false))
	}
	third := writers[len(writers)-1]
	w := world.AddMember("w", true)
	r := world.AddMember("r", false)
	x := world.AddAgent("x")
	world.Grant(true, writers...)
	world.Grant(false, w, r, x)
	world.Admin(a)
	world.Advance()
	world.Publish()
	world.Create(a)
	world.AddPending(a)
	repoId := world.RepoId
	leaves := append(append([]*FsKeysDevice{}, writers...), w, r)
	world.syncLeaves(leaves)
	if labels := world.Roster(a); len(labels) != 10 {
		t.Fatalf("the tree holds %s, not 10 leaves", labels)
	}
	world.AgreeOnEpoch(leaves...)

	pathCommits := map[*FsKeysDevice]int{}
	firstEpoch := world.NewestEpoch()
	for day := 1; day <= 35; day += 1 {
		world.Clock.Advance(24 * time.Hour)
		if day%6 == 0 {
			// under r alone: the device's own records
			w.PublishReaderKey()
			r.PublishReaderKey()
		}
		if day == 12 {
			w.PublishKeyPackages()
			r.PublishKeyPackages()
		}
		for _, leaf := range leaves {
			world.Again(leaf.Label+"'s sync", func() error { return leaf.Client.SyncRepo(world.Ctx, repoId) })
			before := world.NewestEpoch()
			world.Again(leaf.Label+"'s self-update", func() error { return leaf.Client.RunSelfUpdate(world.Ctx, repoId) })
			switch committed := world.NewestEpoch() - before; committed {
			case 0:
			case 1:
				pathCommits[leaf] += 1
				if len(world.EpochObject(before+1).GetSealedGroupInfo()) == 0 {
					t.Fatalf("day %d: %s's path-only commit carries no sealed GroupInfo", day, leaf.Label)
				}
			default:
				t.Fatalf("day %d: %s's self-update made %d epochs", day, leaf.Label, committed)
			}
		}
		if day == 16 {
			world.syncLeaves(leaves)
			world.resyncByExternalCommit(w)
		}
		if day == 17 {
			world.syncLeaves(leaves)
			world.resyncByExternalCommit(r)
		}
		world.syncLeaves(leaves)
		world.AgreeOnEpoch(leaves...)
		for _, device := range []*FsKeysDevice{w, r} {
			if device.ack() != 1 {
				t.Fatalf("day %d: %s acked no group", day, device.Label)
			}
		}
	}
	for _, device := range []*FsKeysDevice{w, r} {
		if pathCommits[device] < 4 {
			t.Errorf("%s committed %d path-only self-updates in 35 days", device.Label, pathCommits[device])
		}
	}
	if labels := world.Roster(a); len(labels) != 10 {
		t.Errorf("the tree after 35 days: %s", labels)
	}
	if count := fsKeysAlarmCount(leaves...); count != 0 {
		t.Errorf("35 days of upkeep raised %d alarms", count)
	}
	// a writer leaf's scheduled rotation may land in 35 days; none is w's or r's
	generationCount := uint64(world.GenerationCount())
	for generation := uint64(2); generation <= generationCount; generation += 1 {
		rotated := world.Generation(generation)
		if rotated.SignerId == w.SidecarId() || rotated.SignerId == r.SidecarId() || sidecar.GkmCause(rotated.Rotate.GetCause()) != sidecar.GkmCauseSchedule {
			t.Errorf("generation %d: cause %d, signed by %s", generation, rotated.Rotate.GetCause(), rotated.SignerId)
		}
	}

	// a third leaf resyncs from the sealed GroupInfo the read_only leaf's last path-only commit carries
	before := world.NewestEpoch()
	if err := w.Client.SelfUpdate(world.Ctx, repoId); err != nil {
		t.Fatalf("the read_only leaf's path-only commit: %v", err)
	}
	if world.NewestEpoch() != before+1 || len(world.EpochObject(before+1).GetSealedGroupInfo()) == 0 {
		t.Fatalf("the read_only leaf's path-only commit carries no sealed GroupInfo")
	}
	world.resyncByExternalCommit(third)
	world.syncLeaves(leaves)
	world.AgreeOnEpoch(leaves...)
	for _, device := range []*FsKeysDevice{w, r} {
		device.ack()
	}

	// epoch retention passes their acks: the epochs of the first days are 30 days old and go, the newest stays
	epochCount := world.EpochCount()
	reconciler := world.StartReconciler(nil)
	world.Sweep(reconciler)
	if world.EpochObject(firstEpoch) != nil || epochCount <= world.EpochCount() {
		t.Errorf("the sweep on day 35 kept the first epoch: %d epochs stand of %d", world.EpochCount(), epochCount)
	}
	if world.EpochObject(world.NewestEpoch()) == nil {
		t.Fatalf("the sweep deleted the newest epoch")
	}

	// the reader-only leaf's group-info write lands, the read_only one's is refused
	newest := world.NewestEpoch()
	pointer := &protocol.GkmGroupInfoObject{Epoch: newest}
	if err := w.Api.UploadGroupInfo(world.Ctx, repoId, world.GroupId, pointer); !sidecar.IsGkmStatus(err, http.StatusForbidden) {
		t.Errorf("the read_only leaf's group-info write: %v", err)
	}
	if err := r.Api.UploadGroupInfo(world.Ctx, repoId, world.GroupId, pointer); err != nil {
		t.Errorf("the reader-only leaf's group-info write: %v", err)
	}
	if object := world.GroupInfoObject(world.GroupId); object.GetEpoch() != newest {
		t.Errorf("the pointer is at %d, not the reader-only leaf's %d", object.GetEpoch(), newest)
	}

	// read_only loses its wraps, claims and Welcomes, whatever scope its token names
	x.PublishReaderKey()
	if status := world.UploadDelivery(w, world.SealDelivery(w, generationCount, x, world.Log.Tip().Pin(), world.Clock.Now())); status != http.StatusForbidden {
		t.Errorf("the read_only leaf's delivery: %d", status)
	}
	c8 := hex.EncodeToString(world.Generation(generationCount).Rotate.GetCommitment()[:8])
	generationSegment := strconv.FormatUint(generationCount, 10)
	refusedRoutes := []struct {
		label string
		path  string
	}{
		{label: "wrap", path: world.groupPath("wraps/" + generationSegment + "/" + c8)},
		{label: "claim of a generation", path: world.groupPath("gen/" + strconv.FormatUint(generationCount+1, 10))},
		{label: "claim of a KeyPackage", path: "/gkm/key-packages/claim"},
		{label: "Welcome", path: world.groupPath("welcome/" + strconv.FormatUint(newest, 10))},
		{label: "group-info write", path: world.groupPath("group-info")},
	}
	for _, route := range refusedRoutes {
		for _, role := range []string{sidecar.GkmScopeRoleRead, sidecar.GkmScopeRoleWrite} {
			// the KeyPackage claim names its repo in its body, which the guard refuses before it reads
			status := world.RawStatus(w, http.MethodPost, route.path, nil, world.repoScope(role))
			if status != http.StatusForbidden && !(route.label == "claim of a KeyPackage" && status == http.StatusBadRequest) {
				t.Errorf("the read_only leaf's %s under %s: %d", route.label, role, status)
			}
		}
	}
	if uint64(world.GenerationCount()) != generationCount {
		t.Errorf("a read_only claim stands")
	}

	// an agent's epoch PUT is refused
	commitPath := world.groupPath("epochs/" + strconv.FormatUint(newest+1, 10))
	if status := world.RawStatus(x, http.MethodPost, commitPath, nil, world.repoScope(sidecar.GkmScopeRoleRead)); status != http.StatusForbidden {
		t.Errorf("an agent's epoch PUT: %d", status)
	}
	if world.NewestEpoch() != newest {
		t.Fatalf("an agent's epoch stands")
	}

	// a commit carrying a proposal, which gkm cannot see: the members refuse it and alarm naming the read_only leaf
	n := world.AddMember("n", false)
	world.Grant(false, n)
	world.Advance()
	n.Restart()
	keyPackage, err := n.Mls.CreateKeyPackage(false)
	if err != nil {
		t.Fatal(err)
	}
	if status := world.InjectCommit(w, generationCount, [][]byte{keyPackage.Encoded}); status != http.StatusOK {
		t.Fatalf("gkm refused the read_only leaf's commit, which it cannot see into: %d", status)
	}
	for _, member := range []*FsKeysDevice{a, r} {
		// the sync takes the commit as refused, whatever it answers
		member.Client.SyncRepo(world.Ctx, repoId)
		if !member.RefusedBy(w) {
			t.Errorf("%s raised no refusal naming the read_only leaf: %+v", member.Label, member.Alarms)
		}
		group, err := member.Mls.LoadGroup(world.GroupId)
		if err != nil || group.Epoch() != newest {
			t.Errorf("%s adopted the read_only leaf's commit carrying a proposal: %v", member.Label, err)
		}
	}
}

// FS-106's last row: a parked device's ReaderKey upload is refused, and lands once the park is lifted.
func FsKeysScheduleParkedReaderKeyWaits(t FsKeysT, newWorld FsKeysNewWorld) {
	world := newWorld(protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.AddMember("a", false)
	p := world.AddMember("p", false)
	world.Grant(true, a)
	world.Grant(false, p)
	world.Admin(a)
	world.Advance()
	world.Publish()
	world.Create(a)
	world.AddPending(a)
	served := p.ReaderKey
	// a's AdmissionConfirm is still to come: p is parked
	p.row.ParkedAt = world.nextPosition()
	world.Advance()
	world.Clock.Advance(25 * time.Hour)
	now := world.Clock.Now()
	readerKey, _, err := sidecar.NewGkmReaderKey(p.SidecarId(), now, now.Add(6*24*time.Hour), p.signer.Sign)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Api.UploadReaderKey(world.Ctx, readerKey); !sidecar.IsGkmStatus(err, http.StatusForbidden) {
		t.Errorf("a parked device's ReaderKey upload: %v", err)
	}
	stored, err := a.Api.ReaderKey(world.Ctx, p.SidecarId())
	if err != nil || string(stored.GetBody()) != string(served.GetBody()) {
		t.Errorf("gkm serves another ReaderKey for the parked device than the one before its park: %v", err)
	}
	// the lift
	p.row.ParkedAt = 0
	world.Advance()
	if err := p.Api.UploadReaderKey(world.Ctx, readerKey); err != nil {
		t.Fatalf("the ReaderKey upload after the lift: %v", err)
	}
	stored, err = a.Api.ReaderKey(world.Ctx, p.SidecarId())
	if err != nil || string(stored.GetBody()) != string(readerKey.GetBody()) {
		t.Errorf("gkm does not serve the ReaderKey uploaded after the lift: %v", err)
	}
}
