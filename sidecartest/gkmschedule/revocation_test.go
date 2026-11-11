package gkmschedule

// §22.7's revocation suite, gkm's legs, on T2 (KEYS-M2-28; D-TEST-6, I-15, FI-3, FI-4): X loses access by a device
// revoke, a read loss and, for an agent, a revoke and a grant's expiry, keeping its local state and raw store
// access, as a malicious server allows. Each case runs with evs's gate off, which here is no gate at all: what holds
// is the writers' own rule and the members' checks (§8.12, D-TEST-6).
//
//   - writers seal nothing to a generation X holds: the first EnsureWritable after the drop commits the Remove a leaf
//     X needs and claims a REMOVE generation, and answers only that;
//   - after members write at g+1, every GenWrap and ReaderWrap of g+1 fails under all X's keys, its MLS state and its
//     ReaderKeys, however much of the store it fetches;
//   - members refuse a commit that omits a Remove the projection needs, and one that adds a non-reader, each made on
//     the real subset by a hostile leaf past every client check and taken by gkm, which cannot see proposals: the
//     refusal names the committer and poisons the generation the commit carried;
//   - X's tokens, once rev/ voids them, reach no route of gkm (401), and X's external commit, its leaf lost, is
//     refused (403) as X's revocation stands in gkm's state, before and after rev/;
//   - a covered agent's Suspend and a DelegationRevoke are delegation.go's schedules (FS-18), each a REMOVE
//     generation that the agent's keys and the Delegation's seed open nothing of.

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// One way X loses access, and whether X holds a leaf.
type revocationSuiteKeysCase struct {
	name   string
	member bool
	drop   func(world *FsKeysWorld, x *FsKeysDevice)
}

// The revocation suite's causes for a member device and for an uncovered agent.
var revocationSuiteKeysCases = []revocationSuiteKeysCase{
	{name: "a member device revoked", member: true, drop: func(world *FsKeysWorld, x *FsKeysDevice) { world.Revoke(x) }},
	{name: "a member device's read lost", member: true, drop: func(world *FsKeysWorld, x *FsKeysDevice) { world.Drop(x) }},
	{name: "an uncovered agent revoked", member: false, drop: func(world *FsKeysWorld, x *FsKeysDevice) { world.Revoke(x) }},
	{name: "an uncovered agent's grant expired", member: false, drop: func(world *FsKeysWorld, x *FsKeysDevice) {
		world.ExpireAt(x, world.Clock.Now().Add(time.Minute))
		world.Clock.Advance(2 * time.Minute)
	}},
}

// For each cause: the writer's EnsureWritable answers a REMOVE generation X does not hold, a leaf X's Remove
// committed first, and X reaches nothing of it from all gkm stores.
func TestRevocationSuiteKeysXOpensNothingOfTheNextGeneration(t *testing.T) {
	for _, c := range revocationSuiteKeysCases {
		world := NewFsKeysWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
		a := world.AddMember("a", false)
		b := world.AddMember("b", false)
		var x *FsKeysDevice
		if c.member {
			x = world.AddMember("x", false)
		} else {
			x = world.AddAgent("x")
		}
		world.Grant(true, a, b, x)
		world.Admin(a)
		world.Advance()
		world.Publish()
		world.Create(a)
		world.AddPending(a)
		if held, err := x.Client.CurrentRepoKey(world.Ctx, world.RepoId); err != nil || held.Generation() != 1 {
			t.Fatalf("%s: X does not hold generation 1: %v", c.name, err)
		}

		c.drop(world, x)
		x.Offline = true
		world.Advance()
		key, err := a.Client.EnsureWritable(world.Ctx, world.RepoId)
		if err != nil {
			t.Fatalf("%s: the writer's EnsureWritable: %v", c.name, err)
		}
		if key.Generation() != 2 || key.Cause() != sidecar.GkmCauseRemove {
			t.Errorf("%s: the writer seals to generation %d, cause %d", c.name, key.Generation(), key.Cause())
		}
		if c.member && world.Roster(a) != "ab" {
			t.Errorf("%s: the tree after the writer's EnsureWritable: %s", c.name, world.Roster(a))
		}
		if world.WrapRecipients(2)[x.SidecarId()] {
			t.Errorf("%s: a ReaderWrap of generation 2 to X", c.name)
		}
		if reached := world.RemovedReach(x); reached != 1 {
			t.Errorf("%s: X reaches generation %d from all gkm stores", c.name, reached)
		}
		if err := b.Client.SyncRepo(world.Ctx, world.RepoId); err != nil {
			t.Fatalf("%s: b's sync: %v", c.name, err)
		}
		if held, err := b.Client.CurrentRepoKey(world.Ctx, world.RepoId); err != nil || held.Generation() != 2 {
			t.Errorf("%s: b does not follow to generation 2: %v", c.name, err)
		}
	}
}

// The refusal a member raised against committer, false for none.
func revocationSuiteKeysRefused(device *FsKeysDevice, committer *FsKeysDevice) bool {
	for _, alarm := range device.Alarms {
		if alarm.Kind == sidecar.GkmAlarmRefused && alarm.SidecarId == committer.SidecarId() {
			return true
		}
	}
	return false
}

// A hostile leaf's commit that omits the Remove of a revoked leaf, and one that adds a device that reads nothing,
// each taken by gkm: a member that processes it refuses, alarms naming the committer and adopts nothing.
func TestRevocationSuiteKeysMembersRefuseACommitThatOmitsARemoveOrAddsANonReader(t *testing.T) {
	for _, adds := range []bool{false, true} {
		world := NewFsKeysWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
		a := world.AddMember("a", false)
		hostile := world.AddMember("h", false)
		x := world.AddMember("x", false)
		outsider := world.AddMember("y", false)
		world.Grant(true, a, hostile, x)
		world.Admin(a)
		world.Advance()
		world.Publish()
		world.Create(a)
		world.AddPending(a)
		epoch := world.NewestEpoch()
		var keyPackages [][]byte
		if adds {
			// y reads nothing, and the hostile leaf adds it by a KeyPackage it holds
			keyPackage, err := outsider.Mls.CreateKeyPackage(false)
			if err != nil {
				t.Fatal(err)
			}
			keyPackages = [][]byte{keyPackage.Encoded}
		} else {
			// x is revoked, and the hostile leaf commits a path that leaves x's leaf standing
			world.Revoke(x)
			world.Advance()
		}
		if status := world.InjectCommit(hostile, 1, keyPackages); status != 200 {
			t.Fatalf("gkm refused the hostile commit (adds %v): %d", adds, status)
		}
		if err := a.Client.SyncRepo(world.Ctx, world.RepoId); err == nil && !revocationSuiteKeysRefused(a, hostile) {
			t.Fatalf("the member adopted the hostile commit (adds %v)", adds)
		}
		if !revocationSuiteKeysRefused(a, hostile) {
			t.Errorf("the member raised no refusal naming the committer (adds %v): %+v", adds, a.Alarms)
		}
		group, err := a.Mls.LoadGroup(world.GroupId)
		if err != nil {
			t.Fatal(err)
		}
		if group.Epoch() != epoch {
			t.Errorf("the member moved to epoch %d past the hostile commit (adds %v)", group.Epoch(), adds)
		}
	}
}

// X revoked keeps its tokens and its local state. While gkm's state trails the revocation, X's writes still pass the
// standing check, as the twin's KeyPackage upload shows, until api's rev/ voids X's tokens: gkm reads rev/ before
// every write and answers 401 for X's next upload. Once gkm's state holds the revocation, X's reads and its external
// commit, its MLS state lost, are refused (403), and its commit stands nowhere.
func TestRevocationSuiteKeysARevokedDevicesTokensAndExternalCommitAreRefused(t *testing.T) {
	world := NewFsKeysWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.AddMember("a", false)
	x := world.AddMember("x", false)
	world.Grant(true, a, x)
	world.Admin(a)
	world.Advance()
	world.Publish()
	world.Create(a)
	world.AddPending(a)
	keyPackage := func() [][]byte {
		created, err := x.Mls.CreateKeyPackage(false)
		if err != nil {
			t.Fatal(err)
		}
		return [][]byte{created.Encoded}
	}
	world.Revoke(x)
	world.GkmBehind = 1
	world.Advance()
	if err := x.Api.UploadKeyPackages(world.Ctx, keyPackage()); err != nil {
		t.Fatalf("the twin: X's write while gkm's state trails its revocation and no rev/ voids it: %v", err)
	}
	world.VoidTokens(x)
	if err := x.Api.UploadKeyPackages(world.Ctx, keyPackage()); !errors.Is(err, sidecar.ErrGkmTokenRefused) {
		t.Errorf("a write under a token rev/ voids, not the 401 of a refused token: %v", err)
	}
	// gkm's state reaches the revocation: X's read and its external commit are refused
	world.GkmBehind = 0
	if _, err := x.Api.Epochs(world.Ctx, world.RepoId, world.GroupId, 0); !sidecar.IsGkmStatus(err, http.StatusForbidden) {
		t.Errorf("a revoked device's read: %v", err)
	}
	x.LoseMlsState()
	x.Take(world.Log.Tip())
	epoch := world.NewestEpoch()
	if status := world.InjectGenerationZeroJoin(x); status != http.StatusForbidden && status != http.StatusUnauthorized {
		t.Errorf("a revoked device's external commit: %d", status)
	}
	if world.NewestEpoch() != epoch {
		t.Fatalf("the revoked device's external commit stands")
	}
}
