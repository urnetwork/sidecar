package fault

// FI-12 (TEST-M3-01): the recovery check catches each mutant §22.8's row names, an oid a restore changed, a revoked
// client back, an erased entry back, a name lost without an incident line; reads a clean restore, each excused loss
// the incident lists and FS-40's second host clean; assumes neither dump order; and as fault.FI(12), runs after
// every step of a schedule, failing closed on one that never shows what came back.

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// What a small network's recovery must bring back: the network, its admin member with a login, two clients, one of
// them revoked before the loss, a ref's head, two entries' content, one of them erased before the loss, and a
// network deleted before the loss.
type fi12World struct {
	networkId       string
	memberId        string
	clientId        string
	revokedClientId string
	deletedNetwork  string
	repoId          sidecar.Id
	refId           sidecar.Id
}

func newFi12World() *fi12World {
	return &fi12World{
		networkId:       sidecar.NewId().String(),
		memberId:        sidecar.NewId().String(),
		clientId:        sidecar.NewId().String(),
		revokedClientId: sidecar.NewId().String(),
		deletedNetwork:  sidecar.NewId().String(),
		repoId:          sidecar.NewId(),
		refId:           sidecar.NewId(),
	}
}

// The snapshot as the stores hold the world: before its loss, and after a clean restore.
func (self *fi12World) snapshot() *RecoverySnapshot {
	snapshot := NewRecoverySnapshot()
	snapshot.AddIdentity(&RecoveryIdentity{Kind: RecoveryKindNetwork, Id: self.networkId, Active: true, Fields: map[string]string{RecoveryFieldName: "fi12-network"}})
	snapshot.AddIdentity(&RecoveryIdentity{Kind: RecoveryKindMember, Id: self.memberId, Active: true, Fields: map[string]string{RecoveryFieldLogin: "member@example.com", RecoveryFieldNetwork: self.networkId}})
	snapshot.AddIdentity(&RecoveryIdentity{Kind: RecoveryKindClient, Id: self.clientId, Active: true, Fields: map[string]string{RecoveryFieldNetwork: self.networkId}})
	snapshot.AddIdentity(&RecoveryIdentity{Kind: RecoveryKindClient, Id: self.revokedClientId, Active: false, Fields: map[string]string{RecoveryFieldNetwork: self.networkId}})
	snapshot.AddHead(&RecoveryHead{RepoId: self.repoId, RefId: self.refId, Version: 7, Chain: bytes.Repeat([]byte{7}, 32)})
	snapshot.AddContent("entry-kept", self.repoId, []byte("an entry the recovery keeps"))
	snapshot.AddGone(RecoveryContentKey("entry-erased"), "erased")
	snapshot.AddGone(RecoveryIdentityKey(RecoveryKindClient, self.revokedClientId), "revoked")
	snapshot.AddGone(RecoveryIdentityKey(RecoveryKindNetwork, self.deletedNetwork), "deleted")
	return snapshot
}

// A clean restore, every one of FS-42's dump orders' excused losses listed, and FS-40's second host read clean.
func TestFi12ReadsACleanRestoreClean(t *testing.T) {
	world := newFi12World()
	if err := CheckRecovery(world.snapshot(), world.snapshot(), &RecoveryIncident{Id: sidecar.NewId()}); err != nil {
		t.Fatalf("a clean restore: %v", err)
	}
	// a re-keyed vault compares by what it opens to: the same plaintext under new keys is the same content
	after := world.snapshot()
	after.AddContent("entry-kept", world.repoId, []byte("an entry the recovery keeps"))
	if err := CheckRecovery(world.snapshot(), after, nil); err != nil {
		t.Fatalf("a re-formed vault: %v", err)
	}
}

// FS-40's second-host case: the objects whose every shard existed before the second host went still open after it,
// and one of them unreadable fails.
func TestFi12ReadsFs40sSecondHostCaseClean(t *testing.T) {
	repoId := sidecar.NewId()
	before := NewRecoverySnapshot()
	for _, name := range []string{"head", "slot", "segment"} {
		before.AddContent(name, repoId, []byte("every shard of the "+name))
	}
	after := NewRecoverySnapshot()
	for _, name := range []string{"head", "slot", "segment"} {
		after.AddContent(name, repoId, []byte("every shard of the "+name))
	}
	if err := CheckRecovery(before, after, nil); err != nil {
		t.Fatalf("FS-40's second host: %v", err)
	}
	delete(after.Contents, RecoveryContentKey("segment"))
	if err := CheckRecovery(before, after, nil); err == nil || !strings.Contains(err.Error(), "content/segment no longer opens") {
		t.Fatalf("an object whose every shard existed lost to a second host: %v", err)
	}
}

// Each mutant §22.8's FI-12 names fails, saying what came back wrong.
func TestFi12CatchesEachMutant(t *testing.T) {
	world := newFi12World()
	for _, mutant := range []struct {
		name   string
		mutate func(after *RecoverySnapshot)
		want   string
	}{
		{
			name: "an oid changed by a restore",
			mutate: func(after *RecoverySnapshot) {
				network := after.Identities[RecoveryIdentityKey(RecoveryKindNetwork, world.networkId)]
				delete(after.Identities, network.Key())
				network.Id = sidecar.NewId().String()
				after.AddIdentity(network)
			},
			want: "oid changed",
		},
		{
			name: "a revoked client coming back",
			mutate: func(after *RecoverySnapshot) {
				after.Identities[RecoveryIdentityKey(RecoveryKindClient, world.revokedClientId)].Active = true
			},
			want: "revoked before the loss, came back active",
		},
		{
			name: "a deleted network coming back",
			mutate: func(after *RecoverySnapshot) {
				after.AddIdentity(&RecoveryIdentity{Kind: RecoveryKindNetwork, Id: world.deletedNetwork, Active: true, Fields: map[string]string{RecoveryFieldName: "fi12-deleted"}})
			},
			want: "deleted before the loss, came back active",
		},
		{
			name: "an erased entry returning",
			mutate: func(after *RecoverySnapshot) {
				after.AddContent("entry-erased", world.repoId, []byte("an erased entry"))
			},
			want: "erased before the loss, opens again",
		},
		{
			name: "a name lost without an incident line",
			mutate: func(after *RecoverySnapshot) {
				after.Identities[RecoveryIdentityKey(RecoveryKindNetwork, world.networkId)].Fields[RecoveryFieldName] = "fi12-network-3f9a"
			},
			want: "came back with name",
		},
		{
			name: "a login lost without an incident line",
			mutate: func(after *RecoverySnapshot) {
				after.Identities[RecoveryIdentityKey(RecoveryKindMember, world.memberId)].Fields[RecoveryFieldLogin] = ""
			},
			want: "came back with login",
		},
		{
			name: "a client deactivated without an incident line",
			mutate: func(after *RecoverySnapshot) {
				after.Identities[RecoveryIdentityKey(RecoveryKindClient, world.clientId)].Active = false
			},
			want: "came back inactive",
		},
		{
			name: "a network lost without an incident line",
			mutate: func(after *RecoverySnapshot) {
				delete(after.Identities, RecoveryIdentityKey(RecoveryKindNetwork, world.networkId))
			},
			want: "did not come back",
		},
		{
			name: "a head below its C_v",
			mutate: func(after *RecoverySnapshot) {
				after.AddHead(&RecoveryHead{RepoId: world.repoId, RefId: world.refId, Version: 6, Chain: bytes.Repeat([]byte{6}, 32)})
			},
			want: "came back at 6",
		},
		{
			name: "a head at its version on another chain",
			mutate: func(after *RecoverySnapshot) {
				after.AddHead(&RecoveryHead{RepoId: world.repoId, RefId: world.refId, Version: 7, Chain: bytes.Repeat([]byte{9}, 32)})
			},
			want: "came back at 7",
		},
		{
			name: "content that opens to other bytes",
			mutate: func(after *RecoverySnapshot) {
				after.AddContent("entry-kept", world.repoId, []byte("another entry"))
			},
			want: "opens to other content",
		},
	} {
		after := world.snapshot()
		mutant.mutate(after)
		err := CheckRecovery(world.snapshot(), after, &RecoveryIncident{Id: sidecar.NewId()})
		if err == nil || !strings.Contains(err.Error(), mutant.want) {
			t.Errorf("%s: %v; want %q", mutant.name, err, mutant.want)
		}
	}
}

// What the incident lists is the only excuse, and each excuses only what it names: a suffixed name, a login left for
// a reset, a client deactivated to re-enroll, a lost network with its members and clients, its repos' heads and
// content, a repo back only below a pin under an EvsReseed, and a row back at the main dump's age. A line naming
// another id excuses nothing.
func TestFi12TakesOnlyWhatTheIncidentLists(t *testing.T) {
	world := newFi12World()
	after := world.snapshot()
	after.Identities[RecoveryIdentityKey(RecoveryKindNetwork, world.networkId)].Fields[RecoveryFieldName] = "fi12-network-3f9a"
	after.Identities[RecoveryIdentityKey(RecoveryKindMember, world.memberId)].Fields[RecoveryFieldLogin] = ""
	after.Identities[RecoveryIdentityKey(RecoveryKindClient, world.clientId)].Active = false
	after.AddHead(&RecoveryHead{RepoId: world.repoId, RefId: world.refId, Version: 5, Chain: bytes.Repeat([]byte{5}, 32)})
	incident := &RecoveryIncident{Id: sidecar.NewId(), Lines: []*RecoveryIncidentLine{
		{Kind: RecoveryLineNetworkRenamed, Table: "network", RowId: strings.ToUpper(world.networkId), Detail: "fi12-network-3f9a"},
		{Kind: RecoveryLineLoginLeftOut, Table: "network_user_auth_password", RowId: world.memberId},
		{Kind: RecoveryLineClientDeactivated, Table: "network_client", RowId: world.clientId},
		{Kind: RecoveryLineCloseUnderReseed, Table: "repo", RowId: world.repoId.String()},
	}}
	if err := CheckRecovery(world.snapshot(), after, incident); err != nil {
		t.Fatalf("every loss listed: %v", err)
	}
	// a suffixed name other than the one listed fails
	after.Identities[RecoveryIdentityKey(RecoveryKindNetwork, world.networkId)].Fields[RecoveryFieldName] = "fi12-network-0000"
	if err := CheckRecovery(world.snapshot(), after, incident); err == nil || !strings.Contains(err.Error(), "lists its suffixed name") {
		t.Fatalf("a name the incident did not list: %v", err)
	}
	// lines naming another id excuse nothing
	other := sidecar.NewId().String()
	for _, line := range incident.Lines {
		line.RowId = other
	}
	after = world.snapshot()
	after.Identities[RecoveryIdentityKey(RecoveryKindClient, world.clientId)].Active = false
	if err := CheckRecovery(world.snapshot(), after, incident); err == nil {
		t.Fatal("a line for another client excused this one")
	}

	// a network newer than both dumps is lost with its member and clients, its repo shredded under the incident
	lost := world.snapshot()
	for key := range lost.Identities {
		delete(lost.Identities, key)
	}
	delete(lost.Heads, RecoveryHeadKey(world.repoId, world.refId))
	delete(lost.Contents, RecoveryContentKey("entry-kept"))
	lostIncident := &RecoveryIncident{Id: sidecar.NewId(), Lines: []*RecoveryIncidentLine{
		{Kind: RecoveryLineOrphanLog, Table: "proj", RowId: world.networkId, Detail: "1 repos"},
		{Kind: RecoveryLineOrphanRepo, Table: "repo", RowId: world.repoId.String(), Detail: "shredding"},
	}}
	if err := CheckRecovery(world.snapshot(), lost, lostIncident); err != nil {
		t.Fatalf("a network newer than both dumps, listed: %v", err)
	}
	if err := CheckRecovery(world.snapshot(), lost, &RecoveryIncident{Id: sidecar.NewId()}); err == nil {
		t.Fatal("a lost network the incident forgot passed")
	}
}

// FS-42's dumps in each order, the snapshot assuming neither: with the sidecar dump newer, a client newer than the
// main dump comes back with its id; with the main dump newer, a row the sidecar dump does not name comes back as the
// main dump holds it, and a client created after the sidecar dump comes back deactivated to re-enroll, listed.
func TestFi12AssumesNeitherDumpOrder(t *testing.T) {
	world := newFi12World()
	newClient := sidecar.NewId().String()
	before := world.snapshot()
	before.AddIdentity(&RecoveryIdentity{Kind: RecoveryKindClient, Id: newClient, Active: true, Fields: map[string]string{RecoveryFieldNetwork: world.networkId}})

	// the sidecar dump newer: every row comes back from it
	if err := CheckRecovery(before, before, &RecoveryIncident{Id: sidecar.NewId()}); err != nil {
		t.Fatalf("the sidecar dump newer: %v", err)
	}

	// the main dump newer: the new client is deactivated and listed, and the network's name, which the sidecar
	// dump does not name, comes back as the main dump holds it
	after := world.snapshot()
	after.AddIdentity(&RecoveryIdentity{Kind: RecoveryKindClient, Id: newClient, Active: false, Fields: map[string]string{RecoveryFieldNetwork: world.networkId}})
	after.Identities[RecoveryIdentityKey(RecoveryKindNetwork, world.networkId)].Fields[RecoveryFieldName] = "fi12-network-at-the-main-dump"
	mainDumpNetwork := &RecoveryIdentity{Kind: RecoveryKindNetwork, Id: world.networkId, Active: true, Fields: map[string]string{RecoveryFieldName: "fi12-network-at-the-main-dump"}}
	incident := &RecoveryIncident{
		Id:       sidecar.NewId(),
		Lines:    []*RecoveryIncidentLine{{Kind: RecoveryLineClientDeactivated, Table: "network_client", RowId: newClient}},
		MainDump: map[string]*RecoveryIdentity{mainDumpNetwork.Key(): mainDumpNetwork},
	}
	if err := CheckRecovery(before, after, incident); err != nil {
		t.Fatalf("the main dump newer: %v", err)
	}
	// held to the main dump's copy: the sidecar's copy is no longer what it must equal
	after.Identities[RecoveryIdentityKey(RecoveryKindNetwork, world.networkId)].Fields[RecoveryFieldName] = "fi12-network"
	if err := CheckRecovery(before, after, incident); err == nil || !strings.Contains(err.Error(), "the main dump holds") {
		t.Fatalf("a main-dump row back at the sidecar's copy: %v", err)
	}
}

// Writes place/<repo> and head/<repo>/<ref> at version on net's first metadata cluster, as evs writes them, over
// any head there: the stores a T2 schedule loses and restores.
func fi12PutHead(ctx context.Context, net *Net, repoId sidecar.Id, refId sidecar.Id, version uint64) error {
	first, err := net.Host().Blobs.FirstCluster()
	if err != nil {
		return err
	}
	if _, err := sidecar.ReadEvsRepoPlace(ctx, first, repoId); err != nil {
		placeBytes, err := (&sidecar.EvsRepoPlace{ClusterId: first.ClusterId(), CreatorSidecarId: sidecar.NewId()}).Marshal()
		if err != nil {
			return err
		}
		if _, err := first.PutIfNoneMatch(ctx, sidecar.EvsPlaceKey(repoId), placeBytes, nil); err != nil {
			return err
		}
	}
	headBytes, err := proto.Marshal(&protocol.EvsHead{Version: version, Chain: bytes.Repeat([]byte{byte(version)}, 32)})
	if err != nil {
		return err
	}
	key := "head/" + sidecar.EvsKeyId(repoId) + "/" + sidecar.EvsKeyId(refId)
	if err := first.Delete(ctx, key); err != nil && !errors.Is(err, sidecar.ErrBlobNotFound) {
		return err
	}
	_, err = first.PutIfNoneMatch(ctx, key, headBytes, nil)
	return err
}

// A schedule naming FI(12): a head at 7 snapshotted, the site lost, the head restored at restoredVersion, and what came
// back recorded. record false records nothing, as a schedule naming FI-12 and showing nothing would.
func fi12Schedule(restoredVersion uint64, record bool) Builder {
	return func(net *Net) *Schedule {
		repoId, refId := sidecar.NewId(), sidecar.NewId()
		snapshotOf := func(ctx context.Context) (*RecoverySnapshot, error) {
			snapshot := NewRecoverySnapshot()
			err := snapshot.AddHeadsFrom(ctx, NewStoreView(net, nil), repoId, refId)
			return snapshot, err
		}
		steps := []*Step{
			{Actor: "evs", Action: func(ctx context.Context, net *Net) error {
				return fi12PutHead(ctx, net, repoId, refId, 7)
			}},
			{Actor: "ops", Action: func(ctx context.Context, net *Net) error {
				if !record {
					return nil
				}
				snapshot, err := snapshotOf(ctx)
				if err == nil && len(snapshot.Heads) != 1 {
					return errSnapshotTookNoHead
				}
				RecordRecoverySnapshot(net, "site", snapshot)
				return err
			}},
			{Actor: "ops", Action: func(ctx context.Context, net *Net) error {
				return fi12PutHead(ctx, net, repoId, refId, restoredVersion)
			}},
			{Actor: "ops", Action: func(ctx context.Context, net *Net) error {
				if !record {
					return nil
				}
				after, err := snapshotOf(ctx)
				RecordRecovered(net, "site", after, &RecoveryIncident{Id: sidecar.NewId()})
				return err
			}},
		}
		return &Schedule{Id: "FI-12's own schedule", Steps: steps, Check: []Invariant{FI(12)}, Tiers: []Tier{TierT2}}
	}
}

// What a schedule's snapshot step fails with when it read no head, which the schedule's own write put there.
var errSnapshotTookNoHead = errors.New("the snapshot read no head")

// As fault.FI(12), the check runs after each step of a schedule on T2: a head restored at its (v, C_v) reads clean,
// one restored lower fails after the step that recorded it, and a schedule that names FI-12 and records nothing
// fails at the end, never passing on nothing.
func TestFi12RunsAfterEveryStepAndFailsClosed(t *testing.T) {
	run := func(builder Builder) *Result {
		net := sidecartest.NewNet(t.Context(), nil)
		defer net.Close()
		return Run(t.Context(), builder(net), net)
	}
	if result := run(fi12Schedule(7, true)); result.Err != nil {
		t.Fatalf("a head restored at its C_v: %s", result)
	}
	result := run(fi12Schedule(6, true))
	if result.Err == nil || !strings.Contains(result.Err.Error(), "came back at 6") || result.FailedStep != 3 {
		t.Fatalf("a head restored below its C_v: %s", result)
	}
	result = run(fi12Schedule(7, false))
	if result.Err == nil || !strings.Contains(result.Err.Error(), "FI-12 read no recovery") {
		t.Fatalf("a schedule that shows nothing: %s", result)
	}
}

// A snapshot taken before the fault with nothing recorded as recovered fails at the end, and what came back recorded
// with no snapshot before it fails at once.
func TestFi12FailsAHalfRecordedRecovery(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	RecordRecoverySnapshot(net, "postgres", NewRecoverySnapshot())
	if err := checkFi12(&Oracle{Net: net}); err != nil {
		t.Fatalf("mid-run, before the recovery: %v", err)
	}
	if err := checkFi12(&Oracle{Net: net, Final: true}); err == nil || !strings.Contains(err.Error(), "nothing recorded as recovered") {
		t.Fatalf("at the end with no recovery: %v", err)
	}
	other := sidecartest.NewNet(t.Context(), nil)
	defer other.Close()
	RecordRecovered(other, "postgres", NewRecoverySnapshot(), nil)
	if err := checkFi12(&Oracle{Net: other}); err == nil || !strings.Contains(err.Error(), "no snapshot before its fault") {
		t.Fatalf("a recovery with no snapshot: %v", err)
	}
}
