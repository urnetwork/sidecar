// FS-17 on T2 (PROTO-M2-05): the row's registered case under every rule §22.8 gives it, and each
// clause's schedule (fs17.go) fixed, FI-10 checked after every step.

package fault

import (
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// One clause's schedule on a Net of its own, failing t with the trace if it fails.
func fs17Run(t *testing.T, builder Builder) {
	t.Helper()
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	if result := Run(t.Context(), builder(net), net); result.Err != nil {
		t.Fatalf("%s", result)
	}
}

// The registered case: one ref forked under an unchanged epoch, its twin, the explorer's seeds and the
// committed traces.
func TestFs17(t *testing.T) {
	RunRow(t, "FS-17", "", nil)
}

func TestFs17ManyRefsShowWithinCeilExchanges(t *testing.T) {
	fs17Run(t, Fs17ManyRefs)
}

func TestFs17GenerationForkTwoAgentsSee(t *testing.T) {
	fs17Run(t, Fs17GenFork)
}

func TestFs17WithheldProofStopsAtOnce(t *testing.T) {
	fs17Run(t, Fs17WithheldProof)
}

func TestFs17ProofDroppedIsUnverifiedAndStopsAtTheBound(t *testing.T) {
	fs17Run(t, Fs17ProofDropped)
}

func TestFs17RelayedProofStopsTheWriter(t *testing.T) {
	fs17Run(t, Fs17RelayedProof)
}

func TestFs17PhoneHolderServesFromItsNewestEntries(t *testing.T) {
	fs17Run(t, Fs17PhoneHolder)
}

func TestFs17PhoneNotFoundRelaysUnverifiedUntilRevoked(t *testing.T) {
	fs17Run(t, Fs17PhoneNotFound)
}

func TestFs17PeersWithoutStandingNeverCount(t *testing.T) {
	fs17Run(t, Fs17StandingPeers)
}

func TestFs17CatchUpRefreshesAndStaleDoesNot(t *testing.T) {
	fs17Run(t, Fs17CatchUp)
}

// FI-10's conflict reading bites: two devices whose pins differ at one position, an auth digest, a
// generation's commitment, an epoch's authenticator or a ref's chain, conflict, each beside its twin at one
// pin, and a device merely behind conflicts with no one.
func TestFi10ReadsEachConflict(t *testing.T) {
	networkId := sidecar.Id{0x4e}
	api := sidecartest.NewFakeHeadCheckApi(networkId)
	api.Append(10)
	device := func(sidecarId sidecar.Id, history *sidecartest.FakeHeadCheckApi, version uint64) *sidecartest.HeadCheckSidecar {
		side := &sidecartest.HeadCheckSidecar{SidecarId: sidecarId, Device: sidecartest.NewFakeHeadCheckDevice(sidecarId, history)}
		if err := side.Device.Auth.ReachFromApi(version); err != nil {
			t.Fatal(err)
		}
		return side
	}
	ahead := device(sidecar.Id{1}, api, 10)
	behind := device(sidecar.Id{2}, api, 6)
	if conflict := fi10Conflict(ahead, behind); conflict != "" {
		t.Errorf("a device behind conflicts: %s", conflict)
	}
	fork := api.Fork(8, "other")
	fork.Append(3)
	forked := device(sidecar.Id{3}, fork, 11)
	if conflict := fi10Conflict(ahead, forked); conflict == "" {
		t.Error("an auth fork read as none")
	}
	for _, c := range []struct {
		name string
		set  func(side *sidecartest.HeadCheckSidecar, label string)
	}{
		{name: "generation", set: func(side *sidecartest.HeadCheckSidecar, label string) {
			side.Device.Heads.SetGen(&protocol.GenHead{GroupId: fs17GroupId.Bytes(), Generation: 3, Commitment: fs17Digest(label)})
		}},
		{name: "epoch", set: func(side *sidecartest.HeadCheckSidecar, label string) {
			side.Device.Heads.SetGroup(&protocol.GroupHead{GroupId: fs17GroupId.Bytes(), Epoch: 3, EpochAuthenticator: fs17Digest(label)})
		}},
		{name: "ref", set: func(side *sidecartest.HeadCheckSidecar, label string) {
			side.Device.Heads.SetRef(&protocol.RefHead{RepoId: fs17RepoId.Bytes(), RefId: fs17RefId.Bytes(), Version: 7, Chain: fs17Digest(label)}, fs17GroupId)
		}},
	} {
		a := device(sidecar.Id{4}, api, 10)
		b := device(sidecar.Id{5}, api, 10)
		c.set(a, "one")
		c.set(b, "one")
		if conflict := fi10Conflict(a, b); conflict != "" {
			t.Errorf("%s: one pin conflicts: %s", c.name, conflict)
		}
		c.set(b, "two")
		if conflict := fi10Conflict(a, b); conflict == "" {
			t.Errorf("%s: a fork read as none", c.name)
		}
	}
}
