// The HeadCheck fakes behave as the seam's comments promise: api's log chains by AuthChainDigest,
// withholds and forks; a device fetches what api serves it, refuses a fork, serves proofs from its
// newest retain bytes and checks a peer's by its chain; the heads' forward reads answer from the store.

package sidecartest

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	testHeadNetworkId = sidecar.Id{0x4e}
	testHeadHolder    = sidecar.Id{0x52}
	testHeadWriter    = sidecar.Id{0x57}
)

func TestFakeHeadCheckApiChainsItsTicks(t *testing.T) {
	api := NewFakeHeadCheckApi(testHeadNetworkId)
	tip := api.Append(5)
	if tip.GetVersion() != 5 || api.Pin(6) != nil || len(api.Pin(0).GetChain()) != 32 {
		t.Fatalf("tip %v", tip)
	}
	for n, entryBytes := range api.entriesThrough(5) {
		entry := &bridge.AuthEntry{}
		if err := proto.Unmarshal(entryBytes, entry); err != nil {
			t.Fatal(err)
		}
		chain, err := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
		if err != nil {
			t.Fatal(err)
		}
		if entry.GetN() != uint64(n+1) || !bytes.Equal(entry.GetPrevChain(), api.Pin(uint64(n)).GetChain()) || !bytes.Equal(chain[:], api.Pin(uint64(n+1)).GetChain()) {
			t.Fatalf("entry %d does not chain", n+1)
		}
	}
}

func TestFakeHeadCheckAuthFetchesWhatApiServes(t *testing.T) {
	api := NewFakeHeadCheckApi(testHeadNetworkId)
	api.Append(10)
	writer := NewFakeHeadCheckAuth(testHeadWriter, api)
	if err := writer.FetchAuth(context.Background(), api.Tip()); err != nil {
		t.Fatal(err)
	}
	if pin := writer.Pin(); pin.GetVersion() != 10 || !bytes.Equal(pin.GetChain(), api.Tip().GetChain()) {
		t.Fatalf("pin %v", pin)
	}
	// api withholds past 12 from the writer, not from the holder
	api.Withhold(testHeadWriter, 12)
	api.Append(8)
	holder := NewFakeHeadCheckAuth(testHeadHolder, api)
	if err := holder.FetchAuth(context.Background(), api.Tip()); err != nil || holder.Pin().GetVersion() != 18 {
		t.Fatalf("holder at %d: %v", holder.Pin().GetVersion(), err)
	}
	if err := writer.FetchAuth(context.Background(), api.Tip()); err != nil || writer.Pin().GetVersion() != 12 {
		t.Fatalf("writer at %d: %v", writer.Pin().GetVersion(), err)
	}
	for k := uint64(0); k <= 12; k += 1 {
		if chain, kept := writer.ChainAt(k); !kept || !bytes.Equal(chain, api.Pin(k).GetChain()) {
			t.Fatalf("A_%d", k)
		}
	}
	if _, kept := writer.ChainAt(13); kept {
		t.Error("a digest past the pin")
	}
	api.Serve(testHeadWriter)
	if err := writer.FetchAuth(context.Background(), api.Tip()); err != nil || writer.Pin().GetVersion() != 18 {
		t.Fatalf("writer once served at %d: %v", writer.Pin().GetVersion(), err)
	}
}

func TestFakeHeadCheckAuthRefusesAFork(t *testing.T) {
	api := NewFakeHeadCheckApi(testHeadNetworkId)
	api.Append(6)
	split := api.Fork(4, "split")
	split.Append(4)
	device := NewFakeHeadCheckAuth(testHeadWriter, split)
	if err := device.FetchAuth(context.Background(), split.Tip()); err != nil {
		t.Fatal(err)
	}
	other := NewFakeHeadCheckAuth(testHeadHolder, api)
	other.api = api
	if err := other.ReachFromApi(6); err != nil {
		t.Fatal(err)
	}
	// both hold position 5 with different digests; position 4 is shared
	five, _ := device.ChainAt(5)
	otherFive, _ := other.ChainAt(5)
	four, _ := device.ChainAt(4)
	otherFour, _ := other.ChainAt(4)
	if bytes.Equal(five, otherFive) || !bytes.Equal(four, otherFour) {
		t.Fatal("the fork is not after 4")
	}
	// a device on the split fetching main's history, once main passes its pin, refuses what follows
	device.api = api
	api.Append(6)
	if err := device.FetchAuth(context.Background(), api.Tip()); !errors.Is(err, ErrFakeHeadCheckFork) {
		t.Fatalf("err %v", err)
	}
}

func TestFakeHeadCheckProofsServeAndVerify(t *testing.T) {
	api := NewFakeHeadCheckApi(testHeadNetworkId)
	api.Append(10)
	writer := NewFakeHeadCheckAuth(testHeadWriter, api)
	if err := writer.FetchAuth(context.Background(), api.Tip()); err != nil {
		t.Fatal(err)
	}
	api.Withhold(testHeadWriter, 10)
	tip := api.Append(5)
	holder := NewFakeHeadCheckAuth(testHeadHolder, api)
	if err := holder.FetchAuth(context.Background(), tip); err != nil {
		t.Fatal(err)
	}
	proof, err := holder.AuthProof(writer.Pin().GetVersion())
	if err != nil || len(proof) != 5 {
		t.Fatalf("proof %d: %v", len(proof), err)
	}
	if err := writer.VerifyAuthProof(context.Background(), proof, tip); err != nil {
		t.Fatalf("a good proof: %v", err)
	}
	// verifying applies nothing
	if writer.Pin().GetVersion() != 10 {
		t.Fatal("verifying applied the proof")
	}
	// a proof missing an entry, or to another pin, does not verify
	if err := writer.VerifyAuthProof(context.Background(), proof[1:], tip); !errors.Is(err, sidecar.ErrHeadCheckProofInvalid) {
		t.Errorf("a gap: %v", err)
	}
	if err := writer.VerifyAuthProof(context.Background(), proof, api.Pin(14)); !errors.Is(err, sidecar.ErrHeadCheckProofInvalid) {
		t.Errorf("another pin: %v", err)
	}
	tampered := bytes.Clone(proof[2])
	tampered[len(tampered)-1] ^= 1
	if err := writer.VerifyAuthProof(context.Background(), [][]byte{proof[0], proof[1], tampered, proof[3], proof[4]}, tip); !errors.Is(err, sidecar.ErrHeadCheckProofInvalid) {
		t.Errorf("a tampered entry: %v", err)
	}
	// a holder whose kept entries do not reach back that far within its retain bytes answers NOT_FOUND
	holder.SetRetainByteCount(len(proof[0]) * 3)
	if _, err := holder.AuthProof(10); !errors.Is(err, sidecar.ErrHeadCheckProofNotFound) {
		t.Errorf("past the retain bytes: %v", err)
	}
	if proof, err := holder.AuthProof(12); err != nil || len(proof) != 3 {
		t.Errorf("within them: %d, %v", len(proof), err)
	}
	holder.SetRetainByteCount(sidecar.HeadCheckMaxProofByteCount)
	holder.Forget(12)
	if _, err := holder.AuthProof(10); !errors.Is(err, sidecar.ErrHeadCheckProofNotFound) {
		t.Errorf("before what it keeps: %v", err)
	}
}

func TestFakeHeadCheckVetoes(t *testing.T) {
	auth := NewFakeHeadCheckAuth(testHeadWriter, NewFakeHeadCheckApi(testHeadNetworkId))
	auth.SetVetoes([][]byte{[]byte("mine")})
	if vetoes := auth.Vetoes(); len(vetoes) != 1 {
		t.Fatalf("vetoes %q", vetoes)
	}
	if err := auth.HoldVeto(context.Background(), nil); err == nil {
		t.Error("an empty veto held")
	}
	if err := auth.HoldVeto(context.Background(), []byte("theirs")); err != nil {
		t.Fatal(err)
	}
	if held := auth.HeldVetoes(); len(held) != 1 || string(held[0]) != "theirs" {
		t.Errorf("held %q", held)
	}
}

func TestFakeHeadCheckHeadsCatchUpFromTheStore(t *testing.T) {
	heads := NewFakeHeadCheckHeads()
	groupId := sidecar.Id{0x6a}
	gen := func(generation uint64, commitment byte) *protocol.GenHead {
		return &protocol.GenHead{GroupId: groupId.Bytes(), Generation: generation, Commitment: bytes.Repeat([]byte{commitment}, 32)}
	}
	heads.SetGen(gen(3, 3))
	heads.StoreGen(gen(5, 5))
	if outcome, _ := heads.CatchUpGen(context.Background(), gen(4, 4)); outcome != sidecar.HeadCheckCatchUpUnserved {
		t.Errorf("unserved: %v", outcome)
	}
	if outcome, _ := heads.CatchUpGen(context.Background(), gen(5, 9)); outcome != sidecar.HeadCheckCatchUpForked {
		t.Errorf("forked: %v", outcome)
	}
	if outcome, _ := heads.CatchUpGen(context.Background(), gen(5, 5)); outcome != sidecar.HeadCheckCaughtUp {
		t.Errorf("reached: %v", outcome)
	}
	if mine, held := heads.GenHead(groupId); !held || mine.GetGeneration() != 5 {
		t.Errorf("pin %v", mine)
	}
	if _, held := heads.GenHead(sidecar.Id{0x99}); held {
		t.Error("a pin never set")
	}

	repoId, refId := sidecar.Id{0x7a}, sidecar.Id{0x7b}
	ref := func(version uint64, chain byte) *protocol.RefHead {
		return &protocol.RefHead{RepoId: repoId.Bytes(), RefId: refId.Bytes(), Version: version, Chain: bytes.Repeat([]byte{chain}, 32)}
	}
	heads.SetRef(ref(1, 1), groupId)
	heads.StoreRef(ref(4, 4))
	if outcome, _ := heads.CatchUpRef(context.Background(), ref(4, 8)); outcome != sidecar.HeadCheckCatchUpForked {
		t.Errorf("ref forked: %v", outcome)
	}
	if outcome, _ := heads.CatchUpRef(context.Background(), ref(4, 4)); outcome != sidecar.HeadCheckCaughtUp {
		t.Errorf("ref reached: %v", outcome)
	}
	if mine, held := heads.RefHead(repoId, refId); !held || mine.Head.GetVersion() != 4 || mine.GroupId != groupId {
		t.Errorf("ref pin %+v", mine)
	}

	heads.SetGroup(&protocol.GroupHead{GroupId: groupId.Bytes(), Epoch: 2, EpochAuthenticator: []byte{2}})
	if groups := heads.GroupHeads(testHeadHolder); len(groups) != 1 || groups[0].GetEpoch() != 2 {
		t.Errorf("groups %v", groups)
	}
	if len(heads.GenHeads(testHeadHolder)) != 1 || len(heads.RefHeads(testHeadHolder)) != 1 {
		t.Error("listings")
	}
}

func TestFakeHeadCheckDeviceSourcesAreComplete(t *testing.T) {
	device := NewFakeHeadCheckDevice(testHeadWriter, NewFakeHeadCheckApi(testHeadNetworkId))
	device.Peers.Admit(testHeadHolder)
	device.Peers.Set(testHeadWriter, sidecar.HeadCheckPeer{Admitted: true, Suspended: true})
	sources := device.Sources()
	if sources.Auth == nil || sources.Gens == nil || sources.Groups == nil || sources.Refs == nil || sources.Peers == nil {
		t.Fatal("a source missing")
	}
	if peer := sources.Peers.HeadCheckPeer(testHeadHolder); !peer.Admitted || peer.Revoked {
		t.Errorf("holder %+v", peer)
	}
	if peer := sources.Peers.HeadCheckPeer(sidecar.Id{0x44}); peer.Admitted {
		t.Errorf("a stranger %+v", peer)
	}
}
