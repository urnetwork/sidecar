// EVSB-M2-20's tests of the Signed EvsReseed's shape (evs_reseed_statement.go): what a repo admin's device signs is
// what evs parses, tells from a re-seeded push, and verifies under the admin's key alone, and what a reader's
// AcceptReseed takes. The walk itself, EvsRepo.Reseed against evsservice's route, is sidecartest's
// (evs_reseed_world_test.go).

package sidecar

import (
	"bytes"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

func TestEvsReseedStatementSignsParsesAndVerifies(t *testing.T) {
	admin := newEvsTestSigner("reseed admin")
	other := newEvsTestSigner("reseed other")
	repoId, refId := evsTestId("reseed repo"), evsTestId("reseed ref")
	chain := EvsChainNext(EvsChainStart(repoId, refId), evsTestId("reseed push"), EvsStatementSha256([]byte("statement")))
	signedBytes, err := SignEvsReseed(admin.sign, repoId, refId, 7, chain, []byte("incident 1"))
	if err != nil {
		t.Fatal(err)
	}
	if !EvsSignedIsReseed(signedBytes) {
		t.Fatal("a Signed EvsReseed is not told as one")
	}
	statement, err := ParseEvsReseedStatement(signedBytes, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if statement.RepoId != repoId || statement.RefId != refId || statement.Version != 7 || statement.Chain != chain ||
		statement.SignerSidecarId != admin.sidecarId || !bytes.Equal(statement.Reseed.GetIncidentId(), []byte("incident 1")) ||
		!bytes.Equal(statement.Bytes, signedBytes) {
		t.Fatalf("parsed %+v", statement)
	}
	if err := statement.Verify(admin.publicKey()); err != nil {
		t.Fatalf("under the signer's key: %v", err)
	}
	if err := statement.Verify(other.publicKey()); !errors.Is(err, ErrEvsStatementRefused) {
		t.Fatalf("under another key: %v", err)
	}
	if err := statement.Verify(nil); !errors.Is(err, ErrEvsStatementRefused) {
		t.Fatalf("under no key: %v", err)
	}

	// past its bound, of another type, with no version, and with a chain or an id of another width
	if _, err := ParseEvsReseedStatement(signedBytes, len(signedBytes)-1); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("past the bound: %v", err)
	}
	if _, err := ParseEvsReseedStatement(nil, 4096); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("no bytes: %v", err)
	}
	signedAs := func(signedType bridge.SignedType, reseed *protocol.EvsReseed) []byte {
		body, err := proto.Marshal(reseed)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := admin.sign(evsReseedPurpose, signedType, body, nil)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := proto.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	whole := func() *protocol.EvsReseed {
		return &protocol.EvsReseed{RepoId: repoId.Bytes(), RefId: refId.Bytes(), Version: 7, Chain: chain[:]}
	}
	push := signedAs(bridge.SignedType_SIGNED_EVS_PUSH, whole())
	if EvsSignedIsReseed(push) || EvsSignedIsReseed([]byte("no Signed at all")) {
		t.Error("another statement is told as an EvsReseed")
	}
	if _, err := ParseEvsReseedStatement(push, 4096); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("another type: %v", err)
	}
	for label, mutate := range map[string]func(reseed *protocol.EvsReseed){
		"no version":    func(reseed *protocol.EvsReseed) { reseed.Version = 0 },
		"a short chain": func(reseed *protocol.EvsReseed) { reseed.Chain = reseed.Chain[:16] },
		"no repo":       func(reseed *protocol.EvsReseed) { reseed.RepoId = nil },
		"a short ref":   func(reseed *protocol.EvsReseed) { reseed.RefId = reseed.RefId[:8] },
	} {
		reseed := whole()
		mutate(reseed)
		if _, err := ParseEvsReseedStatement(signedAs(bridge.SignedType_SIGNED_EVS_RESEED, reseed), 4096); !errors.Is(err, ErrEvsPushInvalid) {
			t.Errorf("%s: %v", label, err)
		}
	}
	if _, err := SignEvsReseed(nil, repoId, refId, 7, chain, nil); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("no signer: %v", err)
	}
}

// What SignEvsReseed makes is what a reader's AcceptReseed takes for the head it names, from a repo admin.
func TestEvsReseedSignedStatementIsWhatAReaderAccepts(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("1")})
	world.push(&evsTestChange{path: "a.txt", content: []byte("2")})
	reader := world.reader(t, evsTestId("reader"))
	if _, _, err := evsTestRead(t, reader, world, "a.txt"); err != nil {
		t.Fatal(err)
	}
	lowChain := world.commits[0].chain
	low := &protocol.EvsHeadSummary{RefId: world.refId.Bytes(), Version: 1, Chain: lowChain[:]}
	signedBytes, err := SignEvsReseed(world.signer.sign, world.repoId, world.refId, 1, lowChain, []byte("incident"))
	if err != nil {
		t.Fatal(err)
	}
	if EvsRepoAdminIn(world.config, world.repoId, world.signer.sidecarId) {
		t.Fatal("the signer is an admin before its row")
	}
	world.config.repo.Admins = []*protocol.AclRepoAdminRow{{SidecarId: world.signer.sidecarId.Bytes()}}
	if !EvsRepoAdminIn(world.config, world.repoId, world.signer.sidecarId) || EvsRepoAdminIn(world.config, world.repoId, evsTestId("reader")) ||
		EvsRepoAdminIn(nil, world.repoId, world.signer.sidecarId) {
		t.Fatal("the repo's admins are not its standing admin rows")
	}
	if err := reader.client.verifier.AcceptReseed(signedBytes, world.repoId, world.refId, low); err != nil {
		t.Fatal(err)
	}
	pin, _, _ := reader.client.pins.Pin(world.repoId, world.refId)
	if pin.Version != 1 || pin.Loss == nil {
		t.Errorf("after the reseed: %+v", pin)
	}
}
