// EVSB-M2-20's tests of the Signed EvsReseed's shape (evs_reseed_statement.go): what a repo admin's device signs is
// what evs parses, tells from a re-seeded push, and verifies under the admin's key alone, and what a reader's
// AcceptReseed takes; and the reader's side of the frame evs serves after a head below a pin (evs_read.go). The walk
// itself, EvsRepo.Reseed against evsservice's route, is sidecartest's (evs_reseed_world_test.go).

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
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

// evs as a reader meets it after a site loss: the world's own answers until the site is lost, then the head a
// re-seed returned for every read, with the frames given after it when it lies below the request's pin_version.
type evsTestLostSite struct {
	world *evsTestWorld

	stateLock sync.Mutex
	head      *protocol.EvsHeadSummary
	after     []*protocol.EvsReadFrame
	// each read's pin_version since the loss
	pinVersions []uint64
}

func (self *evsTestLostSite) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	self.stateLock.Lock()
	head, after := self.head, self.after
	self.stateLock.Unlock()
	if head == nil {
		self.world.ServeHTTP(writer, request)
		return
	}
	if request.Method != http.MethodPost || !strings.HasSuffix(request.URL.Path, "/read") {
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	body, _ := io.ReadAll(request.Body)
	read := &protocol.EvsReadRequest{}
	if err := proto.Unmarshal(body, read); err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	self.stateLock.Lock()
	self.pinVersions = append(self.pinVersions, read.GetPinVersion())
	self.stateLock.Unlock()
	frames := []*protocol.EvsReadFrame{{Head: head}}
	if head.GetVersion() < read.GetPinVersion() {
		frames = append(frames, after...)
	}
	frames = append(frames, &protocol.EvsReadFrame{End: true})
	writer.WriteHeader(http.StatusOK)
	for _, frame := range frames {
		encoded, err := EncodeEvsReadFrame(frame)
		if err != nil {
			self.world.t.Error(err)
			return
		}
		writer.Write(encoded)
	}
}

// The site lost: reads answer head, followed by after below a pin.
func (self *evsTestLostSite) lose(head *protocol.EvsHeadSummary, after ...*protocol.EvsReadFrame) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.head, self.after, self.pinVersions = head, after, nil
}

func (self *evsTestLostSite) asked() []uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]uint64{}, self.pinVersions...)
}

func evsTestReseedFrame(refId Id, statement []byte) *protocol.EvsReadFrame {
	return &protocol.EvsReadFrame{Object: &protocol.EvsReadObject{Kind: protocol.EvsReadObjectKind_EVS_READ_OBJECT_RESEED, Id: refId.Bytes(), Body: statement}}
}

// A reader pinned above the head a site loss left refuses that head as a fork, with no statement, with a reply
// carrying a reseed frame out of shape, and with a statement that no repo admin signed or that names another head;
// under the admin's statement of exactly that head its own read lowers the pin to it, kept as a loss, and reads on
// from there.
func TestEvsReaderTakesAHeadBelowItsPinOnlyUnderTheServedReseed(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("1")})
	world.stateLock.Lock()
	low := proto.Clone(world.headSummaryWithLock()).(*protocol.EvsHeadSummary)
	world.stateLock.Unlock()
	lowChain := world.commits[0].chain
	world.push(&evsTestChange{path: "a.txt", content: []byte("2")})
	world.config.repo.Admins = []*protocol.AclRepoAdminRow{{SidecarId: world.signer.sidecarId.Bytes()}}

	site := &evsTestLostSite{world: world}
	reader := newEvsTestClient(t, site, newEvsTestStore(t))
	reader.client.args.Gkm = world.gkm
	reader.client.args.Config = func() GkmAuthView { return world.config }
	identity := &SidecarIdentity{NetworkId: testNetworkId, SidecarId: evsTestId("reader"), ClientId: evsTestId("reader client")}
	reader.client.args.Identity = func() *SidecarIdentity { return identity }
	repo := reader.client.Repo(world.repoId)
	ctx := context.Background()
	if head, err := repo.readHeadAlone(ctx, world.refId, true); err != nil || head.Version != 2 {
		t.Fatalf("the head before the loss: %v", err)
	}
	pinOf := func() *EvsPin {
		t.Helper()
		pin, pinned, err := reader.client.pins.Pin(world.repoId, world.refId)
		if err != nil || !pinned {
			t.Fatalf("the reader's pin: %v %v", pinned, err)
		}
		return pin
	}
	refused := func(what string, want error, after ...*protocol.EvsReadFrame) {
		t.Helper()
		site.lose(low, after...)
		if _, err := repo.readHeadAlone(ctx, world.refId, true); !errors.Is(err, want) {
			t.Fatalf("%s: %v, want %v", what, err, want)
		}
		if pin := pinOf(); pin.Version != 2 || pin.Loss != nil {
			t.Fatalf("%s moved the pin to %d", what, pin.Version)
		}
	}
	sign := func(sign EvsSignFunction, version uint64) []byte {
		t.Helper()
		signedBytes, err := SignEvsReseed(sign, world.repoId, world.refId, version, lowChain, []byte("incident"))
		if err != nil {
			t.Fatal(err)
		}
		return signedBytes
	}
	admin := sign(world.signer.sign, 1)
	other := newEvsTestSigner("no admin")
	world.config.identityKeys[other.sidecarId] = other.publicKey()

	refused("no statement", ErrEvsHeadForked)
	if asked := site.asked(); len(asked) != 1 || asked[0] != 2 {
		t.Fatalf("a read from the ref's pin with no statement asked %v", asked)
	}
	refused("a non-admin's statement", ErrEvsHeadForked, evsTestReseedFrame(world.refId, sign(other.sign, 1)))
	refused("a statement of another head", ErrEvsHeadForked, evsTestReseedFrame(world.refId, sign(world.signer.sign, 2)))
	refused("bytes that are no statement", ErrEvsHeadForked, evsTestReseedFrame(world.refId, []byte("no statement")))
	refused("two reseed frames", ErrEvsReplyInvalid, evsTestReseedFrame(world.refId, admin), evsTestReseedFrame(world.refId, admin))
	refused("a reseed frame past its bound", ErrEvsReplyInvalid,
		evsTestReseedFrame(world.refId, bytes.Repeat([]byte{1}, DefaultEvsFormatSettings().ReseedStatementMaxByteCount+1)))
	refused("an empty reseed frame", ErrEvsReplyInvalid, evsTestReseedFrame(world.refId, nil))
	continued := evsTestReseedFrame(world.refId, admin)
	continued.Object.Offset = 1
	refused("a reseed frame at an offset", ErrEvsReplyInvalid, continued)
	if alarms := reader.eventsOf(SidecarEventHeadAlarm); len(alarms) != 4 {
		t.Fatalf("%d head alarms for 4 heads refused below the pin", len(alarms))
	}

	site.lose(low, evsTestReseedFrame(world.refId, admin))
	head, err := repo.readHeadAlone(ctx, world.refId, true)
	if err != nil || head.Version != 1 || head.Chain != lowChain {
		t.Fatalf("the head under the admin's EvsReseed: %+v, %v", head, err)
	}
	pin := pinOf()
	if pin.Version != 1 || pin.Chain != lowChain || pin.Loss == nil || pin.Loss.FromVersion != 2 || !bytes.Equal(pin.Loss.IncidentId, []byte("incident")) {
		t.Fatalf("the pin under the admin's EvsReseed: %+v, loss %+v", pin, pin.Loss)
	}
	// once from the old pin, which the statement answered, and again from the lowered one
	if asked := site.asked(); len(asked) != 2 || asked[0] != 2 || asked[1] != 1 {
		t.Fatalf("the accepted read asked from %v", asked)
	}
	if alarms := reader.eventsOf(SidecarEventHeadAlarm); len(alarms) != 4 {
		t.Fatalf("%d head alarms after the accepted reseed", len(alarms))
	}
	// the loss is kept as the pin rises again
	if _, err := repo.readHeadAlone(ctx, world.refId, true); err != nil {
		t.Fatal(err)
	}
	if pin := pinOf(); pin.Version != 1 || pin.Loss == nil {
		t.Fatalf("the pin after the next read: %+v", pin)
	}
}

// The head an export and a mirror sync start from (pinnedHead) names no pin in its read, so a head below the pin
// brings a second read that does: refused as a fork with no statement, taken under the admin's.
func TestEvsPinnedHeadTakesAHeadBelowItsPinUnderTheServedReseed(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("1")})
	world.stateLock.Lock()
	low := proto.Clone(world.headSummaryWithLock()).(*protocol.EvsHeadSummary)
	world.stateLock.Unlock()
	lowChain := world.commits[0].chain
	world.push(&evsTestChange{path: "a.txt", content: []byte("2")})
	world.config.repo.Admins = []*protocol.AclRepoAdminRow{{SidecarId: world.signer.sidecarId.Bytes()}}

	site := &evsTestLostSite{world: world}
	reader := newEvsTestClient(t, site, newEvsTestStore(t))
	reader.client.args.Gkm = world.gkm
	reader.client.args.Config = func() GkmAuthView { return world.config }
	identity := &SidecarIdentity{NetworkId: testNetworkId, SidecarId: evsTestId("reader"), ClientId: evsTestId("reader client")}
	reader.client.args.Identity = func() *SidecarIdentity { return identity }
	repo := reader.client.Repo(world.repoId)
	ctx := context.Background()
	if head, err := repo.readHeadAlone(ctx, world.refId, true); err != nil || head.Version != 2 {
		t.Fatalf("the head before the loss: %v", err)
	}

	site.lose(low)
	if _, err := repo.pinnedHead(ctx, world.refId); !errors.Is(err, ErrEvsHeadForked) {
		t.Fatalf("a head below the pin with no statement: %v", err)
	}
	// once naming no pin, and again from the pin for the statement
	if asked := site.asked(); len(asked) != 2 || asked[0] != 0 || asked[1] != 2 {
		t.Fatalf("with no statement it asked from %v", asked)
	}
	statement, err := SignEvsReseed(world.signer.sign, world.repoId, world.refId, 1, lowChain, []byte("incident"))
	if err != nil {
		t.Fatal(err)
	}
	site.lose(low, evsTestReseedFrame(world.refId, statement))
	head, err := repo.pinnedHead(ctx, world.refId)
	if err != nil || head.Version != 1 || head.Chain != lowChain {
		t.Fatalf("the head under the admin's EvsReseed: %+v, %v", head, err)
	}
	pin, pinned, err := reader.client.pins.Pin(world.repoId, world.refId)
	if err != nil || !pinned || pin.Version != 1 || pin.Loss == nil || pin.Loss.FromVersion != 2 {
		t.Fatalf("the pin under the admin's EvsReseed: %+v, %v", pin, err)
	}
	if asked := site.asked(); len(asked) != 3 || asked[0] != 0 || asked[1] != 2 || asked[2] != 0 {
		t.Fatalf("the accepted read asked from %v", asked)
	}
}
