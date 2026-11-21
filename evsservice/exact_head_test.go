package evsservice

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The same authenticated routes and file-mode rules apply to both storage formats.
func TestPushExactHeadAndOrdinaryDisjointWrites(t *testing.T) {
	for _, format := range []uint32{sidecar.EvsRepoFormat1, sidecar.EvsRepoFormat2} {
		fixture := newPushFixture(t, func(settings *EvsSettings) { settings.InstanceFormat = format })
		token := fixture.token(fixture.check.signerId)
		read := &protocol.EvsReadRequest{RefId: fixture.check.refId.Bytes(), Fresh: true}
		head := fixture.read(token, read).head
		genesis := sidecar.EvsChainStart(fixture.check.repoId, fixture.check.refId)
		if !head.GetSupportsExactHead() || head.GetVersion() != 0 || !bytes.Equal(head.GetChain(), genesis[:]) {
			t.Fatalf("format %d genesis: %v", format, head)
		}
		first := fixture.plan()
		first.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_EXACT_HEAD)
		fixture.create(first, "first")
		firstBody := fixture.body(first)
		fixture.requireCommitted(fixture.post(token, firstBody), 1)
		fixture.awaitStepEights()
		head = fixture.read(token, read).head
		if !head.GetSupportsExactHead() || head.GetVersion() != 1 || !bytes.Equal(head.GetChain(), fixture.head().Head.GetChain()) {
			t.Fatalf("format %d first commit: %v", format, head)
		}

		confirmed := fixture.plan()
		confirmed.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_EXACT_HEAD)
		fixture.create(confirmed, "confirmed")
		wrongChain := fixture.plan()
		wrongChain.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_EXACT_HEAD)
		wrongChain.BaseChain[0] ^= 1
		fixture.create(wrongChain, "wrong-chain")
		requireRefusal(t, fixture.push(wrongChain), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE)
		ordinary := fixture.plan()
		fixture.create(ordinary, "independent")
		fixture.commitOne(protocol.EvsRefMode_EVS_REF_FILE, "elsewhere")
		before := fixture.head()
		refused := fixture.push(confirmed)
		requireRefusal(t, refused, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE)
		if refusalOf(t, refused).GetRecorded() || fixture.head().Etag != before.Etag {
			t.Fatalf("format %d: stale confirmation changed the head", format)
		}
		fixture.requireCommitted(fixture.push(ordinary), 3)
		// A retry of the exact byte-identical first push still returns its original version.
		fixture.requireCommitted(fixture.post(token, firstBody), 1)
		read.Fresh = false
		if fixture.read(token, read).head.GetSupportsExactHead() {
			t.Fatalf("format %d: capability on a non-fresh read", format)
		}
	}
}

func TestReadExactHeadCapabilityRequiresFreshAuthorizedFileRead(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	read := &protocol.EvsReadRequest{RefId: fixture.check.refId.Bytes(), Fresh: true}
	requireRefusal(t, fixture.call("", http.MethodPost, "/read", read), http.StatusUnauthorized, protocol.EvsRefusalCode_EVS_REFUSAL_UNAUTHENTICATED)
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_GIT, "git-file")
	if fixture.read(token, read).head.GetSupportsExactHead() {
		t.Fatal("a git-mode head advertised the file-mode precondition")
	}
}

func TestPushExactHeadRetainsFormatRestrictions(t *testing.T) {
	fixture := newFormat1PushFixture(t)
	fixture.openFormat2()
	plan := fixture.plan()
	plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_EXACT_HEAD)
	fixture.createVersionless(plan, "versionless")
	reply := fixture.post(fixture.token(fixture.check.signerId), fixture.bodyFormat2(plan))
	requireRefusal(t, reply, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_FORMAT_UNSUPPORTED)
	if refusalOf(t, reply).GetNeedsFormat() != sidecar.EvsRepoFormat2 || fixture.head().Version() != 0 {
		t.Fatal("a format-2 write escaped the format-1 guard")
	}
}

func TestSealExactHeadAfterInterveningCommit(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_FILE, "seed")
	plan := fixture.partsPlan(protocol.EvsRefMode_EVS_REF_FILE, sidecar.DefaultEvsFormatSettings().PartMaxEntryWriteCount+1)
	plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_EXACT_HEAD)
	built := fixture.built(plan)
	if len(built.Parts) < 2 {
		t.Fatalf("got %d parts", len(built.Parts))
	}
	places := fixture.postParts(token, built)
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_FILE, "elsewhere")
	prior := fixture.head()
	requireRefusal(t, fixture.seal(token, built, places), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE)
	if fixture.head().Etag != prior.Etag {
		t.Fatal("a stale seal changed the head")
	}
	fresh := fixture.partsPlan(protocol.EvsRefMode_EVS_REF_FILE, sidecar.DefaultEvsFormatSettings().PartMaxEntryWriteCount+1)
	fresh.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_EXACT_HEAD)
	built = fixture.built(fresh)
	places = fixture.postParts(token, built)
	fixture.requireCommitted(fixture.seal(token, built, places), 3)
	fixture.awaitStepEights()
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_FILE, "later")
	fixture.requireCommitted(fixture.seal(token, built, places), 3)
}
