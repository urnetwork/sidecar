package gkmservice

import (
	"bytes"
	"net/http"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A group world created, active, and its admin's MLS group at epoch 0.
func newGkmCommitWorld(t *testing.T) *gkmGroupWorld {
	world := newGkmGroupWorld(t)
	world.createAndActivate()
	world.startMlsGroup()
	return world
}

// §22.5's one commit per epoch: the first commit for an epoch wins, and the second gets 409 with the winner, which
// it processes (KF6).
func TestGkmOneCommitPerEpoch(t *testing.T) {
	world := newGkmCommitWorld(t)
	first := world.stageSelfUpdate(1, fakeGkmPin(10))
	first.Discard()
	second := world.stageSelfUpdate(1, fakeGkmPin(10))
	if recorder := world.postEpoch(world.adminToken, 1, gkmTestEpochRequest(first.Message(), 1, false)); recorder.Code != http.StatusOK {
		t.Fatalf("the first commit to epoch 1: %d", recorder.Code)
	}
	recorder := world.postEpoch(world.adminToken, 1, gkmTestEpochRequest(second.Message(), 1, false))
	if recorder.Code != http.StatusConflict {
		t.Fatalf("the second commit to epoch 1: %d", recorder.Code)
	}
	winner, err := parseGkmEpochObject(recorder.Body.Bytes())
	if err != nil || !bytes.Equal(winner.GetCommit(), first.Message()) {
		t.Errorf("the 409 does not carry the winner: %v", err)
	}
	if stored := world.storedEpoch(1); stored == nil || !bytes.Equal(stored.GetCommit(), first.Message()) {
		t.Errorf("epoch/1 does not hold the winner")
	}
	// a commit with no epoch to commit onto
	if recorder := world.postEpoch(world.adminToken, 3, gkmTestEpochRequest(first.Message(), 1, false)); recorder.Code != http.StatusBadRequest {
		t.Errorf("a commit sent in epoch 0 posted as epoch 3: %d", recorder.Code)
	}
}

// FI-2: a commit whose answer was lost is sent again and answers the original 200, and one epoch object stands.
func TestGkmCommitRetryAnswersTheOriginalResult(t *testing.T) {
	world := newGkmCommitWorld(t)
	fixture := world.fixture
	staged := world.stageSelfUpdate(1, fakeGkmPin(10))
	request := gkmTestEpochRequest(staged.Message(), 1, false)
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op:        sidecartest.FaultOpPut,
		KeyPrefix: GkmEpochKey(world.groupId, 1),
		Result:    sidecartest.ApplyThenDrop,
	}); err != nil {
		t.Fatal(err)
	}
	first := world.postEpoch(world.adminToken, 1, request)
	if first.Code != http.StatusOK {
		t.Fatalf("a commit whose PUT's answer was lost: %d", first.Code)
	}
	fixture.clock.Advance(time.Second)
	if recorder := world.postEpoch(world.adminToken, 1, request); recorder.Code != http.StatusOK {
		t.Errorf("the commit sent again: %d", recorder.Code)
	}
	if stored := world.storedEpoch(1); stored == nil || !bytes.Equal(stored.GetCommit(), staged.Message()) {
		t.Errorf("epoch/1 does not hold the commit")
	}
}

// I-1, §10.6: a member's commit is stored as the PrivateMessage it arrived as, so gkm holds its group, epoch and
// header in the clear and nothing of the roster or the path.
func TestGkmStoredCommitIsAPrivateMessage(t *testing.T) {
	world := newGkmCommitWorld(t)
	world.commitAndAdopt(1, true)
	stored := world.storedEpoch(1)
	if stored == nil {
		t.Fatal("no epoch/1")
	}
	header, err := sidecar.ParseMlsHeader(stored.GetCommit())
	if err != nil {
		t.Fatal(err)
	}
	if header.External != nil || header.Epoch != 0 || !bytes.Equal(header.GroupId, world.groupId.Bytes()) {
		t.Errorf("the stored commit is not a member's PrivateMessage of epoch 0")
	}
	if !bytes.Equal(header.AuthenticatedData, gkmTestCommitHeader(t, 1, fakeGkmPin(10))) {
		t.Errorf("the stored commit's header is not its own")
	}
	if !bytes.Contains(stored.GetCommit(), world.groupId.Bytes()) || bytes.Contains(stored.GetCommit(), world.admin.publicKey) {
		t.Errorf("the stored commit shows its committer's identity key in the clear")
	}
}

// FS-15's half and §10.6's epoch PUT check: a commit below its predecessor's generation, or below gen/'s newest, is
// refused, and one at gen/'s newest passes.
func TestGkmCommitBelowItsPredecessorsGenerationIsRefused(t *testing.T) {
	world := newGkmCommitWorld(t)
	world.commitAndAdopt(1, false)
	world.putGeneration(world.admin, world.key1)
	stale := world.stageSelfUpdate(1, fakeGkmPin(10))
	if recorder := world.postEpoch(world.adminToken, 2, gkmTestEpochRequest(stale.Message(), 1, false)); recorder.Code != http.StatusForbidden {
		t.Errorf("a commit at generation 1 with gen/2 standing: %d", recorder.Code)
	}
	stale.Discard()
	world.commitAndAdopt(2, false)
	below := world.stageSelfUpdate(1, fakeGkmPin(10))
	if recorder := world.postEpoch(world.adminToken, 3, gkmTestEpochRequest(below.Message(), 1, false)); recorder.Code != http.StatusForbidden {
		t.Errorf("a commit below its predecessor's generation: %d", recorder.Code)
	}
	below.Discard()
	ahead := world.stageSelfUpdate(3, fakeGkmPin(10))
	if recorder := world.postEpoch(world.adminToken, 3, gkmTestEpochRequest(ahead.Message(), 3, false)); recorder.Code != http.StatusForbidden {
		t.Errorf("a commit naming a generation gen/ does not hold: %d", recorder.Code)
	}
	if world.storedEpoch(3) != nil {
		t.Errorf("a refused commit was stored")
	}
}

// No commit past the projection: a commit's pin past gkm's newest state waits (503), one off its chain or before the
// previous base is refused, and a pin below its predecessor's falls and is refused.
func TestGkmCommitPastTheProjectionIsRefused(t *testing.T) {
	world := newGkmCommitWorld(t)
	fixture := world.fixture
	ahead := world.stageSelfUpdate(1, fakeGkmPin(11))
	if recorder := world.postEpoch(world.adminToken, 1, gkmTestEpochRequest(ahead.Message(), 1, false)); recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("a commit at a pin past gkm's state: %d", recorder.Code)
	}
	ahead.Discard()
	offChain := fakeGkmPin(9)
	offChain.Chain = fakeGkmChain(99)
	forked := world.stageSelfUpdate(1, offChain)
	if recorder := world.postEpoch(world.adminToken, 1, gkmTestEpochRequest(forked.Message(), 1, false)); recorder.Code != http.StatusForbidden {
		t.Errorf("a commit at a pin off the chain: %d", recorder.Code)
	}
	forked.Discard()
	if world.storedEpoch(1) != nil {
		t.Fatalf("a refused commit was stored")
	}
	fixture.auth.advanceLog(12, 1)
	staged := world.stageSelfUpdate(1, fakeGkmPin(12))
	if recorder := world.postEpoch(world.adminToken, 1, gkmTestEpochRequest(staged.Message(), 1, false)); recorder.Code != http.StatusOK {
		t.Fatalf("a commit at the newest pin: %d", recorder.Code)
	}
	group, err := staged.Adopt()
	if err != nil {
		t.Fatal(err)
	}
	world.mlsGroup = group
	falling := world.stageSelfUpdate(1, fakeGkmPin(11))
	if recorder := world.postEpoch(world.adminToken, 2, gkmTestEpochRequest(falling.Message(), 1, false)); recorder.Code != http.StatusForbidden {
		t.Errorf("a commit whose pin falls below its predecessor's: %d", recorder.Code)
	}
}

// §10.6's one exception, §10.8: a generation-0 external commit with no GenWrap passes only from a device its member's
// recovery key admitted, and a member's commit never says generation 0.
func TestGkmGenerationZeroCommitOnlyFromARecoveryAdmittedDevice(t *testing.T) {
	world := newGkmCommitWorld(t)
	fixture := world.fixture
	world.commitAndAdopt(1, false)
	groupInfo, err := world.mlsGroup.GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	selfJoin := func(device *gkmTestSidecar, genWrap bool) int {
		engine := device.acceptingMlsEngine(t, fixture.clock)
		staged, err := engine.JoinExternal(groupInfo, &sidecar.MlsCommitArgs{Path: true, AuthenticatedData: gkmTestCommitHeader(t, 0, fakeGkmPin(10))})
		if err != nil {
			t.Fatal(err)
		}
		request := gkmTestEpochRequest(staged.Message(), 0, true)
		if genWrap {
			request.GenWrap = bytes.Repeat([]byte{9}, gkmSealedKeyByteCount)
		}
		fixture.auth.grant(device.sidecarId, world.repoId, sidecar.AclEvsRead)
		token := fixture.token(device.sidecarId, repoScope(world.repoId, "r"))
		return world.postEpoch(token, 2, request).Code
	}
	plain := fixture.newSidecar("sc-plain", memberDeviceFacts(world.memberId))
	if code := selfJoin(plain, false); code != http.StatusForbidden {
		t.Errorf("a generation-0 self-join by a device no recovery key admitted: %d", code)
	}
	recoveryFacts := memberDeviceFacts(world.memberId)
	recoveryFacts.RecoveryAdmitted = true
	recovered := fixture.newSidecar("sc-recovered", recoveryFacts)
	if code := selfJoin(recovered, true); code != http.StatusForbidden {
		t.Errorf("a generation-0 self-join carrying a GenWrap: %d", code)
	}
	member := world.stageSelfUpdate(0, fakeGkmPin(10))
	if recorder := world.postEpoch(world.adminToken, 2, gkmTestEpochRequest(member.Message(), 0, false)); recorder.Code != http.StatusForbidden {
		t.Errorf("a member's commit at generation 0: %d", recorder.Code)
	}
	member.Discard()
	if code := selfJoin(recovered, false); code != http.StatusOK {
		t.Fatalf("a recovery-admitted device's generation-0 self-join: %d", code)
	}
	stored := world.storedEpoch(2)
	header, err := sidecar.ParseMlsHeader(stored.GetCommit())
	if err != nil || header.External == nil || stored.GetHeader().GetGeneration() != 0 || len(stored.GetGenWrap()) != 0 ||
		stored.GetGroupInfoGeneration() != 1 {
		t.Errorf("the stored self-join: %v", err)
	}
}

// A success hints commit on gkm:<group_id> to the repo's readers, versioned epoch × 2^24 + generation (D-KEYS-19).
func TestGkmCommitHintsTheReadersOnTheGroupsTopic(t *testing.T) {
	world := newGkmCommitWorld(t)
	fixture := world.fixture
	reader := fixture.newSidecar("sc-reader", memberDeviceFacts(world.memberId))
	fixture.auth.grant(reader.sidecarId, world.repoId, sidecar.AclEvsRead)
	clientId := fixture.clientOf(reader.sidecarId)
	world.commitAndAdopt(1, false)
	if err := fixture.engine.AwaitHints(fixture.ctx); err != nil {
		t.Fatal(err)
	}
	hints := fixture.host.Push.Hints(connect.Id(clientId))
	if len(hints) != 1 || hints[0].Topic != sidecar.PushTopicGkmGroup(world.groupId) || hints[0].Version != 1<<24+1 {
		t.Fatalf("the reader's hints: %d", len(hints))
	}
	hint := &protocol.GkmHint{}
	if err := proto.Unmarshal(hints[0].Body, hint); err != nil || hint.GetKind() != protocol.GkmHintKind_GKM_HINT_COMMIT ||
		hint.GetEpoch() != 1 || !bytes.Equal(hint.GetGroupId(), world.groupId.Bytes()) {
		t.Errorf("the commit hint: %v", err)
	}
}

// GET .../epochs?after= answers the epochs after n in order, with their sizes, and stops at its bound.
func TestGkmEpochsReadAnswersInOrderUpToItsBound(t *testing.T) {
	world := newGkmGroupWorld(t)
	world.fixture.settings.EpochsReplyMaxCount = 2
	world.fixture.start()
	world.createAndActivate()
	world.startMlsGroup()
	for i := 0; i < 3; i += 1 {
		world.commitAndAdopt(1, false)
	}
	read := func(after string) []*protocol.GkmEpochEntry {
		path := "/gkm/groups/" + sidecar.EvsKeyId(world.groupId) + "/epochs"
		if after != "" {
			path += "?after=" + after
		}
		recorder := world.fixture.serve(http.MethodGet, path, world.adminToken, nil)
		reply := &protocol.GkmEpochsReply{}
		if recorder.Code != http.StatusOK || proto.Unmarshal(recorder.Body.Bytes(), reply) != nil {
			t.Fatalf("GET epochs after %q: %d", after, recorder.Code)
		}
		return reply.GetEpochs()
	}
	first := read("")
	if len(first) != 2 || first[0].GetEpoch() != 0 || first[1].GetEpoch() != 1 {
		t.Fatalf("the first page: %d", len(first))
	}
	if first[1].GetSize() != uint64(len(world.fixture.object("meta-2", GkmEpochKey(world.groupId, 1)))) {
		t.Errorf("an epoch's size is not its stored bytes'")
	}
	second := read(strconv.FormatUint(first[1].GetEpoch(), 10))
	if len(second) != 2 || second[0].GetEpoch() != 2 || second[1].GetEpoch() != 3 {
		t.Fatalf("the second page: %d", len(second))
	}
	if third := read("3"); len(third) != 0 {
		t.Errorf("past the newest epoch: %d", len(third))
	}
}

// §10.6's Welcomes row: no early Welcome, none by another than its epoch's uploader, none to a sidecar that does not
// read the repo; the uploader's lands with its pointers and a welcome hint, and GET /gkm/welcomes serves it.
func TestGkmNoEarlyWelcome(t *testing.T) {
	world := newGkmCommitWorld(t)
	fixture := world.fixture
	joiner := fixture.newSidecar("sc-joiner", memberDeviceFacts(world.memberId))
	fixture.auth.grant(joiner.sidecarId, world.repoId, sidecar.AclEvsRead)
	fixture.clientOf(joiner.sidecarId)
	outsider := fixture.newSidecar("sc-outsider", memberDeviceFacts(world.memberId))
	writer := fixture.newSidecar("sc-writer", memberDeviceFacts(world.memberId))
	fixture.auth.grant(writer.sidecarId, world.repoId, sidecar.AclEvsWrite)
	writerToken := fixture.token(writer.sidecarId, repoScope(world.repoId, "rw"))
	ref := bytes.Repeat([]byte{0xab}, gkmKeyPackageRefByteCount)
	welcome := func(token string, recipient *gkmTestSidecar) int {
		request := &protocol.GkmWelcomeRequest{
			Welcome:    []byte("a Welcome without the tree"),
			Recipients: []*protocol.GkmWelcomeRecipient{{SidecarId: recipient.sidecarId.Bytes(), KeyPackageRef: ref}},
		}
		path := "/gkm/groups/" + sidecar.EvsKeyId(world.groupId) + "/welcome/1"
		return fixture.serve(http.MethodPost, path, token, fixture.marshal(request)).Code
	}
	if code := welcome(world.adminToken, joiner); code != http.StatusNotFound {
		t.Errorf("a Welcome before its epoch: %d", code)
	}
	world.commitAndAdopt(1, true)
	if code := welcome(writerToken, joiner); code != http.StatusForbidden {
		t.Errorf("a Welcome by another than its epoch's uploader: %d", code)
	}
	if code := welcome(world.adminToken, outsider); code != http.StatusForbidden {
		t.Errorf("a Welcome to a sidecar that does not read the repo: %d", code)
	}
	if fixture.object("meta-2", GkmWelcomeKey(world.groupId, 1)) != nil {
		t.Fatalf("a refused Welcome was stored")
	}
	if code := welcome(world.adminToken, joiner); code != http.StatusOK {
		t.Fatalf("the uploader's Welcome: %d", code)
	}
	if code := welcome(world.adminToken, joiner); code != http.StatusOK {
		t.Errorf("the Welcome sent again: %d", code)
	}
	pointerKey := GkmWelcomePointerKey(joiner.sidecarId, world.groupId, 1)
	pointer := &protocol.GkmWelcomePointer{}
	if held := fixture.object("meta-1", pointerKey); held == nil || proto.Unmarshal(held, pointer) != nil || !bytes.Equal(pointer.GetKeyPackageRef(), ref) {
		t.Errorf("no pointer on the first cluster carrying the ref")
	}
	// the same epoch's Welcome naming another KeyPackage for the joiner is the uploader's own conflict
	otherRequest := &protocol.GkmWelcomeRequest{
		Welcome:    []byte("a Welcome without the tree"),
		Recipients: []*protocol.GkmWelcomeRecipient{{SidecarId: joiner.sidecarId.Bytes(), KeyPackageRef: bytes.Repeat([]byte{0xcd}, gkmKeyPackageRefByteCount)}},
	}
	if code := fixture.serve(http.MethodPost, "/gkm/groups/"+sidecar.EvsKeyId(world.groupId)+"/welcome/1", world.adminToken, fixture.marshal(otherRequest)).Code; code != http.StatusConflict {
		t.Errorf("a second ref for one epoch's recipient: %d", code)
	}
	welcomeHintCount := 0
	for _, hint := range fixture.hints(joiner.sidecarId) {
		if hint.GetKind() == protocol.GkmHintKind_GKM_HINT_WELCOME && hint.GetEpoch() == 1 {
			welcomeHintCount += 1
		}
	}
	if welcomeHintCount == 0 {
		t.Errorf("no welcome hint to the joiner")
	}
	joinerToken := fixture.token(joiner.sidecarId, repoScope(world.repoId, "r"))
	recorder := fixture.serve(http.MethodGet, "/gkm/welcomes", joinerToken, nil)
	reply := &protocol.GkmWelcomesReply{}
	if recorder.Code != http.StatusOK || proto.Unmarshal(recorder.Body.Bytes(), reply) != nil || len(reply.GetWelcomes()) != 1 ||
		!bytes.Equal(reply.GetWelcomes()[0].GetWelcome(), []byte("a Welcome without the tree")) {
		t.Errorf("GET /gkm/welcomes: %d", recorder.Code)
	}
}

// QD-747: HEAD welcome/<n> answers whether epoch n's Welcome stands, 404 before the uploader wrote it and 200 after,
// with no body either way; only under rw, so a reader's and a read_only device's token are refused; a path out of
// form is 400; and a store that does not answer is 503, never the 404 a leaf would remove a joiner on.
func TestGkmWelcomeHeadAnswersWhetherTheWelcomeStands(t *testing.T) {
	world := newGkmCommitWorld(t)
	fixture := world.fixture
	joiner := fixture.newSidecar("sc-joiner", memberDeviceFacts(world.memberId))
	fixture.auth.grant(joiner.sidecarId, world.repoId, sidecar.AclEvsRead)
	fixture.clientOf(joiner.sidecarId)
	joinerToken := fixture.token(joiner.sidecarId, repoScope(world.repoId, "r"))
	writer := fixture.newSidecar("sc-writer", memberDeviceFacts(world.memberId))
	fixture.auth.grant(writer.sidecarId, world.repoId, sidecar.AclEvsWrite)
	writerToken := fixture.token(writer.sidecarId, repoScope(world.repoId, "rw"))
	readOnlyFacts := memberDeviceFacts(world.memberId)
	readOnlyFacts.ReadOnly = true
	readOnly := fixture.newSidecar("sc-read-only", readOnlyFacts)
	fixture.auth.grant(readOnly.sidecarId, world.repoId, sidecar.AclEvsWrite)
	readOnlyToken := fixture.token(readOnly.sidecarId, repoScope(world.repoId, "rw"))
	groupPath := "/gkm/groups/" + sidecar.EvsKeyId(world.groupId)
	stands := func(token string, epoch string) int {
		t.Helper()
		recorder := fixture.serve(http.MethodHead, groupPath+"/welcome/"+epoch, token, nil)
		if recorder.Body.Len() != 0 {
			t.Errorf("HEAD welcome/%s answered %d with a body of %d bytes", epoch, recorder.Code, recorder.Body.Len())
		}
		return recorder.Code
	}
	world.commitAndAdopt(1, true)
	// the epoch stands and its uploader has written no Welcome: what a crash between the two leaves
	if code := stands(writerToken, "1"); code != http.StatusNotFound {
		t.Errorf("before the Welcome: %d", code)
	}
	// a leaf without rw learns nothing, whether or not a Welcome stands
	if code := stands(joinerToken, "1"); code != http.StatusForbidden {
		t.Errorf("a reader's token before the Welcome: %d", code)
	}
	request := &protocol.GkmWelcomeRequest{
		Welcome:    []byte("a Welcome without the tree"),
		Recipients: []*protocol.GkmWelcomeRecipient{{SidecarId: joiner.sidecarId.Bytes(), KeyPackageRef: bytes.Repeat([]byte{0xab}, gkmKeyPackageRefByteCount)}},
	}
	if code := fixture.serve(http.MethodPost, groupPath+"/welcome/1", world.adminToken, fixture.marshal(request)).Code; code != http.StatusOK {
		t.Fatalf("the uploader's Welcome: %d", code)
	}
	if code := stands(writerToken, "1"); code != http.StatusOK {
		t.Errorf("after the Welcome: %d", code)
	}
	if code := stands(world.adminToken, "1"); code != http.StatusOK {
		t.Errorf("under admin: %d", code)
	}
	if code := stands(joinerToken, "1"); code != http.StatusForbidden {
		t.Errorf("a reader's token: %d", code)
	}
	if code := stands(readOnlyToken, "1"); code != http.StatusForbidden {
		t.Errorf("a read_only device's token: %d", code)
	}
	// another epoch's Welcome is its own object
	if code := stands(writerToken, "2"); code != http.StatusNotFound {
		t.Errorf("an epoch with no Welcome: %d", code)
	}
	for _, epoch := range []string{"0", "01", "x", "-1"} {
		if code := stands(writerToken, epoch); code != http.StatusBadRequest {
			t.Errorf("epoch %q: %d", epoch, code)
		}
	}
	// the answer carries nothing of the Welcome, and a GET of the path is no route
	if recorder := fixture.serve(http.MethodGet, groupPath+"/welcome/1", writerToken, nil); recorder.Code != http.StatusMethodNotAllowed || bytes.Contains(recorder.Body.Bytes(), request.GetWelcome()) {
		t.Errorf("GET welcome/1: %d", recorder.Code)
	}
	// a store that does not answer is not a 404
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op:        sidecartest.FaultOpGet,
		KeyPrefix: GkmWelcomeKey(world.groupId, 1),
		Result:    sidecartest.FailBeforeApply,
	}); err != nil {
		t.Fatal(err)
	}
	recorder := fixture.serve(http.MethodHead, groupPath+"/welcome/1", writerToken, nil)
	if recorder.Code != http.StatusServiceUnavailable || recorder.Header().Get("Retry-After") == "" {
		t.Errorf("a store fault: %d", recorder.Code)
	}
}

// A crash between an epoch 16 past the pointer and the pointer's PUT heals at the next commit (§10.6's group-info
// row, §22.7's FS-20 case).
func TestGkmGroupInfoPointerHealsAtTheNextCommit(t *testing.T) {
	world := newGkmCommitWorld(t)
	fixture := world.fixture
	pointer := func() *protocol.GkmGroupInfoObject {
		held := fixture.object("meta-2", GkmGroupInfoKey(world.groupId))
		if held == nil {
			return nil
		}
		object, err := parseGkmGroupInfoObject(held)
		if err != nil {
			t.Fatal(err)
		}
		return object
	}
	for epoch := 1; epoch < 16; epoch += 1 {
		world.commitAndAdopt(1, true)
	}
	if pointer() != nil {
		t.Fatalf("gkm moved the pointer before 16 epochs past it")
	}
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op:        sidecartest.FaultOpPut,
		KeyPrefix: GkmGroupInfoKey(world.groupId),
		Result:    sidecartest.FailBeforeApply,
	}); err != nil {
		t.Fatal(err)
	}
	world.commitAndAdopt(1, true)
	if pointer() != nil {
		t.Fatalf("the pointer moved through a failed PUT")
	}
	world.commitAndAdopt(1, true)
	if held := pointer(); held == nil || held.GetEpoch() != 17 || len(held.GetSealedGroupInfo()) != 0 {
		t.Errorf("the next commit did not heal the pointer")
	}
}

// group-info rises: a pointer to an epoch that carries a GroupInfo lands, an older one answers 409 with the newer, a
// pointer to an epoch without one is refused, and a read wanting a newer epoch hints wrap-pending at most once a
// minute.
func TestGkmGroupInfoRisesAndAStaleReadHints(t *testing.T) {
	world := newGkmCommitWorld(t)
	fixture := world.fixture
	fixture.clientOf(world.admin.sidecarId)
	world.commitAndAdopt(1, true)
	world.commitAndAdopt(1, false)
	path := "/gkm/groups/" + sidecar.EvsKeyId(world.groupId) + "/group-info"
	post := func(object *protocol.GkmGroupInfoObject) (int, []byte) {
		recorder := fixture.serve(http.MethodPost, path, world.adminToken, fixture.marshal(object))
		return recorder.Code, recorder.Body.Bytes()
	}
	if code, _ := post(&protocol.GkmGroupInfoObject{Epoch: 2}); code != http.StatusForbidden {
		t.Errorf("a pointer to an epoch without a GroupInfo: %d", code)
	}
	if code, _ := post(&protocol.GkmGroupInfoObject{Epoch: 1}); code != http.StatusOK {
		t.Fatalf("a pointer to epoch 1: %d", code)
	}
	if code, _ := post(&protocol.GkmGroupInfoObject{Epoch: 1}); code != http.StatusOK {
		t.Errorf("the pointer sent again: %d", code)
	}
	if code, winner := post(&protocol.GkmGroupInfoObject{Epoch: 0}); code != http.StatusConflict || !bytes.Equal(winner, fixture.marshal(&protocol.GkmGroupInfoObject{Epoch: 1})) {
		t.Errorf("an older pointer: %d", code)
	}
	if code, _ := post(&protocol.GkmGroupInfoObject{Epoch: 2, Generation: 1, SealedGroupInfo: []byte("above 16 leaves")}); code != http.StatusOK {
		t.Errorf("a sealed GroupInfo for a newer epoch: %d", code)
	}
	read := func(want string) int {
		return fixture.serve(http.MethodGet, path+"?want="+want, world.adminToken, nil).Code
	}
	if code := read("5"); code != http.StatusOK {
		t.Fatalf("a read wanting epoch 5: %d", code)
	}
	read("5")
	countWrapPending := func() int {
		count := 0
		for _, hint := range fixture.hints(world.admin.sidecarId) {
			if hint.GetKind() == protocol.GkmHintKind_GKM_HINT_WRAP_PENDING {
				count += 1
			}
		}
		return count
	}
	if count := countWrapPending(); count != 1 {
		t.Errorf("wrap-pending hints within a minute: %d", count)
	}
	fixture.clock.Advance(fixture.settings.GroupInfoWantHintInterval)
	read("5")
	if count := countWrapPending(); count != 2 {
		t.Errorf("wrap-pending hints a minute later: %d", count)
	}
}

// Acks write {gka_<group_id>} at most daily per leaf, keep since, and live 31 days past their last write.
func TestGkmAckWritesAtMostDailyAndKeepsSince(t *testing.T) {
	world := newGkmCommitWorld(t)
	fixture := world.fixture
	path := "/gkm/groups/" + sidecar.EvsKeyId(world.groupId) + "/ack"
	ack := func(epoch uint64) {
		token := fixture.token(world.admin.sidecarId, repoScope(world.repoId, "r"))
		if recorder := fixture.serve(http.MethodPost, path, token, fixture.marshal(&protocol.GkmAckRequest{Epoch: epoch})); recorder.Code != http.StatusOK {
			t.Fatalf("an ack of epoch %d: %d", epoch, recorder.Code)
		}
	}
	read := func() map[string][]byte {
		fieldValues, err := fixture.host.Redis.HashGetAll(fixture.ctx, GkmAckRedisKey(world.groupId))
		if err != nil {
			t.Fatal(err)
		}
		return fieldValues
	}
	leafField := sidecar.EvsKeyId(world.admin.sidecarId)
	start := fixture.clock.Now()
	ack(3)
	fieldValues := read()
	if epoch, at, ok := parseGkmAckValue(fieldValues[leafField]); !ok || epoch != 3 || !at.Equal(start.Truncate(time.Millisecond)) {
		t.Fatalf("the first ack: %q", fieldValues[leafField])
	}
	since := string(fieldValues[gkmAckSinceField])
	fixture.clock.Advance(time.Hour)
	ack(4)
	if epoch, _, _ := parseGkmAckValue(read()[leafField]); epoch != 3 {
		t.Errorf("an ack within the day was written: epoch %d", epoch)
	}
	fixture.clock.Advance(fixture.settings.AckInterval)
	ack(5)
	fieldValues = read()
	if epoch, _, _ := parseGkmAckValue(fieldValues[leafField]); epoch != 5 {
		t.Errorf("an ack a day later was not written: epoch %d", epoch)
	}
	if string(fieldValues[gkmAckSinceField]) != since {
		t.Errorf("since moved: %q to %q", since, fieldValues[gkmAckSinceField])
	}
	fixture.clock.Advance(fixture.settings.AckTtl)
	if len(read()) != 0 {
		t.Errorf("the ack family outlived its 31 days")
	}
}
