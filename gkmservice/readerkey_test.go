package gkmservice

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A world for ReaderKeys: one member device reading one repo.
type gkmReaderKeyWorld struct {
	fixture *gkmFixture
	repoId  sidecar.Id
	device  *gkmTestSidecar
	token   string
}

func newGkmReaderKeyWorld(t *testing.T) *gkmReaderKeyWorld {
	fixture := newGkmFixture(t)
	world := &gkmReaderKeyWorld{fixture: fixture, repoId: testId("repo-r")}
	world.device = fixture.newSidecar("sc-device", memberDeviceFacts(testId("member-m")))
	fixture.auth.grant(world.device.sidecarId, world.repoId, sidecar.AclEvsRead)
	world.token = fixture.token(world.device.sidecarId, repoScope(world.repoId, "r"))
	return world
}

// A fresh ReaderKey of the device's, signed now, valid lifetime.
func (self *gkmReaderKeyWorld) readerKey(lifetime time.Duration) []byte {
	self.fixture.t.Helper()
	now := self.fixture.clock.Now()
	signed, _, err := sidecar.NewGkmReaderKey(self.device.sidecarId, now, now.Add(lifetime), self.device.sign)
	if err != nil {
		self.fixture.t.Fatal(err)
	}
	return self.fixture.marshal(signed)
}

// POST /gkm/reader-key of body under token.
func (self *gkmReaderKeyWorld) upload(token string, body []byte) int {
	return self.fixture.serve(http.MethodPost, "/gkm/reader-key", token, body).Code
}

// A ReaderKey lands on the first cluster at rk/<sidecar_id>, and GET serves its bytes as stored.
func TestGkmReaderKeyUploadLandsAndReadsBack(t *testing.T) {
	world := newGkmReaderKeyWorld(t)
	fixture := world.fixture
	readerKey := world.readerKey(sidecar.GkmReaderKeyLifetime)
	if status := world.upload(world.token, readerKey); status != http.StatusOK {
		t.Fatalf("upload: %d", status)
	}
	if !bytes.Equal(fixture.object("meta-1", GkmReaderKeyKey(world.device.sidecarId)), readerKey) {
		t.Error("the ReaderKey is not at rk/ on the first cluster")
	}
	recorder := fixture.serve(http.MethodGet, "/gkm/reader-key/"+sidecar.EvsKeyId(world.device.sidecarId), world.token, nil)
	if recorder.Code != http.StatusOK || !bytes.Equal(recorder.Body.Bytes(), readerKey) {
		t.Errorf("read back: %d", recorder.Code)
	}
	if recorder := fixture.serve(http.MethodGet, "/gkm/reader-key/"+sidecar.EvsKeyId(testId("sc-none")), world.token, nil); recorder.Code != http.StatusNotFound {
		t.Errorf("a sidecar with none: %d", recorder.Code)
	}
	// the batch read answers in order, an empty Signed for none
	batch := fixture.marshal(&protocol.GkmReaderKeysRequest{SidecarIds: [][]byte{testId("sc-none").Bytes(), world.device.sidecarId.Bytes()}})
	recorder = fixture.serve(http.MethodPost, "/gkm/reader-keys", world.token, batch)
	reply := &protocol.GkmReaderKeysReply{}
	if recorder.Code != http.StatusOK || proto.Unmarshal(recorder.Body.Bytes(), reply) != nil || len(reply.GetReaderKeys()) != 2 {
		t.Fatalf("batch: %d", recorder.Code)
	}
	if len(reply.GetReaderKeys()[0].GetBody()) != 0 || !bytes.Equal(fixture.marshal(reply.GetReaderKeys()[1]), readerKey) {
		t.Error("the batch answered out of order or other bytes")
	}
	tooMany := &protocol.GkmReaderKeysRequest{}
	for i := 0; i <= gkmReaderKeysMaxCount; i += 1 {
		tooMany.SidecarIds = append(tooMany.SidecarIds, world.device.sidecarId.Bytes())
	}
	if recorder := fixture.serve(http.MethodPost, "/gkm/reader-keys", world.token, fixture.marshal(tooMany)); recorder.Code != http.StatusBadRequest {
		t.Errorf("257 sidecars: %d", recorder.Code)
	}
}

// §10.6's own row: a ReaderKey at most once per 24 h after its first, read from the stored object, on a fake clock.
// The same bytes again are the same upload.
func TestGkmReaderKeyAtMostOncePer24Hours(t *testing.T) {
	world := newGkmReaderKeyWorld(t)
	fixture := world.fixture
	first := world.readerKey(sidecar.GkmReaderKeyLifetime)
	if status := world.upload(world.token, first); status != http.StatusOK {
		t.Fatalf("the first: %d", status)
	}
	if status := world.upload(world.token, first); status != http.StatusOK {
		t.Errorf("a retry of the same bytes: %d", status)
	}
	// a token lives 15 minutes: each later upload takes a fresh one
	fixture.clock.Advance(23 * time.Hour)
	second := world.readerKey(sidecar.GkmReaderKeyLifetime)
	token := fixture.token(world.device.sidecarId, repoScope(world.repoId, "r"))
	recorder := fixture.serve(http.MethodPost, "/gkm/reader-key", token, second)
	if recorder.Code != http.StatusTooManyRequests || recorder.Header().Get("Retry-After") != "3600" {
		t.Errorf("within 24 h: %d, Retry-After %q", recorder.Code, recorder.Header().Get("Retry-After"))
	}
	if !bytes.Equal(fixture.object("meta-1", GkmReaderKeyKey(world.device.sidecarId)), first) {
		t.Error("a refused upload replaced the ReaderKey")
	}
	fixture.clock.Advance(time.Hour)
	third := world.readerKey(sidecar.GkmReaderKeyLifetime)
	token = fixture.token(world.device.sidecarId, repoScope(world.repoId, "r"))
	if status := world.upload(token, third); status != http.StatusOK {
		t.Fatalf("after 24 h: %d", status)
	}
	if !bytes.Equal(fixture.object("meta-1", GkmReaderKeyKey(world.device.sidecarId)), third) {
		t.Error("the new ReaderKey did not replace the old")
	}
}

// The trap: the token's sidecar must be the record's, signed by the identity key the log admits for it, valid at
// most 7 days and 10 minutes from gkm's clock.
func TestGkmReaderKeyRefusedUnlessTheUploadersOwn(t *testing.T) {
	world := newGkmReaderKeyWorld(t)
	fixture := world.fixture
	other := fixture.newSidecar("sc-other", memberDeviceFacts(testId("member-o")))
	fixture.auth.grant(other.sidecarId, world.repoId, sidecar.AclEvsRead)
	otherToken := fixture.token(other.sidecarId, repoScope(world.repoId, "r"))
	if status := world.upload(otherToken, world.readerKey(sidecar.GkmReaderKeyLifetime)); status != http.StatusForbidden {
		t.Errorf("another sidecar's ReaderKey: %d", status)
	}
	// the device's own record, signed by another key
	now := fixture.clock.Now()
	forged, _, err := sidecar.NewGkmReaderKey(world.device.sidecarId, now, now.Add(time.Hour), other.sign)
	if err != nil {
		t.Fatal(err)
	}
	if status := world.upload(world.token, fixture.marshal(forged)); status != http.StatusForbidden {
		t.Errorf("a ReaderKey another key signed: %d", status)
	}
	// valid past §10.5's window from gkm's clock: the device's clock runs a day ahead
	ahead, _, err := sidecar.NewGkmReaderKey(world.device.sidecarId, now.Add(24*time.Hour), now.Add(24*time.Hour+sidecar.GkmReaderKeyLifetime), world.device.sign)
	if err != nil {
		t.Fatal(err)
	}
	if status := world.upload(world.token, fixture.marshal(ahead)); status != http.StatusForbidden {
		t.Errorf("a ReaderKey valid past the window: %d", status)
	}
	if status := world.upload(world.token, []byte("not a Signed")); status != http.StatusBadRequest {
		t.Errorf("bytes that are no Signed: %d", status)
	}
	if fixture.object("meta-1", GkmReaderKeyKey(world.device.sidecarId)) != nil {
		t.Error("a refused upload stored a ReaderKey")
	}
}

// FS-106: a parked device's ReaderKey waits for its lift, and its upkeep's next send lands.
func TestGkmParkedDevicesReaderKeyWaitsForItsLift(t *testing.T) {
	world := newGkmReaderKeyWorld(t)
	fixture := world.fixture
	fixture.auth.update(world.device.sidecarId, func(facts *GkmSidecarFacts) { facts.Parked = true })
	readerKey := world.readerKey(sidecar.GkmReaderKeyLifetime)
	if status := world.upload(world.token, readerKey); status != http.StatusForbidden {
		t.Errorf("while parked: %d", status)
	}
	fixture.auth.update(world.device.sidecarId, func(facts *GkmSidecarFacts) { facts.Parked = false })
	if status := world.upload(world.token, readerKey); status != http.StatusOK {
		t.Errorf("after the lift: %d", status)
	}
	// a read_only device keeps its upkeep under r (D-KEYS-26)
	readOnly := fixture.newSidecar("sc-read-only", &GkmSidecarFacts{MemberDevice: true, ReadOnly: true})
	fixture.auth.grant(readOnly.sidecarId, world.repoId, sidecar.AclEvsRead)
	now := fixture.clock.Now()
	signed, _, err := sidecar.NewGkmReaderKey(readOnly.sidecarId, now, now.Add(sidecar.GkmReaderKeyLifetime), readOnly.sign)
	if err != nil {
		t.Fatal(err)
	}
	if status := world.upload(fixture.token(readOnly.sidecarId, repoScope(world.repoId, "r")), fixture.marshal(signed)); status != http.StatusOK {
		t.Errorf("a read_only device's ReaderKey: %d", status)
	}
}

// GET /gkm/welcomes answers each pointer with its Welcome, only for groups the token reaches, and passes over a
// pointer whose Welcome is not there.
func TestGkmWelcomesAnswerOnlyGroupsTheTokenReaches(t *testing.T) {
	fixture := newGkmFixture(t)
	repoA, groupA := testId("repo-a"), testId("group-a")
	repoB, groupB := testId("repo-b"), testId("group-b")
	fixture.placeRepo(repoA, "meta-1", protocol.EvsRepoState_EVS_REPO_ACTIVE)
	fixture.fileForm(repoA, "meta-1", 1, groupA)
	fixture.placeRepo(repoB, "meta-2", protocol.EvsRepoState_EVS_REPO_ACTIVE)
	fixture.fileForm(repoB, "meta-2", 1, groupB)
	device := testId("sc-device")
	fixture.auth.admit(device, memberDeviceFacts(testId("member-m")))
	fixture.auth.grant(device, repoA, sidecar.AclEvsRead)
	fixture.auth.grant(device, repoB, sidecar.AclEvsRead)
	pointer := func(groupId sidecar.Id, clusterId string, refByte byte, withWelcome bool) []byte {
		ref := bytes.Repeat([]byte{refByte}, gkmKeyPackageRefByteCount)
		key := GkmWelcomePointerKey(device, groupId, 1)
		fixture.put("meta-1", key, fixture.marshal(&protocol.GkmWelcomePointer{GroupId: groupId.Bytes(), Epoch: 1, KeyPackageRef: ref}))
		if withWelcome {
			fixture.put(clusterId, GkmWelcomeKey(groupId, 1), []byte("welcome of "+string(refByte)))
		}
		return ref
	}
	refA := pointer(groupA, "meta-1", 'a', true)
	refB := pointer(groupB, "meta-2", 'b', true)
	pointer(testId("group-c"), "meta-1", 'c', false)
	welcomes := func(token string) []*protocol.GkmWelcomeEntry {
		recorder := fixture.serve(http.MethodGet, "/gkm/welcomes", token, nil)
		reply := &protocol.GkmWelcomesReply{}
		if recorder.Code != http.StatusOK || proto.Unmarshal(recorder.Body.Bytes(), reply) != nil {
			t.Fatalf("welcomes: %d", recorder.Code)
		}
		return reply.GetWelcomes()
	}
	onlyA := welcomes(fixture.token(device, repoScope(repoA, "r")))
	if len(onlyA) != 1 || !bytes.Equal(onlyA[0].GetKeyPackageRef(), refA) || string(onlyA[0].GetWelcome()) != "welcome of a" {
		t.Errorf("a token reaching group a: %v", onlyA)
	}
	both := welcomes(fixture.token(device, repoScope(repoA, "r"), repoScope(repoB, "r")))
	if len(both) != 2 || !bytes.Equal(both[1].GetKeyPackageRef(), refB) || string(both[1].GetWelcome()) != "welcome of b" {
		t.Errorf("a token reaching both: %v", both)
	}
	// a group whose repo the state no longer lets it read is passed over
	fixture.auth.drop(device, repoB)
	if afterDrop := welcomes(fixture.token(device, repoScope(repoA, "r"), repoScope(repoB, "r"))); len(afterDrop) != 1 {
		t.Errorf("after repo b's drop: %v", afterDrop)
	}
	if recorder := fixture.serve(http.MethodGet, "/gkm/welcomes", fixture.token(device, repoScope(repoA, "deposit")), nil); recorder.Code != http.StatusForbidden {
		t.Errorf("a deposit-only token: %d", recorder.Code)
	}
}

// A ReaderKey and KeyPackage from a deposit-only token are refused, as QD-177 names for the route matrix.
func TestGkmDepositOnlyTokenReachesNoUpkeepRoute(t *testing.T) {
	world := newGkmReaderKeyWorld(t)
	fixture := world.fixture
	depositToken := fixture.token(world.device.sidecarId, repoScope(world.repoId, "deposit"))
	if status := world.upload(depositToken, world.readerKey(sidecar.GkmReaderKeyLifetime)); status != http.StatusForbidden {
		t.Errorf("POST reader-key: %d", status)
	}
	if recorder := fixture.serve(http.MethodPost, "/gkm/key-packages", depositToken, fixture.marshal(&protocol.GkmKeyPackagesRequest{})); recorder.Code != http.StatusForbidden {
		t.Errorf("POST key-packages: %d", recorder.Code)
	}
	if recorder := fixture.serve(http.MethodGet, "/gkm/reader-key/"+sidecar.EvsKeyId(world.device.sidecarId), depositToken, nil); recorder.Code != http.StatusForbidden {
		t.Errorf("GET reader-key: %d", recorder.Code)
	}
}
