package gkmschedule

// FS-20's KF1 legs on T2 (KEYS-M2-27; FI-12; §10.7's KF1, D-KEYS-18, DESIGN-DETAILS 6.2.4's KF1 crash row): the
// creator killed at each step of KF1 on the real subset, against gkmservice's engine, and its restart from the
// keychain: before the creation's POST, after it while its answer is lost, and between the group and generation 1's
// deliveries. Each resumes with the same bytes, one group stands, no content can predate the deliveries since the
// repo stays keying until they are staged, and a creator whose only device is lost after the group stands leaves the
// repo keying.

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The world's repo/ state as gkm reads it.
func (self *FsKeysWorld) RepoState() protocol.EvsRepoState {
	self.t.Helper()
	for key, body := range self.objects(gkmservice.GkmEvsRepoKey(self.RepoId)) {
		if key != gkmservice.GkmEvsRepoKey(self.RepoId) {
			continue
		}
		object := &protocol.EvsRepoObject{}
		if err := proto.Unmarshal(body, object); err != nil {
			self.t.Fatal(err)
		}
		return object.GetState()
	}
	return protocol.EvsRepoState(0)
}

// How many forms gkm holds of the world's repo.
func (self *FsKeysWorld) FormCount() int {
	return len(self.objects(gkmservice.GkmFormPrefix(self.RepoId)))
}

// The KF1 world: a creator, a second member device and an agent, all reading the repo, the creator its admin, each
// with its ReaderKey and the member devices their KeyPackages.
func newFsKeysCreationWorld(t *testing.T) (*FsKeysWorld, *FsKeysDevice, *FsKeysDevice, *FsKeysDevice) {
	world := NewFsKeysWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	creator := world.AddMember("a", false)
	member := world.AddMember("b", false)
	agent := world.AddAgent("d")
	world.Grant(true, creator, member, agent)
	world.Admin(creator)
	world.Advance()
	world.Publish()
	return world, creator, member, agent
}

// Whether a request is KF1's POST /gkm/groups.
func fsKeysGroupCreate(request *http.Request) bool {
	return request.Method == http.MethodPost && request.URL.Path == "/gkm/groups"
}

// Whether a request stages generation 1's deliveries, POST /gkm/groups/<id>/wraps/1/<c8>.
func fsKeysFirstWraps(request *http.Request) bool {
	parts := strings.Split(request.URL.Path, "/")
	return request.Method == http.MethodPost && len(parts) == 7 && parts[4] == "wraps" && parts[5] == "1"
}

// FS-20: KF1's creator killed before its POST /gkm/groups leaves only its draft; its restart posts the same bytes,
// the group's id among them, and finishes; nothing of the repo is active before the agent's delivery stands.
func TestFsKeysRecoveryKf1KilledBeforeItsCreationResumesFromTheDraft(t *testing.T) {
	world, creator, member, agent := newFsKeysCreationWorld(t)
	world.Place(creator)
	creator.Transport.Before = func(request *http.Request) FsKeysFault {
		if fsKeysGroupCreate(request) {
			return FsKeysFaultFailBefore
		}
		return FsKeysFaultNone
	}
	args := &sidecar.GkmCreateGroupArgs{NetworkId: sidecar.Id(world.NetworkId), RepoId: world.RepoId, Kind: world.Kind}
	if _, err := creator.Client.CreateGroup(world.Ctx, args); err == nil {
		t.Fatal("a creation whose POST never left answered")
	}
	if world.FormCount() != 0 || world.RepoState() != protocol.EvsRepoState_EVS_REPO_KEYING {
		t.Fatalf("a killed creation wrote a form or moved the repo")
	}
	creator.Transport.Before = nil
	creator.Restart()
	key, err := creator.Client.CreateGroup(world.Ctx, args)
	if err != nil {
		t.Fatalf("the restarted creation: %v", err)
	}
	world.GroupId = key.GroupId()
	if world.FormCount() != 1 || world.GenerationCount() != 1 {
		t.Fatalf("the resumed creation: %d forms, %d generations", world.FormCount(), world.GenerationCount())
	}
	if !world.WrapRecipients(1)[agent.SidecarId()] {
		t.Fatalf("generation 1 holds no ReaderWrap to the agent")
	}
	world.Activate()
	world.AddPending(creator)
	for _, device := range []*FsKeysDevice{member, agent} {
		held, err := device.Client.CurrentRepoKey(world.Ctx, world.RepoId)
		if err != nil || !bytes.Equal(held.Commitment(), key.Commitment()) {
			t.Errorf("%s does not hold generation 1: %v", device.Label, err)
		}
	}
}

// FS-20: KF1's creation lands at gkm and its answer is lost: the client sends the same bytes again, which resume
// every If-None-Match create, and one group stands.
func TestFsKeysRecoveryKf1WhoseAnswerIsLostStandsOnce(t *testing.T) {
	world, creator, _, agent := newFsKeysCreationWorld(t)
	world.Place(creator)
	dropped := 0
	creator.Transport.Before = func(request *http.Request) FsKeysFault {
		if fsKeysGroupCreate(request) && dropped == 0 {
			dropped += 1
			return FsKeysFaultDropAnswer
		}
		return FsKeysFaultNone
	}
	key, err := creator.Client.CreateGroup(world.Ctx, &sidecar.GkmCreateGroupArgs{NetworkId: sidecar.Id(world.NetworkId), RepoId: world.RepoId, Kind: world.Kind})
	if err != nil {
		t.Fatalf("a creation whose answer was lost: %v", err)
	}
	world.GroupId = key.GroupId()
	if dropped != 1 || world.FormCount() != 1 || world.GenerationCount() != 1 {
		t.Fatalf("the creation: %d dropped, %d forms, %d generations", dropped, world.FormCount(), world.GenerationCount())
	}
	if !bytes.Equal(world.Generation(1).Rotate.GetCommitment(), key.Commitment()) || !world.WrapRecipients(1)[agent.SidecarId()] {
		t.Errorf("generation 1 is not the creation's, or lacks its delivery")
	}
}

// FS-20: KF1 killed between its group and generation 1's deliveries: the repo is still keying, and the restart
// stages the deliveries before the creation answers, so the activation that follows has every first wrap behind it;
// a creator whose only device is lost at that point instead leaves the repo keying, with no content possible.
func TestFsKeysRecoveryKf1KilledBeforeItsDeliveriesStaysKeyingUntilTheRestart(t *testing.T) {
	for _, lost := range []bool{false, true} {
		world, creator, _, agent := newFsKeysCreationWorld(t)
		world.Place(creator)
		creator.Transport.Before = func(request *http.Request) FsKeysFault {
			if fsKeysFirstWraps(request) {
				return FsKeysFaultFailBefore
			}
			return FsKeysFaultNone
		}
		args := &sidecar.GkmCreateGroupArgs{NetworkId: sidecar.Id(world.NetworkId), RepoId: world.RepoId, Kind: world.Kind}
		if _, err := creator.Client.CreateGroup(world.Ctx, args); err == nil {
			t.Fatal("a creation killed before its deliveries answered")
		}
		if world.FormCount() != 1 || world.RepoState() != protocol.EvsRepoState_EVS_REPO_KEYING {
			t.Fatalf("the group stands, keying: %d forms, state %s", world.FormCount(), world.RepoState())
		}
		if lost {
			// the creator's only device is gone: nothing activates the repo, and its group has no delivery
			world.GroupId = fsKeysOnlyGroup(t, world)
			if len(world.WrapRecipients(1)) != 0 || world.RepoState() != protocol.EvsRepoState_EVS_REPO_KEYING {
				t.Errorf("a lost creator's repo has deliveries or left keying")
			}
			continue
		}
		creator.Transport.Before = nil
		creator.Restart()
		key, err := creator.Client.CreateGroup(world.Ctx, args)
		if err != nil {
			t.Fatalf("the restarted creation: %v", err)
		}
		world.GroupId = key.GroupId()
		if world.FormCount() != 1 || !world.WrapRecipients(1)[agent.SidecarId()] {
			t.Fatalf("the resumed creation: %d forms, the agent's delivery %v", world.FormCount(), world.WrapRecipients(1)[agent.SidecarId()])
		}
		world.Activate()
		if held, err := agent.Client.CurrentRepoKey(world.Ctx, world.RepoId); err != nil || held.Generation() != 1 {
			t.Errorf("the agent's first wrap: %v", err)
		}
	}
}

// The group the world's repo's one form names.
func fsKeysOnlyGroup(t *testing.T, world *FsKeysWorld) sidecar.Id {
	t.Helper()
	for _, body := range world.objects(gkmservice.GkmFormPrefix(world.RepoId)) {
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(body, signed); err != nil {
			t.Fatal(err)
		}
		form := &protocol.GroupForm{}
		if err := proto.Unmarshal(signed.GetBody(), form); err != nil {
			t.Fatal(err)
		}
		groupId, err := sidecar.IdFromBytes(form.GetGroupId())
		if err != nil {
			t.Fatal(err)
		}
		return groupId
	}
	t.Fatal("no form")
	return sidecar.Id{}
}
