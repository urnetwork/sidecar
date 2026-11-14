//go:build !sidecar_http && !ios_extension

// RECORD-M6-18's requests over the fake world (FS-85's filing cases): a request's entry then its notice, which names
// no approver; the 21st pending and the 51st daily request refused; a request to a private repo by its id; the
// endorsement's channels in tainted and untainted runs; a target's older pending requests shown first past
// directory_target_pending; and a request past not_after read as expired, never as denied.

package sidecar_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A world with a general repo, its admin's device, which decides its requests, and a requesting member's device.
type testRequestsEnv struct {
	t               *testing.T
	world           *testDirectoryWorld
	requester       *testDirectoryDevice
	approver        *testDirectoryDevice
	requesterMember sidecar.Id
	approverMember  sidecar.Id
	repoId          sidecar.Id
	// what GET /sidecar/limits answers every device; nil answers an error
	limits map[string]int64
	// what the gate answers an agent's request, and how often it was asked
	endorsed     *sidecar.DirectoryEndorsed
	endorseErr   error
	endorseCount int
	// access_request and access_decided as raised, by device
	events map[sidecar.Id][]string
}

// The events one device raised.
type testRequestsEvents struct {
	env       *testRequestsEnv
	sidecarId sidecar.Id
}

func (self *testRequestsEvents) RaiseAccessRequest(requestId sidecar.Id) error {
	self.env.events[self.sidecarId] = append(self.env.events[self.sidecarId], "access_request/"+requestId.String())
	return nil
}

func (self *testRequestsEvents) RaiseAccessDecided(requestId sidecar.Id, outcome string) error {
	self.env.events[self.sidecarId] = append(self.env.events[self.sidecarId], "access_decided/"+outcome+"/"+requestId.String())
	return nil
}

func newTestRequestsEnv(t *testing.T) *testRequestsEnv {
	t.Helper()
	world := newTestDirectoryWorld(t, nil)
	env := &testRequestsEnv{
		t:               t,
		world:           world,
		requesterMember: sidecar.NewId(),
		approverMember:  sidecar.NewId(),
		limits: map[string]int64{
			sidecar.DirectoryLimitRequestsPending: 20,
			sidecar.DirectoryLimitRequestsPerDay:  50,
			sidecar.DirectoryLimitRequestsPerRun:  5,
			sidecar.DirectoryLimitTargetPending:   100,
		},
		events: map[sidecar.Id][]string{},
	}
	requesterWriter := world.memberWriter(env.requesterMember)
	approverWriter := world.memberWriter(env.approverMember)
	world.publish()
	env.repoId = world.createRepo(protocol.RepoKind_REPO_KIND_GENERAL, nil, approverWriter)
	env.requester = env.device(requesterWriter)
	env.approver = env.device(approverWriter)
	return env
}

// writer's device with its requests bound to the env's limits, gate and events.
func (self *testRequestsEnv) device(writer *testDirectoryWriter) *testDirectoryDevice {
	self.t.Helper()
	device := self.world.device(writer)
	device.client.BindRequests(self.binding(device))
	return device
}

// The seams a device's requests are bound to.
func (self *testRequestsEnv) binding(device *testDirectoryDevice) *sidecar.DirectoryRequestsBinding {
	return &sidecar.DirectoryRequestsBinding{
		Limits: func(ctx context.Context) (*sidecar.QuotaLimits, error) {
			if self.limits == nil {
				return nil, errors.New("limits did not answer")
			}
			return &sidecar.QuotaLimits{Tier: "team", Limits: self.limits}, nil
		},
		Endorse: func(ctx context.Context, endorsement *sidecar.DirectoryEndorsement) (*sidecar.DirectoryEndorsed, error) {
			self.endorseCount += 1
			if endorsement.Action == nil || len(endorsement.Action.Bytes) == 0 {
				self.t.Errorf("an endorsement asked with no action")
			}
			return self.endorsed, self.endorseErr
		},
		Events: &testRequestsEvents{env: self, sidecarId: device.writer.sidecarId},
		Land:   func(ctx context.Context) error { return device.record.Flush(ctx) },
	}
}

// A person's own ask for reader on the env's repo.
func (self *testRequestsEnv) ask() *sidecar.DirectoryRequestAsk {
	return &sidecar.DirectoryRequestAsk{
		Target:  &protocol.RequestTarget{RepoId: self.repoId.Bytes()},
		Role:    uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_READER),
		Reason:  "to read the build notes",
		FiledBy: sidecar.DirectoryFiledByPerson,
	}
}

// Files ask on device, which must succeed.
func (self *testRequestsEnv) mustFile(device *testDirectoryDevice, ask *sidecar.DirectoryRequestAsk) *sidecar.DirectoryRequestFiled {
	self.t.Helper()
	filed, err := device.client.Request(self.t.Context(), ask)
	if err != nil {
		self.t.Fatal(err)
	}
	return filed
}

// The requests device shows under filter after a sync.
func (self *testRequestsEnv) requests(device *testDirectoryDevice, filter *sidecar.DirectoryRequestFilter) []*sidecar.DirectoryRequestView {
	self.t.Helper()
	device.mustSync(self.t)
	views, err := device.client.GetRequests(self.t.Context(), filter)
	if err != nil {
		self.t.Fatal(err)
	}
	return views
}

// The one request of id device shows.
func (self *testRequestsEnv) request(device *testDirectoryDevice, requestId sidecar.Id) *sidecar.DirectoryRequestView {
	self.t.Helper()
	views := self.requests(device, &sidecar.DirectoryRequestFilter{RequestId: &requestId})
	if len(views) != 1 {
		self.t.Fatalf("%d requests of id %s", len(views), requestId)
	}
	return views[0]
}

// The notice a path holds on the cards ref as device's copy read it, nil for none.
func testNoticeAt(t *testing.T, device *testDirectoryDevice, path string) *protocol.DirectoryNotice {
	t.Helper()
	for _, file := range device.client.Cards() {
		if file.Path == path && !file.Removed {
			notice, err := sidecar.DirectoryDecodeNotice(file.Content)
			if err != nil {
				t.Fatal(err)
			}
			return notice
		}
	}
	return nil
}

// A person's request appends its entry, then writes a pending notice that names the request, its requester and the
// entry's seq and no approver; its subject is the member; the repo's admin sees it as one it decides, and access_request
// is raised once there.
func TestDirectoryRequestFilesEntryThenNotice(t *testing.T) {
	env := newTestRequestsEnv(t)
	filed := env.mustFile(env.requester, env.ask())
	if !filed.NoticeWritten || filed.EntrySeq == 0 || !filed.SubjectIsMember || filed.Subject != env.requesterMember ||
		filed.Channel != protocol.ApprovalChannel_APPROVAL_CHANNEL_UNSPECIFIED {
		t.Fatalf("filed %+v", filed)
	}
	if env.endorseCount != 0 {
		t.Fatalf("a person's own request asked for %d endorsements", env.endorseCount)
	}
	view := env.request(env.approver, filed.RequestId)
	if view.State != sidecar.DirectoryRequestPending || !view.Decidable || view.Mine || view.Notice == nil ||
		view.RequesterSidecarId != env.requester.writer.sidecarId || view.EntrySeq != filed.EntrySeq ||
		view.Request.GetReason() != "to read the build notes" || view.Request.GetFiledBy() != uint32(sidecar.DirectoryFiledByPerson) {
		t.Fatalf("the approver's view %+v", view)
	}
	notice := testNoticeAt(t, env.approver, filed.NoticePath)
	if notice == nil || len(notice.GetDecisions()) != 0 || notice.GetState() != uint32(sidecar.DirectoryNoticeStatePending) ||
		notice.GetEntrySeq() != filed.EntrySeq || notice.GetNotAfterMillis() != filed.NotAfterMillis {
		t.Fatalf("notice %v", notice)
	}
	// no approver named in a notice: readers compute them from their own state
	for _, file := range env.approver.client.Cards() {
		if bytes.Contains(file.Content, env.approver.writer.sidecarId.Bytes()) || bytes.Contains(file.Content, env.approverMember.Bytes()) {
			t.Fatalf("the notice at %s names an approver", file.Path)
		}
	}
	mine := env.request(env.requester, filed.RequestId)
	if !mine.Mine || mine.Decidable || mine.State != sidecar.DirectoryRequestPending {
		t.Fatalf("the requester's view %+v", mine)
	}
	if decidable := env.requests(env.requester, &sidecar.DirectoryRequestFilter{Decidable: true}); len(decidable) != 0 {
		t.Fatalf("the requester decides %d requests", len(decidable))
	}
	for range 2 {
		if err := env.approver.client.Requests().Maintain(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if events := env.events[env.approver.writer.sidecarId]; len(events) != 1 || events[0] != "access_request/"+filed.RequestId.String() {
		t.Fatalf("the approver's events %v", events)
	}
	// a read_only client files nothing, and a request for a repo no state holds names no target
	readOnly := env.world.clientFor(env.requester.writer.sidecarId, env.requester.record.Writer(), true)
	if _, err := readOnly.client.Request(t.Context(), env.ask()); !errors.Is(err, sidecar.ErrDirectoryReadOnly) {
		t.Fatalf("a read_only client's request answered %v", err)
	}
	unknown := env.ask()
	unknown.Target = &protocol.RequestTarget{RepoId: sidecar.NewId().Bytes()}
	if _, err := env.requester.client.Request(t.Context(), unknown); !errors.Is(err, sidecar.ErrDirectoryRequestTarget) {
		t.Fatalf("a request for no repo answered %v", err)
	}
}

// The 21st pending request and the 51st request of a day are refused with their keys, nothing filed; a key the limits
// do not carry refuses, as limits that do not answer do.
func TestDirectoryRequestRefusedPastItsLimits(t *testing.T) {
	env := newTestRequestsEnv(t)
	for i := 0; i < 20; i += 1 {
		env.mustFile(env.requester, env.ask())
	}
	_, err := env.requester.client.Request(t.Context(), env.ask())
	var limitErr *sidecar.DirectoryLimitError
	if !errors.As(err, &limitErr) || limitErr.Key != sidecar.DirectoryLimitRequestsPending || limitErr.Limit != 20 || limitErr.Used != 20 ||
		!errors.Is(err, sidecar.ErrDirectoryRequestLimit) {
		t.Fatalf("the 21st pending request answered %v", err)
	}
	// with no pending limit, the day's count refuses the 51st
	env.limits[sidecar.DirectoryLimitRequestsPending] = -1
	for i := 20; i < 50; i += 1 {
		env.mustFile(env.requester, env.ask())
	}
	_, err = env.requester.client.Request(t.Context(), env.ask())
	if !errors.As(err, &limitErr) || limitErr.Key != sidecar.DirectoryLimitRequestsPerDay || limitErr.Used != 50 {
		t.Fatalf("the 51st request of the day answered %v", err)
	}
	// what a sync read back is counted once, not twice
	env.requester.mustSync(t)
	if _, err = env.requester.client.Request(t.Context(), env.ask()); !errors.As(err, &limitErr) || limitErr.Used != 50 {
		t.Fatalf("the 51st request after a sync answered %v", err)
	}
	// a day on, the window has moved
	env.world.clock.Advance(25 * time.Hour)
	env.mustFile(env.requester, env.ask())

	// a run's sixth request
	runId := sidecar.NewId()
	env.endorsed = &sidecar.DirectoryEndorsed{Channel: protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, DecisionSha256: bytes.Repeat([]byte{0x41}, 32)}
	for i := 0; i < 5; i += 1 {
		ask := env.ask()
		ask.FiledBy, ask.RunId = sidecar.DirectoryFiledByAgent, &runId
		env.mustFile(env.requester, ask)
	}
	ask := env.ask()
	ask.FiledBy, ask.RunId = sidecar.DirectoryFiledByAgent, &runId
	if _, err = env.requester.client.Request(t.Context(), ask); !errors.As(err, &limitErr) || limitErr.Key != sidecar.DirectoryLimitRequestsPerRun {
		t.Fatalf("a run's sixth request answered %v", err)
	}

	delete(env.limits, sidecar.DirectoryLimitTargetPending)
	if _, err = env.requester.client.Request(t.Context(), env.ask()); !errors.As(err, &limitErr) || limitErr.Key != sidecar.DirectoryLimitTargetPending || limitErr.Limit != 0 {
		t.Fatalf("a request under limits with no target key answered %v", err)
	}
	env.limits = nil
	if _, err = env.requester.client.Request(t.Context(), env.ask()); !errors.Is(err, sidecar.ErrDirectoryLimitsUnavailable) {
		t.Fatalf("a request with no limits answered %v", err)
	}
	// with no limits a reader shows its own requests and no other's
	if views, err := env.approver.client.GetRequests(t.Context(), nil); !errors.Is(err, sidecar.ErrDirectoryLimitsUnavailable) || len(views) != 0 {
		t.Fatalf("a reader with no limits showed %d requests, %v", len(views), err)
	}
}

// A repo that announces nothing, private or not, takes a request by its id.
func TestDirectoryRequestToAPrivateRepoById(t *testing.T) {
	env := newTestRequestsEnv(t)
	if _, shown := env.requester.client.RepoItem(env.repoId); shown {
		t.Fatal("the repo announces an item")
	}
	ask := env.ask()
	ask.Role = uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER)
	filed := env.mustFile(env.requester, ask)
	view := env.request(env.approver, filed.RequestId)
	if !view.Decidable || sidecar.Id(view.Request.GetTarget().GetRepoId()) != env.repoId ||
		view.Request.GetRole() != uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER) || len(view.Request.GetAnnouncementId()) != 0 {
		t.Fatalf("view %+v", view)
	}
	// a role the target does not take is refused before anything is filed
	ask = env.ask()
	ask.Role = 9
	if _, err := env.requester.client.Request(t.Context(), ask); !errors.Is(err, sidecar.ErrDirectoryFormatInvalid) {
		t.Fatalf("role 9 answered %v", err)
	}
	// a worker request with nothing announced by that sidecar names no target
	worker := env.ask()
	worker.Target = &protocol.RequestTarget{SidecarId: env.approver.writer.sidecarId.Bytes(), TcpPorts: []uint32{8080}}
	worker.Role = uint32(protocol.AclAction_ACL_ACTION_DIAL)
	if _, err := env.requester.client.Request(t.Context(), worker); !errors.Is(err, sidecar.ErrDirectoryRequestTarget) {
		t.Fatalf("a request to an unannounced worker answered %v", err)
	}
}

// An agent's request needs the member's endorsement before anything is filed: harness evidence passes in an untainted
// run and is refused in a tainted one, where device evidence passes; a pending endorsement and an unbound gate file
// nothing; the subject is the requesting sidecar unless the endorsing person widens it.
func TestDirectoryRequestEndorsementChannels(t *testing.T) {
	env := newTestRequestsEnv(t)
	runId, agentId := sidecar.NewId(), sidecar.NewId()
	agentAsk := func(tainted bool) *sidecar.DirectoryRequestAsk {
		ask := env.ask()
		ask.FiledBy, ask.RunId, ask.AgentId, ask.Tainted = sidecar.DirectoryFiledByAgent, &runId, &agentId, tainted
		return ask
	}
	decisionSha256 := bytes.Repeat([]byte{0x41}, 32)
	env.endorsed = &sidecar.DirectoryEndorsed{Channel: protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS, DecisionSha256: decisionSha256}
	filed := env.mustFile(env.requester, agentAsk(false))
	if filed.Channel != protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS || filed.SubjectIsMember || filed.Subject != env.requester.writer.sidecarId {
		t.Fatalf("an untainted run's request %+v", filed)
	}
	view := env.request(env.approver, filed.RequestId)
	if view.Request.GetFiledBy() != uint32(sidecar.DirectoryFiledByAgent) || view.Request.GetTainted() ||
		view.Request.GetEndorsementChannel() != uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS) ||
		!bytes.Equal(view.Request.GetEndorsementSha256(), decisionSha256) || view.RunId == nil || *view.RunId != runId {
		t.Fatalf("the approver's view %+v", view.Request)
	}

	if _, err := env.requester.client.Request(t.Context(), agentAsk(true)); !errors.Is(err, sidecar.ErrDirectoryRequestUnendorsed) {
		t.Fatalf("a tainted run's request on harness evidence answered %v", err)
	}
	env.endorsed = &sidecar.DirectoryEndorsed{Channel: protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, DecisionSha256: decisionSha256, ForMember: true}
	widened := agentAsk(true)
	widened.ForMember = true
	filed = env.mustFile(env.requester, widened)
	if filed.Channel != protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE || !filed.SubjectIsMember || filed.Subject != env.requesterMember {
		t.Fatalf("a tainted run's widened request %+v", filed)
	}
	if view := env.request(env.approver, filed.RequestId); !view.Request.GetTainted() {
		t.Fatalf("a tainted run's request reads untainted")
	}

	// a decision still awaited, and no gate at all, file nothing
	env.endorsed, env.endorseErr = nil, &sidecar.ApprovalPendingError{ApprovalId: sidecar.NewId()}
	var pending *sidecar.ApprovalPendingError
	if _, err := env.requester.client.Request(t.Context(), agentAsk(false)); !errors.As(err, &pending) {
		t.Fatalf("an awaited endorsement answered %v", err)
	}
	unbound := env.binding(env.requester)
	unbound.Endorse = nil
	env.requester.client.BindRequests(unbound)
	if _, err := env.requester.client.Request(t.Context(), agentAsk(false)); !errors.Is(err, sidecar.ErrDirectoryRequestUnendorsed) {
		t.Fatalf("a request with no gate answered %v", err)
	}
	if views := env.requests(env.approver, nil); len(views) != 2 {
		t.Fatalf("%d requests filed", len(views))
	}
}

// Past directory_target_pending a target shows its older pending requests first: a later one waits until an older
// one clears, here by expiring.
func TestDirectoryRequestOlderPendingShownFirst(t *testing.T) {
	env := newTestRequestsEnv(t)
	env.limits[sidecar.DirectoryLimitTargetPending] = 2
	others := []*testDirectoryDevice{env.requester}
	for range 2 {
		writer := env.world.memberWriter(sidecar.NewId())
		env.world.publish()
		others = append(others, env.device(writer))
	}
	filed := []*sidecar.DirectoryRequestFiled{}
	for index, device := range others {
		ask := env.ask()
		if index == 0 {
			ask.NotAfter = time.Hour
		}
		filed = append(filed, env.mustFile(device, ask))
		env.world.clock.Advance(time.Minute)
	}
	shown := env.requests(env.approver, &sidecar.DirectoryRequestFilter{Decidable: true})
	if len(shown) != 2 || shown[0].RequestId != filed[0].RequestId || shown[1].RequestId != filed[1].RequestId {
		t.Fatalf("%d requests shown first", len(shown))
	}
	// the third's own requester still sees it
	if view := env.request(others[2], filed[2].RequestId); view.State != sidecar.DirectoryRequestPending || !view.Mine {
		t.Fatalf("the third requester's view %+v", view)
	}
	env.world.clock.Advance(2 * time.Hour)
	shown = env.requests(env.approver, &sidecar.DirectoryRequestFilter{Decidable: true})
	if len(shown) != 2 || shown[0].RequestId != filed[1].RequestId || shown[1].RequestId != filed[2].RequestId {
		t.Fatalf("%d requests shown once the oldest expired", len(shown))
	}
}

// Past not_after a pending request is expired in every reader's view, with no entry written, and never denied; it
// frees its requester's pending count, and a life past 30 days is refused.
func TestDirectoryRequestExpiryNeverReadsAsDenied(t *testing.T) {
	env := newTestRequestsEnv(t)
	env.limits[sidecar.DirectoryLimitRequestsPending] = 1
	filed := env.mustFile(env.requester, env.ask())
	if filed.NotAfterMillis != env.world.clock.Now().Add(7*24*time.Hour).UnixMilli() {
		t.Fatalf("not_after %d", filed.NotAfterMillis)
	}
	env.requester.mustSync(t)
	if _, err := env.requester.client.Request(t.Context(), env.ask()); !errors.Is(err, sidecar.ErrDirectoryRequestLimit) {
		t.Fatalf("a second pending request under a limit of one answered %v", err)
	}
	writes := env.world.cards.Counts().CardWrites
	env.world.clock.Advance(7*24*time.Hour + time.Second)
	for _, device := range []*testDirectoryDevice{env.requester, env.approver} {
		view := env.request(device, filed.RequestId)
		if view.State != sidecar.DirectoryRequestExpired || view.Decidable || len(view.Decisions) != 0 {
			t.Fatalf("a request past not_after reads %s", view.State)
		}
	}
	if err := env.requester.client.Requests().Maintain(t.Context()); err != nil {
		t.Fatal(err)
	}
	if env.world.cards.Counts().CardWrites != writes {
		t.Fatal("an expired request's notice was written again")
	}
	env.mustFile(env.requester, env.ask())
	long := env.ask()
	long.NotAfter = 31 * 24 * time.Hour
	if _, err := env.requester.client.Request(t.Context(), long); !errors.Is(err, sidecar.ErrDirectoryFormatInvalid) {
		t.Fatalf("a life of 31 days answered %v", err)
	}
}
