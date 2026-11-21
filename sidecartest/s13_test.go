package sidecartest

// S13 at M6 (§22.4's S13, F13; FS-84 to FS-88; owner decisions 170, 171, 181; RECORD-M6-26), on this package's fakes
// with every entry sealed and signed for real: B's agent finds member A's run within one sync by directory_list's
// answer (the folded listing as stubs), grouped by agent, its title withheld and B's run untainted; a run in a repo
// marked private at creation shows private and the repo id; a run in an announced general repo shows the repo's name
// beside its branch; B requests read on the private repo by its id, its repo admin's lease is hinted, a person
// approves, and B's daemon verifies the RepoGrant at its log position; a denial shows its note; a revoked announcement
// leaves no readable copy of the name once the erasure runner has run; A's opt-out stops A's announcements, and A's
// removal masks them at once.
//
// What is not here: the request by B's agent through directory_request with its harness endorsement (CanonicalAction
// version 3's gate lookup is not bound), the worker reach and its GrantActivate, and phones woken from M8; B's
// request here is a person's. search_agents from M10 runs on the evs world, in fault's s13_search_test.go.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One S13 device: its key, record, directory client and what it raised and recorded.
type s13Device struct {
	sidecarId sidecar.Id
	memberId  sidecar.Id
	key       ed25519.PrivateKey
	record    *sidecar.SidecarRecord
	client    *sidecar.DirectoryClient
	world     *s13World
	hints     int

	stateLock sync.Mutex
	events    []string
	recorded  []*sidecar.DirectoryReceipt
}

func (self *s13Device) sign(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
	return &bridge.Signed{Body: bytes.Clone(body), SignerId: self.sidecarId.Bytes(), Signature: ed25519.Sign(self.key, bridge.SignedBytes(purpose, signedType, body)), Type: uint32(signedType)}, nil
}

func (self *s13Device) RaiseAccessRequest(requestId sidecar.Id) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.events = append(self.events, "access_request/"+requestId.String())
	return nil
}

func (self *s13Device) RaiseAccessDecided(requestId sidecar.Id, outcome string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.events = append(self.events, "access_decided/"+outcome+"/"+requestId.String())
	return nil
}

func (self *s13Device) SignRepoAccess(ctx context.Context, access *sidecar.DirectoryRepoAccess) ([]byte, error) {
	return []byte(fmt.Sprintf("repo-grant/%s/%s/%s/%d", self.sidecarId, access.RepoId, access.Subject, access.Role)), nil
}

func (self *s13Device) FileStatement(ctx context.Context, signed []byte) (uint64, error) {
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	if position, ok := self.world.statements[string(signed)]; ok {
		return position, nil
	}
	self.world.position += 1
	self.world.statements[string(signed)] = self.world.position
	return self.world.position, nil
}

func (self *s13Device) SignReachDecision(ctx context.Context, request *sidecar.StoredApprovalRequest, subject sidecar.Id, expiresMillis int64) ([]byte, error) {
	return nil, errors.New("no reach decision in S13 at M6")
}

func (self *s13Device) StatementHeld(ctx context.Context, statementSha256 []byte, position uint64) (bool, error) {
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	for signed, held := range self.world.statements {
		sum := sha256.Sum256([]byte(signed))
		if held == position && bytes.Equal(sum[:], statementSha256) {
			return true, nil
		}
	}
	return false, nil
}

func (self *s13Device) ActivateReach(ctx context.Context, request *sidecar.StoredApprovalRequest, decisions [][]byte) error {
	return errors.New("no reach approval in S13 at M6")
}

func (self *s13Device) Record(ctx context.Context, receipt *sidecar.DirectoryReceipt) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.recorded = append(self.recorded, receipt)
	return nil
}

// Every run B's device reads untainted.
func (self *s13Device) RunTainted(runId sidecar.Id) bool {
	return false
}

// S13's team: A, a member with a private repo X and an announced repo Y, B, a member, and D, a directory admin.
type s13World struct {
	t                *testing.T
	clock            *FakeClock
	streams          *FakeRecordStreams
	cards            *FakeDirectoryCards
	directoryAuth    *FakeDirectoryAuth
	directoryFixture *FakeDirectoryAuthFixture
	recordAuth       *FakeRecordAuth
	recordFixture    *FakeRecordAuthFixture
	directoryId      sidecar.Id
	networkId        sidecar.Id
	privateId        sidecar.Id
	announcedId      sidecar.Id
	a, b, d          *s13Device
	// each device's directory client's logger, for a test that captures the logs; nil logs nothing
	logs func(device *s13Device) sidecar.Logger

	stateLock  sync.Mutex
	statements map[string]uint64
	position   uint64
}

func (self *s13World) publish() {
	self.recordFixture.TimeMillis = self.clock.Now().UnixMilli()
	self.directoryFixture.TimeMillis = self.recordFixture.TimeMillis
	self.recordAuth.Append(self.recordFixture)
	self.directoryAuth.Append(self.directoryFixture)
}

func (self *s13World) device(admin bool) *s13Device {
	t := self.t
	publicKey, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	memberId := sidecar.NewId()
	device := &s13Device{sidecarId: sidecar.NewId(), memberId: memberId, key: key, world: self}
	if err := self.streams.Grant(self.directoryId, device.sidecarId, RecordStreamsScope{Read: true, Write: true, Admin: admin}); err != nil {
		t.Fatal(err)
	}
	self.recordFixture.IdentityKeys[device.sidecarId] = publicKey
	self.recordFixture.Members[device.sidecarId] = memberId
	repo := self.recordFixture.Repos[self.directoryId]
	repo.Readers = append(repo.Readers, device.sidecarId)
	repo.Writers = append(repo.Writers, device.sidecarId)
	if admin {
		repo.Admins = append(repo.Admins, device.sidecarId)
		directory := self.directoryFixture.Repos[self.directoryId]
		directory.Admins = append(directory.Admins, FakeDirectoryRepoAdmin{SidecarId: device.sidecarId, At: 1})
	}
	self.directoryFixture.Sidecars[device.sidecarId] = &FakeDirectorySidecar{MemberId: &memberId}
	return device
}

func (self *s13World) open(device *s13Device) {
	t := self.t
	recordStore, err := NewFakeStore().Root().Directory("record", "record")
	if err != nil {
		t.Fatal(err)
	}
	record, err := sidecar.OpenSidecarRecord(self.t.Context(), &sidecar.SidecarRecordArgs{
		SidecarId: device.sidecarId, IdentityPublicKey: device.key.Public().(ed25519.PublicKey), Store: recordStore, Sign: device.sign,
		Streams: self.streams.For(device.sidecarId), Auth: func() sidecar.RecordAuthView { return self.recordAuth.Tip() },
		Clock: self.clock, Settings: sidecar.DefaultSidecarSettings().Record,
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewFakeStore().Root().Directory("directory", "search")
	if err != nil {
		t.Fatal(err)
	}
	var log sidecar.Logger
	if self.logs != nil {
		log = self.logs(device)
	}
	client, err := sidecar.NewDirectoryClient(&sidecar.DirectoryClientArgs{
		SidecarId: device.sidecarId, Store: store, Cards: self.cards.For(device.sidecarId), Log: log,
		Streams:    func() sidecar.RecordStreams { return self.streams.For(device.sidecarId) },
		Auth:       func() sidecar.DirectoryAuthView { return self.directoryAuth.Tip() },
		RecordAuth: func() sidecar.RecordAuthView { return self.recordAuth.Tip() },
		Clock:      self.clock, Settings: sidecar.DefaultSidecarSettings().Directory, Writer: record.Writer(),
		NetworkId: self.networkId, Sign: device.sign, Runs: device,
	})
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := sidecar.NewApprovalLedger(NewFakeStore().Root(), sidecar.DefaultSidecarSettings().Mcp, self.clock)
	if err != nil {
		t.Fatal(err)
	}
	client.BindRequests(&sidecar.DirectoryRequestsBinding{
		Limits: func(ctx context.Context) (*sidecar.QuotaLimits, error) {
			return &sidecar.QuotaLimits{Tier: "team", Limits: map[string]int64{
				sidecar.DirectoryLimitRequestsPending: 20, sidecar.DirectoryLimitRequestsPerDay: 50,
				sidecar.DirectoryLimitRequestsPerRun: 5, sidecar.DirectoryLimitTargetPending: 100,
			}, Enforced: true}, nil
		},
		Events: device, Land: func(ctx context.Context) error { return record.Flush(ctx) }, Journal: ledger, Statements: device, Receipts: device,
	})
	device.record, device.client = record, client
}

func newS13World(t *testing.T) *s13World {
	clock := NewFakeClock(DefaultClockStart())
	streams := NewFakeRecordStreams(clock, nil, nil)
	directoryId, err := streams.NewRepo(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	world := &s13World{
		t: t, clock: clock, streams: streams, cards: NewFakeDirectoryCards(streams, nil), directoryAuth: NewFakeDirectoryAuth(),
		recordAuth: NewFakeRecordAuth(), directoryId: directoryId, networkId: sidecar.NewId(), privateId: sidecar.NewId(),
		announcedId: sidecar.NewId(), statements: map[string]uint64{},
		directoryFixture: &FakeDirectoryAuthFixture{
			Sidecars: map[sidecar.Id]*FakeDirectorySidecar{}, DirectoryId: &directoryId,
			Repos: map[sidecar.Id]*FakeDirectoryRepo{directoryId: {Kind: protocol.RepoKind_REPO_KIND_DIRECTORY}},
		},
		recordFixture: &FakeRecordAuthFixture{
			IdentityKeys: map[sidecar.Id][]byte{}, Members: map[sidecar.Id]sidecar.Id{},
			Repos: map[sidecar.Id]*FakeRecordRepoAuth{directoryId: {}}, Logs: &sidecar.RecordLogIds{Team: true, DirectoryId: &directoryId},
		},
	}
	world.a, world.b, world.d = world.device(false), world.device(false), world.device(true)
	for _, repoId := range []sidecar.Id{world.privateId, world.announcedId} {
		world.directoryFixture.Repos[repoId] = &FakeDirectoryRepo{Kind: protocol.RepoKind_REPO_KIND_GENERAL, Admins: []FakeDirectoryRepoAdmin{{SidecarId: world.a.sidecarId, At: 1}}}
	}
	world.publish()
	for _, device := range []*s13Device{world.a, world.b, world.d} {
		world.open(device)
	}
	return world
}

// The steps of S13 at M6: see the file header.
func TestS13AtM6(t *testing.T) {
	ctx := t.Context()
	world := newS13World(t)
	a, b, d := world.a, world.b, world.d
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(a.client.Sync(ctx))
	// X marked private at creation, Y announced
	_, err := a.client.AnnounceRepo(ctx, &sidecar.DirectoryRepoAnnounceArgs{RepoId: world.privateId, Private: true, Confirmed: true})
	must(err)
	_, err = a.client.AnnounceRepo(ctx, &sidecar.DirectoryRepoAnnounceArgs{RepoId: world.announcedId, DisplayName: "launch site", Confirmed: true})
	must(err)
	must(a.record.Flush(ctx))
	must(a.client.Sync(ctx))
	privateRun, announcedRun := sidecar.NewId(), sidecar.NewId()
	for _, start := range []*sidecar.DirectoryRunStart{
		{RunId: privateRun, Claims: sidecar.DirectoryRunClaimsAuto, ProjectKey: "x", AgentLabel: "builder", Harness: "codex", Title: "rework the private module", RepoId: &world.privateId, Branch: "main"},
		{RunId: announcedRun, Claims: sidecar.DirectoryRunClaimsAuto, ProjectKey: "y", AgentLabel: "builder", Harness: "codex", Title: "ship the launch page", RepoId: &world.announcedId, Branch: "launch"},
	} {
		must(a.client.Runs().Started(start))
	}
	world.clock.Advance(10 * time.Second)
	must(a.record.Flush(ctx))

	// B's agent finds A's runs within one sync, grouped by agent, titles withheld, B's run untainted
	must(b.client.Sync(ctx))
	items, err := b.client.List(&sidecar.DirectoryFilter{Kind: sidecar.DirectoryAnnouncementKindRun, ActiveOnly: true})
	must(err)
	byLabel := map[string][]*sidecar.DirectoryStub{}
	for _, item := range items {
		stub, err := sidecar.DirectoryStubOf(item, false)
		must(err)
		if 0 < len(stub.Untrusted) || stub.UntrustedWithheld == 0 {
			t.Fatalf("a stub with prose: %+v", stub)
		}
		byLabel[item.Announcement.GetWho().GetAgentLabel()] = append(byLabel[item.Announcement.GetWho().GetAgentLabel()], stub)
	}
	if len(byLabel["builder"]) != 2 {
		t.Fatalf("A's runs by agent: %v", byLabel)
	}
	for _, item := range items {
		where := item.Announcement.GetWhere()
		repoId, _ := sidecar.IdFromBytes(where.GetRepoId())
		switch repoId {
		case world.privateId:
			if !where.GetPrivate() || where.GetBranch() != "" {
				t.Fatalf("the run in the private repo: %v", where)
			}
		case world.announcedId:
			repoItem, ok := b.client.RepoItem(world.announcedId)
			if where.GetPrivate() || where.GetBranch() != "launch" || !ok || repoItem.Announcement.GetWhat().GetTitle() != "launch site" {
				t.Fatalf("the run in the announced repo: %v, its repo's item %v", where, repoItem)
			}
		}
	}

	// B requests read on X by its id; A's lease on X's prefix is hinted; a person approves; B verifies the grant
	prefix, err := sidecar.DirectoryNoticePrefix(&protocol.RequestTarget{RepoId: world.privateId.Bytes()})
	must(err)
	release, err := a.client.Lease(prefix)
	must(err)
	defer release()
	leasesBefore := world.cards.Counts().LeasesTaken
	filed, err := b.client.Request(ctx, &sidecar.DirectoryRequestAsk{
		Target: &protocol.RequestTarget{RepoId: world.privateId.Bytes()}, Role: uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_READER),
		Reason: "to review the module", FiledBy: sidecar.DirectoryFiledByPerson,
	})
	must(err)
	if world.cards.Counts().LeasesTaken < leasesBefore {
		t.Fatal("A's lease went")
	}
	decide := func(device *s13Device, requestId sidecar.Id, approve bool, note string) *sidecar.DirectoryDecided {
		t.Helper()
		for range 2 {
			must(device.client.Sync(ctx))
			decided, err := device.client.Decide(ctx, &sidecar.DirectoryDecideArgs{RequestId: requestId, Approve: approve, Note: note})
			must(err)
			if decided.Finished() {
				return decided
			}
		}
		t.Fatal("the decision did not reach its notice")
		return nil
	}
	approved := decide(a, filed.RequestId, true, "")
	must(b.client.Sync(ctx))
	must(b.client.Requests().Maintain(ctx))
	if len(b.recorded) != 1 || b.recorded[0].Outcome != sidecar.SidecarAccessDecidedApproved ||
		b.recorded[0].Decisions[0].Decision.GetStatementPosition() != approved.StatementPosition {
		t.Fatalf("B's receipt: %+v", b.recorded)
	}

	// a denial shows its note
	denied, err := b.client.Request(ctx, &sidecar.DirectoryRequestAsk{
		Target: &protocol.RequestTarget{RepoId: world.announcedId.Bytes()}, Role: uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER),
		Reason: "to edit the page", FiledBy: sidecar.DirectoryFiledByPerson,
	})
	must(err)
	decide(a, denied.RequestId, false, "reviewers only this week")
	must(b.client.Sync(ctx))
	views, err := b.client.GetRequests(ctx, &sidecar.DirectoryRequestFilter{RequestId: &denied.RequestId})
	must(err)
	if len(views) != 1 || views[0].State != sidecar.DirectoryRequestDenied || views[0].Decisions[0].Decision.GetNote() != "reviewers only this week" {
		t.Fatalf("B's denied request: %+v", views)
	}

	// A revokes Y's announcement; after the erasure runner no readable copy of the name is left
	must(a.client.Sync(ctx))
	_, err = a.client.RevokeRepo(ctx, &sidecar.DirectoryRevokeArgs{RepoId: world.announcedId, Confirmed: true})
	must(err)
	must(a.record.Flush(ctx))
	d.client.BindEraser(d.record.Eraser().Erase)
	runner, err := sidecar.NewDirectoryErasureRunner(&sidecar.DirectoryErasureRunnerArgs{Client: d.client, Erase: d.record.Eraser().Erase, Random: bytes.NewReader(make([]byte, 64))})
	must(err)
	for range 2 {
		must(d.client.Sync(ctx))
		_, err := runner.Pass(ctx)
		must(err)
		must(d.record.Flush(ctx))
	}
	reader := d.record.Reader()
	must(reader.Sync(ctx, world.directoryId))
	entries, _ := reader.EntriesOfKinds(world.directoryId, 0, sidecar.RecordKindAnnounce)
	for _, entry := range entries {
		if entry.State == sidecar.RecordEntryLive && bytes.Contains(entry.Body, []byte("launch site")) {
			t.Fatalf("entry %s still holds the revoked name readable", entry.EntryId)
		}
	}

	// A's opt-out stops A's announcements; A's removal masks them at once
	must(a.client.Runs().Withdraw(privateRun))
	must(a.record.Flush(ctx))
	must(b.client.Sync(ctx))
	items, err = b.client.List(&sidecar.DirectoryFilter{Kind: sidecar.DirectoryAnnouncementKindRun})
	must(err)
	if slices.ContainsFunc(items, func(item *sidecar.DirectoryItem) bool {
		return bytes.Equal(item.Announcement.GetWhat().GetRunId(), privateRun.Bytes())
	}) {
		t.Fatal("a withdrawn run still shows")
	}
	world.directoryFixture.Sidecars[a.sidecarId].RevokedAt = world.directoryAuth.Tip().Pin().GetVersion() + 1
	world.publish()
	must(b.client.Sync(ctx))
	items, err = b.client.List(&sidecar.DirectoryFilter{Kind: sidecar.DirectoryAnnouncementKindRun})
	must(err)
	if slices.ContainsFunc(items, func(item *sidecar.DirectoryItem) bool { return item.SignerSidecarId == a.sidecarId }) {
		t.Fatal("a removed member's run still shows")
	}
}
