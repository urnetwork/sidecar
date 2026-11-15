//go:build !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-85's and FS-100's wake cases on T2 (§22.8; §16.11's phones row, D-SDK-28, D-MCP-34, §18.7, WK4; RECORD-M8-01).
//
// The phones are sidecar.DirectoryClients as built, each with its phone part bound and reaching evs through
// sidecartest's FakeDirectoryPhone, T4's phone surrogate until SDK-M8-15's cells exist: it keeps leases as evs keys
// them, lapsing 7 d after their last renewal, turns each hint into one wake whose payload pushservice builds, and
// serves §11.9's head reads. The desktop approver is a client of the world's fake cards, and decides by RECORD-M6-19's
// journal over its approval ledger. Entries are sealed and signed for real, so every reader verifies them.
//
//	FS-100's wakes  requester R, a phone leasing only its own notice's path, with no view open, no indexer and no
//	                stream sync; approver A denies R's repo request: R gets exactly one wake, naming no directory,
//	                target or request; at its resync R reads that notice version and the one decision entry its
//	                DecisionRef names, and no other stream, listing or cards read, and shows denied with A's note
//	                through access_decided, recorded in its vault
//	FS-85's wakes   an approver's phone, itself an admin of repo P, leases P's notice prefix alone; R's request wakes
//	                it once, naming nothing, and at its resync it lists the prefix and reads the request's entry,
//	                raising access_request once and showing the request as one it decides
//
// After every step, FI-26 as these cases hold it: no request is approved and none raised so, a decided notice names
// exactly A's denial, R's denied outcome stands only on a decided notice, and no wake names an id.
//
// What this is not: a run on T4's real cells or vendors (SDK-M8-15, OPS-M8-01), on T3's stores, or through
// pushservice's enqueuer and sender (PROTO-M8-01, SDK-M8-10); the surrogate makes the wake those would.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

var (
	Fs100Wakes = Register("FS-100", "wakes", []Tier{TierT2}, Fs100WakeOnDenial)
	Fs85Wakes  = Register("FS-85", "wakes", []Tier{TierT2}, Fs85WakeOnNewRequest)
)

// One sidecar of the wakes' world: its key, its record, its directory client, and what it raised.
type wakeDevice struct {
	name      string
	sidecarId sidecar.Id
	memberId  sidecar.Id
	key       ed25519.PrivateKey
	record    *sidecar.SidecarRecord
	client    *sidecar.DirectoryClient
	// a phone's
	surrogate *sidecartest.FakeDirectoryPhone
	phone     *sidecar.DirectoryPhoneNotices

	stateLock sync.Mutex
	events    []string
	alarms    []sidecar.SidecarRecordAlarm
	recorded  []*sidecar.DirectoryReceipt
}

func (self *wakeDevice) sign(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
	return &bridge.Signed{
		Body:      bytes.Clone(body),
		SignerId:  self.sidecarId.Bytes(),
		Signature: ed25519.Sign(self.key, bridge.SignedBytes(purpose, signedType, body)),
		Type:      uint32(signedType),
	}, nil
}

func (self *wakeDevice) RaiseAccessRequest(requestId sidecar.Id) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.events = append(self.events, "access_request/"+requestId.String())
	return nil
}

func (self *wakeDevice) RaiseAccessDecided(requestId sidecar.Id, outcome string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.events = append(self.events, "access_decided/"+outcome+"/"+requestId.String())
	return nil
}

// Every event raised, in order.
func (self *wakeDevice) raised() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.events)
}

// How many times event was raised.
func (self *wakeDevice) raisedCount(event string) int {
	count := 0
	for _, raised := range self.raised() {
		if raised == event {
			count += 1
		}
	}
	return count
}

// A requester's receipts: no repo approval is taken in these cases, and the vault records each outcome.
func (self *wakeDevice) StatementHeld(ctx context.Context, statementSha256 []byte, position uint64) (bool, error) {
	return false, errors.New("no approval is taken in the wake cases")
}

func (self *wakeDevice) ActivateReach(ctx context.Context, request *sidecar.StoredApprovalRequest, decisions [][]byte) error {
	return errors.New("no reach approval is spent in the wake cases")
}

func (self *wakeDevice) Record(ctx context.Context, receipt *sidecar.DirectoryReceipt) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.recorded = append(self.recorded, receipt)
	return nil
}

func (self *wakeDevice) recordedReceipts() []*sidecar.DirectoryReceipt {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.recorded)
}

// The wakes' world: a team's directory, a general repo P, R's phone, A's desktop and A's member's phone, both admins
// of P.
type wakeWorld struct {
	clock            *sidecartest.FakeClock
	streams          *sidecartest.FakeRecordStreams
	cards            *sidecartest.FakeDirectoryCards
	directoryAuth    *sidecartest.FakeDirectoryAuth
	directoryFixture *sidecartest.FakeDirectoryAuthFixture
	recordAuth       *sidecartest.FakeRecordAuth
	recordFixture    *sidecartest.FakeRecordAuthFixture
	directoryId      sidecar.Id
	repoId           sidecar.Id

	requester     *wakeDevice
	approver      *wakeDevice
	approverPhone *wakeDevice

	// R's request, once filed
	filed *sidecar.DirectoryRequestFiled
}

// The limits §20.4 gives a Team, as GET /sidecar/limits answers them.
func wakeLimits(ctx context.Context) (*sidecar.QuotaLimits, error) {
	return &sidecar.QuotaLimits{Tier: "team", Limits: map[string]int64{
		sidecar.DirectoryLimitRequestsPending: 20,
		sidecar.DirectoryLimitRequestsPerDay:  50,
		sidecar.DirectoryLimitRequestsPerRun:  5,
		sidecar.DirectoryLimitTargetPending:   100,
	}}, nil
}

// A device admitted in both states as a member device of memberId, writing its own stream of the directory.
func (self *wakeWorld) device(name string, memberId sidecar.Id) (*wakeDevice, error) {
	publicKey, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	device := &wakeDevice{name: name, sidecarId: sidecar.NewId(), memberId: memberId, key: key}
	if err := self.streams.Grant(self.directoryId, device.sidecarId, sidecartest.RecordStreamsScope{Read: true, Write: true}); err != nil {
		return nil, err
	}
	self.recordFixture.IdentityKeys[device.sidecarId] = publicKey
	self.recordFixture.Members[device.sidecarId] = memberId
	repo := self.recordFixture.Repos[self.directoryId]
	repo.Readers = append(repo.Readers, device.sidecarId)
	repo.Writers = append(repo.Writers, device.sidecarId)
	self.directoryFixture.Sidecars[device.sidecarId] = &sidecartest.FakeDirectorySidecar{MemberId: &memberId}
	return device, nil
}

// Opens device's record and directory client, its requests bound, and on a phone its phone part over the surrogate.
func (self *wakeWorld) open(device *wakeDevice, phone bool) error {
	recordStore, err := sidecartest.NewFakeStore().Root().Directory("record", "record")
	if err != nil {
		return err
	}
	record, err := sidecar.NewSidecarRecord(&sidecar.SidecarRecordArgs{
		SidecarId:         device.sidecarId,
		IdentityPublicKey: device.key.Public().(ed25519.PublicKey),
		Store:             recordStore,
		Sign:              device.sign,
		Streams:           self.streams.For(device.sidecarId),
		Auth:              func() sidecar.RecordAuthView { return self.recordAuth.Tip() },
		Clock:             self.clock,
		Settings:          sidecar.DefaultSidecarSettings().Record,
	})
	if err != nil {
		return err
	}
	clientStore, err := sidecartest.NewFakeStore().Root().Directory("directory", "search")
	if err != nil {
		return err
	}
	var cards sidecar.DirectoryCards = self.cards.For(device.sidecarId)
	if phone {
		device.surrogate = sidecartest.NewFakeDirectoryPhone(self.cards, device.sidecarId, nil)
		cards = device.surrogate
	}
	client, err := sidecar.NewDirectoryClient(&sidecar.DirectoryClientArgs{
		SidecarId:  device.sidecarId,
		Store:      clientStore,
		Cards:      cards,
		Streams:    func() sidecar.RecordStreams { return self.streams.For(device.sidecarId) },
		Auth:       func() sidecar.DirectoryAuthView { return self.directoryAuth.Tip() },
		RecordAuth: func() sidecar.RecordAuthView { return self.recordAuth.Tip() },
		Alarm: func(alarm *sidecar.RecordAlarm) {
			device.stateLock.Lock()
			defer device.stateLock.Unlock()
			device.alarms = append(device.alarms, alarm.Reason)
		},
		Clock:    self.clock,
		Settings: sidecar.DefaultSidecarSettings().Directory,
		Writer:   record.Writer(),
	})
	if err != nil {
		return err
	}
	ledger, err := sidecar.NewApprovalLedger(sidecartest.NewFakeStore().Root(), sidecar.DefaultSidecarSettings().Mcp, self.clock)
	if err != nil {
		return err
	}
	client.BindRequests(&sidecar.DirectoryRequestsBinding{
		Limits:   wakeLimits,
		Events:   device,
		Land:     func(ctx context.Context) error { return record.Flush(ctx) },
		Journal:  ledger,
		Receipts: device,
	})
	device.record, device.client = record, client
	if phone {
		if device.phone, err = client.BindPhoneNotices(nil); err != nil {
			return err
		}
	}
	return nil
}

func newWakeWorld(ctx context.Context) (*wakeWorld, error) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	streams := sidecartest.NewFakeRecordStreams(clock, nil, nil)
	directoryId, err := streams.NewRepo(ctx)
	if err != nil {
		return nil, err
	}
	world := &wakeWorld{
		clock:         clock,
		streams:       streams,
		cards:         sidecartest.NewFakeDirectoryCards(streams, nil),
		directoryAuth: sidecartest.NewFakeDirectoryAuth(),
		recordAuth:    sidecartest.NewFakeRecordAuth(),
		directoryId:   directoryId,
		repoId:        sidecar.NewId(),
		directoryFixture: &sidecartest.FakeDirectoryAuthFixture{
			Sidecars:    map[sidecar.Id]*sidecartest.FakeDirectorySidecar{},
			Repos:       map[sidecar.Id]*sidecartest.FakeDirectoryRepo{},
			DirectoryId: &directoryId,
		},
		recordFixture: &sidecartest.FakeRecordAuthFixture{
			IdentityKeys: map[sidecar.Id][]byte{},
			Members:      map[sidecar.Id]sidecar.Id{},
			Repos:        map[sidecar.Id]*sidecartest.FakeRecordRepoAuth{directoryId: {}},
			Logs:         &sidecar.RecordLogIds{Team: true, DirectoryId: &directoryId},
		},
	}
	requesterMember, approverMember := sidecar.NewId(), sidecar.NewId()
	if world.requester, err = world.device("requester R's phone", requesterMember); err != nil {
		return nil, err
	}
	if world.approver, err = world.device("approver A's desktop", approverMember); err != nil {
		return nil, err
	}
	if world.approverPhone, err = world.device("approver A's phone", approverMember); err != nil {
		return nil, err
	}
	world.directoryFixture.Repos[directoryId] = &sidecartest.FakeDirectoryRepo{
		Kind:   protocol.RepoKind_REPO_KIND_DIRECTORY,
		Admins: []sidecartest.FakeDirectoryRepoAdmin{{SidecarId: world.approver.sidecarId, At: 1}},
	}
	world.directoryFixture.Repos[world.repoId] = &sidecartest.FakeDirectoryRepo{
		Kind: protocol.RepoKind_REPO_KIND_GENERAL,
		Admins: []sidecartest.FakeDirectoryRepoAdmin{
			{SidecarId: world.approver.sidecarId, At: 1},
			{SidecarId: world.approverPhone.sidecarId, At: 1},
		},
	}
	world.recordFixture.TimeMillis = clock.Now().UnixMilli()
	world.directoryFixture.TimeMillis = world.recordFixture.TimeMillis
	world.recordAuth.Append(world.recordFixture)
	world.directoryAuth.Append(world.directoryFixture)
	if err := world.open(world.requester, true); err != nil {
		return nil, err
	}
	if err := world.open(world.approver, false); err != nil {
		return nil, err
	}
	if err := world.open(world.approverPhone, true); err != nil {
		return nil, err
	}
	return world, nil
}

// R files a person's request to read P.
func (self *wakeWorld) file(ctx context.Context) error {
	filed, err := self.requester.client.Request(ctx, &sidecar.DirectoryRequestAsk{
		Target:  &protocol.RequestTarget{RepoId: self.repoId.Bytes()},
		Role:    uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_READER),
		Reason:  "to read the build notes",
		FiledBy: sidecar.DirectoryFiledByPerson,
	})
	if err != nil {
		return err
	}
	if !filed.NoticeWritten || filed.EntrySeq == 0 {
		return fmt.Errorf("R's request filed as %+v", filed)
	}
	self.filed = filed
	return nil
}

// A's desktop denies R's request, carried to its notice's rewrite: the entry is read back from A's own stream first.
func (self *wakeWorld) deny(ctx context.Context) error {
	for attempt := 0; attempt < 2; attempt += 1 {
		if err := self.approver.client.Sync(ctx); err != nil {
			return err
		}
		decided, err := self.approver.client.Decide(ctx, &sidecar.DirectoryDecideArgs{RequestId: self.filed.RequestId, Note: "not this quarter"})
		if err != nil {
			return err
		}
		if decided.Finished() {
			return nil
		}
	}
	return errors.New("A's denial did not reach its notice's rewrite")
}

// The notice at R's request's path as the world's cards hold it, nil for none.
func (self *wakeWorld) notice(ctx context.Context) (*protocol.DirectoryNotice, *sidecar.DirectoryCardFile, error) {
	if self.filed == nil {
		return nil, nil, nil
	}
	phone := sidecartest.NewFakeDirectoryPhone(self.cards, self.approver.sidecarId, nil)
	file, err := phone.ReadCard(ctx, self.directoryId, self.filed.NoticePath)
	if err != nil || file == nil {
		return nil, nil, err
	}
	notice, err := sidecar.DirectoryDecodeNotice(file.Content)
	return notice, file, err
}

// No wake of either phone names an id: each is APNs' body of the evs class and a version alone.
func (self *wakeWorld) wakesNameNothing() error {
	ids := []sidecar.Id{self.directoryId, self.repoId, self.requester.sidecarId, self.approver.sidecarId, self.approverPhone.sidecarId}
	if self.filed != nil {
		ids = append(ids, self.filed.RequestId)
	}
	for _, device := range []*wakeDevice{self.requester, self.approverPhone} {
		for _, wake := range device.surrogate.Wakes() {
			if wake.Payload.TopicClass != "evs" || !bytes.Equal(wake.Body, []byte(fmt.Sprintf(`{"aps":{"content-available":1},"t":"evs","v":%d}`, wake.Payload.Version))) {
				return fmt.Errorf("%s's wake %q", device.name, wake.Body)
			}
			text := strings.ToLower(string(wake.Body))
			for _, id := range ids {
				if strings.Contains(text, hex.EncodeToString(id.Bytes())) || strings.Contains(text, id.String()) {
					return fmt.Errorf("%s's wake names %s", device.name, id)
				}
			}
		}
	}
	return nil
}

// FI-26 as the wake cases hold it, after every step: see the file header.
func (self *wakeWorld) check(ctx context.Context) error {
	for _, device := range []*wakeDevice{self.requester, self.approver, self.approverPhone} {
		for _, event := range device.raised() {
			if strings.HasPrefix(event, "access_decided/approved/") {
				return fmt.Errorf("%s raised %s, and nothing was approved", device.name, event)
			}
		}
	}
	notice, file, err := self.notice(ctx)
	if err != nil {
		return err
	}
	if notice != nil && sidecar.DirectoryNoticeState(notice.GetState()) == sidecar.DirectoryNoticeStateDecided {
		decisions := notice.GetDecisions()
		if sidecar.DirectoryOutcome(notice.GetOutcome()) != sidecar.DirectoryOutcomeDenied || len(decisions) != 1 ||
			sidecar.Id(decisions[0].GetDeciderSidecarId()) != self.approver.sidecarId || file.SignerSidecarId != self.approver.sidecarId {
			return fmt.Errorf("R's notice decided as %v by %s", notice, file.SignerSidecarId)
		}
	}
	if self.filed != nil && 0 < self.requester.raisedCount("access_decided/denied/"+self.filed.RequestId.String()) {
		if notice == nil || sidecar.DirectoryNoticeState(notice.GetState()) != sidecar.DirectoryNoticeStateDecided {
			return errors.New("R shows a denial no decided notice holds")
		}
	}
	return self.wakesNameNothing()
}

// The world a schedule's steps share, made by its first step.
type wakeState struct {
	world *wakeWorld
	// R's surrogate's counts when A decided
	beforeDecision sidecartest.FakeDirectoryPhoneCounts
}

func wakeSchedule(state *wakeState, steps []*Step) *Schedule {
	built := append([]*Step{{Actor: "authority", Action: func(ctx context.Context, net *Net) error {
		world, err := newWakeWorld(ctx)
		if err != nil {
			return err
		}
		state.world = world
		return nil
	}}}, steps...)
	return &Schedule{
		Steps: built,
		Check: []Invariant{NewInvariant("FI-26/wakes", func(ctx context.Context, oracle *Oracle) error {
			if state.world == nil {
				return nil
			}
			return state.world.check(ctx)
		})},
		Tiers: []Tier{TierT2},
	}
}

func wakeStep(state *wakeState, actor string, action func(ctx context.Context, world *wakeWorld) error) *Step {
	return &Step{Actor: actor, Action: func(ctx context.Context, net *Net) error {
		if state.world == nil {
			return errors.New("the wakes' world was not set up")
		}
		return action(ctx, state.world)
	}}
}

// The leases a phone holds at evs, each live with one holder, in prefix order.
func wakeLeases(device *wakeDevice) ([]string, error) {
	prefixes := []string{}
	for _, lease := range device.surrogate.Leases() {
		if !lease.Live || lease.Holders != 1 {
			return nil, fmt.Errorf("%s's lease %+v", device.name, lease)
		}
		prefixes = append(prefixes, lease.Prefix)
	}
	return prefixes, nil
}

// FS-100's wake case: see the file header.
func Fs100WakeOnDenial(net *Net) *Schedule {
	state := &wakeState{}
	return wakeSchedule(state, []*Step{
		wakeStep(state, "phoneR", func(ctx context.Context, world *wakeWorld) error {
			return world.file(ctx)
		}),
		wakeStep(state, "judge", func(ctx context.Context, world *wakeWorld) error {
			// R leases its notice's path alone, and its own write woke nothing
			leases, err := wakeLeases(world.requester)
			if err != nil {
				return err
			}
			if !slices.Equal(leases, []string{world.filed.NoticePath}) {
				return fmt.Errorf("R leases %v", leases)
			}
			if wakes := world.requester.surrogate.Wakes(); len(wakes) != 0 {
				return fmt.Errorf("R got %d wakes before any decision", len(wakes))
			}
			state.beforeDecision = world.requester.surrogate.Counts()
			return nil
		}),
		wakeStep(state, "daemonA", func(ctx context.Context, world *wakeWorld) error {
			return world.deny(ctx)
		}),
		wakeStep(state, "judge", func(ctx context.Context, world *wakeWorld) error {
			if wakes := world.requester.surrogate.Wakes(); len(wakes) != 1 {
				return fmt.Errorf("R got %d wakes for one denial", len(wakes))
			}
			return nil
		}),
		wakeStep(state, "phoneR", func(ctx context.Context, world *wakeWorld) error {
			resynced, err := world.requester.phone.Resync(ctx)
			if err != nil {
				return err
			}
			if resynced.Decided != 1 {
				return fmt.Errorf("R's resync %+v", resynced)
			}
			return nil
		}),
		wakeStep(state, "judge", func(ctx context.Context, world *wakeWorld) error {
			before, after := state.beforeDecision, world.requester.surrogate.Counts()
			if after.NoticeReads-before.NoticeReads != 1 || after.EntryReads-before.EntryReads != 1 {
				return fmt.Errorf("R read %d notices and %d entries at its wake", after.NoticeReads-before.NoticeReads, after.EntryReads-before.EntryReads)
			}
			if after.Listings != 0 || after.Refs != 0 || after.ReadStreams != 0 || after.ReadStreamLogs != 0 || after.ReadCards != 0 {
				return fmt.Errorf("R read beyond one notice and one entry: %+v", after)
			}
			event := "access_decided/denied/" + world.filed.RequestId.String()
			if count := world.requester.raisedCount(event); count != 1 {
				return fmt.Errorf("R raised %s %d times: %v", event, count, world.requester.raised())
			}
			recorded := world.requester.recordedReceipts()
			if len(recorded) != 1 || len(recorded[0].Decisions) != 1 || recorded[0].Decisions[0].Decision.GetNote() != "not this quarter" {
				return fmt.Errorf("R's vault recorded %+v", recorded)
			}
			return nil
		}),
	})
}

// FS-85's wake case: see the file header.
func Fs85WakeOnNewRequest(net *Net) *Schedule {
	state := &wakeState{}
	return wakeSchedule(state, []*Step{
		wakeStep(state, "phoneA", func(ctx context.Context, world *wakeWorld) error {
			_, err := world.approverPhone.phone.Resync(ctx)
			return err
		}),
		wakeStep(state, "judge", func(ctx context.Context, world *wakeWorld) error {
			prefix, err := sidecar.DirectoryNoticePrefix(&protocol.RequestTarget{RepoId: world.repoId.Bytes()})
			if err != nil {
				return err
			}
			leases, err := wakeLeases(world.approverPhone)
			if err != nil {
				return err
			}
			if !slices.Equal(leases, []string{prefix}) {
				return fmt.Errorf("A's phone leases %v, not P's prefix alone", leases)
			}
			return nil
		}),
		wakeStep(state, "phoneR", func(ctx context.Context, world *wakeWorld) error {
			return world.file(ctx)
		}),
		wakeStep(state, "judge", func(ctx context.Context, world *wakeWorld) error {
			if wakes := world.approverPhone.surrogate.Wakes(); len(wakes) != 1 {
				return fmt.Errorf("A's phone got %d wakes for one request", len(wakes))
			}
			return nil
		}),
		wakeStep(state, "phoneA", func(ctx context.Context, world *wakeWorld) error {
			resynced, err := world.approverPhone.phone.Resync(ctx)
			if err != nil {
				return err
			}
			if resynced.ListingReads != 1 || resynced.EntryReads != 1 || resynced.Requested != 1 {
				return fmt.Errorf("A's phone's resync %+v", resynced)
			}
			return nil
		}),
		wakeStep(state, "judge", func(ctx context.Context, world *wakeWorld) error {
			event := "access_request/" + world.filed.RequestId.String()
			if count := world.approverPhone.raisedCount(event); count != 1 {
				return fmt.Errorf("A's phone raised %s %d times", event, count)
			}
			incoming := world.approverPhone.phone.Incoming()
			if len(incoming) != 1 || incoming[0].RequestId != world.filed.RequestId || !incoming[0].Decidable {
				return fmt.Errorf("A's phone's incoming %+v", incoming)
			}
			return nil
		}),
	})
}

func TestFs100Wakes(t *testing.T) {
	RunRow(t, "FS-100", "wakes", nil)
}

func TestFs85Wakes(t *testing.T) {
	RunRow(t, "FS-85", "wakes", nil)
}
