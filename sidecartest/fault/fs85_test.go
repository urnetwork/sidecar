//go:build !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-85's M6 case on T2 (§22.8; §16.11's Requests block, D-MCP-30, FI-26; RECORD-M6-26), and the directory world the
// M6 cases of FS-85, FS-87, FS-88 and FS-100 share: a team's directory over sidecartest's fakes, every entry sealed and
// signed for real, and desktop devices that file, decide and receive through RECORD-M6-18's and -19's protocols, their
// statements filed into a world log and their receipts checked against it.
//
//	FS-85   a repo request any repo admin approves yields one RepoGrant with the asked subject and expiry and a decision
//	        entry naming its log position, after which the requester's receipt holds the statement at that position
//	        (KF3's seat, which this world stands in for by the log); a request to an owner-bound repo is decided only by
//	        a consented device of its owner, an admin's decision refused before anything is journaled; a denial and a
//	        cancel sign no statement, and expiry leaves a request expired, never denied; a notice whose DecisionRef
//	        names another request's entry activates nothing and alarms; the approver's lease on the target's prefix is
//	        hinted; a sidecar's 21st pending request is refused
//
// After every step, FI-26 as these cases hold it: every statement in the world log was signed by an approver eligible
// for its request's target, names exactly that target and the request's subject, and exists only for a request whose
// notice ends approved; no requester records an approval no decided notice holds.
//
// Not here: FS-85's worker reach case (CanonicalAction version 3's endorsement and its GrantActivate, which need the
// gate's access_request effect lookup and a spend binding), its T3 run (server's sidecar_directory_requests_t3_test.go
// is the review phase's), and its wakes (fs100_wake_test.go).

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

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs85M6 = Register("FS-85", "", []Tier{TierT2}, Fs85RequestLifecycle)

// The world's authorization log as directory statements enter it: each filed statement, by its bytes.
type dirStatementLog struct {
	stateLock sync.Mutex
	positions map[string]uint64
	accesses  map[string]*sidecar.DirectoryRepoAccess
	signers   map[string]sidecar.Id
	next      uint64
}

// One device of the directory world.
type dirDevice struct {
	name      string
	sidecarId sidecar.Id
	memberId  sidecar.Id
	key       ed25519.PrivateKey
	world     *dirWorld
	record    *sidecar.SidecarRecord
	client    *sidecar.DirectoryClient
	store     sidecar.SidecarStore

	// each run's taint as its run file says it; a run not here reads tainted
	runs map[sidecar.Id]bool

	stateLock sync.Mutex
	events    []string
	alarms    []*sidecar.RecordAlarm
	recorded  []*sidecar.DirectoryReceipt
	signed    int
}

// RecordRunView: a run this device knows by its taint, any other tainted (D-MCP-16).
func (self *dirDevice) RunTainted(runId sidecar.Id) bool {
	tainted, ok := self.runs[runId]
	return !ok || tainted
}

func (self *dirDevice) sign(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
	return &bridge.Signed{
		Body:      bytes.Clone(body),
		SignerId:  self.sidecarId.Bytes(),
		Signature: ed25519.Sign(self.key, bridge.SignedBytes(purpose, signedType, body)),
		Type:      uint32(signedType),
	}, nil
}

func (self *dirDevice) RaiseAccessRequest(requestId sidecar.Id) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.events = append(self.events, "access_request/"+requestId.String())
	return nil
}

func (self *dirDevice) RaiseAccessDecided(requestId sidecar.Id, outcome string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.events = append(self.events, "access_decided/"+outcome+"/"+requestId.String())
	return nil
}

func (self *dirDevice) raised() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.events)
}

func (self *dirDevice) raisedCount(event string) int {
	count := 0
	for _, raised := range self.raised() {
		if raised == event {
			count += 1
		}
	}
	return count
}

func (self *dirDevice) alarmCount(reason sidecar.SidecarRecordAlarm) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	count := 0
	for _, alarm := range self.alarms {
		if alarm.Reason == reason {
			count += 1
		}
	}
	return count
}

// DirectoryStatements: signs a statement naming its access, and files it into the world log.
func (self *dirDevice) SignRepoAccess(ctx context.Context, access *sidecar.DirectoryRepoAccess) ([]byte, error) {
	self.stateLock.Lock()
	self.signed += 1
	signed := []byte(fmt.Sprintf("%s/%s/%s/%d/%d/%v/%d", self.sidecarId, access.RepoId, access.Subject, access.Role, access.ExpiresMillis, access.OwnerBound, self.signed))
	self.stateLock.Unlock()
	log := self.world.log
	log.stateLock.Lock()
	defer log.stateLock.Unlock()
	copied := *access
	log.accesses[string(signed)] = &copied
	log.signers[string(signed)] = self.sidecarId
	return signed, nil
}

func (self *dirDevice) FileStatement(ctx context.Context, signed []byte) (uint64, error) {
	log := self.world.log
	log.stateLock.Lock()
	defer log.stateLock.Unlock()
	if position, ok := log.positions[string(signed)]; ok {
		return position, nil
	}
	log.next += 1
	log.positions[string(signed)] = log.next
	return log.next, nil
}

func (self *dirDevice) SignReachDecision(ctx context.Context, request *sidecar.StoredApprovalRequest, subject sidecar.Id, expiresMillis int64) ([]byte, error) {
	return nil, errors.New("no reach decision is signed in the directory world")
}

// DirectoryReceipts: the world log, and a vault that records.
func (self *dirDevice) StatementHeld(ctx context.Context, statementSha256 []byte, position uint64) (bool, error) {
	log := self.world.log
	log.stateLock.Lock()
	defer log.stateLock.Unlock()
	for signed, held := range log.positions {
		sum := sha256.Sum256([]byte(signed))
		if held == position && bytes.Equal(sum[:], statementSha256) {
			return true, nil
		}
	}
	return false, nil
}

func (self *dirDevice) ActivateReach(ctx context.Context, request *sidecar.StoredApprovalRequest, decisions [][]byte) error {
	return errors.New("no reach approval is spent in the directory world")
}

func (self *dirDevice) Record(ctx context.Context, receipt *sidecar.DirectoryReceipt) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.recorded = append(self.recorded, receipt)
	return nil
}

func (self *dirDevice) recordedReceipts() []*sidecar.DirectoryReceipt {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.recorded)
}

// The directory world: a team's directory, a general repo P whose admin is A, an owner-bound vault V of member O, and
// a requester R; each a desktop device.
type dirWorld struct {
	clock            *sidecartest.FakeClock
	streams          *sidecartest.FakeRecordStreams
	cards            *sidecartest.FakeDirectoryCards
	directoryAuth    *sidecartest.FakeDirectoryAuth
	directoryFixture *sidecartest.FakeDirectoryAuthFixture
	recordAuth       *sidecartest.FakeRecordAuth
	recordFixture    *sidecartest.FakeRecordAuthFixture
	log              *dirStatementLog
	directoryId      sidecar.Id
	networkId        sidecar.Id
	repoId           sidecar.Id
	vaultId          sidecar.Id

	requester *dirDevice
	approver  *dirDevice
	owner     *dirDevice
	admin     *dirDevice
	devices   []*dirDevice

	// the hints an approver's lease took
	hintLock sync.Mutex
	hints    int

	// the requests filed, by name, and each one's target repo
	filed   map[string]*sidecar.DirectoryRequestFiled
	targets map[string]sidecar.Id
}

// The limits §20.4 gives a Team.
func dirLimits(ctx context.Context) (*sidecar.QuotaLimits, error) {
	return wakeLimits(ctx)
}

// Appends the fixtures as the next position of each state, timed now.
func (self *dirWorld) publish() {
	self.recordFixture.TimeMillis = self.clock.Now().UnixMilli()
	self.directoryFixture.TimeMillis = self.recordFixture.TimeMillis
	self.recordAuth.Append(self.recordFixture)
	self.directoryAuth.Append(self.directoryFixture)
}

// A device admitted in both states as a member device of memberId, writing and reading the directory; admin also
// gives it admin scope at evs and makes it a directory admin.
func (self *dirWorld) device(name string, memberId sidecar.Id, admin bool) (*dirDevice, error) {
	publicKey, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	device := &dirDevice{name: name, sidecarId: sidecar.NewId(), memberId: memberId, key: key, world: self}
	if err := self.streams.Grant(self.directoryId, device.sidecarId, sidecartest.RecordStreamsScope{Read: true, Write: true, Admin: admin}); err != nil {
		return nil, err
	}
	self.recordFixture.IdentityKeys[device.sidecarId] = publicKey
	self.recordFixture.Members[device.sidecarId] = memberId
	repo := self.recordFixture.Repos[self.directoryId]
	repo.Readers = append(repo.Readers, device.sidecarId)
	repo.Writers = append(repo.Writers, device.sidecarId)
	if admin {
		repo.Admins = append(repo.Admins, device.sidecarId)
		directory := self.directoryFixture.Repos[self.directoryId]
		directory.Admins = append(directory.Admins, sidecartest.FakeDirectoryRepoAdmin{SidecarId: device.sidecarId, At: 1})
	}
	self.directoryFixture.Sidecars[device.sidecarId] = &sidecartest.FakeDirectorySidecar{MemberId: &memberId}
	self.devices = append(self.devices, device)
	return device, nil
}

// Opens device's record and directory client, its requests and decisions bound.
func (self *dirWorld) open(device *dirDevice) error {
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
		Runs:              device,
	})
	if err != nil {
		return err
	}
	if device.store == nil {
		if device.store, err = sidecartest.NewFakeStore().Root().Directory("directory", "search"); err != nil {
			return err
		}
	}
	client, err := sidecar.NewDirectoryClient(&sidecar.DirectoryClientArgs{
		SidecarId:  device.sidecarId,
		Store:      device.store,
		Cards:      self.cards.For(device.sidecarId),
		Streams:    func() sidecar.RecordStreams { return self.streams.For(device.sidecarId) },
		Auth:       func() sidecar.DirectoryAuthView { return self.directoryAuth.Tip() },
		RecordAuth: func() sidecar.RecordAuthView { return self.recordAuth.Tip() },
		Alarm: func(alarm *sidecar.RecordAlarm) {
			device.stateLock.Lock()
			defer device.stateLock.Unlock()
			device.alarms = append(device.alarms, alarm)
		},
		Clock:     self.clock,
		Settings:  sidecar.DefaultSidecarSettings().Directory,
		Writer:    record.Writer(),
		NetworkId: self.networkId,
		Sign:      device.sign,
		Runs:      device,
	})
	if err != nil {
		return err
	}
	ledger, err := sidecar.NewApprovalLedger(sidecartest.NewFakeStore().Root(), sidecar.DefaultSidecarSettings().Mcp, self.clock)
	if err != nil {
		return err
	}
	client.BindRequests(&sidecar.DirectoryRequestsBinding{
		Limits:     dirLimits,
		Events:     device,
		Land:       func(ctx context.Context) error { return record.Flush(ctx) },
		Journal:    ledger,
		Statements: device,
		Receipts:   device,
	})
	device.record, device.client = record, client
	return nil
}

func newDirWorld(ctx context.Context) (*dirWorld, error) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	streams := sidecartest.NewFakeRecordStreams(clock, nil, nil)
	directoryId, err := streams.NewRepo(ctx)
	if err != nil {
		return nil, err
	}
	world := &dirWorld{
		clock:         clock,
		streams:       streams,
		cards:         sidecartest.NewFakeDirectoryCards(streams, nil),
		directoryAuth: sidecartest.NewFakeDirectoryAuth(),
		recordAuth:    sidecartest.NewFakeRecordAuth(),
		log:           &dirStatementLog{positions: map[string]uint64{}, accesses: map[string]*sidecar.DirectoryRepoAccess{}, signers: map[string]sidecar.Id{}},
		directoryId:   directoryId,
		networkId:     sidecar.NewId(),
		repoId:        sidecar.NewId(),
		vaultId:       sidecar.NewId(),
		directoryFixture: &sidecartest.FakeDirectoryAuthFixture{
			Sidecars:    map[sidecar.Id]*sidecartest.FakeDirectorySidecar{},
			Repos:       map[sidecar.Id]*sidecartest.FakeDirectoryRepo{directoryId: {Kind: protocol.RepoKind_REPO_KIND_DIRECTORY}},
			DirectoryId: &directoryId,
		},
		recordFixture: &sidecartest.FakeRecordAuthFixture{
			IdentityKeys: map[sidecar.Id][]byte{},
			Members:      map[sidecar.Id]sidecar.Id{},
			Repos:        map[sidecar.Id]*sidecartest.FakeRecordRepoAuth{directoryId: {}},
			Logs:         &sidecar.RecordLogIds{Team: true, DirectoryId: &directoryId},
		},
		filed:   map[string]*sidecar.DirectoryRequestFiled{},
		targets: map[string]sidecar.Id{},
	}
	ownerMember := sidecar.NewId()
	if world.requester, err = world.device("requester R", sidecar.NewId(), false); err != nil {
		return nil, err
	}
	if world.approver, err = world.device("repo admin A", sidecar.NewId(), false); err != nil {
		return nil, err
	}
	if world.owner, err = world.device("vault owner O", ownerMember, false); err != nil {
		return nil, err
	}
	if world.admin, err = world.device("directory admin D", sidecar.NewId(), true); err != nil {
		return nil, err
	}
	world.directoryFixture.Repos[world.repoId] = &sidecartest.FakeDirectoryRepo{
		Kind: protocol.RepoKind_REPO_KIND_GENERAL, Admins: []sidecartest.FakeDirectoryRepoAdmin{{SidecarId: world.approver.sidecarId, At: 1}},
	}
	world.directoryFixture.Repos[world.vaultId] = &sidecartest.FakeDirectoryRepo{
		Kind: protocol.RepoKind_REPO_KIND_VAULT, OwnerMemberId: &ownerMember,
		// a directory admin is the vault's repo admin too, and still decides nothing for it (owner decision 126)
		Admins: []sidecartest.FakeDirectoryRepoAdmin{{SidecarId: world.admin.sidecarId, At: 1}},
	}
	world.publish()
	for _, device := range world.devices {
		if err := world.open(device); err != nil {
			return nil, err
		}
	}
	return world, nil
}

// device files a person's request for role on target, kept under name.
func (self *dirWorld) file(ctx context.Context, name string, device *dirDevice, target *protocol.RequestTarget, role protocol.RepoGrantRole, grantExpiresMillis int64) error {
	filed, err := device.client.Request(ctx, &sidecar.DirectoryRequestAsk{
		Target: target, Role: uint32(role), GrantExpiresMillis: grantExpiresMillis, Reason: "to read the build notes", FiledBy: sidecar.DirectoryFiledByPerson,
	})
	if err != nil {
		return err
	}
	if !filed.NoticeWritten || filed.EntrySeq == 0 {
		return fmt.Errorf("%s filed as %+v", name, filed)
	}
	self.filed[name] = filed
	self.targets[name] = sidecar.Id(target.GetRepoId())
	return nil
}

// device decides request name, carried to its notice's rewrite.
func (self *dirWorld) decide(ctx context.Context, device *dirDevice, name string, approve bool, note string) (*sidecar.DirectoryDecided, error) {
	filed := self.filed[name]
	for attempt := 0; attempt < 2; attempt += 1 {
		if err := device.client.Sync(ctx); err != nil {
			return nil, err
		}
		decided, err := device.client.Decide(ctx, &sidecar.DirectoryDecideArgs{RequestId: filed.RequestId, Approve: approve, Note: note})
		if err != nil {
			return nil, err
		}
		if decided.Finished() {
			return decided, nil
		}
	}
	return nil, fmt.Errorf("%s's decision on %s did not reach its notice's rewrite", device.name, name)
}

// A sync and the requests' upkeep on device.
func (self *dirWorld) upkeep(ctx context.Context, device *dirDevice) error {
	if err := device.client.Sync(ctx); err != nil {
		return err
	}
	return device.client.Requests().Maintain(ctx)
}

// The one request of name device shows.
func (self *dirWorld) request(ctx context.Context, device *dirDevice, name string) (*sidecar.DirectoryRequestView, error) {
	if err := device.client.Sync(ctx); err != nil {
		return nil, err
	}
	requestId := self.filed[name].RequestId
	views, err := device.client.GetRequests(ctx, &sidecar.DirectoryRequestFilter{RequestId: &requestId})
	if err != nil {
		return nil, err
	}
	if len(views) != 1 {
		return nil, fmt.Errorf("%s shows %d requests of %s", device.name, len(views), name)
	}
	return views[0], nil
}

// The notice at a request's path as the world's cards hold it, nil for none.
func (self *dirWorld) notice(ctx context.Context, name string) (*protocol.DirectoryNotice, *sidecar.DirectoryCardFile, error) {
	filed := self.filed[name]
	if filed == nil {
		return nil, nil, nil
	}
	phone := sidecartest.NewFakeDirectoryPhone(self.cards, self.admin.sidecarId, nil)
	file, err := phone.ReadCard(ctx, self.directoryId, filed.NoticePath)
	if err != nil || file == nil {
		return nil, nil, err
	}
	notice, err := sidecar.DirectoryDecodeNotice(file.Content)
	return notice, file, err
}

// FI-26 as the directory world holds it, after every step: see the file header.
func (self *dirWorld) check(ctx context.Context) error {
	self.log.stateLock.Lock()
	statements := map[string]*sidecar.DirectoryRepoAccess{}
	signers := map[string]sidecar.Id{}
	for signed, position := range self.log.positions {
		if 0 < position {
			statements[signed] = self.log.accesses[signed]
			signers[signed] = self.log.signers[signed]
		}
	}
	self.log.stateLock.Unlock()
	auth := self.directoryAuth.Tip()
	for signed, access := range statements {
		// the statement's request: one filed for its repo and subject whose notice does not end other than approved
		matched := false
		for name, filed := range self.filed {
			if filed.Subject != access.Subject || self.targets[name] != access.RepoId {
				continue
			}
			notice, _, err := self.notice(ctx, name)
			if err != nil {
				return err
			}
			if notice == nil || sidecar.DirectoryNoticeState(notice.GetState()) != sidecar.DirectoryNoticeStateDecided ||
				sidecar.DirectoryOutcome(notice.GetOutcome()) == sidecar.DirectoryOutcomeApproved {
				matched = true
			}
		}
		if !matched {
			return fmt.Errorf("a statement %q for no request that may hold it", signed)
		}
		repo, ok := auth.Repo(access.RepoId)
		if !ok {
			return fmt.Errorf("a statement for repo %s no state holds", access.RepoId)
		}
		signer := signers[signed]
		if repo.Kind == protocol.RepoKind_REPO_KIND_VAULT {
			if memberId, ok := auth.MemberOf(signer); !ok || memberId != repo.OwnerMemberId || !access.OwnerBound {
				return fmt.Errorf("an owner-bound repo's statement signed by %s, no consented device of its owner", signer)
			}
		} else if right, err := auth.RepoAdminRight(access.RepoId, signer, auth.Pin().GetVersion()); err != nil || !right {
			return fmt.Errorf("a repo's statement signed by %s, no admin of it: %v", signer, err)
		}
	}
	for _, device := range self.devices {
		for _, receipt := range device.recordedReceipts() {
			if receipt.Outcome != sidecar.SidecarAccessDecidedApproved {
				continue
			}
			for name, filed := range self.filed {
				if filed.RequestId != receipt.RequestId {
					continue
				}
				notice, _, err := self.notice(ctx, name)
				if err != nil {
					return err
				}
				// an approved notice is removed once recorded; until then it must read approved
				if notice != nil && sidecar.DirectoryOutcome(notice.GetOutcome()) != sidecar.DirectoryOutcomeApproved {
					return fmt.Errorf("%s recorded an approval of %s its notice does not hold", device.name, name)
				}
			}
		}
	}
	return nil
}

// The world a schedule's steps share, made by its first step.
type dirState struct {
	world *dirWorld
	// what a step leaves for a later one
	counts map[string]int
}

func dirSchedule(state *dirState, check string, steps []*Step) *Schedule {
	built := append([]*Step{{Actor: "authority", Action: func(ctx context.Context, net *Net) error {
		world, err := newDirWorld(ctx)
		if err != nil {
			return err
		}
		state.world = world
		state.counts = map[string]int{}
		return nil
	}}}, steps...)
	return &Schedule{
		Steps: built,
		Check: []Invariant{NewInvariant(check, func(ctx context.Context, oracle *Oracle) error {
			if state.world == nil {
				return nil
			}
			return state.world.check(ctx)
		})},
		Tiers: []Tier{TierT2},
	}
}

func dirStep(state *dirState, actor string, action func(ctx context.Context, world *dirWorld) error) *Step {
	return &Step{Actor: actor, Action: func(ctx context.Context, net *Net) error {
		if state.world == nil {
			return errors.New("the directory world was not set up")
		}
		return action(ctx, state.world)
	}}
}

// FS-85's M6 case: see the file header.
func Fs85RequestLifecycle(net *Net) *Schedule {
	state := &dirState{}
	expiresMillis := sidecartest.DefaultClockStart().Add(30 * 24 * time.Hour).UnixMilli()
	return dirSchedule(state, "FI-26/requests", []*Step{
		dirStep(state, "daemonA", func(ctx context.Context, world *dirWorld) error {
			// A leases P's notice prefix as an approver
			prefix, err := sidecar.DirectoryNoticePrefix(&protocol.RequestTarget{RepoId: world.repoId.Bytes()})
			if err != nil {
				return err
			}
			// as A's client leases it (DirectoryClient.Lease), its hints counted here
			if _, err := world.cards.For(world.approver.sidecarId).Lease(world.directoryId, prefix, func(repoId sidecar.Id) {
				world.hintLock.Lock()
				defer world.hintLock.Unlock()
				world.hints += 1
			}); err != nil {
				return err
			}
			return nil
		}),
		dirStep(state, "daemonR", func(ctx context.Context, world *dirWorld) error {
			return world.file(ctx, "read", world.requester, &protocol.RequestTarget{RepoId: world.repoId.Bytes()}, protocol.RepoGrantRole_REPO_GRANT_ROLE_READER, expiresMillis)
		}),
		dirStep(state, "daemonA", func(ctx context.Context, world *dirWorld) error {
			view, err := world.request(ctx, world.approver, "read")
			if err != nil {
				return err
			}
			if view.State != sidecar.DirectoryRequestPending || !view.Decidable {
				return fmt.Errorf("A's view of R's request: %+v", view)
			}
			decided, err := world.decide(ctx, world.approver, "read", true, "welcome")
			if err != nil {
				return err
			}
			if decided.Outcome != sidecar.DirectoryOutcomeApproved || decided.StatementPosition == 0 {
				return fmt.Errorf("A's approval: %+v", decided)
			}
			state.counts["position"] = int(decided.StatementPosition)
			return nil
		}),
		dirStep(state, "judge", func(ctx context.Context, world *dirWorld) error {
			// one RepoGrant, with the asked subject, role and expiry
			world.log.stateLock.Lock()
			defer world.log.stateLock.Unlock()
			if len(world.log.positions) != 1 {
				return fmt.Errorf("%d statements for one approval", len(world.log.positions))
			}
			for _, access := range world.log.accesses {
				if access.RepoId != world.repoId || access.Subject != world.requester.memberId || access.OwnerBound ||
					access.Role != uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_READER) || access.ExpiresMillis != expiresMillis {
					return fmt.Errorf("the grant: %+v", access)
				}
			}
			return nil
		}),
		dirStep(state, "daemonR", func(ctx context.Context, world *dirWorld) error {
			if err := world.upkeep(ctx, world.requester); err != nil {
				return err
			}
			event := "access_decided/approved/" + world.filed["read"].RequestId.String()
			if count := world.requester.raisedCount(event); count != 1 {
				return fmt.Errorf("R raised %s %d times: %v", event, count, world.requester.raised())
			}
			recorded := world.requester.recordedReceipts()
			if len(recorded) != 1 || len(recorded[0].Decisions) != 1 ||
				recorded[0].Decisions[0].Decision.GetStatementPosition() != uint64(state.counts["position"]) {
				return fmt.Errorf("R's receipt: %+v", recorded)
			}
			return nil
		}),
		dirStep(state, "daemonR", func(ctx context.Context, world *dirWorld) error {
			// an owner-bound request: the directory admin, the vault's repo admin, decides nothing
			return world.file(ctx, "vault", world.requester, &protocol.RequestTarget{RepoId: world.vaultId.Bytes()}, protocol.RepoGrantRole_REPO_GRANT_ROLE_READER, 0)
		}),
		dirStep(state, "daemonD", func(ctx context.Context, world *dirWorld) error {
			_, err := world.decide(ctx, world.admin, "vault", true, "")
			if !errors.Is(err, sidecar.ErrDirectoryDecideNotEligible) {
				return fmt.Errorf("an admin's decision on an owner-bound request: %v", err)
			}
			return nil
		}),
		dirStep(state, "daemonO", func(ctx context.Context, world *dirWorld) error {
			decided, err := world.decide(ctx, world.owner, "vault", false, "not my vault's")
			if err != nil {
				return err
			}
			if decided.Outcome != sidecar.DirectoryOutcomeDenied {
				return fmt.Errorf("O's denial: %+v", decided)
			}
			return nil
		}),
		dirStep(state, "daemonR", func(ctx context.Context, world *dirWorld) error {
			// a cancel signs nothing either
			if err := world.file(ctx, "cancelled", world.requester, &protocol.RequestTarget{RepoId: world.repoId.Bytes()}, protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER, 0); err != nil {
				return err
			}
			if err := world.requester.client.Sync(ctx); err != nil {
				return err
			}
			return world.requester.client.Cancel(ctx, world.filed["cancelled"].RequestId)
		}),
		dirStep(state, "judge", func(ctx context.Context, world *dirWorld) error {
			world.log.stateLock.Lock()
			count := len(world.log.positions)
			world.log.stateLock.Unlock()
			if count != 1 || world.admin.signed != 0 || world.owner.signed != 0 {
				return fmt.Errorf("%d statements after a denial and a cancel; D signed %d, O %d", count, world.admin.signed, world.owner.signed)
			}
			view, err := world.request(ctx, world.requester, "vault")
			if err != nil {
				return err
			}
			if view.State != sidecar.DirectoryRequestDenied {
				return fmt.Errorf("R's owner-bound request reads %s", view.State)
			}
			return nil
		}),
		dirStep(state, "daemonR", func(ctx context.Context, world *dirWorld) error {
			// expiry: a request past not_after reads expired, never denied, with no entry written
			if err := world.file(ctx, "expired", world.requester, &protocol.RequestTarget{RepoId: world.repoId.Bytes()}, protocol.RepoGrantRole_REPO_GRANT_ROLE_DEPOSIT, 0); err != nil {
				return err
			}
			world.clock.Advance(8 * 24 * time.Hour)
			world.publish()
			view, err := world.request(ctx, world.requester, "expired")
			if err != nil {
				return err
			}
			if view.State != sidecar.DirectoryRequestExpired || len(view.Decisions) != 0 {
				return fmt.Errorf("an expired request reads %s with %d decisions", view.State, len(view.Decisions))
			}
			return nil
		}),
		dirStep(state, "evs", func(ctx context.Context, world *dirWorld) error {
			// a notice whose DecisionRef names the approved request's entry, copied onto a new request, activates nothing
			if err := world.file(ctx, "copied", world.requester, &protocol.RequestTarget{RepoId: world.repoId.Bytes()}, protocol.RepoGrantRole_REPO_GRANT_ROLE_READER, 0); err != nil {
				return err
			}
			approved, _, err := world.notice(ctx, "read")
			if err != nil {
				return err
			}
			if approved == nil {
				// the approved notice is closed once R recorded it: its decision entry is named again from R's view
				view, err := world.request(ctx, world.requester, "read")
				if err != nil {
					return err
				}
				approved = &protocol.DirectoryNotice{Decisions: []*protocol.DecisionRef{{
					DeciderSidecarId: view.Decisions[0].DeciderSidecarId.Bytes(), Seq: view.Decisions[0].Seq, HeaderSha256: view.Decisions[0].HeaderSha256[:],
				}}}
			}
			copied := world.filed["copied"]
			forged := &protocol.DirectoryNotice{
				RequestId: copied.RequestId.Bytes(), RequesterSidecarId: world.requester.sidecarId.Bytes(), EntrySeq: copied.EntrySeq,
				NotAfterMillis: copied.NotAfterMillis, State: uint32(sidecar.DirectoryNoticeStateDecided),
				Outcome: uint32(sidecar.DirectoryOutcomeApproved), Decisions: approved.GetDecisions(),
			}
			content, err := proto.MarshalOptions{Deterministic: true}.Marshal(forged)
			if err != nil {
				return err
			}
			holder := world.cards.For(world.approver.sidecarId)
			_, file, err := world.notice(ctx, "copied")
			if err != nil || file == nil {
				return fmt.Errorf("the copied request's notice: %v", err)
			}
			_, err = holder.PutCard(ctx, world.directoryId, &sidecar.DirectoryCardWrite{
				PushId: sidecar.NewId(), Path: copied.NoticePath, IfVersion: file.Version, Content: content, AuthPin: world.directoryAuth.Tip().Pin(),
			})
			return err
		}),
		dirStep(state, "daemonR", func(ctx context.Context, world *dirWorld) error {
			// the receipt refuses the copied decision, ignoring it with an alarm, and the upkeep says so
			if err := world.upkeep(ctx, world.requester); err != nil && !errors.Is(err, sidecar.ErrDirectoryReceiptRefused) {
				return err
			}
			view, err := world.request(ctx, world.requester, "copied")
			if err != nil {
				return err
			}
			// activates nothing: no decision entry binds the request, nothing is recorded or raised approved (the view
			// still reads the notice's outcome, which the review phase is to hold to its decisions)
			copiedId := world.filed["copied"].RequestId
			event := "access_decided/approved/" + copiedId.String()
			recordedApproval := slices.ContainsFunc(world.requester.recordedReceipts(), func(receipt *sidecar.DirectoryReceipt) bool {
				return receipt.RequestId == copiedId && receipt.Outcome == sidecar.SidecarAccessDecidedApproved
			})
			if len(view.Decisions) != 0 || recordedApproval || world.requester.raisedCount(event) != 0 {
				return fmt.Errorf("a copied decision activated: %d decisions, recorded %v, events %v", len(view.Decisions), recordedApproval, world.requester.raised())
			}
			if world.requester.alarmCount(sidecar.SidecarRecordAlarmPathRule)+world.requester.alarmCount(sidecar.SidecarRecordAlarmBadDecision) == 0 {
				return errors.New("a copied decision raised no alarm")
			}
			return nil
		}),
		dirStep(state, "judge", func(ctx context.Context, world *dirWorld) error {
			// the approver's lease on P's prefix was hinted at each notice written under it
			world.hintLock.Lock()
			defer world.hintLock.Unlock()
			if world.hints == 0 {
				return errors.New("A's lease on P's prefix was never hinted")
			}
			return nil
		}),
		dirStep(state, "daemonR", func(ctx context.Context, world *dirWorld) error {
			// past 20 pending requests the 21st is refused, nothing filed
			if err := world.requester.client.Sync(ctx); err != nil {
				return err
			}
			mine, err := world.requester.client.GetRequests(ctx, &sidecar.DirectoryRequestFilter{Mine: true, States: []sidecar.DirectoryRequestState{sidecar.DirectoryRequestPending}})
			if err != nil {
				return err
			}
			ask := &sidecar.DirectoryRequestAsk{
				Target: &protocol.RequestTarget{RepoId: world.repoId.Bytes()}, Role: uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_READER),
				Reason: "one of many", FiledBy: sidecar.DirectoryFiledByPerson,
			}
			for index := len(mine); index < 20; index += 1 {
				if _, err := world.requester.client.Request(ctx, ask); err != nil {
					return fmt.Errorf("pending request %d: %w", index+1, err)
				}
			}
			if _, err := world.requester.client.Request(ctx, ask); !errors.Is(err, sidecar.ErrDirectoryRequestLimit) {
				return fmt.Errorf("the 21st pending request: %v", err)
			}
			return nil
		}),
	})
}

func TestFs85M6(t *testing.T) {
	RunRow(t, "FS-85", "", nil)
}
