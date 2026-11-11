// The evs rows' world (EVS1-M2-40, EVS1-M2-41; §22.8's evs schedules): one repo of one network on a Net's evs,
// served by several evs instances behind a model of the lb, written and read by devices that are sidecar.EvsClients
// as built, so a schedule drives the real client and the real engine end to end and an oracle reads what they leave.
//
//	instances  each evs instance is a process of its own name (evs1, evs2, ...) on the Net: an engine hosted on the
//	           Net's host, which Kill drops with no drain and Restart builds again from the stores alone. Every
//	           request an instance serves runs as an Action of that instance's actor, so a barrier the engine reaches
//	           holds the instance, and killing it drops the request where it stands, its client seeing the connection
//	           close. On T2 the world builds evsservice's engine with the deps server/cli/evs gives it (the storage
//	           gate, usage producer, HDD share and cohort limit); on T3 server's test names evshost's block through
//	           SetEvsTier, so a row runs through the handler server runs
//	lb         a device's requests go to the first live instance it names, and, as warp's proxy_next_upstream error
//	           timeout http_503 non_idempotent with proxy_next_upstream_tries 2 has it, a connection error, a 503 or
//	           proxy_read_timeout (30 s of the Net's clock) sends the same request once to the next live one. A device
//	           sees the last answer, or a transport error when none came; what each instance answered is kept by push
//	           id, so a schedule checks an attempt whose answer the lb dropped
//	devices    each a sidecar of the network with its own identity key, client and store: every device reads the repo,
//	           and writers write it. A device's waits answer at once, so a retry the client makes runs on at once and
//	           never parks a schedule on the clock. A device's evs alarms are kept, and EvsWorldNoAlarms fails on one
//	ledger     every write a device starts is pending until its answer: committed at a version, refused, or unknown.
//	           Verify reads a path through a device and takes only the newest committed content or a pending or
//	           unknown write's, so readers verify at every barrier a schedule puts a Verify beside
//	setup      Setup, a schedule's first step, places the repo, starts the instances and devices and makes the
//	           repo's group as its first writer, whose actor so holds RK_g, as FI-1's decrypt clause needs. Its own
//	           store writes go under an inspecting context: they take no fault and count toward no Nth, so §22.8's
//	           unknown rule loses the row's writes, never the fixture's, and a plan's Nth names the same write on
//	           every run
//
// Barrier sites a schedule names here carry no key: one world holds one repo, and the instance a step names is the
// arm's actor, so a hold is the instance's request and no other. Safe for concurrent use.

package fault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
	"weak"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// What a T3 test gives a Net's evs worlds in place of T2's own: the block a world's instances run and the tokens
// its devices present. server's T3 names server/cli/evs's block (evshost.NewHost) over the Net's real stores and
// service tokens server's oauth mints, which that host's Authenticator verifies.
type EvsTier struct {
	// Builds one instance's block on host with the world's settings and seams.
	NewHost func(ctx context.Context, host *sidecar.ServiceHost, settings *evsservice.EvsSettings, deps *EvsTierDeps) (EvsTierHost, error)
	// A token for principal that host's Authenticator verifies.
	IssueToken func(principal *sidecar.Principal) (string, error)
}

// The seams a world gives an instance's block.
type EvsTierDeps struct {
	AuthState   evsservice.EvsAuthState
	GateViews   evsservice.EvsGateViews
	ReceiptKeys *evsservice.ReceiptKeys
	// The segment cluster's HDD share's settings (EvsWorldSettings.HddInterval).
	Hdd *evsservice.HddAdmissionSettings
	// The engine's log, nil for none: the Net's capture when the settings ask (T2's block only).
	Log sidecar.Logger
}

// One instance's block: an engine server hosts, with what it owns.
type EvsTierHost interface {
	sidecar.Engine
	Handler() http.Handler
	Engine() *evsservice.EvsEngine
}

var evsTiers sync.Map

var evsWorlds sync.Map

// The world NewEvsWorld made last on net, or nil: what a history check reads once a row's run has ended.
func EvsWorldOf(net *Net) *EvsWorld {
	if world, ok := evsWorlds.Load(weak.Make(net)); ok {
		return world.(*EvsWorld)
	}
	return nil
}

// Names the tier net's evs worlds build on. server's T3 test calls this from its NetSettings.Engines, as each Net
// is made, so every Net of a row's rules gets it; with none named, a world builds on T2's terms.
func SetEvsTier(net *Net, tier *EvsTier) {
	key := weak.Make(net)
	if _, loaded := evsTiers.LoadOrStore(key, tier); !loaded {
		runtime.AddCleanup(net, func(key weak.Pointer[Net]) { evsTiers.Delete(key) }, key)
		return
	}
	evsTiers.Store(key, tier)
}

// The tier named for net, or nil for T2's.
func evsTierOf(net *Net) *EvsTier {
	if tier, ok := evsTiers.Load(weak.Make(net)); ok {
		return tier.(*EvsTier)
	}
	return nil
}

type EvsWorldSettings struct {
	// The repo's kind.
	Kind protocol.RepoKind
	// Setup places nothing and makes no group: a schedule places the repo through the route (PlaceRepo), as a create
	// resuming the RepoCreate the world's projection holds does, and then makes its group (FinishCreate).
	Unplaced bool
	// The instances Setup starts, each a process of its name.
	Instances []string
	// The devices Setup starts, the first writer making the repo's group.
	Devices []*EvsWorldDeviceSettings
	// warp's proxy_next_upstream_tries: how many instances one request reaches at most.
	LbTries int
	// warp's proxy_read_timeout, on the Net's clock: an instance that has not answered by then loses the request to
	// the next. Non-positive never times out.
	LbReadTimeout time.Duration
	// Real time a request's step 8s may take before the request fails: a guard, never a wait a schedule orders.
	StepEightTimeout time.Duration
	// The HDD share's loop interval on each instance: past any schedule's span, 10,000 h, so a schedule's Advance
	// ticks no loop. A loop ticking on the Net's clock writes Redis as often as its goroutine wins the race with the
	// Advance, so the count of a run's Redis writes, which §22.8's unknown rule loses one at a time, would differ from
	// run to run. Non-positive takes the share's own 5 s.
	HddInterval time.Duration
	// The engine settings of an instance past the world's own, nil for none.
	AdjustEngine func(instance string, settings *evsservice.EvsSettings)
	// A device's client settings past the defaults, nil for none.
	AdjustClient func(device string, settings *sidecar.EvsSettings)
	// Every instance's handler serves through the Net's privacy capture (CC1) and logs to it (§22.7), for a
	// scenario that scans what servers held.
	Capture bool
}

// One device of a world.
type EvsWorldDeviceSettings struct {
	Name string
	// The instances its requests go to, in the lb's order.
	Instances []string
	// Whether it writes the repo. Every device reads it.
	Writer bool
}

// Two writers, each with an instance of its own and a second the lb re-sends to, and a reader on an instance no
// schedule holds: writerA reaches evs1 then evs2, writerB evs3 then evs2, reader evsr.
func DefaultEvsWorldSettings() *EvsWorldSettings {
	return &EvsWorldSettings{
		Kind:      protocol.RepoKind_REPO_KIND_GENERAL,
		Instances: []string{"evs1", "evs2", "evs3", "evsr"},
		Devices: []*EvsWorldDeviceSettings{
			{Name: "writerA", Instances: []string{"evs1", "evs2"}, Writer: true},
			{Name: "writerB", Instances: []string{"evs3", "evs2"}, Writer: true},
			{Name: "reader", Instances: []string{"evsr"}},
		},
		LbTries:          2,
		LbReadTimeout:    30 * time.Second,
		StepEightTimeout: 10 * time.Second,
		HddInterval:      10000 * time.Hour,
	}
}

// One device: a sidecar of the world's network with its own identity key, gkm client, store and evs client.
type EvsWorldDevice struct {
	Name      string
	Signer    *sidecartest.FakeGkmSigner
	ClientId  sidecar.Id
	Gkm       sidecar.GkmClient
	Client    *sidecar.EvsClient
	Repo      *sidecar.EvsRepo
	settings  *EvsWorldDeviceSettings
	transport *evsWorldTransport
}

// What one instance answered one attempt of a push, or what the lb gave a device.
type EvsWorldAnswer struct {
	// The instance, or "lb" for what the device saw.
	Instance string
	Status   int
	// A 200's version.
	Version uint64
	// A refusal's.
	Code     protocol.EvsRefusalCode
	Recorded bool
	Unknown  bool
}

// Whether the answer refuses the push: a 4xx past the 400 and 429 that refuse nothing, an unknown outcome aside.
func (self *EvsWorldAnswer) Refuses() bool {
	switch {
	case self.Unknown:
		return false
	case self.Status == http.StatusBadRequest || self.Status == http.StatusTooManyRequests || self.Status == http.StatusUnauthorized:
		return false
	}
	return 400 <= self.Status && self.Status < 500
}

func (self *EvsWorldAnswer) String() string {
	if self.Status == http.StatusOK {
		return fmt.Sprintf("%s 200 v%d", self.Instance, self.Version)
	}
	text := fmt.Sprintf("%s %d %s", self.Instance, self.Status, self.Code)
	if self.Recorded {
		text += " recorded"
	}
	if self.Unknown {
		text += " unknown"
	}
	return text
}

// One push id's attempts as the world saw them.
type EvsWorldPush struct {
	PushId sidecar.Id
	Device string
	// In arrival order.
	Answers []*EvsWorldAnswer
}

// One write a device started, in the ledger.
type evsWorldWrite struct {
	device string
	// nil for a removal
	content []byte
	state   evsWorldWriteState
	version uint64
	pushId  sidecar.Id
	err     error
}

type evsWorldWriteState int

const (
	evsWorldWritePending evsWorldWriteState = iota + 1
	evsWorldWriteCommitted
	evsWorldWriteRefused
	evsWorldWriteUnknown
)

// See the file header.
type EvsWorld struct {
	net         *Net
	settings    *EvsWorldSettings
	NetworkId   sidecar.Id
	RepoId      sidecar.Id
	MemberId    sidecar.Id
	receiptKeys *evsservice.ReceiptKeys
	log         *sidecartest.FakeGkmAuthLog
	deviceNames []string
	devices     map[string]*EvsWorldDevice

	stateLock sync.Mutex
	gkm       *sidecartest.FakeGkm
	view      *sidecartest.FakeGkmAuthView
	refId     sidecar.Id
	setUp     bool
	// each instance's gate view while a schedule holds it stale, by instance
	staleViews map[string]*sidecartest.FakeGkmAuthView
	// the devices that no longer read the repo, the position the repo's holders last shrank at, and how many
	// positions the log holds
	droppedReaders map[string]bool
	shrunkAt       uint64
	viewCount      uint64
	// the sidecars an instance's auth state takes no scope of, by instance
	scopeDenials map[string]map[sidecar.Id]bool
	// by path, every write started, in order
	pathWrites map[string][]*evsWorldWrite
	// by push id
	pushes     map[sidecar.Id]*EvsWorldPush
	pushIdList []sidecar.Id
	// each device's next push posts to every instance named, at once
	duplicates map[string][]string
	// each device's evs alarms
	deviceAlarms map[string][]string
	// what each device's placement of the repo answered
	placeStatuses map[string]int
	// what the outcome check has seen: each committed version's push id, and each push id's version
	versionPushIds map[uint64]sidecar.Id
	pushIdVersions map[sidecar.Id]uint64
	// every attempt an instance took, in the order each began, and the logical clock their times are read from
	attempts     []*EvsWorldAttempt
	attemptClock int64
}

// One attempt of a push as an instance took it, for a history check of §11.8's commit rule (Porcupine, EVS1-M2-42):
// Call when the instance began it and Return when it answered, both on the world's logical clock, which moves at
// every event under the world's lock and so orders them as they happened. An attempt its instance never answered,
// killed or still held, has Return 0 and no Answer: its outcome is unknown and its end open.
type EvsWorldAttempt struct {
	PushId   sidecar.Id
	Instance string
	Call     int64
	Return   int64
	Answer   *EvsWorldAnswer
}

// A world on net, drawing its ids and keys; it writes nothing until Setup runs as a schedule's first step. settings
// nil takes the defaults.
func NewEvsWorld(net *Net, settings *EvsWorldSettings) *EvsWorld {
	if settings == nil {
		settings = DefaultEvsWorldSettings()
	}
	self := &EvsWorld{
		net:            net,
		settings:       settings,
		NetworkId:      sidecar.NewId(),
		RepoId:         sidecar.NewId(),
		MemberId:       sidecar.NewId(),
		log:            sidecartest.NewFakeGkmAuthLog(),
		devices:        map[string]*EvsWorldDevice{},
		staleViews:     map[string]*sidecartest.FakeGkmAuthView{},
		droppedReaders: map[string]bool{},
		scopeDenials:   map[string]map[sidecar.Id]bool{},
		pathWrites:     map[string][]*evsWorldWrite{},
		pushes:         map[sidecar.Id]*EvsWorldPush{},
		duplicates:     map[string][]string{},
		deviceAlarms:   map[string][]string{},
		placeStatuses:  map[string]int{},
		versionPushIds: map[uint64]sidecar.Id{},
		pushIdVersions: map[sidecar.Id]uint64{},
	}
	for _, deviceSettings := range settings.Devices {
		device := &EvsWorldDevice{
			Name:     deviceSettings.Name,
			Signer:   sidecartest.NewFakeGkmSigner(),
			ClientId: sidecar.NewId(),
			settings: deviceSettings,
		}
		device.transport = &evsWorldTransport{world: self, device: device}
		self.devices[device.Name] = device
		self.deviceNames = append(self.deviceNames, device.Name)
	}
	key := weak.Make(net)
	if _, loaded := evsWorlds.LoadOrStore(key, self); loaded {
		evsWorlds.Store(key, self)
	} else {
		runtime.AddCleanup(net, func(key weak.Pointer[Net]) { evsWorlds.Delete(key) }, key)
	}
	return self
}

// An attempt beginning now, its call time taken from the logical clock.
func (self *EvsWorld) beginAttempt(pushId sidecar.Id, instance string) *EvsWorldAttempt {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.attemptClock += 1
	attempt := &EvsWorldAttempt{PushId: pushId, Instance: instance, Call: self.attemptClock}
	self.attempts = append(self.attempts, attempt)
	return attempt
}

// The attempt answered now.
func (self *EvsWorld) endAttempt(attempt *EvsWorldAttempt, answer *EvsWorldAnswer) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.attemptClock += 1
	attempt.Return = self.attemptClock
	attempt.Answer = answer
}

// Every attempt so far, in the order they began, each a copy.
func (self *EvsWorld) Attempts() []*EvsWorldAttempt {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	attempts := []*EvsWorldAttempt{}
	for _, attempt := range self.attempts {
		copied := *attempt
		attempts = append(attempts, &copied)
	}
	return attempts
}

// The logical clock's reading now: a time after every attempt's call and return so far.
func (self *EvsWorld) AttemptClock() int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.attemptClock += 1
	return self.attemptClock
}

// The device of name. Panics on a name the settings do not hold: a schedule naming one is wrong where it was
// written.
func (self *EvsWorld) Device(name string) *EvsWorldDevice {
	device, ok := self.devices[name]
	if !ok {
		panic(fmt.Sprintf("the evs world has no device %q", name))
	}
	return device
}

// main's ref id, known once Setup has made the group.
func (self *EvsWorld) RefId() sidecar.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.refId
}

// The first writer, which makes the repo's group.
func (self *EvsWorld) creator() *EvsWorldDevice {
	for _, name := range self.deviceNames {
		if device := self.devices[name]; device.settings.Writer {
			return device
		}
	}
	panic("the evs world has no writer")
}

// The schedule's first step: see the file header. Run it as the creator's actor, which is the first writer's name.
func (self *EvsWorld) Setup(ctx context.Context, net *Net) error {
	inspect := sidecartest.InspectContext(ctx)
	fakes := net.Fakes()
	network := connect.Id(self.NetworkId).String()
	if err := fakes.Gates.Set(fmt.Sprintf("sidecar:\n  evs: {enabled: true, networks: [%q]}\n", network)); err != nil {
		return err
	}
	fakes.Quota.SetBalance(connect.Id(self.NetworkId), 1024*1024*1024*1024)
	sidecartest.RegisterEvsTwins(fakes.Redis)
	view := self.appendView()
	SetAuthorizationView(net, self.NetworkId, view)

	receiptKey := sha256.Sum256([]byte("evs world receipt key " + sidecar.EvsKeyId(self.RepoId)))
	receiptKeys, err := evsservice.NewReceiptKeys([]*evsservice.ReceiptKey{
		{KeyId: 1, Key: receiptKey[:], IssueFrom: net.Clock().Now().Add(-48 * time.Hour)},
	}, nil)
	if err != nil {
		return err
	}
	self.receiptKeys = receiptKeys

	gkm := sidecartest.NewFakeGkm(net.Clock(), &evsWorldGkmBlobs{BlobStore: net.Host().Blobs}, nil)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.gkm = gkm
	}()
	if self.settings.Unplaced {
		for _, instance := range self.settings.Instances {
			if err := self.StartInstance(instance); err != nil {
				return err
			}
		}
		for _, name := range self.deviceNames {
			if err := self.startDevice(self.devices[name], view); err != nil {
				return err
			}
		}
		return nil
	}

	first, err := net.Host().Blobs.FirstCluster()
	if err != nil {
		return err
	}
	creator := self.creator()
	placeBytes, err := (&sidecar.EvsRepoPlace{ClusterId: first.ClusterId(), CreatorSidecarId: creator.Signer.SidecarId}).Marshal()
	if err != nil {
		return err
	}
	if _, err := sidecar.PutImmutable(inspect, first, sidecar.EvsPlaceKey(self.RepoId), placeBytes, nil); err != nil {
		return fmt.Errorf("place/: %w", err)
	}
	repoBytes, err := proto.Marshal(&protocol.EvsRepoObject{
		RepoId: self.RepoId.Bytes(), Kind: self.settings.Kind, State: protocol.EvsRepoState_EVS_REPO_ACTIVE,
		Format: sidecar.EvsRepoFormat1, NetworkId: self.NetworkId.Bytes(),
	})
	if err != nil {
		return err
	}
	if _, err := sidecar.PutImmutable(inspect, first, sidecar.EvsRepoObjectKey(self.RepoId), repoBytes, nil); err != nil {
		return fmt.Errorf("repo/: %w", err)
	}

	for _, instance := range self.settings.Instances {
		if err := self.StartInstance(instance); err != nil {
			return err
		}
	}
	for _, name := range self.deviceNames {
		if err := self.startDevice(self.devices[name], view); err != nil {
			return err
		}
	}
	repoKey, err := creator.Gkm.CreateGroup(inspect, &sidecar.GkmCreateGroupArgs{RepoId: self.RepoId, Kind: self.settings.Kind})
	if err != nil {
		return fmt.Errorf("the repo's group: %w", err)
	}
	refKey, err := sidecar.NewEvsRefKey(repoKey)
	if err != nil {
		return err
	}
	refId, err := sidecar.EvsRefId(refKey, sidecar.EvsMainRefName)
	if err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refId = refId
	self.setUp = true
	return nil
}

// Appends a position at which every device but a dropped one reads the repo and writers write it, with the holders
// shrunk where the newest drop was, and gives it to evs and every device.
func (self *EvsWorld) appendView() *sidecartest.FakeGkmAuthView {
	self.stateLock.Lock()
	droppedReaders := map[string]bool{}
	for name, dropped := range self.droppedReaders {
		droppedReaders[name] = dropped
	}
	shrunkAt := self.shrunkAt
	self.stateLock.Unlock()
	fixture := &sidecartest.FakeGkmAuthFixture{
		Rows: sidecartest.FakeGkmAuthRows(&protocol.AclRepo{
			RepoId: self.RepoId.Bytes(), Kind: self.settings.Kind, HoldersShrunkAt: shrunkAt,
		}),
		IdentityKeys: map[sidecar.Id][]byte{},
		RepoReaders:  map[sidecar.Id][]sidecar.Id{},
		RepoWriters:  map[sidecar.Id][]sidecar.Id{},
	}
	sidecarIds := []sidecar.Id{}
	for _, name := range self.deviceNames {
		device := self.devices[name]
		fixture.IdentityKeys[device.Signer.SidecarId] = device.Signer.PublicKey()
		sidecarIds = append(sidecarIds, device.Signer.SidecarId)
		if droppedReaders[name] {
			continue
		}
		fixture.RepoReaders[self.RepoId] = append(fixture.RepoReaders[self.RepoId], device.Signer.SidecarId)
		if device.settings.Writer {
			fixture.RepoWriters[self.RepoId] = append(fixture.RepoWriters[self.RepoId], device.Signer.SidecarId)
		}
	}
	sidecarRows, memberRow := sidecartest.FakeGkmAuthMemberDevices(self.MemberId, sidecarIds...)
	fixture.Rows.Sidecars = sidecarRows
	fixture.Rows.Members = []*bridge.MemberRow{memberRow}
	view := self.log.Append(fixture)
	self.stateLock.Lock()
	self.view = view
	self.viewCount += 1
	self.stateLock.Unlock()
	for _, name := range self.deviceNames {
		if gkm := self.devices[name].Gkm; gkm != nil {
			gkm.AuthAdvanced(view)
		}
	}
	return view
}

// The store as the world's fake gkm writes its generations to it: every request under an inspecting context, so an evs
// row's plans never land on gkm's own writes and §22.8's unknown rule loses evs's writes, not a fake of another
// service's. Its writes stay in the blob history, so FI-1 reads every generation it makes.
type evsWorldGkmBlobs struct {
	sidecar.BlobStore
}

func (self *evsWorldGkmBlobs) Cluster(clusterId string) (sidecar.BlobCluster, error) {
	cluster, err := self.BlobStore.Cluster(clusterId)
	if err != nil {
		return nil, err
	}
	return &evsWorldGkmCluster{BlobCluster: cluster}, nil
}

func (self *evsWorldGkmBlobs) FirstCluster() (sidecar.BlobCluster, error) {
	cluster, err := self.BlobStore.FirstCluster()
	if err != nil {
		return nil, err
	}
	return &evsWorldGkmCluster{BlobCluster: cluster}, nil
}

func (self *evsWorldGkmBlobs) SegmentCluster() (sidecar.BlobCluster, error) {
	cluster, err := self.BlobStore.SegmentCluster()
	if err != nil {
		return nil, err
	}
	return &evsWorldGkmCluster{BlobCluster: cluster}, nil
}

// One cluster of evsWorldGkmBlobs.
type evsWorldGkmCluster struct {
	sidecar.BlobCluster
}

func (self *evsWorldGkmCluster) PutIfNoneMatch(ctx context.Context, key string, body []byte, options *sidecar.BlobPutOptions) (string, error) {
	return self.BlobCluster.PutIfNoneMatch(sidecartest.InspectContext(ctx), key, body, options)
}

func (self *evsWorldGkmCluster) PutIfMatch(ctx context.Context, key string, etag string, body []byte, options *sidecar.BlobPutOptions) (string, error) {
	return self.BlobCluster.PutIfMatch(sidecartest.InspectContext(ctx), key, etag, body, options)
}

func (self *evsWorldGkmCluster) PutStream(ctx context.Context, key string, body io.Reader, byteCount int64, checksumSha256 []byte) (string, error) {
	return self.BlobCluster.PutStream(sidecartest.InspectContext(ctx), key, body, byteCount, checksumSha256)
}

func (self *evsWorldGkmCluster) Get(ctx context.Context, key string) (*sidecar.BlobObject, error) {
	return self.BlobCluster.Get(sidecartest.InspectContext(ctx), key)
}

func (self *evsWorldGkmCluster) GetRange(ctx context.Context, key string, offset int64, byteCount int64) (*sidecar.BlobObject, error) {
	return self.BlobCluster.GetRange(sidecartest.InspectContext(ctx), key, offset, byteCount)
}

func (self *evsWorldGkmCluster) Head(ctx context.Context, key string) (*sidecar.BlobInfo, error) {
	return self.BlobCluster.Head(sidecartest.InspectContext(ctx), key)
}

func (self *evsWorldGkmCluster) List(ctx context.Context, keyPrefix string, startAfter string, limit int) ([]*sidecar.BlobInfo, bool, error) {
	return self.BlobCluster.List(sidecartest.InspectContext(ctx), keyPrefix, startAfter, limit)
}

func (self *evsWorldGkmCluster) Delete(ctx context.Context, key string) error {
	return self.BlobCluster.Delete(sidecartest.InspectContext(ctx), key)
}

// The newest position.
func (self *EvsWorld) currentView() *sidecartest.FakeGkmAuthView {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.view
}

// Starts an instance's process, or starts it again after a Kill: an engine built from the stores alone.
func (self *EvsWorld) StartInstance(instance string) error {
	_, err := self.net.AddEngine(instance, func(ctx context.Context, host *sidecar.ServiceHost) (sidecar.Engine, error) {
		return self.buildInstance(ctx, host, instance)
	})
	return err
}

// One instance's block: see the file header.
func (self *EvsWorld) buildInstance(ctx context.Context, host *sidecar.ServiceHost, instance string) (sidecar.Engine, error) {
	settings := evsservice.DefaultEvsSettings()
	settings.InstanceFormat = sidecar.EvsRepoFormat1
	settings.BatchFlushDelay = 0
	settings.PushUnknownRereadInterval = 0
	// the clock stands still between steps, so a cached repo/ would never lapse
	settings.RepoCacheTtl = 0
	// no fold off the reply path, so a check meets a store at rest: a schedule folds explicitly, and a page-out folds
	// as it pages
	settings.FoldUnfoldedTriggerCount = 0
	settings.FoldIdleDelay = 0
	if self.settings.AdjustEngine != nil {
		self.settings.AdjustEngine(instance, settings)
	}
	deps := &EvsTierDeps{
		AuthState:   &evsWorldAuthState{world: self, instance: instance},
		GateViews:   &evsWorldGateViews{world: self, instance: instance},
		ReceiptKeys: self.receiptKeys,
		Hdd:         evsservice.DefaultHddAdmissionSettings(),
	}
	if 0 < self.settings.HddInterval {
		deps.Hdd.Interval = self.settings.HddInterval
		deps.Hdd.RetryAfter = self.settings.HddInterval
		deps.Hdd.PutReportTtl = 3 * self.settings.HddInterval
	}
	var built EvsTierHost
	if tier := evsTierOf(self.net); tier != nil && tier.NewHost != nil {
		tierHost, err := tier.NewHost(ctx, host, settings, deps)
		if err != nil {
			return nil, err
		}
		built = tierHost
	} else {
		if self.settings.Capture {
			deps.Log = self.net.Capture().Logger("evs " + instance)
		}
		worldHost, err := newEvsWorldHost(ctx, host, settings, deps)
		if err != nil {
			return nil, err
		}
		built = worldHost
	}
	// serving before the step that starts it ends: its readiness probe runs on a goroutine of its own, and a request
	// it took first would answer 503 however long the schedule waited
	if err := self.awaitReady(built); err != nil {
		built.Close()
		return nil, fmt.Errorf("evs instance %s: %w", instance, err)
	}
	return built, nil
}

// The engine's first probe answered and it is ready. Real time bounds the wait only to fail it.
func (self *EvsWorld) awaitReady(host EvsTierHost) error {
	guard := time.After(self.settings.StepEightTimeout)
	for {
		count, changed := host.Engine().Probes()
		if 0 < count && host.Ready() {
			return nil
		}
		select {
		case <-changed:
		case <-guard:
			return errors.New("never ready")
		}
	}
}

// T2's block: evsservice's engine with the segment route's parts as server/cli/evs builds them (evshost.NewHost).
type evsWorldHost struct {
	engine  *evsservice.EvsEngine
	closers []func()
}

func newEvsWorldHost(ctx context.Context, host *sidecar.ServiceHost, settings *evsservice.EvsSettings, deps *EvsTierDeps) (*evsWorldHost, error) {
	self := &evsWorldHost{}
	fail := func(err error) (*evsWorldHost, error) {
		self.Close()
		return nil, err
	}
	clusterLimit, err := evsservice.NewClusterLimitOfHost(host, nil)
	if err != nil {
		return fail(err)
	}
	uploads := &evsservice.EvsUploadDeps{Keys: deps.ReceiptKeys, ClusterLimit: clusterLimit}
	quotaGate, err := evsservice.NewQuotaGate(ctx, host, nil)
	if err != nil {
		return fail(err)
	}
	self.closers = append(self.closers, quotaGate.Close)
	uploads.Quota = quotaGate
	usage, err := evsservice.NewUsageBatcher(ctx, host, nil)
	if err != nil {
		return fail(err)
	}
	self.closers = append(self.closers, usage.Close)
	uploads.Usage = usage
	segmentCluster, err := host.Blobs.SegmentCluster()
	if err != nil {
		return fail(err)
	}
	hdd, err := evsservice.NewHddAdmission(ctx, host, segmentCluster.ClusterId(), deps.Hdd)
	if err != nil {
		return fail(err)
	}
	self.closers = append(self.closers, hdd.Close)
	uploads.Hdd = hdd
	engine, err := evsservice.NewEvsEngine(ctx, host, settings, &evsservice.EvsEngineDeps{
		AuthState: deps.AuthState,
		Log:       deps.Log,
		Uploads:   uploads,
		GateViews: deps.GateViews,
	})
	if err != nil {
		return fail(err)
	}
	self.engine = engine
	return self, nil
}

func (self *evsWorldHost) Engine() *evsservice.EvsEngine {
	return self.engine
}

func (self *evsWorldHost) Handler() http.Handler {
	return self.engine.Handler()
}

func (self *evsWorldHost) Ready() bool {
	return self.engine != nil && self.engine.Ready()
}

func (self *evsWorldHost) Drain() {
	if self.engine != nil {
		self.engine.Drain()
	}
}

func (self *evsWorldHost) Close() {
	if self.engine != nil {
		self.engine.Close()
	}
	for _, close := range self.closers {
		close()
	}
	self.closers = nil
}

// The running block of an instance, or nil while it is killed or never started.
func (self *EvsWorld) instanceHost(instance string) EvsTierHost {
	host, _ := self.net.Process(instance).(EvsTierHost)
	return host
}

// What an instance's requests are served by: its block's handler, through the Net's capture when the settings ask.
func (self *EvsWorld) handlerOf(instance string, host EvsTierHost) http.Handler {
	if self.settings.Capture {
		return self.net.Capture().WrapHandler("evs "+instance, host.Handler())
	}
	return host.Handler()
}

// The engine of a running instance, for a step that drives its parts.
func (self *EvsWorld) Engine(instance string) (*evsservice.EvsEngine, error) {
	host := self.instanceHost(instance)
	if host == nil {
		return nil, fmt.Errorf("evs instance %s is not running", instance)
	}
	return host.Engine(), nil
}

// A device's client over the lb, its waits answered at once.
func (self *EvsWorld) startDevice(device *EvsWorldDevice, view *sidecartest.FakeGkmAuthView) error {
	self.stateLock.Lock()
	gkm := self.gkm
	self.stateLock.Unlock()
	device.Gkm = gkm.Client(device.Signer.SidecarId, device.Signer.Sign)
	device.Gkm.AuthAdvanced(view)
	identity := &sidecar.SidecarIdentity{
		NetworkId: self.NetworkId, SidecarId: device.Signer.SidecarId, ClientId: device.ClientId, Generation: 1,
		IdentityPublicKey: device.Signer.PublicKey(),
	}
	settings := sidecar.DefaultEvsSettings()
	// one helper goroutine at a time, served on itself (serveHelper), so a schedule repeats
	settings.UploadConcurrency = 1
	settings.PartConcurrency = 1
	if self.settings.AdjustClient != nil {
		self.settings.AdjustClient(device.Name, settings)
	}
	client, err := sidecar.NewEvsClient(&sidecar.EvsClientArgs{
		NetworkId: self.NetworkId,
		EvsUrl:    "https://evs.example",
		Transport: device.transport,
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			return self.issueToken(device, scopes)
		},
		Sign:     sidecar.EvsSignFunction(device.Signer.Sign),
		Identity: func() *sidecar.SidecarIdentity { return identity },
		Gkm:      device.Gkm,
		Store:    sidecartest.NewFakeStore().Root(),
		Config:   func() sidecar.GkmAuthView { return self.currentView() },
		// the world's projection already holds the repo's RepoCreate, which a create resumes (CreateRepo); a device
		// files nothing else
		FileStatement: func(ctx context.Context, signedType bridge.SignedType, statement proto.Message) error {
			return fmt.Errorf("the evs world files no %s", signedType)
		},
		Emit: func(event sidecar.SidecarEvent) {
			if event.Kind != sidecar.SidecarEventEvsAlarm {
				return
			}
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.deviceAlarms[device.Name] = append(self.deviceAlarms[device.Name], fmt.Sprintf("%s at %q", event.EvsAlarm, event.Path))
		},
		Clock:    &evsWorldDeviceClock{clock: self.net.Clock()},
		Log:      sidecar.NewNoopLogger(),
		Settings: settings,
	})
	if err != nil {
		return err
	}
	device.Client = client
	device.Repo = client.Repo(self.RepoId)
	return nil
}

// A device's token for scopes, as the tier's Authenticator verifies it.
func (self *EvsWorld) issueToken(device *EvsWorldDevice, scopes []string) (string, error) {
	now := self.net.Clock().Now()
	sidecarId := connect.Id(device.Signer.SidecarId)
	principal := &sidecar.Principal{
		NetworkId: connect.Id(self.NetworkId),
		ClientId:  connect.Id(device.ClientId),
		SidecarId: &sidecarId,
		Audience:  evsservice.EvsAudience,
		Scopes:    scopes,
		IssuedAt:  now,
		ExpiresAt: now.Add(15 * time.Minute),
	}
	if tier := evsTierOf(self.net); tier != nil && tier.IssueToken != nil {
		return tier.IssueToken(principal)
	}
	return self.net.Fakes().Authenticator.Issue(principal), nil
}

// A device's clock: the Net's time, every wait answered at once, AfterFunc on the Net's clock.
type evsWorldDeviceClock struct {
	clock *sidecartest.FakeClock
}

func (self *evsWorldDeviceClock) Now() time.Time {
	return self.clock.Now()
}

func (self *evsWorldDeviceClock) After(timeout time.Duration) <-chan time.Time {
	fired := make(chan time.Time, 1)
	fired <- self.clock.Now()
	return fired
}

func (self *evsWorldDeviceClock) AfterFunc(timeout time.Duration, function func()) func() bool {
	return self.clock.AfterFunc(timeout, function)
}

// evs's view of the authorization state on one instance: every binding and scope, unless a schedule took the scope
// of a sidecar away on this instance (DenyScope), as a projection newer on one instance than another does.
type evsWorldAuthState struct {
	world    *EvsWorld
	instance string
}

func (self *evsWorldAuthState) CheckRevocation(ctx context.Context, principal *sidecar.Principal) error {
	return nil
}

func (self *evsWorldAuthState) MatchBinding(principal *sidecar.Principal) evsservice.EvsAuthAnswer {
	return evsservice.EvsAuthAllowed
}

func (self *evsWorldAuthState) HonorScope(principal *sidecar.Principal, repoId sidecar.Id, rights sidecar.AclEvsRights, now time.Time) evsservice.EvsAuthAnswer {
	if principal.SidecarId == nil {
		return evsservice.EvsAuthDenied
	}
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	if self.world.scopeDenials[self.instance][sidecar.Id(*principal.SidecarId)] {
		return evsservice.EvsAuthDenied
	}
	return evsservice.EvsAuthAllowed
}

func (self *evsWorldAuthState) Repo(principal *sidecar.Principal, repoId sidecar.Id) (*evsservice.EvsRepoFacts, evsservice.EvsAuthAnswer) {
	if repoId != self.world.RepoId {
		return nil, evsservice.EvsAuthDenied
	}
	return &evsservice.EvsRepoFacts{Kind: self.world.settings.Kind, NetworkId: self.world.NetworkId}, evsservice.EvsAuthAllowed
}

// The gate views of one instance: the world's newest position, or the one a schedule holds it at (HoldView).
type evsWorldGateViews struct {
	world    *EvsWorld
	instance string
}

func (self *evsWorldGateViews) View(networkId sidecar.Id) (sidecar.GkmAuthView, evsservice.EvsAuthAnswer) {
	if networkId != self.world.NetworkId {
		return nil, evsservice.EvsAuthUnknown
	}
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	if view := self.world.staleViews[self.instance]; view != nil {
		return view, evsservice.EvsAuthAllowed
	}
	if self.world.view == nil {
		return nil, evsservice.EvsAuthUnknown
	}
	return self.world.view, evsservice.EvsAuthAllowed
}

// A step action: the instance's projection stops taking the scope of device's sidecar, as a projection that has
// read a scope's drop does while another instance's has not.
func (self *EvsWorld) DenyScope(instance string, device string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		sidecarId := self.Device(device).Signer.SidecarId
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.scopeDenials[instance] == nil {
			self.scopeDenials[instance] = map[sidecar.Id]bool{}
		}
		self.scopeDenials[instance][sidecarId] = true
		return nil
	}
}

// A device's transport: the lb.
type evsWorldTransport struct {
	world  *EvsWorld
	device *EvsWorldDevice
}

func (self *evsWorldTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return self.world.roundTrip(self.device, request)
}

// What the lb did with one request: see the file header.
func (self *EvsWorld) roundTrip(device *EvsWorldDevice, request *http.Request) (*http.Response, error) {
	body := []byte{}
	if request.Body != nil {
		var err error
		body, err = io.ReadAll(request.Body)
		request.Body.Close()
		if err != nil {
			return nil, err
		}
	}
	pushId, isPush := evsWorldPushIdOf(request, body)
	if isPush {
		self.notePush(pushId, device.Name)
		self.stateLock.Lock()
		duplicates := self.duplicates[device.Name]
		delete(self.duplicates, device.Name)
		self.stateLock.Unlock()
		if 0 < len(duplicates) {
			return self.serveDuplicates(device, request, body, pushId, duplicates)
		}
	}
	if self.net.Barriers().CurrentActor() == "" {
		// a helper goroutine of the device's: its own goroutine waits for it holding the baton, so it is served here
		return self.serveHelper(device, request, body)
	}
	tried := []string{}
	var last *httptest.ResponseRecorder
	for try := 0; try < max(1, self.settings.LbTries); try += 1 {
		instance := ""
		for _, candidate := range device.settings.Instances {
			if !slices.Contains(tried, candidate) && self.instanceHost(candidate) != nil {
				instance = candidate
				break
			}
		}
		if instance == "" {
			break
		}
		tried = append(tried, instance)
		var notePushId *sidecar.Id
		if isPush {
			notePushId = &pushId
		}
		recorder, answered := self.serve(request.Context(), instance, request, body, notePushId)
		if !answered {
			// a connection error or the read timeout: the lb sends it on
			last = nil
			continue
		}
		last = recorder
		if recorder.Code == http.StatusServiceUnavailable {
			continue
		}
		break
	}
	if last == nil {
		if isPush {
			self.noteAnswer(pushId, &EvsWorldAnswer{Instance: "lb", Status: http.StatusBadGateway})
		}
		return nil, fmt.Errorf("evs world lb: no instance answered (tried %v)", tried)
	}
	if isPush {
		answer := evsWorldAnswerOf("lb", last)
		self.noteAnswer(pushId, answer)
	}
	return last.Result(), nil
}

// A request from a goroutine of the device's own, a segment upload or a part, while the device's actor holds the
// baton and waits for it where the driver cannot see: served on that goroutine by the first live instance, under the
// device's context, so no other actor runs meanwhile. A schedule holds no instance and kills none inside one; the
// lb's re-send and read timeout apply as to any request.
func (self *EvsWorld) serveHelper(device *EvsWorldDevice, request *http.Request, body []byte) (*http.Response, error) {
	tried := []string{}
	for try := 0; try < max(1, self.settings.LbTries); try += 1 {
		var host EvsTierHost
		for _, candidate := range device.settings.Instances {
			if !slices.Contains(tried, candidate) {
				if host = self.instanceHost(candidate); host != nil {
					tried = append(tried, candidate)
					break
				}
			}
		}
		if host == nil {
			break
		}
		recorder := httptest.NewRecorder()
		served := request.Clone(request.Context())
		served.Body = io.NopCloser(bytes.NewReader(body))
		self.handlerOf(tried[len(tried)-1], host).ServeHTTP(recorder, served)
		if err := self.awaitStepEights(host.Engine()); err != nil {
			return nil, err
		}
		if recorder.Code == http.StatusServiceUnavailable && try+1 < max(1, self.settings.LbTries) {
			continue
		}
		return recorder.Result(), nil
	}
	return nil, fmt.Errorf("evs world lb: no instance answered a helper's request (tried %v)", tried)
}

// One request served by instance as an Action of its actor, waited for with the baton given up. Whether it answered
// before its instance died, the lb's read timeout passed or ctx ended. A push's answer is noted under pushId when the
// instance gives it, whether or not the lb still waits for it.
func (self *EvsWorld) serve(ctx context.Context, instance string, request *http.Request, body []byte, pushId *sidecar.Id) (*httptest.ResponseRecorder, bool) {
	host := self.instanceHost(instance)
	if host == nil {
		return nil, false
	}
	actor := self.net.Actors().Actor(self.net.Context(), instance)
	recorder := httptest.NewRecorder()
	answered := make(chan struct{})
	run := self.net.Barriers().Start(actor, func() error {
		served := request.Clone(actor.Context())
		served.Body = io.NopCloser(bytes.NewReader(body))
		var attempt *EvsWorldAttempt
		if pushId != nil {
			attempt = self.beginAttempt(*pushId, instance)
		}
		self.handlerOf(instance, host).ServeHTTP(recorder, served)
		if err := self.awaitStepEights(host.Engine()); err != nil {
			return err
		}
		if pushId != nil {
			answer := evsWorldAnswerOf(instance, recorder)
			self.endAttempt(attempt, answer)
			self.noteAnswer(*pushId, answer)
		}
		close(answered)
		return nil
	})
	timedOut := make(chan struct{})
	stop := func() bool { return false }
	if 0 < self.settings.LbReadTimeout {
		stop = self.net.Clock().AfterFunc(self.settings.LbReadTimeout, func() { close(timedOut) })
	}
	defer stop()
	ok := false
	self.net.Barriers().Blocking(func() {
		select {
		case <-answered:
			ok = true
		case <-run.Ended():
			select {
			case <-answered:
				ok = true
			default:
			}
		case <-timedOut:
		case <-ctx.Done():
		}
	})
	return recorder, ok
}

// The instance's step 8s, which run off the reply path, finished, so a check meets a store at rest. Real time bounds
// the wait only to fail it.
func (self *EvsWorld) awaitStepEights(engine *evsservice.EvsEngine) error {
	guard := time.After(self.settings.StepEightTimeout)
	for {
		started, finished, changed := engine.StepEights()
		if started == finished {
			return nil
		}
		select {
		case <-changed:
		case <-guard:
			return errors.New("an instance's step 8s never finished")
		}
	}
}

// The device's next push goes to every instance named at once, as a client's retry and the lb's re-send of one push
// id reach evs together; the device sees the first instance's answer.
func (self *EvsWorld) DuplicateNextPush(device string, instances ...string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.duplicates[device] = slices.Clone(instances)
		return nil
	}
}

// serveDuplicates: each instance serves the push at once.
func (self *EvsWorld) serveDuplicates(device *EvsWorldDevice, request *http.Request, body []byte, pushId sidecar.Id, instances []string) (*http.Response, error) {
	type served struct {
		recorder *httptest.ResponseRecorder
		answered chan struct{}
		run      *sidecartest.ActorRun
	}
	runs := []*served{}
	for _, instance := range instances {
		host := self.instanceHost(instance)
		if host == nil {
			return nil, fmt.Errorf("evs world lb: instance %s is not running", instance)
		}
		actor := self.net.Actors().Actor(self.net.Context(), instance)
		one := &served{recorder: httptest.NewRecorder(), answered: make(chan struct{})}
		one.run = self.net.Barriers().Start(actor, func() error {
			copied := request.Clone(actor.Context())
			copied.Body = io.NopCloser(bytes.NewReader(body))
			attempt := self.beginAttempt(pushId, instance)
			self.handlerOf(instance, host).ServeHTTP(one.recorder, copied)
			if err := self.awaitStepEights(host.Engine()); err != nil {
				return err
			}
			answer := evsWorldAnswerOf(instance, one.recorder)
			self.endAttempt(attempt, answer)
			self.noteAnswer(pushId, answer)
			close(one.answered)
			return nil
		})
		runs = append(runs, one)
	}
	self.net.Barriers().Blocking(func() {
		for _, one := range runs {
			select {
			case <-one.answered:
			case <-one.run.Ended():
			case <-request.Context().Done():
				return
			}
		}
	})
	var first *httptest.ResponseRecorder
	for _, one := range runs {
		select {
		case <-one.answered:
			if first == nil {
				first = one.recorder
			}
		default:
		}
	}
	if first == nil {
		return nil, errors.New("evs world lb: no duplicate answered")
	}
	self.noteAnswer(pushId, evsWorldAnswerOf("lb", first))
	return first.Result(), nil
}

// The push id a POST .../push carries, and whether it is one.
func evsWorldPushIdOf(request *http.Request, body []byte) (sidecar.Id, bool) {
	if request.Method != http.MethodPost || !strings.HasSuffix(request.URL.Path, "/push") {
		return sidecar.Id{}, false
	}
	pushRequest := &protocol.EvsPushRequest{}
	if err := proto.Unmarshal(body, pushRequest); err != nil {
		return sidecar.Id{}, false
	}
	statement, err := sidecar.ParseEvsStatement(pushRequest.GetStatement())
	if err != nil || len(statement.Push.GetPushId()) != 16 {
		return sidecar.Id{}, false
	}
	return sidecar.Id(statement.Push.GetPushId()), true
}

// What a recorder's answer to a push says.
func evsWorldAnswerOf(instance string, recorder *httptest.ResponseRecorder) *EvsWorldAnswer {
	answer := &EvsWorldAnswer{Instance: instance, Status: recorder.Code}
	if recorder.Code == http.StatusOK {
		reply := &protocol.EvsPushReply{}
		if err := proto.Unmarshal(recorder.Body.Bytes(), reply); err == nil {
			answer.Version = reply.GetVersion()
		}
		return answer
	}
	reply := &protocol.EvsRefusalReply{}
	if err := proto.Unmarshal(recorder.Body.Bytes(), reply); err == nil {
		answer.Code = reply.GetCode()
		answer.Recorded = reply.GetRecorded()
		answer.Unknown = reply.GetOutcome() == protocol.EvsPushOutcome_EVS_PUSH_OUTCOME_UNKNOWN
	}
	return answer
}

func (self *EvsWorld) notePush(pushId sidecar.Id, device string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if _, ok := self.pushes[pushId]; !ok {
		self.pushes[pushId] = &EvsWorldPush{PushId: pushId, Device: device}
		self.pushIdList = append(self.pushIdList, pushId)
	}
}

func (self *EvsWorld) noteAnswer(pushId sidecar.Id, answer *EvsWorldAnswer) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if push := self.pushes[pushId]; push != nil {
		push.Answers = append(push.Answers, answer)
	}
}

// Every push id a device posted, in the order they first reached the lb, with every answer each attempt got.
func (self *EvsWorld) Pushes() []*EvsWorldPush {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	pushes := []*EvsWorldPush{}
	for _, pushId := range self.pushIdList {
		push := self.pushes[pushId]
		pushes = append(pushes, &EvsWorldPush{PushId: push.PushId, Device: push.Device, Answers: slices.Clone(push.Answers)})
	}
	return pushes
}

// The pushes a device posted, in order.
func (self *EvsWorld) DevicePushes(device string) []*EvsWorldPush {
	pushes := []*EvsWorldPush{}
	for _, push := range self.Pushes() {
		if push.Device == device {
			pushes = append(pushes, push)
		}
	}
	return pushes
}

// What each instance answered one push id, the lb's answer left out.
func (self *EvsWorldPush) InstanceAnswers() []*EvsWorldAnswer {
	answers := []*EvsWorldAnswer{}
	for _, answer := range self.Answers {
		if answer.Instance != "lb" {
			answers = append(answers, answer)
		}
	}
	return answers
}

// A device's content of size bytes, different on each label.
func EvsWorldContent(label string, size int) []byte {
	return bytes.Repeat([]byte(fmt.Sprintf("%s;", label)), size/(len(label)+1)+1)[:size]
}

// A step action: device writes content to path, which must commit.
func (self *EvsWorld) Write(device string, path string, content []byte) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		write, err := self.write(ctx, device, path, content)
		if err != nil {
			return err
		}
		if write.state != evsWorldWriteCommitted {
			return fmt.Errorf("%s's write of %q did not commit: %v", device, path, write.err)
		}
		return nil
	}
}

// A step action: device removes path, which must commit.
func (self *EvsWorld) Remove(device string, path string) func(ctx context.Context, net *Net) error {
	return self.Write(device, path, nil)
}

// A step action: device writes content to path, which evs must refuse with code.
func (self *EvsWorld) WriteRefused(device string, path string, content []byte, code protocol.EvsRefusalCode) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		write, err := self.write(ctx, device, path, content)
		if err != nil {
			return err
		}
		evsError, ok := sidecar.EvsErrorOf(write.err)
		if write.state != evsWorldWriteRefused || !ok || evsError.Code != code {
			return fmt.Errorf("%s's write of %q ended %v, not refused %s", device, path, write.err, code)
		}
		return nil
	}
}

// A step action: device writes content to path, and the write may end any way, which the ledger keeps.
func (self *EvsWorld) WriteAny(device string, path string, content []byte) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		_, err := self.write(ctx, device, path, content)
		return err
	}
}

// A step action: device writes count paths, pattern's %03d from first, each committing, one push each.
func (self *EvsWorld) WriteMany(device string, pattern string, first int, count int) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		for index := first; index < first+count; index += 1 {
			path := fmt.Sprintf(pattern, index)
			if err := self.Write(device, path, EvsWorldContent(path, 40))(ctx, net); err != nil {
				return err
			}
		}
		return nil
	}
}

// One write through device, in the ledger. The error is the world's, not the write's: a write's own end is in the
// ledger entry.
func (self *EvsWorld) write(ctx context.Context, deviceName string, path string, content []byte) (*evsWorldWrite, error) {
	device := self.Device(deviceName)
	if device.Repo == nil {
		return nil, fmt.Errorf("device %s is not started: Setup runs first", deviceName)
	}
	write := &evsWorldWrite{device: deviceName, content: bytes.Clone(content), state: evsWorldWritePending}
	self.stateLock.Lock()
	self.pathWrites[path] = append(self.pathWrites[path], write)
	self.stateLock.Unlock()
	args := &sidecar.EvsWriteArgs{Path: path, Remove: content == nil}
	if content != nil {
		args.Content = bytes.NewReader(content)
		args.Size = int64(len(content))
	}
	result, err := device.Repo.Write(ctx, args)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	write.err = err
	switch evsError, ok := sidecar.EvsErrorOf(err); {
	case err == nil:
		write.state = evsWorldWriteCommitted
		write.version = result.Version
		write.pushId = result.PushId
	case ok && !evsError.RefusesNothing() && !evsError.OutcomeUnknown:
		write.state = evsWorldWriteRefused
	default:
		write.state = evsWorldWriteUnknown
	}
	return write, nil
}

// The version device's newest write of path committed at, or an error when it did not commit.
func (self *EvsWorld) CommittedVersion(device string, path string) (uint64, sidecar.Id, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	writes := self.pathWrites[path]
	for index := len(writes) - 1; 0 <= index; index -= 1 {
		write := writes[index]
		if write.device != device {
			continue
		}
		if write.state != evsWorldWriteCommitted {
			return 0, sidecar.Id{}, fmt.Errorf("%s's write of %q ended %v", device, path, write.err)
		}
		return write.version, write.pushId, nil
	}
	return 0, sidecar.Id{}, fmt.Errorf("%s wrote no %q", device, path)
}

// The contents a read of path may return now: the newest committed write's, nil for absent, and each write still
// pending or of unknown outcome. Whether the newest committed is a removal or none is in absentOk.
func (self *EvsWorld) acceptable(path string) (contents [][]byte, absentOk bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	writes := self.pathWrites[path]
	var newest *evsWorldWrite
	for _, write := range writes {
		switch write.state {
		case evsWorldWriteCommitted:
			if newest == nil || newest.version < write.version {
				newest = write
			}
		case evsWorldWritePending, evsWorldWriteUnknown:
			if write.content == nil {
				absentOk = true
			} else {
				contents = append(contents, write.content)
			}
		}
	}
	switch {
	case newest == nil || newest.content == nil:
		absentOk = true
	default:
		contents = append(contents, newest.content)
	}
	return contents, absentOk
}

// A step action: device reads each path from the cluster's head, verified as the client verifies every read, and the
// content must be what the ledger allows (acceptable). Readers verify at every barrier a schedule puts this beside.
func (self *EvsWorld) Verify(device string, paths ...string) func(ctx context.Context, net *Net) error {
	return self.verify(device, true, paths...)
}

// Verify through evs's head cache.
func (self *EvsWorld) VerifyCached(device string, paths ...string) func(ctx context.Context, net *Net) error {
	return self.verify(device, false, paths...)
}

func (self *EvsWorld) verify(deviceName string, fresh bool, paths ...string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		device := self.Device(deviceName)
		for _, path := range paths {
			contents, absentOk := self.acceptable(path)
			out := &bytes.Buffer{}
			_, err := device.Repo.ReadHead(ctx, &sidecar.EvsReadArgs{Path: path, Fresh: fresh}, out)
			switch {
			case errors.Is(err, sidecar.ErrEvsPathAbsent):
				if !absentOk {
					return fmt.Errorf("%s read %q as absent, which the ledger does not allow", deviceName, path)
				}
			case err != nil:
				return fmt.Errorf("%s's read of %q: %w", deviceName, path, err)
			default:
				if !slices.ContainsFunc(contents, func(content []byte) bool { return bytes.Equal(content, out.Bytes()) }) {
					return fmt.Errorf("%s read %q as %d bytes no committed, pending or unknown write wrote", deviceName, path, out.Len())
				}
			}
		}
		return nil
	}
}

// A step action: device lists directory, which must name exactly names.
func (self *EvsWorld) VerifyListing(device string, directory string, names ...string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		listing, err := self.Device(device).Repo.List(ctx, &sidecar.EvsReadArgs{Path: directory, Fresh: true})
		if err != nil {
			return fmt.Errorf("%s's listing of %q: %w", device, directory, err)
		}
		listed := []string{}
		for _, entry := range listing.Entries {
			listed = append(listed, string(entry.Name))
		}
		slices.Sort(listed)
		want := slices.Clone(names)
		slices.Sort(want)
		if !slices.Equal(listed, want) {
			return fmt.Errorf("%s listed %q as %v, not %v", device, directory, listed, want)
		}
		return nil
	}
}

// main's head as the repo's cluster holds it, read under an inspecting context; nil while absent.
func (self *EvsWorld) Head(ctx context.Context) (*protocol.EvsHead, error) {
	first, err := self.net.Host().Blobs.FirstCluster()
	if err != nil {
		return nil, err
	}
	object, err := first.Get(sidecartest.InspectContext(ctx), evsservice.HeadKey(self.RepoId, self.RefId()))
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer object.Body.Close()
	headBytes, err := io.ReadAll(object.Body)
	if err != nil {
		return nil, err
	}
	head := &protocol.EvsHead{}
	if err := proto.Unmarshal(headBytes, head); err != nil {
		return nil, err
	}
	return head, nil
}

// A step action: instance folds every unfolded version of main; its next commit raises folded_through over them.
func (self *EvsWorld) Fold(instance string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		engine, err := self.Engine(instance)
		if err != nil {
			return err
		}
		first, err := net.Host().Blobs.FirstCluster()
		if err != nil {
			return err
		}
		head, err := engine.Heads().ReadCluster(ctx, first, self.RepoId, self.RefId())
		if err != nil {
			return err
		}
		now := net.Clock().Now()
		if _, err := engine.Folder().FoldAll(ctx, first, self.RepoId, self.RefId(), head, now, now.Add(15*time.Second)); err != nil {
			return err
		}
		return self.awaitStepEights(engine)
	}
}

// A step action: one hourly evacuation run on the repo's cluster, as taskworker runs it, its spool in the system's
// temporary directory, which the run removes. A run a store error ends is run once more, as taskworker's next run
// would be, and only that one's error fails the step: a lost answer is the row's fault, not the job's.
func (self *EvsWorld) Evacuate() func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		first, err := net.Host().Blobs.FirstCluster()
		if err != nil {
			return err
		}
		run := func() error {
			evacuator, err := evsservice.NewEvacuator(net.Host(), &evsservice.EvacuatorDeps{Settings: evsservice.DefaultEvacuatorSettings()})
			if err != nil {
				return err
			}
			_, err = evacuator.Run(ctx, first.ClusterId())
			return err
		}
		if err := run(); err == nil {
			return nil
		}
		return run()
	}
}

// A step action: the nightly pass over the repo's cluster, orphan GC among it, the segment cluster quiet. A pass a
// store error ends runs once more, as Evacuate's does.
func (self *EvsWorld) Nightly() func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		first, err := net.Host().Blobs.FirstCluster()
		if err != nil {
			return err
		}
		run := func() error {
			pass, err := evsservice.NewNightlyPass(net.Host(), &evsservice.NightlyPassDeps{
				Evacuator:          evsservice.DefaultEvacuatorSettings(),
				SegmentClusterBusy: func(ctx context.Context, clusterId string) bool { return false },
			})
			if err != nil {
				return err
			}
			_, err = pass.Run(ctx, first.ClusterId(), "", "")
			return err
		}
		if err := run(); err == nil {
			return nil
		}
		return run()
	}
}

// The checks every evs row of this world names beside its own: FI-1 and FI-6, which are bound, the outcome rules
// FI-2's oracle (TEST-M2-04) will hold once it binds (EvsWorldOutcomes), and no device alarming.
func (self *EvsWorld) Checks(invariants ...Invariant) []Invariant {
	return append([]Invariant{FI(1), FI(6), self.Outcomes(), self.NoAlarms()}, invariants...)
}

// FI-2's clauses a world can read until TEST-M2-04's oracle binds, which a schedule names in its place, as
// fs_team.go's agreement does for FI-2 and FI-3: every committed version of main names one push id, which commits
// once and never moves; every 200 an instance or the lb answered names its push id's committed version (a retry
// returns the original result); no push id a refusal answered ever commits (I-EVS-3); and no evs instance issued a
// DELETE, since no answer deletes anything (I-EVS-2). The window is read after every step, so a schedule pages out
// at most 64 versions in one step.
func (self *EvsWorld) Outcomes() Invariant {
	return NewInvariant("FI-2/outcomes", func(ctx context.Context, oracle *Oracle) error {
		self.stateLock.Lock()
		setUp := self.setUp
		refId := self.refId
		self.stateLock.Unlock()
		if !setUp {
			return nil
		}
		for _, entry := range oracle.Changed() {
			if entry.Op == sidecartest.BlobHistoryDelete && slices.Contains(self.settings.Instances, entry.Actor) {
				return fmt.Errorf("evs instance %s deleted %s: no answer deletes anything (I-EVS-2)", entry.Actor, entry.Key)
			}
		}
		heads, err := oracle.View.Heads(ctx, self.RepoId)
		if err != nil {
			return err
		}
		for _, stored := range heads {
			if sidecar.Id(stored.RefId) != refId {
				continue
			}
			entries, err := sidecar.DecodeEvsWindow(stored.Head.GetWindow())
			if err != nil {
				return fmt.Errorf("main's window: %w", err)
			}
			first := stored.Head.GetVersion() + 1 - uint64(len(entries))
			self.stateLock.Lock()
			for index, entry := range entries {
				version := first + uint64(index)
				if seen, ok := self.versionPushIds[version]; ok && seen != entry.PushId {
					self.stateLock.Unlock()
					return fmt.Errorf("version %d named push %s, now %s", version, seen, entry.PushId)
				}
				if seen, ok := self.pushIdVersions[entry.PushId]; ok && seen != version {
					self.stateLock.Unlock()
					return fmt.Errorf("push %s committed at %d and at %d", entry.PushId, seen, version)
				}
				self.versionPushIds[version] = entry.PushId
				self.pushIdVersions[entry.PushId] = version
			}
			self.stateLock.Unlock()
		}
		for _, push := range self.Pushes() {
			self.stateLock.Lock()
			version, committed := self.pushIdVersions[push.PushId]
			self.stateLock.Unlock()
			for _, answer := range push.Answers {
				switch {
				case answer.Status == http.StatusOK && committed && answer.Version != version:
					return fmt.Errorf("push %s committed at %d, and %s answered %d", push.PushId, version, answer.Instance, answer.Version)
				case answer.Refuses() && committed:
					return fmt.Errorf("push %s committed at %d after %s refused it (I-EVS-3)", push.PushId, version, answer)
				}
			}
		}
		return nil
	})
}

// Whether a push id is in main's committed history as the outcome check has read it, and at which version.
func (self *EvsWorld) committedVersionOf(pushId sidecar.Id) (uint64, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	version, ok := self.pushIdVersions[pushId]
	return version, ok
}

// No device has raised an evs alarm.
func (self *EvsWorld) NoAlarms() Invariant {
	return NewInvariant("evs alarms", func(ctx context.Context, oracle *Oracle) error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, name := range self.deviceNames {
			if alarms := self.deviceAlarms[name]; 0 < len(alarms) {
				return fmt.Errorf("%s alarmed: %v", name, alarms)
			}
		}
		return nil
	})
}

// A step action checking the world's state as a schedule's own clause states it.
func (self *EvsWorld) Expect(what string, check func(ctx context.Context) error) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		if err := check(ctx); err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
		return nil
	}
}
