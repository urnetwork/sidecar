//go:build !sidecar_http && !ios_extension

// An app host on BridgeNet (BRIDGE-M8-07; DESIGN-DETAILS 4.2.5, 4.6; §18.6's following and posture; D-SDK-32, owner
// decision 197): a host whose device role is fed by its own sidecar.Forwarder, as an app's VPN component's is while the
// app and its sidecar role do not run. No BridgeComponent, ConfigClient or sidecar role runs for it:
//
//	keys      the host's own forwarding Delegation, filed by its identity key as §18.6's setup files it, naming a real
//	          X-Wing reader key, and the key set the hand-off leaves in the component's key store (ForwarderKeys)
//	follow    the Forwarder reads api's projection as F's token reads it; a team hint, which F's long-poll brings, is
//	          Hint here, which each wait for the host at the tip sends
//	gkm       the config group as F's exchange reads it: generation 1's Signed GenRotate, signed by the owner's
//	          device with the key holders' digest at its pin, and a LATE DelegationWrap of it to each forwarding
//	          Delegation's reader key at the state the Delegation landed at, which setup's step 4 files: each passes
//	          §10.9's checks, which the Forwarder runs at its own pin
//	heads     the network's config heads; bindings, each device's signed binding as GET /sidecar/identity answers it
//	sink      the device role's posture, read at the clock's now (device.Bridge.DecisionNow) as sdk's sink reads it,
//	          its overdue alarm reported raised once a raise
//	posture   an in-memory store and floor, which a restart hands the next host and a rollback copies and puts back
//	nat       a LocalUserNat built with the role's hook, under the sdk host's profile, and its provider only once the
//	          Forwarder has anchored the posture, so no flow reaches the NAT before a hook that denies (BridgeNat.tla's
//	          ProviderBeforeCatchUp)
//
// A schedule holds a compile at its admission (HoldCompiles), so a race is staged with no sleep, and blocks compiles
// as a device under provider load does (SetHeapInUse past the settings' ceiling) or as one over the memory cap does
// (the Forwarder's CompileMemoryMaxByteCount). The Forwarder's timers, the posture's waiting clock and the device role
// run on the Net's clock, which a schedule moves; flows and contracts run on connect's real timers.
//
// What is not the system here: F is not minted at api and no token of its is checked, since the admission world's api
// is read in process (forward_only's exchange is server/oauth's TEAM-M8-02 test); gkm is a fake serving the one
// generation BridgeNet seals under; and the long-poll is Hint.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
	sidecarprotocol "github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The config group at gkm, as a forwarding client reads it with F's exchange: the Signed GenRotates in order, and each
// generation's DelegationWraps by recipient, d:<delegation_id>. Safe for concurrent use.
type bridgeNetGkm struct {
	groupId sidecar.Id
	key     *sidecar.EvsRepoKey
	// the device that rotated generation 1 and delivers its wraps: a holder of it
	holder *AdmissionDevice

	stateLock   sync.Mutex
	generations []*bridge.Signed
	wraps       map[uint64]map[string][]*bridge.Signed
	// how many reads of each kind it answered
	generationsReadCount int
	wrapsReadCount       int
}

var _ sidecar.ForwarderGkm = (*bridgeNetGkm)(nil)

// The config group with generation 1's GenRotate signed by holder, the owner's device, which rotated it.
func newBridgeNetGkm(groupId sidecar.Id, key *sidecar.EvsRepoKey, rotate *sidecarprotocol.GenRotate, holder *AdmissionDevice) (*bridgeNetGkm, error) {
	signed, err := sidecar.SignGenRotate(rotate, bridgeNetGkmSign(holder))
	if err != nil {
		return nil, err
	}
	return &bridgeNetGkm{
		groupId:     groupId,
		key:         key,
		holder:      holder,
		generations: []*bridge.Signed{signed},
		wraps:       map[uint64]map[string][]*bridge.Signed{},
	}, nil
}

// A device's identity key as gkm's signer.
func bridgeNetGkmSign(device *AdmissionDevice) sidecar.GkmSignFunction {
	return func(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
		return &bridge.Signed{
			Body:      bytes.Clone(body),
			SignerId:  device.SidecarId.Bytes(),
			Signature: ed25519.Sign(device.Key, bridge.SignedBytes(purpose, signedType, body)),
			Type:      uint32(signedType),
		}, nil
	}
}

// A DelegationWrap of generation 1 to a forwarding Delegation's reader key, signed by the holder (DESIGN-DETAILS 4.2.6's
// step 4: the late wrap of the config's current generation): LATE at auth, a state where the Delegation is live, and at,
// the holder's clock, as §10.9's late row has it, since the Delegation was filed after generation 1's claim.
func (self *bridgeNetGkm) wrap(delegationId []byte, readerKey hpke.PrivateKey, auth *bridge.AuthPin, at time.Time) error {
	delivery, err := sidecar.SealGkmDelivery(self.key, &sidecar.GkmDeliveryArgs{
		GroupId:            self.groupId,
		Type:               sidecar.GkmWrapTypeDelegation,
		Recipient:          delegationId,
		RecipientPublicKey: readerKey.PublicKey().Bytes(),
		Kind:               sidecar.GkmDeliveryLate,
		Auth:               auth,
		Time:               at,
	})
	if err != nil {
		return err
	}
	signed, err := sidecar.SignGkmDelivery(delivery, sidecar.GkmWrapTypeDelegation, bridgeNetGkmSign(self.holder))
	if err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	generation := self.key.Generation()
	if self.wraps[generation] == nil {
		self.wraps[generation] = map[string][]*bridge.Signed{}
	}
	recipient := bridgeNetWrapRecipient(delegationId)
	self.wraps[generation][recipient] = append(self.wraps[generation][recipient], signed)
	return nil
}

// A Delegation as a wrap's recipient, as the wrap path writes it.
func bridgeNetWrapRecipient(delegationId []byte) string {
	return fmt.Sprintf("d:%x", delegationId)
}

// sidecar.ForwarderGkm: the GenRotates after since.
func (self *bridgeNetGkm) Generations(ctx context.Context, repoId sidecar.Id, groupId sidecar.Id, since uint64) (*sidecarprotocol.GkmGenerationsReply, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.generationsReadCount += 1
	reply := &sidecarprotocol.GkmGenerationsReply{}
	if groupId != self.groupId || repoId != self.key.RepoId() {
		return reply, nil
	}
	if since < uint64(len(self.generations)) {
		for _, signed := range self.generations[since:] {
			reply.Generations = append(reply.Generations, proto.Clone(signed).(*bridge.Signed))
		}
	}
	return reply, nil
}

// sidecar.ForwarderGkm: one recipient's deliveries of a generation.
func (self *bridgeNetGkm) Wraps(ctx context.Context, repoId sidecar.Id, groupId sidecar.Id, generation uint64, query *sidecar.GkmWrapsQuery) (*sidecarprotocol.GkmWrapsReply, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.wrapsReadCount += 1
	reply := &sidecarprotocol.GkmWrapsReply{}
	if groupId != self.groupId || repoId != self.key.RepoId() || query == nil {
		return reply, nil
	}
	for _, signed := range self.wraps[generation][query.Recipient] {
		reply.Wraps = append(reply.Wraps, proto.Clone(signed).(*bridge.Signed))
	}
	return reply, nil
}

// sidecar.ForwarderGkm: none, so the Forwarder lists generations in the group its hand-off named, which no re-form
// moved here.
func (self *bridgeNetGkm) Forms(ctx context.Context, repoId sidecar.Id) (*sidecarprotocol.GkmFormsReply, error) {
	return &sidecarprotocol.GkmFormsReply{}, nil
}

// A forwarding Delegation's X-Wing reader key from a label, the same on every run.
func bridgeNetReaderKey(networkId sidecar.Id, label string) (hpke.PrivateKey, error) {
	seed := sha256.Sum256(append(networkId.Bytes(), []byte("bridge net reader key "+label)...))
	return hpke.MLKEM768X25519().NewPrivateKey(seed[:])
}

// The component's forwarding key set as the hand-off leaves it (sidecar.ForwarderKeys): the host's own forwarding
// Delegation, its key and its reader key, which never leave the component.
type bridgeNetForwarderKeys struct {
	forwarding *BridgeNetForwarding
}

var _ sidecar.ForwarderKeys = (*bridgeNetForwarderKeys)(nil)

func (self *bridgeNetForwarderKeys) Delegation() ([sha256.Size]byte, ed25519.PublicKey, bool) {
	return [sha256.Size]byte(self.forwarding.DelegationId), self.forwarding.Key.Public().(ed25519.PublicKey), true
}

func (self *bridgeNetForwarderKeys) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(self.forwarding.Key, message), nil
}

func (self *bridgeNetForwarderKeys) ReaderKeys() ([]sidecar.ForwarderReaderKey, error) {
	return []sidecar.ForwarderReaderKey{{
		DelegationId: [sha256.Size]byte(self.forwarding.DelegationId),
		PrivateKey:   self.forwarding.ReaderKey,
	}}, nil
}

// A device role's posture store in memory (device.PostureStore), which a restart hands the next host, and which a
// test copies and puts back as an attacker holding the device's storage would (Fwd.tla's Snapshot and Rollback). Safe
// for concurrent use.
type BridgeNetPostureStore struct {
	stateLock sync.Mutex
	records   map[string][]byte
}

var _ device.PostureStore = (*BridgeNetPostureStore)(nil)

func NewBridgeNetPostureStore() *BridgeNetPostureStore {
	return &BridgeNetPostureStore{records: map[string][]byte{}}
}

func (self *BridgeNetPostureStore) Open(name string) (io.ReadCloser, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	record, found := self.records[name]
	if !found {
		return nil, device.ErrPostureStoreAbsent
	}
	return io.NopCloser(bytes.NewReader(bytes.Clone(record))), nil
}

func (self *BridgeNetPostureStore) Write(name string, write func(writer io.Writer) error) error {
	buffer := &bytes.Buffer{}
	if err := write(buffer); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.records[name] = buffer.Bytes()
	return nil
}

func (self *BridgeNetPostureStore) Remove(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.records, name)
	return nil
}

func (self *BridgeNetPostureStore) List() ([]string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Sorted(maps.Keys(self.records)), nil
}

// A copy of every record, as an attacker copies the store's files.
func (self *BridgeNetPostureStore) Snapshot() map[string][]byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	snapshot := map[string][]byte{}
	for name, record := range self.records {
		snapshot[name] = bytes.Clone(record)
	}
	return snapshot
}

// Puts snapshot back in place of every record, as an attacker restores a copy.
func (self *BridgeNetPostureStore) Restore(snapshot map[string][]byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.records = map[string][]byte{}
	for name, record := range snapshot {
		self.records[name] = bytes.Clone(record)
	}
}

// The posture's floor outside its store (DESIGN-DETAILS 4.2.5's restart row; 4.2.2's fwd.<net8>.floor): the highest
// pin it committed, in the platform's key store, which a copy of the store does not carry. Safe for concurrent use.
type BridgeNetPostureFloor struct {
	stateLock sync.Mutex
	n         uint64
	chain     []byte
}

func NewBridgeNetPostureFloor() *BridgeNetPostureFloor {
	return &BridgeNetPostureFloor{}
}

// The floor as the posture's settings take it.
func (self *BridgeNetPostureFloor) postureFloor() *device.PostureFloor {
	return &device.PostureFloor{
		Load: func() (uint64, []byte, error) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.n, bytes.Clone(self.chain), nil
		},
		Commit: func(n uint64, chain []byte) error {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.n, self.chain = n, bytes.Clone(chain)
			return nil
		},
	}
}

// The floor's position.
func (self *BridgeNetPostureFloor) N() uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.n
}

// The device role as its Forwarder's sink (sidecar.ForwarderSink), as sdk's deviceForwardSink is: each call through,
// the decision read at the clock's now, and an overdue alarm reported raised once, by its position and age, since a
// later read of the posture finds the same raise.
type bridgeNetForwardSink struct {
	bridge         *device.Bridge
	overdueTimeout time.Duration

	stateLock sync.Mutex
	// the overdue alarm last reported raised
	raised    bool
	raisedN   uint64
	raisedAge time.Duration
	// the newest pin a call handed the posture after which it wanted a compile
	wantedThrough uint64
}

var _ sidecar.ForwarderSink = (*bridgeNetForwardSink)(nil)

func (self *bridgeNetForwardSink) SetPending(pending *bridge.Pending) error {
	return self.bridge.SetPending(pending)
}

func (self *bridgeNetForwardSink) SetState(state *bridge.BridgeState, log *sidecar.BridgeStateLog) error {
	return self.bridge.SetState(state, bridgeNetPostureLog(log))
}

func (self *bridgeNetForwardSink) ApplyDeltas(log *sidecar.BridgeStateLog) error {
	err := self.bridge.ApplyDeltas(bridgeNetPostureLog(log))
	if decision := self.bridge.Decision(); decision.CompileWanted {
		self.stateLock.Lock()
		self.wantedThrough = max(self.wantedThrough, decision.Pin.GetVersion())
		self.stateLock.Unlock()
	}
	return err
}

func (self *bridgeNetForwardSink) SetFork(fork bool) error {
	return self.bridge.SetFork(fork)
}

// The posture's decision at now, as the Forwarder reads it (sdk's deviceForwardSinkDecisionOf).
func (self *bridgeNetForwardSink) Decision() sidecar.BridgeSinkDecision {
	decision := self.bridge.DecisionNow()
	sink := sidecar.BridgeSinkDecision{
		Pin:           decision.Pin,
		Fork:          decision.Fork,
		CompileWanted: decision.CompileWanted,
		WaitingCount:  len(decision.Waiting),
	}
	switch {
	case decision.State == device.PostureLegacy:
		sink.State = sidecar.BridgeSinkLegacy
	case decision.State.Enforcing() && !decision.Fork && decision.OverlayFullThroughN == 0:
		sink.State = sidecar.BridgeSinkEnforcing
	default:
		sink.State = sidecar.BridgeSinkPending
	}
	if decision.BridgeState != nil {
		sink.StatePin = decision.BridgeState.GetAuth()
	}
	if overdue := decision.Overdue; overdue != nil {
		sink.Overdue = &sidecar.BridgeSinkOverdue{N: overdue.N, Age: overdue.Age}
		sink.NextAlarmAt = overdue.NextAlarmAt
		for _, alarm := range decision.Alarms {
			if alarm.Kind != device.PostureAlarmCompileOverdue {
				continue
			}
			self.stateLock.Lock()
			if !self.raised || alarm.N != self.raisedN || alarm.Age != self.raisedAge {
				self.raised, self.raisedN, self.raisedAge = true, alarm.N, alarm.Age
				sink.Overdue.Raised = true
			}
			self.stateLock.Unlock()
		}
	} else if 0 < len(decision.Waiting) && 0 < self.overdueTimeout {
		oldest := decision.Waiting[0].FirstSeen
		for _, waiting := range decision.Waiting {
			if waiting.FirstSeen.Before(oldest) {
				oldest = waiting.FirstSeen
			}
		}
		sink.NextAlarmAt = oldest.Add(self.overdueTimeout)
	}
	return sink
}

// The newest position whose entries the posture wanted a compile for.
func (self *bridgeNetForwardSink) compileWantedThrough() uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.wantedThrough
}

// One bridge_alarm or head_alarm the Forwarder raised, when the Net's clock read At; for narrowing_overdue, the
// posture's raise it carried: the waiting entry's position and age.
type BridgeNetForwarderAlarm struct {
	Reason string
	At     time.Time
	N      uint64
	Age    time.Duration
}

// What holds a compile at its admission until the schedule lets it go: the Forwarder's heap reading, which every
// compile takes once it has captured the newest stored entry.
type bridgeNetCompileGate struct {
	stateLock sync.Mutex
	held      bool
	release   chan struct{}
	// moves each time a compile arrives at the gate
	arrivals *connect.MonitorValue[int]
	// the heap a compile reads once through the gate
	heapInUse atomic.Int64
}

func newBridgeNetCompileGate() *bridgeNetCompileGate {
	return &bridgeNetCompileGate{release: make(chan struct{}), arrivals: connect.NewMonitorValue(0)}
}

// The Forwarder's HeapInUse: waits while the gate is held, then answers the heap the schedule set.
func (self *bridgeNetCompileGate) pass(ctx context.Context) int64 {
	self.stateLock.Lock()
	held, release := self.held, self.release
	self.stateLock.Unlock()
	self.arrivals.Update(func(count int) int { return count + 1 })
	if held {
		select {
		case <-release:
		case <-ctx.Done():
		}
	}
	return self.heapInUse.Load()
}

func (self *bridgeNetCompileGate) hold() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !self.held {
		self.held = true
		self.release = make(chan struct{})
	}
}

func (self *bridgeNetCompileGate) open() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.held {
		self.held = false
		close(self.release)
	}
}

// Tunables of an app host. The zero value is an app host of the network's with no address.
type BridgeNetAppHostSettings struct {
	// The host's own overlay address, which it files as its BridgeAddress; the zero address files none.
	Address netip.Addr
	// Edits the Forwarder's settings, which start as a desktop service's with no compile delay, no least interval and
	// no memory returned to the OS, so a compile runs as soon as it is wanted on the Net's clock.
	Forwarder func(settings *sidecar.ForwarderSettings)
	// Edits the device role's settings, which start as DefaultBridgeSettings on the Net's clock under the sdk host's
	// table, the posture's clock the Net's and its floor the host's.
	Bridge func(settings *device.BridgeSettings)
	// Stands between the Forwarder and api's projection, as a lagging or withholding api would; nil reads api's.
	Projection func(api sidecar.ConfigProjectionReader) sidecar.ConfigProjectionReader
	// The host this one restarts, closed by the caller first: its posture's store and floor, its Forwarder's store,
	// its forwarding keys and its address, none of them filed again, and its upstream where the caller made it, an
	// upstream of the host's own having closed with it.
	Restart *BridgeNetHost
	// Whether to return before the role enforces a state at the network's tip, for a schedule whose compiles cannot
	// run yet.
	NoWait bool
	// Whether every compile is held at its admission from the start until ReleaseCompiles, so the posture the role
	// restored is what it enforces until the schedule lets a compile run.
	HoldCompiles bool
}

// What an app host holds beside BridgeNetHost's fields.
type bridgeNetAppHost struct {
	settings *BridgeNetAppHostSettings
	// its own forwarding Delegation and the keys it names
	forwarding *BridgeNetForwarding
	keys       *bridgeNetForwarderKeys
	sink       *bridgeNetForwardSink
	store      *BridgeNetPostureStore
	floor      *BridgeNetPostureFloor
	// the Forwarder's store, a FakeStore's root
	forwarderStore sidecar.ForwarderStore
	gate           *bridgeNetCompileGate
	nat            *connect.LocalUserNat
	provider       *connect.RemoteUserNatProvider
	pending        *bridge.Pending

	stateLock sync.Mutex
	forwarder *sidecar.Forwarder
	alarms    []BridgeNetForwarderAlarm
	// moves at each alarm recorded
	alarmCount *connect.MonitorValue[int]
}

// Starts device as an app host (the file's comment): files its address and its forwarding Delegation where settings
// name no restart, builds its device role, its connect client, its NAT and its Forwarder, anchors the posture, starts
// the provider, and unless NoWait waits until the role enforces a state at the network's tip.
func (self *BridgeNet) StartAppHost(hostDevice *BridgeNetDevice, settings *BridgeNetAppHostSettings) *BridgeNetHost {
	self.t.Helper()
	if settings == nil {
		settings = &BridgeNetAppHostSettings{}
	}
	ctx, cancel := context.WithCancel(self.net.Context())
	host := &BridgeNetHost{
		bridgeNet:  self,
		Device:     hostDevice,
		Address:    settings.Address,
		ctx:        ctx,
		cancel:     cancel,
		dials:      &bridgeNetDials{changes: connect.NewMonitorValue(0), lanHosts: map[netip.Addr]bool{}},
		adoptedPin: connect.NewMonitorValue[uint64](0),
		records:    connect.NewMonitorValue(0),
	}
	app := &bridgeNetAppHost{
		settings:   settings,
		gate:       newBridgeNetCompileGate(),
		alarmCount: connect.NewMonitorValue(0),
	}
	if settings.HoldCompiles {
		app.gate.hold()
	}
	host.app = app
	fail := func(format string, args ...any) {
		host.Close()
		self.t.Fatalf(format, args...)
	}
	if restart := settings.Restart; restart != nil && restart.app != nil {
		host.Address = restart.Address
		if !restart.ownsUpstream {
			// the caller's, which outlives the host; one the host owned closed with it, and the next host makes its own
			host.Upstream = restart.Upstream
		}
		app.forwarding = restart.app.forwarding
		app.store = restart.app.store
		app.floor = restart.app.floor
		app.forwarderStore = restart.app.forwarderStore
	} else {
		if settings.Address.IsValid() {
			self.FileAddress(hostDevice, settings.Address)
		}
		app.forwarding = self.FileForwarding(hostDevice, "app host "+hostDevice.Name)
		app.store = NewBridgeNetPostureStore()
		app.floor = NewBridgeNetPostureFloor()
		app.forwarderStore = NewFakeStore().Root()
	}
	app.keys = &bridgeNetForwarderKeys{forwarding: app.forwarding}
	if host.Upstream == nil {
		upstream, err := newBridgeNetUpstream(self.settings.ReadByteCount)
		if err != nil {
			fail("the upstream: %v", err)
		}
		host.Upstream = upstream
		host.ownsUpstream = true
	}

	clientSettings := netClientSettings()
	clientSettings.ClientKeySeed = bytes.Clone(hostDevice.clientKeySeed)
	clientSettings.EncryptionSettings.ExposeVerifiedPeerClientKey = true
	host.Client = self.net.exchange.addClientWithControl(ctx, hostDevice.Name, hostDevice.ClientId, clientSettings, &bridgeNetControl{
		ctx:      ctx,
		clientId: hostDevice.ClientId,
		platform: self.platform,
		mint: func(request *protocol.CreateContract) (*protocol.CreateContractResult, bool, error) {
			return self.mintReturn(hostDevice.ClientId, request)
		},
		workers: self.controls,
	})
	if err := self.waitClient(ctx, host.Client, map[protocol.ProvideMode]bool{protocol.ProvideMode_Network: true}); err != nil {
		fail("the host's client: %v", err)
	}

	clock := self.net.Clock()
	postureSettings := device.DefaultPostureSettings()
	postureSettings.Now = clock.Now
	postureSettings.Floor = app.floor.postureFloor()
	bridgeSettings := device.DefaultBridgeSettings()
	bridgeSettings.Clock = clock
	bridgeSettings.PolicyProfile = device.BridgePolicyProfileSdkHost
	bridgeSettings.PostureSettings = postureSettings
	if settings.Bridge != nil {
		settings.Bridge(bridgeSettings)
	}
	var err error
	host.Bridge, err = device.NewBridge(ctx, app.store, nil, bridgeSettings)
	if err != nil {
		fail("the device role: %v", err)
	}
	host.removeCallbacks = append(host.removeCallbacks, host.Bridge.AddChangeCallback(func() {
		pin := host.Bridge.Decision().Pin.GetVersion()
		host.adoptedPin.Update(func(adopted uint64) uint64 { return max(adopted, pin) })
	}))
	overdueTimeout := device.DefaultPostureSettings().NarrowingOverdueTimeout
	if bridgeSettings.PostureSettings != nil {
		overdueTimeout = bridgeSettings.PostureSettings.NarrowingOverdueTimeout
	}
	app.sink = &bridgeNetForwardSink{bridge: host.Bridge, overdueTimeout: overdueTimeout}

	natSettings := connect.DefaultLocalUserNatSettings()
	dialSettings := &connect.DialContextSettings{DialContext: host.dials.dial}
	natSettings.TcpBufferSettings.DialContextSettings = dialSettings
	natSettings.UdpBufferSettings.DialContextSettings = dialSettings
	natSettings.EgressHook = &bridgeNetHook{inner: host.Bridge.EgressHook(), host: host}
	app.nat = connect.NewLocalUserNat(ctx, "bridge app host "+hostDevice.Name, natSettings)

	genesisChain := self.admission.GenesisChain()
	app.pending = &bridge.Pending{
		NetworkId:           self.NetworkId().Bytes(),
		GenesisSha256:       genesisChain[:],
		SidecarId:           hostDevice.SidecarId().Bytes(),
		IdentityPublicKey:   hostDevice.Device.PublicKey(),
		ForwardDelegationId: bytes.Clone(app.forwarding.DelegationId),
	}
	if err := host.startForwarder(nil); err != nil {
		fail("the Forwarder: %v", err)
	}
	// the provider only once the Forwarder's start has anchored the posture, which then denies every private
	// destination until a state verifies
	if !host.waitPosture(func(decision device.PostureDecision) bool { return decision.State != device.PostureLegacy }) {
		fail("%s's posture was never anchored", hostDevice.Name)
	}
	app.provider, err = connect.TryNewRemoteUserNatProvider(host.Client.Client, app.nat, connect.DefaultRemoteUserNatProviderSettings())
	if err != nil {
		fail("the provider: %v", err)
	}
	self.stateLock.Lock()
	self.hosts = append(self.hosts, host)
	self.stateLock.Unlock()
	if !settings.NoWait {
		host.WaitAdopted(self.admission.Tip().GetVersion())
	}
	return host
}

// What a restart of an app host's Forwarder changes, over the settings the host started with.
type BridgeNetForwarderRestart struct {
	// Edits the restarted Forwarder's settings after the host's own edit.
	Forwarder func(settings *sidecar.ForwarderSettings)
	// Starts the Forwarder over an empty store of its own, as a component whose store was lost.
	FreshStore bool
	// Stands between the restarted Forwarder and api's projection; nil keeps the host's.
	Projection func(api sidecar.ConfigProjectionReader) sidecar.ConfigProjectionReader
}

// Builds and starts the host's Forwarder over restart's changes, nil for none.
func (self *BridgeNetHost) startForwarder(restart *BridgeNetForwarderRestart) error {
	app := self.app
	world := self.bridgeNet
	forwarderSettings := sidecar.DefaultForwarderSettings(sidecar.ForwarderHostDesktop)
	forwarderSettings.CompileDelay = 0
	forwarderSettings.CompileMinInterval = 0
	forwarderSettings.FreeMemoryAfterCompile = false
	if app.settings.Forwarder != nil {
		app.settings.Forwarder(forwarderSettings)
	}
	projection := world.admission.projection()
	wrap := app.settings.Projection
	if restart != nil {
		if restart.Forwarder != nil {
			restart.Forwarder(forwarderSettings)
		}
		if restart.FreshStore {
			app.forwarderStore = NewFakeStore().Root()
		}
		if restart.Projection != nil {
			wrap = restart.Projection
		}
	}
	if wrap != nil {
		projection = wrap(projection)
	}
	forwarder, err := sidecar.NewForwarder(self.ctx, &sidecar.ForwarderArgs{
		NetworkId:     world.NetworkId(),
		SidecarId:     self.Device.SidecarId(),
		Pending:       app.pending,
		ConfigRepoId:  world.admission.ConfigRepoId(),
		ConfigGroupId: world.gkm.groupId,
		Projection:    projection,
		Heads:         world.admission.heads,
		Gkm:           world.gkm,
		Binding:       world.signedBinding,
		Store:         app.forwarderStore,
		Keys:          app.keys,
		Sink:          app.sink,
		HeapInUse: func() int64 {
			return app.gate.pass(self.ctx)
		},
		Emit: func(event sidecar.SidecarEvent) {
			self.recordForwarderAlarm(event)
		},
		Clock:    world.net.Clock(),
		Log:      sidecar.NewNoopLogger(),
		Settings: forwarderSettings,
	})
	if err != nil {
		return err
	}
	app.stateLock.Lock()
	app.forwarder = forwarder
	app.stateLock.Unlock()
	return nil
}

// Records an alarm the Forwarder raised, on its goroutine: for narrowing_overdue, the posture's raise it carried,
// which the sink adopted into the role's decision just before.
func (self *BridgeNetHost) recordForwarderAlarm(event sidecar.SidecarEvent) {
	app := self.app
	alarm := BridgeNetForwarderAlarm{At: self.bridgeNet.net.Clock().Now()}
	switch event.Kind {
	case sidecar.SidecarEventBridgeAlarm:
		alarm.Reason = string(event.BridgeAlarm)
	case sidecar.SidecarEventHeadAlarm:
		alarm.Reason = "head_alarm " + string(event.HeadAlarm)
	default:
		return
	}
	if alarm.Reason == sidecar.ForwarderAlarmNarrowingOverdue {
		for _, raised := range self.Bridge.Decision().Alarms {
			if raised.Kind == device.PostureAlarmCompileOverdue {
				alarm.N, alarm.Age = raised.N, raised.Age
			}
		}
	}
	app.stateLock.Lock()
	app.alarms = append(app.alarms, alarm)
	app.stateLock.Unlock()
	app.alarmCount.Update(func(count int) int { return count + 1 })
}

// Whether a compile waited for something the world serves, which a later compile takes: a generation, or the binding
// of a device of the world's. The owner's first device signed no binding here, so a wait for its binding stands.
func (self *BridgeNet) waitsForWhatIsServed(waits []sidecar.BridgeCompileWait) bool {
	for _, wait := range waits {
		switch wait.Kind {
		case sidecar.BridgeCompileWaitGeneration:
			return true
		case sidecar.BridgeCompileWaitBinding:
			if _, err := self.signedBinding(self.net.Context(), wait.SidecarId); err == nil {
				return true
			}
		}
	}
	return false
}

// A device of the world's own signed binding, as GET /sidecar/identity answers it.
func (self *BridgeNet) signedBinding(ctx context.Context, sidecarId sidecar.Id) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, device := range self.devices {
		if device.SidecarId() == sidecarId {
			return bytes.Clone(device.Binding), nil
		}
	}
	return nil, errors.New("api holds no binding for the sidecar")
}

// Whether the host is an app host, fed by its own Forwarder.
func (self *BridgeNetHost) IsAppHost() bool {
	return self.app != nil
}

// The app host's running Forwarder; nil for a host the sidecar role feeds.
func (self *BridgeNetHost) Forwarder() *sidecar.Forwarder {
	if self.app == nil {
		return nil
	}
	self.app.stateLock.Lock()
	defer self.app.stateLock.Unlock()
	return self.app.forwarder
}

// The app host's own forwarding Delegation, whose reader key opens the config's generations.
func (self *BridgeNetHost) Forwarding() *BridgeNetForwarding {
	return self.app.forwarding
}

// The app host's posture store and floor, which a rollback copies and a restart hands on.
func (self *BridgeNetHost) PostureStore() *BridgeNetPostureStore {
	return self.app.store
}

func (self *BridgeNetHost) PostureFloor() *BridgeNetPostureFloor {
	return self.app.floor
}

// A team hint for api's tip, as F's long-poll brings one: the Forwarder follows past what it holds.
func (self *BridgeNetHost) Hint() {
	if forwarder := self.Forwarder(); forwarder != nil {
		forwarder.ReceiveHint(self.bridgeNet.admission.Tip().GetVersion())
	}
}

// Stops the app host's Forwarder and starts another over restart's changes, the device role, its NAT and its flows
// standing: the component's process restarting with the app's sidecar stopped. Fails the test on an error.
func (self *BridgeNetHost) RestartForwarder(restart *BridgeNetForwarderRestart) {
	t := self.bridgeNet.t
	t.Helper()
	self.app.stateLock.Lock()
	forwarder := self.app.forwarder
	self.app.forwarder = nil
	self.app.stateLock.Unlock()
	if forwarder != nil {
		forwarder.Close()
	}
	if err := self.startForwarder(restart); err != nil {
		t.Fatalf("%s's restarted Forwarder: %v", self.Device.Name, err)
	}
}

// Holds the next compile at its admission, once it has captured the newest stored entry, until ReleaseCompiles.
func (self *BridgeNetHost) HoldCompiles() {
	self.app.gate.hold()
}

// Lets a held compile go on, and every later one.
func (self *BridgeNetHost) ReleaseCompiles() {
	self.app.gate.open()
}

// Waits until count compiles have reached the gate since the host started, failing the test past WaitTimeout.
func (self *BridgeNetHost) WaitCompileArrivals(count int) {
	t := self.bridgeNet.t
	t.Helper()
	deadline := time.After(self.bridgeNet.settings.WaitTimeout)
	for {
		arrived, changed := self.app.gate.arrivals.Get()
		if count <= arrived {
			return
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("%s: %d compiles reached the gate, not %d", self.Device.Name, arrived, count)
			return
		}
	}
}

// How many compiles have reached the gate since the host started.
func (self *BridgeNetHost) CompileArrivals() int {
	arrived, _ := self.app.gate.arrivals.Get()
	return arrived
}

// The heap the Forwarder reads at each compile's admission, which a schedule raises past the settings' ceiling to
// defer every compile, as sustained provider load does.
func (self *BridgeNetHost) SetHeapInUse(byteCount int64) {
	self.app.gate.heapInUse.Store(byteCount)
}

// Every alarm the Forwarder raised, oldest first.
func (self *BridgeNetHost) ForwarderAlarms() []BridgeNetForwarderAlarm {
	self.app.stateLock.Lock()
	defer self.app.stateLock.Unlock()
	return slices.Clone(self.app.alarms)
}

// Waits until the Forwarder has raised count alarms of reason since the host started, and answers them, failing the
// test past WaitTimeout.
func (self *BridgeNetHost) WaitForwarderAlarms(reason string, count int) []BridgeNetForwarderAlarm {
	t := self.bridgeNet.t
	t.Helper()
	deadline := time.After(self.bridgeNet.settings.WaitTimeout)
	for {
		_, changed := self.app.alarmCount.Get()
		matched := []BridgeNetForwarderAlarm{}
		for _, alarm := range self.ForwarderAlarms() {
			if alarm.Reason == reason {
				matched = append(matched, alarm)
			}
		}
		if count <= len(matched) {
			return matched
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("%s raised %d %s alarms, not %d: %+v", self.Device.Name, len(matched), reason, count, self.ForwarderAlarms())
			return nil
		}
	}
}

// Waits until the role's posture holds what done says, failing nothing: false past WaitTimeout.
func (self *BridgeNetHost) waitPosture(done func(decision device.PostureDecision) bool) bool {
	deadline := time.After(self.bridgeNet.settings.WaitTimeout)
	for {
		_, changed := self.adoptedPin.Get()
		if done(self.Bridge.Decision()) {
			return true
		}
		select {
		case <-changed:
		case <-time.After(self.bridgeNet.settings.PollInterval):
			// a publish that moves no pin, the anchor's among them, moves no monitor
		case <-deadline:
			return false
		case <-self.ctx.Done():
			return false
		}
	}
}

// Hints the Forwarder of api's tip, then waits until the role enforces a state at n or past it: false past
// WaitTimeout.
func (self *BridgeNetHost) WaitStatePin(n uint64) bool {
	self.Hint()
	return self.waitPosture(func(decision device.PostureDecision) bool {
		return decision.State.Enforcing() && n <= decision.BridgeState.GetAuth().GetVersion()
	})
}

// Hints the Forwarder of api's tip, then waits until the posture has applied every entry through n, compiled or
// not, failing the test past WaitTimeout: for an entry the posture applies with no compile, a denial it can check.
func (self *BridgeNetHost) WaitApplied(n uint64) {
	t := self.bridgeNet.t
	t.Helper()
	self.Hint()
	if !self.waitPosture(func(decision device.PostureDecision) bool { return n <= decision.Pin.GetVersion() }) {
		t.Fatalf("%s's posture stands at %d, not %d: %+v", self.Device.Name, self.Bridge.Decision().Pin.GetVersion(), n, self.Forwarder().Status())
	}
}

// WaitAdopted for an app host: hints the Forwarder, then waits until bridgeNetAppAdopted holds.
func (self *BridgeNetHost) waitAppAdopted(n uint64) {
	t := self.bridgeNet.t
	t.Helper()
	self.Hint()
	deadline := time.After(self.bridgeNet.settings.WaitTimeout)
	for {
		_, changed := self.adoptedPin.Get()
		status := self.Forwarder().Status()
		decision := self.Bridge.Decision()
		wantedThrough := self.app.sink.compileWantedThrough()
		if bridgeNetAppAdopted(n, status, decision, wantedThrough, self.bridgeNet.waitsForWhatIsServed(status.Waits)) {
			return
		}
		select {
		case <-changed:
		case <-time.After(self.bridgeNet.settings.PollInterval):
			// a compile's waits and the store's tip move no monitor of the role's
		case <-deadline:
			t.Fatalf("%s did not adopt %d: posture %s at %d, state at %d, wanted through %d; forwarder %+v", self.Device.Name, n,
				decision.State, decision.Pin.GetVersion(), decision.BridgeState.GetAuth().GetVersion(), wantedThrough, status)
		}
	}
}

// Whether an app host has adopted n: its Forwarder has stored the log through n, the posture enforces a state at or
// past every entry it wanted a compile for with every entry through n applied, and the newest compile waited for
// nothing the world serves (waitsServed false). wantedThrough is the sink's record, read after decision: the posture
// shows its new pin, and whether that call wanted a compile, before ApplyDeltas returns and the sink records it, so
// the decision's own CompileWanted counts through its pin too, or a read between the two would take the state before
// the compile for what was just applied (FS-38's app host rows found states lacking a forwarding Delegation just
// filed so).
func bridgeNetAppAdopted(n uint64, status sidecar.ForwarderStatus, decision device.PostureDecision, wantedThrough uint64, waitsServed bool) bool {
	statePin := decision.BridgeState.GetAuth().GetVersion()
	if decision.CompileWanted {
		wantedThrough = max(wantedThrough, decision.Pin.GetVersion())
	}
	return n <= status.Tip.GetVersion() && decision.State.Enforcing() && !decision.Fork && n <= decision.Pin.GetVersion() &&
		wantedThrough <= statePin && 0 < statePin && !waitsServed && status.CompiledPin.GetVersion() == statePin
}

// Ends an app host's Forwarder, provider and NAT, before BridgeNetHost.Close ends the rest.
func (self *bridgeNetAppHost) close() {
	self.gate.open()
	self.stateLock.Lock()
	forwarder := self.forwarder
	self.forwarder = nil
	self.stateLock.Unlock()
	if forwarder != nil {
		forwarder.Close()
	}
	if self.provider != nil {
		self.provider.Close()
	}
	if self.nat != nil {
		self.nat.Close()
	}
}

// A projection that serves api's log no further than a position the schedule sets, as a lagging or withholding api
// does: entries past it are withheld, and nothing it serves is forged. Safe for concurrent use.
type BridgeNetLaggingProjection struct {
	api     sidecar.ConfigProjectionReader
	through atomic.Uint64
}

// A lagging projection over api, serving through n.
func NewBridgeNetLaggingProjection(api sidecar.ConfigProjectionReader, n uint64) *BridgeNetLaggingProjection {
	self := &BridgeNetLaggingProjection{api: api}
	self.through.Store(n)
	return self
}

// Serves through n from here on.
func (self *BridgeNetLaggingProjection) SetThrough(n uint64) {
	self.through.Store(n)
}

func (self *BridgeNetLaggingProjection) ReadConfigProjection(ctx context.Context, after uint64) (*sidecar.ConfigProjection, error) {
	projection, err := self.api.ReadConfigProjection(ctx, after)
	if err != nil || projection == nil {
		return projection, err
	}
	through := self.through.Load()
	kept := [][]byte{}
	var tip *bridge.AuthPin
	for _, entryBytes := range projection.Entries {
		entry := &bridge.AuthEntry{}
		if proto.Unmarshal(entryBytes, entry) != nil || through < entry.GetN() {
			break
		}
		chain, err := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
		if err != nil {
			break
		}
		kept = append(kept, entryBytes)
		tip = &bridge.AuthPin{Version: entry.GetN(), Chain: chain[:]}
	}
	if len(kept) < len(projection.Entries) {
		withheld := *projection
		withheld.Entries = kept
		withheld.More = false
		if tip != nil {
			withheld.Tip = tip
		}
		return &withheld, nil
	}
	return projection, nil
}
