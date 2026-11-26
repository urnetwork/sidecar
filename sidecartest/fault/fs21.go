// FS-21 (§22.8; §2, §6; D-PROTO-18, D-TRUST-10, I-10; FI-10), its M4-out case: a personal network whose document
// gives its writer's peers no reach to each other, every device a dispatcher whose client runs on server's exchange
// under server's own contract gate (ACL-M4-01), installed over the gate cache's state of the network's log on server's
// sequencer, and every receiver PROTO-M4-03's. On T3 alone (catalog.yml): the row's point is the server's issuing, so
// the T3 Net's AclExchangeTier (server/sidecart3) opens the clients, and a Net with none, T2's, refuses the row.
//
// The world: the owner member, its laptop the admission world's writer, and four of its devices, w, x, r and d, each
// a client server minted as a sidecar's (strict_exp, admin_refused, declaring no egress, bound to its sidecar_id),
// admitted by the laptop, Hello reading the device's own follower of the log, its HeadCheck comparing that follower's
// auth pin, its own state's standing of each peer, and no shared group, as a personal network has none. Steps:
//
//   - the document {"grants": []}: no reach between any two devices. The gate gives every pair of w, x and r the
//     witness exception's control contract, every HeadCheck between them passes and counts, and each receiver saw
//     the peer's frames sealed control and sourced from the network;
//   - on those contracts a data RPC is refused PERMISSION_DENIED with its handler never run, a StreamOpen is
//     rejected DENIED with no accept run, and an IP packet w sends x reaches x's EgressHook (BRIDGE's
//     BridgeEgressPolicy) sealed control, which denies it, so x's NAT dials nothing;
//   - the server partitions its relays, r off the exchange: w and x still witness each other, the HeadCheck path
//     the server leaves, while r's exchange goes unanswered; 24 h on r alarms unwitnessed, and w and x, witnessed
//     since, raise nothing; past witness_bound_hours r still seals, since a personal network's groups are its own
//     (D-TRUST-10's own-group rule). Relayed, r witnesses again;
//   - a second document lets w dial d: w's first contract to d is data, so the same RPC is answered, the same open
//     accepted and w's packet reaches d's hook sealed data, while w to x stays control and refused.
//
// Its M6-out case, a Team's default document, is the same schedule on another cast and other documents (fs21Scenario;
// Fs21Team in fs_acl_m6.go).
//
// FI-10 reads every device after every step (AddHeadCheckDispatchers). Time: the devices' dispatchers, stops and
// followers run on the Net's fake clock, which only a step moves; server's exchange, controller and gate keep real
// time, and every real wait here is bounded by Fs21Settings.WaitTimeout, a failure's bound only.

package fault

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"
	"weak"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs21Case = Register("FS-21", "", []Tier{TierT3}, Fs21)

// What a T3 Net gives a row whose sidecars run on server's exchange under §8.10's contract gate (FS-21). server's
// sidecart3 names one for every T3 Net (SetAclExchangeTier); a Net with none refuses such a row.
type AclExchangeTier struct {
	// Opens a sidecar's client on server's exchange in networkId, minted as a sidecar's enrollment mints one
	// (strict_exp, admin_refused, declaring no egress, the network in sidecar.yml's preview_networks) and bound as POST
	// /sidecar/bind binds it, with the marshalled SignedSidecarIdentityBinding bind makes once the client's id is
	// known. The network is made and funded at its first client. Answers once server holds the client's key.
	OpenSidecarClient func(ctx context.Context, networkId sidecar.Id, name string, settings *connect.ClientSettings, bind func(clientId sidecar.Id) ([]byte, error)) (*sidecartest.NetPlatformClient, error)
	// Raises networkId's network_acl_head to pin, as api's sequencer does once it appends an entry.
	AdvanceHead func(ctx context.Context, networkId sidecar.Id, pin *bridge.AuthPin, hasDocument bool) error
	// Installs a contract gate over states in server's controller, its heads read from network_acl_head, and turns
	// sidecar.yml's acl_contract_gate switch on, answering once the gate's first heads load has read. restore undoes
	// both; the tier undoes them too when the Net closes.
	InstallGate func(ctx context.Context, states sidecar.AclContractStateSource) (restore func(), err error)
	// Has server's exchange relay nothing to or from clientId, as a server partitioning its relays does, or, with
	// partitioned false, relay it again, answering once it is back.
	Partition func(ctx context.Context, clientId connect.Id, partitioned bool) error
}

var aclExchangeTiers sync.Map

// Names the tier net's FS-21 world runs on. server's T3 calls this as each Net is made, so every Net of a row's rules
// gets it; a Net with none named refuses the row.
func SetAclExchangeTier(net *Net, tier *AclExchangeTier) {
	key := weak.Make(net)
	if _, loaded := aclExchangeTiers.LoadOrStore(key, tier); !loaded {
		// removed when the Net closes, not when it is collected
		context.AfterFunc(net.Context(), func() { aclExchangeTiers.Delete(key) })
		return
	}
	aclExchangeTiers.Store(key, tier)
}

// The tier named for net, or nil.
func aclExchangeTierOf(net *Net) *AclExchangeTier {
	if tier, ok := aclExchangeTiers.Load(weak.Make(net)); ok {
		return tier.(*AclExchangeTier)
	}
	return nil
}

// What FS-21's world runs with.
type Fs21Settings struct {
	// The dispatchers' §6 bounds: the defaults, HeadCheckTimeout among them, on the Net's clock.
	Protocol *sidecar.SidecarProtocolSettings
	// The process's share of §5's budget each dispatcher takes.
	BudgetByteCount int64
	// How long, in real time, a wait on server's exchange, controller, gate or stores may take before it fails: a
	// failure's bound only, since every step's outcome comes from what the server did. Within the Net's
	// BarrierDriverSettings.AwaitTimeout, so a wait that fails names itself before the run's own bound does.
	WaitTimeout time.Duration
	// The data RPC type a step calls and the stream target it opens: a type of §6.11's unreleased experimental
	// services, which no release assigns, and a target no listener of a release holds.
	DataType     protocol.MessageType
	StreamTarget string
	// The packet w sends: a TCP SYN from an overlay address to a LAN one, the destination I-10 holds shut by default.
	PacketFrom netip.AddrPort
	PacketTo   netip.AddrPort
	// How long a packet's send may wait for its route, in real time: within WaitTimeout.
	PacketSendTimeout time.Duration
}

func DefaultFs21Settings() *Fs21Settings {
	return &Fs21Settings{
		Protocol:          sidecar.DefaultSidecarProtocolSettings(),
		BudgetByteCount:   64 * 1024 * 1024,
		WaitTimeout:       8 * time.Second,
		DataType:          protocol.MessageType(0x8021),
		StreamTarget:      "fs21:echo",
		PacketFrom:        netip.MustParseAddrPort("10.217.0.2:40021"),
		PacketTo:          netip.MustParseAddrPort("192.168.77.20:80"),
		PacketSendTimeout: 4 * time.Second,
	}
}

// The devices: w, x and r, which the first document gives no reach to each other, and d, which the second lets w
// dial.
var fs21Names = []string{"w", "x", "r", "d"}

// The documents: none of the owner's devices reaches another, then w dials d.
const fs21NoReachPolicy = `{"grants": []}`

func fs21DialPolicy(source sidecar.Id, destination sidecar.Id) string {
	return fmt.Sprintf(`{"grants": [{"src": ["sidecar:%s"], "dst": ["sidecar:%s"], "allow": ["dial"]}]}`, source, destination)
}

// One device of the world: its identity, its client on server's exchange, its dispatcher and what it records.
type fs21Device struct {
	name     string
	identity *sidecartest.AdmissionDevice
	client   *sidecartest.NetPlatformClient
	binding  []byte
	follower *sidecar.ConfigClient
	dispatch *sidecar.Subprotocol
	removes  []func()
	classes  *fs21Classes
	egress   *fs21Egress
	// its IP provider, whose NAT's hook is egress
	provider    *connect.RemoteUserNatProvider
	providerNat *connect.LocalUserNat
	// how often its data RPC handler and its accept ran
	handled  atomic.Int64
	accepted atomic.Int64
}

// What a case of FS-21 changes in its world: the personal network's of M4-out here (fs21Personal), a Team's default
// document's of M6-out in fs_acl_m6.go.
type fs21Scenario struct {
	// the schedule's id
	id string
	// the member a device is admitted under, and the capabilities its admission by the owner's laptop carries
	member       func(admission *sidecartest.AdmissionNet, name string) sidecar.Id
	capabilities uint32
	// runs once every device is admitted, before the first document; nil for nothing
	cast func(admission *sidecartest.AdmissionNet, world *fs21World) error
	// the first document, which gives w, x and r no reach to each other, and the second, which lets w dial d
	policy     func() []byte
	dialPolicy func(source sidecar.Id, destination sidecar.Id) []byte
	// a group holding another member's devices, in which a device unwitnessed past witness_bound_hours stops sealing
	// (D-TRUST-10); the zero id for a network whose groups are all its one member's own
	sharedGroupId sidecar.Id
}

// The M4-out case: every device the owner member's own, the document one of no grants, and no shared group.
func fs21Personal() *fs21Scenario {
	return &fs21Scenario{
		id: "FS-21",
		member: func(admission *sidecartest.AdmissionNet, name string) sidecar.Id {
			return admission.Owner().MemberId
		},
		policy: func() []byte {
			return []byte(fs21NoReachPolicy)
		},
		dialPolicy: func(source sidecar.Id, destination sidecar.Id) []byte {
			return []byte(fs21DialPolicy(source, destination))
		},
	}
}

// What FS-21's steps share.
type fs21World struct {
	*fsTeamWorld
	settings *Fs21Settings
	scenario *fs21Scenario
	tier     *AclExchangeTier
	devices  map[string]*fs21Device
	// on the Net's context, closed at the last step, which waits for its loaders
	cache       *sidecar.AclGateCache
	loads       chan *bridge.AuthPin
	restoreGate func()
	headCheck   *sidecartest.HeadCheckNet
	// w's IP client, made at the first packet
	natClients map[string]*connect.RemoteUserNatClient
	// r's last consistent witness before the partition
	rWitnessedAt time.Time
}

// The classes of the subprotocol frames a device received, by source client: what each frame's contract sealed.
type fs21Classes struct {
	stateLock sync.Mutex
	counts    map[connect.Id]map[connectprotocol.ContractClass]int
	// the source networks the seals named
	networks map[connect.Id]map[connect.Id]bool
}

func newFs21Classes() *fs21Classes {
	return &fs21Classes{counts: map[connect.Id]map[connectprotocol.ContractClass]int{}, networks: map[connect.Id]map[connect.Id]bool{}}
}

// A raw subprotocol listener: counts the frame's class by its source. Inline on the receive goroutine, never blocking.
func (self *fs21Classes) record(source connect.TransferPath, subprotocolId connect.SubprotocolId, messageBytes []byte, peer connect.Peer) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	counts := self.counts[source.SourceId]
	if counts == nil {
		counts = map[connectprotocol.ContractClass]int{}
		self.counts[source.SourceId] = counts
	}
	counts[peer.ContractClass] += 1
	networks := self.networks[source.SourceId]
	if networks == nil {
		networks = map[connect.Id]bool{}
		self.networks[source.SourceId] = networks
	}
	networks[peer.SourceNetwork] = true
}

// Fails unless every frame from source so far was sealed class, at least one was, and each seal named networkId.
func (self *fs21Classes) expectOnly(source connect.Id, class connectprotocol.ContractClass, networkId sidecar.Id) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	counts := self.counts[source]
	if counts[class] == 0 {
		return fmt.Errorf("no frame from %s sealed %s: %v", source, class, counts)
	}
	for seen, count := range counts {
		if seen != class {
			return fmt.Errorf("%d frames from %s sealed %s, not %s", count, source, seen, class)
		}
	}
	for network := range self.networks[source] {
		if network != connect.Id(networkId) {
			return fmt.Errorf("a frame from %s sealed source network %s, not %s", source, network, networkId)
		}
	}
	return nil
}

// One flow a provider's hook decided.
type fs21Flow struct {
	flow     connect.EgressFlow
	decision connect.EgressDecision
}

// A provider's EgressHook: BRIDGE's policy, every flow and decision it made recorded. The policy never passes here, so
// the NAT dials nothing; one that did would be refused by this hook as well, and fail the step that reads it.
type fs21Egress struct {
	policy *device.BridgeEgressPolicy

	stateLock sync.Mutex
	flows     []*fs21Flow
	recorded  *sidecar.MonitorValue[int]
}

var _ connect.EgressHook = (*fs21Egress)(nil)

func newFs21Egress() *fs21Egress {
	return &fs21Egress{
		policy:   device.NewBridgeEgressPolicy(device.BridgePolicyProfileHost, nil),
		recorded: sidecar.NewMonitorValue(0),
	}
}

func (self *fs21Egress) VerifyPrincipal(source connect.TransferPath, peer connect.Peer) *connect.BridgePrincipal {
	return self.policy.VerifyPrincipal(source, peer)
}

func (self *fs21Egress) ResolveEgress(flow *connect.EgressFlow) connect.EgressDecision {
	decision := self.policy.ResolveEgress(flow)
	passed := decision.Verdict != connect.EgressVerdictDeny
	if passed {
		// nothing here may dial a LAN address from the test host
		decision = connect.EgressDecision{Verdict: connect.EgressVerdictDeny, PolicyGeneration: decision.PolicyGeneration}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		recorded := &fs21Flow{decision: decision}
		if flow != nil {
			recorded.flow = *flow
		}
		if passed {
			// marked so the step that reads it fails: the policy passed what this row says it never passes
			recorded.decision.Verdict = connect.EgressVerdictPass
		}
		self.flows = append(self.flows, recorded)
	}()
	self.recorded.Update(func(count int) int { return count + 1 })
	return decision
}

func (self *fs21Egress) PolicyGeneration() uint64 {
	return self.policy.PolicyGeneration()
}

func (self *fs21Egress) FriendsAndFamilyEgress() bool {
	return self.policy.FriendsAndFamilyEgress()
}

// Waits until a flow from source to the packet's destination is recorded, or ctx ends, and answers it.
func (self *fs21Egress) await(ctx context.Context, source connect.Id, to netip.AddrPort) (*fs21Flow, error) {
	for {
		_, changed := self.recorded.Get()
		found := func() *fs21Flow {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			for _, recorded := range self.flows {
				if recorded.flow.Source.SourceId == source && recorded.flow.To == to {
					return recorded
				}
			}
			return nil
		}()
		if found != nil {
			return found, nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, fmt.Errorf("no flow from %s to %s reached the hook: %w", source, to, ctx.Err())
		}
	}
}

// Hello's admission check over a device's own follower: its state of the log, and whether it is admitted there.
type fs21Admissions struct {
	authority *sidecar.ConfigAuthority
	sidecarId sidecar.Id
}

func (self *fs21Admissions) Authority() sidecar.SidecarAuthority {
	return self.authority
}

func (self *fs21Admissions) Admitted() bool {
	admission := self.authority.Admission(self.sidecarId)
	return admission != nil && admission.Row.GetRevokedAt() == 0
}

// HeadCheck's peer state over a device's own follower: how its newest verified state holds each sidecar (§6.4's
// witness rows), the standing rules ConfigState's own.
type fs21Peers struct {
	follower *sidecar.ConfigClient
}

func (self *fs21Peers) HeadCheckPeer(sidecarId sidecar.Id) sidecar.HeadCheckPeer {
	state := self.follower.State()
	if state == nil {
		return sidecar.HeadCheckPeer{}
	}
	admission := state.Sidecar(sidecarId)
	if admission == nil {
		return sidecar.HeadCheckPeer{}
	}
	return sidecar.HeadCheckPeer{
		Admitted:  true,
		Revoked:   admission.Row.GetRevokedAt() != 0,
		Parked:    state.Parked(sidecarId),
		Suspended: state.Suspended(sidecarId),
	}
}

// A client's settings for a sidecar's dispatcher: connect's defaults made Required by ApplySidecarClientSettings, the
// identity binding's ClientKey from clientKeySeed.
func fs21ClientSettings(clientKeySeed []byte) *connect.ClientSettings {
	settings := connect.DefaultClientSettings()
	settings.ContractManagerSettings.LegacyCreateContract = false
	sidecar.ApplySidecarClientSettings(settings)
	settings.ClientKeySeed = slices.Clone(clientKeySeed)
	return settings
}

// A TCP SYN from from to to, with no options, its checksums set.
func fs21SynPacket(from netip.AddrPort, to netip.AddrPort) []byte {
	const ipHeaderByteCount = 20
	const tcpHeaderByteCount = 20
	packet := make([]byte, ipHeaderByteCount+tcpHeaderByteCount)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	// don't fragment
	packet[6] = 0x40
	packet[8] = 64
	packet[9] = 6
	source, destination := from.Addr().As4(), to.Addr().As4()
	copy(packet[12:16], source[:])
	copy(packet[16:20], destination[:])
	binary.BigEndian.PutUint16(packet[10:12], fs21Checksum(0, packet[:ipHeaderByteCount]))
	tcp := packet[ipHeaderByteCount:]
	binary.BigEndian.PutUint16(tcp[0:2], from.Port())
	binary.BigEndian.PutUint16(tcp[2:4], to.Port())
	binary.BigEndian.PutUint32(tcp[4:8], 1)
	tcp[12] = tcpHeaderByteCount / 4 << 4
	// syn
	tcp[13] = 0x02
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], source[:])
	copy(pseudo[4:8], destination[:])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], tcpHeaderByteCount)
	sum := fs21ChecksumAdd(0, pseudo)
	binary.BigEndian.PutUint16(tcp[16:18], fs21Checksum(sum, tcp))
	return packet
}

// RFC 1071's sum of data onto sum, unfolded.
func fs21ChecksumAdd(sum uint32, data []byte) uint32 {
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	return sum
}

// RFC 1071's checksum of data, with sum carried in.
func fs21Checksum(sum uint32, data []byte) uint16 {
	sum = fs21ChecksumAdd(sum, data)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// A step of FS-21's world, its failures the step's.
func fs21Do(actor string, world *fs21World, body func(ctx context.Context, net *Net, admission *sidecartest.AdmissionNet) error) *Step {
	return &Step{Actor: actor, Action: func(ctx context.Context, net *Net) error {
		return fsTeamCatch(func() error {
			return body(ctx, net, world.net)
		})
	}}
}

// Runs wait with the actor's baton given up, since it waits on server's real I/O, bounded by the world's WaitTimeout.
func (self *fs21World) blocking(ctx context.Context, net *Net, wait func(ctx context.Context) error) error {
	waitCtx, cancel := context.WithTimeout(ctx, self.settings.WaitTimeout)
	defer cancel()
	var err error
	net.Barriers().Blocking(func() {
		err = wait(waitCtx)
	})
	return err
}

// The device of a name.
func (self *fs21World) device(name string) *fs21Device {
	return self.devices[name]
}

// The first step: the T3 tier, the admission world with ACL's own compile, each device's client opened on server's
// exchange and admitted by the owner's laptop, and the document that gives no device reach to another.
func fs21Setup(world *fs21World) *Step {
	return &Step{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
		world.tier = aclExchangeTierOf(net)
		if world.tier == nil {
			return errors.New("FS-21 runs on server's exchange under its contract gate, and this Net names no AclExchangeTier: T3 alone")
		}
		return aclSetup(world.fsTeamWorld, func(admission *sidecartest.AdmissionNet) error {
			networkId := admission.NetworkId()
			owner := admission.Owner()
			for _, name := range fs21Names {
				identity := admission.Device("fs21 "+name, world.scenario.member(admission, name))
				clientKey := admission.Device("fs21 client key "+name, sidecar.Id{}).Key
				device := &fs21Device{name: name, identity: identity, classes: newFs21Classes(), egress: newFs21Egress()}
				bind := func(clientId sidecar.Id) ([]byte, error) {
					binding, err := sidecar.NewSidecarIdentityBinding(&sidecar.SidecarIdentityBinding{
						NetworkId:  networkId,
						SidecarId:  identity.SidecarId,
						ClientId:   clientId,
						Generation: 1,
						IssuedAt:   admission.Clock().Now(),
					}, identity.Key.Seed(), clientKey.Seed())
					if err != nil {
						return nil, err
					}
					device.binding = binding
					return binding, nil
				}
				err := world.blocking(ctx, net, func(ctx context.Context) error {
					client, err := world.tier.OpenSidecarClient(ctx, networkId, name, fs21ClientSettings(clientKey.Seed()), bind)
					device.client = client
					return err
				})
				if err != nil {
					return fmt.Errorf("%s's client on server's exchange: %w", name, err)
				}
				if len(device.binding) == 0 {
					return fmt.Errorf("%s's client was opened with no binding", name)
				}
				world.devices[name] = device
				admission.AdmitDevice(owner, identity, world.scenario.capabilities)
			}
			if world.scenario.cast != nil {
				if err := world.scenario.cast(admission, world); err != nil {
					return err
				}
			}
			plan, _ := admission.SaveAclPolicy(world.scenario.policy(), nil)
			if !plan.Rows.GetHasDocument() {
				return errors.New("the saved head has no document")
			}
			return nil
		}).Action(ctx, net)
	}}
}

// The second step: the head row at the tip, the gate cache over the network's projection on the Net's stores, and
// server's contract gate over it, the cache loaded at the tip.
func fs21Gate(world *fs21World) *Step {
	return fs21Do("server", world, func(ctx context.Context, net *Net, admission *sidecartest.AdmissionNet) error {
		settings := sidecar.DefaultAclGateSettings()
		settings.Log = sidecar.NewNoopLogger()
		settings.PollInterval = 0
		settings.FailureBackoff = 0
		world.loads = make(chan *bridge.AuthPin, 1024)
		settings.OnLoad = func(networkId sidecar.Id, pin *bridge.AuthPin, err error) {
			if networkId != admission.NetworkId() || err != nil || pin == nil {
				return
			}
			select {
			case world.loads <- pin:
			default:
			}
		}
		world.cache = sidecar.NewAclGateCache(net.Context(), sidecar.NewAclGateDirectSource(net.Host().Redis, net.Host().Blobs, settings), net.Clock(), settings)
		if err := fs21Head(ctx, net, world, admission); err != nil {
			return err
		}
		return world.blocking(ctx, net, func(ctx context.Context) error {
			restore, err := world.tier.InstallGate(ctx, world.cache)
			if err != nil {
				return err
			}
			world.restoreGate = restore
			return nil
		})
	})
}

// Raises the head row to the tip and waits until the gate cache holds the tip: what api and the cache's {acl_}v
// subscriber do after an append, here at the step's own call.
func fs21Head(ctx context.Context, net *Net, world *fs21World, admission *sidecartest.AdmissionNet) error {
	tip := admission.Tip()
	return world.blocking(ctx, net, func(ctx context.Context) error {
		if err := world.tier.AdvanceHead(ctx, admission.NetworkId(), tip, true); err != nil {
			return err
		}
		world.cache.Changed(admission.NetworkId())
		for {
			select {
			case pin := <-world.loads:
				if tip.GetVersion() <= pin.GetVersion() {
					return nil
				}
			case <-ctx.Done():
				return fmt.Errorf("the gate cache did not load the tip %d: %w", tip.GetVersion(), ctx.Err())
			}
		}
	})
}

// The third step: each device's follower at the tip, its dispatcher over its client with Hello reading the follower's
// state, a raw listener of the classes, a data handler, a listen and an IP provider whose hook records, and HeadCheck
// attached to every one with no shared group.
func fs21Online(world *fs21World) *Step {
	return fs21Do("setup", world, func(ctx context.Context, net *Net, admission *sidecartest.AdmissionNet) error {
		networkId := admission.NetworkId()
		dispatchers := []*sidecartest.HeadCheckDispatcher{}
		for _, name := range fs21Names {
			device := world.device(name)
			device.follower = admission.Follower()
			dispatch, err := sidecar.NewSubprotocol(net.Context(), &sidecar.SubprotocolEnv{
				Client:    device.client.Client,
				Store:     sidecartest.NewFakeStore().Root(),
				Log:       sidecar.NewNoopLogger(),
				Settings:  world.settings.Protocol,
				Budget:    sidecar.NewSubprotocolBudget(world.settings.Protocol, world.settings.BudgetByteCount),
				Clock:     net.Clock(),
				Inbound:   sidecar.SubprotocolInboundWithoutPolicy,
				NetworkId: networkId,
				Binding:   device.binding,
				Admissions: &fs21Admissions{
					authority: device.follower.Authority(),
					sidecarId: device.identity.SidecarId,
				},
			})
			if err != nil {
				return fmt.Errorf("%s's dispatcher: %w", name, err)
			}
			device.dispatch = dispatch
			removeRaw, err := device.client.Client.AddSubprotocolRawCallback(connect.SubprotocolId(sidecar.SubprotocolId), device.classes.record)
			if err != nil {
				return err
			}
			removeHandle, err := dispatch.Handle(world.settings.DataType, func(ctx context.Context, request *sidecar.SubprotocolRequest) ([]byte, error) {
				device.handled.Add(1)
				return []byte("answered"), nil
			}, nil)
			if err != nil {
				return err
			}
			removeListen, err := dispatch.Listen(world.settings.StreamTarget, func(ctx context.Context, incoming *sidecar.StreamIncoming) error {
				device.accepted.Add(1)
				return nil
			})
			if err != nil {
				return err
			}
			device.removes = append(device.removes, removeRaw, removeHandle, removeListen)
			natSettings := connect.DefaultLocalUserNatSettings()
			natSettings.EgressHook = device.egress
			device.providerNat = connect.NewLocalUserNat(net.Context(), "fs21 provider "+name, natSettings)
			device.provider = connect.NewRemoteUserNatProvider(device.client.Client, device.providerNat, connect.DefaultRemoteUserNatProviderSettings())
			if device.provider == nil {
				return fmt.Errorf("%s's IP provider did not start", name)
			}
			dispatchers = append(dispatchers, &sidecartest.HeadCheckDispatcher{
				Name:        name,
				SidecarId:   device.identity.SidecarId,
				ClientId:    device.client.ClientId,
				Subprotocol: dispatch,
				Binding:     device.binding,
				Auth:        device.follower,
				Peers:       &fs21Peers{follower: device.follower},
			})
		}
		sharedGroupId := world.scenario.sharedGroupId
		headCheck, err := net.AddHeadCheckDispatchers(networkId, func(groupId sidecar.Id) bool {
			return sharedGroupId != (sidecar.Id{}) && groupId == sharedGroupId
		}, dispatchers...)
		if err != nil {
			return err
		}
		world.headCheck = headCheck
		return nil
	})
}

// One HeadCheck exchange from one device to another, bounded by WaitTimeout: whether it counted as a witness.
func (self *fs21World) exchange(ctx context.Context, net *Net, from string, to string) (bool, error) {
	var counted bool
	err := self.blocking(ctx, net, func(ctx context.Context) error {
		var err error
		counted, err = self.headCheck.Sidecar(from).HeadCheckWith(ctx, self.headCheck.Sidecar(to))
		return err
	})
	return counted, fs21Detail(err)
}

// err with a SubprotocolError's message, which its own text leaves out.
func fs21Detail(err error) error {
	subprotocolError := &sidecar.SubprotocolError{}
	if errors.As(err, &subprotocolError) && subprotocolError.Message != "" {
		return fmt.Errorf("%w: %s", err, subprotocolError.Message)
	}
	return err
}

// A step: every ordered pair of names exchanges once, each counting the other as a consistent witness.
func fs21Witness(actor string, world *fs21World, names ...string) *Step {
	return fs21Do(actor, world, func(ctx context.Context, net *Net, admission *sidecartest.AdmissionNet) error {
		for _, from := range names {
			for _, to := range names {
				if from == to {
					continue
				}
				counted, err := world.exchange(ctx, net, from, to)
				if err != nil || !counted {
					return fmt.Errorf("%s's exchange with %s counted %t: %v", from, to, counted, err)
				}
			}
		}
		return nil
	})
}

// The fourth step: every exchange among w, x and r rode control contracts, sealed so by server's gate and sourced from
// the network, the only class the document leaves a pair of them (the witness exception).
func fs21ControlSeen(world *fs21World) *Step {
	return fs21Do("w", world, func(ctx context.Context, net *Net, admission *sidecartest.AdmissionNet) error {
		names := []string{"w", "x", "r"}
		for _, to := range names {
			for _, from := range names {
				if from == to {
					continue
				}
				if err := world.device(to).classes.expectOnly(world.device(from).client.ClientId, connectprotocol.ContractClass_ContractClassControl, admission.NetworkId()); err != nil {
					return fmt.Errorf("at %s: %w", to, err)
				}
			}
		}
		return nil
	})
}

// Fails unless from's data RPC to to is answered: or, with refused, refused PERMISSION_DENIED at the receiver, whose
// handler never runs.
func (self *fs21World) expectCall(ctx context.Context, net *Net, from string, to string, refused bool) error {
	target := self.device(to)
	handledBefore := target.handled.Load()
	var body []byte
	err := self.blocking(ctx, net, func(ctx context.Context) error {
		var err error
		body, err = self.device(from).dispatch.Call(ctx, sidecar.Id(target.client.ClientId), self.settings.DataType, []byte("ask"), nil)
		return err
	})
	if refused {
		if code, _ := sidecar.SubprotocolErrorCode(err); code != protocol.ErrorCode_ERR_PERMISSION_DENIED {
			return fmt.Errorf("%s's data RPC to %s: %q, %v, want PERMISSION_DENIED", from, to, body, err)
		}
		if handled := target.handled.Load() - handledBefore; handled != 0 {
			return fmt.Errorf("%s's handler ran %d times for a data RPC on a control contract", to, handled)
		}
		return nil
	}
	if err != nil || string(body) != "answered" {
		return fmt.Errorf("%s's data RPC to %s: %q, %v", from, to, body, err)
	}
	if handled := target.handled.Load() - handledBefore; handled != 1 {
		return fmt.Errorf("%s's handler ran %d times for one data RPC", to, handled)
	}
	return nil
}

// Fails unless from's stream open to to is accepted: or, with refused, rejected DENIED with no accept run.
func (self *fs21World) expectStream(ctx context.Context, net *Net, from string, to string, refused bool) error {
	target := self.device(to)
	acceptedBefore := target.accepted.Load()
	var stream *sidecar.SubprotocolStream
	err := self.blocking(ctx, net, func(ctx context.Context) error {
		var err error
		stream, err = self.device(from).dispatch.OpenStream(ctx, sidecar.Id(target.client.ClientId), &sidecar.StreamOpenRequest{Target: self.settings.StreamTarget})
		return err
	})
	if stream != nil {
		stream.Close()
	}
	if refused {
		rejected := &sidecar.StreamRejectError{}
		if !errors.As(err, &rejected) || rejected.Code != protocol.StreamRejectCode_SR_DENIED {
			return fmt.Errorf("%s's open to %s: %v, want DENIED", from, to, err)
		}
		if accepted := target.accepted.Load() - acceptedBefore; accepted != 0 {
			return fmt.Errorf("%s's accept ran %d times for an open on a control contract", to, accepted)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s's open to %s: %w", from, to, err)
	}
	if accepted := target.accepted.Load() - acceptedBefore; accepted != 1 {
		return fmt.Errorf("%s's accept ran %d times for one open", to, accepted)
	}
	return nil
}

// Sends one SYN from w to to's provider and fails unless it reaches to's hook sealed class, the hook denying it.
func (self *fs21World) expectPacket(ctx context.Context, net *Net, to string, class connectprotocol.ContractClass) error {
	from := self.device("w")
	target := self.device(to)
	natClient := self.natClients[to]
	if natClient == nil {
		natClient = connect.NewRemoteUserNatClient(
			from.client.Client,
			func(source connect.TransferPath, provideMode connectprotocol.ProvideMode, ipPath *connect.IpPath, packet []byte) {
			},
			[]connect.MultiHopId{connect.RequireMultiHopId(target.client.ClientId)},
			connectprotocol.ProvideMode_Network,
		)
		self.natClients[to] = natClient
	}
	var flow *fs21Flow
	err := self.blocking(ctx, net, func(ctx context.Context) error {
		packet := fs21SynPacket(self.settings.PacketFrom, self.settings.PacketTo)
		if !natClient.SendPacket(connect.SourceId(from.client.ClientId), connectprotocol.ProvideMode_Network, packet, self.settings.PacketSendTimeout) {
			return fmt.Errorf("w's packet to %s was not sent", to)
		}
		var err error
		flow, err = target.egress.await(ctx, from.client.ClientId, self.settings.PacketTo)
		return err
	})
	if err != nil {
		return err
	}
	if flow.flow.ContractClass != class {
		return fmt.Errorf("w's flow reached %s's hook sealed %s, not %s", to, flow.flow.ContractClass, class)
	}
	if flow.flow.ProvideMode != connectprotocol.ProvideMode_Network {
		return fmt.Errorf("w's flow reached %s's hook in mode %s", to, flow.flow.ProvideMode)
	}
	if flow.decision.Verdict != connect.EgressVerdictDeny {
		return fmt.Errorf("%s's hook passed w's flow on a %s contract", to, class)
	}
	return nil
}

// The fifth step: on w's control contract to x, a data RPC, a stream and IP are each refused.
func fs21ControlRefusals(world *fs21World) *Step {
	return fs21Do("w", world, func(ctx context.Context, net *Net, admission *sidecartest.AdmissionNet) error {
		if err := world.expectCall(ctx, net, "w", "x", true); err != nil {
			return err
		}
		if err := world.expectStream(ctx, net, "w", "x", true); err != nil {
			return err
		}
		return world.expectPacket(ctx, net, "x", connectprotocol.ContractClass_ContractClassControl)
	})
}

// Waits until the Net's clock holds a timer for at, which a goroutine arms when it reaches its wait, so a step that
// moves the clock past at never moves it before the wait is set.
func fs21AwaitTimer(ctx context.Context, net *Net, at time.Time) error {
	for {
		pending, added := net.Clock().WatchTimers()
		if slices.ContainsFunc(pending, func(timer time.Time) bool { return timer.Equal(at) }) {
			return nil
		}
		select {
		case <-added:
		case <-ctx.Done():
			return fmt.Errorf("no timer for %s among %v: %w", at, pending, ctx.Err())
		}
	}
}

// Fails unless name has raised exactly count alarms of kind.
func (self *fs21World) expectAlarms(name string, kind sidecar.SidecarHeadAlarm, count int) error {
	if alarms := self.headCheck.Sidecar(name).Alarms(kind); len(alarms) != count {
		return fmt.Errorf("%s raised %d %s alarms, want %d", name, len(alarms), kind, count)
	}
	return nil
}

// The partition's steps: the server takes r off its relays; w and x still witness each other; r's exchange with w goes
// unanswered until its HeadCheckTimeout; 24 h from r's last witness r alarms unwitnessed while w and x, witnessed
// since, raise nothing; past witness_bound_hours r still seals in every group, its own; relayed again, r witnesses.
func fs21Partition(world *fs21World) []*Step {
	bound := time.Duration(sidecar.WitnessBoundDefaultHours) * time.Hour
	return []*Step{
		fs21Do("server", world, func(ctx context.Context, net *Net, admission *sidecartest.AdmissionNet) error {
			world.rWitnessedAt = world.headCheck.Sidecar("r").Stop.WitnessedAt()
			if world.rWitnessedAt.IsZero() {
				return errors.New("r never witnessed before the partition")
			}
			return world.blocking(ctx, net, func(ctx context.Context) error {
				return world.tier.Partition(ctx, world.device("r").client.ClientId, true)
			})
		}),
		// the HeadCheck path the server leaves
		fs21Witness("w", world, "w", "x"),
		// r's exchange waits on its HeadCheckTimeout, on the Net's clock, with its baton given up
		{Actor: "r", Background: true, Action: func(ctx context.Context, net *Net) error {
			counted, err := world.exchange(ctx, net, "r", "w")
			if counted || err == nil {
				return fmt.Errorf("r's exchange across the partition counted %t: %v", counted, err)
			}
			if code, _ := sidecar.SubprotocolErrorCode(err); code != protocol.ErrorCode_ERR_DEADLINE_EXCEEDED {
				return fmt.Errorf("r's exchange across the partition: %v, want DEADLINE_EXCEEDED", err)
			}
			return nil
		}},
		{Actor: "server", Action: func(ctx context.Context, net *Net) error {
			at := net.Clock().Now().Add(world.settings.Protocol.HeadCheckTimeout)
			if err := world.blocking(ctx, net, func(ctx context.Context) error {
				return fs21AwaitTimer(ctx, net, at)
			}); err != nil {
				return err
			}
			net.Clock().AdvanceTo(at)
			return nil
		}},
		{Actor: "r", Join: true},
		fs21Do("server", world, func(ctx context.Context, net *Net, admission *sidecartest.AdmissionNet) error {
			if !world.headCheck.Sidecar("r").Stop.WitnessedAt().Equal(world.rWitnessedAt) {
				return errors.New("r's witnessed_at moved across the partition")
			}
			// an hour short of the alarm, w and x witness each other again
			net.Clock().AdvanceTo(world.rWitnessedAt.Add(sidecar.HeadCheckUnwitnessedAlarmTimeout - time.Hour))
			return nil
		}),
		fs21Witness("w", world, "w", "x"),
		fs21Do("server", world, func(ctx context.Context, net *Net, admission *sidecartest.AdmissionNet) error {
			due := world.rWitnessedAt.Add(sidecar.HeadCheckUnwitnessedAlarmTimeout)
			if err := world.blocking(ctx, net, func(ctx context.Context) error {
				return fs21AwaitTimer(ctx, net, due)
			}); err != nil {
				return err
			}
			net.Clock().AdvanceTo(due)
			return world.blocking(ctx, net, func(ctx context.Context) error {
				return world.headCheck.Sidecar("r").AwaitAlarm(ctx, sidecar.SidecarHeadAlarmUnwitnessed)
			})
		}),
		fs21Do("server", world, func(ctx context.Context, net *Net, admission *sidecartest.AdmissionNet) error {
			if err := world.expectAlarms("r", sidecar.SidecarHeadAlarmUnwitnessed, 1); err != nil {
				return err
			}
			for _, name := range []string{"w", "x"} {
				if err := world.expectAlarms(name, sidecar.SidecarHeadAlarmUnwitnessed, 0); err != nil {
					return err
				}
			}
			// w and x keep witnessing as the clock runs on to r's bound
			net.Clock().AdvanceTo(world.rWitnessedAt.Add(bound - time.Hour))
			return nil
		}),
		fs21Witness("w", world, "w", "x"),
		fs21Do("r", world, func(ctx context.Context, net *Net, admission *sidecartest.AdmissionNet) error {
			shared := world.scenario.sharedGroupId
			if shared != (sidecar.Id{}) {
				// an hour short of the bound r still seals in the group it shares
				if err := world.headCheck.Sidecar("r").Stop.SealAllowed(shared); err != nil {
					return fmt.Errorf("r stopped sealing in a shared group before the bound: %w", err)
				}
			}
			net.Clock().AdvanceTo(world.rWitnessedAt.Add(bound))
			// own groups only alarm: r, unwitnessed past the bound, still seals in every group that is its member's own
			if err := world.headCheck.Sidecar("r").Stop.SealAllowed(admission.Id("fs21 an owned group")); err != nil {
				return fmt.Errorf("r stopped sealing in its own group: %w", err)
			}
			if shared != (sidecar.Id{}) {
				// in a group with another member's devices r stops at the bound, and w, witnessed since, does not
				stop := &sidecar.HeadStopError{}
				if err := world.headCheck.Sidecar("r").Stop.SealAllowed(shared); !errors.As(err, &stop) || stop.Cause != sidecar.HeadStopUnwitnessed {
					return fmt.Errorf("r, unwitnessed past the bound, sealing in a shared group: %v", err)
				}
				if err := world.headCheck.Sidecar("w").Stop.SealAllowed(shared); err != nil {
					return fmt.Errorf("w, witnessed, stopped sealing in a shared group: %w", err)
				}
			}
			if !world.headCheck.Sidecar("r").Stop.WitnessedAt().Equal(world.rWitnessedAt) {
				return errors.New("r's witnessed_at moved while it was off the relays")
			}
			for _, name := range []string{"w", "x", "r"} {
				if err := world.expectAlarms(name, sidecar.SidecarHeadAlarmFork, 0); err != nil {
					return err
				}
			}
			return nil
		}),
		fs21Do("server", world, func(ctx context.Context, net *Net, admission *sidecartest.AdmissionNet) error {
			return world.blocking(ctx, net, func(ctx context.Context) error {
				return world.tier.Partition(ctx, world.device("r").client.ClientId, false)
			})
		}),
		fs21Do("r", world, func(ctx context.Context, net *Net, admission *sidecartest.AdmissionNet) error {
			counted, err := world.exchange(ctx, net, "r", "w")
			if err != nil || !counted {
				return fmt.Errorf("r's exchange with w once relayed again counted %t: %v", counted, err)
			}
			if witnessedAt := world.headCheck.Sidecar("r").Stop.WitnessedAt(); !witnessedAt.Equal(net.Clock().Now()) {
				return fmt.Errorf("r witnessed at %s once relayed again, not now", witnessedAt)
			}
			if shared := world.scenario.sharedGroupId; shared != (sidecar.Id{}) {
				if err := world.headCheck.Sidecar("r").Stop.SealAllowed(shared); err != nil {
					return fmt.Errorf("r, witnessed again, does not seal in a shared group: %w", err)
				}
			}
			return nil
		}),
	}
}

// The twin's steps: a second document lets w dial d, so w's first contract to d is data: the RPC is answered, the
// open accepted and the packet reaches d's hook sealed data, while w to x stays control and refused.
func fs21DataTwin(world *fs21World) []*Step {
	return []*Step{
		fs21Do("owner", world, func(ctx context.Context, net *Net, admission *sidecartest.AdmissionNet) error {
			plan, _ := admission.SaveAclPolicy(world.scenario.dialPolicy(world.device("w").identity.SidecarId, world.device("d").identity.SidecarId), nil)
			if !plan.Rows.GetHasDocument() {
				return errors.New("the second head has no document")
			}
			return fs21Head(ctx, net, world, admission)
		}),
		fs21Do("w", world, func(ctx context.Context, net *Net, admission *sidecartest.AdmissionNet) error {
			// each follower reaches the second document as HeadCheck fetches it, and w then counts d as a witness
			counted, err := world.exchange(ctx, net, "w", "d")
			if err != nil || !counted {
				return fmt.Errorf("w's exchange with d counted %t: %v", counted, err)
			}
			if err := world.expectCall(ctx, net, "w", "d", false); err != nil {
				return err
			}
			if err := world.expectStream(ctx, net, "w", "d", false); err != nil {
				return err
			}
			if err := world.expectPacket(ctx, net, "d", connectprotocol.ContractClass_ContractClassData); err != nil {
				return err
			}
			if err := world.device("d").classes.expectOnly(world.device("w").client.ClientId, connectprotocol.ContractClass_ContractClassData, admission.NetworkId()); err != nil {
				return fmt.Errorf("at d: %w", err)
			}
			if err := world.expectCall(ctx, net, "w", "x", true); err != nil {
				return err
			}
			return world.expectStream(ctx, net, "w", "x", true)
		}),
	}
}

// The last step: every exchange and act still running joins, then the world's dispatchers, providers, gate and
// writer stop. The gate cache closes once server's contract gate no longer reads it, and the step waits for its
// loaders, so none reads server's stores or reaches the Net's hooks after the schedule. A schedule that fails at an
// earlier step runs no later one, so its cache ends with the Net's context, unwaited for.
func fs21Close(world *fs21World) *Step {
	return &Step{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
		if world.headCheck != nil {
			for _, side := range world.headCheck.Sidecars() {
				side.Detach()
			}
		}
		for _, natClient := range world.natClients {
			natClient.Close()
		}
		for _, name := range fs21Names {
			device := world.device(name)
			if device == nil {
				continue
			}
			for _, remove := range device.removes {
				remove()
			}
			if device.dispatch != nil {
				device.dispatch.Close()
			}
			if device.provider != nil {
				device.provider.Close()
			}
			if device.providerNat != nil {
				device.providerNat.Close()
			}
			if device.follower != nil {
				device.follower.Close()
			}
		}
		if world.restoreGate != nil {
			world.restoreGate()
			world.restoreGate = nil
		}
		if world.cache != nil {
			// its loaders may be reading server's stores: the wait gives up the baton, as every real wait here does
			net.Barriers().Blocking(world.cache.CloseAndWait)
		}
		return fsTeamClose(world.fsTeamWorld).Action(ctx, net)
	}}
}

// FS-21's M4-out case (see the file header).
func Fs21(net *Net) *Schedule {
	return Fs21With(nil)(net)
}

// FS-21's schedule on settings, nil for the defaults.
func Fs21With(settings *Fs21Settings) Builder {
	return fs21Builder(settings, fs21Personal)
}

// The schedule of one case of FS-21 on settings, nil for the defaults: a world of its own for each Net.
func fs21Builder(settings *Fs21Settings, scenario func() *fs21Scenario) Builder {
	if settings == nil {
		settings = DefaultFs21Settings()
	}
	return func(net *Net) *Schedule {
		world := &fs21World{
			fsTeamWorld: newFsTeamWorld(),
			settings:    settings,
			scenario:    scenario(),
			devices:     map[string]*fs21Device{},
			natClients:  map[string]*connect.RemoteUserNatClient{},
		}
		steps := []*Step{
			fs21Setup(world),
			fs21Gate(world),
			fs21Online(world),
			fs21Witness("w", world, "w", "x", "r"),
			fs21ControlSeen(world),
			fs21ControlRefusals(world),
		}
		steps = append(steps, fs21Partition(world)...)
		steps = append(steps, fs21DataTwin(world)...)
		steps = append(steps, fs21Close(world))
		return &Schedule{
			Id:    world.scenario.id,
			Tiers: []Tier{TierT3},
			Check: []Invariant{FI(10), FsTeamAgreement(world.fsTeamWorld)},
			Steps: steps,
		}
	}
}
