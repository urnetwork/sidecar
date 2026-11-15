//go:build !sidecar_http && !ios_extension

// §17's world end to end (§22.4; BRIDGE-M4-22): one network whose bridge runs on real code, for FS-38, FS-56, S8 and
// §22.7's bridge asserts on T2, and for server's T3 run of them (server/controller/connect_bridge_m4_test.go), which
// gives it the platform's real CreateContract.
//
//	config    an AdmissionNet with ACL's own compile: the owner's device files the block into the config head, and each
//	          sidecar's admission, its own BridgeAddress and every other bridge statement land at api, signed by the
//	          device that would sign them in production; a SidecarRevoke is an admin's statement like any other
//	host      a host sidecar's device role, a real device.Bridge on a posture store of its own, fed by the root's
//	          BridgeComponent over a ConfigClient that follows the network: the component compiles each state from the
//	          log, the head and the subjects' bindings, hands the posture the log run that vouches for it, and hands
//	          each denial an entry carries to Bridge.Revoke at the entry's own position. On the host's connect client,
//	          Required and exposing the verified peer key, it builds each generation's LocalUserNat with the role's
//	          hook and only then its RemoteUserNatProvider
//	upstream  what the host's flows reach: a TCP and a UDP listener on loopback, counted, and the kernel's echo for
//	          ICMP. The NAT's TCP and UDP dials go through a counter a test can hold at a gate (FS-56's barrier), and
//	          the hook's every verified principal and decision is recorded
//	window    a window client on the Net's exchange carrying the WindowDelegation its subject's identity key signed,
//	          its contracts from the platform, sending through a RemoteUserNatClient to its host from a userspace
//	          connect.Tun, so a test dials TCP and UDP through a real stack and pings with an echo it builds
//	minted    the malicious operator's window client: every contract it asks for is Net.MintContract's, correctly
//	          HMACed under the host's provide secret and naming whatever subject, network, class and delegation the
//	          test chose (FS-38)
//
// The platform is the seam between the tiers: where clients register, and where their out-of-band control goes, as
// api's control route takes it. On T2 it is in memory: a client registry and an issuer that seals what server's
// CreateContract seals (C13, PROTO-M4-02): the source's subject, a window client's parent's, its network, the data
// class, and the request's delegation unchanged. On T3 server's test gives its own, rows in Postgres and every control
// frame to server's controller. Minting goes around the platform on both tiers, through the provide secret the test
// stack holds in the host's live client, as an operator holding the platform's provide keys would; the operator also
// answers the host's return contracts to its own clients, as its platform would.
//
// What is not the system here: each sidecar's binding is signed by the world and reaches the host's component through
// its store's binding cache, since no api serves these sidecars' identities (the component's fetcher has no api and
// fetches nothing); the host's daemon listener is one the world opens and names; a LAN host behind a route is the
// upstream's loopback listener, which the NAT's dial reaches in its place; and on T3 a client's key reaches server
// through the platform rather than in band, since the exchange carries no ControlId frame to server. Waits are on
// monitors and sockets, bounded by BridgeNetSettings.WaitTimeout of real time, since connect's timers are real (X9).
//
// Safe for concurrent use. A BridgeNet is closed by its test, before its Net.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
	sidecarprotocol "github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Tunables of a BridgeNet.
type BridgeNetSettings struct {
	// Where clients register and contracts come from: nil is T2's, in memory.
	Platform BridgeNetPlatform
	// The overlay block the owner files: 100.80.0.0/16, inside 100.64/10 as owner decision 28 draws one.
	Block netip.Prefix
	// How long, in real time, a wait for a state, a decision, a flow or an answer may take before it fails: 30 s, only
	// ever a failure's bound, since every wait is a monitor's or a socket's.
	WaitTimeout time.Duration
	// How long a WindowDelegation the world signs lives past the Net's clock: 1 h.
	DelegationLifetime time.Duration
	// The bytes a contract the world issues or mints allows: 8 MiB.
	ContractByteCount uint64
	// How long a window's send waits for its client to take a packet: 5 s.
	SendTimeout time.Duration
	// The binding cache the hosts' components keep: 7 days and 16 a sidecar, the component's defaults.
	BindingRetainTimeout time.Duration
	BindingMaxCount      int
	// How often a wait on what raises nothing looks again: 10 ms. A host's component raises nothing when its provider
	// starts or a compile lands, nor an exit's policy when it judges a packet, so those waits poll, bounded by
	// WaitTimeout. Positive.
	PollInterval time.Duration
	// The largest read an upstream listener or a window's UDP socket takes at once: 64 KiB, a datagram's most.
	ReadByteCount int
	// The strict_exp a sender's link gives each window client past the Net's clock: 7 days, §7.4's.
	WindowClientLifetime time.Duration
	// §16.6's spend check, which the network's api and readers install alike, so a GrantActivate spends an admin's
	// decision for real, a share's activation among them (BridgeShareNet); nil installs none, and every GrantActivate
	// is refused.
	AclSpendCheck sidecar.AclSpendCheck
}

func DefaultBridgeNetSettings() *BridgeNetSettings {
	return &BridgeNetSettings{
		Block:                netip.MustParsePrefix("100.80.0.0/16"),
		WaitTimeout:          30 * time.Second,
		DelegationLifetime:   time.Hour,
		ContractByteCount:    8 * 1024 * 1024,
		SendTimeout:          5 * time.Second,
		BindingRetainTimeout: 7 * 24 * time.Hour,
		BindingMaxCount:      16,
		PollInterval:         10 * time.Millisecond,
		ReadByteCount:        64 * 1024,
		WindowClientLifetime: 7 * 24 * time.Hour,
	}
}

// What a BridgeNet's clients register on and send their out-of-band control to: the in-memory registry and issuer on
// T2, server's Postgres and controller on T3. Safe for concurrent use.
type BridgeNetPlatform interface {
	// Registers a client of the network and answers its id: a sidecar's own client, or a window client whose subject
	// is its parent's.
	AddClient(ctx context.Context, args *BridgeNetClientArgs) (connect.Id, error)
	// The platform's answers to the control frames clientId sent it, as api's control route answers them: its contracts,
	// and its provide modes' and key's acks. Borrows frames; the answers are the caller's, to return to the pool.
	Control(ctx context.Context, clientId connect.Id, frames []*protocol.Frame) ([]*protocol.Frame, error)
	// Holds publicKey as the key clientId publishes in band, so a contract to it carries that key and its peer's session
	// can verify it. The world's exchange carries no client's ControlId frames to a platform, so the key's in-band
	// publication reaches the platform here.
	RegisterClientKey(ctx context.Context, clientId connect.Id, publicKey []byte) error
}

// One client a BridgeNet registers.
type BridgeNetClientArgs struct {
	Name      string
	NetworkId sidecar.Id
	// The sidecar whose own client it is, zero for a window client.
	SidecarId sidecar.Id
	// A window client's parent, the subject's own client, whose subject C13 seals for it.
	ParentClientId *connect.Id
	// A public exit's client, which provides Public to clients of other networks.
	Exit bool
}

// The seals and bytes of a contract an operator mints (Net.MintContract), whatever the platform's records say.
type MintContractArgs struct {
	SourceId      connect.Id
	DestinationId connect.Id
	ProvideMode   protocol.ProvideMode
	// C13's seals as the operator writes them; nil seals none.
	SourceSubjectClientId *connect.Id
	SourceNetworkId       *connect.Id
	ContractClass         protocol.ContractClass
	// The delegation the contract carries, verbatim; empty for none.
	WindowDelegation []byte
	// The destination key the contract names: nil is the destination's own, its live client's.
	DestinationClientPublicKey []byte
	TransferByteCount          uint64
}

// The malicious operator's contract (FS-38): stored contract bytes naming whatever args say, HMACed under the
// destination's provide secret for args.ProvideMode, which the test stack reads from the destination's live client on
// the Net's exchange, as an operator holding the platform's provide keys would. The destination accepts it as it
// accepts every contract the platform signs; what it is worth past that is the destination's own checks.
func (self *Net) MintContract(args *MintContractArgs) (*protocol.Contract, error) {
	if args == nil {
		return nil, errors.New("mint: no contract")
	}
	destination := self.exchange.client(args.DestinationId)
	if destination == nil {
		return nil, fmt.Errorf("mint: no live client %s on the exchange", args.DestinationId)
	}
	secretKey, ok := destination.Client.ContractManager().GetProvideSecretKey(args.ProvideMode)
	if !ok {
		return nil, fmt.Errorf("mint: %s does not provide %s", args.DestinationId, args.ProvideMode)
	}
	destinationKey := args.DestinationClientPublicKey
	if destinationKey == nil {
		destinationKey = destination.Client.ClientKeyManager().PublicKey()
	}
	storedContract := &protocol.StoredContract{
		ContractId:                 connect.NewId().Bytes(),
		TransferByteCount:          args.TransferByteCount,
		SourceId:                   args.SourceId.Bytes(),
		DestinationId:              args.DestinationId.Bytes(),
		DestinationClientPublicKey: bytes.Clone(destinationKey),
		ContractClass:              args.ContractClass,
		WindowDelegation:           bytes.Clone(args.WindowDelegation),
	}
	if args.SourceSubjectClientId != nil {
		storedContract.SourceSubjectClientId = args.SourceSubjectClientId.Bytes()
	}
	if args.SourceNetworkId != nil {
		storedContract.SourceNetworkId = args.SourceNetworkId.Bytes()
	}
	storedContractBytes, err := proto.Marshal(storedContract)
	if err != nil {
		return nil, err
	}
	return &protocol.Contract{
		StoredContractBytes:        storedContractBytes,
		StoredContractHmac:         connect.SignStoredContract(connect.DefaultContractManagerSettings(), secretKey, storedContractBytes),
		ProvideMode:                args.ProvideMode,
		DestinationClientPublicKey: bytes.Clone(destinationKey),
	}, nil
}

// T2's platform: a registry of the world's clients and an issuer that seals as server's CreateContract does, settling
// a share as its contract gate and escrow do (bridge_share_net.go).
type bridgeNetFakePlatform struct {
	net      *Net
	settings *BridgeNetSettings

	stateLock sync.Mutex
	clients   map[connect.Id]*bridgeNetFakeClient
	// each network's verified ACL state a share world handed in (SetShareStates), which a share's two halves read
	shareStates map[sidecar.Id]*sidecar.AclGateSnapshot
	// the network each issued contract was escrowed from, by contract id
	contractPayers map[connect.Id]sidecar.Id
	// the payer of each pair's newest non-companion contract, by source then destination: what a companion answering
	// it is escrowed from
	originPayers map[[2]connect.Id]sidecar.Id
	// the pairs, by source then destination, a share's FriendsAndFamily contract was issued for, whose companions the
	// platform answers (shareSettles)
	shareOrigins map[[2]connect.Id]struct{}
}

type bridgeNetFakeClient struct {
	networkId       sidecar.Id
	subjectClientId connect.Id
	// the sidecar the subject's own client is bound to, zero for a client that is no sidecar's
	subjectSidecarId sidecar.Id
	exit             bool
}

func newBridgeNetFakePlatform(net *Net, settings *BridgeNetSettings) *bridgeNetFakePlatform {
	return &bridgeNetFakePlatform{
		net:            net,
		settings:       settings,
		clients:        map[connect.Id]*bridgeNetFakeClient{},
		shareStates:    map[sidecar.Id]*sidecar.AclGateSnapshot{},
		contractPayers: map[connect.Id]sidecar.Id{},
		originPayers:   map[[2]connect.Id]sidecar.Id{},
		shareOrigins:   map[[2]connect.Id]struct{}{},
	}
}

func (self *bridgeNetFakePlatform) AddClient(ctx context.Context, args *BridgeNetClientArgs) (connect.Id, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	clientId := connect.NewId()
	client := &bridgeNetFakeClient{networkId: args.NetworkId, subjectClientId: clientId, subjectSidecarId: args.SidecarId, exit: args.Exit}
	if args.ParentClientId != nil {
		parent := self.clients[*args.ParentClientId]
		if parent == nil {
			return connect.Id{}, fmt.Errorf("no parent client %s", *args.ParentClientId)
		}
		client.subjectClientId, client.subjectSidecarId = parent.subjectClientId, parent.subjectSidecarId
	}
	self.clients[clientId] = client
	return clientId, nil
}

// The fake reads a destination's key and provide secrets from its live client, as Net.MintContract does, so it holds
// nothing.
func (self *bridgeNetFakePlatform) RegisterClientKey(ctx context.Context, clientId connect.Id, publicKey []byte) error {
	return nil
}

// Each CreateContract answered as createContract answers it; every other control taken with no answer, as the
// exchange's issuer does.
func (self *bridgeNetFakePlatform) Control(ctx context.Context, clientId connect.Id, frames []*protocol.Frame) ([]*protocol.Frame, error) {
	resultFrames := []*protocol.Frame{}
	for _, frame := range frames {
		message, err := connect.FromFrame(frame)
		if err != nil {
			continue
		}
		request, ok := message.(*protocol.CreateContract)
		if !ok {
			continue
		}
		result, err := self.createContract(clientId, request)
		if err != nil {
			continue
		}
		resultFrame, err := connect.ToFrame(result, connect.DefaultProtocolVersion)
		if err != nil {
			continue
		}
		resultFrames = append(resultFrames, resultFrame)
	}
	return resultFrames, nil
}

// Network contracts between two of the network's clients, sealed with the source's subject and network, the data
// class and the request's delegation; a companion carries its forward contract's seals, its destination's, and no
// delegation. Between two networks: a public exit's Public and its Stream companion, and a share's FriendsAndFamily
// and its Stream companion (shareSettles), escrowed from the dialer's network both ways. Anything else is refused.
// Each issued contract's payer is kept for ContractPayer: the source's network, and for a companion the payer of the
// forward contract it answers.
func (self *bridgeNetFakePlatform) createContract(sourceId connect.Id, request *protocol.CreateContract) (*protocol.CreateContractResult, error) {
	destinationId, err := connect.IdFromBytes(request.GetDestinationId())
	if err != nil {
		return nil, err
	}
	source, destination := func() (*bridgeNetFakeClient, *bridgeNetFakeClient) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.clients[sourceId], self.clients[destinationId]
	}()
	refused := protocol.ContractError_NoPermission
	provideMode := protocol.ProvideMode_Network
	switch {
	case source == nil || destination == nil:
		return &protocol.CreateContractResult{Error: &refused, CreateContract: request}, nil
	case source.networkId != destination.networkId && destination.exit && !request.GetCompanion():
		// a public exit's Public, with the source's seals as in every mode (D-PROTO-19)
		provideMode = protocol.ProvideMode_Public
	case source.networkId != destination.networkId && source.exit && request.GetCompanion():
		// the Stream companion answering a Public contract, with the forward's seals
		provideMode = protocol.ProvideMode_Stream
	case source.networkId != destination.networkId:
		settled, ok := self.shareSettles(sourceId, source, destinationId, destination, request.GetCompanion())
		if !ok {
			return &protocol.CreateContractResult{Error: &refused, CreateContract: request}, nil
		}
		provideMode = settled
	}
	sealed := source
	delegation := request.GetWindowDelegation()
	if request.GetCompanion() {
		sealed = destination
		delegation = nil
	}
	networkId := connect.Id(sealed.networkId)
	contract, err := self.net.MintContract(&MintContractArgs{
		SourceId:              sourceId,
		DestinationId:         destinationId,
		ProvideMode:           provideMode,
		SourceSubjectClientId: &sealed.subjectClientId,
		SourceNetworkId:       &networkId,
		ContractClass:         protocol.ContractClass_ContractClassData,
		WindowDelegation:      delegation,
		TransferByteCount:     max(request.GetTransferByteCount(), self.settings.ContractByteCount),
	})
	if err != nil {
		return nil, err
	}
	storedContract := &protocol.StoredContract{}
	if err := proto.Unmarshal(contract.GetStoredContractBytes(), storedContract); err != nil {
		return nil, err
	}
	contractId, err := connect.IdFromBytes(storedContract.GetContractId())
	if err != nil {
		return nil, err
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		payer := source.networkId
		if request.GetCompanion() {
			if originPayer, found := self.originPayers[[2]connect.Id{destinationId, sourceId}]; found {
				payer = originPayer
			}
		} else {
			self.originPayers[[2]connect.Id{sourceId, destinationId}] = payer
		}
		self.contractPayers[contractId] = payer
	}()
	return &protocol.CreateContractResult{Contract: contract, CreateContract: request}, nil
}

// A client's out-of-band control, as api's control route answers it, off the caller's goroutine: a CreateContract the
// operator answers (mint) is minted, and every other frame goes to the platform. Once SendControl returns, the frames
// and the callback are this control's (connect/CODESTYLE.md's out-of-band boundary).
type bridgeNetControl struct {
	ctx      context.Context
	clientId connect.Id
	platform BridgeNetPlatform
	// answers a CreateContract itself and true, the operator's, or false to leave it to the platform; nil for none
	mint func(request *protocol.CreateContract) (*protocol.CreateContractResult, bool, error)
	// the world's controls in flight
	workers *bridgeNetControls
}

// Why a control is refused once its world has closed.
var errBridgeNetClosed = errors.New("the bridge world is closed")

// The out-of-band controls in flight across a world's clients, which its close waits for, and every contract they were
// answered, kept for BridgeNet.Contracts. A client may send a control after its world began to close, a contract's
// close among them, which is refused at once. Safe for concurrent use.
type bridgeNetControls struct {
	stateLock sync.Mutex
	closed    bool
	count     *connect.MonitorValue[int]
	contracts []*BridgeNetContract
	// moves at each contract kept
	contractCount *connect.MonitorValue[int]
}

// One contract a world client asked for and what answered it, the platform or the operator's mint. A value the world
// never changes once kept.
type BridgeNetContract struct {
	// The client that asked, the contract's source.
	SourceId      connect.Id
	DestinationId connect.Id
	// The request's own companion bit.
	Companion bool
	// The operator's mint answered it, not the platform.
	Minted bool
	// An issued contract's mode and stored contract: C13's seals, the delegation, the contract's id. The zero mode and
	// nil for a refusal.
	ProvideMode protocol.ProvideMode
	Stored      *protocol.StoredContract
	// A refusal's error, nil for an issued contract.
	Error *protocol.ContractError
}

// Whether the contract was issued, not refused.
func (self *BridgeNetContract) Issued() bool {
	return self.Stored != nil
}

// Keeps what answered each of requests, which sourceId sent in one control: answers' CreateContractResults, in order.
// An issued contract pairs with the first unpaired request to its destination, and a refusal with the request it
// echoes or, when it echoes none, as server's do not, with the next unpaired request.
func (self *bridgeNetControls) record(sourceId connect.Id, requests []*protocol.CreateContract, answers []*protocol.Frame, minted bool) {
	paired := make([]bool, len(requests))
	pair := func(destinationId []byte) *protocol.CreateContract {
		for i, request := range requests {
			if !paired[i] && (destinationId == nil || bytes.Equal(request.GetDestinationId(), destinationId)) {
				paired[i] = true
				return request
			}
		}
		return nil
	}
	contracts := []*BridgeNetContract{}
	for _, answer := range answers {
		message, err := connect.FromFrame(answer)
		if err != nil {
			continue
		}
		result, ok := message.(*protocol.CreateContractResult)
		if !ok {
			continue
		}
		contract := &BridgeNetContract{SourceId: sourceId, Minted: minted, Error: result.Error}
		var request *protocol.CreateContract
		if result.GetContract() != nil {
			storedContract := &protocol.StoredContract{}
			if err := proto.Unmarshal(result.GetContract().GetStoredContractBytes(), storedContract); err != nil {
				continue
			}
			contract.Stored, contract.ProvideMode = storedContract, result.GetContract().GetProvideMode()
			request = pair(storedContract.GetDestinationId())
		} else if result.GetCreateContract() != nil {
			request = pair(result.GetCreateContract().GetDestinationId())
		} else {
			request = pair(nil)
		}
		if request == nil {
			continue
		}
		if destinationId, err := connect.IdFromBytes(request.GetDestinationId()); err == nil {
			contract.DestinationId = destinationId
		}
		contract.Companion = request.GetCompanion()
		contracts = append(contracts, contract)
	}
	if len(contracts) == 0 {
		return
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.contracts = append(self.contracts, contracts...)
	}()
	self.contractCount.Update(func(count int) int { return count + len(contracts) })
}

// Every contract kept from sourceId to destinationId, in the order they were answered.
func (self *bridgeNetControls) between(sourceId connect.Id, destinationId connect.Id) []*BridgeNetContract {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	contracts := []*BridgeNetContract{}
	for _, contract := range self.contracts {
		if contract.SourceId == sourceId && contract.DestinationId == destinationId {
			contracts = append(contracts, contract)
		}
	}
	return contracts
}

func newBridgeNetControls() *bridgeNetControls {
	return &bridgeNetControls{count: connect.NewMonitorValue(0), contractCount: connect.NewMonitorValue(0)}
}

// Counts a control in, false once the world closed.
func (self *bridgeNetControls) start() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return false
	}
	self.count.Update(func(count int) int { return count + 1 })
	return true
}

func (self *bridgeNetControls) finish() {
	self.count.Update(func(count int) int { return count - 1 })
}

// Refuses every later control and waits for those in flight.
func (self *bridgeNetControls) close() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
	}()
	for {
		count, changed := self.count.Get()
		if count == 0 {
			return
		}
		<-changed
	}
}

func (self *bridgeNetControl) SendControl(frames []*protocol.Frame, callback connect.OobResultFunction) {
	if !self.workers.start() {
		for _, frame := range frames {
			connect.MessagePoolReturn(frame.MessageBytes)
		}
		if callback != nil {
			connect.HandleError(func() {
				callback(nil, errBridgeNetClosed)
			})
		}
		return
	}
	go func() {
		defer self.workers.finish()
		resultFrames := []*protocol.Frame{}
		defer func() {
			for _, frame := range frames {
				connect.MessagePoolReturn(frame.MessageBytes)
			}
			for _, frame := range resultFrames {
				connect.MessagePoolReturn(frame.MessageBytes)
			}
		}()
		platformFrames := []*protocol.Frame{}
		platformRequests := []*protocol.CreateContract{}
		for _, frame := range frames {
			message, err := connect.FromFrame(frame)
			request, isRequest := message.(*protocol.CreateContract)
			if err == nil && isRequest && self.mint != nil {
				result, minted, err := self.mint(request)
				if minted {
					if err == nil && result != nil {
						if resultFrame, err := connect.ToFrame(result, connect.DefaultProtocolVersion); err == nil {
							resultFrames = append(resultFrames, resultFrame)
							self.workers.record(self.clientId, []*protocol.CreateContract{request}, []*protocol.Frame{resultFrame}, true)
						}
					}
					continue
				}
			}
			if err == nil && isRequest {
				platformRequests = append(platformRequests, request)
			}
			platformFrames = append(platformFrames, frame)
		}
		var err error
		if 0 < len(platformFrames) {
			var answers []*protocol.Frame
			answers, err = self.platform.Control(self.ctx, self.clientId, platformFrames)
			// kept before the client takes the answers, so a flow that rode a contract finds it kept
			self.workers.record(self.clientId, platformRequests, answers, false)
			resultFrames = append(resultFrames, answers...)
		}
		if callback != nil {
			connect.HandleError(func() {
				callback(resultFrames, err)
			})
		}
	}()
}

// A client's provide modes, set with the platform's ack waited for, and its key held at the platform, as a client
// opening on api is open once both hold.
func (self *BridgeNet) waitClient(ctx context.Context, client *NetClient, provideModes map[protocol.ProvideMode]bool) error {
	acks := make(chan error, 1)
	client.Client.ContractManager().SetProvideModesWithReturnTrafficWithOobAckCallback(provideModes, func(err error) {
		select {
		case acks <- err:
		default:
		}
	})
	select {
	case err := <-acks:
		if err != nil {
			return fmt.Errorf("the platform refused %s's provide modes: %w", client.Name, err)
		}
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(self.settings.WaitTimeout):
		return fmt.Errorf("no ack of %s's provide modes within %s", client.Name, self.settings.WaitTimeout)
	}
	return self.platform.RegisterClientKey(ctx, client.ClientId, client.Client.ClientKeyManager().PublicKey())
}

// The parts of §22.7 this world runs (BRIDGE-M4-22): S8 on T2 in sidecartest/scenario and on T3 in server's controller
// package, and the bridge's asserts, each a test of its own.
var (
	_ = RegisterPrivacyAssert("public-exits", &PrivacyAssertTest{Repo: "sidecar", Package: "github.com/urnetwork/sidecar/sidecartest", Name: "TestBridgePublicExitsRefuseOverlayAndPrivateDestinations"})
	_ = RegisterScenario("S8", "", ScenarioTierT2, &ScenarioTest{Repo: "sidecar", Package: "github.com/urnetwork/sidecar/sidecartest/scenario", Name: "TestScenarioS8"})
	_ = RegisterScenario("S8", "", ScenarioTierT3, &ScenarioTest{Repo: "server", Package: "github.com/urnetwork/server/controller", Name: "TestScenarioS8OnT3", Tags: "sidecar_pending"})
	_ = RegisterPrivacyAssert("unsealed-peer", &PrivacyAssertTest{Repo: "sidecar", Package: "github.com/urnetwork/sidecar/sidecartest", Name: "TestBridgeUnsealedPeerFlowIsDenied"})
)

// A failure a world raised inside a scenario's flow, which the flow returns.
type bridgeNetFailure struct {
	err error
}

// A world's AdmissionT inside a scenario's flow: a failure panics, and bridgeNetCatch recovers it into the flow's error.
type bridgeNetFailer struct{}

func (bridgeNetFailer) Helper() {}

func (bridgeNetFailer) Fatal(args ...any) {
	panic(bridgeNetFailure{err: errors.New(fmt.Sprint(args...))})
}

func (bridgeNetFailer) Fatalf(format string, args ...any) {
	panic(bridgeNetFailure{err: fmt.Errorf(format, args...)})
}

func (bridgeNetFailer) Logf(format string, args ...any) {}

// Runs body, turning a failure the world raises into its error.
func bridgeNetCatch(body func() error) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			failure, ok := recovered.(bridgeNetFailure)
			if !ok {
				panic(recovered)
			}
			err = failure.err
		}
	}()
	return body()
}

// The settings a schedule's world takes on a Net, which server's T3 test sets before it runs a schedule there.
var netBridgeSettings sync.Map

// Sets the BridgeNetSettings a schedule's world on net takes; nil drops them.
func SetNetBridgeSettings(net *Net, settings *BridgeNetSettings) {
	if settings == nil {
		netBridgeSettings.Delete(net)
		return
	}
	netBridgeSettings.Store(net, settings)
}

// The BridgeNetSettings set for net, nil for T2's defaults.
func NetBridgeSettings(net *Net) *BridgeNetSettings {
	if settings, ok := netBridgeSettings.Load(net); ok {
		return settings.(*BridgeNetSettings)
	}
	return nil
}

// One network's bridge world. See the file's comment.
type BridgeNet struct {
	t         AdmissionT
	net       *Net
	settings  *BridgeNetSettings
	platform  BridgeNetPlatform
	admission *AdmissionNet
	// the config repo's generation 1, which every bridge body is sealed under and every host's compile opens with
	configKey *sidecar.EvsRepoKey
	rows      *bridgeNetRows

	stateLock sync.Mutex
	devices   []*BridgeNetDevice
	hosts     []*BridgeNetHost
	exits     []*BridgeNetExit
	senders   []*BridgeNetSender
	windows   []*BridgeNetWindow
	// the operator's clients, whose return contracts the operator mints too
	mintedClientIds map[connect.Id]bool
	// the local policy of the newest document saved, nil before one (SaveAclPolicy)
	aclLocal *sidecar.AclLocalPolicy
	// every client's out-of-band controls in flight
	controls *bridgeNetControls
}

// A network on net's tier, bootstrapped by its owner's device, whose head holds settings' block, failing through t: a
// testing.TB, or a schedule's step that turns a failure into its error. settings nil is DefaultBridgeNetSettings. The
// caller closes it before net.
func NewBridgeNet(t AdmissionT, net *Net, settings *BridgeNetSettings) *BridgeNet {
	t.Helper()
	if settings == nil {
		settings = DefaultBridgeNetSettings()
	}
	tier, err := net.AdmissionTier()
	if err != nil {
		t.Fatal(err)
	}
	tier.AclCompile = AclAdmissionCompile
	tier.AclSpendCheck = settings.AclSpendCheck
	admission := NewAdmissionNet(t, tier)
	admission.StartReadersAtBases(false)
	self := &BridgeNet{
		t:         t,
		net:       net,
		settings:  settings,
		platform:  settings.Platform,
		admission: admission,

		mintedClientIds: map[connect.Id]bool{},
		controls:        newBridgeNetControls(),
	}
	if self.platform == nil {
		self.platform = newBridgeNetFakePlatform(net, settings)
	}
	self.rows = &bridgeNetRows{bridgeNet: self, rows: map[[sha256.Size]byte][]byte{}}
	var groupId sidecar.Id
	rand.Read(groupId[:])
	self.configKey, _, err = sidecar.NewGkmFirstGeneration(admission.ConfigRepoId(), groupId, &sidecar.GkmGenerationArgs{
		Cause:         sidecar.GkmCauseRequest,
		Auth:          admission.Tip(),
		Time:          net.Clock().Now(),
		HoldersSha256: make([]byte, sha256.Size),
	})
	if err != nil {
		admission.Close()
		t.Fatal(err)
	}
	self.SetBlock(settings.Block)
	return self
}

// Closes every window and host, then the network's config world.
func (self *BridgeNet) Close() {
	var windows []*BridgeNetWindow
	var senders []*BridgeNetSender
	var hosts []*BridgeNetHost
	var exits []*BridgeNetExit
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		windows, senders, hosts, exits = self.windows, self.senders, self.hosts, self.exits
		self.windows, self.senders, self.hosts, self.exits = nil, nil, nil, nil
	}()
	for _, window := range windows {
		window.Close()
	}
	for _, exit := range exits {
		exit.Close()
	}
	for _, sender := range senders {
		sender.Close()
	}
	for _, host := range hosts {
		host.Close()
	}
	self.controls.close()
	self.admission.Close()
}

// The network's config world.
func (self *BridgeNet) Admission() *AdmissionNet {
	return self.admission
}

// Every contract a client of the world asked for from sourceId to destinationId, and what answered it, in the order
// they were answered: each request a client's control carried, the platform's and the operator's alike.
func (self *BridgeNet) Contracts(sourceId connect.Id, destinationId connect.Id) []*BridgeNetContract {
	return self.controls.between(sourceId, destinationId)
}

// Waits until done holds for the contracts kept from sourceId to destinationId, at most WaitTimeout of real time;
// false when it never did.
func (self *BridgeNet) WaitContracts(sourceId connect.Id, destinationId connect.Id, done func(contracts []*BridgeNetContract) bool) bool {
	deadline := time.After(self.settings.WaitTimeout)
	for {
		// armed at the read, so a contract kept after it wakes the wait
		_, changed := self.controls.contractCount.Get()
		if done(self.controls.between(sourceId, destinationId)) {
			return true
		}
		select {
		case <-changed:
		case <-deadline:
			return false
		case <-self.net.Context().Done():
			return false
		}
	}
}

func (self *BridgeNet) Net() *Net {
	return self.net
}

func (self *BridgeNet) NetworkId() sidecar.Id {
	return self.admission.NetworkId()
}

func (self *BridgeNet) Settings() *BridgeNetSettings {
	return self.settings
}

// The config repo's generation 1, which the world seals every bridge body under.
func (self *BridgeNet) ConfigKey() *sidecar.EvsRepoKey {
	return self.configKey
}

// The owner's device files block into the config head, with its base (`ur bridge block`).
func (self *BridgeNet) SetBlock(block netip.Prefix) *bridge.AuthPin {
	self.t.Helper()
	signed := self.admission.Sign(self.admission.Owner(), bridge.SignedType_SIGNED_BRIDGE_BLOCK, &bridge.BridgeBlock{
		Ipv4Prefix: BridgeNetPrefix(block),
	})
	return self.admission.SaveHead(func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error) {
		return head.WithFile(sidecar.ConfigHeadBridgeBlockPath, signed)
	})
}

// prefix as bridge.proto holds one.
func BridgeNetPrefix(prefix netip.Prefix) *bridge.BridgeIpv4Prefix {
	return &bridge.BridgeIpv4Prefix{Address: BridgeNetIpv4(prefix.Masked().Addr()), Length: uint32(prefix.Bits())}
}

// An IPv4 address as bridge.proto's fixed32 holds one.
func BridgeNetIpv4(address netip.Addr) uint32 {
	octets := address.As4()
	return binary.BigEndian.Uint32(octets[:])
}

// A sidecar of the network: its admission device, its own client on the platform and the binding naming it.
type BridgeNetDevice struct {
	Name   string
	Device *AdmissionDevice
	// Its own client, which its binding names and its window clients are children of.
	ClientId        connect.Id
	clientKeySeed   []byte
	ClientPublicKey []byte
	// The SignedSidecarIdentityBinding of ClientId, which a host's compile reads its client ids from.
	Binding []byte
}

func (self *BridgeNetDevice) SidecarId() sidecar.Id {
	return self.Device.SidecarId
}

// Admits an untagged device of the owner's member, signed by the owner's device, with its own client registered on
// the platform and its binding signed by both its keys. A host compiles a device's client ids from the bindings it
// holds when it starts, so add each device before the hosts that should know it.
func (self *BridgeNet) AddDevice(name string) *BridgeNetDevice {
	self.t.Helper()
	admission := self.admission
	device := admission.Device("bridge "+name, admission.Owner().MemberId)
	admission.AdmitDevice(admission.Owner(), device, 0)
	return self.addDevice(name, device)
}

// The device of an admitted admission device: its client registered, its binding signed.
func (self *BridgeNet) addDevice(name string, admissionDevice *AdmissionDevice) *BridgeNetDevice {
	self.t.Helper()
	clientId, err := self.platform.AddClient(self.net.Context(), &BridgeNetClientArgs{
		Name:      name,
		NetworkId: self.NetworkId(),
		SidecarId: admissionDevice.SidecarId,
	})
	if err != nil {
		self.t.Fatalf("client of %s: %v", name, err)
	}
	seed := sha256.Sum256(append(self.NetworkId().Bytes(), []byte("bridge net client key "+name)...))
	clientKey := ed25519.NewKeyFromSeed(seed[:])
	binding, err := sidecar.NewSidecarIdentityBinding(&sidecar.SidecarIdentityBinding{
		NetworkId:  self.NetworkId(),
		SidecarId:  admissionDevice.SidecarId,
		ClientId:   sidecar.Id(clientId),
		Generation: 1,
		IssuedAt:   self.net.Clock().Now(),
	}, admissionDevice.Key.Seed(), seed[:])
	if err != nil {
		self.t.Fatal(err)
	}
	device := &BridgeNetDevice{
		Name:            name,
		Device:          admissionDevice,
		ClientId:        clientId,
		clientKeySeed:   seed[:],
		ClientPublicKey: clientKey.Public().(ed25519.PublicKey),
		Binding:         binding,
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.devices = append(self.devices, device)
	return device
}

// device's own BridgeAddress at address (§17.4's binding; an own-resource filing, signed by the device itself), its
// body sealed under the config key. The position it landed at.
func (self *BridgeNet) FileAddress(device *BridgeNetDevice, address netip.Addr) uint64 {
	self.t.Helper()
	header := self.admission.Header()
	sealed := self.Seal(bridge.SignedType_SIGNED_BRIDGE_ADDRESS, header, &bridge.BridgeAddressBody{Ipv4: BridgeNetIpv4(address)})
	return self.Land(device.Device, bridge.SignedType_SIGNED_BRIDGE_ADDRESS, &bridge.BridgeAddress{
		Header: header, SidecarId: device.SidecarId().Bytes(), SealedBody: sealed,
	})
}

// body sealed into a statement of signedType with header, under the config key.
func (self *BridgeNet) Seal(signedType bridge.SignedType, header *bridge.StatementHeader, body proto.Message) []byte {
	self.t.Helper()
	sealed, err := sidecar.SealConfigBody(self.configKey, sidecar.NewConfigSealContext(signedType, header), body, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	return sealed
}

// statement signed by signer, which must land; the position it landed at.
func (self *BridgeNet) Land(signer *AdmissionDevice, signedType bridge.SignedType, statement proto.Message) uint64 {
	self.t.Helper()
	self.admission.MustLand(self.admission.Sign(signer, signedType, statement))
	return self.admission.Tip().GetVersion()
}

// The owner's device saves source as the network's ACL document, as `ur acl push` does once a person confirms its
// preview (§8.8), with its base; every host's compile takes the plan's local policy from then on. The plan.
func (self *BridgeNet) SaveAclPolicy(source string) *sidecar.AclSavePlan {
	self.t.Helper()
	plan, _ := self.admission.SaveAclPolicy([]byte(source), nil)
	self.stateLock.Lock()
	self.aclLocal = plan.Local
	self.stateLock.Unlock()
	return plan
}

// The id of the document's one rule that allows route, failing the test unless there is exactly one.
func BridgeNetRouteRuleId(t AdmissionT, plan *sidecar.AclSavePlan) []byte {
	t.Helper()
	ruleIds := [][]byte{}
	for _, rule := range plan.Rows.GetRules() {
		if slices.Contains(rule.GetActions(), uint32(sidecarprotocol.AclAction_ACL_ACTION_ROUTE)) {
			ruleIds = append(ruleIds, rule.GetRuleId())
		}
	}
	if len(ruleIds) != 1 {
		t.Fatalf("the document holds %d route rules, not one", len(ruleIds))
	}
	return ruleIds[0]
}

// A subnet route of prefix the host advertises under the standing route rules routeRuleIds, its body sealed under the
// config key and its site id siteId (`ur bridge expose` under a standing grant, §17.7), which must land: its route id.
func (self *BridgeNet) FileRoute(host *BridgeNetDevice, prefix netip.Prefix, routeRuleIds [][]byte, siteId []byte) []byte {
	self.t.Helper()
	header := self.admission.Header()
	routeId := make([]byte, sha256.Size)
	rand.Read(routeId)
	sealed := self.Seal(bridge.SignedType_SIGNED_BRIDGE_ROUTE, header, &bridge.BridgeRouteBody{
		Prefixes: []*bridge.BridgeIpv4Prefix{BridgeNetPrefix(prefix)},
		SiteId:   siteId,
		Weight:   1,
		Kind:     bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_SUBNET,
	})
	self.Land(host.Device, bridge.SignedType_SIGNED_BRIDGE_ROUTE, &bridge.BridgeRoute{
		Header: header, RouteId: routeId, Advertiser: host.SidecarId().Bytes(), RouteRuleIds: routeRuleIds, SealedBody: sealed,
	})
	return routeId
}

// A BridgeWithdraw of ruleId in mode, signed by signer, the rule's own or an admin's device, which must land: the
// position it landed at.
func (self *BridgeNet) Withdraw(signer *BridgeNetDevice, ruleId []byte, mode bridge.BridgeWithdrawMode) uint64 {
	self.t.Helper()
	return self.Land(signer.Device, bridge.SignedType_SIGNED_BRIDGE_WITHDRAW, &bridge.BridgeWithdraw{
		Header: self.admission.Header(), RuleId: ruleId, Mode: mode,
	})
}

// A SidecarRevoke of device by the owner's device, an admin's (§7.9), which must land: the position it landed at.
func (self *BridgeNet) RevokeDevice(device *BridgeNetDevice) uint64 {
	self.t.Helper()
	revoke := self.admission.Revocation(device.Device, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0)
	return self.Land(self.admission.Owner(), bridge.SignedType_SIGNED_SIDECAR_REVOKE, revoke)
}

// Waits until every host's follower stands at the network's tip and its bridge has published what it adopted
// there, failing the test past WaitTimeout.
func (self *BridgeNet) Follow() {
	self.t.Helper()
	tip := self.admission.Tip().GetVersion()
	for _, host := range self.Hosts() {
		host.WaitAdopted(tip)
	}
}

// The hosts started so far.
func (self *BridgeNet) Hosts() []*BridgeNetHost {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.hosts)
}

// The network's projection rows for a host's posture, read from api, which is safe for concurrent use, since the
// admission world's own copy is its test's alone.
type bridgeNetRows struct {
	bridgeNet *BridgeNet

	stateLock sync.Mutex
	rows      map[[sha256.Size]byte][]byte
}

// sidecar.ConfigRowsSource: rows from api's projection.
func (self *bridgeNetRows) Rows(networkId sidecar.Id, rowsSha256 []byte) ([]byte, error) {
	if len(rowsSha256) != sha256.Size {
		return nil, fmt.Errorf("%w: a hash of %d bytes", sidecar.ErrConfigRowsUnavailable, len(rowsSha256))
	}
	key := [sha256.Size]byte(rowsSha256)
	if rows, found := func() ([]byte, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		rows, found := self.rows[key]
		return rows, found
	}(); found {
		return bytes.Clone(rows), nil
	}
	admission := self.bridgeNet.admission
	after := uint64(0)
	for {
		projection, err := admission.api.ReadConfigProjection(admission.ctx, networkId, after)
		if err != nil {
			return nil, err
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			for _, rows := range projection.Rows {
				self.rows[sha256.Sum256(rows)] = bytes.Clone(rows)
			}
		}()
		after += uint64(len(projection.Entries))
		if !projection.More || len(projection.Entries) == 0 {
			break
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if rows, found := self.rows[key]; found {
		return bytes.Clone(rows), nil
	}
	return nil, fmt.Errorf("%w: api served no rows at %x", sidecar.ErrConfigRowsUnavailable, rowsSha256)
}

// sidecar.ConfigRowsSource: the head a base names, checked as a full reader checks it.
func (self *bridgeNetRows) CheckHead(check *sidecar.ConfigHeadCheck) (*sidecar.ConfigHeadFacts, error) {
	admission := self.bridgeNet.admission
	head, err := admission.heads.ReadConfigHead(admission.ctx, check.Header.GetConfigVersion(), check.Header.GetConfigHeadSha256())
	if err != nil {
		return nil, err
	}
	return sidecar.CheckConfigBase(head, check, check.CompileRows)
}

// A posture store in memory, as an app's sealed store would hold one network's records.
type bridgeNetPostureStore struct {
	stateLock sync.Mutex
	records   map[string][]byte
}

func newBridgeNetPostureStore() *bridgeNetPostureStore {
	return &bridgeNetPostureStore{records: map[string][]byte{}}
}

func (self *bridgeNetPostureStore) Open(name string) (io.ReadCloser, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	record, found := self.records[name]
	if !found {
		return nil, device.ErrPostureStoreAbsent
	}
	return io.NopCloser(bytes.NewReader(bytes.Clone(record))), nil
}

func (self *bridgeNetPostureStore) Write(name string, write func(writer io.Writer) error) error {
	buffer := &bytes.Buffer{}
	if err := write(buffer); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.records[name] = buffer.Bytes()
	return nil
}

func (self *bridgeNetPostureStore) Remove(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.records, name)
	return nil
}

func (self *bridgeNetPostureStore) List() ([]string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	names := []string{}
	for name := range self.records {
		names = append(names, name)
	}
	slices.Sort(names)
	return names, nil
}

// device.Bridge as the component's sink, as cli/'s urBridgeSink is: each call through, a log run converted to the
// posture's, the decision read off what the bridge adopted, and its hook wrapped so the host records what it decided.
type bridgeNetSink struct {
	bridge *device.Bridge
	hook   connect.EgressHook
	// records each denial handed through Revoke; nil records none
	revoked func(revocation *BridgeNetRevocation)
}

var (
	_ sidecar.BridgeStateSink     = (*bridgeNetSink)(nil)
	_ sidecar.BridgeShareResigner = (*bridgeNetSink)(nil)
)

// sidecar.BridgeShareResigner: the shares whose signer changed, whose links' live window clients the role signs again.
func (self *bridgeNetSink) ResignShares(shareIds []sidecar.Id) error {
	connectIds := make([]connect.Id, 0, len(shareIds))
	for _, shareId := range shareIds {
		connectIds = append(connectIds, connect.Id(shareId))
	}
	return self.bridge.ResignShares(connectIds)
}

func (self *bridgeNetSink) SetPending(pending *bridge.Pending) error {
	return self.bridge.SetPending(pending)
}

func (self *bridgeNetSink) SetState(state *bridge.BridgeState, log *sidecar.BridgeStateLog) error {
	return self.bridge.SetState(state, bridgeNetPostureLog(log))
}

func (self *bridgeNetSink) ApplyDeltas(log *sidecar.BridgeStateLog) error {
	return self.bridge.ApplyDeltas(bridgeNetPostureLog(log))
}

func (self *bridgeNetSink) SetFork(fork bool) error {
	return self.bridge.SetFork(fork)
}

func (self *bridgeNetSink) Decision() sidecar.BridgeSinkDecision {
	decision := self.bridge.Decision()
	sinkDecision := sidecar.BridgeSinkDecision{Pin: decision.Pin, Fork: decision.Fork}
	switch decision.State {
	case device.PostureLegacy:
		sinkDecision.State = sidecar.BridgeSinkLegacy
	case device.PostureEnforcingDocument, device.PostureEnforcingNoDocument:
		sinkDecision.State = sidecar.BridgeSinkEnforcing
	default:
		sinkDecision.State = sidecar.BridgeSinkPending
	}
	if decision.BridgeState != nil {
		sinkDecision.StatePin = decision.BridgeState.GetAuth()
	}
	return sinkDecision
}

func (self *bridgeNetSink) Revoke(statementType bridge.SignedType, id []byte, n uint64) error {
	err := self.bridge.Revoke(statementType, id, n)
	if self.revoked != nil {
		self.revoked(&BridgeNetRevocation{Type: statementType, Id: bytes.Clone(id), N: n, Err: err})
	}
	return err
}

func (self *bridgeNetSink) EgressHook() connect.EgressHook {
	return self.hook
}

// A log run as the posture reads it.
func bridgeNetPostureLog(log *sidecar.BridgeStateLog) *device.PostureLog {
	if log == nil {
		return nil
	}
	return &device.PostureLog{Entries: log.Entries, OpenRows: log.OpenRows}
}

// One denial the component handed the host's role through Bridge.Revoke, and what the role answered.
type BridgeNetRevocation struct {
	Type bridge.SignedType
	Id   []byte
	N    uint64
	Err  error
}

// One principal the host's hook verified: the contract's source and what it answered, nil for none.
type BridgeNetPrincipal struct {
	SourceId    connect.Id
	ProvideMode protocol.ProvideMode
	Principal   *connect.BridgePrincipal
}

// One decision the host's hook made, with the flow it was asked about.
type BridgeNetDecision struct {
	SourceId    connect.Id
	ProvideMode protocol.ProvideMode
	Protocol    connect.IpProtocol
	To          netip.AddrPort
	Sealed      bool
	Principal   *connect.BridgePrincipal
	Verdict     connect.EgressVerdict
	Target      netip.AddrPort
	Generation  uint64
	// The (subject, rule) pair the decision came from, a share target's for a share's flow (§17.9's tag row).
	RuleTag uint64
}

// Whether the hook let the flow open a socket: a pass or a map.
func (self *BridgeNetDecision) Opens() bool {
	return self.Verdict == connect.EgressVerdictPass || self.Verdict == connect.EgressVerdictMap
}

// The device role's hook, each answer recorded on its host. It binds the NAT's closer through to the role's, so a
// revocation still ends the NAT's flows.
type bridgeNetHook struct {
	inner connect.EgressHook
	host  *BridgeNetHost
}

var (
	_ connect.EgressHook       = (*bridgeNetHook)(nil)
	_ connect.EgressHookBinder = (*bridgeNetHook)(nil)
)

func (self *bridgeNetHook) VerifyPrincipal(source connect.TransferPath, peer connect.Peer) *connect.BridgePrincipal {
	principal := self.inner.VerifyPrincipal(source, peer)
	self.host.record(func() {
		self.host.principals = append(self.host.principals, &BridgeNetPrincipal{SourceId: source.SourceId, ProvideMode: peer.ProvideMode, Principal: principal})
	})
	return principal
}

func (self *bridgeNetHook) ResolveEgress(flow *connect.EgressFlow) connect.EgressDecision {
	decision := self.inner.ResolveEgress(flow)
	self.host.record(func() {
		self.host.decisions = append(self.host.decisions, &BridgeNetDecision{
			SourceId:    flow.Source.SourceId,
			ProvideMode: flow.ProvideMode,
			Protocol:    flow.Protocol,
			To:          flow.To,
			Sealed:      flow.Sealed,
			Principal:   flow.Principal,
			Verdict:     decision.Verdict,
			Target:      decision.Target,
			Generation:  decision.PolicyGeneration,
			RuleTag:     decision.RuleTag,
		})
	})
	return decision
}

func (self *bridgeNetHook) PolicyGeneration() uint64 {
	return self.inner.PolicyGeneration()
}

func (self *bridgeNetHook) FriendsAndFamilyEgress() bool {
	return self.inner.FriendsAndFamilyEgress()
}

func (self *bridgeNetHook) BindFlowCloser(closer connect.EgressFlowCloser) (unbind func()) {
	if binder, ok := self.inner.(connect.EgressHookBinder); ok {
		return binder.BindFlowCloser(closer)
	}
	return func() {}
}

// One dial the host's NAT made upstream, and what its socket carried.
type BridgeNetDial struct {
	Network string
	Address string
	// Whether it waited at the gate.
	Held bool
	// Whether the dial gave a socket, the bytes the NAT wrote to it, and whether the NAT closed it.
	Connected        bool
	WrittenByteCount int
	Closed           bool
}

// What a host's NAT dials, counted, and the gate a test holds dials at (FS-56): a held dial waits for the gate to
// open, then completes against the real address whatever its flow's context says, as a dial already in the kernel
// would.
type bridgeNetDials struct {
	stateLock sync.Mutex
	dials     []*BridgeNetDial
	// open while dials hold; nil when none do
	gate chan struct{}
	// the dials waiting at the gate
	heldCount int
	// moves at each dial
	changes *connect.MonitorValue[int]
	// LAN hosts whose dials reach the upstream's loopback listeners (BridgeNetHost.AddLan)
	lanHosts map[netip.Addr]bool
}

// A host's upstream: a TCP and a UDP listener on loopback, each counting what reached it. The UDP listener answers
// each datagram with the same bytes.
type BridgeNetUpstream struct {
	tcp net.Listener
	udp net.PacketConn
	// the largest read each takes at once
	readByteCount int

	stateLock sync.Mutex
	accepts   []*BridgeNetAccept
	datagrams [][]byte
	// moves at each accept, read and datagram
	changes *connect.MonitorValue[int]
	workers sync.WaitGroup
}

// One TCP connection the upstream accepted and what reached it.
type BridgeNetAccept struct {
	Bytes  []byte
	Closed bool
}

func newBridgeNetUpstream(readByteCount int) (*BridgeNetUpstream, error) {
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		tcp.Close()
		return nil, err
	}
	self := &BridgeNetUpstream{tcp: tcp, udp: udp, readByteCount: readByteCount, changes: connect.NewMonitorValue(0)}
	self.workers.Add(2)
	go self.acceptTcp()
	go self.readUdp()
	return self, nil
}

func (self *BridgeNetUpstream) acceptTcp() {
	defer self.workers.Done()
	for {
		conn, err := self.tcp.Accept()
		if err != nil {
			return
		}
		accept := &BridgeNetAccept{}
		self.change(func() {
			self.accepts = append(self.accepts, accept)
		})
		self.workers.Add(1)
		go func() {
			defer self.workers.Done()
			defer conn.Close()
			buffer := make([]byte, self.readByteCount)
			for {
				n, err := conn.Read(buffer)
				if 0 < n {
					self.change(func() {
						accept.Bytes = append(accept.Bytes, buffer[:n]...)
					})
				}
				if err != nil {
					self.change(func() {
						accept.Closed = true
					})
					return
				}
			}
		}()
	}
}

func (self *BridgeNetUpstream) readUdp() {
	defer self.workers.Done()
	buffer := make([]byte, self.readByteCount)
	for {
		n, address, err := self.udp.ReadFrom(buffer)
		if err != nil {
			return
		}
		datagram := bytes.Clone(buffer[:n])
		self.change(func() {
			self.datagrams = append(self.datagrams, datagram)
		})
		self.udp.WriteTo(datagram, address)
	}
}

func (self *BridgeNetUpstream) change(change func()) {
	self.stateLock.Lock()
	change()
	self.stateLock.Unlock()
	self.changes.Update(func(count int) int { return count + 1 })
}

// The TCP listener's port and the UDP listener's.
func (self *BridgeNetUpstream) TcpPort() uint16 {
	return uint16(self.tcp.Addr().(*net.TCPAddr).Port)
}

func (self *BridgeNetUpstream) UdpPort() uint16 {
	return uint16(self.udp.LocalAddr().(*net.UDPAddr).Port)
}

// Copies of every connection accepted so far, oldest first.
func (self *BridgeNetUpstream) Accepts() []BridgeNetAccept {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	accepts := []BridgeNetAccept{}
	for _, accept := range self.accepts {
		accepts = append(accepts, BridgeNetAccept{Bytes: bytes.Clone(accept.Bytes), Closed: accept.Closed})
	}
	return accepts
}

// Copies of every datagram received so far, oldest first.
func (self *BridgeNetUpstream) Datagrams() [][]byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	datagrams := [][]byte{}
	for _, datagram := range self.datagrams {
		datagrams = append(datagrams, bytes.Clone(datagram))
	}
	return datagrams
}

// Waits until done holds of the upstream, false past timeout.
func (self *BridgeNetUpstream) WaitFor(timeout time.Duration, done func(accepts []BridgeNetAccept, datagrams [][]byte) bool) bool {
	deadline := time.After(timeout)
	for {
		_, changed := self.changes.Get()
		if done(self.Accepts(), self.Datagrams()) {
			return true
		}
		select {
		case <-changed:
		case <-deadline:
			return false
		}
	}
}

func (self *BridgeNetUpstream) close() {
	self.tcp.Close()
	self.udp.Close()
	self.workers.Wait()
}

// A host's own settings.
type BridgeNetHostSettings struct {
	// The host's own overlay address, which it files as its BridgeAddress; the zero address files none.
	Address netip.Addr
	// Whether the host provides FriendsAndFamily beside Network, as a share host does, so a contract in that mode
	// verifies and the hook decides it.
	ProvideFriendsAndFamily bool
	// Edits the component's settings, which start as its defaults with no compile delay.
	Component func(settings *sidecar.BridgeComponentSettings)
	// Edits the device role's settings, which start as DefaultBridgeSettings on the Net's clock.
	Bridge func(settings *device.BridgeSettings)
	// Where the shares' rows the host serves are fetched from (BridgeComponentArgs.ShareRows): no api serves these
	// networks' shares, so a share's world hands them in. Nil fetches none.
	ShareRows sidecar.BridgeShareRowSource
	// The device role's posture store, which a restart hands the next host to restore from; nil is a store of its own.
	PostureStore device.PostureStore
	// The upstream the host's flows reach, made and closed by the caller, so it can name the upstream's ports before
	// the host starts and hand a restarted host the same one; nil is an upstream of the host's own.
	Upstream *BridgeNetUpstream
}

// A host sidecar: its device role, the component that feeds it, its connect client and its upstream. See the file's
// comment.
type BridgeNetHost struct {
	bridgeNet *BridgeNet
	Device    *BridgeNetDevice
	Address   netip.Addr
	Client    *NetClient
	Bridge    *device.Bridge
	Upstream  *BridgeNetUpstream
	// The loopback listener standing for the daemon's own (§17.6's rule 0), which the component names.
	Daemon net.Listener

	ctx       context.Context
	cancel    context.CancelFunc
	follower  *sidecar.ConfigClient
	component *sidecar.BridgeComponent
	dials     *bridgeNetDials

	stateLock   sync.Mutex
	principals  []*BridgeNetPrincipal
	decisions   []*BridgeNetDecision
	revocations []*BridgeNetRevocation
	// the posture's pin at the bridge's last publish, read in its change callback
	adoptedPin *connect.MonitorValue[uint64]
	// moves at each principal or decision recorded
	records         *connect.MonitorValue[int]
	removeCallbacks []func()
	// whether the upstream is the host's own, which its close closes
	ownsUpstream bool
}

// Starts device as a host: files its address where settings name one, then builds its device role, its connect
// client and its component, and waits until the role enforces a state at the network's tip.
func (self *BridgeNet) StartHost(hostDevice *BridgeNetDevice, settings *BridgeNetHostSettings) *BridgeNetHost {
	self.t.Helper()
	if settings == nil {
		settings = &BridgeNetHostSettings{}
	}
	if settings.Address.IsValid() {
		self.FileAddress(hostDevice, settings.Address)
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
	fail := func(format string, args ...any) {
		host.Close()
		self.t.Fatalf(format, args...)
	}
	var err error
	if settings.Upstream != nil {
		host.Upstream = settings.Upstream
	} else {
		host.Upstream, err = newBridgeNetUpstream(self.settings.ReadByteCount)
		if err != nil {
			fail("the upstream: %v", err)
		}
		host.ownsUpstream = true
	}
	host.Daemon, err = net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		fail("the daemon's listener: %v", err)
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
	provideModes := map[protocol.ProvideMode]bool{protocol.ProvideMode_Network: true}
	if settings.ProvideFriendsAndFamily {
		provideModes[protocol.ProvideMode_FriendsAndFamily] = true
	}
	if err := self.waitClient(ctx, host.Client, provideModes); err != nil {
		fail("the host's client: %v", err)
	}

	bridgeSettings := device.DefaultBridgeSettings()
	bridgeSettings.Clock = self.net.Clock()
	if settings.Bridge != nil {
		settings.Bridge(bridgeSettings)
	}
	postureStore := settings.PostureStore
	if postureStore == nil {
		postureStore = newBridgeNetPostureStore()
	}
	host.Bridge, err = device.NewBridge(ctx, postureStore, nil, bridgeSettings)
	if err != nil {
		fail("the device role: %v", err)
	}
	host.removeCallbacks = append(host.removeCallbacks, host.Bridge.AddChangeCallback(func() {
		pin := host.Bridge.Decision().Pin.GetVersion()
		host.adoptedPin.Update(func(adopted uint64) uint64 { return max(adopted, pin) })
	}))

	// the bindings every device signed, in the store the component reads its cache from
	store, err := self.bindingStore()
	if err != nil {
		fail("the binding cache: %v", err)
	}

	componentSettings := sidecar.DefaultBridgeComponentSettings()
	componentSettings.CompileDelay = 0
	componentSettings.CompileMinInterval = 0
	natSettings := connect.DefaultLocalUserNatSettings()
	dialSettings := &connect.DialContextSettings{DialContext: host.dials.dial}
	natSettings.TcpBufferSettings.DialContextSettings = dialSettings
	natSettings.UdpBufferSettings.DialContextSettings = dialSettings
	componentSettings.Nat = natSettings
	if settings.Component != nil {
		settings.Component(componentSettings)
	}
	host.follower = self.admission.Follower()
	identity := &sidecar.SidecarIdentity{
		NetworkId:         self.NetworkId(),
		SidecarId:         hostDevice.SidecarId(),
		ClientId:          sidecar.Id(hostDevice.ClientId),
		Generation:        1,
		IdentityPublicKey: hostDevice.Device.PublicKey(),
		ClientPublicKey:   bytes.Clone(hostDevice.ClientPublicKey),
	}
	daemonAddress := host.Daemon.Addr().String()
	host.component, err = sidecar.NewBridgeComponent(ctx, &sidecar.BridgeComponentArgs{
		NetworkId: self.NetworkId(),
		Identity:  func() *sidecar.SidecarIdentity { return identity },
		Config:    host.follower,
		Heads:     self.admission.heads,
		Rows:      self.rows,
		RepoKeyAt: func(generation uint64) *sidecar.EvsRepoKey {
			if generation == self.configKey.Generation() {
				return self.configKey
			}
			return nil
		},
		DaemonListeners: func() []string { return []string{daemonAddress} },
		AclLocal: func() *sidecar.AclLocalPolicy {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.aclLocal
		},
		ShareRows: settings.ShareRows,
		Clock:     self.net.Clock(),
		Log:       sidecar.NewNoopLogger(),
		Settings:  componentSettings,
	})
	if err != nil {
		fail("the component: %v", err)
	}
	// the generation first, so its store's bindings load before the role's first compile
	if err := host.component.Attach(&sidecar.SidecarEnv{Ctx: ctx, Client: host.Client.Client, Store: store.Root(), Log: sidecar.NewNoopLogger()}); err != nil {
		fail("the generation: %v", err)
	}
	sink := &bridgeNetSink{
		bridge: host.Bridge,
		hook:   &bridgeNetHook{inner: host.Bridge.EgressHook(), host: host},
		revoked: func(revocation *BridgeNetRevocation) {
			host.record(func() {
				host.revocations = append(host.revocations, revocation)
			})
		},
	}
	if err := host.component.SetDeviceRole(sink); err != nil {
		fail("the device role: %v", err)
	}
	self.stateLock.Lock()
	self.hosts = append(self.hosts, host)
	self.stateLock.Unlock()
	host.WaitAdopted(self.admission.Tip().GetVersion())
	return host
}

// Ends the host's generation, its component, its role and its upstream. Idempotent.
func (self *BridgeNetHost) Close() {
	self.cancel()
	for _, remove := range self.removeCallbacks {
		remove()
	}
	self.removeCallbacks = nil
	if self.component != nil {
		self.component.Close()
	}
	if self.Bridge != nil {
		self.Bridge.Close()
	}
	if self.follower != nil {
		self.follower.Close()
	}
	self.dials.open()
	if self.Upstream != nil && self.ownsUpstream {
		self.Upstream.close()
	}
	if self.Daemon != nil {
		self.Daemon.Close()
	}
}

// Waits until the host's follower stands at n, the role has published what it holds at or past n, the component has
// compiled at or past the newest entry through n that wants a compile (all but a pure denial, which reaches the role
// as a delta and through Bridge.Revoke), and the generation's provider serves: then a flow meets what n holds. Fails
// the test past WaitTimeout.
func (self *BridgeNetHost) WaitAdopted(n uint64) {
	t := self.bridgeNet.t
	t.Helper()
	ctx, cancel := context.WithTimeout(self.ctx, self.bridgeNet.settings.WaitTimeout)
	defer cancel()
	if _, err := self.follower.WaitFor(ctx, n); err != nil {
		t.Fatalf("%s's follower did not reach %d: %v", self.Device.Name, n, err)
	}
	compileAt := uint64(0)
	for _, read := range self.follower.BridgeEntries(1, n) {
		if !read.Pure {
			compileAt = read.N
		}
	}
	for {
		adopted, changed := self.adoptedPin.Get()
		status := self.component.Status()
		if n <= adopted && compileAt <= status.CompiledPin.GetVersion() && status.Serving {
			return
		}
		select {
		case <-changed:
		case <-time.After(self.bridgeNet.settings.PollInterval):
			// the component's compile and serving move without a callback of the bridge's
		case <-ctx.Done():
			t.Fatalf("%s adopted %d, not %d, compiled at %d, not %d: %+v", self.Device.Name, adopted, n, status.CompiledPin.GetVersion(), compileAt, status)
		}
	}
}

// The state the role enforces, nil for none.
func (self *BridgeNetHost) State() *bridge.BridgeState {
	return self.Bridge.Decision().BridgeState
}

// The rules of the state the role enforces, nil for none. Fails the test on rules that do not parse.
func (self *BridgeNetHost) Rules() *bridge.BridgeRules {
	t := self.bridgeNet.t
	t.Helper()
	state := self.State()
	if state == nil {
		return nil
	}
	rules := &bridge.BridgeRules{}
	if err := proto.Unmarshal(state.GetRules(), rules); err != nil {
		t.Fatalf("the state's rules: %v", err)
	}
	return rules
}

// What the host's component reports: its compiles and the alarms they raised.
func (self *BridgeNetHost) ComponentStatus() sidecar.BridgeComponentStatus {
	return self.component.Status()
}

func (self *BridgeNetHost) record(record func()) {
	self.stateLock.Lock()
	record()
	self.stateLock.Unlock()
	self.records.Update(func(count int) int { return count + 1 })
}

// Waits until the component has handed the role a denial at n through Bridge.Revoke, and answers it. Fails the test
// past WaitTimeout.
func (self *BridgeNetHost) WaitRevoked(n uint64) *BridgeNetRevocation {
	t := self.bridgeNet.t
	t.Helper()
	deadline := time.After(self.bridgeNet.settings.WaitTimeout)
	for {
		_, changed := self.records.Get()
		found := func() *BridgeNetRevocation {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			for _, revocation := range self.revocations {
				if revocation.N == n {
					copied := *revocation
					return &copied
				}
			}
			return nil
		}()
		if found != nil {
			return found
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("%s was handed no denial at %d", self.Device.Name, n)
			return nil
		}
	}
}

// Every decision the hook made, oldest first.
func (self *BridgeNetHost) AllDecisions() []*BridgeNetDecision {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	decisions := []*BridgeNetDecision{}
	for _, decision := range self.decisions {
		copied := *decision
		decisions = append(decisions, &copied)
	}
	return decisions
}

// Waits until the hook has made count decisions of flows from sourceId, and answers them. Fails the test past
// WaitTimeout.
func (self *BridgeNetHost) WaitDecisionCount(sourceId connect.Id, count int) []*BridgeNetDecision {
	t := self.bridgeNet.t
	t.Helper()
	deadline := time.After(self.bridgeNet.settings.WaitTimeout)
	for {
		_, changed := self.records.Get()
		if decisions := self.Decisions(sourceId); count <= len(decisions) {
			return decisions
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("%s's hook made %d decisions of %s's flows, not %d", self.Device.Name, len(self.Decisions(sourceId)), sourceId, count)
			return nil
		}
	}
}

// Every decision the hook made of a flow from sourceId, oldest first.
func (self *BridgeNetHost) Decisions(sourceId connect.Id) []*BridgeNetDecision {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	decisions := []*BridgeNetDecision{}
	for _, decision := range self.decisions {
		if decision.SourceId == sourceId {
			copied := *decision
			decisions = append(decisions, &copied)
		}
	}
	return decisions
}

// Every principal the hook answered for a contract of sourceId, oldest first.
func (self *BridgeNetHost) Principals(sourceId connect.Id) []*BridgeNetPrincipal {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	principals := []*BridgeNetPrincipal{}
	for _, principal := range self.principals {
		if principal.SourceId == sourceId {
			copied := *principal
			principals = append(principals, &copied)
		}
	}
	return principals
}

// Waits until the hook has decided a flow of protocol from sourceId, and answers that decision. Fails the test past
// WaitTimeout.
func (self *BridgeNetHost) WaitDecision(sourceId connect.Id, ipProtocol connect.IpProtocol) *BridgeNetDecision {
	t := self.bridgeNet.t
	t.Helper()
	deadline := time.After(self.bridgeNet.settings.WaitTimeout)
	for {
		_, changed := self.records.Get()
		for _, decision := range self.Decisions(sourceId) {
			if decision.Protocol == ipProtocol {
				return decision
			}
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("%s's hook decided no %s flow of %s", self.Device.Name, ipProtocol, sourceId)
			return nil
		}
	}
}

// Every dial the NAT made upstream so far.
func (self *BridgeNetHost) Dials() []BridgeNetDial {
	self.dials.stateLock.Lock()
	defer self.dials.stateLock.Unlock()
	dials := []BridgeNetDial{}
	for _, dial := range self.dials.dials {
		dials = append(dials, *dial)
	}
	return dials
}

// Holds every later dial at a gate until OpenDials, so a flow resolves and its dial waits (FS-56's barrier).
func (self *BridgeNetHost) HoldDials() {
	self.dials.stateLock.Lock()
	defer self.dials.stateLock.Unlock()
	if self.dials.gate == nil {
		self.dials.gate = make(chan struct{})
	}
}

// Stands the upstream's loopback listeners in for a host at lan on a LAN this host reaches: a dial to lan at a port
// reaches loopback at that port, the TCP or UDP listener, and is counted under lan.
func (self *BridgeNetHost) AddLan(lan netip.Addr) {
	self.dials.stateLock.Lock()
	defer self.dials.stateLock.Unlock()
	self.dials.lanHosts[lan] = true
}

// Lets every held dial go on.
func (self *BridgeNetHost) OpenDials() {
	self.dials.open()
}

// Waits until done holds of the dials made so far, false past WaitTimeout.
func (self *BridgeNetHost) WaitDials(done func(dials []BridgeNetDial) bool) bool {
	deadline := time.After(self.bridgeNet.settings.WaitTimeout)
	for {
		_, changed := self.dials.changes.Get()
		if done(self.Dials()) {
			return true
		}
		select {
		case <-changed:
		case <-deadline:
			return false
		}
	}
}

// Waits until count dials wait at the gate. Fails the test past WaitTimeout.
func (self *BridgeNetHost) WaitHeldDials(count int) {
	t := self.bridgeNet.t
	t.Helper()
	deadline := time.After(self.bridgeNet.settings.WaitTimeout)
	for {
		_, changed := self.dials.changes.Get()
		held := func() int {
			self.dials.stateLock.Lock()
			defer self.dials.stateLock.Unlock()
			return self.dials.heldCount
		}()
		if count <= held {
			return
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("%d dials held, not %d", held, count)
		}
	}
}

// connect.DialContextFunction: counts the dial, waits at the gate if one is up, then dials. A held dial completes
// whatever its context says, as one the kernel has taken.
func (self *bridgeNetDials) dial(ctx context.Context, network string, address string) (net.Conn, error) {
	record := &BridgeNetDial{Network: network, Address: address}
	gate, dialAddress := func() (chan struct{}, string) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.dials = append(self.dials, record)
		if self.gate != nil {
			record.Held = true
			self.heldCount += 1
		}
		if addressPort, err := netip.ParseAddrPort(address); err == nil && self.lanHosts[addressPort.Addr()] {
			return self.gate, netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), addressPort.Port()).String()
		}
		return self.gate, address
	}()
	self.changes.Update(func(count int) int { return count + 1 })
	dialCtx := ctx
	if gate != nil {
		<-gate
		dialCtx = context.Background()
	}
	conn, err := (&net.Dialer{}).DialContext(dialCtx, network, dialAddress)
	if err != nil {
		return nil, err
	}
	self.update(func() {
		record.Connected = true
	})
	return &bridgeNetConn{Conn: conn, record: record, dials: self}, nil
}

// Changes a dial's record under the lock, and moves the monitor.
func (self *bridgeNetDials) update(change func()) {
	self.stateLock.Lock()
	change()
	self.stateLock.Unlock()
	self.changes.Update(func(count int) int { return count + 1 })
}

// An upstream socket, counting what the NAT writes to it and when it closes. The NAT's optional socket tuning, which
// asks for a *net.TCPConn or *net.UDPConn, does not apply to it; its half close does.
type bridgeNetConn struct {
	net.Conn
	record *BridgeNetDial
	dials  *bridgeNetDials
}

func (self *bridgeNetConn) Write(data []byte) (int, error) {
	n, err := self.Conn.Write(data)
	self.dials.update(func() {
		self.record.WrittenByteCount += n
	})
	return n, err
}

func (self *bridgeNetConn) Close() error {
	err := self.Conn.Close()
	self.dials.update(func() {
		self.record.Closed = true
	})
	return err
}

func (self *bridgeNetConn) CloseWrite() error {
	if closeWriter, ok := self.Conn.(interface{ CloseWrite() error }); ok {
		return closeWriter.CloseWrite()
	}
	return nil
}

func (self *bridgeNetDials) open() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.gate != nil {
		close(self.gate)
		self.gate = nil
		self.heldCount = 0
	}
}

// How a window is built.
type BridgeNetWindowArgs struct {
	// The window's own provide mode on its link: Network, the zero value's reading, or FriendsAndFamily.
	ProvideMode protocol.ProvideMode
	// Edits the honest delegation before it is signed: the subject's, over this window client and its key, to the
	// host, lapsing DelegationLifetime past the Net's clock.
	Edit func(delegation *bridge.WindowDelegation)
	// Signs the delegation with this key in place of the subject's identity key.
	SignKey ed25519.PrivateKey
	// Carries no delegation at all.
	NoDelegation bool
	// The operator mints every contract the window asks for (Net.MintContract), from what this answers for each
	// request; nil takes the platform's. A minted window is a client of its own on the platform, no subject's child,
	// so the platform answers the host's return contracts to it as the operator's platform would.
	Mint func(window *BridgeNetWindow, request *protocol.CreateContract) *MintContractArgs
	// The window's client runs with encryption off, the unsealed peer I-3 shuts out (§22.7's unsealed-peer assert):
	// the one client the world attaches that is not Required.
	Unsealed bool
	// A public client of this exit's in place of a window to a host: Public, with no delegation. Its own client's policy
	// judges what it sends first, as every public client's does: it refuses a destination that is not public before
	// the exit sees it, and sends 100.64/10, which it counts public until a release drops it.
	Exit *BridgeNetExit
	// The network the platform registers the window client in, and its parent there, for a window whose subject is no
	// device of this network, another network's sidecar on a share (BridgeShareNet): zero and nil are this network
	// and the subject's own client. Unused for a minted window.
	NetworkId      sidecar.Id
	ParentClientId *connect.Id
	// Signs the window's delegation itself, given the window with its client, in place of the subject's identity key:
	// a share's, by a ShareSigner. Edit and SignKey are then unused.
	Sign func(window *BridgeNetWindow) []byte
}

// A window client to one host. See the file's comment.
type BridgeNetWindow struct {
	bridgeNet   *BridgeNet
	Name        string
	Subject     *BridgeNetDevice
	Host        *BridgeNetHost
	Client      *NetClient
	ProvideMode protocol.ProvideMode
	// The Signed WindowDelegation it carries, nil for none.
	Delegation []byte

	ctx       context.Context
	cancel    context.CancelFunc
	natClient *connect.RemoteUserNatClient
	tun       *connect.Tun
	source    netip.Addr
	workers   sync.WaitGroup

	stateLock sync.Mutex
	// the echo replies received, by sequence number
	echoReplies map[uint16]bool
	echoes      *connect.MonitorValue[int]
	echoId      uint16
}

// Opens a window client of subject's to host, sending from a userspace stack of its own. args nil is the honest
// window: registered as the subject's child, carrying the delegation the subject's identity key signed for it.
func (self *BridgeNet) OpenWindow(name string, subject *BridgeNetDevice, host *BridgeNetHost, args *BridgeNetWindowArgs) *BridgeNetWindow {
	self.t.Helper()
	if args == nil {
		args = &BridgeNetWindowArgs{}
	}
	provideMode := args.ProvideMode
	if provideMode == protocol.ProvideMode_None {
		provideMode = protocol.ProvideMode_Network
	}
	destination := func() *NetClient {
		if args.Exit != nil {
			return args.Exit.Client
		}
		return host.Client
	}()
	if args.Exit != nil {
		provideMode = protocol.ProvideMode_Public
		noDelegation := *args
		noDelegation.NoDelegation = true
		args = &noDelegation
	}
	ctx, cancel := context.WithCancel(self.net.Context())
	window := &BridgeNetWindow{
		bridgeNet:   self,
		Name:        name,
		Subject:     subject,
		Host:        host,
		ProvideMode: provideMode,
		ctx:         ctx,
		cancel:      cancel,
		echoReplies: map[uint16]bool{},
		echoes:      connect.NewMonitorValue(0),
	}
	fail := func(format string, args ...any) {
		window.Close()
		self.t.Fatalf(format, args...)
	}
	var clientId connect.Id
	var control *bridgeNetControl
	if args.Mint == nil {
		networkId := self.NetworkId()
		if args.NetworkId != (sidecar.Id{}) {
			networkId = args.NetworkId
		}
		var parentClientId connect.Id
		switch {
		case args.ParentClientId != nil:
			parentClientId = *args.ParentClientId
		case subject != nil:
			parentClientId = subject.ClientId
		default:
			fail("the window %s has neither a subject nor a parent", name)
		}
		var err error
		clientId, err = self.platform.AddClient(ctx, &BridgeNetClientArgs{Name: name, NetworkId: networkId, ParentClientId: &parentClientId})
		if err != nil {
			fail("the window client: %v", err)
		}
		control = &bridgeNetControl{ctx: ctx, clientId: clientId, platform: self.platform, workers: self.controls}
	} else {
		// the operator's own client, which the platform it runs answers for, so the host's return contracts reach it
		var err error
		clientId, err = self.platform.AddClient(ctx, &BridgeNetClientArgs{Name: name, NetworkId: self.NetworkId()})
		if err != nil {
			fail("the operator's client: %v", err)
		}
		self.stateLock.Lock()
		self.mintedClientIds[clientId] = true
		self.stateLock.Unlock()
		control = &bridgeNetControl{ctx: ctx, clientId: clientId, platform: self.platform, workers: self.controls,
			mint: func(request *protocol.CreateContract) (*protocol.CreateContractResult, bool, error) {
				mintArgs := args.Mint(window, request)
				if mintArgs == nil {
					refused := protocol.ContractError_NoPermission
					return &protocol.CreateContractResult{Error: &refused, CreateContract: request}, true, nil
				}
				contract, err := self.net.MintContract(mintArgs)
				if err != nil {
					return nil, true, err
				}
				return &protocol.CreateContractResult{Contract: contract, CreateContract: request}, true, nil
			},
		}
	}
	echoSeed := sha256.Sum256([]byte("bridge net echo " + name))
	window.echoId = binary.BigEndian.Uint16(echoSeed[:2])
	if args.Unsealed {
		clientSettings := netClientSettings()
		clientSettings.EncryptionSettings.Mode = connect.EncryptionModeOff
		window.Client = self.net.exchange.attachClient(ctx, name, clientId, clientSettings, control)
	} else {
		window.Client = self.net.exchange.addClientWithControl(ctx, name, clientId, netClientSettings(), control)
	}
	if !args.NoDelegation && args.Sign != nil {
		window.Delegation = args.Sign(window)
		window.Client.Client.ContractManager().SetWindowDelegation(window.Delegation)
	} else if !args.NoDelegation {
		subjectId := sidecar.Id{}
		if subject != nil {
			subjectId = subject.SidecarId()
		}
		delegation := &bridge.WindowDelegation{
			NetworkId:             self.NetworkId().Bytes(),
			SubjectSidecarId:      subjectId.Bytes(),
			WindowClientId:        clientId.Bytes(),
			WindowClientPublicKey: window.Client.Client.ClientKeyManager().PublicKey(),
			TargetSidecarId:       host.Device.SidecarId().Bytes(),
			NotAfterMs:            self.net.Clock().Now().Add(self.settings.DelegationLifetime).UnixMilli(),
		}
		if args.Edit != nil {
			args.Edit(delegation)
		}
		signKey := args.SignKey
		if signKey == nil && subject != nil {
			signKey = subject.Device.Key
		}
		window.Delegation = self.SignDelegation(delegation, signKey)
		window.Client.Client.ContractManager().SetWindowDelegation(window.Delegation)
	}
	// its provide modes, for its host's return contracts, and its key, with the platform before its first send
	if err := self.waitClient(ctx, window.Client, map[protocol.ProvideMode]bool{protocol.ProvideMode_Network: true}); err != nil {
		fail("the window's client: %v", err)
	}

	tunSettings := connect.DefaultTunSettingsWithBufferSize(64)
	tunSettings.Log = connect.NewNoopLogger()
	tun, err := connect.CreateTun(ctx, tunSettings)
	if err != nil {
		fail("the window's stack: %v", err)
	}
	window.tun = tun
	for _, address := range tun.LocalAddresses() {
		if address.Is4() {
			window.source = address
		}
	}
	destinationHop, err := connect.NewMultiHopId(destination.ClientId)
	if err != nil {
		fail("the destination's hop: %v", err)
	}
	window.natClient = connect.NewRemoteUserNatClient(window.Client.Client, window.receive, []connect.MultiHopId{destinationHop}, provideMode)
	window.workers.Add(1)
	go window.pump()
	self.stateLock.Lock()
	self.windows = append(self.windows, window)
	self.stateLock.Unlock()
	return window
}

// A return contract from sourceId to one of the operator's clients, minted as the operator's platform would answer it,
// sealed with the destination's own seals and no delegation; minted false for any other destination, which the
// platform answers. The operator mints its own clients' contracts both ways, so a minted window's session forms and its
// flows reach the host's checks, where they are refused (FS-38).
func (self *BridgeNet) mintReturn(sourceId connect.Id, request *protocol.CreateContract) (*protocol.CreateContractResult, bool, error) {
	destinationId, err := connect.IdFromBytes(request.GetDestinationId())
	if err != nil {
		return nil, false, nil
	}
	self.stateLock.Lock()
	minted := self.mintedClientIds[destinationId]
	self.stateLock.Unlock()
	if !minted {
		return nil, false, nil
	}
	networkId := connect.Id(self.NetworkId())
	contract, err := self.net.MintContract(&MintContractArgs{
		SourceId:              sourceId,
		DestinationId:         destinationId,
		ProvideMode:           protocol.ProvideMode_Network,
		SourceSubjectClientId: &destinationId,
		SourceNetworkId:       &networkId,
		ContractClass:         protocol.ContractClass_ContractClassData,
		TransferByteCount:     max(request.GetTransferByteCount(), self.settings.ContractByteCount),
	})
	if err != nil {
		return nil, true, err
	}
	return &protocol.CreateContractResult{Contract: contract, CreateContract: request}, true, nil
}

// delegation's Signed bytes, as bridge.WindowDelegationSigned writes them, signed by key as the subject's id signs.
func (self *BridgeNet) SignDelegation(delegation *bridge.WindowDelegation, key ed25519.PrivateKey) []byte {
	self.t.Helper()
	signed, err := bridge.WindowDelegationSigned(delegation, func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
		return &bridge.Signed{
			Body:      body,
			SignerId:  bytes.Clone(delegation.GetSubjectSidecarId()),
			Signature: ed25519.Sign(key, bridge.SignedBytes(purpose, signedType, body)),
			Type:      uint32(signedType),
		}, nil
	}, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	return signed
}

// Reads the stack's packets into the link until the window closes.
func (self *BridgeNetWindow) pump() {
	defer self.workers.Done()
	source := connect.SourceId(self.Client.ClientId)
	for {
		packet, err := self.tun.Read()
		if err != nil {
			return
		}
		if !self.natClient.SendPacket(source, self.ProvideMode, packet, self.bridgeNet.settings.SendTimeout) {
			connect.MessagePoolReturn(packet)
		}
	}
}

// connect.ReceivePacketFunction: an echo reply is counted here, everything else goes into the stack. Borrows the
// packet; the stack's write copies it (the device-side tun write, CODESTYLE's callback exception).
func (self *BridgeNetWindow) receive(source connect.TransferPath, provideMode protocol.ProvideMode, ipPath *connect.IpPath, packet []byte) {
	if ipPath != nil && ipPath.Protocol == connect.IpProtocolIcmp {
		if sequence, ok := bridgeNetEchoReply(packet, self.echoId); ok {
			self.stateLock.Lock()
			self.echoReplies[sequence] = true
			self.stateLock.Unlock()
			self.echoes.Update(func(count int) int { return count + 1 })
		}
		return
	}
	self.tun.Write(packet)
}

// Ends the window's stack, link and client. Idempotent.
func (self *BridgeNetWindow) Close() {
	self.cancel()
	if self.tun != nil {
		self.tun.Close()
	}
	self.workers.Wait()
	if self.natClient != nil {
		self.natClient.Close()
	}
	if self.Client != nil {
		self.Client.Client.Cancel()
	}
}

// The window's address in its own stack, the source the host sees.
func (self *BridgeNetWindow) Source() netip.Addr {
	return self.source
}

// A TCP connection through the window to address, its error if the host refuses it.
func (self *BridgeNetWindow) DialTcp(address netip.AddrPort) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(self.ctx, self.bridgeNet.settings.WaitTimeout)
	defer cancel()
	return self.tun.DialContext(ctx, "tcp4", address.String())
}

// payload sent to address over UDP through the window, and the answer read back within timeout, nil with an error
// when none came.
func (self *BridgeNetWindow) ExchangeUdp(address netip.AddrPort, payload []byte, timeout time.Duration) ([]byte, error) {
	conn, err := self.SendUdp(address, payload)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(timeout))
	buffer := make([]byte, self.bridgeNet.settings.ReadByteCount)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}
	return bytes.Clone(buffer[:n]), nil
}

// payload sent to address over UDP through the window; the caller closes the socket it answers.
func (self *BridgeNetWindow) SendUdp(address netip.AddrPort, payload []byte) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(self.ctx, self.bridgeNet.settings.WaitTimeout)
	defer cancel()
	conn, err := self.tun.DialContext(ctx, "udp4", address.String())
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(payload); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// An ICMP echo request to address, sequence its number, sent through the window's link.
func (self *BridgeNetWindow) SendEcho(address netip.Addr, sequence uint16) error {
	packet := bridgeNetEchoRequest(self.source, address, self.echoId, sequence)
	pooled := connect.MessagePoolGet(len(packet))
	copy(pooled, packet)
	if !self.natClient.SendPacket(connect.SourceId(self.Client.ClientId), self.ProvideMode, pooled, self.bridgeNet.settings.SendTimeout) {
		connect.MessagePoolReturn(pooled)
		return errors.New("the window refused the echo")
	}
	return nil
}

// A TCP SYN to address from the window's own address, built by hand and sent through the window's link: a peer whose
// session never forms gets no answer a stack would wait out.
func (self *BridgeNetWindow) SendSyn(address netip.AddrPort) error {
	packet := bridgeNetSyn(netip.AddrPortFrom(self.source, 40000), address)
	pooled := connect.MessagePoolGet(len(packet))
	copy(pooled, packet)
	if !self.natClient.SendPacket(connect.SourceId(self.Client.ClientId), self.ProvideMode, pooled, self.bridgeNet.settings.SendTimeout) {
		connect.MessagePoolReturn(pooled)
		return errors.New("the window refused the SYN")
	}
	return nil
}

// Waits for the reply to the echo of sequence, false past timeout.
func (self *BridgeNetWindow) WaitEchoReply(sequence uint16, timeout time.Duration) bool {
	deadline := time.After(timeout)
	for {
		_, changed := self.echoes.Get()
		if self.EchoReplied(sequence) {
			return true
		}
		select {
		case <-changed:
		case <-deadline:
			return false
		}
	}
}

// Whether the echo of sequence was answered.
func (self *BridgeNetWindow) EchoReplied(sequence uint16) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.echoReplies[sequence]
}

// An IPv4 ICMP echo request from source to destination, with its checksums.
func bridgeNetEchoRequest(source netip.Addr, destination netip.Addr, id uint16, sequence uint16) []byte {
	payload := []byte("bridge net echo payload")
	icmp := make([]byte, 8+len(payload))
	icmp[0] = 8
	binary.BigEndian.PutUint16(icmp[4:6], id)
	binary.BigEndian.PutUint16(icmp[6:8], sequence)
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:4], bridgeNetChecksum(icmp))
	packet := make([]byte, 20+len(icmp))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 1
	sourceOctets := source.As4()
	copy(packet[12:16], sourceOctets[:])
	destinationOctets := destination.As4()
	copy(packet[16:20], destinationOctets[:])
	binary.BigEndian.PutUint16(packet[10:12], bridgeNetChecksum(packet[:20]))
	copy(packet[20:], icmp)
	return packet
}

// An IPv4 TCP SYN from source to destination, with its checksums.
func bridgeNetSyn(source netip.AddrPort, destination netip.AddrPort) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], source.Port())
	binary.BigEndian.PutUint16(tcp[2:4], destination.Port())
	binary.BigEndian.PutUint32(tcp[4:8], 1)
	tcp[12] = 0x50
	tcp[13] = 0x02
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	sourceOctets := source.Addr().As4()
	destinationOctets := destination.Addr().As4()
	pseudo := append(append(append([]byte{}, sourceOctets[:]...), destinationOctets[:]...), 0, 6, 0, byte(len(tcp)))
	binary.BigEndian.PutUint16(tcp[16:18], bridgeNetChecksum(append(pseudo, tcp...)))
	packet := make([]byte, 20+len(tcp))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 6
	copy(packet[12:16], sourceOctets[:])
	copy(packet[16:20], destinationOctets[:])
	binary.BigEndian.PutUint16(packet[10:12], bridgeNetChecksum(packet[:20]))
	copy(packet[20:], tcp)
	return packet
}

// The sequence of an IPv4 echo reply to id, false for anything else.
func bridgeNetEchoReply(packet []byte, id uint16) (uint16, bool) {
	if len(packet) < 20 || packet[0]>>4 != 4 || packet[9] != 1 {
		return 0, false
	}
	headerLength := int(packet[0]&0x0f) * 4
	if len(packet) < headerLength+8 || packet[headerLength] != 0 || binary.BigEndian.Uint16(packet[headerLength+4:]) != id {
		return 0, false
	}
	return binary.BigEndian.Uint16(packet[headerLength+6:]), true
}

// The internet checksum of data.
func bridgeNetChecksum(data []byte) uint16 {
	sum := uint32(0)
	for index := 0; index+1 < len(data); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[index:]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for 0xffff < sum {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum)
}

// The host's overlay address in S8, in BridgeNet's default block's lower /17, and the LAN behind it.
var (
	bridgeScenarioHostAddress  = netip.MustParseAddr("100.80.7.20")
	bridgeScenarioLanPrefix    = netip.MustParsePrefix("192.0.2.0/24")
	bridgeScenarioLanAddress   = netip.MustParseAddr("192.0.2.10")
	bridgeScenarioOtherAddress = netip.MustParseAddr("192.168.9.10")
)

// The document S8 saves: every member device routes the LAN through a member device that serves it, with no dial
// anywhere. A route rule with no via opens nothing yet (question acl-m2-17-no-via-route-advertisers), so it names one.
const bridgeScenarioS8Policy = `{"grants": [{"src": ["autogroup:member"], "dst": ["ip:192.0.2.0/24"], "via": ["autogroup:member"], "allow": ["route"]}]}`

// S8 (§22.7; §3.7's F7, reach a subnet; R-BRIDGE-3, R-BRIDGE-7, R-BRIDGE-10, D-BRIDGE-3, D-BRIDGE-6, I-10): rules only
// from the config repo, decided at the host per flow. A member device's window client, its delegation its own, sends
// from a userspace stack to a member host whose address, block, route and document are all statements and heads of
// the network's config, compiled by the host's component:
//
//   - with no document, an untagged source reaches the host's loopback service through the host's address and the
//     LAN, any of it, but never the daemon's own listener (rule 0, D-BRIDGE-19);
//   - once a document exists, the LAN by rule alone: the routed /24 the host serves under a standing route rule passes,
//     another LAN address, the loopback service no dial rule opens, and the daemon's listener are refused;
//   - a SidecarRevoke resets the subject's live connection at once, no byte after it reaching the target.
//
// settings nil is T2's; server's T3 hands its platform. Payloads and the route's site are canaries, and the host's
// addresses and the LAN are forbidden values, so the harness's scan finds them nowhere a server saw.
func BridgeScenarioS8(settings *BridgeNetSettings) *Scenario {
	return &Scenario{Id: "S8", Run: func(ctx context.Context, run *ScenarioRun) error {
		return bridgeNetCatch(func() error {
			return bridgeScenarioS8(run, settings)
		})
	}}
}

func bridgeScenarioS8(run *ScenarioRun, settings *BridgeNetSettings) error {
	world := NewBridgeNet(bridgeNetFailer{}, run.Net, settings)
	defer world.Close()
	capture := run.Net.Capture()
	hostDevice := world.AddDevice("s8 host")
	subject := world.AddDevice("s8 subject")
	host := world.StartHost(hostDevice, &BridgeNetHostSettings{Address: bridgeScenarioHostAddress})
	host.AddLan(bridgeScenarioLanAddress)
	host.AddLan(bridgeScenarioOtherAddress)
	for _, text := range []string{bridgeScenarioHostAddress.String(), bridgeScenarioLanAddress.String(), bridgeScenarioOtherAddress.String(), bridgeScenarioLanPrefix.String()} {
		capture.Forbid("an address "+text, []byte(text))
	}
	window := world.OpenWindow("s8 window", subject, host, nil)
	tcp := func(address netip.Addr) netip.AddrPort {
		return netip.AddrPortFrom(address, host.Upstream.TcpPort())
	}
	daemon := netip.AddrPortFrom(host.Address, uint16(host.Daemon.Addr().(*net.TCPAddr).Port))
	waitTimeout := world.Settings().WaitTimeout
	// a connection that carries a canary to its target, and the hook's decision of it
	opens := func(clause string, address netip.AddrPort, verdict connect.EgressVerdict) error {
		before := len(host.Decisions(window.Client.ClientId))
		payload := run.Canary("bridge payload")
		conn, err := window.DialTcp(address)
		if err != nil {
			return fmt.Errorf("%s: %w", clause, err)
		}
		_, err = conn.Write(payload)
		conn.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", clause, err)
		}
		if !host.Upstream.WaitFor(waitTimeout, func(accepts []BridgeNetAccept, datagrams [][]byte) bool {
			return slices.ContainsFunc(accepts, func(accept BridgeNetAccept) bool { return bytes.Equal(accept.Bytes, payload) })
		}) {
			return fmt.Errorf("%s: the payload never reached its target", clause)
		}
		decision := host.WaitDecisionCount(window.Client.ClientId, before+1)[before]
		if decision.Verdict != verdict {
			return fmt.Errorf("%s: decided %s, not %s", clause, decision.Verdict, verdict)
		}
		return nil
	}
	// a connection the host refuses, every decision of it a denial
	refused := func(clause string, address netip.AddrPort) error {
		before := len(host.Decisions(window.Client.ClientId))
		if conn, err := window.DialTcp(address); err == nil {
			conn.Close()
			return fmt.Errorf("%s: the connection opened", clause)
		}
		for _, decision := range host.WaitDecisionCount(window.Client.ClientId, before+1)[before:] {
			if decision.Opens() {
				return fmt.Errorf("%s: decided %+v", clause, decision)
			}
		}
		return nil
	}

	if err := opens("no document, the host's loopback service", tcp(host.Address), connect.EgressVerdictMap); err != nil {
		return err
	}
	if err := refused("no document, the daemon's own listener", daemon); err != nil {
		return err
	}
	if err := opens("no document, the LAN", tcp(bridgeScenarioLanAddress), connect.EgressVerdictPass); err != nil {
		return err
	}
	if err := opens("no document, another LAN address", tcp(bridgeScenarioOtherAddress), connect.EgressVerdictPass); err != nil {
		return err
	}

	plan := world.SaveAclPolicy(bridgeScenarioS8Policy)
	if !plan.Rows.GetHasDocument() {
		return errors.New("the saved head holds no document")
	}
	world.FileRoute(hostDevice, bridgeScenarioLanPrefix, [][]byte{BridgeNetRouteRuleId(bridgeNetFailer{}, plan)}, run.Canary("bridge route site"))
	world.Follow()
	if err := opens("a document, the routed LAN", tcp(bridgeScenarioLanAddress), connect.EgressVerdictPass); err != nil {
		return err
	}
	if err := refused("a document, a LAN address no rule routes", tcp(bridgeScenarioOtherAddress)); err != nil {
		return err
	}
	if err := refused("a document, the loopback service no dial rule opens", tcp(host.Address)); err != nil {
		return err
	}
	if err := refused("a document, the daemon's own listener", daemon); err != nil {
		return err
	}

	// revoke resets: the live connection's target sees nothing after the revocation, and its upstream socket closes
	dialCount := len(host.Dials())
	conn, err := window.DialTcp(tcp(bridgeScenarioLanAddress))
	if err != nil {
		return fmt.Errorf("the connection to revoke: %w", err)
	}
	defer conn.Close()
	before := run.Canary("bridge payload before the revocation")
	if _, err := conn.Write(before); err != nil {
		return err
	}
	if !host.WaitDials(func(dials []BridgeNetDial) bool {
		return dialCount < len(dials) && len(before) <= dials[dialCount].WrittenByteCount
	}) {
		return errors.New("the payload before the revocation never reached the target")
	}
	n := world.RevokeDevice(subject)
	world.Follow()
	host.WaitRevoked(n)
	if !host.WaitDials(func(dials []BridgeNetDial) bool {
		return dials[dialCount].Closed
	}) {
		return errors.New("the revoked subject's upstream socket stayed open")
	}
	conn.SetReadDeadline(time.Now().Add(waitTimeout))
	if _, err := conn.Read(make([]byte, 16)); err == nil {
		return errors.New("the revoked connection read on")
	}
	conn.Write(run.Canary("bridge payload after the revocation"))
	if written := host.Dials()[dialCount].WrittenByteCount; written != len(before) {
		return fmt.Errorf("%d bytes reached the target, not the %d before the revocation", written, len(before))
	}
	return nil
}

// A sender's own settings.
type BridgeNetSenderSettings struct {
	// The key the operator writes as the target's into every contract a link's window client asks for (FS-38's sender
	// row), each sealed and HMACed as the platform would; nil leaves the platform's contracts alone.
	SubstitutedTargetKey []byte
	// Edits the device role's settings, which start as DefaultBridgeSettings on the Net's clock with the world's signer
	// and binding lookups.
	Bridge func(settings *device.BridgeSettings)
}

// A sender sidecar (§17.5): its device role, fed by a component of its own, whose router carries a userspace stack's
// packets over real links to the hosts its rules name, each link a RemoteUserNatMultiClient over device's generator
// wrapper, its window clients the sender's children on the Net's exchange, signed for by the sender's identity key and
// held to the target's bound key. See the file's comment.
type BridgeNetSender struct {
	bridgeNet *BridgeNet
	Device    *BridgeNetDevice
	Bridge    *device.Bridge
	// The sender's own client, its component's generation.
	Client *NetClient

	ctx       context.Context
	cancel    context.CancelFunc
	settings  *BridgeNetSenderSettings
	follower  *sidecar.ConfigClient
	component *sidecar.BridgeComponent
	tun       *connect.Tun
	source    netip.Addr
	workers   sync.WaitGroup
	// the posture's pin at the bridge's last publish
	adoptedPin      *connect.MonitorValue[uint64]
	removeCallbacks []func()

	stateLock sync.Mutex
	// every window client the links built, oldest first
	windowClientIds []connect.Id
	// what the multi clients' own local NATs dialed, which a bridged packet must never reach (TCP/25's rule)
	localDials []string
	// the packets the router sent to the default route
	defaultCount int
	// the contracts the links' window clients refused as naming a key not the target's (connect's Trust status)
	trustRefusals *connect.MonitorValue[int]
}

// Starts device as a sender: its client, its device role with the world's signer and binding lookups, its component,
// and a userspace stack whose every packet the role's router routes. Waits until the role enforces a state at the
// network's tip.
func (self *BridgeNet) StartSender(senderDevice *BridgeNetDevice, settings *BridgeNetSenderSettings) *BridgeNetSender {
	self.t.Helper()
	if settings == nil {
		settings = &BridgeNetSenderSettings{}
	}
	ctx, cancel := context.WithCancel(self.net.Context())
	sender := &BridgeNetSender{
		bridgeNet:  self,
		Device:     senderDevice,
		ctx:        ctx,
		cancel:     cancel,
		settings:   settings,
		adoptedPin: connect.NewMonitorValue[uint64](0),

		trustRefusals: connect.NewMonitorValue(0),
	}
	fail := func(format string, args ...any) {
		sender.Close()
		self.t.Fatalf(format, args...)
	}
	clientSettings := netClientSettings()
	clientSettings.ClientKeySeed = bytes.Clone(senderDevice.clientKeySeed)
	clientSettings.EncryptionSettings.ExposeVerifiedPeerClientKey = true
	sender.Client = self.net.exchange.addClientWithControl(ctx, senderDevice.Name, senderDevice.ClientId, clientSettings, &bridgeNetControl{
		ctx: ctx, clientId: senderDevice.ClientId, platform: self.platform, workers: self.controls,
	})
	if err := self.waitClient(ctx, sender.Client, map[protocol.ProvideMode]bool{protocol.ProvideMode_Network: true}); err != nil {
		fail("the sender's client: %v", err)
	}

	bridgeSettings := device.DefaultBridgeSettings()
	bridgeSettings.Clock = self.net.Clock()
	bridgeSettings.LinkSign = func(ctx context.Context, delegation *bridge.WindowDelegation) ([]byte, error) {
		return bridge.WindowDelegationSigned(delegation, func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
			return &bridge.Signed{
				Body:      body,
				SignerId:  senderDevice.SidecarId().Bytes(),
				Signature: ed25519.Sign(senderDevice.Device.Key, bridge.SignedBytes(purpose, signedType, body)),
				Type:      uint32(signedType),
			}, nil
		}, bridgeSettings.WindowDelegation)
	}
	bridgeSettings.LinkTargetKey = func(ctx context.Context, targetSidecarId connect.Id, targetClientId connect.Id) ([]byte, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, device := range self.devices {
			if connect.Id(device.SidecarId()) == targetSidecarId {
				return bytes.Clone(device.Binding), nil
			}
		}
		return nil, fmt.Errorf("no binding of %s", targetSidecarId)
	}
	if settings.Bridge != nil {
		settings.Bridge(bridgeSettings)
	}
	var err error
	sender.Bridge, err = device.NewBridge(ctx, newBridgeNetPostureStore(), &bridgeNetLinkHost{sender: sender, settings: bridgeSettings}, bridgeSettings)
	if err != nil {
		fail("the device role: %v", err)
	}
	sender.removeCallbacks = append(sender.removeCallbacks, sender.Bridge.AddChangeCallback(func() {
		pin := sender.Bridge.Decision().Pin.GetVersion()
		sender.adoptedPin.Update(func(adopted uint64) uint64 { return max(adopted, pin) })
	}))

	store, err := self.bindingStore()
	if err != nil {
		fail("the binding cache: %v", err)
	}
	componentSettings := sidecar.DefaultBridgeComponentSettings()
	componentSettings.CompileDelay = 0
	componentSettings.CompileMinInterval = 0
	sender.follower = self.admission.Follower()
	identity := &sidecar.SidecarIdentity{
		NetworkId:         self.NetworkId(),
		SidecarId:         senderDevice.SidecarId(),
		ClientId:          sidecar.Id(senderDevice.ClientId),
		Generation:        1,
		IdentityPublicKey: senderDevice.Device.PublicKey(),
		ClientPublicKey:   bytes.Clone(senderDevice.ClientPublicKey),
	}
	sender.component, err = sidecar.NewBridgeComponent(ctx, &sidecar.BridgeComponentArgs{
		NetworkId: self.NetworkId(),
		Identity:  func() *sidecar.SidecarIdentity { return identity },
		Config:    sender.follower,
		Heads:     self.admission.heads,
		Rows:      self.rows,
		RepoKeyAt: func(generation uint64) *sidecar.EvsRepoKey {
			if generation == self.configKey.Generation() {
				return self.configKey
			}
			return nil
		},
		AclLocal: func() *sidecar.AclLocalPolicy {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.aclLocal
		},
		Clock:    self.net.Clock(),
		Log:      sidecar.NewNoopLogger(),
		Settings: componentSettings,
	})
	if err != nil {
		fail("the component: %v", err)
	}
	if err := sender.component.Attach(&sidecar.SidecarEnv{Ctx: ctx, Client: sender.Client.Client, Store: store.Root(), Log: sidecar.NewNoopLogger()}); err != nil {
		fail("the generation: %v", err)
	}
	if err := sender.component.SetDeviceRole(&bridgeNetSink{bridge: sender.Bridge, hook: sender.Bridge.EgressHook()}); err != nil {
		fail("the device role: %v", err)
	}

	tunSettings := connect.DefaultTunSettingsWithBufferSize(64)
	tunSettings.Log = connect.NewNoopLogger()
	sender.tun, err = connect.CreateTun(ctx, tunSettings)
	if err != nil {
		fail("the sender's stack: %v", err)
	}
	for _, address := range sender.tun.LocalAddresses() {
		if address.Is4() {
			sender.source = address
		}
	}
	sender.Bridge.SetReceivePacket(func(source connect.TransferPath, provideMode protocol.ProvideMode, ipPath *connect.IpPath, packet []byte) {
		sender.tun.Write(packet)
	})
	sender.workers.Add(1)
	go sender.pump()
	self.stateLock.Lock()
	self.senders = append(self.senders, sender)
	self.stateLock.Unlock()
	sender.WaitAdopted(self.admission.Tip().GetVersion())
	return sender
}

// A store holding every device's binding, verified as the component's fetcher verifies an answer, as the cache the
// component reads at its first generation.
func (self *BridgeNet) bindingStore() (*FakeStore, error) {
	store := NewFakeStore()
	cache := sidecar.NewBridgeBindingCache(self.settings.BindingRetainTimeout, self.settings.BindingMaxCount)
	state := self.admission.State()
	self.stateLock.Lock()
	devices := slices.Clone(self.devices)
	self.stateLock.Unlock()
	for _, other := range devices {
		binding, err := sidecar.VerifyBridgeBinding(other.Binding, self.NetworkId(), other.SidecarId(), state.IdentityKey(other.SidecarId()))
		if err != nil {
			return nil, fmt.Errorf("%s's binding: %w", other.Name, err)
		}
		cache.Record(binding, self.net.Clock().Now())
	}
	if err := cache.Save(store.Root()); err != nil {
		return nil, err
	}
	return store, nil
}

// Routes the stack's packets until the sender closes: a link's, the reject's or the resolver's client takes a packet,
// and the default route, which goes nowhere here, drops it.
func (self *BridgeNetSender) pump() {
	defer self.workers.Done()
	source := connect.SourceId(self.Client.ClientId)
	for {
		packet, err := self.tun.Read()
		if err != nil {
			return
		}
		client := self.Bridge.Route(packet)
		if client == nil {
			self.stateLock.Lock()
			self.defaultCount += 1
			self.stateLock.Unlock()
			connect.MessagePoolReturn(packet)
			continue
		}
		if !client.SendPacket(source, protocol.ProvideMode_Network, packet, self.bridgeNet.settings.SendTimeout) {
			connect.MessagePoolReturn(packet)
		}
	}
}

// Ends the sender's stack, component, role and client. Idempotent.
func (self *BridgeNetSender) Close() {
	self.cancel()
	if self.tun != nil {
		self.tun.Close()
	}
	self.workers.Wait()
	for _, remove := range self.removeCallbacks {
		remove()
	}
	self.removeCallbacks = nil
	if self.component != nil {
		self.component.Close()
	}
	if self.Bridge != nil {
		self.Bridge.Close()
	}
	if self.follower != nil {
		self.follower.Close()
	}
	if self.Client != nil {
		self.Client.Client.Cancel()
	}
}

// As BridgeNetHost.WaitAdopted, for the sender's role.
func (self *BridgeNetSender) WaitAdopted(n uint64) {
	t := self.bridgeNet.t
	t.Helper()
	ctx, cancel := context.WithTimeout(self.ctx, self.bridgeNet.settings.WaitTimeout)
	defer cancel()
	if _, err := self.follower.WaitFor(ctx, n); err != nil {
		t.Fatalf("%s's follower did not reach %d: %v", self.Device.Name, n, err)
	}
	compileAt := uint64(0)
	for _, read := range self.follower.BridgeEntries(1, n) {
		if !read.Pure {
			compileAt = read.N
		}
	}
	for {
		adopted, changed := self.adoptedPin.Get()
		status := self.component.Status()
		if n <= adopted && compileAt <= status.CompiledPin.GetVersion() {
			return
		}
		select {
		case <-changed:
		case <-time.After(self.bridgeNet.settings.PollInterval):
		case <-ctx.Done():
			t.Fatalf("%s adopted %d, not %d, compiled at %d, not %d", self.Device.Name, adopted, n, status.CompiledPin.GetVersion(), compileAt)
		}
	}
}

// A TCP connection through the sender's router to address, its error if nothing answers it with a connection.
func (self *BridgeNetSender) DialTcp(address netip.AddrPort) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(self.ctx, self.bridgeNet.settings.WaitTimeout)
	defer cancel()
	return self.tun.DialContext(ctx, "tcp4", address.String())
}

// Waits until the links' window clients have refused count contracts as naming a key not the target's, false past
// WaitTimeout.
func (self *BridgeNetSender) WaitTrustRefusals(count int) bool {
	deadline := time.After(self.bridgeNet.settings.WaitTimeout)
	for {
		refused, changed := self.trustRefusals.Get()
		if count <= refused {
			return true
		}
		select {
		case <-changed:
		case <-deadline:
			return false
		}
	}
}

// The contracts the links' window clients refused as naming a key not the target's.
func (self *BridgeNetSender) TrustRefusalCount() int {
	return self.trustRefusals.Value()
}

// A TCP connection through the sender's router to address, ended by ctx too.
func (self *BridgeNetSender) DialTcpContext(ctx context.Context, address netip.AddrPort) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, self.bridgeNet.settings.WaitTimeout)
	defer cancel()
	return self.tun.DialContext(ctx, "tcp4", address.String())
}

// The window clients the sender's links built, oldest first.
func (self *BridgeNetSender) WindowClientIds() []connect.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.windowClientIds)
}

// What the links' own local NATs dialed, which a bridged packet never reaches.
func (self *BridgeNetSender) LocalDials() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.localDials)
}

// The address the sender's stack sends from.
func (self *BridgeNetSender) Source() netip.Addr {
	return self.source
}

// The CLI's BridgeHost on the Net's exchange (cli/bridge_host.go's shape): each link a multi client of one window client
// to its target, drawn from a generator that registers the sender's children on the platform, wrapped by
// device.NewBridgeLinkGenerator, on device.BridgeLinkMultiClientSettings. A share link waits for C18 and is refused.
type bridgeNetLinkHost struct {
	sender   *BridgeNetSender
	settings *device.BridgeSettings
}

var _ device.BridgeHost = (*bridgeNetLinkHost)(nil)

func (self *bridgeNetLinkHost) NewBridgeLink(ctx context.Context, target connect.Id, subject connect.Id, shareAliases []netip.Prefix,
	sign func(windowClientId connect.Id, windowClientPublicKey []byte, notAfter time.Time) ([]byte, error),
) (connect.UserNatClient, error) {
	if shareAliases != nil {
		return nil, errors.New("share links come with shares")
	}
	sender := self.sender
	multiClientSettings := device.BridgeLinkMultiClientSettings(self.settings)
	if err := device.CheckBridgeLinkMultiClientSettings(multiClientSettings, self.settings.LinkAllowDirect); err != nil {
		return nil, err
	}
	// the multi client's own local NAT, which a TCP/25 packet that entered a link would be dialed from
	multiClientSettings.LocalDialContextSettings = &connect.DialContextSettings{
		DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
			sender.stateLock.Lock()
			sender.localDials = append(sender.localDials, network+" "+address)
			sender.stateLock.Unlock()
			return nil, errors.New("the sender's links dial nothing locally")
		},
	}
	generator := &bridgeNetLinkGenerator{sender: sender, target: target}
	receive := func(source connect.TransferPath, provideMode protocol.ProvideMode, ipPath *connect.IpPath, packet []byte) {
		sender.tun.Write(packet)
	}
	return connect.NewRemoteUserNatMultiClient(ctx, device.NewBridgeLinkGenerator(ctx, generator, sign), receive,
		protocol.ProvideMode_Network, multiClientSettings), nil
}

// One link's generator: its target alone, each window client a child of the sender registered on the platform, its
// token unsigned but naming the client and a strict_exp the delegation's not_after may not pass.
type bridgeNetLinkGenerator struct {
	sender *BridgeNetSender
	target connect.Id
}

var _ connect.MultiClientGenerator = (*bridgeNetLinkGenerator)(nil)

func (self *bridgeNetLinkGenerator) NextDestinations(count int, excludeDestinations []connect.MultiHopId, rankMode string) (map[connect.MultiHopId]connect.DestinationStats, error) {
	destination, err := connect.NewMultiHopId(self.target)
	if err != nil {
		return nil, err
	}
	if slices.Contains(excludeDestinations, destination) {
		return map[connect.MultiHopId]connect.DestinationStats{}, nil
	}
	return map[connect.MultiHopId]connect.DestinationStats{destination: {}}, nil
}

func (self *bridgeNetLinkGenerator) NewClientArgs() (*connect.MultiClientGeneratorClientArgs, error) {
	sender := self.sender
	world := sender.bridgeNet
	parentClientId := sender.Device.ClientId
	clientId, err := world.platform.AddClient(sender.ctx, &BridgeNetClientArgs{
		Name: sender.Device.Name + " window", NetworkId: world.NetworkId(), ParentClientId: &parentClientId,
	})
	if err != nil {
		return nil, err
	}
	strictExp := world.net.Clock().Now().Add(world.settings.WindowClientLifetime)
	return &connect.MultiClientGeneratorClientArgs{
		ClientId:   clientId,
		ClientAuth: &connect.ClientAuth{ByJwt: bridgeNetUnsignedToken(clientId, strictExp)},
	}, nil
}

func (self *bridgeNetLinkGenerator) RemoveClientArgs(args *connect.MultiClientGeneratorClientArgs) {}

func (self *bridgeNetLinkGenerator) RemoveClientWithArgs(client *connect.Client, args *connect.MultiClientGeneratorClientArgs) {
}

func (self *bridgeNetLinkGenerator) NewClientSettings() *connect.ClientSettings {
	return netClientSettings()
}

func (self *bridgeNetLinkGenerator) NewClient(ctx context.Context, args *connect.MultiClientGeneratorClientArgs, clientSettings *connect.ClientSettings) (*connect.Client, error) {
	sender := self.sender
	world := sender.bridgeNet
	control := &bridgeNetControl{ctx: ctx, clientId: args.ClientId, platform: world.platform, workers: world.controls}
	if substituted := sender.settings.SubstitutedTargetKey; substituted != nil {
		// the operator's contracts, each naming another key as the target's
		control.mint = func(request *protocol.CreateContract) (*protocol.CreateContractResult, bool, error) {
			destinationId, err := connect.IdFromBytes(request.GetDestinationId())
			if err != nil || destinationId != self.target {
				return nil, false, nil
			}
			subject := sender.Device.ClientId
			networkId := connect.Id(world.NetworkId())
			contract, err := world.net.MintContract(&MintContractArgs{
				SourceId:                   args.ClientId,
				DestinationId:              destinationId,
				ProvideMode:                protocol.ProvideMode_Network,
				SourceSubjectClientId:      &subject,
				SourceNetworkId:            &networkId,
				ContractClass:              protocol.ContractClass_ContractClassData,
				WindowDelegation:           request.GetWindowDelegation(),
				DestinationClientPublicKey: substituted,
				TransferByteCount:          max(request.GetTransferByteCount(), world.settings.ContractByteCount),
			})
			if err != nil {
				return nil, true, err
			}
			return &protocol.CreateContractResult{Contract: contract, CreateContract: request}, true, nil
		}
	}
	client := world.net.exchange.addClientWithControl(ctx, sender.Device.Name+" window", args.ClientId, clientSettings, control)
	if err := world.waitClient(ctx, client, map[protocol.ProvideMode]bool{protocol.ProvideMode_Network: true}); err != nil {
		client.Client.Cancel()
		return nil, err
	}
	// what the target check the generator wrapper installs refuses, each contract with a Trust status
	client.Client.ContractManager().AddContractStatusCallback(func(status *connect.ContractStatus) {
		if status != nil && status.Error != nil && *status.Error == protocol.ContractError_Trust {
			sender.trustRefusals.Update(func(count int) int { return count + 1 })
		}
	})
	sender.stateLock.Lock()
	sender.windowClientIds = append(sender.windowClientIds, args.ClientId)
	sender.stateLock.Unlock()
	return client.Client, nil
}

func (self *bridgeNetLinkGenerator) FixedDestinationSize() (int, bool) {
	return 1, true
}

// An unsigned token naming clientId and expiring at expireTime, as the platform's child token reads to
// connect.ParseByJwtUnverified: nothing verifies it on the exchange, and the generator wrapper reads its exp as the
// window client's strict_exp.
func bridgeNetUnsignedToken(clientId connect.Id, expireTime time.Time) string {
	claims, _ := json.Marshal(map[string]any{"client_id": clientId.String(), "exp": expireTime.Unix()})
	encode := base64.RawURLEncoding.EncodeToString
	return encode([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + encode(claims) + "." + encode([]byte("unsigned"))
}

// Whether the sender's router sends a TCP SYN to destination down the default route, as it does a carved local address
// whatever entry covers it (§17.4's carve).
func (self *BridgeNetSender) TakesDefaultRoute(destination netip.AddrPort) bool {
	return self.Bridge.Route(bridgeNetSyn(netip.AddrPortFrom(self.source, 40000), destination)) == nil
}

// A public exit (§17.6's C6a; §22.7's public-exits assert): a client of a network of its own providing Public over a
// NAT with no hook, as today's providers run, its provider's CFAA policy dropping 100.64/10 when the release that
// turns DropSharedAddressSpace on runs, and only counting it before. Its dials are counted, and one to a LAN or
// overlay address it is given reaches the upstream's loopback listener, so a pass is seen.
type BridgeNetExit struct {
	bridgeNet *BridgeNet
	Client    *NetClient
	Upstream  *BridgeNetUpstream

	ctx      context.Context
	cancel   context.CancelFunc
	nat      *connect.LocalUserNat
	provider *connect.RemoteUserNatProvider
	dials    *bridgeNetDials
}

// Starts a public exit in a network of its own, dropping 100.64/10 when dropSharedAddressSpace is set.
func (self *BridgeNet) StartExit(name string, dropSharedAddressSpace bool) *BridgeNetExit {
	self.t.Helper()
	ctx, cancel := context.WithCancel(self.net.Context())
	exit := &BridgeNetExit{
		bridgeNet: self,
		ctx:       ctx,
		cancel:    cancel,
		dials:     &bridgeNetDials{changes: connect.NewMonitorValue(0), lanHosts: map[netip.Addr]bool{}},
	}
	fail := func(format string, args ...any) {
		exit.Close()
		self.t.Fatalf(format, args...)
	}
	var exitNetworkId sidecar.Id
	rand.Read(exitNetworkId[:])
	clientId, err := self.platform.AddClient(ctx, &BridgeNetClientArgs{Name: name, NetworkId: exitNetworkId, Exit: true})
	if err != nil {
		fail("the exit's client: %v", err)
	}
	exit.Client = self.net.exchange.addClientWithControl(ctx, name, clientId, netClientSettings(), &bridgeNetControl{
		ctx: ctx, clientId: clientId, platform: self.platform, workers: self.controls,
	})
	if err := self.waitClient(ctx, exit.Client, map[protocol.ProvideMode]bool{protocol.ProvideMode_Public: true}); err != nil {
		fail("the exit's client: %v", err)
	}
	exit.Upstream, err = newBridgeNetUpstream(self.settings.ReadByteCount)
	if err != nil {
		fail("the exit's upstream: %v", err)
	}
	natSettings := connect.DefaultLocalUserNatSettings()
	dialSettings := &connect.DialContextSettings{DialContext: exit.dials.dial}
	natSettings.TcpBufferSettings.DialContextSettings = dialSettings
	natSettings.UdpBufferSettings.DialContextSettings = dialSettings
	exit.nat = connect.NewLocalUserNat(ctx, name, natSettings)
	providerSettings := connect.DefaultRemoteUserNatProviderSettings()
	providerSettings.SecurityPolicyGenerator = func(ctx context.Context, stats *connect.SecurityPolicyStatsCollector) connect.SecurityPolicy {
		cfaa := connect.DefaultCfaaSecurityPolicySettings()
		cfaa.DropSharedAddressSpace = dropSharedAddressSpace
		return connect.Reverse(connect.NewSecurityPolicy(ctx, cfaa, connect.DefaultDmcaSecurityPolicySettings(), connect.DefaultWebStandardSettings(), stats))
	}
	exit.provider, err = connect.TryNewRemoteUserNatProvider(exit.Client.Client, exit.nat, providerSettings)
	if err != nil {
		fail("the exit's provider: %v", err)
	}
	self.stateLock.Lock()
	self.exits = append(self.exits, exit)
	self.stateLock.Unlock()
	return exit
}

// Ends the exit's provider, NAT, client and upstream. Idempotent.
func (self *BridgeNetExit) Close() {
	self.cancel()
	if self.provider != nil {
		self.provider.Close()
	}
	if self.nat != nil {
		self.nat.Close()
	}
	if self.Client != nil {
		self.Client.Client.Cancel()
	}
	self.dials.open()
	if self.Upstream != nil {
		self.Upstream.close()
	}
}

// As BridgeNetHost.AddLan: a dial to lan reaches the exit's upstream on loopback, counted under lan.
func (self *BridgeNetExit) AddLan(lan netip.Addr) {
	self.dials.stateLock.Lock()
	defer self.dials.stateLock.Unlock()
	self.dials.lanHosts[lan] = true
}

// Every dial the exit's NAT made upstream so far.
func (self *BridgeNetExit) Dials() []BridgeNetDial {
	self.dials.stateLock.Lock()
	defer self.dials.stateLock.Unlock()
	dials := []BridgeNetDial{}
	for _, dial := range self.dials.dials {
		dials = append(dials, *dial)
	}
	return dials
}

// How many packets to port the exit's policy judged by reason: SecurityPolicyReasonSharedAddressSpace drops them once
// the release turns DropSharedAddressSpace on, and only counts them before. The policy's counts keep a destination's
// port and never its address (I-13), so a test tells two destinations apart by their reasons.
func (self *BridgeNetExit) ReasonCount(reason connect.SecurityPolicyReason, port uint16) uint64 {
	count := uint64(0)
	for securityDestination, destinationCount := range self.provider.SecurityPolicyReasons(false)[reason] {
		if securityDestination.Port == int(port) {
			count += destinationCount
		}
	}
	return count
}

// Waits until the exit's policy has judged a packet to port by reason, false past WaitTimeout. The policy raises
// nothing when it judges, so the wait polls at PollInterval.
func (self *BridgeNetExit) WaitReason(reason connect.SecurityPolicyReason, port uint16) bool {
	deadline := time.After(self.bridgeNet.settings.WaitTimeout)
	for self.ReasonCount(reason, port) == 0 {
		select {
		case <-time.After(self.bridgeNet.settings.PollInterval):
		case <-deadline:
			return false
		}
	}
	return true
}
