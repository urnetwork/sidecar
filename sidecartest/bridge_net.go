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
// The platform is the seam between the tiers. On T2 it is in memory: a client registry and an issuer that seals what
// server's CreateContract seals (C13, PROTO-M4-02): the source's subject, a window client's parent's, its network, the
// data class, and the request's delegation unchanged. On T3 server's test gives its own, over Postgres and
// controller.CreateContract. Minting goes around the platform on both tiers, through the provide secret the test
// stack holds in the host's live client, as an operator holding the platform's provide keys would.
//
// What is not the system here: each sidecar's binding is signed by the world and reaches the host's component through
// its store's binding cache, since no api serves these sidecars' identities (the component's fetcher has no api and
// fetches nothing); the host's daemon listener is one the world opens and names. Waits are on monitors and sockets,
// bounded by BridgeNetSettings.WaitTimeout of real time, since connect's timers are real (X9).
//
// Safe for concurrent use. A BridgeNet is closed by its test, before its Net.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
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
	}
}

// What a BridgeNet's clients register on and take their contracts from: the in-memory registry and issuer on T2,
// server's Postgres and CreateContract on T3. Safe for concurrent use.
type BridgeNetPlatform interface {
	// Registers a client of the network and answers its id: a sidecar's own client, or a window client whose subject
	// is its parent's.
	AddClient(ctx context.Context, args *BridgeNetClientArgs) (connect.Id, error)
	// Records a client's provide keys, as connect's ProvideKey control carries them to the platform.
	SetProvide(ctx context.Context, clientId connect.Id, secretKeys map[protocol.ProvideMode][]byte) error
	// The platform's answer to sourceId's CreateContract, as its out-of-band control asks it.
	CreateContract(ctx context.Context, sourceId connect.Id, request *protocol.CreateContract) (*protocol.CreateContractResult, error)
}

// One client a BridgeNet registers.
type BridgeNetClientArgs struct {
	Name      string
	NetworkId sidecar.Id
	// The sidecar whose own client it is, zero for a window client.
	SidecarId sidecar.Id
	// A window client's parent, the subject's own client, whose subject C13 seals for it.
	ParentClientId *connect.Id
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

// T2's platform: a registry of the world's clients and an issuer that seals as server's CreateContract does.
type bridgeNetFakePlatform struct {
	net      *Net
	settings *BridgeNetSettings

	stateLock sync.Mutex
	clients   map[connect.Id]*bridgeNetFakeClient
}

type bridgeNetFakeClient struct {
	networkId       sidecar.Id
	subjectClientId connect.Id
}

func newBridgeNetFakePlatform(net *Net, settings *BridgeNetSettings) *bridgeNetFakePlatform {
	return &bridgeNetFakePlatform{net: net, settings: settings, clients: map[connect.Id]*bridgeNetFakeClient{}}
}

func (self *bridgeNetFakePlatform) AddClient(ctx context.Context, args *BridgeNetClientArgs) (connect.Id, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	clientId := connect.NewId()
	client := &bridgeNetFakeClient{networkId: args.NetworkId, subjectClientId: clientId}
	if args.ParentClientId != nil {
		parent := self.clients[*args.ParentClientId]
		if parent == nil {
			return connect.Id{}, fmt.Errorf("no parent client %s", *args.ParentClientId)
		}
		client.subjectClientId = parent.subjectClientId
	}
	self.clients[clientId] = client
	return clientId, nil
}

// The fake reads a destination's provide keys from its live client, as Net.MintContract does.
func (self *bridgeNetFakePlatform) SetProvide(ctx context.Context, clientId connect.Id, secretKeys map[protocol.ProvideMode][]byte) error {
	return nil
}

// Network contracts between two of the network's clients, sealed with the source's subject and network, the data
// class and the request's delegation; a companion carries its forward contract's seals, its destination's, and no
// delegation. Anything else is refused, as shares wait for C18.
func (self *bridgeNetFakePlatform) CreateContract(ctx context.Context, sourceId connect.Id, request *protocol.CreateContract) (*protocol.CreateContractResult, error) {
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
	if source == nil || destination == nil || source.networkId != destination.networkId {
		return &protocol.CreateContractResult{Error: &refused, CreateContract: request}, nil
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
		ProvideMode:           protocol.ProvideMode_Network,
		SourceSubjectClientId: &sealed.subjectClientId,
		SourceNetworkId:       &networkId,
		ContractClass:         protocol.ContractClass_ContractClassData,
		WindowDelegation:      delegation,
		TransferByteCount:     max(request.GetTransferByteCount(), self.settings.ContractByteCount),
	})
	if err != nil {
		return nil, err
	}
	return &protocol.CreateContractResult{Contract: contract, CreateContract: request}, nil
}

// A client's out-of-band control: every CreateContract answered by create, everything else taken with no answer, as
// the exchange's issuer does.
type bridgeNetControl struct {
	ctx    context.Context
	create func(ctx context.Context, request *protocol.CreateContract) (*protocol.CreateContractResult, error)
}

func (self *bridgeNetControl) SendControl(frames []*protocol.Frame, callback connect.OobResultFunction) {
	resultFrames := []*protocol.Frame{}
	defer func() {
		for _, frame := range frames {
			connect.MessagePoolReturn(frame.MessageBytes)
		}
		for _, frame := range resultFrames {
			connect.MessagePoolReturn(frame.MessageBytes)
		}
	}()
	for _, frame := range frames {
		message, err := connect.FromFrame(frame)
		if err != nil {
			continue
		}
		request, ok := message.(*protocol.CreateContract)
		if !ok {
			continue
		}
		result, err := self.create(self.ctx, request)
		if err != nil || result == nil {
			continue
		}
		resultFrame, err := connect.ToFrame(result, connect.DefaultProtocolVersion)
		if err != nil {
			continue
		}
		resultFrames = append(resultFrames, resultFrame)
	}
	if callback != nil {
		connect.HandleError(func() {
			callback(resultFrames, nil)
		})
	}
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
	windows   []*BridgeNetWindow
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
	admission := NewAdmissionNet(t, tier)
	admission.StartReadersAtBases(false)
	self := &BridgeNet{
		t:         t,
		net:       net,
		settings:  settings,
		platform:  settings.Platform,
		admission: admission,
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
	var hosts []*BridgeNetHost
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		windows, hosts = self.windows, self.hosts
		self.windows, self.hosts = nil, nil
	}()
	for _, window := range windows {
		window.Close()
	}
	for _, host := range hosts {
		host.Close()
	}
	self.admission.Close()
}

// The network's config world.
func (self *BridgeNet) Admission() *AdmissionNet {
	return self.admission
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
	hook   *bridgeNetHook
}

var _ sidecar.BridgeStateSink = (*bridgeNetSink)(nil)

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
	self.hook.host.record(func() {
		self.hook.host.revocations = append(self.hook.host.revocations, &BridgeNetRevocation{Type: statementType, Id: bytes.Clone(id), N: n, Err: err})
	})
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
}

// A host's upstream: a TCP and a UDP listener on loopback, each counting what reached it. The UDP listener answers
// each datagram with the same bytes.
type BridgeNetUpstream struct {
	tcp net.Listener
	udp net.PacketConn

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

func newBridgeNetUpstream() (*BridgeNetUpstream, error) {
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		tcp.Close()
		return nil, err
	}
	self := &BridgeNetUpstream{tcp: tcp, udp: udp, changes: connect.NewMonitorValue(0)}
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
			buffer := make([]byte, 4096)
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
	buffer := make([]byte, 64*1024)
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
		dials:      &bridgeNetDials{changes: connect.NewMonitorValue(0)},
		adoptedPin: connect.NewMonitorValue[uint64](0),
		records:    connect.NewMonitorValue(0),
	}
	fail := func(format string, args ...any) {
		host.Close()
		self.t.Fatalf(format, args...)
	}
	var err error
	host.Upstream, err = newBridgeNetUpstream()
	if err != nil {
		fail("the upstream: %v", err)
	}
	host.Daemon, err = net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		fail("the daemon's listener: %v", err)
	}

	clientSettings := netClientSettings()
	clientSettings.ClientKeySeed = bytes.Clone(hostDevice.clientKeySeed)
	clientSettings.EncryptionSettings.ExposeVerifiedPeerClientKey = true
	host.Client = self.net.exchange.addClientWithControl(ctx, hostDevice.Name, hostDevice.ClientId, clientSettings, &bridgeNetControl{
		ctx: ctx,
		create: func(ctx context.Context, request *protocol.CreateContract) (*protocol.CreateContractResult, error) {
			return self.platform.CreateContract(ctx, hostDevice.ClientId, request)
		},
	})
	provideModes := map[protocol.ProvideMode]bool{protocol.ProvideMode_Network: true}
	if settings.ProvideFriendsAndFamily {
		provideModes[protocol.ProvideMode_FriendsAndFamily] = true
	}
	host.Client.Client.ContractManager().SetProvideModes(provideModes)
	if err := self.platform.SetProvide(ctx, hostDevice.ClientId, host.Client.Client.ContractManager().GetProvideSecretKeys()); err != nil {
		fail("the host's provide keys: %v", err)
	}

	bridgeSettings := device.DefaultBridgeSettings()
	bridgeSettings.Clock = self.net.Clock()
	if settings.Bridge != nil {
		settings.Bridge(bridgeSettings)
	}
	host.Bridge, err = device.NewBridge(ctx, newBridgeNetPostureStore(), nil, bridgeSettings)
	if err != nil {
		fail("the device role: %v", err)
	}
	host.removeCallbacks = append(host.removeCallbacks, host.Bridge.AddChangeCallback(func() {
		pin := host.Bridge.Decision().Pin.GetVersion()
		host.adoptedPin.Update(func(adopted uint64) uint64 { return max(adopted, pin) })
	}))

	// the bindings every device signed, verified as the component's fetcher verifies an answer, in the store the
	// component reads its cache from
	store := NewFakeStore()
	cache := sidecar.NewBridgeBindingCache(self.settings.BindingRetainTimeout, self.settings.BindingMaxCount)
	state := self.admission.State()
	self.stateLock.Lock()
	devices := slices.Clone(self.devices)
	self.stateLock.Unlock()
	for _, other := range devices {
		binding, err := sidecar.VerifyBridgeBinding(other.Binding, self.NetworkId(), other.SidecarId(), state.IdentityKey(other.SidecarId()))
		if err != nil {
			fail("%s's binding: %v", other.Name, err)
		}
		cache.Record(binding, self.net.Clock().Now())
	}
	if err := cache.Save(store.Root()); err != nil {
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
		Clock:           self.net.Clock(),
		Log:             sidecar.NewNoopLogger(),
		Settings:        componentSettings,
	})
	if err != nil {
		fail("the component: %v", err)
	}
	// the generation first, so its store's bindings load before the role's first compile
	if err := host.component.Attach(&sidecar.SidecarEnv{Ctx: ctx, Client: host.Client.Client, Store: store.Root(), Log: sidecar.NewNoopLogger()}); err != nil {
		fail("the generation: %v", err)
	}
	sink := &bridgeNetSink{bridge: host.Bridge, hook: &bridgeNetHook{inner: host.Bridge.EgressHook(), host: host}}
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
	if self.Upstream != nil {
		self.Upstream.close()
	}
	if self.Daemon != nil {
		self.Daemon.Close()
	}
}

// Waits until the host's follower stands at n and the role has published a state or entry at or past it, with the
// component's catch-up done: then a flow meets what n holds. Fails the test past WaitTimeout.
func (self *BridgeNetHost) WaitAdopted(n uint64) {
	t := self.bridgeNet.t
	t.Helper()
	ctx, cancel := context.WithTimeout(self.ctx, self.bridgeNet.settings.WaitTimeout)
	defer cancel()
	if _, err := self.follower.WaitFor(ctx, n); err != nil {
		t.Fatalf("%s's follower did not reach %d: %v", self.Device.Name, n, err)
	}
	for {
		adopted, changed := self.adoptedPin.Get()
		if n <= adopted && self.component.Status().Serving {
			return
		}
		select {
		case <-changed:
		case <-time.After(10 * time.Millisecond):
			// the component's serving flag moves without a callback of the bridge's
		case <-ctx.Done():
			t.Fatalf("%s adopted %d, not %d, serving %t: %+v", self.Device.Name, adopted, n, self.component.Status().Serving, self.component.Status())
		}
	}
}

// The state the role enforces, nil for none.
func (self *BridgeNetHost) State() *bridge.BridgeState {
	return self.Bridge.Decision().BridgeState
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
	gate := func() chan struct{} {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.dials = append(self.dials, record)
		if self.gate != nil {
			record.Held = true
			self.heldCount += 1
		}
		return self.gate
	}()
	self.changes.Update(func(count int) int { return count + 1 })
	dialCtx := ctx
	if gate != nil {
		<-gate
		dialCtx = context.Background()
	}
	conn, err := (&net.Dialer{}).DialContext(dialCtx, network, address)
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
		parentClientId := subject.ClientId
		var err error
		clientId, err = self.platform.AddClient(ctx, &BridgeNetClientArgs{Name: name, NetworkId: self.NetworkId(), ParentClientId: &parentClientId})
		if err != nil {
			fail("the window client: %v", err)
		}
		control = &bridgeNetControl{ctx: ctx, create: func(ctx context.Context, request *protocol.CreateContract) (*protocol.CreateContractResult, error) {
			return self.platform.CreateContract(ctx, clientId, request)
		}}
	} else {
		// the operator's own client, which the platform it runs answers for, so the host's return contracts reach it
		var err error
		clientId, err = self.platform.AddClient(ctx, &BridgeNetClientArgs{Name: name, NetworkId: self.NetworkId()})
		if err != nil {
			fail("the operator's client: %v", err)
		}
		control = &bridgeNetControl{ctx: ctx, create: func(ctx context.Context, request *protocol.CreateContract) (*protocol.CreateContractResult, error) {
			mintArgs := args.Mint(window, request)
			if mintArgs == nil {
				refused := protocol.ContractError_NoPermission
				return &protocol.CreateContractResult{Error: &refused, CreateContract: request}, nil
			}
			contract, err := self.net.MintContract(mintArgs)
			if err != nil {
				return nil, err
			}
			return &protocol.CreateContractResult{Contract: contract, CreateContract: request}, nil
		}}
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
	if !args.NoDelegation {
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
	hostHop, err := connect.NewMultiHopId(host.Client.ClientId)
	if err != nil {
		fail("the host's hop: %v", err)
	}
	window.natClient = connect.NewRemoteUserNatClient(window.Client.Client, window.receive, []connect.MultiHopId{hostHop}, provideMode)
	window.workers.Add(1)
	go window.pump()
	self.stateLock.Lock()
	self.windows = append(self.windows, window)
	self.stateLock.Unlock()
	return window
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
	buffer := make([]byte, 64*1024)
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
