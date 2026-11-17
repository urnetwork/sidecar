//go:build !sidecar_http && !ios_extension

// §17.9's share end to end (BRIDGE-M6-08; FS-38's share rows, §22.7's share asserts): two networks on one Net. The
// sharing network X is a BridgeNet whose host serves a share the accepting network Y holds, every part of it X's own
// and real: the share's grant activated through X's ACL by its admin's decision under §16.6's spend check, the grant
// file pinning Y's ShareKey, K and both tables' hashes written into X's head, the share's row at api sealed under K,
// and the host's compile, device role, provider NAT and upstream the BridgeNet's. Y is what X's host and the platform
// see of it: its network id, its verified ACL state, two readers of its config with their own clients on the platform,
// the ShareKey its approving admin holds, the ShareSigners each generation of its config certifies, and window clients
// whose contracts carry a ShareSigner's delegation, FriendsAndFamily and sealed to Y.
//
//	activate  X's admin requests the share's grant, a dial on the host for network:Y under the implicit document's
//	          shares rule (QD-820), decides it on its own device and spends the decision in a GrantActivate
//	pin       the grant file bridge/share-grant/<share_id hex> in a head of X's: the grant, Y's ShareKey, K, Y and both
//	          tables' hashes and versions (QD-077, QD-670)
//	row       the target table, sealed under K at version 1: the host's address as a /32 on every protocol, and again
//	          for TCP to the port of the upstream the share's hosts reach alone, an upstream the share net makes before
//	          it seals and hands each host, a restarted one too; and Y's side, the alias table and the ShareKey sealed
//	          under K, as network_bridge_share stores them. The host fetches it from the world
//	          (BridgeNetHostSettings.ShareRows), since no api serves these networks
//	sign      a ShareCert of a generation by Y's ShareKey, and a delegation by that generation's ShareSigner, as Y's
//	          keyring and sidecars make them (bridge.ShareCertSigned, bridge.ShareSignerSign)
//	readers   Y's state, a hand-made one (FakeAclView): two sidecars of Y's owner, the granted reader, whose rule
//	          dials network:X (Y's half of §8.11's intersection), and the ungranted reader, which no rule of Y's lets
//	          reach X (CC-05's reader); each has its own client on the platform, in Y's network, bound to it
//	gate      both networks' verified states handed to the platform (BridgeNetSharePlatform), which settles a contract
//	          between them as its contract gate's share half and CreateContract do: T2's in memory over the same
//	          states (sidecar.AclShareReach), T3's through server's own gate and CreateContract (server's
//	          connect_bridge_m6_test.go)
//
// Two kinds of window reach the host. A reader's window (OpenReaderWindow) is the honest one: a child of the reader's
// own client on the platform, whose contracts the platform issues and seals itself, the subject its rows store and Y,
// with the delegation the window carries. A minted window (OpenWindow) is the operator's, every contract minted
// FriendsAndFamily and sealed to whatever the test names, so what the host admits rests on its own checks alone, which
// is FS-38's question. Y's routers are not run here (the sender's share link is the device's and compile's tests').
// Safe for concurrent use. A BridgeShareNet is closed by its test, before its Net.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"net/netip"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar"
	sidecarprotocol "github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Tunables of a BridgeShareNet.
type BridgeShareNetSettings struct {
	// X's world; nil is the Net's (NetBridgeSettings) or the defaults. Its spend check is the share net's own.
	Bridge *BridgeNetSettings
	// The host's own overlay address in X's block, which both of the share's targets name: 100.80.7.20.
	HostAddress netip.Addr
	// The first target's alias in Y's block, as host bits of its upper /17: 0x8001, x.y.128.1. That target is the
	// host's address on every protocol.
	AliasHostBits uint32
	// The second target's alias: 0x8002, x.y.128.2. That target is the host's address for TCP to its upstream's port
	// alone, so a flow there on another port or protocol is the target's to refuse.
	PortAliasHostBits uint32
	// Y's block, which Y's senders route the aliases in: 100.90.0.0/16.
	AcceptingBlock netip.Prefix
	// How long a ShareCert the world signs runs past the Net's clock: 168 h, §17.9's 7 days.
	CertLifetime time.Duration
	// The lowest destination port a window's own client policy passes to a share's alias, a public relationship to it:
	// 1024, connect's CFAA rule, which drops every privileged port but a few named services before any packet leaves
	// the window. PortTargetOtherPort picks no port under it; zero lets it pick any.
	UnprivilegedPortFirst uint16
}

func DefaultBridgeShareNetSettings() *BridgeShareNetSettings {
	return &BridgeShareNetSettings{
		HostAddress:           netip.MustParseAddr("100.80.7.20"),
		AliasHostBits:         0x8001,
		PortAliasHostBits:     0x8002,
		AcceptingBlock:        netip.MustParsePrefix("100.90.0.0/16"),
		CertLifetime:          168 * time.Hour,
		UnprivilegedPortFirst: 1024,
	}
}

// What a platform answers about shares between networks (§8.11, §6.10.1 item 4), beside BridgeNetPlatform: it takes
// each network's verified ACL state, which its contract rule reads for that network's half of a share, and says which
// network each contract it issued was escrowed from. A platform without it settles no share, so every honest contract
// between two networks' clients is refused and only the operator's minted ones reach a share's host. Safe for
// concurrent use.
type BridgeNetSharePlatform interface {
	// Takes each network's verified state, which the platform's contract rule reads from then on, in place of any it
	// held for that network.
	SetShareStates(ctx context.Context, states map[sidecar.Id]*sidecar.AclGateSnapshot) error
	// The network the contract's escrow was reserved from, and false for a contract the platform did not issue.
	ContractPayer(ctx context.Context, contractId connect.Id) (sidecar.Id, bool, error)
}

// TCP's IANA protocol number, as a share target's protocol names it. An identifier.
const bridgeShareNetProtocolTcp = 6

// One share between two networks. See the file's comment.
type BridgeShareNet struct {
	t        AdmissionT
	settings *BridgeShareNetSettings
	// X, its host and the host's device
	X          *BridgeNet
	Host       *BridgeNetHost
	HostDevice *BridgeNetDevice
	// Y, the accepting network; its granted reader, whose delegations the test signs unless it names another subject;
	// and its ungranted reader, whom no rule of Y's lets reach X
	AcceptingNetworkId sidecar.Id
	AcceptingSidecarId sidecar.Id
	UngrantedSidecarId sidecar.Id
	ShareId            sidecar.Id
	// the share's GrantActivate's grant_id, which the grant file names
	GrantId []byte

	shareKey ed25519.PrivateKey
	row      *sidecar.BridgeShareRow
	// the upstream every host of the share reaches, the share net's own, so its ports are known before the target
	// table is sealed and stay the same across a host's restart
	upstream *BridgeNetUpstream
	// the one port the second target admits, the upstream's TCP port, sealed into the immutable target table
	portTargetPort uint16
	// the host's posture store, which a restart restores from
	postureStore *BridgeNetPostureStore
	// Y's verified state, which the platform takes beside X's
	acceptingState *sidecar.AclGateSnapshot
	// each reader's own client on the platform, by sidecar
	readerClientIds map[sidecar.Id]connect.Id
}

// The implicit document's shares rule (§8.5), its third requests rule after four grants: rule i takes the first 16
// bytes of SHA-256("urnetwork-sidecar-v1/acl-implicit-rule" || 0x00 || u32be(i)) (acl_implicit.go).
func bridgeShareNetImplicitSharesRule() []byte {
	hash := sha256.New()
	hash.Write([]byte("urnetwork-sidecar-v1/acl-implicit-rule"))
	hash.Write([]byte{0x00})
	hash.Write(binary.BigEndian.AppendUint32(nil, 6))
	return hash.Sum(nil)[:16]
}

// X with its host serving a share Y accepted, the host enforcing a state that holds it (the file's comment), failing
// through t. settings nil is DefaultBridgeShareNetSettings. The caller closes it before net.
func NewBridgeShareNet(t AdmissionT, net *Net, settings *BridgeShareNetSettings) *BridgeShareNet {
	t.Helper()
	if settings == nil {
		settings = DefaultBridgeShareNetSettings()
	}
	bridgeSettings := settings.Bridge
	if bridgeSettings == nil {
		bridgeSettings = NetBridgeSettings(net)
	}
	if bridgeSettings == nil {
		bridgeSettings = DefaultBridgeNetSettings()
	}
	withSpend := *bridgeSettings
	withSpend.AclSpendCheck = sidecar.NewSpendCheck(nil)
	self := &BridgeShareNet{
		t:                  t,
		settings:           settings,
		X:                  NewBridgeNet(t, net, &withSpend),
		AcceptingNetworkId: sidecar.NewId(),
		ShareId:            sidecar.NewId(),
		readerClientIds:    map[sidecar.Id]connect.Id{},
	}
	shareSeed := make([]byte, ed25519.SeedSize)
	rand.Read(shareSeed)
	self.shareKey = ed25519.NewKeyFromSeed(shareSeed)
	self.HostDevice = self.X.AddDevice("share host")
	upstream, err := newBridgeNetUpstream(self.X.Settings().ReadByteCount)
	if err != nil {
		self.X.Close()
		t.Fatalf("the share's upstream: %v", err)
	}
	self.upstream = upstream
	self.accepting()
	self.activate()
	self.pin()
	self.postureStore = NewBridgeNetPostureStore()
	self.Host = self.X.StartHost(self.HostDevice, &BridgeNetHostSettings{
		Address:                 settings.HostAddress,
		ProvideFriendsAndFamily: true,
		ShareRows:               self,
		PostureStore:            self.postureStore,
		Upstream:                self.upstream,
	})
	self.waitShare()
	self.gate()
	return self
}

// Y's state and its readers' clients (the file's readers row): the granted reader's rule dials network:X, and the
// ungranted reader has none.
func (self *BridgeShareNet) accepting() {
	self.t.Helper()
	view := NewFakeAclView()
	owner := view.AddMember(bridge.MemberRole_MEMBER_ROLE_OWNER)
	self.AcceptingSidecarId = view.AddDevice(owner)
	self.UngrantedSidecarId = view.AddDevice(owner)
	atom := FakeAclSidecarAtom(self.AcceptingSidecarId)
	rows := &sidecarprotocol.AclRows{
		HasDocument: true,
		Atoms:       []*sidecarprotocol.AclAtom{atom},
		Rules: []*sidecarprotocol.AclRule{{
			RuleId:   sidecar.NewId().Bytes(),
			SrcAtoms: [][]byte{atom.Atom},
			Targets:  []*sidecarprotocol.AclTarget{{NetworkId: self.X.NetworkId().Bytes()}},
			Actions:  []uint32{uint32(sidecarprotocol.AclAction_ACL_ACTION_DIAL)},
		}},
	}
	state, err := sidecar.NewAclState(rows, view)
	if err != nil {
		self.t.Fatalf("Y's state: %v", err)
	}
	self.acceptingState = &sidecar.AclGateSnapshot{Pin: view.Pin(), Acl: state}
	for _, reader := range []struct {
		name      string
		sidecarId sidecar.Id
	}{
		{name: "Y's reader", sidecarId: self.AcceptingSidecarId},
		{name: "Y's ungranted reader", sidecarId: self.UngrantedSidecarId},
	} {
		clientId, err := self.X.platform.AddClient(self.X.Net().Context(), &BridgeNetClientArgs{
			Name: reader.name, NetworkId: self.AcceptingNetworkId, SidecarId: reader.sidecarId,
		})
		if err != nil {
			self.t.Fatalf("%s's client: %v", reader.name, err)
		}
		self.readerClientIds[reader.sidecarId] = clientId
	}
}

// Both networks' verified states to the platform (the file's gate row), X's as its readers hold it now. A platform
// that settles no share takes nothing.
func (self *BridgeShareNet) gate() {
	self.t.Helper()
	platform, ok := self.X.platform.(BridgeNetSharePlatform)
	if !ok {
		return
	}
	state := self.X.Admission().State()
	acl, err := state.Acl()
	if err != nil {
		self.Close()
		self.t.Fatalf("X's acl state: %v", err)
	}
	if err := platform.SetShareStates(self.X.Net().Context(), map[sidecar.Id]*sidecar.AclGateSnapshot{
		self.X.NetworkId():      {Pin: state.Pin(), Config: state, Acl: acl},
		self.AcceptingNetworkId: self.acceptingState,
	}); err != nil {
		self.Close()
		self.t.Fatalf("the platform took no share states: %v", err)
	}
}

// A reader's own client on the platform, in Y's network.
func (self *BridgeShareNet) ReaderClientId(readerId sidecar.Id) connect.Id {
	return self.readerClientIds[readerId]
}

// The network each contract was escrowed from, the platform's answer (BridgeNetSharePlatform); an error for a platform
// that settles no share or a contract it did not issue.
func (self *BridgeShareNet) ContractPayer(contractId connect.Id) (sidecar.Id, error) {
	platform, ok := self.X.platform.(BridgeNetSharePlatform)
	if !ok {
		return sidecar.Id{}, fmt.Errorf("the platform settles no share")
	}
	payer, found, err := platform.ContractPayer(self.X.Net().Context(), contractId)
	switch {
	case err != nil:
		return sidecar.Id{}, err
	case !found:
		return sidecar.Id{}, fmt.Errorf("the platform issued no contract %s", contractId)
	}
	return payer, nil
}

// A reader's honest window to the host (the file's comment): a child of the reader's own client in Y's network, its
// contracts the platform's, carrying the reader's delegation by signerGeneration's ShareSigner under cert.
func (self *BridgeShareNet) OpenReaderWindow(name string, readerId sidecar.Id, cert func() []byte, signerGeneration uint64) *BridgeNetWindow {
	self.t.Helper()
	parentClientId, found := self.readerClientIds[readerId]
	if !found {
		self.t.Fatalf("no reader %s of Y's", readerId)
	}
	return self.X.OpenWindow(name, nil, self.Host, &BridgeNetWindowArgs{
		ProvideMode:    protocol.ProvideMode_FriendsAndFamily,
		NetworkId:      self.AcceptingNetworkId,
		ParentClientId: &parentClientId,
		Sign: func(window *BridgeNetWindow) []byte {
			return self.Delegation(window, cert(), signerGeneration, func(delegation *bridge.WindowDelegation) {
				delegation.SubjectSidecarId = readerId.Bytes()
			})
		},
	})
}

// Waits until the host's state holds the share: its first compile waits for the share's row, which its fetcher takes
// from the world and then compiles again. A component raises nothing when a compile lands, so this polls, bounded by
// WaitTimeout.
func (self *BridgeShareNet) waitShare() {
	self.t.Helper()
	settings := self.X.Settings()
	deadline := time.Now().Add(settings.WaitTimeout)
	for len(self.Host.Rules().GetShares()) != 1 {
		if deadline.Before(time.Now()) {
			self.Close()
			self.t.Fatalf("the host compiled %d shares", len(self.Host.Rules().GetShares()))
		}
		select {
		case <-self.X.Net().Context().Done():
			self.t.Fatal("the net ended before the host compiled the share")
		case <-time.After(settings.PollInterval):
		}
	}
}

// Closes X's world, then the share's upstream.
func (self *BridgeShareNet) Close() {
	self.X.Close()
	if self.upstream != nil {
		self.upstream.close()
	}
}

// sidecar.BridgeShareRowSource: the share's row as api stores it, and no other share's.
func (self *BridgeShareNet) GetBridgeShare(ctx context.Context, shareId sidecar.Id) (*sidecar.BridgeShareRow, error) {
	if shareId != self.ShareId || self.row == nil {
		return nil, &sidecar.SidecarApiError{Status: 404, Code: "not_found"}
	}
	row := *self.row
	return &row, nil
}

// The share's grant in X (the file's activate row): a dial on the host for network:Y, requested by X's owner's device
// under the implicit shares rule, decided by the owner, an admin, on a second device of its own, since a spender never
// decides its own spend, and spent in a GrantActivate.
func (self *BridgeShareNet) activate() {
	self.t.Helper()
	admission := self.X.Admission()
	owner := admission.Owner()
	approver := admission.Device("share approver", owner.MemberId)
	admission.AdmitDevice(owner, approver, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
	clear := &sidecarprotocol.CanonicalAction{
		Kind:           uint32(sidecarprotocol.SidecarActionKind_SIDECAR_ACTION_KIND_FORWARD),
		GrantDst:       []string{fmt.Sprintf("sidecar:%x", self.HostDevice.SidecarId().Bytes())},
		GrantAllow:     []string{"dial"},
		RuleId:         bridgeShareNetImplicitSharesRule(),
		Subject:        owner.SidecarId.Bytes(),
		ShareNetworkId: self.AcceptingNetworkId.Bytes(),
		// a share's grant names the other network, version 4's field (record.proto's share_network_id)
		Version: 4,
	}
	detail := &sidecarprotocol.CanonicalActionDetail{GrantDst: []string{"ip:" + netip.PrefixFrom(self.settings.HostAddress, 32).String()}}
	action, err := sidecar.NewSealedCanonicalAction(clear, detail, self.X.ConfigKey(), self.X.NetworkId(), nil)
	if err != nil {
		self.t.Fatalf("the share's action: %v", err)
	}
	requestId := sidecar.NewId()
	payloadSha256 := action.PayloadSha256()
	now := self.X.Net().Clock().Now()
	approval := &sidecarprotocol.ApprovalRequest{
		ApprovalId:         requestId.Bytes(),
		CanonicalAction:    action.Bytes,
		PayloadSha256:      payloadSha256[:],
		RequesterSidecarId: owner.SidecarId.Bytes(),
		NotAfterMillis:     now.Add(24 * time.Hour).UnixMilli(),
		Version:            1,
	}
	approvalBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(approval)
	if err != nil {
		self.t.Fatal(err)
	}
	requestSha256 := sidecar.ApprovalRequestSha256(approvalBytes)
	decisionBody, err := proto.MarshalOptions{Deterministic: true}.Marshal(&sidecarprotocol.ApprovalDecision{
		ApprovalId:         requestId.Bytes(),
		RequestSha256:      requestSha256[:],
		PayloadSha256:      payloadSha256[:],
		Decision:           uint32(sidecarprotocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE),
		Uses:               1,
		NotAfterMillis:     now.Add(time.Hour).UnixMilli(),
		ApproverMemberId:   owner.MemberId.Bytes(),
		Channel:            uint32(sidecarprotocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE),
		RequesterSidecarId: owner.SidecarId.Bytes(),
		AuthPin:            admission.Tip(),
		Version:            1,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	decision := &bridge.Signed{
		Body:      decisionBody,
		SignerId:  approver.SidecarId.Bytes(),
		Signature: ed25519.Sign(approver.Key, bridge.SignedBytes(sidecar.ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, decisionBody)),
		Type:      uint32(bridge.SignedType_SIGNED_APPROVAL_DECISION),
	}
	grantId := sidecar.AclGrantId(requestId, payloadSha256)
	self.GrantId = grantId[:]
	admission.MustLand(admission.Sign(owner, bridge.SignedType_SIGNED_GRANT_ACTIVATE, &sidecarprotocol.GrantActivate{
		Header: admission.Header(), GrantId: grantId[:], CanonicalAction: action.Bytes, Decisions: []*bridge.Signed{decision},
	}))
}

// The share's row and X's grant file (the file's row and pin rows).
func (self *BridgeShareNet) pin() {
	self.t.Helper()
	code := make([]byte, 32)
	rand.Read(code)
	seal, err := sidecar.NewBridgeShareSeal(code, self.X.NetworkId(), nil)
	if err != nil {
		self.t.Fatal(err)
	}
	address := self.settings.HostAddress.As4()
	self.portTargetPort = self.upstream.TcpPort()
	targets := &bridge.BridgeShareTargets{Targets: []*bridge.BridgeShareTarget{
		{
			Index:                 0,
			HostSidecarId:         self.HostDevice.SidecarId().Bytes(),
			HostIdentityPublicKey: bytes.Clone(self.HostDevice.Device.PublicKey()),
			Prefix:                &bridge.BridgeIpv4Prefix{Address: binary.BigEndian.Uint32(address[:]), Length: 32},
		},
		{
			Index:                 1,
			HostSidecarId:         self.HostDevice.SidecarId().Bytes(),
			HostIdentityPublicKey: bytes.Clone(self.HostDevice.Device.PublicKey()),
			Prefix:                &bridge.BridgeIpv4Prefix{Address: binary.BigEndian.Uint32(address[:]), Length: 32},
			Protocol:              bridgeShareNetProtocolTcp,
			Ports:                 []*bridge.BridgePortRange{{First: uint32(self.portTargetPort), Last: uint32(self.portTargetPort)}},
		},
	}}
	targetTable, err := seal.Seal(sidecar.BridgeShareLabelTargets, sidecar.Id{}, 1, targets, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	aliases := &bridge.BridgeShareAliases{Aliases: []*bridge.BridgeShareAlias{
		{Index: 0, AliasHostBits: self.settings.AliasHostBits, Length: 32},
		{Index: 1, AliasHostBits: self.settings.PortAliasHostBits, Length: 32},
	}}
	sealedAliases, err := seal.Seal(sidecar.BridgeShareLabelAliases, self.AcceptingNetworkId, 1, aliases, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	sharePublicKey := self.shareKey.Public().(ed25519.PublicKey)
	sealedKey, err := seal.Seal(sidecar.BridgeShareLabelShareKey, self.AcceptingNetworkId, 1, &bridge.BridgeShareKeyBody{SharePublicKey: sharePublicKey}, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	aliasTable, err := proto.MarshalOptions{Deterministic: true}.Marshal(&bridge.BridgeShareAccept{Aliases: sealedAliases, ShareKey: sealedKey})
	if err != nil {
		self.t.Fatal(err)
	}
	self.row = &sidecar.BridgeShareRow{
		ShareId: self.ShareId, SharingNetworkId: self.X.NetworkId(), AcceptingNetworkId: self.AcceptingNetworkId,
		TargetTable: targetTable, TargetTableVersion: 1, AliasTable: aliasTable, AliasTableVersion: 1,
		AcceptStatus: sidecar.BridgeShareAcceptStatusActive,
	}
	grantFile, err := proto.MarshalOptions{Deterministic: true}.Marshal(&bridge.BridgeShareGrant{
		ShareId:            self.ShareId.Bytes(),
		GrantId:            bytes.Clone(self.GrantId),
		SharePublicKey:     bytes.Clone(sharePublicKey),
		TargetTableSha256:  sidecar.BridgeShareTableSha256(targetTable),
		TableKey:           seal.TableKey(),
		AcceptingNetworkId: self.AcceptingNetworkId.Bytes(),
		AliasTableSha256:   sidecar.BridgeShareTableSha256(aliasTable),
		TargetTableVersion: 1,
		AliasTableVersion:  1,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.X.Admission().SaveHead(func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error) {
		return head.WithFile(sidecar.ConfigHeadBridgeShareGrantPath(self.ShareId), grantFile)
	})
}

// The target's alias in Y's block, where Y's senders send what reaches the host's address.
func (self *BridgeShareNet) Alias() netip.Addr {
	return self.aliasAt(self.settings.AliasHostBits)
}

// The second target's alias in Y's block, where TCP to PortTargetPort alone reaches the host's address.
func (self *BridgeShareNet) PortAlias() netip.Addr {
	return self.aliasAt(self.settings.PortAliasHostBits)
}

// The one port the second target admits: the TCP port of the upstream every host of the share reaches.
func (self *BridgeShareNet) PortTargetPort() uint16 {
	return self.portTargetPort
}

// A TCP port beside PortTargetPort that the second target does not admit and a flow to which still reaches the host's
// hook to be refused there: never the host's daemon listener, which rule 0 denies whatever a target admits, and never
// one under UnprivilegedPortFirst, which the window's own client policy drops before the host sees it. A port past the
// top of the range is never taken, so a target port of 65535 looks below it. Fails the test when no port beside the
// target's qualifies.
func (self *BridgeShareNet) PortTargetOtherPort() uint16 {
	self.t.Helper()
	daemonPort := 0
	if daemon, ok := self.Host.Daemon.Addr().(*net.TCPAddr); ok {
		daemonPort = daemon.Port
	}
	port := int(self.portTargetPort)
	for _, candidate := range []int{port + 1, port - 1, port + 2, port - 2} {
		if int(self.settings.UnprivilegedPortFirst) <= candidate && candidate <= math.MaxUint16 && candidate != daemonPort {
			return uint16(candidate)
		}
	}
	self.t.Fatalf("no TCP port beside the port target's %d is free of the daemon's %d and at or above %d", port, daemonPort, self.settings.UnprivilegedPortFirst)
	return 0
}

// The address at hostBits in Y's block.
func (self *BridgeShareNet) aliasAt(hostBits uint32) netip.Addr {
	block := self.settings.AcceptingBlock.Addr().As4()
	address := binary.BigEndian.Uint32(block[:]) | hostBits
	return netip.AddrFrom4([4]byte{byte(address >> 24), byte(address >> 16), byte(address >> 8), byte(address)})
}

// The seed of Y's ShareSigner of a generation, which Y's keyring draws fresh and the world fixes.
func (self *BridgeShareNet) signerSeed(generation uint64) []byte {
	seed := sha256.Sum256(append(append([]byte("share net signer "), self.ShareId.Bytes()...), byte(generation)))
	return seed[:]
}

// A ShareCert of the share at a generation, certifying that generation's signer until notAfter, signed by key, Y's
// ShareKey for nil.
func (self *BridgeShareNet) Cert(generation uint64, notAfter time.Time, key ed25519.PrivateKey) []byte {
	self.t.Helper()
	if key == nil {
		key = self.shareKey
	}
	cert, err := bridge.ShareCertSigned(&bridge.ShareCert{
		ShareId:          self.ShareId.Bytes(),
		ConfigGeneration: generation,
		SignerPublicKey:  ed25519.NewKeyFromSeed(self.signerSeed(generation)).Public().(ed25519.PublicKey),
		NotAfterMs:       notAfter.UnixMilli(),
	}, key.Seed(), nil)
	if err != nil {
		self.t.Fatalf("the share's cert: %v", err)
	}
	return cert
}

// A cert of a generation running CertLifetime past the Net's clock, by Y's ShareKey.
func (self *BridgeShareNet) CurrentCert(generation uint64) []byte {
	return self.Cert(generation, self.X.Net().Clock().Now().Add(self.settings.CertLifetime), nil)
}

// Y's sidecar's delegation for window to the host on the share, carrying cert, signed by signerGeneration's ShareSigner,
// lapsing DelegationLifetime past the Net's clock, edit applied first.
func (self *BridgeShareNet) Delegation(window *BridgeNetWindow, cert []byte, signerGeneration uint64, edit func(delegation *bridge.WindowDelegation)) []byte {
	self.t.Helper()
	delegation := &bridge.WindowDelegation{
		NetworkId:             self.AcceptingNetworkId.Bytes(),
		SubjectSidecarId:      self.AcceptingSidecarId.Bytes(),
		WindowClientId:        window.Client.ClientId.Bytes(),
		WindowClientPublicKey: window.Client.Client.ClientKeyManager().PublicKey(),
		TargetSidecarId:       self.HostDevice.SidecarId().Bytes(),
		NotAfterMs:            self.X.Net().Clock().Now().Add(self.X.Settings().DelegationLifetime).UnixMilli(),
		ShareId:               self.ShareId.Bytes(),
		ShareCert:             cert,
	}
	if edit != nil {
		edit(delegation)
	}
	signed, err := bridge.WindowDelegationSigned(delegation, func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
		return bridge.ShareSignerSign(delegation.GetShareId(), self.signerSeed(signerGeneration), body)
	}, nil)
	if err != nil {
		self.t.Fatalf("the share's delegation: %v", err)
	}
	return signed
}

// A window client of Y's to the host, as the operator mints it: every contract it asks for FriendsAndFamily, sealed to
// network, Y's for the zero id, and to a source subject of the operator's choosing, never the delegation's, so the
// principal the host verifies is the signer's whatever C13 sealed (§22.7's forged source_subject); carrying what
// delegation answers for the window. Its flows go to Alias.
func (self *BridgeShareNet) OpenWindow(name string, network sidecar.Id, delegation func(window *BridgeNetWindow) []byte) *BridgeNetWindow {
	self.t.Helper()
	if network == (sidecar.Id{}) {
		network = self.AcceptingNetworkId
	}
	sealedNetwork := connect.Id(network)
	subject := connect.Id(sidecar.NewId())
	return self.X.OpenWindow(name, self.HostDevice, self.Host, &BridgeNetWindowArgs{
		ProvideMode:  protocol.ProvideMode_FriendsAndFamily,
		NoDelegation: true,
		Mint: func(window *BridgeNetWindow, request *protocol.CreateContract) *MintContractArgs {
			return &MintContractArgs{
				SourceId:              window.Client.ClientId,
				DestinationId:         self.Host.Client.ClientId,
				ProvideMode:           protocol.ProvideMode_FriendsAndFamily,
				SourceSubjectClientId: &subject,
				SourceNetworkId:       &sealedNetwork,
				ContractClass:         protocol.ContractClass_ContractClassData,
				WindowDelegation:      delegation(window),
				TransferByteCount:     self.X.Settings().ContractByteCount,
			}
		},
	})
}

// Restarts the host from the posture store it kept: its role, component and client are closed, and new ones built on
// the same store, its address filed already (§17.8's persisted state).
func (self *BridgeShareNet) RestartHost() {
	self.t.Helper()
	self.Host.Close()
	self.Host = self.X.StartHost(self.HostDevice, &BridgeNetHostSettings{
		ProvideFriendsAndFamily: true,
		ShareRows:               self,
		PostureStore:            self.postureStore,
		Upstream:                self.upstream,
	})
	self.Host.Address = self.settings.HostAddress
	self.waitShare()
}

var _ BridgeNetSharePlatform = (*bridgeNetFakePlatform)(nil)

// Keeps each network's state, which shareSettles reads.
func (self *bridgeNetFakePlatform) SetShareStates(ctx context.Context, states map[sidecar.Id]*sidecar.AclGateSnapshot) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for networkId, snapshot := range states {
		if snapshot == nil || snapshot.Acl == nil {
			return fmt.Errorf("network %s's state holds no acl part", networkId)
		}
		self.shareStates[networkId] = snapshot
	}
	return nil
}

// The payer createContract kept.
func (self *bridgeNetFakePlatform) ContractPayer(ctx context.Context, contractId connect.Id) (sidecar.Id, bool, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	payer, found := self.contractPayers[contractId]
	return payer, found, nil
}

// How a contract between two networks' clients settles as a share, as server's CreateContract settles one (§6.10.1
// item 4; model.AclShareBetween over the gate's share half, acl_share.go): a non-companion from a sidecar's subject of
// one network to another network's sidecar's own client is FriendsAndFamily when both halves hold, each on its own
// network's state (sidecar.AclShareReach on the Net's clock), and the destination provides FriendsAndFamily; a
// companion answering such a contract is Stream, sealed as its forward contract. false refuses the contract: no client
// here provides Public, which server's Public rule would leave such a pair to.
func (self *bridgeNetFakePlatform) shareSettles(
	sourceId connect.Id,
	source *bridgeNetFakeClient,
	destinationId connect.Id,
	destination *bridgeNetFakeClient,
	companion bool,
) (protocol.ProvideMode, bool) {
	var sourceState, destinationState *sidecar.AclGateSnapshot
	var answersShare bool
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		sourceState, destinationState = self.shareStates[source.networkId], self.shareStates[destination.networkId]
		_, answersShare = self.shareOrigins[[2]connect.Id{destinationId, sourceId}]
	}()
	if companion {
		return protocol.ProvideMode_Stream, answersShare
	}
	if source.subjectSidecarId == (sidecar.Id{}) || destination.subjectSidecarId == (sidecar.Id{}) || destination.subjectClientId != destinationId {
		// a subject the gate cannot tell, or a destination that is no sidecar's own client
		return protocol.ProvideMode_None, false
	}
	if sourceState == nil || destinationState == nil {
		return protocol.ProvideMode_None, false
	}
	outbound, inbound := sidecar.AclShareReach(
		sourceState.Acl, source.networkId, sidecar.AclSubject{Kind: sidecar.AclSubjectSidecar, Id: source.subjectSidecarId},
		destinationState.Acl, destination.networkId, sidecar.AclSubject{Kind: sidecar.AclSubjectSidecar, Id: destination.subjectSidecarId},
		self.net.Clock().Now(),
	)
	if !outbound.Allowed || !inbound.Allowed {
		return protocol.ProvideMode_None, false
	}
	client := self.net.exchange.client(destinationId)
	if client == nil {
		return protocol.ProvideMode_None, false
	}
	if _, provides := client.Client.ContractManager().GetProvideSecretKey(protocol.ProvideMode_FriendsAndFamily); !provides {
		return protocol.ProvideMode_None, false
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.shareOrigins[[2]connect.Id{sourceId, destinationId}] = struct{}{}
	}()
	return protocol.ProvideMode_FriendsAndFamily, true
}

// §22.7's FriendsAndFamily clause, on both tiers: FS-38's share case, whose twin runs a reader's honest window on the
// platform's contracts beside the operator's minted one (sidecartest/fault/fs_bridge_m6.go).
var (
	_ = RegisterPrivacyAssert("friends-and-family", &PrivacyAssertTest{Repo: "sidecar", Package: "github.com/urnetwork/sidecar/sidecartest/fault", Name: "TestFs38Share"})
	_ = RegisterPrivacyAssert("friends-and-family", &PrivacyAssertTest{Repo: "server", Package: "github.com/urnetwork/server/controller", Name: "TestFs38ShareOnT3", Tags: "sidecar_pending"})
)
