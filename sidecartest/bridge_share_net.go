//go:build !sidecar_http && !ios_extension

// §17.9's share end to end (BRIDGE-M6-08; FS-38's share rows, §22.7's share asserts): two networks on one Net. The
// sharing network X is a BridgeNet whose host serves a share the accepting network Y holds, every part of it X's own
// and real: the share's grant activated through X's ACL by its admin's decision under §16.6's spend check, the grant
// file pinning Y's ShareKey, K and both tables' hashes written into X's head, the share's row at api sealed under K,
// and the host's compile, device role, provider NAT and upstream the BridgeNet's. Y is what X's host sees of it: its
// network id, the ShareKey its approving admin holds, the ShareSigners each generation of its config certifies, and
// window clients whose contracts carry a ShareSigner's delegation, FriendsAndFamily and sealed to Y.
//
//	activate  X's admin requests the share's grant, a dial on the host for network:Y under the implicit document's
//	          shares rule (QD-820), decides it on its own device and spends the decision in a GrantActivate
//	pin       the grant file bridge/share-grant/<share_id hex> in a head of X's: the grant, Y's ShareKey, K, Y and both
//	          tables' hashes and versions (QD-077, QD-670)
//	row       the target table, the host's address as a /32 on every protocol, sealed under K at version 1, and Y's
//	          side, the alias table and the ShareKey sealed under K, as network_bridge_share stores them; the host
//	          fetches it from the world (BridgeNetHostSettings.ShareRows), since no api serves these networks
//	sign      a ShareCert of a generation by Y's ShareKey, and a delegation by that generation's ShareSigner, as Y's
//	          keyring and sidecars make them (bridge.ShareCertSigned, bridge.ShareSignerSign)
//
// Y's routers are not run here: a share window is the operator's minted client, whose every contract the test mints
// FriendsAndFamily and sealed to Y, so what the host admits rests on its own checks alone, which is FS-38's question;
// Y's honest gate and routers are ACL's and the sender's tests'. Safe for concurrent use. A BridgeShareNet is closed by
// its test, before its Net.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
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
	// The host's own overlay address in X's block, the share's one target: 100.80.7.20.
	HostAddress netip.Addr
	// The target's alias in Y's block, as host bits of its upper /17: 0x8001, x.y.128.1.
	AliasHostBits uint32
	// Y's block, which Y's senders route the alias in: 100.90.0.0/16.
	AcceptingBlock netip.Prefix
	// How long a ShareCert the world signs runs past the Net's clock: 168 h, §17.9's 7 days.
	CertLifetime time.Duration
}

func DefaultBridgeShareNetSettings() *BridgeShareNetSettings {
	return &BridgeShareNetSettings{
		HostAddress:    netip.MustParseAddr("100.80.7.20"),
		AliasHostBits:  0x8001,
		AcceptingBlock: netip.MustParsePrefix("100.90.0.0/16"),
		CertLifetime:   168 * time.Hour,
	}
}

// One share between two networks. See the file's comment.
type BridgeShareNet struct {
	t        AdmissionT
	settings *BridgeShareNetSettings
	// X, its host and the host's device
	X          *BridgeNet
	Host       *BridgeNetHost
	HostDevice *BridgeNetDevice
	// Y, the accepting network, and a sidecar of it whose delegations the test signs
	AcceptingNetworkId sidecar.Id
	AcceptingSidecarId sidecar.Id
	ShareId            sidecar.Id
	// the share's GrantActivate's grant_id, which the grant file names
	GrantId []byte

	shareKey ed25519.PrivateKey
	row      *sidecar.BridgeShareRow
	// the host's posture store, which a restart restores from
	postureStore *bridgeNetPostureStore
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
		AcceptingSidecarId: sidecar.NewId(),
		ShareId:            sidecar.NewId(),
	}
	shareSeed := make([]byte, ed25519.SeedSize)
	rand.Read(shareSeed)
	self.shareKey = ed25519.NewKeyFromSeed(shareSeed)
	self.HostDevice = self.X.AddDevice("share host")
	self.activate()
	self.pin()
	self.postureStore = newBridgeNetPostureStore()
	self.Host = self.X.StartHost(self.HostDevice, &BridgeNetHostSettings{
		Address:                 settings.HostAddress,
		ProvideFriendsAndFamily: true,
		ShareRows:               self,
		PostureStore:            self.postureStore,
	})
	self.waitShare()
	return self
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

// Closes X's world.
func (self *BridgeShareNet) Close() {
	self.X.Close()
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
	targets := &bridge.BridgeShareTargets{Targets: []*bridge.BridgeShareTarget{{
		Index:                 0,
		HostSidecarId:         self.HostDevice.SidecarId().Bytes(),
		HostIdentityPublicKey: bytes.Clone(self.HostDevice.Device.PublicKey()),
		Prefix:                &bridge.BridgeIpv4Prefix{Address: binary.BigEndian.Uint32(address[:]), Length: 32},
	}}}
	targetTable, err := seal.Seal(sidecar.BridgeShareLabelTargets, sidecar.Id{}, 1, targets, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	aliases := &bridge.BridgeShareAliases{Aliases: []*bridge.BridgeShareAlias{{Index: 0, AliasHostBits: self.settings.AliasHostBits, Length: 32}}}
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
	block := self.settings.AcceptingBlock.Addr().As4()
	address := binary.BigEndian.Uint32(block[:]) | self.settings.AliasHostBits
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
	})
	self.Host.Address = self.settings.HostAddress
	self.waitShare()
}
