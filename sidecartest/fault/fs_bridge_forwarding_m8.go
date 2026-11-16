//go:build !sidecar_http && !ios_extension

// BRIDGE-M8-07's forwarding rows on sidecartest's BridgeNet (DESIGN-DETAILS 4.6's FS-38 rows; FS-38, FI-11,
// D-BRIDGE-17, D-SDK-32, I-3, I-4, owner decision 197): the subject's forwarding Delegation lands in the network's log,
// signed by its own identity key as §18.6's setup signs it, the host's real component compiles it into the subject's
// BridgeIdentity (BRIDGE-M8-04), and window clients carry WindowDelegations its forwarding key signs, signer_id the
// Delegation's 32-byte id and key_id the key's SHA-256, as an app's VPN component signs them (§18.6's Signing). Each
// builder is exported, so server/controller/connect_bridge_forwarding_test.go runs the same ones on T3:
//
//   - the twin: a window signed by the subject's live forwarding key opens TCP, UDP and ICMP sockets, its principal the
//     subject of this network and its flows under the forwarding key's own tags (BridgeForwardRuleTag).
//   - the refusals, each carried by an honest window client of its subject's and opening no upstream socket: a key no
//     Delegation names, a superseded Delegation's key, a revoked one's, another sidecar's live forwarding key, the live
//     key under a 16-byte key id, and the live key's delegation lapsed.
//   - the forged case, the operator's (T2 alone; its twin carries T3): a window client the operator minted, its
//     contract HMACed under the host's provide secret and sealed to claim the subject, carrying a forwarding delegation
//     the operator signed or the subject's real one of another window client replayed, opens no socket.
//
// None of these is in the fault catalog: §23.6's M8 row names §22.5's forwarding cases, not an FS-38 case, so each runs
// as a schedule of its own until a design-records fold of DESIGN-DETAILS 4.6 gives FS-38 its M8-out case. What the
// forwarding rows still lack, each in BRIDGE-M8-07's report: an app host fed by its own Forwarder with the app's
// sidecar stopped, and the schedules that need one (a grant and a revocation within §8.9's targets, a DelegationRevoke
// racing a compile, a supersession racing a contract, a compile finishing below a newer state, a refused Unsuspend,
// FwdReach-NoCompile and Fwd.tla's twins as schedules).

package fault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// FS-38's forwarding refusals beside their twin, and the forged case beside the same twin.
var (
	Fs38ForwardingCase       = Twin(Fs38ForwardingRefusals, Fs38ForwardingDelegation)
	Fs38ForwardingForgedCase = Twin(Fs38ForwardingMinted, Fs38ForwardingDelegation)
)

// Whether the host's state lists forwarding as its subject's live forwarding Delegation (BRIDGE-M8-04's compile).
func fsForwardingCompiled(world *fsBridgeWorld, forwarding *sidecartest.BridgeNetForwarding) error {
	for _, identity := range world.host.State().GetIdentities() {
		if !bytes.Equal(identity.GetSidecarId(), forwarding.Subject.SidecarId().Bytes()) {
			continue
		}
		if !bytes.Equal(identity.GetForwardDelegationId(), forwarding.DelegationId) ||
			!bytes.Equal(identity.GetForwardPublicKey(), forwarding.Key.Public().(ed25519.PublicKey)) {
			return fmt.Errorf("the host's state lists %x as %s's forwarding Delegation, not %x", identity.GetForwardDelegationId(),
				forwarding.Subject.Name, forwarding.DelegationId)
		}
		return nil
	}
	return fmt.Errorf("the host's state holds no identity of %s", forwarding.Subject.Name)
}

// A window of forwarding's subject to the host, its delegation signed by forwarding's key, edited and keyed as
// SignForwardingDelegation takes them.
func fsForwardingWindow(world *fsBridgeWorld, name string, subject *sidecartest.BridgeNetDevice, forwarding *sidecartest.BridgeNetForwarding,
	edit func(delegation *bridge.WindowDelegation), keyId []byte,
) *sidecartest.BridgeNetWindow {
	return world.world.OpenWindow(name, subject, world.host, &sidecartest.BridgeNetWindowArgs{
		Sign: func(window *sidecartest.BridgeNetWindow) []byte {
			return world.world.SignForwardingDelegation(window, forwarding, edit, keyId)
		},
	})
}

// A forwarding Delegation no log holds: a key and a 32-byte id of the operator's.
func fsForwardingForged(subject *sidecartest.BridgeNetDevice) *sidecartest.BridgeNetForwarding {
	delegationId := sha256.Sum256([]byte("fs38 a forwarding Delegation no log holds"))
	return &sidecartest.BridgeNetForwarding{Subject: subject, DelegationId: delegationId[:], Key: fsBridgeOperatorKey()}
}

// FS-38's forwarding twin: the subject files its forwarding Delegation, the host compiles it, and a window whose
// delegation that key signed reaches the host over TCP, UDP and ICMP, admitted as the subject of this network under
// the forwarding key's tags.
func Fs38ForwardingDelegation(net *Net) *Schedule {
	world := newFsBridgeWorld()
	var forwarding *sidecartest.BridgeNetForwarding
	return fsBridgeSchedule("FS-38", "", world,
		fsBridgeSetup(world, "subject"),
		fsBridgeDo("subject", world, func() error {
			forwarding = world.world.FileForwarding(world.subjects["subject"], "fs38 twin")
			world.world.Follow()
			return fsForwardingCompiled(world, forwarding)
		}),
		fsBridgeDo("window", world, func() error {
			subject := world.subjects["subject"]
			window := fsForwardingWindow(world, "fs38 forwarding", subject, forwarding, nil, nil)
			if err := (&fsBridgeFlows{world: world, window: window}).expectOpen("fs38 forwarding"); err != nil {
				return err
			}
			principals := world.host.Principals(window.Client.ClientId)
			if len(principals) == 0 || principals[0].Principal == nil {
				return fmt.Errorf("the host verified no principal: %+v", principals)
			}
			principal := principals[0].Principal
			if principal.Subject != connect.Id(subject.SidecarId()) || principal.Network != connect.Id(world.world.NetworkId()) {
				return fmt.Errorf("the principal %+v is not the subject of this network", principal)
			}
			// rule 3's tag at the host's address, the forwarding key's own (DESIGN-DETAILS 4.2.5)
			addressOctets := world.host.Address.As4()
			ruleId := append([]byte{device.BridgeRuleHosted}, addressOctets[:]...)
			forwardTag := device.BridgeForwardRuleTag(connect.Id(subject.SidecarId()), [sha256.Size]byte(forwarding.DelegationId), ruleId)
			for _, decision := range world.host.Decisions(window.Client.ClientId) {
				if decision.Opens() && decision.RuleTag != forwardTag {
					return fmt.Errorf("a %s flow opened under tag %d, not the forwarding key's %d", decision.Protocol, decision.RuleTag, forwardTag)
				}
			}
			return nil
		}),
	)
}

// FS-38's forwarding refusals: each delegation, carried by an honest window client of its subject's, opens nothing.
func Fs38ForwardingRefusals(net *Net) *Schedule {
	world := newFsBridgeWorld()
	var superseded, live, revoked, others *sidecartest.BridgeNetForwarding
	steps := []*Step{
		fsBridgeSetup(world, "subject", "revoked", "other"),
		fsBridgeDo("subject", world, func() error {
			superseded = world.world.FileForwarding(world.subjects["subject"], "fs38 superseded")
			live = world.world.FileForwarding(world.subjects["subject"], "fs38 live")
			revoked = world.world.FileForwarding(world.subjects["revoked"], "fs38 revoked")
			world.world.RevokeForwarding(world.subjects["revoked"], revoked)
			others = world.world.FileForwarding(world.subjects["other"], "fs38 other")
			world.world.Follow()
			if err := fsForwardingCompiled(world, live); err != nil {
				return err
			}
			return fsForwardingCompiled(world, others)
		}),
	}
	shortKeyId := bytes.Repeat([]byte{0x16}, 16)
	cases := []struct {
		name    string
		subject string
		key     func() *sidecartest.BridgeNetForwarding
		edit    func(delegation *bridge.WindowDelegation)
		keyId   []byte
	}{
		{name: "a key no Delegation names", subject: "subject", key: func() *sidecartest.BridgeNetForwarding {
			return fsForwardingForged(world.subjects["subject"])
		}},
		{name: "a superseded Delegation's key", subject: "subject", key: func() *sidecartest.BridgeNetForwarding { return superseded }},
		{name: "a revoked Delegation's key", subject: "revoked", key: func() *sidecartest.BridgeNetForwarding { return revoked }},
		{name: "another sidecar's live forwarding key", subject: "subject", key: func() *sidecartest.BridgeNetForwarding { return others }},
		{name: "the live key under a 16-byte key id", subject: "subject", key: func() *sidecartest.BridgeNetForwarding { return live },
			keyId: shortKeyId},
		{name: "the live key's delegation lapsed", subject: "subject", key: func() *sidecartest.BridgeNetForwarding { return live },
			edit: func(delegation *bridge.WindowDelegation) {
				delegation.NotAfterMs = net.Clock().Now().Add(-time.Minute).UnixMilli()
			}},
	}
	for _, refusal := range cases {
		steps = append(steps, fsBridgeDo("window", world, func() error {
			window := fsForwardingWindow(world, "fs38 "+refusal.name, world.subjects[refusal.subject], refusal.key(), refusal.edit, refusal.keyId)
			defer window.Close()
			if err := (&fsBridgeFlows{world: world, window: window}).expectRefused("fs38 " + refusal.name); err != nil {
				return fmt.Errorf("a delegation signed by %s: %w", refusal.name, err)
			}
			return nil
		}))
	}
	return fsBridgeSchedule("FS-38", "a window client whose delegation a forwarding key signed that is not its subject's live one, or whose key id or lapse is wrong, opens no socket", world, steps...)
}

// FS-38's forwarding forged case: the operator's window clients, each contract minted to claim the subject and carrying
// a forwarding delegation the subject's live key did not sign for that client, open nothing.
func Fs38ForwardingMinted(net *Net) *Schedule {
	world := newFsBridgeWorld()
	var live *sidecartest.BridgeNetForwarding
	// the subject's honest forwarding window, whose real delegation the operator replays from another client
	var honest *sidecartest.BridgeNetWindow
	minted := func(delegation func(window *sidecartest.BridgeNetWindow) []byte) *sidecartest.BridgeNetWindowArgs {
		return &sidecartest.BridgeNetWindowArgs{
			NoDelegation: true,
			Mint: func(window *sidecartest.BridgeNetWindow, request *protocol.CreateContract) *sidecartest.MintContractArgs {
				subjectClientId := world.subjects["subject"].ClientId
				network := connect.Id(world.world.NetworkId())
				return &sidecartest.MintContractArgs{
					SourceId:              window.Client.ClientId,
					DestinationId:         world.host.Client.ClientId,
					ProvideMode:           protocol.ProvideMode_Network,
					SourceSubjectClientId: &subjectClientId,
					SourceNetworkId:       &network,
					ContractClass:         protocol.ContractClass_ContractClassData,
					WindowDelegation:      delegation(window),
					TransferByteCount:     world.world.Settings().ContractByteCount,
				}
			},
		}
	}
	cases := []struct {
		name string
		args func() *sidecartest.BridgeNetWindowArgs
	}{
		{name: "a forwarding delegation the operator signed", args: func() *sidecartest.BridgeNetWindowArgs {
			return minted(func(window *sidecartest.BridgeNetWindow) []byte {
				return world.world.SignForwardingDelegation(window, fsForwardingForged(world.subjects["subject"]), nil, nil)
			})
		}},
		{name: "the subject's forwarding delegation of another window client, replayed", args: func() *sidecartest.BridgeNetWindowArgs {
			return minted(func(window *sidecartest.BridgeNetWindow) []byte {
				return bytes.Clone(honest.Delegation)
			})
		}},
	}
	steps := []*Step{
		fsBridgeSetup(world, "subject"),
		fsBridgeDo("subject", world, func() error {
			live = world.world.FileForwarding(world.subjects["subject"], "fs38 minted")
			world.world.Follow()
			return fsForwardingCompiled(world, live)
		}),
		fsBridgeDo("window", world, func() error {
			honest = fsForwardingWindow(world, "fs38 forwarding honest", world.subjects["subject"], live, nil, nil)
			if len(honest.Delegation) == 0 {
				return errors.New("the honest window carries no delegation")
			}
			return nil
		}),
	}
	for _, refusal := range cases {
		steps = append(steps, fsBridgeDo("operator", world, func() error {
			window := world.world.OpenWindow("fs38 forwarding minted "+refusal.name, world.subjects["subject"], world.host, refusal.args())
			defer window.Close()
			if err := (&fsBridgeFlows{world: world, window: window}).expectRefused("fs38 forwarding minted"); err != nil {
				return fmt.Errorf("a minted contract with %s: %w", refusal.name, err)
			}
			return nil
		}))
	}
	schedule := fsBridgeSchedule("FS-38", "an operator-minted window client carrying a forwarding delegation the subject's live key did not sign for it opens no socket over TCP, UDP or ICMP", world, steps...)
	schedule.Tiers = []Tier{TierT2}
	schedule.Forged = true
	return schedule
}
