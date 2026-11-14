//go:build !sidecar_http && !ios_extension

// BRIDGE-M4-22's schedules (§22.8's FS-38 at M4-out and FS-56; FI-11, D-BRIDGE-17, D-BRIDGE-21, R-BRIDGE-12, I-3, I-5)
// on sidecartest's BridgeNet: one network whose config, compile, device role, provider NAT and window clients are
// each the real one, the network's statements signed by the devices that sign them in production, and the host's
// upstream a TCP and a UDP listener on loopback and the kernel's echo, each socket the NAT opens counted. Registered,
// each on T2 here; server/controller/connect_bridge_m4_test.go runs the same builders on T3 over server's
// CreateContract (BridgeNetSettings.Platform, through SetNetBridgeSettings):
//
//   - FS-38, its M4 part: a window client whose subject signed its delegation opens sockets over TCP, UDP and ICMP
//     (the twin); one whose delegation names another key, has lapsed, names another target or another network opens
//     none, each refused before data at the host's verify.
//   - FS-38's forged case, the operator's (T2 alone; its twin carries T3): a window client the operator minted, its
//     contract correctly HMACed under the host's provide secret and sealed to claim subject S, opens no socket over
//     TCP, UDP or ICMP, whether it carries no delegation, one the operator signed, or S's own delegation of another
//     window client replayed; nor does a FriendsAndFamily contract whose sealed network is not the one S's
//     delegation names.
//   - FS-56 through the whole stack: a flow resolved and its dial held at the NAT's gate; S revoked by an admin's
//     SidecarRevoke, which the component hands the role through Bridge.Revoke at its own position; the dial then
//     completes into a reset: for TCP the source never sees a SYN-ACK and the upstream socket closes having carried no
//     byte, for UDP the datagram is never written. An ICMP flow of a revoked subject is a silent drop. The twin, no
//     revocation, forwards each.
//
// What these do not cover, each in the task's report: FS-38's sender row, a substituted target key, and FS-56's
// bridged TCP/25, both on the sender's real link, and FS-56's ICMP case held mid-open, which connect exports no gate
// for (BRIDGE-M4-02's report), so the ICMP case revokes an answered flow instead. FI-11's oracle is TEST-M4-01's and
// unbuilt; FsBridgePathIntegrity stands in for its bridge half.

package fault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

var (
	Fs38Case       = Register("FS-38", "", []Tier{TierT2, TierT3}, Twin(Fs38DelegationRefusals, Fs38ValidDelegation))
	Fs38ForgedCase = Register("FS-38", "forged", []Tier{TierT2}, Twin(Fs38OperatorMinted, Fs38ValidDelegation))
	Fs56Case       = Register("FS-56", "", []Tier{TierT2, TierT3}, Twin(Fs56RevokedDuringDial, Fs56UnrevokedDialForwards))
)

// The host's overlay address, in BridgeNet's default block's lower /17.
var fsBridgeHostAddress = netip.MustParseAddr("100.80.7.20")

// What one schedule builds in its first step and its later steps read.
type fsBridgeWorld struct {
	world *sidecartest.BridgeNet
	host  *sidecartest.BridgeNetHost
	// subjects by name, each an untagged device of the owner's member whose binding the host holds
	subjects map[string]*sidecartest.BridgeNetDevice
}

// The first step: the network, its host with an address and the subjects named, every one known to the host.
func fsBridgeSetup(world *fsBridgeWorld, subjectNames ...string) *Step {
	return &Step{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
		return fsTeamCatch(func() error {
			world.world = sidecartest.NewBridgeNet(fsTeamFailer{}, net, sidecartest.NetBridgeSettings(net))
			hostDevice := world.world.AddDevice("host")
			for _, name := range subjectNames {
				world.subjects[name] = world.world.AddDevice(name)
			}
			world.host = world.world.StartHost(hostDevice, &sidecartest.BridgeNetHostSettings{
				Address:                 fsBridgeHostAddress,
				ProvideFriendsAndFamily: true,
			})
			return nil
		})
	}}
}

// A step by actor on the world, its failures the step's.
func fsBridgeDo(actor string, world *fsBridgeWorld, body func() error) *Step {
	return &Step{Actor: actor, Action: func(ctx context.Context, net *Net) error {
		return fsTeamCatch(body)
	}}
}

// The last step: everything the world started ends.
func fsBridgeClose(world *fsBridgeWorld) *Step {
	return &Step{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
		if world.world != nil {
			world.world.Close()
		}
		return nil
	}}
}

// FI-11's bridge half until TEST-M4-01 binds its oracle: no upstream socket without the hook's opening decision. Every
// dial the host's NAT made is matched by a pass or a map of a TCP or UDP flow to that address, so nothing reaches a
// target the hook did not open it to.
func FsBridgePathIntegrity(world *fsBridgeWorld) Invariant {
	return NewInvariant("FI-11/bridge-dials", func(ctx context.Context, oracle *Oracle) error {
		if world.host == nil {
			return nil
		}
		opened := map[string]int{}
		for _, decision := range world.host.AllDecisions() {
			if !decision.Opens() || decision.Protocol == connect.IpProtocolIcmp {
				continue
			}
			target := decision.To
			if decision.Verdict == connect.EgressVerdictMap {
				target = netip.AddrPortFrom(decision.Target.Addr(), cmpPort(decision.Target.Port(), decision.To.Port()))
			}
			opened[target.String()] += 1
		}
		for _, dial := range world.host.Dials() {
			if opened[dial.Address] == 0 {
				return fmt.Errorf("the NAT dialed %s %s with no opening decision for it", dial.Network, dial.Address)
			}
			opened[dial.Address] -= 1
		}
		return nil
	})
}

// A map's port, the flow's own when the map keeps it.
func cmpPort(mapPort uint16, flowPort uint16) uint16 {
	if mapPort == 0 {
		return flowPort
	}
	return mapPort
}

// A schedule on world, checked by the path integrity stand-in after every step.
func fsBridgeSchedule(id string, refuses string, world *fsBridgeWorld, steps ...*Step) *Schedule {
	return &Schedule{
		Id:      id,
		Steps:   append(steps, fsBridgeClose(world)),
		Check:   []Invariant{FsBridgePathIntegrity(world)},
		Tiers:   []Tier{TierT2, TierT3},
		Refuses: refuses,
	}
}

func newFsBridgeWorld() *fsBridgeWorld {
	return &fsBridgeWorld{subjects: map[string]*sidecartest.BridgeNetDevice{}}
}

// The flows FS-38 and FS-56 open, each to the host's address, which §17.6's rule 3 maps onto the host's loopback with
// no ACL document: a TCP connection carrying payload, a UDP datagram answered with its own bytes, an echo.
type fsBridgeFlows struct {
	world  *fsBridgeWorld
	window *sidecartest.BridgeNetWindow
}

func (self *fsBridgeFlows) tcpAddress() netip.AddrPort {
	return netip.AddrPortFrom(self.world.host.Address, self.world.host.Upstream.TcpPort())
}

func (self *fsBridgeFlows) udpAddress() netip.AddrPort {
	return netip.AddrPortFrom(self.world.host.Address, self.world.host.Upstream.UdpPort())
}

// Every flow opens: the TCP payload and the datagram reach the upstream, and the datagram and the echo are
// answered.
func (self *fsBridgeFlows) expectOpen(payload string) error {
	host := self.world.host
	settings := self.world.world.Settings()
	conn, err := self.window.DialTcp(self.tcpAddress())
	if err != nil {
		return fmt.Errorf("%s's TCP connection: %w", self.window.Name, err)
	}
	if _, err := conn.Write([]byte(payload)); err != nil {
		conn.Close()
		return fmt.Errorf("%s's TCP payload: %w", self.window.Name, err)
	}
	conn.Close()
	if !host.Upstream.WaitFor(settings.WaitTimeout, func(accepts []sidecartest.BridgeNetAccept, datagrams [][]byte) bool {
		return slices.ContainsFunc(accepts, func(accept sidecartest.BridgeNetAccept) bool { return string(accept.Bytes) == payload })
	}) {
		return fmt.Errorf("%s's TCP payload never reached the upstream", self.window.Name)
	}
	answer, err := self.window.ExchangeUdp(self.udpAddress(), []byte(payload), settings.WaitTimeout)
	if err != nil || string(answer) != payload {
		return fmt.Errorf("%s's datagram: %q, %v", self.window.Name, answer, err)
	}
	if err := self.window.SendEcho(host.Address, 1); err != nil {
		return err
	}
	if !self.window.WaitEchoReply(1, settings.WaitTimeout) {
		return fmt.Errorf("%s's echo was never answered", self.window.Name)
	}
	return nil
}

// No flow of the window opens a socket: its TCP connection is refused, the hook denies its TCP, UDP and ICMP flows
// before any dial, and nothing it sent reaches the upstream.
func (self *fsBridgeFlows) expectRefused(payload string) error {
	host := self.world.host
	if conn, err := self.window.DialTcp(self.tcpAddress()); err == nil {
		conn.Close()
		return fmt.Errorf("%s's TCP connection opened", self.window.Name)
	}
	udp, err := self.window.SendUdp(self.udpAddress(), []byte(payload))
	if err != nil {
		return err
	}
	defer udp.Close()
	if err := self.window.SendEcho(host.Address, 1); err != nil {
		return err
	}
	for _, ipProtocol := range []connect.IpProtocol{connect.IpProtocolTcp, connect.IpProtocolUdp, connect.IpProtocolIcmp} {
		decision := host.WaitDecision(self.window.Client.ClientId, ipProtocol)
		if decision.Opens() {
			return fmt.Errorf("%s's %s flow was opened: %+v", self.window.Name, ipProtocol, decision)
		}
		if decision.Principal != nil {
			return fmt.Errorf("%s's %s flow carried a principal: %+v", self.window.Name, ipProtocol, decision.Principal)
		}
	}
	for _, principal := range host.Principals(self.window.Client.ClientId) {
		if principal.Principal != nil {
			return fmt.Errorf("%s's contract was admitted: %+v", self.window.Name, principal.Principal)
		}
	}
	// a denied flow never dials, so the counts are final once the hook has decided
	if dials := host.Dials(); 0 < len(dials) {
		return fmt.Errorf("the NAT dialed %d upstream sockets: %+v", len(dials), dials)
	}
	if accepts, datagrams := host.Upstream.Accepts(), host.Upstream.Datagrams(); 0 < len(accepts) || 0 < len(datagrams) {
		return fmt.Errorf("the upstream took %d connections and %d datagrams", len(accepts), len(datagrams))
	}
	if self.window.EchoReplied(1) {
		return fmt.Errorf("%s's echo was answered", self.window.Name)
	}
	return nil
}

// FS-38's twin: S's window, its delegation S's own, reaches the host over TCP, UDP and ICMP, and the host verified
// its principal as S of this network.
func Fs38ValidDelegation(net *Net) *Schedule {
	world := newFsBridgeWorld()
	return fsBridgeSchedule("FS-38", "", world,
		fsBridgeSetup(world, "subject"),
		fsBridgeDo("window", world, func() error {
			subject := world.subjects["subject"]
			window := world.world.OpenWindow("fs38 window", subject, world.host, nil)
			flows := &fsBridgeFlows{world: world, window: window}
			if err := flows.expectOpen("fs38 valid"); err != nil {
				return err
			}
			principals := world.host.Principals(window.Client.ClientId)
			if len(principals) == 0 || principals[0].Principal == nil {
				return fmt.Errorf("the host verified no principal: %+v", principals)
			}
			principal := principals[0].Principal
			if principal.Subject != connect.Id(subject.SidecarId()) || principal.Network != connect.Id(world.world.NetworkId()) {
				return fmt.Errorf("the principal %+v is not S of this network", principal)
			}
			return nil
		}),
	)
}

// FS-38's M4 refusals: a delegation naming another key, lapsed, naming another target or another network, each
// carried by an honest window client of S's, opens nothing.
func Fs38DelegationRefusals(net *Net) *Schedule {
	world := newFsBridgeWorld()
	cases := []struct {
		name string
		edit func(delegation *bridge.WindowDelegation)
	}{
		{name: "another key", edit: func(delegation *bridge.WindowDelegation) {
			delegation.WindowClientPublicKey = bytes.Repeat([]byte{0x38}, len(delegation.WindowClientPublicKey))
		}},
		{name: "lapsed", edit: func(delegation *bridge.WindowDelegation) {
			delegation.NotAfterMs = net.Clock().Now().Add(-time.Minute).UnixMilli()
		}},
		{name: "another target", edit: func(delegation *bridge.WindowDelegation) {
			delegation.TargetSidecarId = bytes.Clone(delegation.SubjectSidecarId)
		}},
		{name: "another network", edit: func(delegation *bridge.WindowDelegation) {
			delegation.NetworkId = bytes.Repeat([]byte{0x38}, len(delegation.NetworkId))
		}},
	}
	steps := []*Step{fsBridgeSetup(world, "subject")}
	for _, refusal := range cases {
		steps = append(steps, fsBridgeDo("window", world, func() error {
			window := world.world.OpenWindow("fs38 "+refusal.name, world.subjects["subject"], world.host, &sidecartest.BridgeNetWindowArgs{Edit: refusal.edit})
			defer window.Close()
			if err := (&fsBridgeFlows{world: world, window: window}).expectRefused("fs38 " + refusal.name); err != nil {
				return fmt.Errorf("a delegation naming %s: %w", refusal.name, err)
			}
			return nil
		}))
	}
	return fsBridgeSchedule("FS-38", "a window client whose delegation names another key, has lapsed, or names another target or network opens no socket", world, steps...)
}

// FS-38's forged case: the operator's window clients, each contract minted to claim S, open nothing.
func Fs38OperatorMinted(net *Net) *Schedule {
	world := newFsBridgeWorld()
	// S's honest window, whose real delegation the operator replays from another client
	var honest *sidecartest.BridgeNetWindow
	minted := func(provideMode protocol.ProvideMode, networkId func() connect.Id, delegation func(window *sidecartest.BridgeNetWindow) []byte) *sidecartest.BridgeNetWindowArgs {
		return &sidecartest.BridgeNetWindowArgs{
			ProvideMode:  provideMode,
			NoDelegation: true,
			Mint: func(window *sidecartest.BridgeNetWindow, request *protocol.CreateContract) *sidecartest.MintContractArgs {
				subjectClientId := world.subjects["subject"].ClientId
				network := networkId()
				return &sidecartest.MintContractArgs{
					SourceId:              window.Client.ClientId,
					DestinationId:         world.host.Client.ClientId,
					ProvideMode:           provideMode,
					SourceSubjectClientId: &subjectClientId,
					SourceNetworkId:       &network,
					ContractClass:         protocol.ContractClass_ContractClassData,
					WindowDelegation:      delegation(window),
					TransferByteCount:     world.world.Settings().ContractByteCount,
				}
			},
		}
	}
	thisNetwork := func() connect.Id { return connect.Id(world.world.NetworkId()) }
	cases := []struct {
		name string
		args func() *sidecartest.BridgeNetWindowArgs
	}{
		{name: "no delegation", args: func() *sidecartest.BridgeNetWindowArgs {
			return minted(protocol.ProvideMode_Network, thisNetwork, func(window *sidecartest.BridgeNetWindow) []byte { return nil })
		}},
		{name: "a delegation the operator signed", args: func() *sidecartest.BridgeNetWindowArgs {
			return minted(protocol.ProvideMode_Network, thisNetwork, func(window *sidecartest.BridgeNetWindow) []byte {
				return world.world.SignDelegation(fsBridgeDelegationOf(world, window), fsBridgeOperatorKey())
			})
		}},
		{name: "S's delegation of another window client, replayed", args: func() *sidecartest.BridgeNetWindowArgs {
			return minted(protocol.ProvideMode_Network, thisNetwork, func(window *sidecartest.BridgeNetWindow) []byte {
				return bytes.Clone(honest.Delegation)
			})
		}},
		{name: "a FriendsAndFamily contract sealed to another network", args: func() *sidecartest.BridgeNetWindowArgs {
			return minted(protocol.ProvideMode_FriendsAndFamily, func() connect.Id { return connect.Id(bytes.Repeat([]byte{0x56}, 16)) },
				func(window *sidecartest.BridgeNetWindow) []byte {
					return world.world.SignDelegation(fsBridgeDelegationOf(world, window), world.subjects["subject"].Device.Key)
				})
		}},
	}
	steps := []*Step{
		fsBridgeSetup(world, "subject"),
		fsBridgeDo("window", world, func() error {
			honest = world.world.OpenWindow("fs38 honest", world.subjects["subject"], world.host, nil)
			if len(honest.Delegation) == 0 {
				return errors.New("the honest window carries no delegation")
			}
			return nil
		}),
	}
	for _, refusal := range cases {
		steps = append(steps, fsBridgeDo("operator", world, func() error {
			window := world.world.OpenWindow("fs38 minted "+refusal.name, world.subjects["subject"], world.host, refusal.args())
			defer window.Close()
			if err := (&fsBridgeFlows{world: world, window: window}).expectRefused("fs38 minted"); err != nil {
				return fmt.Errorf("a minted contract with %s: %w", refusal.name, err)
			}
			return nil
		}))
	}
	schedule := fsBridgeSchedule("FS-38", "an operator-minted window client claiming S opens no socket over TCP, UDP or ICMP", world, steps...)
	schedule.Tiers = []Tier{TierT2}
	schedule.Forged = true
	return schedule
}

// S's delegation as a minted window would claim it: S's network, the window client and its key, the host.
func fsBridgeDelegationOf(world *fsBridgeWorld, window *sidecartest.BridgeNetWindow) *bridge.WindowDelegation {
	return &bridge.WindowDelegation{
		NetworkId:             world.world.NetworkId().Bytes(),
		SubjectSidecarId:      world.subjects["subject"].SidecarId().Bytes(),
		WindowClientId:        window.Client.ClientId.Bytes(),
		WindowClientPublicKey: window.Client.Client.ClientKeyManager().PublicKey(),
		TargetSidecarId:       world.host.Device.SidecarId().Bytes(),
		NotAfterMs:            world.world.Net().Clock().Now().Add(time.Hour).UnixMilli(),
	}
}

// A key the operator holds, which no sidecar's admission names.
func fsBridgeOperatorKey() ed25519.PrivateKey {
	return sidecartest.BridgeFixtureIdentityKey(0x0e)
}

// FS-56's refusal: for TCP and for UDP a flow resolves and its dial is held at the NAT's gate; its subject is revoked
// by an admin's SidecarRevoke, which reaches the role through Bridge.Revoke at its own position; the dial completes,
// and the flow is reset before any byte reaches the target. For ICMP, an answered flow's subject is revoked, and its
// next echo is denied and never answered.
func Fs56RevokedDuringDial(net *Net) *Schedule {
	world := newFsBridgeWorld()
	steps := []*Step{
		fsBridgeSetup(world, "tcp subject", "udp subject", "icmp subject"),
		fsBridgeDo("tcp", world, func() error {
			return fs56HeldDial(world, "tcp subject", connect.IpProtocolTcp, true)
		}),
		fsBridgeDo("udp", world, func() error {
			return fs56HeldDial(world, "udp subject", connect.IpProtocolUdp, true)
		}),
		fsBridgeDo("icmp", world, func() error {
			return fs56Echo(world, "icmp subject", true)
		}),
	}
	return fsBridgeSchedule("FS-56", "a flow whose subject is revoked while its dial is held is reset before any byte reaches the target", world, steps...)
}

// FS-56's twin: the same held dials and echo with no revocation forward.
func Fs56UnrevokedDialForwards(net *Net) *Schedule {
	world := newFsBridgeWorld()
	steps := []*Step{
		fsBridgeSetup(world, "tcp subject", "udp subject", "icmp subject"),
		fsBridgeDo("tcp", world, func() error {
			return fs56HeldDial(world, "tcp subject", connect.IpProtocolTcp, false)
		}),
		fsBridgeDo("udp", world, func() error {
			return fs56HeldDial(world, "udp subject", connect.IpProtocolUdp, false)
		}),
		fsBridgeDo("icmp", world, func() error {
			return fs56Echo(world, "icmp subject", false)
		}),
	}
	return fsBridgeSchedule("FS-56", "", world, steps...)
}

// One held dial of the subject's window over ipProtocol, revoked during the hold or not.
func fs56HeldDial(world *fsBridgeWorld, subjectName string, ipProtocol connect.IpProtocol, revoke bool) error {
	host := world.host
	settings := world.world.Settings()
	subject := world.subjects[subjectName]
	window := world.world.OpenWindow("fs56 "+subjectName, subject, host, nil)
	defer window.Close()
	payload := []byte("fs56 " + subjectName + " payload")
	dialsBefore := len(host.Dials())
	host.HoldDials()
	type flowResult struct {
		answer []byte
		err    error
	}
	results := make(chan flowResult, 1)
	go func() {
		switch {
		case ipProtocol == connect.IpProtocolTcp:
			conn, err := window.DialTcp(netip.AddrPortFrom(host.Address, host.Upstream.TcpPort()))
			if err != nil {
				results <- flowResult{err: err}
				return
			}
			_, err = conn.Write(payload)
			conn.Close()
			results <- flowResult{err: err}
		case revoke:
			// the datagram is written into the window's stack at once, and its answer, which cannot come, is not read
			conn, err := window.SendUdp(netip.AddrPortFrom(host.Address, host.Upstream.UdpPort()), payload)
			if conn != nil {
				conn.Close()
			}
			results <- flowResult{err: err}
		default:
			answer, err := window.ExchangeUdp(netip.AddrPortFrom(host.Address, host.Upstream.UdpPort()), payload, settings.WaitTimeout)
			results <- flowResult{answer: answer, err: err}
		}
	}()
	decision := host.WaitDecision(window.Client.ClientId, ipProtocol)
	if !decision.Opens() || decision.Principal == nil {
		host.OpenDials()
		<-results
		return fmt.Errorf("the hook did not open the %s flow: %+v", ipProtocol, decision)
	}
	host.WaitHeldDials(1)
	if revoke {
		n := world.world.RevokeDevice(subject)
		world.world.Follow()
		revocation := host.WaitRevoked(n)
		if revocation.Type != bridge.SignedType_SIGNED_SIDECAR_REVOKE || !bytes.Equal(revocation.Id, subject.SidecarId().Bytes()) || revocation.Err != nil {
			host.OpenDials()
			<-results
			return fmt.Errorf("the role was handed %+v at %d, not the SidecarRevoke of %s", revocation, n, subjectName)
		}
	}
	host.OpenDials()
	result := <-results
	// the held dial's own socket: connected, then closed having carried nothing, or carrying the payload
	if !host.WaitDials(func(dials []sidecartest.BridgeNetDial) bool {
		if len(dials) <= dialsBefore {
			return false
		}
		dial := dials[dialsBefore]
		if revoke {
			return dial.Connected && dial.Closed
		}
		return dial.Connected && len(payload) <= dial.WrittenByteCount
	}) {
		return fmt.Errorf("the held %s dial never finished: %+v", ipProtocol, host.Dials()[dialsBefore:])
	}
	dial := host.Dials()[dialsBefore]
	if !dial.Held {
		return fmt.Errorf("the %s dial was not the held one: %+v", ipProtocol, dial)
	}
	if revoke {
		if dial.WrittenByteCount != 0 {
			return fmt.Errorf("%d bytes reached the target after the revocation", dial.WrittenByteCount)
		}
		if ipProtocol == connect.IpProtocolTcp && result.err == nil {
			return errors.New("the window's TCP connection opened after the revocation: the host sent a SYN-ACK")
		}
		if slices.ContainsFunc(host.Upstream.Accepts(), func(accept sidecartest.BridgeNetAccept) bool { return 0 < len(accept.Bytes) }) ||
			0 < len(host.Upstream.Datagrams()) {
			return errors.New("the upstream received bytes after the revocation")
		}
		return nil
	}
	if result.err != nil {
		return fmt.Errorf("the unrevoked %s flow: %w", ipProtocol, result.err)
	}
	if ipProtocol == connect.IpProtocolUdp && !bytes.Equal(result.answer, payload) {
		return fmt.Errorf("the datagram's answer %q", result.answer)
	}
	if ipProtocol == connect.IpProtocolTcp && !host.Upstream.WaitFor(settings.WaitTimeout, func(accepts []sidecartest.BridgeNetAccept, datagrams [][]byte) bool {
		return slices.ContainsFunc(accepts, func(accept sidecartest.BridgeNetAccept) bool { return bytes.Equal(accept.Bytes, payload) })
	}) {
		return errors.New("the TCP payload never reached the upstream")
	}
	return nil
}

// An echo the subject's window sends, answered; then, revoked or not, its second echo, and a first echo of a new window
// of the subject's. A revoked subject's are never answered, and the new window's flow, which no closed flow can
// shadow, is denied; the twin's are answered. The old window's second echo may meet its closed flow and be dropped
// before any decision, which is the silent drop too, so only the new window's decision is waited for.
func fs56Echo(world *fsBridgeWorld, subjectName string, revoke bool) error {
	host := world.host
	settings := world.world.Settings()
	subject := world.subjects[subjectName]
	window := world.world.OpenWindow("fs56 "+subjectName, subject, host, nil)
	defer window.Close()
	if err := window.SendEcho(host.Address, 1); err != nil {
		return err
	}
	if !window.WaitEchoReply(1, settings.WaitTimeout) {
		return errors.New("the first echo was never answered")
	}
	if revoke {
		n := world.world.RevokeDevice(subject)
		world.world.Follow()
		host.WaitRevoked(n)
	}
	if err := window.SendEcho(host.Address, 2); err != nil {
		return err
	}
	next := world.world.OpenWindow("fs56 "+subjectName+" again", subject, host, nil)
	defer next.Close()
	if err := next.SendEcho(host.Address, 1); err != nil {
		return err
	}
	if !revoke {
		if !window.WaitEchoReply(2, settings.WaitTimeout) || !next.WaitEchoReply(1, settings.WaitTimeout) {
			return errors.New("an echo of the unrevoked subject was never answered")
		}
		return nil
	}
	decision := host.WaitDecision(next.Client.ClientId, connect.IpProtocolIcmp)
	if decision.Opens() || decision.Principal != nil {
		return fmt.Errorf("the revoked subject's new echo flow was decided %+v", decision)
	}
	for _, later := range host.Decisions(window.Client.ClientId)[1:] {
		if later.Opens() {
			return fmt.Errorf("the revoked subject's echo flow was opened again: %+v", later)
		}
	}
	if window.EchoReplied(2) || next.EchoReplied(1) {
		return errors.New("the revoked subject's echo was answered")
	}
	return nil
}
