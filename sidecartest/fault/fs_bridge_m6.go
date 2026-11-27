//go:build !sidecar_http && !ios_extension

// BRIDGE-M6-08's schedules (§22.8's FS-38 at M6-out, its share rows; §22.7's FriendsAndFamily clause; FI-11,
// D-BRIDGE-14, D-BRIDGE-17, CC-05, I-10) on sidecartest's BridgeShareNet: network X's host serving a share network Y
// accepted, X's grant, pins, compile, device role and provider NAT each the real one, Y's verified state with a granted
// and an ungranted reader, and two kinds of window: a reader's honest one, whose contracts the platform issues and
// seals (T2's in memory, T3's server's gate and CreateContract), and the operator's, every contract minted
// FriendsAndFamily and sealed to Y, carrying what the schedule has Y's ShareSigners sign. Registered on T2 and T3;
// server/controller/connect_bridge_m6_test.go runs the same builders on server's platform.
//
//   - The twin, §22.7's clause: Y's granted reader's window on the platform's contracts opens TCP, UDP and ICMP to the
//     host's address through its alias in Y's block and nothing past the share's target, the host verifying a
//     principal of the share and Y; every contract issued to the host is FriendsAndFamily under the subject the
//     platform stores for the window and Y's network, carrying the window's delegation; every companion the host was
//     issued to answer it carries that same subject and Y, and is no Network contract; and each was escrowed from Y
//     alone. Then CC-05's minted reach: a delegation by generation 7's ShareSigner under a cert of Y's pinned ShareKey
//     opens the same flows, the host's principal the delegation's subject whatever subject the operator sealed, every
//     decision tagged by the share's target, and the alias's neighbour, which the share names no target at, opening
//     nothing.
//   - The refusals: a cert expired, which is also the share lapsed after 7 days with no renewal, one over 7 days and
//     the skew out, and one not by the pinned ShareKey each open nothing; a removed sidecar's generation 7 is admitted
//     until a later generation's cert reaches the host, and refused on every contract after, the host restarted from
//     its persisted state included. CC-05's row: a current Y reader with no Y grant on X asks the platform for its
//     window's contracts, which the honest gate refuses, so nothing of it reaches the host; the same reader's valid
//     signer on a contract the operator mints reaches X's granted targets and ports alone, TCP to the port target's
//     one port and nothing else there, and what enforced is X's grant, the host's compiled share naming it, and the
//     platform's refusal, never a router of Y's, which runs nowhere here.
//
// What these do not cover, each in the task's report: the accepting network's routers over a real share link (the
// sender's share link is the device's and compile's tests'), and the accept's refusals, which bridge_share_invite's
// tests run through both networks' filers over the routes' fake.

package fault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs38ShareCase = Register("FS-38", "shares", []Tier{TierT2, TierT3}, Twin(Fs38ShareRefusals, Fs38ShareSigner))

// What FS-38's share schedules run their world with.
type Fs38ShareSettings struct {
	// How long, in real time, a wait of the share's world may take before it fails, the world's
	// BridgeNetSettings.WaitTimeout at most: a failure's bound only. Within the Net's
	// BarrierDriverSettings.AwaitTimeout, so a wait that fails names itself and what the world saw of its flow before
	// the run's own bound fails the step as an actor that never ended, which is all the share refusals' lost datagram
	// said.
	WaitTimeout time.Duration
}

func DefaultFs38ShareSettings() *Fs38ShareSettings {
	return &Fs38ShareSettings{
		WaitTimeout: 8 * time.Second,
	}
}

// What one share schedule builds in its first step and its later steps read.
type fsShareWorld struct {
	share *sidecartest.BridgeShareNet
}

// The first step: X, its host serving the share, enforcing a state that holds it, on the Net's bridge settings (T3's
// platform among them) with its waits bounded by settings'.
func fsShareSetup(world *fsShareWorld, settings *Fs38ShareSettings) *Step {
	return &Step{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
		return fsTeamCatch(func() error {
			bridgeSettings := sidecartest.NetBridgeSettings(net)
			if bridgeSettings == nil {
				bridgeSettings = sidecartest.DefaultBridgeNetSettings()
			}
			bounded := *bridgeSettings
			bounded.WaitTimeout = min(bounded.WaitTimeout, settings.WaitTimeout)
			shareSettings := sidecartest.DefaultBridgeShareNetSettings()
			shareSettings.Bridge = &bounded
			world.share = sidecartest.NewBridgeShareNet(fsTeamFailer{}, net, shareSettings)
			return nil
		})
	}}
}

// A step by actor on the world, its failures the step's.
func fsShareDo(actor string, world *fsShareWorld, body func() error) *Step {
	return &Step{Actor: actor, Action: func(ctx context.Context, net *Net) error {
		return fsTeamCatch(body)
	}}
}

// A share schedule: its steps, then the world's end, under FI-11's bridge half.
func fsShareSchedule(refuses string, world *fsShareWorld, steps ...*Step) *Schedule {
	closeStep := &Step{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
		if world.share != nil {
			world.share.Close()
		}
		return nil
	}}
	return &Schedule{
		Id:      "FS-38",
		Steps:   append(steps, closeStep),
		Check:   []Invariant{fsSharePathIntegrity(world)},
		Tiers:   []Tier{TierT2, TierT3},
		Refuses: refuses,
	}
}

// FI-11's bridge half on the share's host, as FsBridgePathIntegrity reads a BridgeNet's: no upstream socket without the
// hook's opening decision, every dial matched by a pass or a map of a TCP or UDP flow to that address.
func fsSharePathIntegrity(world *fsShareWorld) Invariant {
	return NewInvariant("FI-11/share-dials", func(ctx context.Context, oracle *Oracle) error {
		if world.share == nil || world.share.Host == nil {
			return nil
		}
		host := world.share.Host
		opened := map[string]int{}
		for _, decision := range host.AllDecisions() {
			if !decision.Opens() || decision.Protocol == connect.IpProtocolIcmp {
				continue
			}
			target := decision.To
			if decision.Verdict == connect.EgressVerdictMap {
				target = netip.AddrPortFrom(decision.Target.Addr(), cmpPort(decision.Target.Port(), decision.To.Port()))
			}
			opened[target.String()] += 1
		}
		for _, dial := range host.Dials() {
			if opened[dial.Address] == 0 {
				return fmt.Errorf("the NAT dialed %s %s with no opening decision for it", dial.Network, dial.Address)
			}
			opened[dial.Address] -= 1
		}
		return nil
	})
}

// The flows a share window opens, each to the share's alias in Y's block, which the host maps to its own address and
// rule 3 to its loopback service: a TCP connection carrying a payload, a datagram answered with its own bytes, an echo.
type fsShareFlows struct {
	world  *fsShareWorld
	window *sidecartest.BridgeNetWindow
	// the subject the window's delegation names: zero is Y's granted reader
	subject sidecar.Id
}

// The subject the host must admit the window as.
func (self *fsShareFlows) subjectId() sidecar.Id {
	if self.subject == (sidecar.Id{}) {
		return self.world.share.AcceptingSidecarId
	}
	return self.subject
}

func (self *fsShareFlows) tcpAddress() netip.AddrPort {
	return netip.AddrPortFrom(self.world.share.Alias(), self.world.share.Host.Upstream.TcpPort())
}

func (self *fsShareFlows) udpAddress() netip.AddrPort {
	return netip.AddrPortFrom(self.world.share.Alias(), self.world.share.Host.Upstream.UdpPort())
}

// Every flow opens: the payload and the datagram reach the upstream, the datagram and the echo are answered, and the
// host admitted the window as a principal of the share and Y, the delegation's subject, its decisions tagged by the
// share's target.
func (self *fsShareFlows) expectOpen(payload string) error {
	share := self.world.share
	host := share.Host
	settings := share.X.Settings()
	dialCount := len(host.Dials())
	conn, err := self.window.DialTcp(self.tcpAddress())
	if err != nil {
		return fmt.Errorf("%s's TCP connection: %w; %s", self.window.Name, err, self.seenOf(connect.IpProtocolTcp, self.tcpAddress(), nil, dialCount))
	}
	if _, err := conn.Write([]byte(payload)); err != nil {
		conn.Close()
		return fmt.Errorf("%s's TCP payload: %w", self.window.Name, err)
	}
	conn.Close()
	if !host.Upstream.WaitFor(settings.WaitTimeout, func(accepts []sidecartest.BridgeNetAccept, datagrams [][]byte) bool {
		return slices.ContainsFunc(accepts, func(accept sidecartest.BridgeNetAccept) bool { return string(accept.Bytes) == payload })
	}) {
		return fmt.Errorf("%s's TCP payload never reached the upstream; %s", self.window.Name, self.seenOf(connect.IpProtocolTcp, self.tcpAddress(), []byte(payload), dialCount))
	}
	dialCount = len(host.Dials())
	answer, err := self.window.ExchangeUdp(self.udpAddress(), []byte(payload), settings.WaitTimeout)
	if err != nil || string(answer) != payload {
		return fmt.Errorf("%s's datagram: %q, %v; %s", self.window.Name, answer, err, self.seenOf(connect.IpProtocolUdp, self.udpAddress(), []byte(payload), dialCount))
	}
	if err := self.window.SendEcho(share.Alias(), 1); err != nil {
		return err
	}
	// sent again while it waits, since its path may lose it (BridgeNetWindow.WaitEchoAnswered)
	if !self.window.WaitEchoAnswered(share.Alias(), 1, settings.WaitTimeout) {
		return fmt.Errorf("%s's echo was never answered, sent again %d times; %s", self.window.Name, self.window.EchoResendCount(), self.seenOf(connect.IpProtocolIcmp, netip.AddrPortFrom(share.Alias(), 0), nil, len(host.Dials())))
	}
	principals := host.Principals(self.window.Client.ClientId)
	if len(principals) == 0 || principals[0].Principal == nil {
		return fmt.Errorf("the host verified no principal of %s: %+v", self.window.Name, principals)
	}
	principal := principals[0].Principal
	if principal.ShareId != connect.Id(share.ShareId) || principal.Network != connect.Id(share.AcceptingNetworkId) ||
		principal.Subject != connect.Id(self.subjectId()) {
		return fmt.Errorf("%s's principal %+v is not the share's, of Y, as its delegation names it", self.window.Name, principal)
	}
	tag := device.BridgeShareRuleTag(connect.Id(share.ShareId), 0)
	for _, decision := range host.Decisions(self.window.Client.ClientId) {
		if decision.Opens() && decision.RuleTag != tag {
			return fmt.Errorf("%s's flow opened under tag %d, not the share target's", self.window.Name, decision.RuleTag)
		}
	}
	return nil
}

// What the world saw of the window's flow of ipProtocol to to, for a failed exchange to say where its packet stopped:
// how many packets the window's link refused, the host's latest decision of the flow, the NAT's dials to the
// decision's target since dialCount of them, and whether the upstream took payload, unless payload is nil. The world
// keeps no record of a packet between the window's link and the host's hook, so a flow the host never decided, with
// nothing refused, was lost on that way. A denied flow says what the hook was handed and where the host's daemon
// listens, since rule 0 refuses a daemon listener's port whatever the flow's protocol: tip-check's red at 54e31119 said
// only "deny to invalid AddrPort" of a datagram to a port the daemon's TCP listener had taken.
func (self *fsShareFlows) seenOf(ipProtocol connect.IpProtocol, to netip.AddrPort, payload []byte, dialCount int) string {
	host := self.world.share.Host
	seen := []string{fmt.Sprintf("the window's link refused %d packets", self.window.RefusedCount())}
	var decision *sidecartest.BridgeNetDecision
	for _, each := range host.Decisions(self.window.Client.ClientId) {
		if each.Protocol == ipProtocol && each.To == to {
			decision = each
		}
	}
	if decision == nil {
		return strings.Join(append(seen, fmt.Sprintf("the host decided no %s flow of it to %s", ipProtocol, to)), ", ")
	}
	if !decision.Opens() {
		principal := "no principal"
		if decision.Principal != nil {
			principal = fmt.Sprintf("a principal of share %s and network %s", decision.Principal.ShareId, decision.Principal.Network)
		}
		seen = append(seen, fmt.Sprintf("the host decided %s at generation %d, the flow sealed=%v with %s, the host's daemon listening at %s", decision.Verdict, decision.Generation, decision.Sealed, principal, host.Daemon.Addr()))
		return strings.Join(seen, ", ")
	}
	seen = append(seen, fmt.Sprintf("the host decided %s to %s", decision.Verdict, decision.Target))
	if ipProtocol == connect.IpProtocolIcmp {
		return strings.Join(seen, ", ")
	}
	target := netip.AddrPortFrom(decision.Target.Addr(), cmpPort(decision.Target.Port(), decision.To.Port())).String()
	dialed := false
	dials := host.Dials()
	for _, dial := range dials[min(dialCount, len(dials)):] {
		if dial.Address == target {
			dialed = true
			seen = append(seen, fmt.Sprintf("the NAT's %s dial held=%v connected=%v wrote %d bytes closed=%v", dial.Network, dial.Held, dial.Connected, dial.WrittenByteCount, dial.Closed))
		}
	}
	if !dialed {
		seen = append(seen, "the NAT dialed nothing to "+target)
	}
	if payload != nil {
		took := slices.ContainsFunc(host.Upstream.Accepts(), func(accept sidecartest.BridgeNetAccept) bool { return bytes.Contains(accept.Bytes, payload) })
		if ipProtocol == connect.IpProtocolUdp {
			took = slices.ContainsFunc(host.Upstream.Datagrams(), func(datagram []byte) bool { return bytes.Equal(datagram, payload) })
		}
		seen = append(seen, fmt.Sprintf("the upstream took the payload: %v", took))
	}
	return strings.Join(seen, ", ")
}

// The aliases' neighbour in Y's block, past the port target's alias, is no target of the share: the window's TCP
// connection there is refused, and the NAT dials nothing for it.
func (self *fsShareFlows) expectNeighbourRefused() error {
	share := self.world.share
	neighbour := share.PortAlias().Next()
	dialCount := len(share.Host.Dials())
	if conn, err := self.window.DialTcp(netip.AddrPortFrom(neighbour, share.Host.Upstream.TcpPort())); err == nil {
		conn.Close()
		return fmt.Errorf("%s's flow past the share's targets opened", self.window.Name)
	}
	if len(share.Host.Dials()) != dialCount {
		return fmt.Errorf("the NAT dialed for %s's flow past the share's targets", self.window.Name)
	}
	return nil
}

// §22.7's clause on the platform's contracts for a reader's window (the file's comment): every contract issued to the
// host is the platform's, FriendsAndFamily, sealed to the subject the platform stores for the window, the reader's own
// client, and to Y, carrying the window's delegation unchanged; every companion the host was issued to answer it is
// the platform's, sealed to that same subject and Y with no delegation, and no Network contract; and each was escrowed
// from Y, the dialer's network, alone.
func (self *fsShareFlows) expectPlatformContracts() error {
	share := self.world.share
	windowId, hostId := self.window.Client.ClientId, share.Host.Client.ClientId
	subjectClientId := share.ReaderClientId(self.subjectId())
	issued := func(contracts []*sidecartest.BridgeNetContract) []*sidecartest.BridgeNetContract {
		return slices.DeleteFunc(contracts, func(contract *sidecartest.BridgeNetContract) bool { return !contract.Issued() })
	}
	forwards := issued(share.X.Contracts(windowId, hostId))
	companions := issued(share.X.Contracts(hostId, windowId))
	if len(forwards) == 0 || len(companions) == 0 {
		return fmt.Errorf("%s holds %d contracts to the host and the host %d back", self.window.Name, len(forwards), len(companions))
	}
	sealedTo := func(contract *sidecartest.BridgeNetContract) error {
		subject, err := connect.IdFromBytes(contract.Stored.GetSourceSubjectClientId())
		if err != nil {
			return fmt.Errorf("no sealed subject: %w", err)
		}
		network, err := connect.IdFromBytes(contract.Stored.GetSourceNetworkId())
		if err != nil {
			return fmt.Errorf("no sealed network: %w", err)
		}
		if subject != subjectClientId || network != connect.Id(share.AcceptingNetworkId) {
			return fmt.Errorf("sealed to subject %s of network %s, not the reader's own client %s of Y", subject, network, subjectClientId)
		}
		return nil
	}
	for _, contract := range forwards {
		switch {
		case contract.Minted || contract.Companion:
			return fmt.Errorf("%s's contract to the host is no platform's forward contract", self.window.Name)
		case contract.ProvideMode != protocol.ProvideMode_FriendsAndFamily:
			return fmt.Errorf("%s's contract to the host settled as %s", self.window.Name, contract.ProvideMode)
		case !bytes.Equal(contract.Stored.GetWindowDelegation(), self.window.Delegation):
			return fmt.Errorf("%s's contract to the host carries another delegation than the window's", self.window.Name)
		}
		if err := sealedTo(contract); err != nil {
			return fmt.Errorf("%s's contract to the host: %w", self.window.Name, err)
		}
	}
	for _, contract := range companions {
		switch {
		case contract.Minted || !contract.Companion:
			return fmt.Errorf("the host's contract to %s is no platform's companion", self.window.Name)
		case contract.ProvideMode == protocol.ProvideMode_Network:
			return fmt.Errorf("the host's companion to %s settled as Network", self.window.Name)
		case 0 < len(contract.Stored.GetWindowDelegation()):
			return fmt.Errorf("the host's companion to %s carries a delegation", self.window.Name)
		}
		if err := sealedTo(contract); err != nil {
			return fmt.Errorf("the host's companion to %s: %w", self.window.Name, err)
		}
	}
	for _, contract := range append(forwards, companions...) {
		contractId, err := connect.IdFromBytes(contract.Stored.GetContractId())
		if err != nil {
			return err
		}
		payer, err := share.ContractPayer(contractId)
		if err != nil {
			return fmt.Errorf("contract %s's payer: %w", contractId, err)
		}
		if payer != share.AcceptingNetworkId {
			return fmt.Errorf("contract %s from %s to %s was escrowed from %s, not the dialer's network", contractId, contract.SourceId, contract.DestinationId, payer)
		}
	}
	return nil
}

// CC-05's honest half: the platform refuses every contract the window asks for to the host, so nothing of it reaches
// the host, which decides nothing for it, admits no principal and dials nothing.
func (self *fsShareFlows) expectRefusedByPlatform(payload string) error {
	share := self.world.share
	host := share.Host
	windowId, hostId := self.window.Client.ClientId, host.Client.ClientId
	dialCount := len(host.Dials())
	acceptCount, datagramCount := len(host.Upstream.Accepts()), len(host.Upstream.Datagrams())
	udp, err := self.window.SendUdp(self.udpAddress(), []byte(payload))
	if err != nil {
		return err
	}
	defer udp.Close()
	if !share.X.WaitContracts(windowId, hostId, func(contracts []*sidecartest.BridgeNetContract) bool { return 0 < len(contracts) }) {
		return fmt.Errorf("%s asked the platform for no contract to the host", self.window.Name)
	}
	for _, contract := range share.X.Contracts(windowId, hostId) {
		if contract.Issued() {
			return fmt.Errorf("%s was issued a %s contract to the host", self.window.Name, contract.ProvideMode)
		}
	}
	// with no contract none of its packets reaches the host
	if decisions := host.Decisions(windowId); 0 < len(decisions) {
		return fmt.Errorf("the host decided %d flows of %s", len(decisions), self.window.Name)
	}
	if principals := host.Principals(windowId); 0 < len(principals) {
		return fmt.Errorf("the host verified %d contracts of %s", len(principals), self.window.Name)
	}
	if dials := host.Dials(); dialCount < len(dials) {
		return fmt.Errorf("the NAT dialed %d upstream sockets more", len(dials)-dialCount)
	}
	if accepts, datagrams := host.Upstream.Accepts(), host.Upstream.Datagrams(); acceptCount < len(accepts) || datagramCount < len(datagrams) {
		return fmt.Errorf("the upstream took %d connections and %d datagrams more", len(accepts)-acceptCount, len(datagrams)-datagramCount)
	}
	return nil
}

// The share's port target (BridgeShareNet's second target) admits TCP to its one port alone (§17.9's FriendsAndFamily
// row: the target's protocol and ports admit the flow): a connection there reaches the upstream under the target's
// tag, while a datagram to the same alias, to the port the upstream's UDP listener answers on through the first
// target, and a SYN to another TCP port, which rule 3 would map were the target to admit it, are each decided, opened
// by nothing and dialed by nothing.
func (self *fsShareFlows) expectPortTarget(payload string) error {
	share := self.world.share
	host := share.Host
	settings := share.X.Settings()
	windowId := self.window.Client.ClientId
	port := share.PortTargetPort()
	allowed := netip.AddrPortFrom(share.PortAlias(), port)
	dialCount := len(host.Dials())
	conn, err := self.window.DialTcp(allowed)
	if err != nil {
		return fmt.Errorf("%s's TCP connection to the port target: %w; %s", self.window.Name, err, self.seenOf(connect.IpProtocolTcp, allowed, nil, dialCount))
	}
	if _, err := conn.Write([]byte(payload)); err != nil {
		conn.Close()
		return fmt.Errorf("%s's TCP payload to the port target: %w", self.window.Name, err)
	}
	conn.Close()
	if !host.Upstream.WaitFor(settings.WaitTimeout, func(accepts []sidecartest.BridgeNetAccept, datagrams [][]byte) bool {
		return slices.ContainsFunc(accepts, func(accept sidecartest.BridgeNetAccept) bool { return string(accept.Bytes) == payload })
	}) {
		return fmt.Errorf("%s's TCP payload to the port target never reached the upstream; %s", self.window.Name, self.seenOf(connect.IpProtocolTcp, allowed, []byte(payload), dialCount))
	}
	// a decision is a flow's protocol and destination together: the upstream's UDP port may be its TCP port's number,
	// so a destination alone can name the TCP connection the target admits
	decisionOf := func(decisions []*sidecartest.BridgeNetDecision, ipProtocol connect.IpProtocol, to netip.AddrPort) *sidecartest.BridgeNetDecision {
		for _, decision := range decisions {
			if decision.Protocol == ipProtocol && decision.To == to {
				return decision
			}
		}
		return nil
	}
	tag := device.BridgeShareRuleTag(connect.Id(share.ShareId), 1)
	if decision := decisionOf(host.Decisions(windowId), connect.IpProtocolTcp, allowed); decision == nil || !decision.Opens() || decision.RuleTag != tag {
		return fmt.Errorf("%s's connection to the port target opened under no tag of that target: %+v", self.window.Name, decision)
	}

	dialCount = len(host.Dials())
	acceptCount, datagramCount := len(host.Upstream.Accepts()), len(host.Upstream.Datagrams())
	otherProtocol := netip.AddrPortFrom(share.PortAlias(), host.Upstream.UdpPort())
	otherPort := netip.AddrPortFrom(share.PortAlias(), share.PortTargetOtherPort())
	udp, err := self.window.SendUdp(otherProtocol, []byte(payload))
	if err != nil {
		return err
	}
	defer udp.Close()
	if err := self.window.SendSyn(otherPort); err != nil {
		return err
	}
	decisions := host.WaitDecisions(windowId, func(decisions []*sidecartest.BridgeNetDecision) bool {
		return decisionOf(decisions, connect.IpProtocolUdp, otherProtocol) != nil && decisionOf(decisions, connect.IpProtocolTcp, otherPort) != nil
	})
	for _, flow := range []struct {
		ipProtocol connect.IpProtocol
		to         netip.AddrPort
	}{
		{ipProtocol: connect.IpProtocolUdp, to: otherProtocol},
		{ipProtocol: connect.IpProtocolTcp, to: otherPort},
	} {
		if decision := decisionOf(decisions, flow.ipProtocol, flow.to); decision.Opens() {
			return fmt.Errorf("%s's %s flow to %s, past the port target's protocol and port, was opened: %+v", self.window.Name, flow.ipProtocol, flow.to, decision)
		}
	}
	if dials := host.Dials(); dialCount < len(dials) {
		return fmt.Errorf("the NAT dialed %d upstream sockets more for flows past the port target's port", len(dials)-dialCount)
	}
	if accepts, datagrams := host.Upstream.Accepts(), host.Upstream.Datagrams(); acceptCount < len(accepts) || datagramCount < len(datagrams) {
		return fmt.Errorf("the upstream took %d connections and %d datagrams more past the port target's port", len(accepts)-acceptCount, len(datagrams)-datagramCount)
	}
	return nil
}

// What enforced a share window's reach (§8.11, CC-05): X's grant, the one the host's compiled share names, and the
// share's target, whose tag every decision that opened carries. Nothing of Y's runs here to be credited.
func (self *fsShareFlows) expectEnforcedByXsGrant() error {
	share := self.world.share
	shares := share.Host.Rules().GetShares()
	if len(shares) != 1 || !bytes.Equal(shares[0].GetGrantId(), share.GrantId) || !bytes.Equal(shares[0].GetShareId(), share.ShareId.Bytes()) {
		return errors.New("the host's compiled share is not the one X's grant activated")
	}
	tags := []uint64{device.BridgeShareRuleTag(connect.Id(share.ShareId), 0), device.BridgeShareRuleTag(connect.Id(share.ShareId), 1)}
	opened := 0
	for _, decision := range share.Host.Decisions(self.window.Client.ClientId) {
		if !decision.Opens() {
			continue
		}
		opened += 1
		if !slices.Contains(tags, decision.RuleTag) || decision.Principal == nil || decision.Principal.ShareId != connect.Id(share.ShareId) {
			return fmt.Errorf("%s's flow opened under tag %d and principal %+v, not one of X's share targets", self.window.Name, decision.RuleTag, decision.Principal)
		}
	}
	if opened == 0 {
		return fmt.Errorf("no flow of %s opened", self.window.Name)
	}
	return nil
}

// No flow of the window opens a socket: its TCP connection is refused, the hook denies its TCP, UDP and ICMP flows
// before any dial, no principal is admitted, and nothing reaches the upstream past what earlier windows opened.
func (self *fsShareFlows) expectRefused(payload string) error {
	share := self.world.share
	host := share.Host
	dialCount := len(host.Dials())
	acceptCount, datagramCount := len(host.Upstream.Accepts()), len(host.Upstream.Datagrams())
	if conn, err := self.window.DialTcp(self.tcpAddress()); err == nil {
		conn.Close()
		return fmt.Errorf("%s's TCP connection opened", self.window.Name)
	}
	udp, err := self.window.SendUdp(self.udpAddress(), []byte(payload))
	if err != nil {
		return err
	}
	defer udp.Close()
	if err := self.window.SendEcho(share.Alias(), 1); err != nil {
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
	if dials := host.Dials(); dialCount < len(dials) {
		return fmt.Errorf("the NAT dialed %d upstream sockets more", len(dials)-dialCount)
	}
	if accepts, datagrams := host.Upstream.Accepts(), host.Upstream.Datagrams(); acceptCount < len(accepts) || datagramCount < len(datagrams) {
		return fmt.Errorf("the upstream took %d connections and %d datagrams more", len(accepts)-acceptCount, len(datagrams)-datagramCount)
	}
	return nil
}

// A share window whose contracts carry a delegation of generation's signer under cert, sealed to Y.
func fsShareWindow(world *fsShareWorld, name string, cert func() []byte, generation uint64) *sidecartest.BridgeNetWindow {
	return world.share.OpenWindow(name, sidecar.Id{}, func(window *sidecartest.BridgeNetWindow) []byte {
		return world.share.Delegation(window, cert(), generation, nil)
	})
}

// FS-38's share twin, §22.7's clause on the platform's contracts and CC-05's minted reach (the file's comment): a
// ShareSigner's delegation opens every flow to the share's target and nothing past it.
func Fs38ShareSigner(net *Net) *Schedule {
	world := &fsShareWorld{}
	return fsShareSchedule("", world,
		fsShareSetup(world, DefaultFs38ShareSettings()),
		fsShareDo("readerY", world, func() error {
			window := world.share.OpenReaderWindow("fs38 share reader", world.share.AcceptingSidecarId, func() []byte { return world.share.CurrentCert(7) }, 7)
			defer window.Close()
			flows := &fsShareFlows{world: world, window: window}
			if err := flows.expectOpen("fs38 share reader"); err != nil {
				return err
			}
			if err := flows.expectNeighbourRefused(); err != nil {
				return err
			}
			return flows.expectPlatformContracts()
		}),
		fsShareDo("operator", world, func() error {
			window := fsShareWindow(world, "fs38 share", func() []byte { return world.share.CurrentCert(7) }, 7)
			defer window.Close()
			flows := &fsShareFlows{world: world, window: window}
			if err := flows.expectOpen("fs38 share"); err != nil {
				return err
			}
			return flows.expectNeighbourRefused()
		}),
	)
}

// FS-38's share refusals (the file's comment).
func Fs38ShareRefusals(net *Net) *Schedule {
	world := &fsShareWorld{}
	now := func() time.Time { return world.share.X.Net().Clock().Now() }
	cases := []struct {
		name string
		cert func() []byte
	}{
		{name: "an expired cert, the share lapsed with no renewal", cert: func() []byte { return world.share.Cert(7, now(), nil) }},
		{name: "a cert over 7 days and the skew out", cert: func() []byte {
			return world.share.Cert(7, now().Add(7*24*time.Hour+2*time.Minute), nil)
		}},
		{name: "a cert not by the pinned ShareKey", cert: func() []byte {
			return world.share.Cert(7, now().Add(time.Hour), ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
		}},
	}
	steps := []*Step{fsShareSetup(world, DefaultFs38ShareSettings())}
	for _, refusal := range cases {
		steps = append(steps, fsShareDo("operator", world, func() error {
			window := fsShareWindow(world, "fs38 share "+refusal.name, refusal.cert, 7)
			defer window.Close()
			if err := (&fsShareFlows{world: world, window: window}).expectRefused("fs38 share refused"); err != nil {
				return fmt.Errorf("%s: %w", refusal.name, err)
			}
			return nil
		}))
	}
	steps = append(steps,
		fsShareDo("ungrantedReaderY", world, func() error {
			// CC-05: a current reader of Y's config whom Y grants nothing on X asks the platform, whose gate refuses
			share := world.share
			window := share.OpenReaderWindow("fs38 share ungranted", share.UngrantedSidecarId, func() []byte { return share.CurrentCert(7) }, 7)
			defer window.Close()
			if err := (&fsShareFlows{world: world, window: window, subject: share.UngrantedSidecarId}).expectRefusedByPlatform("fs38 share ungranted"); err != nil {
				return fmt.Errorf("the ungranted reader's honest window: %w", err)
			}
			return nil
		}),
		fsShareDo("operator", world, func() error {
			// CC-05: the same reader's valid signer on a contract the operator mints reaches X's granted targets and
			// ports alone
			share := world.share
			window := share.OpenWindow("fs38 share ungranted minted", sidecar.Id{}, func(window *sidecartest.BridgeNetWindow) []byte {
				return share.Delegation(window, share.CurrentCert(7), 7, func(delegation *bridge.WindowDelegation) {
					delegation.SubjectSidecarId = share.UngrantedSidecarId.Bytes()
				})
			})
			defer window.Close()
			flows := &fsShareFlows{world: world, window: window, subject: share.UngrantedSidecarId}
			if err := flows.expectOpen("fs38 share ungranted minted"); err != nil {
				return fmt.Errorf("the ungranted reader's minted window: %w", err)
			}
			if err := flows.expectNeighbourRefused(); err != nil {
				return fmt.Errorf("the ungranted reader's minted window: %w", err)
			}
			if err := flows.expectPortTarget("fs38 share ungranted minted port"); err != nil {
				return fmt.Errorf("the ungranted reader's minted window: %w", err)
			}
			return flows.expectEnforcedByXsGrant()
		}),
	)
	steps = append(steps,
		fsShareDo("removedReader", world, func() error {
			// a sidecar Y removed still holds generation 7's signer, which the host admits until a later cert reaches it
			window := fsShareWindow(world, "fs38 share removed before", func() []byte { return world.share.CurrentCert(7) }, 7)
			defer window.Close()
			return (&fsShareFlows{world: world, window: window}).expectOpen("fs38 share removed before")
		}),
		fsShareDo("readerY", world, func() error {
			window := fsShareWindow(world, "fs38 share generation 8", func() []byte { return world.share.CurrentCert(8) }, 8)
			defer window.Close()
			return (&fsShareFlows{world: world, window: window}).expectOpen("fs38 share generation 8")
		}),
		fsShareDo("removedReader", world, func() error {
			window := fsShareWindow(world, "fs38 share removed after", func() []byte { return world.share.CurrentCert(7) }, 7)
			defer window.Close()
			if err := (&fsShareFlows{world: world, window: window}).expectRefused("fs38 share removed after"); err != nil {
				return fmt.Errorf("generation 7 after generation 8 reached the host: %w", err)
			}
			return nil
		}),
		fsShareDo("restart", world, func() error {
			world.share.RestartHost()
			window := fsShareWindow(world, "fs38 share removed after the restart", func() []byte { return world.share.CurrentCert(7) }, 7)
			defer window.Close()
			if err := (&fsShareFlows{world: world, window: window}).expectRefused("fs38 share removed after the restart"); err != nil {
				return fmt.Errorf("generation 7 after the host's restart: %w", err)
			}
			return nil
		}),
	)
	return fsShareSchedule("a share's contract on a cert expired, too long, not by the pinned ShareKey, or below the host's newest generation, before or after a restart, opens no socket; a reader Y grants nothing on X gets no contract from the platform", world, steps...)
}
