//go:build !sidecar_http && !ios_extension

// §22.7's bridge asserts and I-18's guard over the bridge's contract fields (BRIDGE-M4-22; I-3, I-13, I-18, R-BRIDGE-12,
// D-BRIDGE-3) on sidecartest's BridgeNet:
//
//   - unsealed-peer: a window client whose encryption is off carries its flows to the host's client, and none of them
//     opens a socket, while a sealed twin's do;
//   - CC2: every TransferFrame a window and its host exchanged is sealed, and neither the host's addresses nor the
//     flows' payloads, canaries, appear in any capture, raw or encoded;
//   - I-18: the contract fields the bridge adds to connect, CreateContract.window_delegation and C13's seals in
//     StoredContract, are §2.8's connect-1, and the guard's map says so.
//
// After C6a's drop, public exits refuse 100.64/10 (the public-exits assert) is connect's own test today (BRIDGE-M4-03),
// and the pin rows through real links wait for a sender's links here; both are in the task's report.

package sidecartest_test

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/sidecartest"
)

// A network with a host at an address and a subject of the owner's member.
func bridgePrivacyWorld(t *testing.T, net *sidecartest.Net) (*sidecartest.BridgeNet, *sidecartest.BridgeNetHost, *sidecartest.BridgeNetDevice) {
	t.Helper()
	world := sidecartest.NewBridgeNet(t, net, nil)
	t.Cleanup(world.Close)
	hostDevice := world.AddDevice("host")
	subject := world.AddDevice("subject")
	host := world.StartHost(hostDevice, &sidecartest.BridgeNetHostSettings{Address: netip.MustParseAddr("100.80.7.20")})
	return world, host, subject
}

// A sealed window's TCP payload and datagram reach the upstream and its echo is answered.
func bridgePrivacyOpen(t *testing.T, world *sidecartest.BridgeNet, host *sidecartest.BridgeNetHost, window *sidecartest.BridgeNetWindow, payload []byte) {
	t.Helper()
	waitTimeout := world.Settings().WaitTimeout
	conn, err := window.DialTcp(netip.AddrPortFrom(host.Address, host.Upstream.TcpPort()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if !host.Upstream.WaitFor(waitTimeout, func(accepts []sidecartest.BridgeNetAccept, datagrams [][]byte) bool {
		return slices.ContainsFunc(accepts, func(accept sidecartest.BridgeNetAccept) bool { return bytes.Equal(accept.Bytes, payload) })
	}) {
		t.Fatal("the TCP payload never reached the upstream")
	}
	if answer, err := window.ExchangeUdp(netip.AddrPortFrom(host.Address, host.Upstream.UdpPort()), payload, waitTimeout); err != nil || !bytes.Equal(answer, payload) {
		t.Fatalf("the datagram: %v", err)
	}
	if err := window.SendEcho(host.Address, 1); err != nil || !window.WaitEchoReply(1, waitTimeout) {
		t.Fatalf("the echo: %v", err)
	}
}

// §22.7's unsealed-peer: a peer with no sealed session reaches the host's client and opens nothing (I-3, R-BRIDGE-12):
// its SYN, datagram and echo cross the exchange, and the host decides none of them open, verifies no principal for it
// and dials nothing for it; the sealed twin, sent after, opens all three.
func TestBridgeUnsealedPeerFlowIsDenied(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	world, host, subject := bridgePrivacyWorld(t, net)
	unsealed := world.OpenWindow("unsealed", subject, host, &sidecartest.BridgeNetWindowArgs{Unsealed: true})
	if err := unsealed.SendSyn(netip.AddrPortFrom(host.Address, host.Upstream.TcpPort())); err != nil {
		t.Fatal(err)
	}
	if udp, err := unsealed.SendUdp(netip.AddrPortFrom(host.Address, host.Upstream.UdpPort()), []byte("unsealed datagram")); err != nil {
		t.Fatal(err)
	} else {
		udp.Close()
	}
	if err := unsealed.SendEcho(host.Address, 1); err != nil {
		t.Fatal(err)
	}
	sealed := world.OpenWindow("sealed", subject, host, nil)
	bridgePrivacyOpen(t, world, host, sealed, []byte("the sealed twin's payload"))

	if len(net.Capture().FrameSizes(unsealed.Client.ClientId, host.Client.ClientId)) == 0 {
		t.Fatal("the unsealed peer's frames never crossed to the host: the run proves nothing of the host")
	}
	for _, decision := range host.Decisions(unsealed.Client.ClientId) {
		if decision.Opens() || decision.Sealed {
			t.Errorf("the unsealed peer's flow was decided %+v", decision)
		}
	}
	for _, principal := range host.Principals(unsealed.Client.ClientId) {
		if principal.Principal != nil {
			t.Errorf("the unsealed peer was admitted as %+v", principal.Principal)
		}
	}
	for _, dial := range host.Dials() {
		if !slices.ContainsFunc(host.Decisions(sealed.Client.ClientId), func(decision *sidecartest.BridgeNetDecision) bool {
			target := decision.To
			if decision.Verdict == connect.EgressVerdictMap {
				target = decision.Target
			}
			return decision.Opens() && target.String() == dial.Address
		}) {
			t.Errorf("a dial no sealed flow opened: %+v", dial)
		}
	}
	if unsealed.EchoReplied(1) {
		t.Error("the unsealed peer's echo was answered")
	}
}

// CC2 on the bridge: a sealed window's frames to and from its host are each sealed, and the scan finds neither the
// flows' canaries nor the host's addresses in any capture.
func TestBridgeTransferFramesAreSealedAndCarryNoAddress(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	world, host, subject := bridgePrivacyWorld(t, net)
	capture := net.Capture()
	for _, text := range []string{host.Address.String(), netip.AddrPortFrom(host.Address, host.Upstream.TcpPort()).String()} {
		capture.Forbid("the host's address "+text, []byte(text))
	}
	window := world.OpenWindow("window", subject, host, nil)
	bridgePrivacyOpen(t, world, host, window, capture.Canary("bridge payload"))
	if len(capture.FrameSizes(window.Client.ClientId, host.Client.ClientId)) == 0 || len(capture.FrameSizes(host.Client.ClientId, window.Client.ClientId)) == 0 {
		t.Fatal("no frame crossed between the window and its host: the scan reads nothing of the link")
	}
	for _, finding := range capture.Scan() {
		t.Errorf("%s", finding)
	}
}

// I-18's guard over the bridge's contract fields: connect's CreateContract.window_delegation and StoredContract's
// window_delegation and C13 seals, at the numbers PROTO-M4-01 gave them, are values §2.8's connect-1 names, and the
// guard's map files WindowDelegation under connect-1. The bridge adds no prefix or address to any of them: a
// delegation names ids, keys, a target and a time.
func TestBridgeContractFieldsAreConnect1(t *testing.T) {
	fields := []struct {
		message protoreflect.Message
		name    protoreflect.Name
		number  protoreflect.FieldNumber
	}{
		{message: (&protocol.CreateContract{}).ProtoReflect(), name: "window_delegation", number: 10},
		{message: (&protocol.StoredContract{}).ProtoReflect(), name: "source_subject_client_id", number: 13},
		{message: (&protocol.StoredContract{}).ProtoReflect(), name: "source_network_id", number: 14},
		{message: (&protocol.StoredContract{}).ProtoReflect(), name: "contract_class", number: 15},
		{message: (&protocol.StoredContract{}).ProtoReflect(), name: "window_delegation", number: 16},
	}
	for _, field := range fields {
		descriptor := field.message.Descriptor().Fields().ByName(field.name)
		if descriptor == nil || descriptor.Number() != field.number {
			t.Errorf("%s.%s is not field %d", field.message.Descriptor().FullName(), field.name, field.number)
		}
	}
	list, err := sidecartest.LoadMetadataList()
	if err != nil {
		t.Fatal(err)
	}
	row := list.Row("connect-1")
	if row == nil || !row.Live() {
		t.Fatal("§2.8's list holds no live connect-1")
	}
	for _, named := range []string{"source subject and source network", "the contract class", "WindowDelegation"} {
		if !strings.Contains(row.Sees, named) {
			t.Errorf("connect-1 does not name %q", named)
		}
	}
	for _, unnamed := range []string{"prefix", "address"} {
		if strings.Contains(row.Sees, "WindowDelegation ("+unnamed) {
			t.Errorf("connect-1's WindowDelegation names a %s", unnamed)
		}
	}
	fieldsMap, err := os.ReadFile(filepath.Join("..", "testdata", "metadata", "fields.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(strings.Split(string(fieldsMap), "\n"), func(line string) bool {
		return strings.HasPrefix(strings.TrimSpace(line), "WindowDelegation:") && strings.Contains(line, "connect-1")
	}) {
		t.Error("the guard's map files WindowDelegation under no connect-1")
	}
}
