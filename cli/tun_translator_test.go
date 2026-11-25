// ur tun's half of §17.5's translator (tun_translator.go; owner decision 778): the network's /48 is drawn once and kept;
// the tun turns the bridge's translator on over it, the platform holding the tun's own address and routing the
// instances' /96; a reply to the translator's address is translated on its way into the device and one that does not
// translate is dropped; the status shows it; the close turns it off before the device goes; and a platform that refuses
// leaves it off, saying why.

package main

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar"
)

func TestTunTranslatorPrefixIsDrawnOnceAndKept(t *testing.T) {
	store := &urTunMemoryTranslator{}
	first, err := urTunTranslatorPrefix(store)
	if err != nil || !urTunTranslatorPrefixValid(first) {
		t.Fatalf("drew %v, %v", first, err)
	}
	again, err := urTunTranslatorPrefix(store)
	if err != nil || again != first {
		t.Fatalf("drew again %v, %v", again, err)
	}
	if _, err := urTunTranslatorPrefix(nil); err == nil {
		t.Fatal("no store drew a prefix")
	}
	for _, prefix := range []string{"fd12:3456:789a::/48", "fc12:3456:789a::/48", "fd12:3456:789a::/64", "fd12:3456:789a:1::/48"} {
		parsed, err := netip.ParsePrefix(prefix)
		want := prefix == "fd12:3456:789a::/48"
		if err == nil && urTunTranslatorPrefixValid(parsed) != want {
			t.Fatalf("%s valid %v", prefix, !want)
		}
	}
}

// A bridge with a translator the test reads: it translates a reply to 100.70.0.46 by marking it, and refuses one whose
// payload says so.
type testTunTranslatorBridge struct {
	*testTunBridge
	translatorLock sync.Mutex
	ula            netip.Prefix
	sets           []netip.Prefix
}

var _ urTunTranslatorBridge = (*testTunTranslatorBridge)(nil)

func (self *testTunTranslatorBridge) SetTranslator(ula netip.Prefix, mtu int) error {
	self.translatorLock.Lock()
	defer self.translatorLock.Unlock()
	self.ula = ula
	self.sets = append(self.sets, ula)
	return nil
}

func (self *testTunTranslatorBridge) TranslatorAddresses() (netip.Prefix, netip.Addr) {
	self.translatorLock.Lock()
	defer self.translatorLock.Unlock()
	if !self.ula.IsValid() {
		return netip.Prefix{}, netip.Addr{}
	}
	octets := self.ula.Addr().As16()
	octets[7] = 1
	instances := netip.PrefixFrom(netip.AddrFrom16(octets), 96)
	octets = self.ula.Addr().As16()
	octets[15] = 1
	return instances, netip.AddrFrom16(octets)
}

func (self *testTunTranslatorBridge) TranslateReply(out []byte, packet []byte) (int, bool) {
	if netip.AddrFrom4([4]byte(packet[16:20])) != netip.MustParseAddr("100.70.0.46") {
		return 0, false
	}
	if bytes.HasSuffix(packet, []byte("refused")) {
		return 0, true
	}
	n := copy(out, append([]byte("translated:"), packet[20:]...))
	return n, true
}

func (self *testTunTranslatorBridge) TranslatorCounts() (uint64, uint64, uint64) {
	return 1, 2, 3
}

// A device whose platform carries the translator's IPv6, or refuses it with err.
type testTunTranslatorInterface struct {
	*testTunInterface
	translatorLock sync.Mutex
	own            netip.Addr
	instances      netip.Prefix
	err            error
}

var _ urTunTranslatorInterface = (*testTunTranslatorInterface)(nil)

func (self *testTunTranslatorInterface) SetTranslator(own netip.Addr, instances netip.Prefix) error {
	self.translatorLock.Lock()
	defer self.translatorLock.Unlock()
	if self.err != nil {
		return self.err
	}
	self.own, self.instances = own, instances
	return nil
}

// A system whose Open answers iface.
type testTunTranslatorSystem struct {
	*testTunSystem
	iface urTunInterface
}

func (self *testTunTranslatorSystem) Open(name string, mtu int) (urTunInterface, error) {
	return self.iface, nil
}

// A tun over a translating bridge and a device that refuses the translator with refuse, nil for none.
func startTestTranslatorTun(t *testing.T, store urTunTranslatorStore, refuse error) (*urTun, *testTunTranslatorBridge, *testTunTranslatorInterface, *testTunLinks) {
	t.Helper()
	system := newTestTunSystem()
	iface := &testTunTranslatorInterface{testTunInterface: system.iface, err: refuse}
	tunBridge := &testTunTranslatorBridge{testTunBridge: newTestTunBridge()}
	links := &testTunLinks{source: connect.SourceId(connect.NewId())}
	tun, err := startUrTun(context.Background(), &urTunArgs{
		Name:      "ur-test",
		NetworkId: sidecar.NewId(),
		System:    &testTunTranslatorSystem{testTunSystem: system, iface: iface},
		Bridge:    tunBridge,
		Links:     links,
		Settings:  testUrTunSettings(),
		Translator: func() (netip.Prefix, error) {
			return urTunTranslatorPrefix(store)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return tun, tunBridge, iface, links
}

func TestTunTurnsTheTranslatorOnAndTranslatesReplies(t *testing.T) {
	store := &urTunMemoryTranslator{}
	tun, tunBridge, iface, links := startTestTranslatorTun(t, store, nil)
	prefix, _ := store.Load()
	instances, own := tunBridge.TranslatorAddresses()
	if !prefix.IsValid() || len(tunBridge.sets) != 1 || tunBridge.sets[0] != prefix || iface.own != own || iface.instances != instances {
		t.Fatalf("the translator: bridge %v, device %v %v, kept %v", tunBridge.sets, iface.own, iface.instances, prefix)
	}
	status := tun.status()
	if status.Translator != instances.String() || status.TranslatorAddress != own.String() || status.TranslatorError != "" ||
		status.TranslatedOutCount != 1 || status.TranslatedBackCount != 2 || status.TranslateDroppedCount != 3 {
		t.Fatalf("status %+v", status)
	}
	receive := links.current()
	receive(connect.TransferPath{}, protocol.ProvideMode_Network, nil, testTunPacket("100.70.1.2", "100.70.0.46", 6, []byte("reply")))
	receive(connect.TransferPath{}, protocol.ProvideMode_Network, nil, testTunPacket("100.70.1.2", "100.70.0.46", 6, []byte("refused")))
	plain := testTunPacket("100.70.1.2", "100.70.9.9", 6, []byte("plain"))
	receive(connect.TransferPath{}, protocol.ProvideMode_Network, nil, plain)
	iface.stateLock.Lock()
	writes := slices.Clone(iface.writes)
	iface.stateLock.Unlock()
	if len(writes) != 2 || string(writes[0]) != "translated:reply" || !bytes.Equal(writes[1], plain) {
		t.Fatalf("the device was written %q", writes)
	}
	tun.close()
	if len(tunBridge.sets) != 2 || tunBridge.sets[1].IsValid() {
		t.Fatalf("after the close the translator was set %v", tunBridge.sets)
	}
	// the next start keeps the /48
	again, againBridge, _, _ := startTestTranslatorTun(t, store, nil)
	defer again.close()
	if againBridge.sets[0] != prefix {
		t.Fatalf("the next start drew %v, not %v", againBridge.sets[0], prefix)
	}
}

func TestTunLeavesTheTranslatorOffWhereThePlatformRefuses(t *testing.T) {
	tun, tunBridge, _, links := startTestTranslatorTun(t, &urTunMemoryTranslator{}, errors.New("IPv6 is off on this device"))
	defer tun.close()
	if len(tunBridge.sets) != 2 || tunBridge.sets[1].IsValid() {
		t.Fatalf("the bridge's translator was set %v", tunBridge.sets)
	}
	status := tun.status()
	if status.Translator != "" || status.TranslatorError != "IPv6 is off on this device" {
		t.Fatalf("status %+v", status)
	}
	// with it off, a packet to the translator's address is written as it is
	reply := testTunPacket("100.70.1.2", "100.70.0.46", 6, []byte("reply"))
	links.current()(connect.TransferPath{}, protocol.ProvideMode_Network, nil, reply)
	tun.iface.(*testTunTranslatorInterface).stateLock.Lock()
	defer tun.iface.(*testTunTranslatorInterface).stateLock.Unlock()
	if writes := tun.iface.(*testTunTranslatorInterface).writes; len(writes) != 1 || !bytes.Equal(writes[0], reply) {
		t.Fatalf("written %q", writes)
	}
}

// The tun hands the advertising proxy each mDNS query the host sends on its link from its own address and the bridge
// the rest, an mDNS packet from another address among them; the proxy's answers go into the device as replies do, from
// <block>.0.53; and with no receiver every packet goes to the bridge.
func TestTunHandsTheHostsMdnsQueriesToTheProxy(t *testing.T) {
	tun, system, tunBridge, _, _ := startTestUrTun(t)
	link := &testTunLink{}
	tunBridge.stateLock.Lock()
	tunBridge.route = func(packet []byte) connect.UserNatClient { return link }
	tunBridge.stateLock.Unlock()
	if tun.ResolverAddress() != netip.MustParseAddr("100.70.0.53") {
		t.Fatalf("the resolver reads %v", tun.ResolverAddress())
	}
	query := &urMdnsMessage{questions: []urMdnsQuestion{{name: urMdnsNameParse("_ipp._tcp.local"), qtype: urMdnsTypePtr}}}
	payload := query.pack(9000)[0]
	own := urMdnsProxyUdpPacket(netip.MustParseAddrPort("100.70.9.9:5353"), netip.MustParseAddrPort("224.0.0.251:5353"), payload)
	foreign := urMdnsProxyUdpPacket(netip.MustParseAddrPort("100.70.4.4:5353"), netip.MustParseAddrPort("224.0.0.251:5353"), payload)
	other := testTunPacket("100.70.9.9", "100.70.1.2", 17, []byte("to a link"))
	handed := make(chan []byte, 4)
	tun.SetMdnsReceiver(func(packet []byte) { handed <- slices.Clone(packet) })
	system.iface.reads <- testTunRead{packets: [][]byte{own, other, foreign}}
	system.iface.reads <- testTunRead{}
	if got := <-handed; !bytes.Equal(got, own) {
		t.Fatal("the proxy was handed another packet")
	}
	if taken := link.taken(); len(taken) != 2 || !bytes.Equal(taken[0], other) || !bytes.Equal(taken[1], foreign) {
		t.Fatalf("the bridge took %d packets", len(taken))
	}
	select {
	case got := <-handed:
		t.Fatalf("the proxy was handed a second packet %x", got)
	default:
	}
	answer := urMdnsProxyUdpPacket(netip.AddrPortFrom(tun.ResolverAddress(), 5353), netip.MustParseAddrPort("224.0.0.251:5353"), payload)
	tun.WritePacket(answer)
	system.iface.stateLock.Lock()
	writes := slices.Clone(system.iface.writes)
	system.iface.stateLock.Unlock()
	if len(writes) != 1 || !bytes.Equal(writes[0], answer) {
		t.Fatalf("the device was written %d packets", len(writes))
	}
	tun.SetMdnsReceiver(nil)
	system.iface.reads <- testTunRead{packets: [][]byte{own}}
	system.iface.reads <- testTunRead{}
	if taken := link.taken(); len(taken) != 3 {
		t.Fatalf("with no receiver the bridge took %d packets", len(taken))
	}
	if err := tun.SetLinkMulticastDns(true); err == nil {
		t.Fatal("a device with no mDNS of its link turned it on")
	}
}

// The app's VPN component carries a network for discovery only on a paired Mac whose app routes the network's block on
// another interface while ur tun does not carry it (§17.7.1's default row; bridge_discovery_app.go).
func TestAppViewingNeedsAPairedMacWhoseAppRoutesTheBlock(t *testing.T) {
	block := netip.MustParsePrefix("100.70.0.0/16")
	cases := []struct {
		goos       string
		paired     bool
		tunCarries bool
		block      netip.Prefix
		holder     string
		want       bool
	}{
		{goos: "darwin", paired: true, block: block, holder: "utun4", want: true},
		{goos: "linux", paired: true, block: block, holder: "tun0"},
		{goos: "darwin", block: block, holder: "utun4"},
		{goos: "darwin", paired: true, tunCarries: true, block: block, holder: "utun4"},
		{goos: "darwin", paired: true, holder: "utun4"},
		{goos: "darwin", paired: true, block: block},
	}
	for i, c := range cases {
		if got := urAppViewing(c.goos, c.paired, c.tunCarries, c.block, c.holder); got != c.want {
			t.Errorf("case %d: %v", i, got)
		}
	}
	link := urAppDiscoveryLink{}
	if link.ResolverAddress().IsValid() || link.SetLinkMulticastDns(true) == nil {
		t.Fatal("the app's link answers for a tun it is not")
	}
}
