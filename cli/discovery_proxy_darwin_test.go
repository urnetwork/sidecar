//go:build darwin && !ios && !sdk_mobile_bind

// The macOS advertising proxy (§17.7.1; owner decision 778): against this machine's mDNSResponder, an instance the
// viewer keeps is found by a LocalOnly browse alone, resolves to its target under its host's client name with its TXT
// unchanged, its target answering A at the instance's address and AAAA at its translated one; a moved address is
// followed with the instance staying registered; an empty set withdraws it at once; a name another LocalOnly
// registration holds is refused once, counted, and tried again only at the set's next change; and over a fake
// connection, a connection that ends is built again and everything registered on it anew.

package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A proxy over this machine's mDNSResponder whose applies the test hears.
func testDarwinDiscoveryProxy(t *testing.T) (*urDarwinDiscoveryProxy, chan urDiscoveryProxyStatus) {
	t.Helper()
	// skips where no mDNSResponder answers
	testDarwinDnsSdConnection(t)
	applied := make(chan urDiscoveryProxyStatus, 64)
	proxy := newUrDarwinDiscoveryProxy(context.Background(), nil, defaultUrDiscoveryProxySettings(), func() (urDarwinDnsSdConnection, error) {
		return newDarwinDnsSdConnection()
	}, func(status urDiscoveryProxyStatus) { applied <- status })
	t.Cleanup(proxy.Close)
	return proxy, applied
}

// Reads applies until one's status is want: a set handed over before the connection opens is applied twice.
func testDarwinProxyApplied(t *testing.T, applied chan urDiscoveryProxyStatus, want urDiscoveryProxyStatus) {
	t.Helper()
	for status := testDarwinDnsSdNext(t, applied, "apply"); status != want; status = testDarwinDnsSdNext(t, applied, "apply") {
	}
}

// One registration of an instance at address under host.
func testDarwinProxyRegistration(name string, service string, label string, host string, address string, port uint16, txt string) *sidecar.BridgeDiscoveryRegistration {
	return &sidecar.BridgeDiscoveryRegistration{
		Instance: &sidecar.BridgeDiscoveryViewInstance{
			HostName:  host,
			Name:      name,
			Service:   service,
			Subtypes:  []string{"_sub1"},
			Port:      port,
			Txt:       []byte(txt),
			HostLabel: label,
			Address:   netip.MustParseAddr(address),
		},
		Name:   name,
		Target: label + "." + host,
	}
}

func TestDarwinDiscoveryProxyRegistersLocalOnly(t *testing.T) {
	proxy, applied := testDarwinDiscoveryProxy(t)
	service := "_urtest" + testDarwinDnsSdLabel(t, "")[:6] + "._tcp"
	client := testDarwinDnsSdLabel(t, "host-a-")
	name := "Alice's iPhone " + testDarwinDnsSdLabel(t, "")
	txt := "\x0aauthTag=xy\x0cmodel=iPhone"
	translated := func(address netip.Addr) netip.Addr {
		octets := address.As4()
		return netip.AddrFrom16([16]byte{0xfd, 0x12, 0x34, 0x56, 0x78, 0x9a, 0, 1, 0, 0, 0, 0, octets[0], octets[1], octets[2], octets[3]})
	}
	proxy.Set([]*sidecar.BridgeDiscoveryRegistration{
		testDarwinProxyRegistration(name, service, "iphone", client, "100.80.128.7", 49152, txt),
	}, translated)
	testDarwinProxyApplied(t, applied, urDiscoveryProxyStatus{RegisteredCount: 1})

	watcher := testDarwinDnsSdConnection(t)
	browsed := make(chan *darwinDnsSdBrowseReply, 8)
	if _, err := watcher.Browse(darwinDnsSdInterfaceIndexAny, service, "local.", func(reply *darwinDnsSdBrowseReply) {
		browsed <- reply
	}); err != nil {
		t.Fatal(err)
	}
	found := testDarwinDnsSdNext(t, browsed, "browse reply")
	// LocalOnly alone: the registration is this machine's, on no interface
	if found.Name != name || found.Flags&darwinDnsSdFlagsAdd == 0 || found.InterfaceIndex != darwinDnsSdInterfaceIndexLocalOnly {
		t.Fatalf("browsed %+v", found)
	}
	resolved := make(chan *darwinDnsSdResolveReply, 8)
	if _, err := watcher.Resolve(found.InterfaceIndex, found.Name, found.Service, found.Domain, func(reply *darwinDnsSdResolveReply) {
		resolved <- reply
	}); err != nil {
		t.Fatal(err)
	}
	target := testDarwinDnsSdNext(t, resolved, "resolve reply")
	if target.Host != "iphone."+client+".local." || target.Port != 49152 || string(target.Txt) != txt {
		t.Fatalf("resolved %q:%d %q", target.Host, target.Port, target.Txt)
	}
	lookup := func(protocol uint32) chan *darwinDnsSdAddressReply {
		replies := make(chan *darwinDnsSdAddressReply, 8)
		if _, err := watcher.GetAddrInfo(darwinDnsSdInterfaceIndexLocalOnly, protocol, target.Host, func(reply *darwinDnsSdAddressReply) {
			replies <- reply
		}); err != nil {
			t.Fatal(err)
		}
		return replies
	}
	ipv4s, ipv6s := lookup(darwinDnsSdProtocolIpv4), lookup(darwinDnsSdProtocolIpv6)
	if reply := testDarwinDnsSdNext(t, ipv4s, "A"); reply.Address != netip.MustParseAddr("100.80.128.7") {
		t.Fatalf("A %v", reply.Address)
	}
	if reply := testDarwinDnsSdNext(t, ipv6s, "AAAA"); reply.Address != translated(netip.MustParseAddr("100.80.128.7")) {
		t.Fatalf("AAAA %v", reply.Address)
	}

	// the device moves within its served prefix: the lookup follows, and the instance stays
	proxy.Set([]*sidecar.BridgeDiscoveryRegistration{
		testDarwinProxyRegistration(name, service, "iphone", client, "100.80.128.8", 49152, txt),
	}, translated)
	held := map[netip.Addr]bool{netip.MustParseAddr("100.80.128.7"): true}
	for held[netip.MustParseAddr("100.80.128.7")] || !held[netip.MustParseAddr("100.80.128.8")] {
		change := testDarwinDnsSdNext(t, ipv4s, "A change")
		held[change.Address] = change.Flags&darwinDnsSdFlagsAdd != 0
	}
	select {
	case reply := <-browsed:
		if reply.Flags&darwinDnsSdFlagsAdd == 0 {
			t.Fatal("the instance went when its address moved")
		}
	default:
	}

	// the viewer drops it: withdrawn at once
	proxy.Set(nil, translated)
	testDarwinProxyApplied(t, applied, urDiscoveryProxyStatus{})
	if gone := testDarwinDnsSdNext(t, browsed, "removal"); gone.Flags&darwinDnsSdFlagsAdd != 0 || gone.Name != name {
		t.Fatalf("after the withdrawal the browse heard %+v", gone)
	}
}

func TestDarwinDiscoveryProxyLeavesATakenNameOut(t *testing.T) {
	proxy, applied := testDarwinDiscoveryProxy(t)
	service := "_urtest" + testDarwinDnsSdLabel(t, "")[:6] + "._tcp"
	name := "Taken " + testDarwinDnsSdLabel(t, "")
	client := testDarwinDnsSdLabel(t, "host-b-")
	// another LocalOnly registration holds the name first
	holder := testDarwinDnsSdConnection(t)
	registered := make(chan *darwinDnsSdRegisterReply, 2)
	blocker, err := holder.Register(darwinDnsSdFlagsNoAutoRename, darwinDnsSdInterfaceIndexLocalOnly, name, service, "local.", "", 7000, nil,
		func(reply *darwinDnsSdRegisterReply) { registered <- reply })
	if err != nil {
		t.Fatal(err)
	}
	if reply := testDarwinDnsSdNext(t, registered, "blocker"); reply.Err != nil {
		t.Fatal(reply.Err)
	}
	registrations := []*sidecar.BridgeDiscoveryRegistration{
		testDarwinProxyRegistration(name, service, "nas", client, "100.80.128.9", 445, ""),
	}
	proxy.Set(registrations, nil)
	// the refusal arrives on the reader, which wakes one more apply that withdraws and counts it
	testDarwinProxyApplied(t, applied, urDiscoveryProxyStatus{RefusedCount: 1})
	// the name is free at the set's next change, which tries it again
	holder.Cancel(blocker)
	proxy.Set(slices.Clone(registrations), nil)
	testDarwinProxyApplied(t, applied, urDiscoveryProxyStatus{RegisteredCount: 1})
}

// A refused name is withdrawn and not tried again by its refusal's wake or any other under the same set, and is tried
// again at the set's next change. The fake's registrations and withdrawals and the proxy's applies land on one channel
// in the order the proxy's goroutine makes them.
func TestDarwinDiscoveryProxyTriesARefusedNameOnlyAtTheNextSet(t *testing.T) {
	events := make(chan string, 64)
	connection := newTestDarwinProxyConnection()
	connection.taken["Files"] = true
	connection.events = events
	proxy := newUrDarwinDiscoveryProxy(context.Background(), nil, defaultUrDiscoveryProxySettings(), func() (urDarwinDnsSdConnection, error) {
		return connection, nil
	}, func(status urDiscoveryProxyStatus) {
		events <- fmt.Sprintf("apply %d %d", status.RegisteredCount, status.RefusedCount)
	})
	defer proxy.Close()
	registrations := []*sidecar.BridgeDiscoveryRegistration{
		testDarwinProxyRegistration("Files", "_smb._tcp", "nas", "host-a", "100.80.128.9", 445, ""),
		testDarwinProxyRegistration("Screen", "_rfb._tcp", "nas", "host-a", "100.80.128.9", 5900, ""),
	}
	// reads events until want, failing on a second registration of Files before it
	await := func(want string) {
		t.Helper()
		filesCount := 0
		for {
			event := testDarwinDnsSdNext(t, events, want)
			if event == "register Files" {
				filesCount += 1
				if 1 < filesCount {
					t.Fatalf("Files registered twice before %q", want)
				}
			}
			if event == want {
				return
			}
		}
	}
	proxy.Set(registrations, nil)
	await("cancel Files")
	// the apply that withdrew it registers nothing after
	if event := testDarwinDnsSdNext(t, events, "apply"); event != "apply 1 1" {
		t.Fatalf("after the withdrawal %q", event)
	}
	// another wake under the same set registers nothing
	proxy.poke()
	if event := testDarwinDnsSdNext(t, events, "apply"); event != "apply 1 1" {
		t.Fatalf("a wake under the same set brought %q", event)
	}
	// the next set tries it again, once
	proxy.Set(slices.Clone(registrations), nil)
	await("cancel Files")
	if count := connection.registerCount("Files"); count != 2 {
		t.Fatalf("Files was tried %d times over two sets", count)
	}
	// freed, it registers at the set after
	connection.free("Files")
	proxy.Set(slices.Clone(registrations), nil)
	await("apply 2 0")
	if count := connection.registerCount("Screen"); count != 1 {
		t.Fatalf("the name never refused was registered %d times", count)
	}
}

// A connection that a test ends, recording what is registered on it, each name's registrations, and refusing the names
// another registration holds, its refusal coming later on another goroutine as mDNSResponder's reader would bring it.
type testDarwinProxyConnection struct {
	stateLock sync.Mutex
	done      chan struct{}
	closed    bool
	services  map[*darwinDnsSdOperation]string
	records   map[*darwinDnsSdRecord]string
	taken     map[string]bool
	registers map[string]int
	// each name's latest registration's handler, which refuse calls
	nameHandles map[string]func(reply *darwinDnsSdRegisterReply)
	// hears each registration and withdrawal of a service by its name, "register <name>" and "cancel <name>"; nil hears
	// none
	events chan string
}

func newTestDarwinProxyConnection() *testDarwinProxyConnection {
	return &testDarwinProxyConnection{
		done:        make(chan struct{}),
		services:    map[*darwinDnsSdOperation]string{},
		records:     map[*darwinDnsSdRecord]string{},
		taken:       map[string]bool{},
		registers:   map[string]int{},
		nameHandles: map[string]func(reply *darwinDnsSdRegisterReply){},
	}
}

// Refuses name's latest registration on the calling goroutine, at the moment a test chooses, as mDNSResponder's reader
// would when another registration took the name.
func (self *testDarwinProxyConnection) refuse(name string) {
	handle := func() func(reply *darwinDnsSdRegisterReply) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.nameHandles[name]
	}()
	handle(&darwinDnsSdRegisterReply{Err: darwinDnsSdError(darwinDnsSdErrNameConflict), Name: name})
}

// How many times name was registered.
func (self *testDarwinProxyConnection) registerCount(name string) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.registers[name]
}

// Frees a taken name.
func (self *testDarwinProxyConnection) free(name string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.taken, name)
}

func (self *testDarwinProxyConnection) Register(flags uint32, index uint32, name string, service string, domain string, host string,
	port uint16, txt []byte, handle func(reply *darwinDnsSdRegisterReply)) (*darwinDnsSdOperation, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return nil, errDarwinDnsSdClosed
	}
	if index != darwinDnsSdInterfaceIndexLocalOnly || flags&darwinDnsSdFlagsNoAutoRename == 0 {
		return nil, errors.New("not LocalOnly with NoAutoRename")
	}
	operation := &darwinDnsSdOperation{}
	self.services[operation] = name
	self.registers[name] += 1
	self.nameHandles[name] = handle
	if self.events != nil {
		self.events <- "register " + name
	}
	if self.taken[name] {
		go handle(&darwinDnsSdRegisterReply{Err: darwinDnsSdError(darwinDnsSdErrNameConflict), Name: name})
	}
	return operation, nil
}

func (self *testDarwinProxyConnection) RegisterRecord(flags uint32, index uint32, fullName string, rrtype uint16, rdata []byte, ttl uint32,
	handle func(err error)) (*darwinDnsSdRecord, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return nil, errDarwinDnsSdClosed
	}
	if index != darwinDnsSdInterfaceIndexLocalOnly {
		return nil, errors.New("not LocalOnly")
	}
	record := &darwinDnsSdRecord{}
	self.records[record] = fullName
	return record, nil
}

func (self *testDarwinProxyConnection) RemoveRecord(record *darwinDnsSdRecord) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.records, record)
}

func (self *testDarwinProxyConnection) Cancel(operation *darwinDnsSdOperation) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if name, held := self.services[operation]; held && self.events != nil {
		self.events <- "cancel " + name
	}
	delete(self.services, operation)
}

func (self *testDarwinProxyConnection) Done() <-chan struct{} {
	return self.done
}

// Ends the connection as mDNSResponder's restart would.
func (self *testDarwinProxyConnection) end() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !self.closed {
		self.closed = true
		close(self.done)
	}
}

func (self *testDarwinProxyConnection) Close() {
	self.end()
}

// What is registered on it: its services' names and its records' names, each sorted.
func (self *testDarwinProxyConnection) held() ([]string, []string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	services, records := []string{}, []string{}
	for _, name := range self.services {
		services = append(services, name)
	}
	for _, name := range self.records {
		records = append(records, name)
	}
	slices.Sort(services)
	slices.Sort(records)
	return services, records
}

func TestDarwinDiscoveryProxyBuildsAgainAfterAFailure(t *testing.T) {
	connections := make(chan *testDarwinProxyConnection, 4)
	attempts := 0
	settings := defaultUrDiscoveryProxySettings()
	settings.RetryInterval = 0
	applied := make(chan urDiscoveryProxyStatus, 16)
	proxy := newUrDarwinDiscoveryProxy(context.Background(), nil, settings, func() (urDarwinDnsSdConnection, error) {
		attempts += 1
		if attempts == 1 {
			return nil, darwinDnsSdError(darwinDnsSdErrServiceNotRunning)
		}
		connection := newTestDarwinProxyConnection()
		connections <- connection
		return connection, nil
	}, func(status urDiscoveryProxyStatus) { applied <- status })
	defer proxy.Close()
	registrations := []*sidecar.BridgeDiscoveryRegistration{
		testDarwinProxyRegistration("Files", "_smb._tcp", "nas", "host-a", "100.80.128.9", 445, ""),
		testDarwinProxyRegistration("Screen", "_rfb._tcp", "nas", "host-a", "100.80.128.9", 5900, ""),
	}
	proxy.Set(registrations, nil)
	first := testDarwinDnsSdNext(t, connections, "first connection")
	testDarwinProxyApplied(t, applied, urDiscoveryProxyStatus{RegisteredCount: 2})
	services, records := first.held()
	if !slices.Equal(services, []string{"Files", "Screen"}) || !slices.Equal(records, []string{"nas.host-a.local."}) {
		t.Fatalf("held %v %v", services, records)
	}
	// mDNSResponder restarts: everything goes again on a new connection
	first.end()
	second := testDarwinDnsSdNext(t, connections, "second connection")
	testDarwinProxyApplied(t, applied, urDiscoveryProxyStatus{RegisteredCount: 2})
	services, records = second.held()
	if !slices.Equal(services, []string{"Files", "Screen"}) || !slices.Equal(records, []string{"nas.host-a.local."}) {
		t.Fatalf("held again %v %v", services, records)
	}
	// a target that is no host name is left out, and the rest stay
	bad := testDarwinProxyRegistration("Bad", "_smb._tcp", "nas", "host_a", "100.80.128.10", 445, "")
	proxy.Set(append(slices.Clone(registrations), bad), nil)
	testDarwinProxyApplied(t, applied, urDiscoveryProxyStatus{RegisteredCount: 2})
	if services, _ := second.held(); !slices.Equal(services, []string{"Files", "Screen"}) {
		t.Fatalf("with a bad target held %v", services)
	}
	proxy.Close()
	if services, records := second.held(); len(services) != 0 || len(records) != 0 {
		t.Fatalf("after close held %v %v", services, records)
	}
}
