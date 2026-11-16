// The seam each platform's ur tun sits behind (tun_device.go), on every GOOS a CI leg runs: each system the release
// builds has a platform, a privilege refusal reads in its platform's words and is errUrTunPrivilege still, the read
// leaves the headroom a utun's family header needs, a device the platform names keeps that name, the exits' halves
// cover IPv4 whole and IPv6's IPv6, and a zone only names a resolver file or rule when it is a DNS name. tun_darwin_test.go,
// tun_windows_test.go and tun_linux_test.go hold each platform's own.

package main

import (
	"context"
	"errors"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

// Linux, macOS and Windows each set their platform, so ur tun refuses nowhere the release ships.
func TestTunPlatformIsRegistered(t *testing.T) {
	switch runtime.GOOS {
	case "linux", "darwin", "windows":
		if urTunPlatform == nil {
			t.Fatalf("%s has no ur tun", runtime.GOOS)
		}
		if system := urTunPlatform(testUrTunSettings(), sidecar.NewNoopLogger()); system == nil {
			t.Fatalf("%s's platform is nil", runtime.GOOS)
		}
	default:
		if urTunPlatform != nil {
			t.Fatalf("%s has a platform", runtime.GOOS)
		}
	}
}

// A platform's refusal is errUrTunPrivilege for the start, reads as the platform says, and keeps the system's cause.
func TestTunPrivilegeErrorReadsAsThePlatformSays(t *testing.T) {
	cause := errors.New("operation not permitted")
	err := error(&urTunPrivilegeError{text: "a platform's words", err: cause})
	if !errors.Is(err, errUrTunPrivilege) || !errors.Is(err, cause) {
		t.Fatal("not the privilege refusal")
	}
	if err.Error() != "a platform's words (operation not permitted)" {
		t.Fatalf("reads %q", err.Error())
	}
	if errors.Is(errors.New("another"), errUrTunPrivilege) {
		t.Fatal("any error is the refusal")
	}
}

// IPv6's halves are /1s, apart, and together all of IPv6, as IPv4's are of IPv4, so the default route they make under
// exits takes every IPv6 address the host's own default would (QD-881).
func TestTunExitsIpv6HalvesCoverIpv6(t *testing.T) {
	halves := urTunExitsIpv6Halves()
	if len(halves) != 2 || halves[0].Overlaps(halves[1]) {
		t.Fatalf("halves %v", halves)
	}
	for _, address := range []string{"::", "::1", "2001:db8::1", "7fff:ffff::1", "8000::", "fe80::1", "ff02::1",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"} {
		inside := 0
		for _, half := range halves {
			if half.Bits() != 1 || !half.Addr().Is6() {
				t.Fatalf("a half %s", half)
			}
			if half.Contains(netip.MustParseAddr(address)) {
				inside += 1
			}
		}
		if inside != 1 {
			t.Fatalf("%s is in %d halves", address, inside)
		}
	}
	for _, half := range urTunExitsHalves() {
		if !half.Addr().Is4() {
			t.Fatalf("IPv4's half %s", half)
		}
	}
}

// The halves are /1s, apart, and together all of IPv4, so the default route they make takes every address the host's
// own default would.
func TestTunExitsHalvesCoverIpv4(t *testing.T) {
	halves := urTunExitsHalves()
	if len(halves) != 2 || halves[0].Overlaps(halves[1]) {
		t.Fatalf("halves %v", halves)
	}
	for _, address := range []string{"0.0.0.0", "10.0.0.1", "127.255.255.255", "192.0.2.1", "203.0.113.7", "255.255.255.255"} {
		inside := 0
		for _, half := range halves {
			if half.Bits() != 1 {
				t.Fatalf("a half %s", half)
			}
			if half.Contains(netip.MustParseAddr(address)) {
				inside += 1
			}
		}
		if inside != 1 {
			t.Fatalf("%s is in %d halves", address, inside)
		}
	}
}

// A zone names a file or a rule only as a DNS name, lowercase and without its root dot; anything else is refused.
func TestTunZoneNames(t *testing.T) {
	settings := testUrTunSettings()
	for zone, want := range map[string]string{
		"net.example":      "net.example",
		"Net.Example.":     "net.example",
		"a-1.b2.example":   "a-1.b2.example",
		"x":                "x",
		"label-63.example": "label-63.example",
	} {
		if got, ok := urTunZoneName(zone, settings); !ok || got != want {
			t.Errorf("%q: %q %v", zone, got, ok)
		}
	}
	for _, zone := range []string{"", ".", "../etc", "a/b", "a..b", "-a.example", "a-.example", "a b.example",
		"a_b.example", "a\\b", strings.Repeat("a", settings.ZoneLabelMaxByteCount+1) + ".example",
		strings.Repeat("abcdefgh.", 32) + "example"} {
		if got, ok := urTunZoneName(zone, settings); ok {
			t.Errorf("%q named %q", zone, got)
		}
	}
}

// A device that records the offset each read is asked for, and names itself as macOS's do.
type testTunNamedInterface struct {
	*testTunInterface
	name string

	offsetLock sync.Mutex
	offsets    []int
}

func (self *testTunNamedInterface) Name() string {
	return self.name
}

func (self *testTunNamedInterface) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	self.offsetLock.Lock()
	self.offsets = append(self.offsets, offset)
	self.offsetLock.Unlock()
	return self.testTunInterface.Read(bufs, sizes, offset)
}

// A platform whose device is named by the system.
type testTunNamedSystem struct {
	*testTunSystem
	named *testTunNamedInterface

	namesLock sync.Mutex
	names     []string
}

func (self *testTunNamedSystem) Open(name string, mtu int) (urTunInterface, error) {
	if _, err := self.testTunSystem.Open(name, mtu); err != nil {
		return nil, err
	}
	return self.named, nil
}

func (self *testTunNamedSystem) LocalAddresses(name string, exclude []netip.Addr) ([]netip.Addr, error) {
	self.namesLock.Lock()
	self.names = append(self.names, name)
	self.namesLock.Unlock()
	return self.testTunSystem.LocalAddresses(name, exclude)
}

// The tun takes the device's own name where the platform names it, and asks the platform about that interface; each
// read leaves the settings' headroom in front, and the packet behind it reaches the bridge whole.
func TestTunTakesThePlatformsNameAndHeadroom(t *testing.T) {
	system := &testTunNamedSystem{testTunSystem: newTestTunSystem()}
	system.named = &testTunNamedInterface{testTunInterface: system.iface, name: "utun7"}
	tunBridge := newTestTunBridge()
	link := &testTunLink{}
	tunBridge.route = func(packet []byte) connect.UserNatClient { return link }
	settings := testUrTunSettings()
	tun, err := startUrTun(context.Background(), &urTunArgs{
		Name:      "ur-test",
		NetworkId: sidecar.NewId(),
		System:    system,
		Bridge:    tunBridge,
		Links:     &testTunLinks{},
		Settings:  settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tun.close()
	if status := tun.status(); status.Device != "utun7" {
		t.Fatalf("device %q", status.Device)
	}
	packet := testTunPacket("100.70.9.9", "100.70.1.2", 17, []byte("behind the headroom"))
	system.iface.reads <- testTunRead{packets: [][]byte{packet}}
	system.iface.reads <- testTunRead{}
	taken := link.taken()
	if len(taken) != 1 || string(taken[0]) != string(packet) {
		t.Fatalf("the link took %d packets", len(taken))
	}
	system.named.offsetLock.Lock()
	offsets := slices.Clone(system.named.offsets)
	system.named.offsetLock.Unlock()
	if len(offsets) == 0 || slices.ContainsFunc(offsets, func(offset int) bool { return offset != settings.ReadHeadroomByteCount }) {
		t.Fatalf("read at offsets %v", offsets)
	}
	system.namesLock.Lock()
	names := slices.Clone(system.names)
	system.namesLock.Unlock()
	if len(names) == 0 || slices.ContainsFunc(names, func(name string) bool { return name != "utun7" }) {
		t.Fatalf("asked about %v", names)
	}
}
