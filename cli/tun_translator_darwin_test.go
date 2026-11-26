//go:build darwin

// The translator's IPv6 on a utun (tun_darwin.go; §17.5, owner decision 778): struct in6_aliasreq's layout as
// <netinet6/in6_var.h> has it, 128 bytes, so SIOCAIFADDR_IN6's number, which encodes that size, is the kernel's; and a
// kernel that takes no IPv6 address leaves the translator refused.

package main

import (
	"net/netip"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestUrTunDarwinIn6AliasreqIsTheKernels(t *testing.T) {
	request := urTunDarwinIn6Aliasreq{}
	if size := unsafe.Sizeof(request); size != 128 {
		t.Fatalf("in6_aliasreq is %d bytes", size)
	}
	if offset := unsafe.Offsetof(request.Flags); offset != unix.IFNAMSIZ+3*unix.SizeofSockaddrInet6 {
		t.Fatalf("ifra_flags at %d", offset)
	}
	if offset := unsafe.Offsetof(request.Lifetime); offset != 104 {
		t.Fatalf("ifra_lifetime at %d", offset)
	}
	// _IOW('i', 26, struct in6_aliasreq): IOC_IN, the size, the group and the number
	if want := uint32(0x80000000 | (128&0x1FFF)<<16 | uint32('i')<<8 | 26); urTunDarwinSiocaifaddrIn6 != want {
		t.Fatalf("SIOCAIFADDR_IN6 %#x, want %#x", urTunDarwinSiocaifaddrIn6, want)
	}
}

func TestUrTunDarwinTranslatorNeedsAnIpv6Kernel(t *testing.T) {
	iface := &urTunDarwinInterface{system: &urTunDarwinSystem{kernel: &testUrTunDarwinNoIpv6Kernel{}}, name: "utun9", index: 9}
	if err := iface.SetTranslator(netip.MustParseAddr("fd12::1"), netip.MustParsePrefix("fd12:0:0:1::/96")); err == nil {
		t.Fatal("a kernel with no IPv6 address took the translator")
	}
	if err := iface.SetTranslator(netip.MustParseAddr("100.70.0.46"), netip.MustParsePrefix("fd12:0:0:1::/96")); err == nil {
		t.Fatal("an IPv4 address took the translator")
	}
}

// A kernel that records nothing and takes no IPv6 address.
type testUrTunDarwinNoIpv6Kernel struct {
	urTunDarwinKernel
}
