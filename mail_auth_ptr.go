//go:build !sidecar_http && !js && !ios_extension

// The receiver's own forward-confirmed PTR of sender_ip (§15.5; MAIL-M7-08), which owner decision 135's operator
// match reads, never mxedge's: the address's PTR names, each looked up forward until one holds the address, at most
// PtrNameMaxCount of them as RFC 7208 §4.6.4 bounds a ptr term. A lookup that fails or is cut leaves it empty.

package sidecar

import (
	"context"
	"net/netip"
	"strings"
	"unicode/utf8"
)

// The first PTR name of ip that resolves back to it, lowercase with no trailing dot, or empty.
func (self *MailAuthChecker) checkPtr(ctx context.Context, resolver *MailAuthResolver, ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	ip = ip.Unmap()
	names, _, err := resolver.LookupAddr(ctx, ip.String())
	if err != nil {
		return ""
	}
	for _, name := range names[:min(len(names), max(0, self.settings.PtrNameMaxCount))] {
		ips, _, err := resolver.LookupIP(ctx, "ip", name)
		if err != nil {
			continue
		}
		for _, forward := range ips {
			if address, ok := netip.AddrFromSlice(forward); ok && address.Unmap() == ip {
				host := strings.ToLower(strings.TrimSuffix(name, "."))
				if utf8.ValidString(host) && host != "" && len(host) <= dnsDomainMaxByteCount {
					return host
				}
			}
		}
	}
	return ""
}
