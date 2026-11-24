// DNS-SD's service type names (RFC 6763 §7; owner decision 778), which the ACL document's discovery block (§8.5) and
// §17.7.1's watch both write: `_<name>._tcp` or `_<name>._udp`, the name one to 62 ASCII letters,
// digits and hyphens with at least one letter, no hyphen at either end and no two together (RFC 6335 §5.1). RFC 6763
// §7.2 caps a name at 15 characters, but Apple's device types run longer, `_remotepairing-manual-pairing` among them,
// and mDNSResponder browses such a type in local. alone (DNSCommon.c), so a name past 15 is kept, bounded by one DNS
// label, and only the advertising proxy carries it (§17.7.1's types row).
//
// On every leg: the policy document's reader is on the forwarding leg (D-SDK-20), and every reader must parse a
// document alike (§8.5).

package protocol

import (
	"strings"
)

// The transports a service type names (RFC 6763 §7).
const (
	DnsSdTransportTcp = "_tcp"
	DnsSdTransportUdp = "_udp"
)

// The longest service name one DNS label holds beside its underscore: 62 octets. A format value, since every reader of a
// document must refuse the same names (§8.5), so a constant.
const dnsSdServiceNameMaxByteCount = 62

// A service type as written, lowercased, split into its name, without the underscore, and its transport. ok is false
// for anything that is not `_<name>._tcp` or `_<name>._udp` by the file's rule.
func ParseDnsSdServiceType(text string) (name string, transport string, ok bool) {
	serviceLabel, transportLabel, found := strings.Cut(strings.ToLower(text), ".")
	if !found || (transportLabel != DnsSdTransportTcp && transportLabel != DnsSdTransportUdp) {
		return "", "", false
	}
	if !strings.HasPrefix(serviceLabel, "_") {
		return "", "", false
	}
	name = serviceLabel[1:]
	if !ValidDnsSdServiceName(name) {
		return "", "", false
	}
	return name, transportLabel, true
}

// Whether text is a service type by the file's rule, in any case.
func ValidDnsSdServiceType(text string) bool {
	_, _, ok := ParseDnsSdServiceType(text)
	return ok
}

// Whether name, without its underscore, is a service name by the file's rule: lowercase letters, digits and hyphens,
// with at least one letter, no hyphen at either end and no two together.
func ValidDnsSdServiceName(name string) bool {
	if name == "" || dnsSdServiceNameMaxByteCount < len(name) || name[0] == '-' || name[len(name)-1] == '-' {
		return false
	}
	letter := false
	for i := 0; i < len(name); i += 1 {
		c := name[i]
		switch {
		case 'a' <= c && c <= 'z':
			letter = true
		case '0' <= c && c <= '9':
		case c == '-':
			if name[i-1] == '-' {
				return false
			}
		default:
			return false
		}
	}
	return letter
}
