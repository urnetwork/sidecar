// The routing key from a hello's server name, §13.5's step 2. What this refuses never reaches a map,
// and §13.5 answers it as it does any unknown name, so a name is either a clean key or nothing.

package tlsedgeservice

import (
	"strings"
)

// DNS limits, from RFC 1035 §2.3.4: a name in its dotted text form, and one label.
const (
	dnsNameMaxByteCount  = 253
	dnsLabelMaxByteCount = 63
)

// A name as tlsedge routes on it: lowercase, one trailing dot removed, at most 253 bytes, and labels
// of 1 to 63 letters, digits and hyphens with no hyphen at either end. false for anything else: a
// second trailing dot, an empty label, an underscore or a byte outside ASCII. Normalizing a result
// gives it back, so a name already in a map compares as is.
func NormalizeSni(name string) (string, bool) {
	name = strings.TrimSuffix(name, ".")
	if name == "" || dnsNameMaxByteCount < len(name) {
		return "", false
	}
	labelStart := 0
	for index := 0; index <= len(name); index += 1 {
		if index == len(name) || name[index] == '.' {
			labelByteCount := index - labelStart
			if labelByteCount == 0 || dnsLabelMaxByteCount < labelByteCount ||
				name[labelStart] == '-' || name[index-1] == '-' {
				return "", false
			}
			labelStart = index + 1
			continue
		}
		switch c := name[index]; {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '-':
		default:
			return "", false
		}
	}
	return strings.ToLower(name), true
}
