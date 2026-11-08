// §13.8's identifier sets and their hash. A device building a CSR, certs checking one and the CT watch reading a
// certificate must all get one answer, so this is pure, on every leg, and nothing here takes a name from anywhere but
// its arguments. A set is canonical: lowercase, a wildcard written *.x, sorted bytewise, each name once.
//
// Errors name no input, since a label or alias may reach a log (I-13).

package sidecar

import (
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
)

// DNS limits, from RFC 1035 §2.3.4: one label, and a name in its dotted text form.
const (
	tlsDnsLabelMaxByteCount = 63
	tlsDnsNameMaxByteCount  = 253
)

// A name that cannot be in a set, or a set that has no names.
var ErrTlsIdentifierSet = errors.New("tls identifier set refused")

// Whether label is one lowercase label of letters, digits and hyphens, with no hyphen at either end. §13.5's
// NormalizeSni gives no other label, so a set holds only what a visitor can reach.
func tlsDnsLabelCanonical(label string) bool {
	if label == "" || tlsDnsLabelMaxByteCount < len(label) || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for index := range len(label) {
		switch c := label[index]; {
		case 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}

// Whether name is canonical labels joined by dots, at most 253 bytes, with no trailing dot.
func tlsDnsNameCanonical(name string) bool {
	if name == "" || tlsDnsNameMaxByteCount < len(name) {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if !tlsDnsLabelCanonical(label) {
			return false
		}
	}
	return true
}

// Whether name is a canonical name, or that name under one leading wildcard label, at most 253 bytes in all.
func tlsIdentifierCanonical(name string) bool {
	zone, _ := strings.CutPrefix(name, "*.")
	return len(name) <= tlsDnsNameMaxByteCount && tlsDnsNameCanonical(zone)
}

// §13.8's set for a device of the network whose label this is, under root: {*.<net>.<root>, <net>.<root>}, each live
// alias's pair beside it, or with a scope, {*.<scope>.<net>.<root>, <scope>.<net>.<root>} alone, whatever aliases say,
// since a scope's devices hold nothing else (owner decisions 40, 58). label, scope and each alias are one label each.
// An empty scope is none.
//
// The set comes from verified config on a device, never from a server's answer, and what a caller's scope does not
// give it is not here to refuse: a device checked against this set gets only this set.
func TlsIdentifierSet(root string, label string, scope string, aliases []string) ([]string, error) {
	if !tlsDnsNameCanonical(root) || !tlsDnsLabelCanonical(label) {
		return nil, ErrTlsIdentifierSet
	}
	zones := []string{label + "." + root}
	if scope != "" {
		if !tlsDnsLabelCanonical(scope) {
			return nil, ErrTlsIdentifierSet
		}
		zones = []string{scope + "." + label + "." + root}
	} else {
		for _, alias := range aliases {
			if !tlsDnsLabelCanonical(alias) {
				return nil, ErrTlsIdentifierSet
			}
			zones = append(zones, alias+"."+root)
		}
	}
	identifierSet := make([]string, 0, 2*len(zones))
	for _, zone := range zones {
		identifierSet = append(identifierSet, "*."+zone, zone)
	}
	slices.Sort(identifierSet)
	identifierSet = slices.Compact(identifierSet)
	for _, name := range identifierSet {
		// the wildcard takes 2 bytes more than the name that passed above, and a zone is only checked here
		if !tlsIdentifierCanonical(name) {
			return nil, ErrTlsIdentifierSet
		}
	}
	return identifierSet, nil
}

// SHA-256 over a set's names, sorted bytewise, each once and each followed by one 0x00 byte, so the order a caller
// holds them in changes nothing. What an attestation binds (TlsKeyAttestation.identifier_set_sha256).
//
// Names off a CSR or a certificate pass as they came, so a name that is not canonical refuses the whole set: 0x00
// inside a name would hash as two names, and a name in another case would hash as a name it is not. An empty set has
// no hash either.
func TlsIdentifierSetHash(identifierSet []string) ([sha256.Size]byte, error) {
	if len(identifierSet) == 0 {
		return [sha256.Size]byte{}, ErrTlsIdentifierSet
	}
	names := slices.Sorted(slices.Values(identifierSet))
	names = slices.Compact(names)
	hash := sha256.New()
	for _, name := range names {
		if !tlsIdentifierCanonical(name) {
			return [sha256.Size]byte{}, ErrTlsIdentifierSet
		}
		hash.Write([]byte(name))
		hash.Write([]byte{0x00})
	}
	return [sha256.Size]byte(hash.Sum(nil)), nil
}
