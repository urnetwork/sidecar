//go:build !sidecar_http && !ios_extension

// A DNS wire parser of the sender's own for dnssec_chain (§14.4's TL1, D-SMTP-2): uncompressed resource
// records of the eight types a chain to the root needs (DNSKEY, DS, RRSIG, NSEC, NSEC3, MX, TLSA and
// CNAME), in RFC 9102's order, and nothing else. It keeps a DNS library out of the root module (the
// client legs link no miekg/dns), and smtpedge reuses it to build the chain it sends, so both ends read
// one format the same way.
//
// Every read is bounded by the octets it was given: a name is at most 255 octets in labels of at most
// 63, a compression pointer is refused (RFC 9102 §3 sends none, and RFC 4034 forbids them in RRSIG and
// NSEC), an rdata is parsed only within its own length, and a record of another type or class, or one
// whose rdata does not parse, fails the whole chain. Nothing here is trusted: smtp_dnssec_chain.go
// decides what validates.
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10).

package sidecar

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// DNS format values (RFC 1035, RFC 4034, RFC 5155, RFC 6698).
const (
	smtpDnsTypeA      uint16 = 1
	smtpDnsTypeNs     uint16 = 2
	smtpDnsTypeCname  uint16 = 5
	smtpDnsTypeSoa    uint16 = 6
	smtpDnsTypeMx     uint16 = 15
	smtpDnsTypeDname  uint16 = 39
	smtpDnsTypeDs     uint16 = 43
	smtpDnsTypeRrsig  uint16 = 46
	smtpDnsTypeNsec   uint16 = 47
	smtpDnsTypeDnskey uint16 = 48
	smtpDnsTypeNsec3  uint16 = 50
	smtpDnsTypeTlsa   uint16 = 52
	smtpDnsClassIn    uint16 = 1
	// RFC 1035 §2.3.4.
	smtpDnsNameMaxByteCount  = 255
	smtpDnsLabelMaxByteCount = 63
	// owner, type, class, TTL and rdlength after the name
	smtpDnsRrFixedByteCount = 10
)

// A chain that does not parse, or does not validate. errors.Is finds it under the detail, which names
// no record's content.
var ErrSmtpDnssecBogus = errors.New("smtp dnssec: chain does not validate")

// A domain name as uncompressed wire octets with ASCII letters lowercased: its canonical form (RFC 4034
// §6.2), which compares, keys a map and hashes exactly. The root is one zero octet.
type smtpDnsName string

// The root's name.
const smtpDnsRoot smtpDnsName = "\x00"

// Reads one uncompressed name at offset, returning it canonical and the offset after it.
func readSmtpDnsName(data []byte, offset int) (smtpDnsName, int, error) {
	start := offset
	var canonical []byte
	for {
		if len(data) <= offset {
			return "", 0, fmt.Errorf("%w: a name runs past its record", ErrSmtpDnssecBogus)
		}
		length := int(data[offset])
		if length&0xc0 != 0 {
			return "", 0, fmt.Errorf("%w: a compressed or extended label", ErrSmtpDnssecBogus)
		}
		if len(data) < offset+1+length {
			return "", 0, fmt.Errorf("%w: a label runs past its record", ErrSmtpDnssecBogus)
		}
		canonical = append(canonical, byte(length))
		for _, octet := range data[offset+1 : offset+1+length] {
			if 'A' <= octet && octet <= 'Z' {
				octet += 'a' - 'A'
			}
			canonical = append(canonical, octet)
		}
		offset += 1 + length
		if smtpDnsNameMaxByteCount < offset-start {
			return "", 0, fmt.Errorf("%w: a name past 255 octets", ErrSmtpDnssecBogus)
		}
		if length == 0 {
			return smtpDnsName(canonical), offset, nil
		}
	}
}

// The canonical name of a text name of letters, digits, hyphens and underscores, such as an MX host or
// _25._tcp.<host>. ok is false for anything else, which no caller here needs.
func smtpDnsNameFromText(text string) (smtpDnsName, bool) {
	text = strings.TrimSuffix(strings.ToLower(text), ".")
	if text == "" {
		return smtpDnsRoot, true
	}
	var wire []byte
	for label := range strings.SplitSeq(text, ".") {
		if label == "" || smtpDnsLabelMaxByteCount < len(label) {
			return "", false
		}
		for i := range len(label) {
			c := label[i]
			if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_' || c == '*') {
				return "", false
			}
		}
		wire = append(wire, byte(len(label)))
		wire = append(wire, label...)
	}
	wire = append(wire, 0)
	if smtpDnsNameMaxByteCount < len(wire) {
		return "", false
	}
	return smtpDnsName(wire), true
}

// The labels, leftmost first, without the root.
func (self smtpDnsName) labels() []string {
	var labels []string
	for offset := 0; offset < len(self) && self[offset] != 0; {
		length := int(self[offset])
		labels = append(labels, string(self[offset+1:offset+1+length]))
		offset += 1 + length
	}
	return labels
}

// How many labels, the root's none, as an RRSIG's labels field counts them (a leading * excluded by
// the caller).
func (self smtpDnsName) labelCount() int {
	return len(self.labels())
}

// The name less its leftmost label. The root's parent is the root.
func (self smtpDnsName) parent() smtpDnsName {
	if self == smtpDnsRoot || len(self) == 0 {
		return smtpDnsRoot
	}
	return self[1+int(self[0]):]
}

// The rightmost count labels of the name.
func (self smtpDnsName) suffix(count int) smtpDnsName {
	name := self
	for extra := name.labelCount() - count; 0 < extra; extra -= 1 {
		name = name.parent()
	}
	return name
}

// The name with label added on the left.
func (self smtpDnsName) child(label string) smtpDnsName {
	return smtpDnsName(string([]byte{byte(len(label))}) + label + string(self))
}

// Whether the name is zone or under it.
func (self smtpDnsName) under(zone smtpDnsName) bool {
	return len(zone) <= len(self) && strings.HasSuffix(string(self), string(zone)) &&
		(len(zone) == len(self) || self.suffix(zone.labelCount()) == zone)
}

// Whether the leftmost label is *.
func (self smtpDnsName) wildcard() bool {
	return 2 <= len(self) && self[0] == 1 && self[1] == '*'
}

// RFC 4034 §6.1's canonical order: labels compared from the rightmost, each as octets, a missing label
// first. Negative, zero or positive as with bytes.Compare.
func (self smtpDnsName) compare(other smtpDnsName) int {
	left, right := self.labels(), other.labels()
	for i := 1; i <= len(left) && i <= len(right); i += 1 {
		if order := strings.Compare(left[len(left)-i], right[len(right)-i]); order != 0 {
			return order
		}
	}
	return len(left) - len(right)
}

// One resource record as the chain carries it, its owner canonical and its rdata as sent.
type smtpDnsRr struct {
	owner  smtpDnsName
	rrtype uint16
	rdata  []byte
}

// A parsed RRSIG (RFC 4034 §3.1).
type smtpDnsRrsig struct {
	typeCovered uint16
	algorithm   uint8
	labels      uint8
	originalTtl uint32
	expiration  uint32
	inception   uint32
	keyTag      uint16
	signer      smtpDnsName
	// The rdata through the signer's name, which is canonical here, as the signed data opens with it.
	signedPrefix []byte
	signature    []byte
}

// A parsed DNSKEY (RFC 4034 §2.1).
type smtpDnsDnskey struct {
	flags     uint16
	protocol  uint8
	algorithm uint8
	publicKey []byte
	rdata     []byte
	keyTag    uint16
}

// A parsed DS (RFC 4034 §5.1).
type smtpDnsDs struct {
	keyTag     uint16
	algorithm  uint8
	digestType uint8
	digest     []byte
}

// A parsed NSEC (RFC 4034 §4.1).
type smtpDnsNsec struct {
	next   smtpDnsName
	bitmap []byte
}

// A parsed NSEC3 (RFC 5155 §3).
type smtpDnsNsec3 struct {
	hashAlgorithm uint8
	flags         uint8
	iterations    uint16
	salt          []byte
	nextHashed    []byte
	bitmap        []byte
}

// RFC 5155 §3.1.2.1: the opt-out flag.
const smtpDnsNsec3OptOut = 0x01

// RFC 4034 §2.1.1: the zone key and revoke (RFC 5011) flags.
const (
	smtpDnsDnskeyZone   = 0x0100
	smtpDnsDnskeyRevoke = 0x0080
)

// Reads an RRSIG's rdata.
func parseSmtpDnsRrsig(rdata []byte) (*smtpDnsRrsig, error) {
	if len(rdata) < 18 {
		return nil, fmt.Errorf("%w: a short rrsig", ErrSmtpDnssecBogus)
	}
	signer, end, err := readSmtpDnsName(rdata, 18)
	if err != nil {
		return nil, err
	}
	if end == len(rdata) {
		return nil, fmt.Errorf("%w: an rrsig with no signature", ErrSmtpDnssecBogus)
	}
	prefix := append(append([]byte{}, rdata[:18]...), signer...)
	return &smtpDnsRrsig{
		typeCovered:  binary.BigEndian.Uint16(rdata[0:2]),
		algorithm:    rdata[2],
		labels:       rdata[3],
		originalTtl:  binary.BigEndian.Uint32(rdata[4:8]),
		expiration:   binary.BigEndian.Uint32(rdata[8:12]),
		inception:    binary.BigEndian.Uint32(rdata[12:16]),
		keyTag:       binary.BigEndian.Uint16(rdata[16:18]),
		signer:       signer,
		signedPrefix: prefix,
		signature:    rdata[end:],
	}, nil
}

// RFC 4034 Appendix B's key tag over a DNSKEY's rdata.
func smtpDnsKeyTag(rdata []byte) uint16 {
	var sum uint32
	for i, octet := range rdata {
		if i&1 == 0 {
			sum += uint32(octet) << 8
		} else {
			sum += uint32(octet)
		}
	}
	sum += sum >> 16 & 0xffff
	return uint16(sum & 0xffff)
}

// Reads a DNSKEY's rdata.
func parseSmtpDnsDnskey(rdata []byte) (*smtpDnsDnskey, error) {
	if len(rdata) < 5 {
		return nil, fmt.Errorf("%w: a short dnskey", ErrSmtpDnssecBogus)
	}
	return &smtpDnsDnskey{
		flags:     binary.BigEndian.Uint16(rdata[0:2]),
		protocol:  rdata[2],
		algorithm: rdata[3],
		publicKey: rdata[4:],
		rdata:     rdata,
		keyTag:    smtpDnsKeyTag(rdata),
	}, nil
}

// Reads a DS's rdata.
func parseSmtpDnsDs(rdata []byte) (*smtpDnsDs, error) {
	if len(rdata) < 5 {
		return nil, fmt.Errorf("%w: a short ds", ErrSmtpDnssecBogus)
	}
	return &smtpDnsDs{keyTag: binary.BigEndian.Uint16(rdata[0:2]), algorithm: rdata[2], digestType: rdata[3], digest: rdata[4:]}, nil
}

// Whether a type bitmap is RFC 4034 §4.1.2's form: windows in increasing order, each 1 to 32 octets.
func smtpDnsBitmapValid(bitmap []byte) bool {
	last := -1
	for offset := 0; offset < len(bitmap); {
		if len(bitmap) < offset+2 {
			return false
		}
		window, length := int(bitmap[offset]), int(bitmap[offset+1])
		if window <= last || length < 1 || 32 < length || len(bitmap) < offset+2+length {
			return false
		}
		last = window
		offset += 2 + length
	}
	return true
}

// Whether a valid type bitmap holds rrtype.
func smtpDnsBitmapHas(bitmap []byte, rrtype uint16) bool {
	window, bit := int(rrtype>>8), int(rrtype&0xff)
	for offset := 0; offset+2 <= len(bitmap); {
		length := int(bitmap[offset+1])
		if int(bitmap[offset]) == window {
			return bit/8 < length && bitmap[offset+2+bit/8]&(0x80>>(bit%8)) != 0
		}
		offset += 2 + length
	}
	return false
}

// Reads an NSEC's rdata.
func parseSmtpDnsNsec(rdata []byte) (*smtpDnsNsec, error) {
	next, end, err := readSmtpDnsName(rdata, 0)
	if err != nil {
		return nil, err
	}
	if !smtpDnsBitmapValid(rdata[end:]) {
		return nil, fmt.Errorf("%w: an nsec bitmap", ErrSmtpDnssecBogus)
	}
	return &smtpDnsNsec{next: next, bitmap: rdata[end:]}, nil
}

// Reads an NSEC3's rdata.
func parseSmtpDnsNsec3(rdata []byte) (*smtpDnsNsec3, error) {
	if len(rdata) < 5 {
		return nil, fmt.Errorf("%w: a short nsec3", ErrSmtpDnssecBogus)
	}
	saltEnd := 5 + int(rdata[4])
	if len(rdata) < saltEnd+1 {
		return nil, fmt.Errorf("%w: a short nsec3", ErrSmtpDnssecBogus)
	}
	hashEnd := saltEnd + 1 + int(rdata[saltEnd])
	if len(rdata) < hashEnd || int(rdata[saltEnd]) == 0 || !smtpDnsBitmapValid(rdata[hashEnd:]) {
		return nil, fmt.Errorf("%w: an nsec3 hash or bitmap", ErrSmtpDnssecBogus)
	}
	return &smtpDnsNsec3{
		hashAlgorithm: rdata[0],
		flags:         rdata[1],
		iterations:    binary.BigEndian.Uint16(rdata[2:4]),
		salt:          rdata[5:saltEnd],
		nextHashed:    rdata[saltEnd+1 : hashEnd],
		bitmap:        rdata[hashEnd:],
	}, nil
}

// An MX's exchange, canonical.
func parseSmtpDnsMx(rdata []byte) (smtpDnsName, error) {
	if len(rdata) < 3 {
		return "", fmt.Errorf("%w: a short mx", ErrSmtpDnssecBogus)
	}
	exchange, end, err := readSmtpDnsName(rdata, 2)
	if err != nil {
		return "", err
	}
	if end != len(rdata) {
		return "", fmt.Errorf("%w: an mx with trailing octets", ErrSmtpDnssecBogus)
	}
	return exchange, nil
}

// A CNAME's target, canonical.
func parseSmtpDnsCname(rdata []byte) (smtpDnsName, error) {
	target, end, err := readSmtpDnsName(rdata, 0)
	if err != nil {
		return "", err
	}
	if end != len(rdata) {
		return "", fmt.Errorf("%w: a cname with trailing octets", ErrSmtpDnssecBogus)
	}
	return target, nil
}

// A TLSA record.
func parseSmtpDnsTlsa(rdata []byte) (*SmtpTlsaRecord, error) {
	if len(rdata) < 3 {
		return nil, fmt.Errorf("%w: a short tlsa", ErrSmtpDnssecBogus)
	}
	return &SmtpTlsaRecord{Usage: rdata[0], Selector: rdata[1], MatchingType: rdata[2], Data: bytes.Clone(rdata[3:])}, nil
}

// The rdata as RFC 4034 §6.2 signs it: names inside an MX and a CNAME lowercased, every other type as
// sent (RFC 6840 §5.1 leaves NSEC's next name as it is).
func (self *smtpDnsRr) canonicalRdata() []byte {
	switch self.rrtype {
	case smtpDnsTypeMx:
		exchange, _ := parseSmtpDnsMx(self.rdata)
		return append(append([]byte{}, self.rdata[:2]...), exchange...)
	case smtpDnsTypeCname:
		target, _ := parseSmtpDnsCname(self.rdata)
		return []byte(target)
	}
	return self.rdata
}

// Reads every record of a chain, at most maxRrCount of them, refusing a type or class outside what a
// chain to the root holds and any rdata that does not parse as its type.
func parseSmtpDnsRrs(chain []byte, maxRrCount int) ([]*smtpDnsRr, error) {
	var rrs []*smtpDnsRr
	for offset := 0; offset < len(chain); {
		if maxRrCount <= len(rrs) {
			return nil, fmt.Errorf("%w: past %d records", ErrSmtpDnssecBogus, maxRrCount)
		}
		owner, end, err := readSmtpDnsName(chain, offset)
		if err != nil {
			return nil, err
		}
		if len(chain) < end+smtpDnsRrFixedByteCount {
			return nil, fmt.Errorf("%w: a record runs past the chain", ErrSmtpDnssecBogus)
		}
		rrtype := binary.BigEndian.Uint16(chain[end : end+2])
		class := binary.BigEndian.Uint16(chain[end+2 : end+4])
		rdataByteCount := int(binary.BigEndian.Uint16(chain[end+8 : end+10]))
		rdataStart := end + smtpDnsRrFixedByteCount
		if len(chain) < rdataStart+rdataByteCount {
			return nil, fmt.Errorf("%w: an rdata runs past the chain", ErrSmtpDnssecBogus)
		}
		if class != smtpDnsClassIn {
			return nil, fmt.Errorf("%w: a record outside class IN", ErrSmtpDnssecBogus)
		}
		rr := &smtpDnsRr{owner: owner, rrtype: rrtype, rdata: chain[rdataStart : rdataStart+rdataByteCount]}
		switch rrtype {
		case smtpDnsTypeRrsig:
			_, err = parseSmtpDnsRrsig(rr.rdata)
		case smtpDnsTypeDnskey:
			_, err = parseSmtpDnsDnskey(rr.rdata)
		case smtpDnsTypeDs:
			_, err = parseSmtpDnsDs(rr.rdata)
		case smtpDnsTypeNsec:
			_, err = parseSmtpDnsNsec(rr.rdata)
		case smtpDnsTypeNsec3:
			_, err = parseSmtpDnsNsec3(rr.rdata)
		case smtpDnsTypeMx:
			_, err = parseSmtpDnsMx(rr.rdata)
		case smtpDnsTypeCname:
			_, err = parseSmtpDnsCname(rr.rdata)
		case smtpDnsTypeTlsa:
			_, err = parseSmtpDnsTlsa(rr.rdata)
		default:
			err = fmt.Errorf("%w: a record of type %d", ErrSmtpDnssecBogus, rrtype)
		}
		if err != nil {
			return nil, err
		}
		rrs = append(rrs, rr)
		offset = rdataStart + rdataByteCount
	}
	return rrs, nil
}
