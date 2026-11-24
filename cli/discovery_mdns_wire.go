// The mDNS wire format the Linux advertising proxy and the Linux and Windows querier read and write (RFC 1035 §4.1,
// RFC 6762 §18; §17.7.1, owner decision 778), on every platform: a name is its labels' raw octets, so an instance's
// label holding a dot or a space stays one label, which golang.org/x/net/dns/dnsmessage refuses (golang/go#56246).
// Names are followed through compression on read, at most urMdnsPointerMaxCount pointers, and written whole.
//
// Records of the types DNS-SD uses are read into their fields; any other type keeps its rdata as it came. Nothing here
// logs: names and TXT are a LAN's words (I-13).

package main

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
)

// DNS's and mDNS's identifiers (RFC 1035, RFC 3596, RFC 2782, RFC 6762).
const (
	urMdnsTypeA    = 1
	urMdnsTypePtr  = 12
	urMdnsTypeTxt  = 16
	urMdnsTypeAaaa = 28
	urMdnsTypeSrv  = 33
	urMdnsTypeNsec = 47
	urMdnsTypeAny  = 255
	urMdnsClassIn  = 1
	// the top bit of a question's class asks a unicast answer (QU), and of a record's class flushes caches
	urMdnsClassTopBit     = 0x8000
	urMdnsHeaderByteCount = 12
	// DNS's bounds on a name: 63 octets a label, 255 the whole on the wire (RFC 1035 §2.3.4)
	urMdnsLabelMaxByteCount = 63
	urMdnsNameMaxByteCount  = 255
	// the most compression pointers one name follows, past any honest message's
	urMdnsPointerMaxCount = 16
)

// mDNS's group and port (RFC 6762 §3): identifiers.
var urMdnsGroup = netip.AddrPortFrom(netip.AddrFrom4([4]byte{224, 0, 0, 251}), 5353)

// A message that does not read as DNS.
var errUrMdnsMalformed = errors.New("mdns: malformed message")

// A name as its labels' raw octets, without the root's empty label.
type urMdnsName []string

// A name from labels, each split no further.
func urMdnsNameOf(labels ...string) urMdnsName {
	return urMdnsName(labels)
}

// A name from dotted text with no escapes: for the fixed parts of DNS-SD's names, "_services._dns-sd._udp.local".
func urMdnsNameParse(text string) urMdnsName {
	text = strings.TrimSuffix(text, ".")
	if text == "" {
		return urMdnsName{}
	}
	return urMdnsName(strings.Split(text, "."))
}

// The name with more labels after it.
func (self urMdnsName) append(labels ...string) urMdnsName {
	out := make(urMdnsName, 0, len(self)+len(labels))
	return append(append(out, self...), labels...)
}

// The key two names that DNS reads as one share: each label lowercased in ASCII and prefixed by its length, so a dot
// inside a label never reads as a separator.
func (self urMdnsName) key() string {
	var builder strings.Builder
	for _, label := range self {
		builder.WriteByte(byte(len(label)))
		builder.WriteString(urMdnsLower(label))
	}
	return builder.String()
}

// Whether two names are one, ASCII case aside (RFC 1035 §2.3.3).
func (self urMdnsName) equal(other urMdnsName) bool {
	if len(self) != len(other) {
		return false
	}
	for i := range self {
		if urMdnsLower(self[i]) != urMdnsLower(other[i]) {
			return false
		}
	}
	return true
}

// Whether the name ends with suffix's labels.
func (self urMdnsName) hasSuffix(suffix urMdnsName) bool {
	if len(self) < len(suffix) {
		return false
	}
	return self[len(self)-len(suffix):].equal(suffix)
}

// A label lowercased in ASCII alone, as DNS compares names.
func urMdnsLower(label string) string {
	out := []byte(label)
	for i, c := range out {
		if 'A' <= c && c <= 'Z' {
			out[i] = c + ('a' - 'A')
		}
	}
	return string(out)
}

// The name's bytes on the wire, or false where a label or the whole passes DNS's bounds or a label is empty.
func (self urMdnsName) wire() ([]byte, bool) {
	out := []byte{}
	for _, label := range self {
		if label == "" || urMdnsLabelMaxByteCount < len(label) {
			return nil, false
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	return out, len(out) <= urMdnsNameMaxByteCount
}

// One question.
type urMdnsQuestion struct {
	name  urMdnsName
	qtype uint16
	// the QU bit: the asker takes a unicast answer (RFC 6762 §5.4)
	unicast bool
}

// One resource record: the fields of its type's rdata, or its rdata as it came for another type.
type urMdnsRecord struct {
	name       urMdnsName
	rrtype     uint16
	cacheFlush bool
	ttl        uint32
	// PTR's target, or SRV's with its priority, weight and port
	target   urMdnsName
	priority uint16
	weight   uint16
	port     uint16
	// TXT's rdata, whole character-strings
	txt []byte
	// A's or AAAA's
	address netip.Addr
	// any other type's rdata
	data []byte
}

// One message.
type urMdnsMessage struct {
	id            uint16
	response      bool
	authoritative bool
	truncated     bool
	questions     []urMdnsQuestion
	answers       []urMdnsRecord
	authorities   []urMdnsRecord
	additionals   []urMdnsRecord
}

// Reads a name at off in message, following compression, and answers it and the offset past it where it began.
func urMdnsReadName(message []byte, off int) (urMdnsName, int, error) {
	name := urMdnsName{}
	byteCount := 1
	end := -1
	for pointers := 0; ; {
		if len(message) <= off {
			return nil, 0, errUrMdnsMalformed
		}
		length := int(message[off])
		switch length & 0xC0 {
		case 0x00:
			if length == 0 {
				if end < 0 {
					end = off + 1
				}
				return name, end, nil
			}
			if len(message) < off+1+length {
				return nil, 0, errUrMdnsMalformed
			}
			byteCount += 1 + length
			if urMdnsNameMaxByteCount < byteCount {
				return nil, 0, errUrMdnsMalformed
			}
			name = append(name, string(message[off+1:off+1+length]))
			off += 1 + length
		case 0xC0:
			if len(message) < off+2 {
				return nil, 0, errUrMdnsMalformed
			}
			pointers += 1
			if urMdnsPointerMaxCount < pointers {
				return nil, 0, errUrMdnsMalformed
			}
			if end < 0 {
				end = off + 2
			}
			off = int(binary.BigEndian.Uint16(message[off:off+2]) & 0x3FFF)
		default:
			return nil, 0, errUrMdnsMalformed
		}
	}
}

// Reads one record at off, answering it and the offset past it.
func urMdnsReadRecord(message []byte, off int) (urMdnsRecord, int, error) {
	record := urMdnsRecord{}
	name, off, err := urMdnsReadName(message, off)
	if err != nil {
		return record, 0, err
	}
	if len(message) < off+10 {
		return record, 0, errUrMdnsMalformed
	}
	record.name = name
	record.rrtype = binary.BigEndian.Uint16(message[off : off+2])
	class := binary.BigEndian.Uint16(message[off+2 : off+4])
	record.cacheFlush = class&urMdnsClassTopBit != 0
	record.ttl = binary.BigEndian.Uint32(message[off+4 : off+8])
	length := int(binary.BigEndian.Uint16(message[off+8 : off+10]))
	off += 10
	if len(message) < off+length {
		return record, 0, errUrMdnsMalformed
	}
	rdata := message[off : off+length]
	switch record.rrtype {
	case urMdnsTypePtr:
		record.target, _, err = urMdnsReadName(message, off)
	case urMdnsTypeSrv:
		if length < 7 {
			return record, 0, errUrMdnsMalformed
		}
		record.priority = binary.BigEndian.Uint16(rdata[0:2])
		record.weight = binary.BigEndian.Uint16(rdata[2:4])
		record.port = binary.BigEndian.Uint16(rdata[4:6])
		record.target, _, err = urMdnsReadName(message, off+6)
	case urMdnsTypeTxt:
		record.txt = append([]byte{}, rdata...)
	case urMdnsTypeA:
		if length != 4 {
			return record, 0, errUrMdnsMalformed
		}
		record.address = netip.AddrFrom4([4]byte(rdata))
	case urMdnsTypeAaaa:
		if length != 16 {
			return record, 0, errUrMdnsMalformed
		}
		record.address = netip.AddrFrom16([16]byte(rdata))
	default:
		record.data = append([]byte{}, rdata...)
	}
	if err != nil {
		return record, 0, err
	}
	return record, off + length, nil
}

// Reads a message.
func parseUrMdnsMessage(message []byte) (*urMdnsMessage, error) {
	if len(message) < urMdnsHeaderByteCount {
		return nil, errUrMdnsMalformed
	}
	flags := binary.BigEndian.Uint16(message[2:4])
	parsed := &urMdnsMessage{
		id:            binary.BigEndian.Uint16(message[0:2]),
		response:      flags&0x8000 != 0,
		authoritative: flags&0x0400 != 0,
		truncated:     flags&0x0200 != 0,
	}
	counts := [4]int{}
	for i := range counts {
		counts[i] = int(binary.BigEndian.Uint16(message[4+2*i : 6+2*i]))
	}
	off := urMdnsHeaderByteCount
	for range counts[0] {
		name, next, err := urMdnsReadName(message, off)
		if err != nil || len(message) < next+4 {
			return nil, errUrMdnsMalformed
		}
		class := binary.BigEndian.Uint16(message[next+2 : next+4])
		parsed.questions = append(parsed.questions, urMdnsQuestion{
			name:    name,
			qtype:   binary.BigEndian.Uint16(message[next : next+2]),
			unicast: class&urMdnsClassTopBit != 0,
		})
		off = next + 4
	}
	sections := []*[]urMdnsRecord{&parsed.answers, &parsed.authorities, &parsed.additionals}
	for i, section := range sections {
		for range counts[i+1] {
			record, next, err := urMdnsReadRecord(message, off)
			if err != nil {
				return nil, err
			}
			*section = append(*section, record)
			off = next
		}
	}
	return parsed, nil
}

// The record's rdata on the wire, or false where a name in it passes DNS's bounds.
func (self *urMdnsRecord) rdata() ([]byte, bool) {
	switch self.rrtype {
	case urMdnsTypePtr:
		return self.target.wire()
	case urMdnsTypeSrv:
		target, ok := self.target.wire()
		if !ok {
			return nil, false
		}
		out := make([]byte, 6, 6+len(target))
		binary.BigEndian.PutUint16(out[0:2], self.priority)
		binary.BigEndian.PutUint16(out[2:4], self.weight)
		binary.BigEndian.PutUint16(out[4:6], self.port)
		return append(out, target...), true
	case urMdnsTypeTxt:
		if len(self.txt) == 0 {
			// one empty string (RFC 6763 §6.1)
			return []byte{0}, true
		}
		return self.txt, true
	case urMdnsTypeA:
		if !self.address.Is4() {
			return nil, false
		}
		octets := self.address.As4()
		return octets[:], true
	case urMdnsTypeAaaa:
		if !self.address.Is6() || self.address.Is4In6() {
			return nil, false
		}
		octets := self.address.As16()
		return octets[:], true
	}
	return self.data, true
}

// The record on the wire, or false where it cannot be written.
func (self *urMdnsRecord) wire() ([]byte, bool) {
	name, ok := self.name.wire()
	if !ok {
		return nil, false
	}
	rdata, ok := self.rdata()
	if !ok || 0xFFFF < len(rdata) {
		return nil, false
	}
	out := make([]byte, 0, len(name)+10+len(rdata))
	out = append(out, name...)
	class := uint16(urMdnsClassIn)
	if self.cacheFlush {
		class |= urMdnsClassTopBit
	}
	var fixed [10]byte
	binary.BigEndian.PutUint16(fixed[0:2], self.rrtype)
	binary.BigEndian.PutUint16(fixed[2:4], class)
	binary.BigEndian.PutUint32(fixed[4:8], self.ttl)
	binary.BigEndian.PutUint16(fixed[8:10], uint16(len(rdata)))
	out = append(out, fixed[:]...)
	return append(out, rdata...), true
}

// The question on the wire, or false where its name cannot be written.
func (self *urMdnsQuestion) wire() ([]byte, bool) {
	name, ok := self.name.wire()
	if !ok {
		return nil, false
	}
	class := uint16(urMdnsClassIn)
	if self.unicast {
		class |= urMdnsClassTopBit
	}
	var fixed [4]byte
	binary.BigEndian.PutUint16(fixed[0:2], self.qtype)
	binary.BigEndian.PutUint16(fixed[2:4], class)
	return append(name, fixed[:]...), true
}

// Writes the message into one or more messages of at most byteCount bytes, each with the header's id and flags and
// every question, the answers, authorities and additionals spread across them in order (each mDNS response stands
// alone, RFC 6762 §6). A record that cannot be written, or that passes byteCount on its own, is left out. Answers no
// message where the questions alone pass byteCount, and none for records all left out.
func (self *urMdnsMessage) pack(byteCount int) [][]byte {
	header := make([]byte, urMdnsHeaderByteCount)
	binary.BigEndian.PutUint16(header[0:2], self.id)
	var flags uint16
	if self.response {
		flags |= 0x8000
	}
	if self.authoritative {
		flags |= 0x0400
	}
	binary.BigEndian.PutUint16(header[2:4], flags)
	questions := [][]byte{}
	for i := range self.questions {
		if wire, ok := self.questions[i].wire(); ok {
			header = append(header, wire...)
			questions = append(questions, wire)
		}
	}
	binary.BigEndian.PutUint16(header[4:6], uint16(len(questions)))
	if byteCount < len(header) {
		return nil
	}
	type sectioned struct {
		section int
		wire    []byte
	}
	records := []sectioned{}
	for section, list := range [][]urMdnsRecord{self.answers, self.authorities, self.additionals} {
		for i := range list {
			if wire, ok := list[i].wire(); ok && len(header)+len(wire) <= byteCount {
				records = append(records, sectioned{section: section, wire: wire})
			}
		}
	}
	if len(records) == 0 {
		if len(self.answers)+len(self.authorities)+len(self.additionals) == 0 {
			return [][]byte{header}
		}
		return nil
	}
	messages := [][]byte{}
	for at := 0; at < len(records); {
		message := append([]byte{}, header...)
		counts := [3]int{}
		for at < len(records) && len(message)+len(records[at].wire) <= byteCount {
			message = append(message, records[at].wire...)
			counts[records[at].section] += 1
			at += 1
		}
		binary.BigEndian.PutUint16(message[6:8], uint16(counts[0]))
		binary.BigEndian.PutUint16(message[8:10], uint16(counts[1]))
		binary.BigEndian.PutUint16(message[10:12], uint16(counts[2]))
		messages = append(messages, message)
	}
	return messages
}
