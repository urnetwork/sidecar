// §12.9.1's DNS-SD names (owner decision 778, D-DNS-12): what a device answers in each zone of its state's name_zones
// from the instances its discovery view holds, which §17.7.1's watches fill on the sidecar role's side and the
// composition root hands the bridge (Bridge.SetDiscoveryView). The device never forwards a query for one of these
// names, so no browse or resolve reaches an upstream resolver or the dns edge:
//
//	b._dns-sd._udp, db._dns-sd._udp                     PTR the zone: the browse domain RFC 6763 §11 enumerates
//	lb._dns-sd._udp, r._dns-sd._udp, dr._dns-sd._udp    NODATA: no automatic browse domain and no registration
//	_services._dns-sd._udp                              PTR each service type in the view (RFC 6763 §9)
//	_<service>._tcp, _<service>._udp, <sub>._sub.<type> PTR each instance of the type or subtype
//	<instance>.<type>                                   SRV 0 0 <port> <target>; TXT the instance's
//	<label>.<client-name>                               A the address the view holds; NODATA for AAAA and the rest
//	another name of these forms                         NXDOMAIN, or NODATA where the name exists
//	every answer and denial                             TTL DiscoveryTtl, 10 s, RFC 8766 §5.5.1's cap
//
// The block's reverse zone answers here too: b and db under the name RFC 6763 §11 derives from the block, PTR the
// zones; an assigned address's PTR, its private name; every other name there NXDOMAIN, or NODATA where it exists.
//
// "These forms" are the names §12.7 refuses to user records: `_dns-sd._udp` and every owner below it, a
// `_<service>._tcp` or `_udp` pair directly under the zone and every owner below it, and, for the targets, a label
// below a client name of the table, which the compiler keeps only where no published host shares it (BRIDGE-M4-16).
// On app paths C14's LocalZone carries addresses alone, so BridgeZone owns the same names and answers each NODATA
// (bridge_zone.go): no DNS-SD query leaves an app's tunnel either.
//
// Names are compared folding ASCII case only, as DNS does (RFC 4343); an instance's name is one label of UTF-8, which
// may hold a dot, so answers are built from labels, never from a dotted string. The view and its answers name nothing
// in a log (I-13). A view is immutable once built; the bridge swaps it whole.

package device

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// DNS's numbers (RFC 1035, RFC 2782, RFC 3596, RFC 6891) the DNS-SD answers read and write, beside bridge_resolver.go's.
const (
	bridgeDnsTypeSoa  = 6
	bridgeDnsTypePtr  = 12
	bridgeDnsTypeTxt  = 16
	bridgeDnsTypeAaaa = 28
	bridgeDnsTypeSrv  = 33
	bridgeDnsTypeOpt  = 41
	// a name that does not exist
	bridgeDnsCodeNameError = 3
	// the header's truncation flag
	bridgeDnsFlagTruncated = 0x0200
)

// The labels of the names §12.9.1 owns.
const (
	bridgeDnsSdLabel         = "_dns-sd"
	bridgeDnsSdUdpLabel      = "_udp"
	bridgeDnsSdTcpLabel      = "_tcp"
	bridgeDnsSdSubLabel      = "_sub"
	bridgeDnsSdServicesLabel = "_services"
	bridgeDnsReverseSuffix   = "in-addr.arpa"
)

// One instance a viewer keeps, as the resolver answers it. Every field is its host's word, held to the view's shape and
// never trusted (§17.7.1).
type BridgeDiscoveryInstance struct {
	// One label of UTF-8, at most 63 octets, with no control character.
	Name string
	// `_<service>._tcp` or `_<service>._udp`, lowercase.
	Service string
	// Each one label, no dot.
	Subtypes []string
	Port     uint16
	// The TXT record's rdata, whole character-strings; empty is one empty string (RFC 6763 §6.1).
	Txt []byte
	// The target <HostLabel>.<ClientName> under the zone: the device's own host label under its host's client name.
	HostLabel  string
	ClientName string
	// Where this device reaches the instance.
	Ipv4 netip.Addr
}

// A viewer's discovery view as the resolver reads it: its instances, indexed. Immutable once built.
type BridgeDiscoveryView struct {
	instances []*BridgeDiscoveryInstance
	// the service types in view, lowercase, sorted
	types []string
	// instance indexes by type, by subtype and type, and by name and type, each folded
	byType     map[string][]int
	bySubtype  map[[2]string][]int
	byInstance map[[2]string]int
	// each target, its label and client name folded, to its address
	targets map[[2]string]netip.Addr
}

// A view of instances, nil or none for an empty one, with each instance not of the view's shape left out and counted:
// at most DiscoveryInstanceCount, the rest left out. Where two instances share a name and type, or two targets an
// address, the first kept stands. Nil settings are DefaultBridgeSettings.
func NewBridgeDiscoveryView(instances []*BridgeDiscoveryInstance, settings *BridgeSettings) (*BridgeDiscoveryView, int) {
	if settings == nil {
		settings = DefaultBridgeSettings()
	}
	self := &BridgeDiscoveryView{
		byType:     map[string][]int{},
		bySubtype:  map[[2]string][]int{},
		byInstance: map[[2]string]int{},
		targets:    map[[2]string]netip.Addr{},
	}
	droppedCount := 0
	for _, instance := range instances {
		if settings.DiscoveryInstanceCount <= len(self.instances) || !bridgeDiscoveryInstanceShaped(instance) {
			droppedCount += 1
			continue
		}
		service := bridgeDnsFold(instance.Service)
		target := [2]string{bridgeDnsFold(instance.HostLabel), bridgeDnsFold(instance.ClientName)}
		if held, found := self.targets[target]; found && held != instance.Ipv4.Unmap() {
			droppedCount += 1
			continue
		}
		key := [2]string{bridgeDnsFold(instance.Name), service}
		if _, found := self.byInstance[key]; found {
			droppedCount += 1
			continue
		}
		index := len(self.instances)
		kept := *instance
		kept.Service = service
		kept.Ipv4 = instance.Ipv4.Unmap()
		self.instances = append(self.instances, &kept)
		self.byInstance[key] = index
		self.targets[target] = kept.Ipv4
		if _, found := self.byType[service]; !found {
			self.types = append(self.types, service)
		}
		self.byType[service] = append(self.byType[service], index)
		for _, subtype := range kept.Subtypes {
			subtypeKey := [2]string{bridgeDnsFold(subtype), service}
			if !slices.Contains(self.bySubtype[subtypeKey], index) {
				self.bySubtype[subtypeKey] = append(self.bySubtype[subtypeKey], index)
			}
		}
	}
	slices.Sort(self.types)
	return self, droppedCount
}

// How many instances the view holds.
func (self *BridgeDiscoveryView) InstanceCount() int {
	if self == nil {
		return 0
	}
	return len(self.instances)
}

// Whether instance has the view's shape: see BridgeDiscoveryInstance's fields.
func bridgeDiscoveryInstanceShaped(instance *BridgeDiscoveryInstance) bool {
	if instance == nil || instance.Port == 0 || !instance.Ipv4.Unmap().Is4() {
		return false
	}
	if instance.Name == "" || bridgeDnsLabelMaxCount < len(instance.Name) || !utf8.ValidString(instance.Name) {
		return false
	}
	for _, r := range instance.Name {
		if r < 0x20 || r == 0x7F {
			return false
		}
	}
	serviceLabel, transport, found := strings.Cut(bridgeDnsFold(instance.Service), ".")
	if !found || (transport != bridgeDnsSdTcpLabel && transport != bridgeDnsSdUdpLabel) ||
		!strings.HasPrefix(serviceLabel, "_") || !bridgeDnsLdhLabel(serviceLabel[1:]) {
		return false
	}
	for _, subtype := range instance.Subtypes {
		if subtype == "" || bridgeDnsLabelMaxCount < len(subtype) || strings.ContainsAny(subtype, ".\\") {
			return false
		}
	}
	if !bridgeDnsLdhLabel(instance.HostLabel) || !bridgeDnsLdhLabel(instance.ClientName) {
		return false
	}
	for at := 0; at < len(instance.Txt); {
		at += 1 + int(instance.Txt[at])
		if len(instance.Txt) < at {
			return false
		}
	}
	return true
}

// Whether label is an LDH label: letters, digits and hyphens, 1 to 63, no hyphen at either end.
func bridgeDnsLdhLabel(label string) bool {
	if label == "" || bridgeDnsLabelMaxCount < len(label) || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i += 1 {
		c := label[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// text with its ASCII letters lowercased, as DNS compares names (RFC 4343); every other byte as it is.
func bridgeDnsFold(text string) string {
	for i := 0; i < len(text); i += 1 {
		if 'A' <= text[i] && text[i] <= 'Z' {
			folded := []byte(text)
			for j := i; j < len(folded); j += 1 {
				if 'A' <= folded[j] && folded[j] <= 'Z' {
					folded[j] += 'a' - 'A'
				}
			}
			return string(folded)
		}
	}
	return text
}

// Hands the resolver a new discovery view, nil for none, which answers every DNS-SD name as a view with no instance
// does. Takes effect at the next query. Answers how many instances were left out (NewBridgeDiscoveryView).
func (self *Bridge) SetDiscoveryView(instances []*BridgeDiscoveryInstance) int {
	view, droppedCount := NewBridgeDiscoveryView(instances, self.settings)
	self.discovery.Store(view)
	return droppedCount
}

// The view the resolver answers from now, nil before SetDiscoveryView.
func (self *Bridge) DiscoveryView() *BridgeDiscoveryView {
	return self.discovery.Load()
}

// One record of an answer: its owner's labels, type, and rdata, whose names are written whole, never compressed.
type bridgeDnsRecord struct {
	owner  []string
	rrtype uint16
	rdata  []byte
}

// What a DNS-SD name gets: an rcode, whether the name is the device's at all, its answers and its additionals.
type bridgeDnsSdAnswer struct {
	owned       bool
	rcode       uint16
	answers     []bridgeDnsRecord
	additionals []bridgeDnsRecord
	// the zone, for a denial's SOA (RFC 2308)
	zone []string
}

// Whether the zone, folded with no trailing dot, holds name's labels below its own, and those labels, leftmost first.
func bridgeDnsRelative(labels []string, zone []string) ([]string, bool) {
	if len(labels) <= len(zone) {
		return nil, false
	}
	at := len(labels) - len(zone)
	for i, label := range zone {
		if bridgeDnsFold(labels[at+i]) != label {
			return nil, false
		}
	}
	return labels[:at], true
}

// Whether a name's labels relative to a zone, leftmost first, are of §12.9.1's forms: at or below _dns-sd._udp, at or
// below a _<service>._tcp or _udp pair, or below a client name the zone's names hold.
func bridgeDnsSdForm(relative []string, clientName func(name string) bool) bool {
	count := len(relative)
	if 2 <= count {
		last, transport := bridgeDnsFold(relative[count-2]), bridgeDnsFold(relative[count-1])
		if last == bridgeDnsSdLabel && transport == bridgeDnsSdUdpLabel {
			return true
		}
		if (transport == bridgeDnsSdTcpLabel || transport == bridgeDnsSdUdpLabel) && strings.HasPrefix(last, "_") &&
			bridgeDnsLdhLabel(last[1:]) {
			return true
		}
		if clientName != nil && clientName(bridgeDnsFold(relative[count-1])) {
			return true
		}
	}
	return false
}

// The answer to a query of qtype for relative, a name's labels below zone, by the file's forward table; owned false for
// a name of none of its forms. view may be nil, which answers as a view with no instance.
func (self *BridgeDiscoveryView) answer(relative []string, zone []string, qtype uint16, clientName func(name string) bool) bridgeDnsSdAnswer {
	answer := bridgeDnsSdAnswer{zone: zone}
	if !bridgeDnsSdForm(relative, clientName) {
		return answer
	}
	answer.owned = true
	view := self
	if view == nil {
		view = &BridgeDiscoveryView{}
	}
	folded := make([]string, len(relative))
	for i, label := range relative {
		folded[i] = bridgeDnsFold(label)
	}
	count := len(folded)
	owner := func() []string {
		return slices.Concat(relative, zone)
	}
	matches := func(rrtype uint16) bool {
		return qtype == rrtype || qtype == bridgeDnsTypeAny
	}
	exists := func(found bool) {
		if !found {
			answer.rcode = bridgeDnsCodeNameError
		}
	}
	// below _dns-sd._udp
	if folded[count-2] == bridgeDnsSdLabel && folded[count-1] == bridgeDnsSdUdpLabel {
		switch {
		case count == 2:
			// _dns-sd._udp itself, an empty non-terminal
		case count == 3 && (folded[0] == "b" || folded[0] == "db"):
			if matches(bridgeDnsTypePtr) {
				answer.answers = append(answer.answers, bridgeDnsRecord{owner: owner(), rrtype: bridgeDnsTypePtr, rdata: bridgeDnsName(zone)})
			}
		case count == 3 && (folded[0] == "lb" || folded[0] == "r" || folded[0] == "dr"):
			// NODATA: no automatic browse domain, no registration
		case count == 3 && folded[0] == bridgeDnsSdServicesLabel:
			if matches(bridgeDnsTypePtr) {
				for _, service := range view.types {
					labels := slices.Concat(strings.Split(service, "."), zone)
					answer.answers = append(answer.answers, bridgeDnsRecord{owner: owner(), rrtype: bridgeDnsTypePtr, rdata: bridgeDnsName(labels)})
				}
			}
		default:
			exists(false)
		}
		return answer
	}
	// below a service type
	if folded[count-1] == bridgeDnsSdTcpLabel || folded[count-1] == bridgeDnsSdUdpLabel {
		service := folded[count-2] + "." + folded[count-1]
		typeLabels := relative[count-2:]
		instances, found := view.byType[service]
		switch {
		case count == 2:
			exists(found)
			if found && matches(bridgeDnsTypePtr) {
				for _, index := range instances {
					view.pointer(&answer, owner(), view.instances[index], typeLabels, zone)
				}
			}
		case count == 3 && folded[0] == bridgeDnsSdSubLabel:
			// <type>'s _sub, an empty non-terminal where any subtype stands
			subtypeFound := false
			for key := range view.bySubtype {
				if key[1] == service {
					subtypeFound = true
					break
				}
			}
			exists(subtypeFound)
		case count == 4 && folded[1] == bridgeDnsSdSubLabel:
			subtyped, subtypeFound := view.bySubtype[[2]string{folded[0], service}]
			exists(subtypeFound)
			if subtypeFound && matches(bridgeDnsTypePtr) {
				for _, index := range subtyped {
					view.pointer(&answer, owner(), view.instances[index], typeLabels, zone)
				}
			}
		case count == 3:
			index, instanceFound := view.byInstance[[2]string{folded[0], service}]
			exists(instanceFound)
			if instanceFound {
				instance := view.instances[index]
				target := slices.Concat([]string{instance.HostLabel, instance.ClientName}, zone)
				if matches(bridgeDnsTypeSrv) {
					answer.answers = append(answer.answers, bridgeDnsRecord{owner: owner(), rrtype: bridgeDnsTypeSrv, rdata: bridgeDnsSrv(instance.Port, target)})
				}
				if matches(bridgeDnsTypeTxt) {
					answer.answers = append(answer.answers, bridgeDnsRecord{owner: owner(), rrtype: bridgeDnsTypeTxt, rdata: bridgeDnsTxt(instance.Txt)})
				}
				if matches(bridgeDnsTypeSrv) {
					answer.additionals = append(answer.additionals, bridgeDnsRecord{owner: target, rrtype: bridgeDnsTypeA, rdata: bridgeDnsA(instance.Ipv4)})
				}
			}
		default:
			exists(false)
		}
		return answer
	}
	// a target below a client name: its own label alone is a name, and anything deeper, or another label, is none
	var address netip.Addr
	found := false
	if count == 2 {
		address, found = view.targets[[2]string{folded[0], folded[1]}]
	}
	if !found {
		exists(false)
		return answer
	}
	if matches(bridgeDnsTypeA) {
		answer.answers = append(answer.answers, bridgeDnsRecord{owner: owner(), rrtype: bridgeDnsTypeA, rdata: bridgeDnsA(address)})
	}
	return answer
}

// A PTR from owner to instance under typeLabels and zone, with its SRV, TXT and A as additionals (RFC 6763 §12.1).
func (self *BridgeDiscoveryView) pointer(answer *bridgeDnsSdAnswer, owner []string, instance *BridgeDiscoveryInstance, typeLabels []string, zone []string) {
	instanceName := slices.Concat([]string{instance.Name}, typeLabels, zone)
	target := slices.Concat([]string{instance.HostLabel, instance.ClientName}, zone)
	answer.answers = append(answer.answers, bridgeDnsRecord{owner: owner, rrtype: bridgeDnsTypePtr, rdata: bridgeDnsName(instanceName)})
	answer.additionals = append(answer.additionals,
		bridgeDnsRecord{owner: instanceName, rrtype: bridgeDnsTypeSrv, rdata: bridgeDnsSrv(instance.Port, target)},
		bridgeDnsRecord{owner: instanceName, rrtype: bridgeDnsTypeTxt, rdata: bridgeDnsTxt(instance.Txt)},
		bridgeDnsRecord{owner: target, rrtype: bridgeDnsTypeA, rdata: bridgeDnsA(instance.Ipv4)},
	)
}

// The answer to a query of qtype for labels in a block's reverse zone (the file's reverse row); owned false for a name
// in none. blocks are the state's blocks, zones the name zones' labels, names each assigned address's private name.
func bridgeDnsReverseAnswer(labels []string, qtype uint16, blocks []netip.Prefix, zones [][]string, names map[netip.Addr]string) bridgeDnsSdAnswer {
	answer := bridgeDnsSdAnswer{}
	matches := func(rrtype uint16) bool {
		return qtype == rrtype || qtype == bridgeDnsTypeAny
	}
	for _, block := range blocks {
		reverse := bridgeDnsReverseZone(block)
		if bridgeDnsLabelsEqual(labels, reverse) {
			// the reverse zone's own apex: it exists, and holds nothing of these forms
			answer.owned = true
			answer.zone = reverse
			return answer
		}
		relative, found := bridgeDnsRelative(labels, reverse)
		if !found {
			continue
		}
		answer.owned = true
		answer.zone = reverse
		folded := make([]string, len(relative))
		for i, label := range relative {
			folded[i] = bridgeDnsFold(label)
		}
		octets := block.Addr().As4()
		// the name RFC 6763 §11 derives from the block's address and mask, relative to the reverse zone
		derived := []string{strconv.Itoa(int(octets[3])), strconv.Itoa(int(octets[2]))}
		switch {
		case len(folded) == 5 && (folded[0] == "b" || folded[0] == "db") && folded[1] == bridgeDnsSdLabel &&
			folded[2] == bridgeDnsSdUdpLabel && folded[3] == derived[0] && folded[4] == derived[1]:
			if matches(bridgeDnsTypePtr) {
				for _, zone := range zones {
					answer.answers = append(answer.answers, bridgeDnsRecord{owner: slices.Concat(relative, reverse), rrtype: bridgeDnsTypePtr, rdata: bridgeDnsName(zone)})
				}
			}
		case len(folded) == 2:
			// an address of the block: its PTR where assigned
			first, firstErr := strconv.Atoi(folded[1])
			second, secondErr := strconv.Atoi(folded[0])
			if firstErr != nil || secondErr != nil || first < 0 || 255 < first || second < 0 || 255 < second ||
				folded[1] != strconv.Itoa(first) || folded[0] != strconv.Itoa(second) {
				answer.rcode = bridgeDnsCodeNameError
				break
			}
			address := netip.AddrFrom4([4]byte{octets[0], octets[1], byte(first), byte(second)})
			name, assigned := names[address]
			if !assigned || len(zones) == 0 {
				// the derived name's own labels exist above b and db
				if !(folded[0] == derived[0] && folded[1] == derived[1]) {
					answer.rcode = bridgeDnsCodeNameError
				}
				break
			}
			if matches(bridgeDnsTypePtr) {
				answer.answers = append(answer.answers, bridgeDnsRecord{owner: slices.Concat(relative, reverse), rrtype: bridgeDnsTypePtr, rdata: bridgeDnsName(slices.Concat([]string{name}, zones[0]))})
			}
		case len(folded) == 1 && folded[0] == derived[1],
			len(folded) == 3 && folded[0] == bridgeDnsSdUdpLabel && folded[1] == derived[0] && folded[2] == derived[1],
			len(folded) == 4 && folded[0] == bridgeDnsSdLabel && folded[1] == bridgeDnsSdUdpLabel && folded[2] == derived[0] && folded[3] == derived[1]:
			// the empty non-terminals above b and db
		case len(folded) == 1:
			// a third octet the block holds: an empty non-terminal over its addresses
			value, err := strconv.Atoi(folded[0])
			if err != nil || value < 0 || 255 < value || folded[0] != strconv.Itoa(value) {
				answer.rcode = bridgeDnsCodeNameError
			}
		default:
			answer.rcode = bridgeDnsCodeNameError
		}
		return answer
	}
	return answer
}

// A /16 or narrower block's reverse zone's labels, leftmost first: its address's significant whole octets reversed
// under in-addr.arpa. A block's length is a multiple of 8 between 8 and 24 in practice; a length between rounds down to
// the octet that holds it.
func bridgeDnsReverseZone(block netip.Prefix) []string {
	octets := block.Masked().Addr().As4()
	count := max(1, min(3, block.Bits()/8))
	labels := []string{}
	for i := count - 1; 0 <= i; i -= 1 {
		labels = append(labels, strconv.Itoa(int(octets[i])))
	}
	return append(labels, "in-addr", "arpa")
}

// Whether two names' labels are equal, folding ASCII case, the second already folded.
func bridgeDnsLabelsEqual(labels []string, folded []string) bool {
	if len(labels) != len(folded) {
		return false
	}
	for i, label := range labels {
		if bridgeDnsFold(label) != folded[i] {
			return false
		}
	}
	return true
}

// A name's labels in wire form, uncompressed, with its root label.
func bridgeDnsName(labels []string) []byte {
	name := []byte{}
	for _, label := range labels {
		name = append(name, byte(len(label)))
		name = append(name, label...)
	}
	return append(name, 0)
}

// An A record's rdata.
func bridgeDnsA(address netip.Addr) []byte {
	octets := address.Unmap().As4()
	return octets[:]
}

// An SRV record's rdata: priority 0, weight 0, port and target (RFC 2782).
func bridgeDnsSrv(port uint16, target []string) []byte {
	rdata := make([]byte, 6, 6+64)
	binary.BigEndian.PutUint16(rdata[4:6], port)
	return append(rdata, bridgeDnsName(target)...)
}

// A TXT record's rdata: txt as it is, or one empty string for none (RFC 6763 §6.1).
func bridgeDnsTxt(txt []byte) []byte {
	if len(txt) == 0 {
		return []byte{0}
	}
	return txt
}

// A record's wire form at ttl.
func (self bridgeDnsRecord) appendTo(message []byte, ttl uint32) []byte {
	message = append(message, bridgeDnsName(self.owner)...)
	var fixed [10]byte
	binary.BigEndian.PutUint16(fixed[0:2], self.rrtype)
	binary.BigEndian.PutUint16(fixed[2:4], bridgeDnsClassIn)
	binary.BigEndian.PutUint32(fixed[4:8], ttl)
	binary.BigEndian.PutUint16(fixed[8:10], uint16(len(self.rdata)))
	message = append(message, fixed[:]...)
	return append(message, self.rdata...)
}

// The SOA a denial carries in its authority section, so a resolver caches the denial for ttl alone (RFC 2308 §3): the
// zone's, every interval ttl, its serial 1, since the device keeps no zone file.
func bridgeDnsSoa(zone []string, ttl uint32) bridgeDnsRecord {
	rdata := slices.Concat(bridgeDnsName(zone), bridgeDnsName(zone))
	var fields [20]byte
	binary.BigEndian.PutUint32(fields[0:4], 1)
	for i := 1; i < 5; i += 1 {
		binary.BigEndian.PutUint32(fields[i*4:i*4+4], ttl)
	}
	return bridgeDnsRecord{owner: zone, rrtype: bridgeDnsTypeSoa, rdata: append(rdata, fields[:]...)}
}

// The response to query from answer, every record at ttl: authoritative, with the answers, the additionals while the
// whole fits in maxByteCount, and the zone's SOA for a denial. Past maxByteCount with the answers alone it carries none
// and sets TC, so the asker comes again over TCP (RFC 1035 §4.2.1).
func buildBridgeDnsSdResponse(query bridgeDnsQuery, answer bridgeDnsSdAnswer, ttl uint32, maxByteCount int) []byte {
	build := func(answers []bridgeDnsRecord, additionals []bridgeDnsRecord, truncated bool) []byte {
		message := make([]byte, bridgeDnsHeaderByteCount, 512)
		flags := uint16(bridgeDnsFlagResponse|bridgeDnsFlagAuthority|bridgeDnsFlagAvailable) | answer.rcode
		if query.recursionDesired {
			flags |= bridgeDnsFlagRecursion
		}
		if truncated {
			flags |= bridgeDnsFlagTruncated
		}
		binary.BigEndian.PutUint16(message[0:2], query.id)
		binary.BigEndian.PutUint16(message[2:4], flags)
		binary.BigEndian.PutUint16(message[4:6], 1)
		message = append(message, query.question...)
		binary.BigEndian.PutUint16(message[6:8], uint16(len(answers)))
		for _, record := range answers {
			message = record.appendTo(message, ttl)
		}
		if len(answers) == 0 && 0 < len(answer.zone) && !truncated {
			binary.BigEndian.PutUint16(message[8:10], 1)
			message = bridgeDnsSoa(answer.zone, ttl).appendTo(message, ttl)
		}
		binary.BigEndian.PutUint16(message[10:12], uint16(len(additionals)))
		for _, record := range additionals {
			message = record.appendTo(message, ttl)
		}
		return message
	}
	message := build(answer.answers, answer.additionals, false)
	if len(message) <= maxByteCount {
		return message
	}
	if message = build(answer.answers, nil, false); len(message) <= maxByteCount {
		return message
	}
	return build(nil, nil, true)
}

// The labels of a query's name, as asked, read from its question; nil for a question that does not read.
func bridgeDnsQueryLabels(query bridgeDnsQuery) []string {
	labels := []string{}
	for at := 0; at < len(query.question); {
		count := int(query.question[at])
		at += 1
		if count == 0 {
			return labels
		}
		if bridgeDnsLabelMaxCount < count || len(query.question) < at+count {
			return nil
		}
		labels = append(labels, string(query.question[at:at+count]))
		at += count
	}
	return nil
}

// The largest UDP answer the asker takes: its EDNS0 OPT record's payload size within [the default, the cap], or the
// default without one (RFC 6891 §6.2.5). message is the whole query.
func bridgeDnsUdpByteCount(message []byte, query bridgeDnsQuery, settings *BridgeSettings) int {
	byteCount := settings.DiscoveryUdpByteCount
	if len(message) < bridgeDnsHeaderByteCount || binary.BigEndian.Uint16(message[10:12]) != 1 {
		return byteCount
	}
	at := bridgeDnsHeaderByteCount + len(query.question)
	// OPT's owner is the root, then its type and its class, the payload size
	if len(message) < at+11 || message[at] != 0 || binary.BigEndian.Uint16(message[at+1:at+3]) != bridgeDnsTypeOpt {
		return byteCount
	}
	payload := int(binary.BigEndian.Uint16(message[at+3 : at+5]))
	return max(byteCount, min(payload, settings.DiscoveryEdnsByteCount))
}

// The TTL every DNS-SD answer and denial carries, in seconds.
func bridgeDiscoveryTtl(settings *BridgeSettings) uint32 {
	return uint32(settings.DiscoveryTtl / time.Second)
}
