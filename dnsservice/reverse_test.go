package dnsservice_test

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/urnetwork/sidecar/dnsservice"
)

// Two sending addresses as smtpedge.yml lists them, with RFC 5737's documentation addresses and
// documentation names standing in for the lb addresses and o<k>.out.bringyour.com.
func reverseTestSendingAddresses() []dnsservice.DnsSendingAddress {
	return []dnsservice.DnsSendingAddress{
		{Address: netip.MustParseAddr("192.0.2.10"), Name: "o1.out.report.example"},
		{Address: netip.MustParseAddr("192.0.2.11"), Name: "o2.out.report.example."},
		// covered by no zone, so it has no PTR
		{Address: netip.MustParseAddr("198.51.100.20"), Name: "o3.out.report.example"},
	}
}

// Edge test settings with zones as reverse's zones and the sending addresses set as the host sets them,
// RRL raised past anything a test sends.
func reverseTestSettings(t testing.TB, zones ...dnsservice.DnsReverseZoneSettings) *dnsservice.DnsSettings {
	t.Helper()
	settings := edgeTestSettings(t)
	settings.Rrl.ResponsesPerSecond = 1000 * 1000
	settings.Reverse.Zones = zones
	if err := settings.SetSendingAddresses(reverseTestSendingAddresses()); err != nil {
		t.Fatal(err)
	}
	if err := settings.Validate(); err != nil {
		t.Fatal(err)
	}
	return settings
}

// HE's classless delegation of 192.0.2.0/26, in RFC 2317's own spelling.
var reverseTestClassless = dnsservice.DnsReverseZoneSettings{Zone: "0/26.2.0.192.in-addr.arpa.", Prefix: "192.0.2.0/26"}

// What zones answer for name and rrType, with DO as asked.
func reverseTestAnswer(t testing.TB, zones *dnsservice.ReverseZones, name string, rrType uint16, signed bool) *dns.Msg {
	t.Helper()
	reply := zones.Answer(&dnsservice.DnsQuery{Message: edgeTestQuery(name, rrType, signed)})
	if reply == nil {
		t.Fatalf("%s: no reply", name)
	}
	return reply
}

// A listed address's PTR answers its HELO name at its classless owner, TTL ptr; an address in the zone
// that smtpedge.yml does not list has none, and the zone's apex answers its SOA and NS.
func TestReverseZoneAnswersAListedAddressAndNoOther(t *testing.T) {
	settings := reverseTestSettings(t, reverseTestClassless)
	zones, err := dnsservice.NewReverseZones(settings)
	if err != nil {
		t.Fatal(err)
	}
	if got := zones.Zones(); !slices.Equal(got, []string{"0/26.2.0.192.in-addr.arpa."}) {
		t.Fatalf("zones %v", got)
	}

	reply := reverseTestAnswer(t, zones, "10.0/26.2.0.192.in-addr.arpa.", dns.TypePTR, false)
	if reply.Rcode != dns.RcodeSuccess || !reply.Authoritative || len(reply.Answer) != 1 {
		t.Fatalf("a listed address %v", reply)
	}
	ptr := reply.Answer[0].(*dns.PTR)
	if ptr.Ptr != "o1.out.report.example." || ptr.Hdr.Ttl != settings.Ttl.Ptr || ptr.Hdr.Name != "10.0/26.2.0.192.in-addr.arpa." {
		t.Errorf("ptr %v", ptr)
	}
	if owner, name, ok := zones.Pointer(netip.MustParseAddr("192.0.2.11")); !ok || owner != "11.0/26.2.0.192.in-addr.arpa." || name != "o2.out.report.example." {
		t.Errorf("192.0.2.11's pointer %s %s %t", owner, name, ok)
	}

	// in the zone and not listed: NXDOMAIN with the zone's SOA at the negative TTL
	reply = reverseTestAnswer(t, zones, "12.0/26.2.0.192.in-addr.arpa.", dns.TypePTR, false)
	if reply.Rcode != dns.RcodeNameError || len(reply.Answer) != 0 || len(reply.Ns) != 1 {
		t.Fatalf("an unlisted address %v", reply)
	}
	soa := reply.Ns[0].(*dns.SOA)
	if soa.Hdr.Name != "0/26.2.0.192.in-addr.arpa." || soa.Hdr.Ttl != settings.Ttl.SoaMinimum || soa.Ns != "ns1."+edgeTestRoot {
		t.Errorf("denial soa %v", soa)
	}
	if _, _, ok := zones.Pointer(netip.MustParseAddr("198.51.100.20")); ok {
		t.Error("an address no zone covers has a pointer")
	}

	// another type at a listed owner has no data; ANY answers the PTR
	reply = reverseTestAnswer(t, zones, "10.0/26.2.0.192.in-addr.arpa.", dns.TypeA, false)
	if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 0 || len(reply.Ns) != 1 {
		t.Errorf("A at a pointer %v", reply)
	}
	reply = reverseTestAnswer(t, zones, "10.0/26.2.0.192.in-addr.arpa.", dns.TypeANY, false)
	if len(reply.Answer) != 1 || reply.Answer[0].Header().Rrtype != dns.TypePTR {
		t.Errorf("ANY at a pointer %v", reply)
	}

	// the apex: SOA and NS
	reply = reverseTestAnswer(t, zones, "0/26.2.0.192.in-addr.arpa.", dns.TypeSOA, false)
	if len(reply.Answer) != 1 || reply.Answer[0].(*dns.SOA).Minttl != settings.Ttl.SoaMinimum {
		t.Errorf("apex SOA %v", reply)
	}
	reply = reverseTestAnswer(t, zones, "0/26.2.0.192.in-addr.arpa.", dns.TypeNS, false)
	nsNames := []string{}
	for _, record := range reply.Answer {
		nsNames = append(nsNames, record.(*dns.NS).Ns)
	}
	if !slices.Equal(nsNames, []string{"ns1." + edgeTestRoot, "ns2." + edgeTestRoot}) {
		t.Errorf("apex NS %v", nsNames)
	}

	// a name in no reverse zone is refused, as a name in no root is
	reply = reverseTestAnswer(t, zones, "10.3.0.192.in-addr.arpa.", dns.TypePTR, false)
	if reply.Rcode != dns.RcodeRefused {
		t.Errorf("outside every zone %v", reply)
	}
}

// RFC 2317's classless owner sits at the address's last octet below the delegated zone; an octet
// boundary's zone holds each PTR at its full reverse name.
func TestReverseZoneOwnersFollowTheirPrefix(t *testing.T) {
	cases := []struct {
		zone      dnsservice.DnsReverseZoneSettings
		wantOwner string
	}{
		{zone: reverseTestClassless, wantOwner: "10.0/26.2.0.192.in-addr.arpa."},
		{zone: dnsservice.DnsReverseZoneSettings{Zone: "0-63.2.0.192.in-addr.arpa.", Prefix: "192.0.2.0/26"}, wantOwner: "10.0-63.2.0.192.in-addr.arpa."},
		{zone: dnsservice.DnsReverseZoneSettings{Zone: "8.2.0.192.in-addr.arpa.", Prefix: "192.0.2.8/29"}, wantOwner: "10.8.2.0.192.in-addr.arpa."},
		{zone: dnsservice.DnsReverseZoneSettings{Zone: "2.0.192.in-addr.arpa.", Prefix: "192.0.2.0/24"}, wantOwner: "10.2.0.192.in-addr.arpa."},
		{zone: dnsservice.DnsReverseZoneSettings{Zone: "0.192.in-addr.arpa.", Prefix: "192.0.0.0/16"}, wantOwner: "10.2.0.192.in-addr.arpa."},
	}
	for _, c := range cases {
		zones, err := dnsservice.NewReverseZones(reverseTestSettings(t, c.zone))
		if err != nil {
			t.Fatalf("%s: %v", c.zone.Zone, err)
		}
		owner, name, ok := zones.Pointer(netip.MustParseAddr("192.0.2.10"))
		if !ok || owner != c.wantOwner || name != "o1.out.report.example." {
			t.Errorf("%s: owner %s name %s %t, want %s", c.zone.Zone, owner, name, ok, c.wantOwner)
		}
		reply := reverseTestAnswer(t, zones, c.wantOwner, dns.TypePTR, false)
		if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 1 {
			t.Errorf("%s: %v", c.zone.Zone, reply)
		}
	}
}

// What dns.yml's reverse may not say: a zone outside in-addr.arpa, a name that does not fit its prefix,
// a prefix that is neither an octet boundary nor classless, an IPv6 or unmasked prefix, and two zones
// that overlap.
func TestReverseZoneSettingsRefuseWhatCannotBeDelegated(t *testing.T) {
	cases := []struct {
		name  string
		zones []dnsservice.DnsReverseZoneSettings
	}{
		{name: "outside in-addr.arpa", zones: []dnsservice.DnsReverseZoneSettings{{Zone: "0/26.2.0.192.example.", Prefix: "192.0.2.0/26"}}},
		{name: "a /24 under another name", zones: []dnsservice.DnsReverseZoneSettings{{Zone: "3.0.192.in-addr.arpa.", Prefix: "192.0.2.0/24"}}},
		{name: "classless under another /24", zones: []dnsservice.DnsReverseZoneSettings{{Zone: "0/26.3.0.192.in-addr.arpa.", Prefix: "192.0.2.0/26"}}},
		{name: "classless two labels down", zones: []dnsservice.DnsReverseZoneSettings{{Zone: "a.0/26.2.0.192.in-addr.arpa.", Prefix: "192.0.2.0/26"}}},
		{name: "a /20", zones: []dnsservice.DnsReverseZoneSettings{{Zone: "0.192.in-addr.arpa.", Prefix: "192.0.0.0/20"}}},
		{name: "host bits", zones: []dnsservice.DnsReverseZoneSettings{{Zone: "0/26.2.0.192.in-addr.arpa.", Prefix: "192.0.2.10/26"}}},
		{name: "ipv6", zones: []dnsservice.DnsReverseZoneSettings{{Zone: "8.b.d.0.1.0.0.2.ip6.arpa.", Prefix: "2001:db8::/32"}}},
		{name: "not canonical", zones: []dnsservice.DnsReverseZoneSettings{{Zone: "0/26.2.0.192.IN-ADDR.ARPA.", Prefix: "192.0.2.0/26"}}},
		{name: "overlapping", zones: []dnsservice.DnsReverseZoneSettings{reverseTestClassless, {Zone: "2.0.192.in-addr.arpa.", Prefix: "192.0.2.0/24"}}},
	}
	for _, c := range cases {
		settings := edgeTestSettings(t)
		settings.Reverse.Zones = c.zones
		if err := settings.Validate(); !errors.Is(err, dnsservice.ErrDnsSettingsRefused) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// what the host sets: IPv4 once each, with a host name
	settings := edgeTestSettings(t)
	for _, addresses := range [][]dnsservice.DnsSendingAddress{
		{{Address: netip.MustParseAddr("2001:db8::10"), Name: "o1.out.report.example"}},
		{{Address: netip.MustParseAddr("192.0.2.10"), Name: "o1.out.report.example"}, {Address: netip.MustParseAddr("192.0.2.10"), Name: "o2.out.report.example"}},
		{{Address: netip.MustParseAddr("192.0.2.10"), Name: "o_1.out.report.example"}},
		{{Address: netip.MustParseAddr("192.0.2.10"), Name: "localhost"}},
	} {
		if err := settings.SetSendingAddresses(addresses); !errors.Is(err, dnsservice.ErrDnsSettingsRefused) {
			t.Errorf("%v: %v", addresses, err)
		}
	}
	if len(settings.SendingAddresses) != 0 {
		t.Errorf("a refused list was set: %v", settings.SendingAddresses)
	}
}

// _spf.<root> lists every sending address, in address order, and sends from nowhere with none; a list
// past one character-string splits so the joined text is the record, each string at most 255 bytes.
func TestDnsSpfRdataListsEverySendingAddress(t *testing.T) {
	settings := edgeTestSettings(t)
	if got := dnsservice.DnsSpfRdata(settings); got != `"v=spf1 -all"` {
		t.Errorf("none: %s", got)
	}
	addresses := reverseTestSendingAddresses()
	slices.Reverse(addresses)
	if err := settings.SetSendingAddresses(addresses); err != nil {
		t.Fatal(err)
	}
	if got := dnsservice.DnsSpfRdata(settings); got != `"v=spf1 ip4:192.0.2.10 ip4:192.0.2.11 ip4:198.51.100.20 -all"` {
		t.Errorf("three: %s", got)
	}
	many := []dnsservice.DnsSendingAddress{}
	want := "v=spf1"
	for index := range 40 {
		address := netip.AddrFrom4([4]byte{203, 0, 113, byte(100 + index)})
		many = append(many, dnsservice.DnsSendingAddress{Address: address, Name: "o.out.report.example."})
		want += " ip4:" + address.String()
	}
	want += " -all"
	if err := settings.SetSendingAddresses(many); err != nil {
		t.Fatal(err)
	}
	record, err := dns.NewRR("_spf.zone.example. 3600 IN TXT " + dnsservice.DnsSpfRdata(settings))
	if err != nil {
		t.Fatal(err)
	}
	texts := record.(*dns.TXT).Txt
	if len(texts) < 2 || strings.Join(texts, "") != want {
		t.Fatalf("forty: %d strings joining to %q", len(texts), strings.Join(texts, ""))
	}
	for _, text := range texts {
		if 255 < len(text) {
			t.Errorf("a string of %d bytes", len(text))
		}
	}
}

// The edge answers the reverse zones unsigned, DO or not: no RRSIG on a PTR, and an unlisted address a
// plain NXDOMAIN with no NSEC, while a root's answers stay signed.
func TestEdgeAnswersReverseZonesUnsignedUnderDo(t *testing.T) {
	settings := reverseTestSettings(t, reverseTestClassless)
	edge := newTestEdge(t, settings)
	edge.publish(t, edgeTestView(t, settings, 7, edgeTestRows()))
	conn := edge.serveUdp(t)

	conn.send(t, edgeTestQuery("10.0/26.2.0.192.in-addr.arpa.", dns.TypePTR, true), "198.51.100.7")
	reply, _ := conn.receive(t)
	if reply.Rcode != dns.RcodeSuccess || !reply.Authoritative || len(reply.Answer) != 1 || reply.Answer[0].Header().Rrtype != dns.TypePTR {
		t.Fatalf("a PTR under DO %v", reply)
	}
	if opt := reply.IsEdns0(); opt == nil || !opt.Do() {
		t.Errorf("the OPT does not echo DO: %v", reply)
	}
	conn.send(t, edgeTestQuery("12.0/26.2.0.192.in-addr.arpa.", dns.TypePTR, true), "198.51.100.7")
	reply, _ = conn.receive(t)
	if reply.Rcode != dns.RcodeNameError || len(reply.Ns) != 1 || reply.Ns[0].Header().Rrtype != dns.TypeSOA {
		t.Fatalf("an unlisted address under DO %v", reply)
	}
	conn.send(t, edgeTestQuery("0/26.2.0.192.in-addr.arpa.", dns.TypeDNSKEY, true), "198.51.100.7")
	reply, _ = conn.receive(t)
	if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 0 {
		t.Fatalf("DNSKEY at the apex %v", reply)
	}
	for _, record := range append(append([]dns.RR{}, reply.Answer...), reply.Ns...) {
		if rrType := record.Header().Rrtype; rrType == dns.TypeRRSIG || rrType == dns.TypeNSEC || rrType == dns.TypeDNSKEY {
			t.Errorf("a reverse zone answered %v", record)
		}
	}
	// the root beside it still signs
	conn.send(t, edgeTestQuery("www.net1."+edgeTestRoot, dns.TypeA, true), "198.51.100.7")
	reply, _ = conn.receive(t)
	edge.wantSigned(t, reply)
}

// §22's FCrDNS on a fixture: each sending address's PTR name, as the edge answers it, has an A record in
// the fixture's forward zone naming the address, which is what a receiver checks; a fixture whose name
// names another address fails the same check, so the check reads the answer and not only its shape.
func TestFcrdnsHoldsForEverySendingAddressOnAFixture(t *testing.T) {
	settings := reverseTestSettings(t, reverseTestClassless)
	edge := newTestEdge(t, settings)
	edge.publish(t, edgeTestView(t, settings, 7, edgeTestRows()))
	conn := edge.serveUdp(t)
	// W11's A records under the HELO domain, which bringyour.com's zone holds in production
	forward := map[string][]netip.Addr{
		"o1.out.report.example.": {netip.MustParseAddr("192.0.2.10")},
		"o2.out.report.example.": {netip.MustParseAddr("192.0.2.11")},
	}
	forwardConfirmed := func(address netip.Addr, forward map[string][]netip.Addr) bool {
		reverseName, err := dns.ReverseAddr(address.String())
		if err != nil {
			t.Fatal(err)
		}
		// HE's parent zone holds a CNAME from the octet's name to the classless owner (RFC 2317)
		owner := strings.Replace(reverseName, "2.0.192.in-addr.arpa.", "0/26.2.0.192.in-addr.arpa.", 1)
		conn.send(t, edgeTestQuery(owner, dns.TypePTR, true), "198.51.100.7")
		reply, _ := conn.receive(t)
		for _, record := range reply.Answer {
			if ptr, ok := record.(*dns.PTR); ok && slices.Contains(forward[ptr.Ptr], address) {
				return true
			}
		}
		return false
	}
	for _, address := range []string{"192.0.2.10", "192.0.2.11"} {
		if !forwardConfirmed(netip.MustParseAddr(address), forward) {
			t.Errorf("%s is not forward-confirmed", address)
		}
	}
	// a sending address with no PTR, and one whose name names another address, both fail
	if forwardConfirmed(netip.MustParseAddr("192.0.2.12"), forward) {
		t.Error("an address with no PTR passed")
	}
	crossed := map[string][]netip.Addr{"o1.out.report.example.": {netip.MustParseAddr("192.0.2.11")}}
	if forwardConfirmed(netip.MustParseAddr("192.0.2.10"), crossed) {
		t.Error("a name naming another address passed")
	}
}

// config/main's dns.yml, once its three open numbers are set, gives reverse and delegated their forms:
// no reverse zone until HE's delegation names one, and delegated zones off.
func TestConfigMainDnsYmlServesNoReverseOrDelegatedZoneYet(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "config", "main", "dns.yml"))
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("not read: no config checkout beside this one")
	}
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, replacement := range [][2]string{
		{"tcp: {idle_timeout_s: 10}", "tcp: {idle_timeout_s: 10, connections_per_source: 1}"},
		{"classes: [answer, denial, error]}", "classes: [answer, denial, error], responses_per_second: 1}"},
	} {
		if !strings.Contains(text, replacement[0]) {
			t.Fatalf("main's dns.yml holds no %q", replacement[0])
		}
		text = strings.Replace(text, replacement[0], replacement[1], 1)
	}
	settings, err := dnsservice.LoadDnsSettings([]byte(text + "signatures_per_second: 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(settings.Reverse.Zones) != 0 || settings.Delegated.Enabled || len(settings.SendingAddresses) != 0 {
		t.Errorf("reverse %+v delegated %+v sending %v", settings.Reverse, settings.Delegated, settings.SendingAddresses)
	}
}
