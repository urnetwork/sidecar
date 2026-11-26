// §12.7's refusal of the DNS-SD names devices answer themselves (§12.9.1, D-DNS-12; owner decision 778): _dns-sd._udp
// and every owner below it, and a _<service>._tcp or _udp pair directly under the zone with every owner below it, for
// every type, naming why; an SRV below a host, a TXT at an underscore label and _udp or _tcp alone stay a user's.

package dnsservice

import (
	"errors"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestValidateUserRecordSetRefusesDnsSdNames(t *testing.T) {
	vectors := readTestUserRecordVectors(t)
	context := vectors.context()
	refused := []struct {
		owner  string
		rrType uint16
		rdata  string
	}{
		{owner: "_dns-sd._udp", rrType: dns.TypeTXT, rdata: `"x"`},
		{owner: "b._dns-sd._udp", rrType: dns.TypeTXT, rdata: `"x"`},
		{owner: "lb._dns-sd._udp", rrType: dns.TypeTXT, rdata: `"x"`},
		{owner: "_services._dns-sd._udp", rrType: dns.TypeTXT, rdata: `"x"`},
		{owner: "_ipp._tcp", rrType: dns.TypeTXT, rdata: `"x"`},
		{owner: "_ipp._tcp", rrType: dns.TypeSRV, rdata: "0 0 631 www." + vectors.Apex},
		{owner: "_smb._udp", rrType: dns.TypeTXT, rdata: `"x"`},
		{owner: "printer._ipp._tcp", rrType: dns.TypeTXT, rdata: `"x"`},
		{owner: "_universal._sub._ipp._tcp", rrType: dns.TypeTXT, rdata: `"x"`},
	}
	for _, c := range refused {
		set := testUserRecordSet(vectors.Apex, c.owner, c.rrType, 300, c.rdata)
		err := ValidateUserRecordSet(context, set)
		if !errors.Is(err, ErrDnsUserRecordRefused) || !strings.Contains(err.Error(), "DNS-SD") {
			t.Errorf("%s %d answered %v, want the DNS-SD refusal", c.owner, c.rrType, err)
		}
	}
	accepted := []struct {
		owner  string
		rrType uint16
		rdata  string
	}{
		{owner: "_ipp._tcp.www", rrType: dns.TypeSRV, rdata: "0 0 631 www." + vectors.Apex},
		{owner: "_udp", rrType: dns.TypeTXT, rdata: `"x"`},
		{owner: "_tcp", rrType: dns.TypeTXT, rdata: `"x"`},
	}
	for _, c := range accepted {
		set := testUserRecordSet(vectors.Apex, c.owner, c.rrType, 300, c.rdata)
		if err := ValidateUserRecordSet(context, set); err != nil {
			t.Errorf("%s %d refused: %v", c.owner, c.rrType, err)
		}
	}
}
