package dnsservice

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

// A suspended host's rows (§12.9; RESOLUTIONS plan-DNS-metadata-rows #5): a host answered only by *, with
// its withheld owner.
func withheldTestRows() []DnsRecordSet {
	return append(testApexRows(),
		DnsRecordSet{Owner: "*." + testRoot, Type: dns.TypeA, Ttl: 60, Kind: DnsRecordKindEdge},
		DnsRecordSet{Owner: "*." + testRoot, Type: dns.TypeMX, Ttl: 300, Kind: DnsRecordKindSystem, Rdata: []string{"0 ."}},
		DnsRecordSet{Owner: "shop." + testRoot, Type: DnsWithheldType, Kind: DnsRecordKindWithheld},
	)
}

func withheldTestHealthy() *HealthySet {
	return NewHealthySet([]DnsLbInterface{{Name: "lb-1", Ipv4: netip.MustParseAddr("192.0.2.10")}}, nil)
}

// A withheld owner answers NODATA for every type, ANY included, where * would answer without it.
func TestWithheldOwnerAnswersNoDataForEveryType(t *testing.T) {
	view := newTestView(t, 7, withheldTestRows()...)
	healthy := withheldTestHealthy()
	for _, rrType := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeTXT, dns.TypeHTTPS, dns.TypeCAA, dns.TypeANY} {
		reply := testAnswer(t, view, healthy, "shop."+testRoot, rrType)
		if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 0 {
			t.Errorf("%s: rcode %s, answer %v", dns.TypeToString[rrType], dns.RcodeToString[reply.Rcode], recordLines(reply.Answer))
		}
		if len(reply.Ns) != 1 || reply.Ns[0].Header().Rrtype != dns.TypeSOA {
			t.Errorf("%s: authority %v", dns.TypeToString[rrType], recordLines(reply.Ns))
		}
	}
	// the wildcard still answers every other host
	reply := testAnswer(t, view, healthy, "blog."+testRoot, dns.TypeA)
	if len(reply.Answer) != 1 {
		t.Errorf("an unsuspended host: %v", recordLines(reply.Answer))
	}
}

// Names below a withheld owner fall under no wildcard: the owner exists, so it is their closest
// encloser, and it holds no * of its own (RFC 4592).
func TestWithheldOwnerBlocksTheWildcardBelowIt(t *testing.T) {
	view := newTestView(t, 7, withheldTestRows()...)
	reply := testAnswer(t, view, withheldTestHealthy(), "www.shop."+testRoot, dns.TypeA)
	if reply.Rcode != dns.RcodeNameError || len(reply.Answer) != 0 {
		t.Fatalf("below a withheld owner: rcode %s, answer %v", dns.RcodeToString[reply.Rcode], recordLines(reply.Answer))
	}
}

// Suspending a host that is an empty non-terminal withholds it while its copy row stays, and lifting
// the suspension answers from * again, each through one journal row.
func TestWithheldOwnerBesideACopyAndLiftsBack(t *testing.T) {
	srv := DnsRecordSet{Owner: "_sip._tcp.shop." + testRoot, Type: dns.TypeSRV, Ttl: 300, Kind: DnsRecordKindUser, Rdata: []string{"0 0 5060 sip.example.net."}}
	rows := append(testApexRows(),
		DnsRecordSet{Owner: "*." + testRoot, Type: dns.TypeA, Ttl: 60, Kind: DnsRecordKindEdge},
		srv,
		DnsRecordSet{Owner: "shop." + testRoot, Type: DnsCopyType, Kind: DnsRecordKindCopy},
	)
	view := newTestView(t, 7, rows...)
	healthy := withheldTestHealthy()
	if reply := testAnswer(t, view, healthy, "shop."+testRoot, dns.TypeA); len(reply.Answer) != 1 {
		t.Fatalf("the copy before: %v", recordLines(reply.Answer))
	}
	suspended, err := view.Apply([]DnsJournalRow{{
		Format:  DnsFormat,
		Root:    testRoot,
		Serial:  8,
		Upserts: []DnsRecordSet{{Owner: "shop." + testRoot, Type: DnsWithheldType, Kind: DnsRecordKindWithheld}},
		Deletes: []DnsRecordKey{srv.Key()},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if reply := testAnswer(t, suspended, healthy, "shop."+testRoot, dns.TypeA); len(reply.Answer) != 0 || reply.Rcode != dns.RcodeSuccess {
		t.Fatalf("suspended: rcode %s, answer %v", dns.RcodeToString[reply.Rcode], recordLines(reply.Answer))
	}
	if reply := testAnswer(t, suspended, healthy, srv.Owner, dns.TypeSRV); len(reply.Answer) != 0 {
		t.Fatalf("a withheld child: %v", recordLines(reply.Answer))
	}
	lifted, err := suspended.Apply([]DnsJournalRow{{
		Format:  DnsFormat,
		Root:    testRoot,
		Serial:  9,
		Upserts: []DnsRecordSet{srv},
		Deletes: []DnsRecordKey{{Owner: "shop." + testRoot, Type: DnsWithheldType}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if reply := testAnswer(t, lifted, healthy, "shop."+testRoot, dns.TypeA); len(reply.Answer) != 1 {
		t.Fatalf("lifted: %v", recordLines(reply.Answer))
	}
	if reply := testAnswer(t, lifted, healthy, srv.Owner, dns.TypeSRV); len(reply.Answer) != 1 {
		t.Fatalf("the child lifted: %v", recordLines(reply.Answer))
	}
}

// A withheld owner holds its own type and no rdata, and no other kind takes that type.
func TestWithheldOwnerRowRules(t *testing.T) {
	good := DnsRecordSet{Owner: "shop." + testRoot, Type: DnsWithheldType, Kind: DnsRecordKindWithheld}
	if err := good.Validate(testRoot); err != nil {
		t.Fatal(err)
	}
	if key := good.Key(); key.Validate(testRoot) != nil {
		t.Fatalf("its key %+v is refused", key)
	}
	typed := good
	typed.Type = dns.TypeA
	copyTyped := good
	copyTyped.Type = DnsCopyType
	withData := good
	withData.Rdata = []string{"192.0.2.1"}
	systemAtWithheldType := DnsRecordSet{Owner: "shop." + testRoot, Type: DnsWithheldType, Ttl: 60, Kind: DnsRecordKindSystem, Rdata: []string{`\# 0`}}
	for _, bad := range []DnsRecordSet{typed, copyTyped, withData, systemAtWithheldType} {
		if err := bad.Validate(testRoot); err == nil {
			t.Errorf("%+v passed", bad)
		}
	}
}

// Compact denial at a withheld owner names no type of data.
func TestWithheldOwnerDeniesEveryTypeUnderDo(t *testing.T) {
	view := newTestView(t, 7, withheldTestRows()...)
	types := view.dataTypes("shop."+testRoot, withheldTestHealthy())
	if types == nil || len(types) != 0 {
		t.Fatalf("data types %v", types)
	}
}
