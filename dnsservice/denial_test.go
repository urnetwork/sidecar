package dnsservice

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// testdata/dns/denial/vectors.json.
type denialVectors struct {
	Root    string        `json:"root"`
	Serial  uint64        `json:"serial"`
	Rows    []string      `json:"rows"`
	Healthy answerHealthy `json:"healthy"`
	Cases   []denialCase  `json:"cases"`
}

type denialCase struct {
	Name  string `json:"name"`
	Query string `json:"query"`
	// nil asks with DO
	Do        *bool    `json:"do"`
	Co        bool     `json:"co"`
	Rcode     string   `json:"rcode"`
	CoEcho    bool     `json:"co_echo"`
	Answer    []string `json:"answer"`
	Authority []string `json:"authority"`
	Rrsigs    []string `json:"rrsigs"`
	Dnskey    bool     `json:"dnskey"`
}

// A section's records other than RRSIGs, and its RRSIGs as '<owner> <covered> <labels>'.
func splitSignedSection(records []dns.RR) (data []string, rrsigs []string) {
	data = []string{}
	rrsigs = []string{}
	for _, record := range records {
		if rrsig, ok := record.(*dns.RRSIG); ok {
			rrsigs = append(rrsigs, fmt.Sprintf("%s %s %d", rrsig.Hdr.Name, dnsTypeText(rrsig.TypeCovered), rrsig.Labels))
			continue
		}
		data = append(data, strings.Join(strings.Fields(record.String()), " "))
	}
	return data, rrsigs
}

func TestDenialVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "dns", "denial", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	vectors := &denialVectors{}
	if err := json.Unmarshal(data, vectors); err != nil {
		t.Fatal(err)
	}
	settings := signingTestSettings(t, 1000)
	snapshot := DnsSnapshot{Format: DnsFormat, Root: vectors.Root, Serial: vectors.Serial}
	view, err := NewZoneView(settings, NewDnsSnapshotRows(snapshot, parseVectorRows(t, vectors.Rows)))
	if err != nil {
		t.Fatal(err)
	}
	interfaces := func(addresses []string) []DnsLbInterface {
		list := []DnsLbInterface{}
		for _, text := range addresses {
			address := netip.MustParseAddr(text)
			if address.Is4() {
				list = append(list, DnsLbInterface{Ipv4: address})
			} else {
				list = append(list, DnsLbInterface{Ipv6: address})
			}
		}
		return list
	}
	healthy := NewHealthySet(interfaces(vectors.Healthy.Edge), interfaces(vectors.Healthy.Router))
	signing := newTestSigning(t, vectors.Root)
	keys := signing.checked(t, view)
	signer := NewSigner(settings, newTestClock(testSigningNow), nil)

	wantDnskeys := []string{}
	for _, record := range keys.dnskeyRecords(vectors.Root) {
		wantDnskeys = append(wantDnskeys, strings.Join(strings.Fields(record.String()), " "))
	}

	for index := range vectors.Cases {
		c := &vectors.Cases[index]
		name, typeText, _ := strings.Cut(c.Query, " ")
		rrType, ok := dns.StringToType[typeText]
		if !ok {
			t.Fatalf("%s: no such type %q", c.Name, typeText)
		}
		signed := c.Do == nil || *c.Do
		message := testQuery(name, rrType)
		message.SetEdns0(1232, signed)
		if c.Co {
			message.IsEdns0().SetCo()
		}
		query := &DnsQuery{Message: message}
		reply := signer.Answer(query, view, keys, healthy)
		if reply == nil {
			t.Fatalf("%s: no reply", c.Name)
		}
		if label := dnsRcodeLabel(reply.Rcode); label != c.Rcode {
			t.Errorf("%s: rcode %s, want %s", c.Name, label, c.Rcode)
			continue
		}
		if opt := reply.IsEdns0(); opt == nil || opt.Co() != c.CoEcho || opt.Do() != signed {
			t.Errorf("%s: opt %v", c.Name, opt)
		}
		answer, answerRrsigs := splitSignedSection(reply.Answer)
		authority, authorityRrsigs := splitSignedSection(reply.Ns)
		wantAnswer := c.Answer
		if c.Dnskey {
			wantAnswer = wantDnskeys
		}
		wantLines(t, c.Name, "answer", answer, wantAnswer)
		wantLines(t, c.Name, "authority", authority, c.Authority)
		wantLines(t, c.Name, "rrsigs", append(answerRrsigs, authorityRrsigs...), c.Rrsigs)
		if reply.Rcode == dns.RcodeFormatError {
			continue
		}
		if err := verifyDnsSignedReply(reply, message.Question[0], signed, c.Co, keys, signing.anchors, testSigningNow); err != nil {
			t.Errorf("%s: %v", c.Name, err)
		}
		// every signature by the ZSK, named by its tag, with the root as signer; the window's by the KSK
		for _, record := range slices.Concat(reply.Answer, reply.Ns) {
			rrsig, ok := record.(*dns.RRSIG)
			if !ok {
				continue
			}
			wantTag := signing.zskRecord.KeyTag()
			if rrsig.TypeCovered == dns.TypeDNSKEY {
				wantTag = signing.kskRecord.KeyTag()
			}
			if rrsig.KeyTag != wantTag || rrsig.SignerName != vectors.Root || rrsig.Algorithm != dns.ECDSAP256SHA256 {
				t.Errorf("%s: rrsig %v", c.Name, rrsig)
			}
		}
	}
}

func TestImmediateSuccessor(t *testing.T) {
	successor, ok := dnsImmediateSuccessor("a.zone.example.")
	if !ok || successor != `\000.a.zone.example.` {
		t.Errorf("%q %v", successor, ok)
	}
	// a name of 254 octets on the wire has no room for a label in front, so its first label grows
	rest := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 61) + "."
	long := strings.Repeat("d", 62) + "." + rest
	if length := len(long) + 1; length != 254 {
		t.Fatalf("the long name is %d octets", length)
	}
	successor, ok = dnsImmediateSuccessor(long)
	if !ok || successor != strings.Repeat("d", 62)+`\000.`+rest {
		t.Errorf("254 octets: %q %v", successor, ok)
	}
	// a 255-octet name whose first label is full has no successor that denies it alone
	full := strings.Repeat("d", 63) + "." + strings.Repeat("e", 63) + "." + strings.Repeat("f", 63) + "." + strings.Repeat("g", 61) + "."
	if _, ok := dnsImmediateSuccessor(full); ok {
		t.Error("a full name got a successor")
	}
}

// What an empty answer's NSEC names follows what the name answers now, so a health drop takes its
// type out of the bitmap with no write.
func TestDataTypesFollowTheHealthySet(t *testing.T) {
	view := newTestView(t, 100, signingTestRows()...)
	got := view.dataTypes("unknown.net1."+testRoot, signingTestHealthy())
	if !slices.Equal(got, []uint16{dns.TypeA, dns.TypeMX}) {
		t.Errorf("healthy: %v", got)
	}
	got = view.dataTypes("unknown.net1."+testRoot, NewHealthySet(nil, nil))
	if !slices.Equal(got, []uint16{dns.TypeMX}) {
		t.Errorf("no healthy address: %v", got)
	}
	if got := view.dataTypes("nosuch."+testRoot, nil); got != nil {
		t.Errorf("a name that does not exist: %v", got)
	}
	if got := view.dataTypes("_tcp.blog.net1."+testRoot, nil); got == nil || len(got) != 0 {
		t.Errorf("an empty non-terminal with no copy: %v", got)
	}
}
