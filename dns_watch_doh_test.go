//go:build !sidecar_http && !js && !ios_extension

package sidecar

// The zone watch's DoH resolvers (DNS-M5-22): each resolver's own answer, parsed into the watch's form from the wire:
// addresses, TXT, a CNAME at the name, CAA and TLSA from their RDATA's bytes, NXDOMAIN as a name error, and a
// SERVFAIL or a resolver with no usable answer as a failure, never an answer.

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// A forwarder answering a fixed message, or nothing.
type testDnsWatchForwarder struct {
	response []byte
	usable   bool
}

func (self *testDnsWatchForwarder) Forward(ctx context.Context, qType dnsmessage.Type, domain string) ([]byte, bool) {
	return self.response, self.usable
}

// A response for name with rcode and the resources add appends.
func testDnsWatchResponse(t *testing.T, name string, rcode dnsmessage.RCode, add func(builder *dnsmessage.Builder, owner dnsmessage.Name)) []byte {
	t.Helper()
	owner := dnsmessage.MustNewName(name)
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, RCode: rcode})
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := builder.Question(dnsmessage.Question{Name: owner, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err := builder.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	if add != nil {
		add(&builder, owner)
	}
	response, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func testDnsWatchHeader(owner dnsmessage.Name, rrType dnsmessage.Type) dnsmessage.ResourceHeader {
	return dnsmessage.ResourceHeader{Name: owner, Type: rrType, Class: dnsmessage.ClassINET, TTL: 60}
}

func TestDnsWatchDohParsesEachType(t *testing.T) {
	name := "shop.lbl0000001.root.example."
	cases := []struct {
		qType  uint16
		add    func(builder *dnsmessage.Builder, owner dnsmessage.Name)
		cname  string
		values []string
	}{
		{
			qType: DnsWatchTypeA,
			add: func(builder *dnsmessage.Builder, owner dnsmessage.Name) {
				builder.AResource(testDnsWatchHeader(owner, dnsmessage.TypeA), dnsmessage.AResource{A: netip.MustParseAddr("11.22.33.45").As4()})
				builder.AResource(testDnsWatchHeader(owner, dnsmessage.TypeA), dnsmessage.AResource{A: netip.MustParseAddr("11.22.33.44").As4()})
			},
			values: []string{"11.22.33.44", "11.22.33.45"},
		},
		{
			qType: DnsWatchTypeA,
			add: func(builder *dnsmessage.Builder, owner dnsmessage.Name) {
				builder.CNAMEResource(testDnsWatchHeader(owner, dnsmessage.TypeCNAME), dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("elsewhere.example.")})
				builder.AResource(testDnsWatchHeader(dnsmessage.MustNewName("elsewhere.example."), dnsmessage.TypeA), dnsmessage.AResource{A: netip.MustParseAddr("11.22.33.46").As4()})
			},
			cname:  "elsewhere.example.",
			values: []string{"11.22.33.46"},
		},
		{
			qType: DnsWatchTypeTxt,
			add: func(builder *dnsmessage.Builder, owner dnsmessage.Name) {
				builder.TXTResource(testDnsWatchHeader(owner, dnsmessage.TypeTXT), dnsmessage.TXTResource{TXT: []string{"two ", "strings"}})
			},
			values: []string{"two strings"},
		},
		{
			qType: DnsWatchTypeCaa,
			add: func(builder *dnsmessage.Builder, owner dnsmessage.Name) {
				data := append([]byte{0, 5}, []byte("issueca.example")...)
				builder.UnknownResource(testDnsWatchHeader(owner, dnsmessage.Type(DnsWatchTypeCaa)), dnsmessage.UnknownResource{Type: dnsmessage.Type(DnsWatchTypeCaa), Data: data})
			},
			values: []string{"0 issue ca.example"},
		},
		{
			qType: DnsWatchTypeTlsa,
			add: func(builder *dnsmessage.Builder, owner dnsmessage.Name) {
				data := []byte{3, 1, 1, 0xab, 0xcd}
				builder.UnknownResource(testDnsWatchHeader(owner, dnsmessage.Type(DnsWatchTypeTlsa)), dnsmessage.UnknownResource{Type: dnsmessage.Type(DnsWatchTypeTlsa), Data: data})
			},
			values: []string{"3 1 1 ABCD"},
		},
	}
	for _, c := range cases {
		resolver := newDnsWatchForwarderResolver(&testDnsWatchForwarder{response: testDnsWatchResponse(t, name, dnsmessage.RCodeSuccess, c.add), usable: true})
		answer, err := resolver.Lookup(context.Background(), 0, name, c.qType)
		if err != nil || answer.NameError || answer.Cname != c.cname || !slices.Equal(answer.Values, c.values) {
			t.Errorf("%d: %+v %v", c.qType, answer, err)
		}
		// the presentation form of the same values reads alike
		for _, value := range c.values {
			if canonicalDnsWatchValue(c.qType, value) != value {
				t.Errorf("%d: %q is not canonical", c.qType, value)
			}
		}
	}
}

func TestDnsWatchDohReadsDenialsAndFailures(t *testing.T) {
	name := "gone.lbl0000001.root.example."
	nxdomain := newDnsWatchForwarderResolver(&testDnsWatchForwarder{response: testDnsWatchResponse(t, name, dnsmessage.RCodeNameError, nil), usable: true})
	if answer, err := nxdomain.Lookup(context.Background(), 0, name, DnsWatchTypeA); err != nil || !answer.NameError {
		t.Fatalf("NXDOMAIN: %+v %v", answer, err)
	}
	servfail := newDnsWatchForwarderResolver(&testDnsWatchForwarder{response: testDnsWatchResponse(t, name, dnsmessage.RCodeServerFailure, nil), usable: true})
	if _, err := servfail.Lookup(context.Background(), 0, name, DnsWatchTypeA); !errors.Is(err, errDnsWatchResolverFailed) {
		t.Fatalf("SERVFAIL: %v", err)
	}
	unusable := newDnsWatchForwarderResolver(&testDnsWatchForwarder{})
	if _, err := unusable.Lookup(context.Background(), 0, name, DnsWatchTypeA); !errors.Is(err, errDnsWatchResolverFailed) {
		t.Fatalf("no answer: %v", err)
	}
	if _, err := unusable.Lookup(context.Background(), 1, name, DnsWatchTypeA); !errors.Is(err, errDnsWatchResolverFailed) {
		t.Fatalf("a resolver past the count: %v", err)
	}
}

// The default resolvers are two of connect's, one a different operator each.
func TestDnsWatchDohDefaultsToTwoResolvers(t *testing.T) {
	settings := DefaultDnsWatchDohSettings()
	if len(settings.ResolverUrls) != 2 || settings.ResolverUrls[0] == settings.ResolverUrls[1] {
		t.Fatalf("%v", settings.ResolverUrls)
	}
}
