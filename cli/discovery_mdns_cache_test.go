// The querier's cache (discovery_mdns_cache.go; §17.7.1): a response's PTR, SRV, TXT and A make one gathered instance
// with its TTL, an escaped name read back, its own target named own, and a goodbye withdrawing it at once.

package main

import (
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// A response holding a printer's PTR, SRV, TXT and its target's A, each at ttl.
func urMdnsTestResponse(t *testing.T, ttl uint32) []byte {
	t.Helper()
	name := func(text string) dnsmessage.Name {
		parsed, err := dnsmessage.NewName(text)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, Authoritative: true})
	builder.EnableCompression()
	if err := builder.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	header := func(owner string, rrType dnsmessage.Type) dnsmessage.ResourceHeader {
		return dnsmessage.ResourceHeader{Name: name(owner), Type: rrType, Class: dnsmessage.ClassINET, TTL: ttl}
	}
	instance := "Synthetic\\.Printer._ipp._tcp.local."
	if err := builder.PTRResource(header("_ipp._tcp.local.", dnsmessage.TypePTR), dnsmessage.PTRResource{PTR: name(instance)}); err != nil {
		t.Fatal(err)
	}
	if err := builder.SRVResource(header(instance, dnsmessage.TypeSRV), dnsmessage.SRVResource{Port: 631, Target: name("Printer.local.")}); err != nil {
		t.Fatal(err)
	}
	if err := builder.TXTResource(header(instance, dnsmessage.TypeTXT), dnsmessage.TXTResource{TXT: []string{"rp=ipp"}}); err != nil {
		t.Fatal(err)
	}
	if err := builder.AResource(header("Printer.local.", dnsmessage.TypeA), dnsmessage.AResource{A: [4]byte{192, 168, 50, 20}}); err != nil {
		t.Fatal(err)
	}
	message, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return message
}

func TestUrMdnsCacheGathersAndForgets(t *testing.T) {
	cache := newUrMdnsCache(defaultUrMdnsSettings())
	now := time.Date(2026, time.November, 24, 12, 0, 0, 0, time.UTC)
	if !cache.take(urMdnsTestResponse(t, 120), now) {
		t.Fatal("the response changed nothing")
	}
	gathered := cache.gathered([]string{"_ipp._tcp", "_ssh._tcp"}, now, []netip.Addr{netip.MustParseAddr("192.168.50.2")})
	if len(gathered) != 1 {
		t.Fatalf("%d gathered", len(gathered))
	}
	printer := gathered[0]
	if printer.Name != "Synthetic.Printer" || printer.Service != "_ipp._tcp" || printer.Port != 631 || string(printer.Txt) != "\x06rp=ipp" ||
		printer.HostName != "printer.local." || len(printer.Addresses) != 1 || printer.Own || !printer.Expires.Equal(now.Add(120*time.Second)) {
		t.Fatalf("the printer %+v", printer)
	}
	// the same host's own address names it own
	if own := cache.gathered([]string{"_ipp._tcp"}, now, []netip.Addr{netip.MustParseAddr("192.168.50.20")}); !own[0].Own {
		t.Errorf("the host's own instance is not own")
	}
	// past its TTL it goes; a goodbye takes it at once
	if late := cache.gathered([]string{"_ipp._tcp"}, now.Add(121*time.Second), nil); len(late) != 0 {
		t.Errorf("an expired instance stayed")
	}
	cache.take(urMdnsTestResponse(t, 0), now)
	if gone := cache.gathered([]string{"_ipp._tcp"}, now, nil); len(gone) != 0 {
		t.Errorf("a goodbye left %d", len(gone))
	}
	if cache.take([]byte{1, 2, 3}, now) {
		t.Errorf("a malformed message changed the cache")
	}
}
