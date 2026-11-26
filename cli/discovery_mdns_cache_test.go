// The querier's cache (discovery_mdns_cache.go; §17.7.1): a response's PTR, SRV, TXT and A make one gathered instance
// with its TTL, a label holding a dot kept whole, its own target named own, and a goodbye withdrawing it at once; the
// subtype PTRs an announcement carries give its subtypes; the known answers a query lists are the PTRs with more than
// half their TTL left; a browse answer with its additionals left out asks for SRV, TXT and A in turn; and the record
// bound holds, counting only what stands.

package main

import (
	"net/netip"
	"slices"
	"testing"
	"time"
)

// A response holding a printer's PTR, SRV, TXT and its target's A at ttl, its subtype PTR, and what of them leave says
// to leave out.
func urMdnsTestResponse(t *testing.T, ttl uint32, leave ...uint16) []byte {
	t.Helper()
	return urMdnsTestResponseOf(t, "Synthetic.Printer", "Printer", "192.168.50.20", ttl, leave...)
}

// The same for an instance of name on host at address.
func urMdnsTestResponseOf(t *testing.T, name string, host string, address string, ttl uint32, leave ...uint16) []byte {
	t.Helper()
	instance := urMdnsNameOf(name).append(urMdnsNameParse("_ipp._tcp.local")...)
	target := urMdnsNameOf(host, "local")
	records := []urMdnsRecord{
		{name: urMdnsNameParse("_ipp._tcp.local"), rrtype: urMdnsTypePtr, ttl: ttl, target: instance},
		{name: urMdnsNameParse("_universal._sub._ipp._tcp.local"), rrtype: urMdnsTypePtr, ttl: ttl, target: instance},
		{name: instance, rrtype: urMdnsTypeSrv, cacheFlush: true, ttl: ttl, port: 631, target: target},
		{name: instance, rrtype: urMdnsTypeTxt, cacheFlush: true, ttl: ttl, txt: []byte("\x06rp=ipp")},
		{name: target, rrtype: urMdnsTypeA, cacheFlush: true, ttl: ttl, address: netip.MustParseAddr(address)},
	}
	message := &urMdnsMessage{response: true, authoritative: true}
	for _, record := range records {
		if !slices.Contains(leave, record.rrtype) {
			message.answers = append(message.answers, record)
		}
	}
	packed := message.pack(9000)
	if len(packed) != 1 {
		t.Fatalf("the response packed into %d", len(packed))
	}
	return packed[0]
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
		printer.HostName != "printer.local." || len(printer.Addresses) != 1 || printer.Own || !printer.Expires.Equal(now.Add(120*time.Second)) ||
		!slices.Equal(printer.Subtypes, []string{"_universal"}) {
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
	cache.take(urMdnsTestResponse(t, 120), now)
	cache.take(urMdnsTestResponse(t, 0), now)
	if gone := cache.gathered([]string{"_ipp._tcp"}, now, nil); len(gone) != 0 {
		t.Errorf("a goodbye left %d", len(gone))
	}
	if cache.take([]byte{1, 2, 3}, now) {
		t.Errorf("a malformed message changed the cache")
	}
}

func TestUrMdnsCacheListsKnownAnswersAndAsksWhatIsMissing(t *testing.T) {
	cache := newUrMdnsCache(defaultUrMdnsSettings())
	now := time.Date(2026, time.November, 24, 12, 0, 0, 0, time.UTC)
	// a browse answer with no additionals: the PTR alone
	cache.take(urMdnsTestResponse(t, 4500, urMdnsTypeSrv, urMdnsTypeTxt, urMdnsTypeA), now)
	missing := cache.missing([]string{"_ipp._tcp"}, now)
	if len(missing) != 2 || missing[0].qtype != urMdnsTypeTxt && missing[0].qtype != urMdnsTypeSrv || missing[0].name[0] != "Synthetic.Printer" {
		t.Fatalf("missing %+v", missing)
	}
	// SRV and TXT come, the address still does not: A for the target
	cache.take(urMdnsTestResponse(t, 4500, urMdnsTypeA), now)
	missing = cache.missing([]string{"_ipp._tcp"}, now)
	if len(missing) != 1 || missing[0].qtype != urMdnsTypeA || !missing[0].name.equal(urMdnsNameParse("printer.local")) {
		t.Fatalf("missing %+v", missing)
	}
	cache.take(urMdnsTestResponse(t, 4500), now)
	if missing := cache.missing([]string{"_ipp._tcp"}, now); len(missing) != 0 {
		t.Fatalf("missing %+v with everything held", missing)
	}
	// known answers: the type's PTR while more than half its TTL is left, never the subtype's
	known := cache.knownAnswers("_ipp._tcp", now.Add(2249*time.Second))
	if len(known) != 1 || known[0].target[0] != "Synthetic.Printer" || known[0].ttl != 2251 {
		t.Fatalf("known %+v", known)
	}
	if known := cache.knownAnswers("_ipp._tcp", now.Add(2250*time.Second)); len(known) != 0 {
		t.Fatalf("at half its TTL known %+v", known)
	}
	// the query lists them, and reads back as a query
	query := urMdnsBrowseQuery("_ipp._tcp", cache.knownAnswers("_ipp._tcp", now), 1472)
	parsed, err := parseUrMdnsMessage(query[0])
	if err != nil || parsed.response || len(parsed.questions) != 1 || len(parsed.answers) != 1 {
		t.Fatalf("the query %+v, %v", parsed, err)
	}
	// follow-ups fit their bound, split across messages
	followUps := urMdnsFollowUps([]urMdnsQuestion{
		{name: urMdnsNameParse("a.local"), qtype: urMdnsTypeA},
		{name: urMdnsNameParse("b.local"), qtype: urMdnsTypeA},
		{name: urMdnsNameParse("c.local"), qtype: urMdnsTypeA},
	}, 12+2*13)
	if len(followUps) != 2 {
		t.Fatalf("%d follow-up messages", len(followUps))
	}
}

func TestUrMdnsCacheHoldsItsBound(t *testing.T) {
	settings := defaultUrMdnsSettings()
	// one printer's five records
	settings.RecordCount = 5
	cache := newUrMdnsCache(settings)
	now := time.Date(2026, time.November, 24, 12, 0, 0, 0, time.UTC)
	cache.take(urMdnsTestResponseOf(t, "First", "first", "192.168.50.21", 60), now)
	cache.take(urMdnsTestResponseOf(t, "Second", "second", "192.168.50.22", 600), now)
	names := func(at time.Time) []string {
		out := []string{}
		for _, gathered := range cache.gathered([]string{"_ipp._tcp"}, at, nil) {
			out = append(out, gathered.Name)
		}
		return out
	}
	if got := names(now); !slices.Equal(got, []string{"First"}) {
		t.Fatalf("at the bound gathered %v", got)
	}
	// once the first lapses, its room comes back
	cache.take(urMdnsTestResponseOf(t, "Second", "second", "192.168.50.22", 600), now.Add(61*time.Second))
	if got := names(now.Add(61 * time.Second)); !slices.Equal(got, []string{"Second"}) {
		t.Fatalf("after the lapse gathered %v", got)
	}
}
