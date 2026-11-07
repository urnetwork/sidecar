package dnsservice

import (
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// The most rows one input applies, which keeps a run's cost bounded by the input's shape and not its
// length.
const fuzzAnswerRowMaxCount = 32

// The seeds under the repository's testdata/fuzz/FuzzAnswer, kept with §12's other vectors. Each file
// is go test's corpus format, which go test reads only from beside the package, so this reads it here.
func addFuzzAnswerSeeds(f *testing.F) {
	paths, err := filepath.Glob(filepath.Join("..", "testdata", "fuzz", "FuzzAnswer", "*"))
	if err != nil {
		f.Fatal(err)
	}
	if len(paths) == 0 {
		f.Fatal("no seeds")
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			f.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) != 3 || lines[0] != "go test fuzz v1" {
			f.Fatalf("%s is not a corpus file of two values", path)
		}
		values := [][]byte{}
		for _, line := range lines[1:] {
			quoted, ok := strings.CutPrefix(line, "[]byte(")
			if !ok || !strings.HasSuffix(quoted, ")") {
				f.Fatalf("%s: %q", path, line)
			}
			value, err := strconv.Unquote(strings.TrimSuffix(quoted, ")"))
			if err != nil {
				f.Fatalf("%s: %v", path, err)
			}
			values = append(values, []byte(value))
		}
		f.Add(values[0], values[1])
	}
}

// A zone with the answer shapes fuzzed rows can land among: a wildcard and a copy row, an empty
// non-terminal, edge and router rows, and system addresses that are not public.
func fuzzAnswerBaseView(f *testing.F) *ZoneView {
	system := func(owner string, rrType uint16, rdata ...string) DnsRecordSet {
		return DnsRecordSet{Owner: owner, Type: rrType, Ttl: 300, Kind: DnsRecordKindSystem, Rdata: rdata}
	}
	sets := append(testApexRows(),
		system(testRoot, dns.TypeNS, "ns1.zone.example."),
		system("ns1.zone.example.", dns.TypeA, "192.0.2.1"),
		system("net1.zone.example.", dns.TypeMX, "0 ."),
		system("*.net1.zone.example.", dns.TypeMX, "10 mx.net1.zone.example."),
		DnsRecordSet{Owner: "*.net1.zone.example.", Type: dns.TypeA, Ttl: 60, Kind: DnsRecordKindEdge},
		DnsRecordSet{Owner: "*.net1.zone.example.", Type: dns.TypeAAAA, Ttl: 60, Kind: DnsRecordKindEdge},
		DnsRecordSet{Owner: "mx.net1.zone.example.", Type: dns.TypeA, Ttl: 300, Kind: DnsRecordKindRouter},
		DnsRecordSet{Owner: "blog.net1.zone.example.", Kind: DnsRecordKindCopy},
		system("_sip._tcp.blog.net1.zone.example.", dns.TypeSRV, "10 5 5060 sip.other.example."),
	)
	return newTestView(f, 100, sets...)
}

// One line of the fuzzer's rows: <label> <kind> <type> <ttl> <rdata>, the label under net1, @ for net1
// itself and - for a row with no rdata.
func parseFuzzAnswerRow(line string) (*DnsRecordSet, bool) {
	fields := strings.SplitN(line, " ", 5)
	if len(fields) != 5 {
		return nil, false
	}
	owner := fields[0] + ".net1.zone.example."
	if fields[0] == "@" {
		owner = "net1.zone.example."
	}
	rrType, ok := dns.StringToType[fields[2]]
	if !ok {
		return nil, false
	}
	ttl, err := strconv.ParseUint(fields[3], 10, 32)
	if err != nil {
		return nil, false
	}
	set := &DnsRecordSet{Owner: owner, Type: rrType, Ttl: uint32(ttl), Kind: DnsRecordKind(fields[1])}
	if fields[4] != "-" {
		set.Rdata = strings.Split(fields[4], "|")
	}
	return set, true
}

// §22.6's synthesis target: whatever rows the feed delivers and whatever query arrives, Answer does not
// panic, its reply packs inside the transport's limit, it never holds a non-public address a user
// wrote, a type §12.7 refuses a user or a CNAME chain past the setting, and a response is left
// unanswered.
func FuzzAnswer(f *testing.F) {
	addFuzzAnswerSeeds(f)
	base := fuzzAnswerBaseView(f)
	healthy := NewHealthySet(
		[]DnsLbInterface{{Ipv4: netip.MustParseAddr("192.0.2.10"), Ipv6: netip.MustParseAddr("2001:db8::10")}},
		[]DnsLbInterface{{Ipv4: netip.MustParseAddr("192.0.2.20")}},
	)
	f.Fuzz(func(t *testing.T, queryBytes []byte, rowBytes []byte) {
		view := base
		// addresses other writers may hold, which a user's rows may not reach an answer with
		systemAddresses := map[netip.Addr]bool{
			netip.MustParseAddr("192.0.2.1"):    true,
			netip.MustParseAddr("192.0.2.10"):   true,
			netip.MustParseAddr("2001:db8::10"): true,
			netip.MustParseAddr("192.0.2.20"):   true,
		}
		for index, line := range strings.Split(string(rowBytes), "\n") {
			if fuzzAnswerRowMaxCount <= index {
				break
			}
			set, ok := parseFuzzAnswerRow(line)
			if !ok {
				continue
			}
			next, err := view.Apply([]DnsJournalRow{{
				Format:  DnsFormat,
				Root:    testRoot,
				Serial:  view.Serial() + 1,
				Upserts: []DnsRecordSet{*set},
			}})
			if err != nil {
				if next != nil {
					t.Fatalf("a refused row made a view: %v", err)
				}
				continue
			}
			view = next
			if set.Kind != DnsRecordKindUser {
				for _, rdata := range set.Rdata {
					if address, err := netip.ParseAddr(rdata); err == nil {
						systemAddresses[address.Unmap()] = true
					}
				}
			}
		}

		message := &dns.Msg{}
		if err := message.Unpack(queryBytes); err != nil {
			return
		}
		for _, tcp := range []bool{false, true} {
			query := &DnsQuery{Message: message, Tcp: tcp}
			reply := Answer(query, view, healthy)
			if message.Response {
				if reply != nil {
					t.Fatalf("a response was answered: %+v", reply)
				}
				continue
			}
			if reply == nil {
				t.Fatal("no reply")
			}
			packed, err := reply.Pack()
			if err != nil {
				t.Fatalf("the reply does not pack: %v", err)
			}
			if limit := dnsAnswerLimit(query, message.IsEdns0(), view.settings); limit < len(packed) {
				t.Fatalf("%d bytes past %d", len(packed), limit)
			}
			cnameCount := 0
			for _, record := range reply.Answer {
				var ip []byte
				switch typed := record.(type) {
				case *dns.A:
					ip = typed.A
				case *dns.AAAA:
					ip = typed.AAAA
				case *dns.CNAME:
					cnameCount += 1
				}
				if ip != nil {
					address, ok := netip.AddrFromSlice(ip)
					if !ok {
						t.Fatalf("record %v", record)
					}
					if !isPublicDnsAddress(address) && !systemAddresses[address.Unmap()] {
						t.Fatalf("a user's address reached an answer: %v", record)
					}
				}
				if isRefusedUserType(record.Header().Rrtype) && dns.CanonicalName(record.Header().Name) != testRoot {
					if kind := fuzzAnswerKindOf(view, record); kind == DnsRecordKindUser {
						t.Fatalf("a type refused to users reached an answer: %v", record)
					}
				}
			}
			if view.settings.CnameChainMaxCount < cnameCount {
				t.Fatalf("%d CNAMEs in one answer", cnameCount)
			}
		}
	})
}

// The kind of the row that gave record, read from the view: what tells a canary's CAA from a user's.
func fuzzAnswerKindOf(view *ZoneView, record dns.RR) DnsRecordKind {
	match := view.match(dns.CanonicalName(record.Header().Name))
	if match.node == nil {
		return ""
	}
	index, found := match.node.rrsetIndex(record.Header().Rrtype)
	if !found {
		return ""
	}
	return match.node.rrsets[index].set.Kind
}
