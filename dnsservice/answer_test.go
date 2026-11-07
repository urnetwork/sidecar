package dnsservice

import (
	"bytes"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// Valid settings for testRoot.
func answerTestSettings(t testing.TB) *DnsSettings {
	t.Helper()
	settings := DefaultDnsSettings()
	settings.Roots = []string{testRoot}
	settings.SignaturesPerSecond = 1
	settings.Tcp.ConnectionsPerSource = 1
	settings.Rrl.ResponsesPerSecond = 1
	if err := settings.Validate(); err != nil {
		t.Fatal(err)
	}
	return settings
}

// A view at serial holding sets.
func newTestView(t testing.TB, serial uint64, sets ...DnsRecordSet) *ZoneView {
	t.Helper()
	snapshot := DnsSnapshot{Format: DnsFormat, Root: testRoot, Serial: serial}
	view, err := NewZoneView(answerTestSettings(t), NewDnsSnapshotRows(snapshot, sets))
	if err != nil {
		t.Fatal(err)
	}
	return view
}

// The rows every test zone needs to answer at all.
func testApexRows() []DnsRecordSet {
	return []DnsRecordSet{
		{Owner: testRoot, Type: dns.TypeSOA, Ttl: 3600, Kind: DnsRecordKindSystem, Rdata: []string{"ns1.zone.example. hostmaster.zone.example. 1 7200 3600 1209600 60"}},
	}
}

// One query the way a resolver sends it, with EDNS.
func testQuery(name string, rrType uint16) *dns.Msg {
	query := &dns.Msg{}
	query.Id = 4242
	query.SetQuestion(name, rrType)
	return query
}

// What the view answers name with, by UDP with no EDNS.
func testAnswer(t testing.TB, view *ZoneView, healthy *HealthySet, name string, rrType uint16) *dns.Msg {
	t.Helper()
	reply := Answer(&DnsQuery{Message: testQuery(name, rrType)}, view, healthy)
	if reply == nil {
		t.Fatalf("%s: no reply", name)
	}
	return reply
}

// The records of a section as one normalized line each.
func recordLines(records []dns.RR) []string {
	lines := []string{}
	for _, record := range records {
		lines = append(lines, strings.Join(strings.Fields(record.String()), " "))
	}
	return lines
}

// testdata/dns/answers/vectors.json.
type answerVectors struct {
	Root   string       `json:"root"`
	Serial uint64       `json:"serial"`
	Rows   []string     `json:"rows"`
	Steps  []answerStep `json:"steps"`
}

type answerStep struct {
	Name    string         `json:"name"`
	Healthy *answerHealthy `json:"healthy"`
	Apply   *answerApply   `json:"apply"`
	Cases   []answerCase   `json:"cases"`
}

type answerHealthy struct {
	Edge   []string `json:"edge"`
	Router []string `json:"router"`
}

type answerApply struct {
	Upserts []string `json:"upserts"`
	Deletes []string `json:"deletes"`
}

type answerCase struct {
	Name        string   `json:"name"`
	Query       string   `json:"query"`
	Class       string   `json:"class"`
	Edns        *uint16  `json:"edns"`
	EdnsVersion uint8    `json:"edns_version"`
	Ecs         string   `json:"ecs"`
	Tcp         bool     `json:"tcp"`
	Rcode       string   `json:"rcode"`
	Tc          bool     `json:"tc"`
	Answer      []string `json:"answer"`
	AnswerCount *int     `json:"answer_count"`
	Authority   []string `json:"authority"`
}

// Rows in the vectors' form, those of one key as one RRset.
func parseVectorRows(t *testing.T, lines []string) []DnsRecordSet {
	t.Helper()
	sets := []DnsRecordSet{}
	for _, line := range lines {
		fields := strings.SplitN(line, " ", 5)
		if len(fields) < 3 {
			t.Fatalf("row %q", line)
		}
		ttl, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			t.Fatalf("row %q: %v", line, err)
		}
		set := DnsRecordSet{Owner: fields[0], Ttl: uint32(ttl), Kind: DnsRecordKind(fields[2])}
		if 3 < len(fields) {
			rrType, ok := dns.StringToType[fields[3]]
			if !ok {
				t.Fatalf("row %q: no such type", line)
			}
			set.Type = rrType
		}
		if 4 < len(fields) {
			set.Rdata = []string{fields[4]}
		}
		index := slices.IndexFunc(sets, func(other DnsRecordSet) bool { return other.Key() == set.Key() })
		if index < 0 {
			sets = append(sets, set)
		} else {
			sets[index].Rdata = append(sets[index].Rdata, set.Rdata...)
		}
	}
	return sets
}

func parseVectorDeletes(t *testing.T, lines []string) []DnsRecordKey {
	t.Helper()
	keys := []DnsRecordKey{}
	for _, line := range lines {
		owner, typeText, _ := strings.Cut(line, " ")
		rrType := DnsCopyType
		if typeText != "COPY" {
			var ok bool
			rrType, ok = dns.StringToType[typeText]
			if !ok {
				t.Fatalf("delete %q: no such type", line)
			}
		}
		keys = append(keys, DnsRecordKey{Owner: owner, Type: rrType})
	}
	return keys
}

// The query a case describes.
func vectorQuery(t *testing.T, c *answerCase) *DnsQuery {
	t.Helper()
	name, typeText, _ := strings.Cut(c.Query, " ")
	rrType, ok := dns.StringToType[typeText]
	if !ok {
		t.Fatalf("%s: no such type %q", c.Name, typeText)
	}
	message := testQuery(name, rrType)
	if c.Class != "" {
		class, ok := dns.StringToClass[c.Class]
		if !ok {
			t.Fatalf("%s: no such class %q", c.Name, c.Class)
		}
		message.Question[0].Qclass = class
	}
	if c.Edns != nil {
		message.SetEdns0(*c.Edns, false)
		opt := message.IsEdns0()
		opt.SetVersion(c.EdnsVersion)
		if c.Ecs != "" {
			prefix := netip.MustParsePrefix(c.Ecs)
			opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
				Code:          dns.EDNS0SUBNET,
				Family:        1,
				SourceNetmask: uint8(prefix.Bits()),
				Address:       net.IP(prefix.Addr().AsSlice()),
			})
		}
	}
	return &DnsQuery{Message: message, Tcp: c.Tcp}
}

func wantLines(t *testing.T, name string, section string, got []string, want []string) {
	t.Helper()
	if !slices.Equal(got, want) && (len(got) != 0 || len(want) != 0) {
		t.Errorf("%s: %s\n got %q\nwant %q", name, section, got, want)
	}
}

// Everything every reply must be, whatever the case wants of it.
func wantReplyShape(t *testing.T, name string, query *DnsQuery, reply *dns.Msg, settings *DnsSettings) {
	t.Helper()
	request := query.Message
	if reply.Id != request.Id || !reply.Response || reply.RecursionAvailable || reply.Opcode != request.Opcode {
		t.Errorf("%s: header %+v", name, reply.MsgHdr)
	}
	if reply.RecursionDesired != request.RecursionDesired || reply.CheckingDisabled != request.CheckingDisabled {
		t.Errorf("%s: flags %+v", name, reply.MsgHdr)
	}
	if !slices.Equal(reply.Question, request.Question) {
		t.Errorf("%s: question %v", name, reply.Question)
	}
	wantAuthoritative := reply.Rcode == dns.RcodeSuccess || reply.Rcode == dns.RcodeNameError
	if reply.Authoritative != wantAuthoritative {
		t.Errorf("%s: AA %v under %s", name, reply.Authoritative, dnsRcodeLabel(reply.Rcode))
	}
	if request.IsEdns0() == nil {
		if len(reply.Extra) != 0 {
			t.Errorf("%s: extra %v with no OPT in the query", name, reply.Extra)
		}
	} else {
		opt := reply.IsEdns0()
		if len(reply.Extra) != 1 || opt == nil {
			t.Fatalf("%s: extra %v", name, reply.Extra)
		}
		if int(opt.UDPSize()) != settings.EdnsUdpSize || len(opt.Option) != 0 || opt.Version() != 0 {
			t.Errorf("%s: opt %v", name, opt)
		}
	}
	packed, err := reply.Pack()
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	limit := dnsAnswerLimit(query, request.IsEdns0(), settings)
	if limit < len(packed) {
		t.Errorf("%s: %d bytes past %d", name, len(packed), limit)
	}
}

func TestAnswerVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "dns", "answers", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	vectors := &answerVectors{}
	if err := json.Unmarshal(data, vectors); err != nil {
		t.Fatal(err)
	}
	settings := answerTestSettings(t)
	snapshot := DnsSnapshot{Format: DnsFormat, Root: vectors.Root, Serial: vectors.Serial}
	view, err := NewZoneView(settings, NewDnsSnapshotRows(snapshot, parseVectorRows(t, vectors.Rows)))
	if err != nil {
		t.Fatal(err)
	}
	var healthy *HealthySet
	for _, step := range vectors.Steps {
		if step.Apply != nil {
			view, err = view.Apply([]DnsJournalRow{{
				Format:  DnsFormat,
				Root:    vectors.Root,
				Serial:  view.Serial() + 1,
				Upserts: parseVectorRows(t, step.Apply.Upserts),
				Deletes: parseVectorDeletes(t, step.Apply.Deletes),
			}})
			if err != nil {
				t.Fatalf("%s: %v", step.Name, err)
			}
		}
		if step.Healthy != nil {
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
			healthy = NewHealthySet(interfaces(step.Healthy.Edge), interfaces(step.Healthy.Router))
		}

		// the other NS: the same rows reached by a snapshot, in another order, on a trie of another seed
		rows := slices.Collect(view.Rows())
		sets := make([]DnsRecordSet, 0, len(rows))
		for _, row := range slices.Backward(rows) {
			sets = append(sets, row.Clone())
		}
		rebuilt, err := NewZoneView(settings, NewDnsSnapshotRows(DnsSnapshot{Format: DnsFormat, Root: vectors.Root, Serial: view.Serial()}, sets))
		if err != nil {
			t.Fatalf("%s: %v", step.Name, err)
		}

		for index := range step.Cases {
			c := &step.Cases[index]
			name := step.Name + ": " + c.Name
			query := vectorQuery(t, c)
			reply := Answer(query, view, healthy)
			if reply == nil {
				t.Errorf("%s: no reply", name)
				continue
			}
			wantReplyShape(t, name, query, reply, settings)
			if label := dnsRcodeLabel(reply.Rcode); label != c.Rcode {
				t.Errorf("%s: rcode %s, want %s", name, label, c.Rcode)
			}
			if reply.Truncated != c.Tc {
				t.Errorf("%s: TC %v", name, reply.Truncated)
			}
			if c.AnswerCount != nil {
				if len(reply.Answer) != *c.AnswerCount {
					t.Errorf("%s: %d answers", name, len(reply.Answer))
				}
			} else {
				wantLines(t, name, "answer", recordLines(reply.Answer), c.Answer)
			}
			wantLines(t, name, "authority", recordLines(reply.Ns), c.Authority)

			packed, err := reply.Pack()
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			rebuiltPacked, err := Answer(query, rebuilt, healthy).Pack()
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if !bytes.Equal(packed, rebuiltPacked) {
				t.Errorf("%s: a rebuilt view answers other bytes", name)
			}
		}
	}
}

func TestAnswerRefusesOpcodesOtherThanQuery(t *testing.T) {
	view := newTestView(t, 1, testApexRows()...)
	for _, opcode := range []int{dns.OpcodeIQuery, dns.OpcodeStatus, dns.OpcodeNotify, dns.OpcodeUpdate, 15} {
		query := testQuery(testRoot, dns.TypeSOA)
		query.Opcode = opcode
		reply := Answer(&DnsQuery{Message: query}, view, nil)
		if reply.Rcode != dns.RcodeNotImplemented || reply.Authoritative || len(reply.Answer) != 0 || reply.Opcode != opcode {
			t.Errorf("opcode %d: %+v", opcode, reply)
		}
	}
}

// A response is never answered, or two servers could answer each other for ever.
func TestAnswerStaysSilentForAResponse(t *testing.T) {
	view := newTestView(t, 1, testApexRows()...)
	query := testQuery(testRoot, dns.TypeSOA)
	query.Response = true
	if reply := Answer(&DnsQuery{Message: query}, view, nil); reply != nil {
		t.Errorf("reply %+v", reply)
	}
	if reply := Answer(&DnsQuery{}, view, nil); reply != nil {
		t.Errorf("a missing message: reply %+v", reply)
	}
}

func TestAnswerRefusesAQuestionCountOtherThanOne(t *testing.T) {
	view := newTestView(t, 1, testApexRows()...)
	none := testQuery(testRoot, dns.TypeSOA)
	none.Question = nil
	two := testQuery(testRoot, dns.TypeSOA)
	two.Question = append(two.Question, two.Question[0])
	for _, query := range []*dns.Msg{none, two} {
		reply := Answer(&DnsQuery{Message: query}, view, nil)
		if reply.Rcode != dns.RcodeFormatError || len(reply.Answer) != 0 || len(reply.Question) != 0 {
			t.Errorf("%d questions: %+v", len(query.Question), reply)
		}
	}
}

// RFC 6891 §6.1.1: one OPT, at the root.
func TestAnswerRefusesABadOpt(t *testing.T) {
	view := newTestView(t, 1, testApexRows()...)
	two := testQuery(testRoot, dns.TypeSOA)
	two.SetEdns0(1232, false)
	two.SetEdns0(1232, false)
	named := testQuery(testRoot, dns.TypeSOA)
	named.SetEdns0(1232, false)
	named.IsEdns0().Hdr.Name = testRoot
	for _, query := range []*dns.Msg{two, named} {
		reply := Answer(&DnsQuery{Message: query}, view, nil)
		if reply.Rcode != dns.RcodeFormatError || len(reply.Answer) != 0 {
			t.Errorf("reply %+v", reply)
		}
	}
}

func TestAnswerBadversPacksItsExtendedRcode(t *testing.T) {
	view := newTestView(t, 1, testApexRows()...)
	query := testQuery(testRoot, dns.TypeSOA)
	query.SetEdns0(1232, false)
	query.IsEdns0().SetVersion(1)
	reply := Answer(&DnsQuery{Message: query}, view, nil)
	packed, err := reply.Pack()
	if err != nil {
		t.Fatal(err)
	}
	unpacked := &dns.Msg{}
	if err := unpacked.Unpack(packed); err != nil {
		t.Fatal(err)
	}
	if unpacked.Rcode != dns.RcodeBadVers || unpacked.IsEdns0() == nil || unpacked.IsEdns0().Version() != 0 {
		t.Errorf("reply %+v", unpacked)
	}
}

// RFC 3225 §3 and RFC 4035 §3.1.6: DO and CD come back as they went, and RD by RFC 1035.
func TestAnswerCopiesDoCdAndRd(t *testing.T) {
	view := newTestView(t, 1, testApexRows()...)
	for _, flag := range []bool{false, true} {
		query := testQuery(testRoot, dns.TypeSOA)
		query.RecursionDesired = flag
		query.CheckingDisabled = flag
		query.SetEdns0(1232, flag)
		reply := Answer(&DnsQuery{Message: query}, view, nil)
		if reply.RecursionDesired != flag || reply.CheckingDisabled != flag || reply.IsEdns0().Do() != flag {
			t.Errorf("flag %v: %+v", flag, reply)
		}
	}
}

// An edge with no view has nothing to serve, and still gives a well-formed refusal.
func TestAnswerWithNoViewRefuses(t *testing.T) {
	query := testQuery(testRoot, dns.TypeSOA)
	query.SetEdns0(1232, false)
	reply := Answer(&DnsQuery{Message: query}, nil, nil)
	if reply.Rcode != dns.RcodeRefused || reply.Authoritative {
		t.Errorf("reply %+v", reply)
	}
	if _, err := reply.Pack(); err != nil {
		t.Error(err)
	}
}

// With no SOA there is nothing a denial can stand on, so nothing is answered as if it were known.
func TestAnswerWithNoSoaFails(t *testing.T) {
	view := newTestView(t, 1, DnsRecordSet{Owner: "a.zone.example.", Type: dns.TypeTXT, Ttl: 60, Kind: DnsRecordKindSystem, Rdata: []string{`"one"`}})
	for _, name := range []string{"a.zone.example.", "b.zone.example.", testRoot} {
		reply := testAnswer(t, view, nil, name, dns.TypeTXT)
		if reply.Rcode != dns.RcodeServerFailure || len(reply.Answer) != 0 || reply.Authoritative {
			t.Errorf("%s: %+v", name, reply)
		}
	}
}

// R-DNS-7: the SOA's MINIMUM and a denial's TTL stay at or under the setting whatever the row says,
// and a shorter row keeps its own.
func TestAnswerHoldsTheDenialTtl(t *testing.T) {
	cases := []struct {
		rowTtl     uint32
		rowMinimum uint32
		wantTtl    uint32
		wantMin    uint32
	}{
		{rowTtl: 3600, rowMinimum: 86400, wantTtl: 60, wantMin: 60},
		{rowTtl: 3600, rowMinimum: 30, wantTtl: 30, wantMin: 30},
		{rowTtl: 10, rowMinimum: 60, wantTtl: 10, wantMin: 60},
	}
	for _, c := range cases {
		view := newTestView(t, 1, DnsRecordSet{
			Owner: testRoot, Type: dns.TypeSOA, Ttl: c.rowTtl, Kind: DnsRecordKindSystem,
			Rdata: []string{"ns1.zone.example. hostmaster.zone.example. 1 7200 3600 1209600 " + strconv.Itoa(int(c.rowMinimum))},
		})
		reply := testAnswer(t, view, nil, "nosuch.zone.example.", dns.TypeA)
		soa, ok := reply.Ns[0].(*dns.SOA)
		if !ok || reply.Rcode != dns.RcodeNameError {
			t.Fatalf("reply %+v", reply)
		}
		if soa.Hdr.Ttl != c.wantTtl || soa.Minttl != c.wantMin {
			t.Errorf("row %d %d: ttl %d, minimum %d", c.rowTtl, c.rowMinimum, soa.Hdr.Ttl, soa.Minttl)
		}
	}
}

// Plan reading 4: the SOA carries a serial's low 32 bits.
func TestAnswerSoaCarriesLowBitsOfTheSerial(t *testing.T) {
	view := newTestView(t, 1<<32+7, testApexRows()...)
	reply := testAnswer(t, view, nil, testRoot, dns.TypeSOA)
	if soa, ok := reply.Answer[0].(*dns.SOA); !ok || soa.Serial != 7 {
		t.Errorf("answer %v", reply.Answer)
	}
}

// One query at one serial gives the same bytes each time, and answering changes nothing.
func TestAnswerIsPure(t *testing.T) {
	sets := append(testApexRows(), DnsRecordSet{Owner: "*.zone.example.", Type: dns.TypeA, Ttl: 60, Kind: DnsRecordKindEdge})
	view := newTestView(t, 1, sets...)
	healthy := NewHealthySet([]DnsLbInterface{{Ipv4: netip.MustParseAddr("192.0.2.10")}}, nil)
	query := testQuery("a.zone.example.", dns.TypeA)
	query.SetEdns0(1232, true)
	before, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	first, err := Answer(&DnsQuery{Message: query}, view, healthy).Pack()
	if err != nil {
		t.Fatal(err)
	}
	second, err := Answer(&DnsQuery{Message: query}, view, healthy).Pack()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Error("two answers differ")
	}
	after, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("answering changed the query")
	}
}

// A reply is the caller's to change: a signer sets TTLs and owners on what it gets.
func TestAnswerSharesNothingWithTheView(t *testing.T) {
	sets := append(testApexRows(), DnsRecordSet{Owner: "a.zone.example.", Type: dns.TypeTXT, Ttl: 60, Kind: DnsRecordKindSystem, Rdata: []string{`"one"`}})
	view := newTestView(t, 1, sets...)
	reply := testAnswer(t, view, nil, "a.zone.example.", dns.TypeTXT)
	reply.Answer[0].Header().Ttl = 1
	reply.Answer[0].(*dns.TXT).Txt[0] = "changed"
	denial := testAnswer(t, view, nil, "b.zone.example.", dns.TypeA)
	denial.Ns[0].Header().Ttl = 1
	denial.Ns[0].(*dns.SOA).Ns = "changed."

	reply = testAnswer(t, view, nil, "a.zone.example.", dns.TypeTXT)
	if txt := reply.Answer[0].(*dns.TXT); txt.Hdr.Ttl != 60 || txt.Txt[0] != "one" {
		t.Errorf("record %v", txt)
	}
	denial = testAnswer(t, view, nil, "b.zone.example.", dns.TypeA)
	if soa := denial.Ns[0].(*dns.SOA); soa.Hdr.Ttl == 1 || soa.Ns == "changed." {
		t.Errorf("soa %v", soa)
	}
}

// Past the setting's bound a chain stops, for the resolver to go on with.
func TestAnswerStopsALongCnameChain(t *testing.T) {
	sets := testApexRows()
	for index := range 20 {
		sets = append(sets, DnsRecordSet{
			Owner: "c" + strconv.Itoa(index) + ".zone.example.", Type: dns.TypeCNAME, Ttl: 60, Kind: DnsRecordKindSystem,
			Rdata: []string{"c" + strconv.Itoa(index+1) + ".zone.example."},
		})
	}
	view := newTestView(t, 1, sets...)
	reply := testAnswer(t, view, nil, "c0.zone.example.", dns.TypeA)
	if len(reply.Answer) != view.settings.CnameChainMaxCount || reply.Rcode != dns.RcodeSuccess || len(reply.Ns) != 0 {
		t.Errorf("%d answers, rcode %d, authority %v", len(reply.Answer), reply.Rcode, reply.Ns)
	}
}

// A query name holding escapes reads as labels, so a label holding a dot is one label and not a way
// into the root, or out of the walk.
func TestAnswerReadsEscapedQueryNames(t *testing.T) {
	sets := append(testApexRows(),
		DnsRecordSet{Owner: "*.net1.zone.example.", Type: dns.TypeA, Ttl: 60, Kind: DnsRecordKindSystem, Rdata: []string{"192.0.2.10"}},
		DnsRecordSet{Owner: "net1.zone.example.", Type: dns.TypeTXT, Ttl: 60, Kind: DnsRecordKindSystem, Rdata: []string{`"one"`}},
	)
	view := newTestView(t, 1, sets...)
	reply := testAnswer(t, view, nil, `a\.b.net1.zone.example.`, dns.TypeA)
	if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 1 || reply.Answer[0].Header().Name != `a\.b.net1.zone.example.` {
		t.Errorf("reply %+v", reply)
	}
	if reply := testAnswer(t, view, nil, `a\.zone.example.`, dns.TypeA); reply.Rcode != dns.RcodeRefused {
		t.Errorf("a label ending like the root: %+v", reply)
	}
	reply = testAnswer(t, view, nil, `\046.zone.example.`, dns.TypeA)
	if reply.Rcode != dns.RcodeNameError {
		t.Errorf("a label of one dot: %+v", reply)
	}
}

// A type nothing stores, the copy row's among them, is a name with no data of it.
func TestAnswerHasNoDataForTypesNoRowHolds(t *testing.T) {
	sets := append(testApexRows(), DnsRecordSet{Owner: "blog.zone.example.", Kind: DnsRecordKindCopy})
	view := newTestView(t, 1, sets...)
	for _, rrType := range []uint16{DnsCopyType, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY, dns.TypeOPT, dns.TypeTSIG, 65280} {
		reply := testAnswer(t, view, nil, "blog.zone.example.", rrType)
		if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 0 || len(reply.Ns) != 1 {
			t.Errorf("type %d: %+v", rrType, reply)
		}
	}
}
