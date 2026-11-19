package sidecartest

// CC4's M5 sources and the certificate rows (privacy_edges.go; TEST-M5-01): each source catches a leak through each of
// its paths in each form a leak takes, a clean world reads clean, a record's every field is read, a Find passes
// through its transport unchanged, the upstream resolver and a dns edge hold every query sent them, and the
// certificate rows fail each planted violation and pass a world that keeps them.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	stdnet "net"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/dnsservice"
	"github.com/urnetwork/sidecar/mxedgeservice"
	"github.com/urnetwork/sidecar/smtpedgeservice"
	"github.com/urnetwork/sidecar/tlsedgeservice"
)

// A sockets service for a Find's transport: it reads the request and answers with answer.
type edgeFindService struct {
	answer   []byte
	received [][]byte
}

func (self *edgeFindService) RoundTrip(request *http.Request) (*http.Response, error) {
	body := []byte{}
	if request.Body != nil {
		read, err := io.ReadAll(request.Body)
		request.Body.Close()
		if err != nil {
			return nil, err
		}
		body = read
	}
	self.received = append(self.received, body)
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(self.answer)), Request: request}, nil
}

// One path into a class: what a bug that put value there would do.
type edgeSourcePath struct {
	name  string
	class PrivacyClass
	// The path puts the value inside text of its own, where no scan opens a stream with no magic.
	embeds bool
	put    func(t *testing.T, net *Net, value []byte)
}

func edgeSourcePaths() []*edgeSourcePath {
	post := func(t *testing.T, net *Net, service *edgeFindService, body []byte) {
		client := &http.Client{Transport: net.Capture().Finds("tlsedge1").Transport(service)}
		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://sockets.example/socket/find", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
	}
	return []*edgeSourcePath{
		{name: "a tls record's host", class: PrivacyClassEdgeRecord, put: func(t *testing.T, net *Net, value []byte) {
			store := NewFakeTlsEdgeStore(nil)
			net.Capture().AddTlsEdgeRecords("tlsedge1", store)
			record := &tlsedgeservice.TlsConnectionRecord{ConnectionId: sidecar.NewId(), NetworkId: sidecar.NewId(), Host: string(value), StartTime: net.Clock().Now(), ByteCount: 7}
			if err := store.InsertConnectionRecords(t.Context(), []*tlsedgeservice.TlsConnectionRecord{record}); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a tls record's visitor hash", class: PrivacyClassEdgeRecord, put: func(t *testing.T, net *Net, value []byte) {
			store := NewFakeTlsEdgeStore(nil)
			net.Capture().AddTlsEdgeRecords("tlsedge1", store)
			record := &tlsedgeservice.TlsConnectionRecord{ConnectionId: sidecar.NewId(), NetworkId: sidecar.NewId(), Host: "@", VisitorHash: value}
			if err := store.InsertConnectionRecords(t.Context(), []*tlsedgeservice.TlsConnectionRecord{record}); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "an mx record's result", class: PrivacyClassEdgeRecord, put: func(t *testing.T, net *Net, value []byte) {
			store := NewFakeMxEdgeStore(nil)
			net.Capture().AddMxEdgeRecords("mxedge1", store)
			record := &mxedgeservice.MxConnectionRecord{NetworkId: sidecar.NewId(), StartTime: net.Clock().Now(), Result: string(value)}
			if err := store.InsertConnectionRecords(t.Context(), []*mxedgeservice.MxConnectionRecord{record}); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a complaint's feedback id", class: PrivacyClassReportParse, put: func(t *testing.T, net *Net, value []byte) {
			store := NewFakeSmtpEdgeStore(net.Clock(), nil)
			net.Capture().AddReportParse("mxedge1", store, nil)
			complaint := &smtpedgeservice.SmtpComplaint{ComplaintId: sidecar.NewId(), NetworkId: sidecar.NewId(), Reporter: "loop.example", FeedbackId: string(value)}
			if err := store.InsertComplaint(t.Context(), complaint); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "an aggregate's counted domain", class: PrivacyClassReportParse, put: func(t *testing.T, net *Net, value []byte) {
			store := NewFakeSmtpEdgeStore(net.Clock(), nil)
			net.Capture().AddReportParse("mxedge1", store, nil)
			report := &smtpedgeservice.SmtpAggregateReport{Reporter: "reporter.example", ReportId: "r1", Counts: []*smtpedgeservice.SmtpAggregateCount{{Domain: string(value)}}}
			if _, err := store.InsertAggregate(t.Context(), report); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a case report's domain", class: PrivacyClassReportParse, put: func(t *testing.T, net *Net, value []byte) {
			sink := NewFakeSmtpAbuseSink()
			net.Capture().AddReportParse("mxedge1", nil, sink)
			if err := sink.OpenSmtpCase(t.Context(), &smtpedgeservice.SmtpAbuseReport{ComplaintId: sidecar.NewId(), NetworkId: sidecar.NewId(), Domain: string(value)}); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a find's name, as its caller made it", class: PrivacyClassFind, put: func(t *testing.T, net *Net, value []byte) {
			networkId := connect.NewId()
			net.Capture().Finds("a sidecar").Add(&sidecar.SocketFindArgs{NetworkId: &networkId, Name: string(value)}, &sidecar.SocketFindResult{})
		}},
		{name: "a find answer's claim, as its caller read it", class: PrivacyClassFind, put: func(t *testing.T, net *Net, value []byte) {
			networkId := connect.NewId()
			result := &sidecar.SocketFindResult{Primary: &sidecar.SocketFindTicket{Ticket: []byte("ticket"), Claim: value}}
			net.Capture().Finds("a sidecar").Add(&sidecar.SocketFindArgs{NetworkId: &networkId, NameToken: []byte("token")}, result)
		}},
		{name: "a find's body over its transport", class: PrivacyClassFind, embeds: true, put: func(t *testing.T, net *Net, value []byte) {
			post(t, net, &edgeFindService{answer: []byte(`{}`)}, slices.Concat([]byte(`{"name":"`), value, []byte(`"}`)))
		}},
		{name: "a find's answer over its transport", class: PrivacyClassFind, put: func(t *testing.T, net *Net, value []byte) {
			post(t, net, &edgeFindService{answer: value}, []byte(`{"name":"tls/443"}`))
		}},
		{name: "a query to a dns edge over a connection", class: PrivacyClassDnsEdgeQuery, put: func(t *testing.T, net *Net, value []byte) {
			querier, edge := stdnet.Pipe()
			read := make(chan struct{})
			go func() {
				defer close(read)
				io.Copy(io.Discard, edge)
			}()
			conn := net.Capture().DnsEdgeQueries("dns").WrapConn("ns1", querier)
			if _, err := conn.Write(value); err != nil {
				t.Fatal(err)
			}
			conn.Close()
			<-read
			edge.Close()
		}},
		{name: "a datagram to a dns edge", class: PrivacyClassDnsEdgeQuery, put: func(t *testing.T, net *Net, value []byte) {
			net.Capture().DnsEdgeQueries("dns").AddDatagram("ns1", value)
		}},
		{name: "a query to the upstream resolver", class: PrivacyClassUpstreamResolver, put: func(t *testing.T, net *Net, value []byte) {
			NewFakeUpstreamResolver(net, "the host's resolver").Resolve(t.Context(), value)
		}},
	}
}

// An M5 class's leak for TestEachCaptureClassNamesItsLeak: the canary through every path into the class.
func leakThroughEdgeSource(class PrivacyClass) func(t *testing.T, net *Net, canary string) {
	return func(t *testing.T, net *Net, canary string) {
		for _, path := range edgeSourcePaths() {
			if path.class == class {
				path.put(t, net, []byte(canary))
			}
		}
	}
}

// Each path into each M5 class catches a canary put through it, in every form the self-test's leaks take, under its
// own class; and the M5 classes are registered, each covered by a path here.
func TestEdgeSourcesCatchEachPathsLeakInEachForm(t *testing.T) {
	paths := edgeSourcePaths()
	for _, class := range PrivacyEdgeClasses() {
		if !slices.Contains(PrivacyClasses(), class) {
			t.Errorf("%s is not registered", class)
		}
		if !slices.ContainsFunc(paths, func(path *edgeSourcePath) bool { return path.class == class }) {
			t.Errorf("%s has no path here", class)
		}
	}
	ran := 0
	for _, path := range paths {
		for _, encoding := range leakEncodings(t) {
			if path.embeds && (encoding.name == "deflate" || encoding.name == "brotli") {
				continue
			}
			func() {
				net := NewNet(t.Context(), nil)
				defer net.Close()
				text := net.Capture().CanaryText("leak")
				body, err := canaryTextEncoding.DecodeString(text)
				if err != nil {
					t.Fatal(err)
				}
				path.put(t, net, encoding.encode(body, text))
				ran += 1
				caught := false
				for _, finding := range net.Capture().Scan() {
					caught = caught || (finding.Needle == "leak" && finding.Class == path.class)
				}
				if !caught {
					t.Errorf("%s (%s) did not catch its leak as %s", path.name, path.class, encoding.name)
				}
			}()
		}
	}
	if ran < len(paths)*20 {
		t.Errorf("only %d leaks ran over %d paths", ran, len(paths))
	}
}

// With nothing planted where it must not be, every path holds an item and the scan finds nothing: the sources add no
// finding of their own.
func TestEdgeSourcesReadACleanWorldClean(t *testing.T) {
	net := NewNet(t.Context(), nil)
	defer net.Close()
	capture := net.Capture()
	capture.Canary("a mail body")
	capture.CanaryText("a socket name")
	for _, path := range edgeSourcePaths() {
		path.put(t, net, []byte("nothing a scan looks for"))
	}
	for _, class := range PrivacyEdgeClasses() {
		if capture.ItemCount(class) == 0 {
			t.Errorf("%s holds no item", class)
		}
	}
	for _, finding := range capture.Scan() {
		t.Errorf("a clean world: %s", finding)
	}
}

// Sets every string and byte-slice field reachable from value to a marker of its own, filling a nil pointer and giving
// an empty slice one element, and returns the markers.
func edgeMarkFields(value reflect.Value, path string, markers *[]string) {
	mark := func() string {
		marker := "marker-" + path + "-end"
		*markers = append(*markers, marker)
		return marker
	}
	switch value.Kind() {
	case reflect.Pointer:
		if value.IsNil() {
			value.Set(reflect.New(value.Type().Elem()))
		}
		edgeMarkFields(value.Elem(), path, markers)
	case reflect.String:
		value.SetString(mark())
	case reflect.Slice:
		if value.Type().Elem().Kind() == reflect.Uint8 {
			value.SetBytes([]byte(mark()))
			return
		}
		value.Set(reflect.MakeSlice(value.Type(), 2, 2))
		for index := 0; index < value.Len(); index += 1 {
			edgeMarkFields(value.Index(index), path+"["+string(rune('0'+index))+"]", markers)
		}
	case reflect.Struct:
		if value.Type() == privacyTimeType {
			return
		}
		for index := 0; index < value.NumField(); index += 1 {
			if field := value.Type().Field(index); field.IsExported() {
				edgeMarkFields(value.Field(index), path+"."+field.Name, markers)
			}
		}
	}
}

// Every string and byte-slice field of every record the sources read, at any depth, is an item of its own holding
// exactly that field, so a field a later change adds to a record is scanned with no change to the sources; ids,
// numbers and times ride in the record's one other item.
func TestEdgeRecordItemsHoldEveryField(t *testing.T) {
	for _, record := range []any{
		&tlsedgeservice.TlsConnectionRecord{}, &mxedgeservice.MxConnectionRecord{}, &smtpedgeservice.SmtpComplaint{},
		&smtpedgeservice.SmtpAggregateReport{}, &smtpedgeservice.SmtpAbuseReport{}, &sidecar.SocketFindArgs{}, &sidecar.SocketFindResult{},
	} {
		markers := []string{}
		edgeMarkFields(reflect.ValueOf(record), reflect.TypeOf(record).Elem().Name(), &markers)
		if len(markers) == 0 {
			t.Errorf("%T has no text field marked", record)
		}
		items := privacyRecordItems(PrivacyClassEdgeRecord, "record", record)
		for _, marker := range markers {
			if !slices.ContainsFunc(items, func(item *PrivacyItem) bool { return string(item.Body) == marker }) {
				t.Errorf("%T: no item holds exactly %s", record, marker)
			}
		}
		for _, item := range items {
			if item.Class != PrivacyClassEdgeRecord || !strings.HasPrefix(item.Name, "record") {
				t.Errorf("%T: an item named %q under %s", record, item.Name, item.Class)
			}
		}
	}

	// an id's bytes, a number and a time are in the record's other item
	networkId := sidecar.NewId()
	start := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	items := privacyRecordItems(PrivacyClassEdgeRecord, "record", &mxedgeservice.MxConnectionRecord{NetworkId: networkId, StartTime: start, ByteCount: 123456789})
	if len(items) != 1 {
		t.Fatalf("a record with no text holds %d items", len(items))
	}
	for _, want := range [][]byte{networkId[:], []byte("123456789"), []byte("2026-03-04T05:06:07Z")} {
		if !bytes.Contains(items[0].Body, want) {
			t.Errorf("the record's other item lacks %q", want)
		}
	}
	// a nil record, and one holding nothing, add nothing a scan could not read
	var none *tlsedgeservice.TlsConnectionRecord
	if items := privacyRecordItems(PrivacyClassEdgeRecord, "record", none); len(items) != 0 {
		t.Errorf("a nil record holds %d items", len(items))
	}
	// a map's keys and values are read, in one order
	mapped := privacyRecordItems(PrivacyClassEdgeRecord, "record", map[string][]string{"key-b": {"value-b"}, "key-a": {"value-a"}})
	bodies := []string{}
	for _, item := range mapped {
		bodies = append(bodies, string(item.Body))
	}
	if !slices.Equal(bodies, []string{"key-a", "value-a", "key-b", "value-b"}) {
		t.Errorf("a map reads %v", bodies)
	}
}

// A Find passes through its transport unchanged both ways, its url, body and answer captured and no header, and a
// call the service fails is still captured as sent.
func TestFindTransportCapturesACallAndChangesNothing(t *testing.T) {
	net := NewNet(t.Context(), nil)
	defer net.Close()
	capture := net.Capture()
	service := &edgeFindService{answer: []byte(`{"primary":{"ticket":"dGlja2V0","claim":"Y2xhaW0="}}`)}
	client := &http.Client{Transport: capture.Finds("tlsedge1").Transport(service)}
	sent := []byte(`{"network_id":"0f0e0d0c-0b0a-0908-0706-050403020100","name":"tls/443"}`)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://sockets.example/socket/find?probe=find-1", bytes.NewReader(sent))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer the-edge-service-token")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	answered, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || !bytes.Equal(answered, service.answer) {
		t.Errorf("the caller read %q, %v", answered, err)
	}
	if len(service.received) != 1 || !bytes.Equal(service.received[0], sent) {
		t.Errorf("the service received %q", service.received)
	}
	if count := capture.ItemCount(PrivacyClassFind); count != 3 {
		t.Errorf("one Find left %d items", count)
	}
	// the bearer travels in a header by design, which is not captured
	capture.Forbid("the edge's service token", []byte("the-edge-service-token"))
	for _, finding := range capture.Scan() {
		t.Errorf("%s", finding)
	}
	// its body, its url and its answer are
	for label, value := range map[string]string{"the find's name": "tls/443\"}", "the find's query": "probe=find-1", "the answer's ticket": "dGlja2V0"} {
		capture.Forbid(label, []byte(value))
	}
	found := map[string]bool{}
	for _, finding := range capture.Scan() {
		if finding.Class == PrivacyClassFind {
			found[finding.Needle] = true
		}
	}
	if len(found) != 3 {
		t.Errorf("the scan found %v of the call", found)
	}

	failing := &http.Client{Transport: capture.Finds("tlsedge2").Transport(&edgeFailingTransport{})}
	request, err = http.NewRequestWithContext(t.Context(), http.MethodPost, "http://sockets.example/socket/find", bytes.NewReader([]byte("a call nothing answered")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failing.Do(request); err == nil {
		t.Fatal("a failed call answered")
	}
	capture.Forbid("the unanswered find", []byte("a call nothing answered"))
	if !slices.ContainsFunc(capture.Scan(), func(finding *PrivacyFinding) bool {
		return finding.Needle == "the unanswered find" && finding.Class == PrivacyClassFind
	}) {
		t.Error("a Find the service failed was not captured")
	}
}

var errEdgeTransportDown = errors.New("the sockets service is down")

type edgeFailingTransport struct{}

func (self *edgeFailingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Body != nil {
		io.Copy(io.Discard, request.Body)
		request.Body.Close()
	}
	return nil, errEdgeTransportDown
}

func edgeQueryBytes(t *testing.T, name string, recordType uint16) []byte {
	t.Helper()
	query := &dns.Msg{}
	query.SetQuestion(dns.Fqdn(name), recordType)
	packed, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return packed
}

// The upstream resolver answers what a test set and NXDOMAIN otherwise, refuses what is no query, fails when told
// to, and holds every query it was sent whatever became of it: a private name passed to it is found there.
func TestFakeUpstreamResolverHoldsEveryQuery(t *testing.T) {
	net := NewNet(t.Context(), nil)
	defer net.Close()
	resolver := NewFakeUpstreamResolver(net, "the host's resolver")
	address, err := dns.NewRR("public.example. 300 IN A 192.0.2.7")
	if err != nil {
		t.Fatal(err)
	}
	resolver.SetAnswer(address)

	unpack := func(data []byte, err error) *dns.Msg {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		reply := &dns.Msg{}
		if err := reply.Unpack(data); err != nil {
			t.Fatal(err)
		}
		return reply
	}
	reply := unpack(resolver.Resolve(t.Context(), edgeQueryBytes(t, "Public.Example", dns.TypeA)))
	if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 1 || !reply.Response {
		t.Errorf("a set name answered %s", reply)
	}
	reply = unpack(resolver.Resolve(t.Context(), edgeQueryBytes(t, "public.example", dns.TypeAAAA)))
	if reply.Rcode != dns.RcodeNameError || len(reply.Answer) != 0 {
		t.Errorf("a type nothing was set for answered %s", reply)
	}
	if _, err := resolver.Resolve(t.Context(), []byte("no dns message")); !errors.Is(err, ErrFakeUpstreamMalformed) {
		t.Errorf("a malformed query: %v", err)
	}
	down := errors.New("the resolver is down")
	resolver.SetFailure(down)
	if _, err := resolver.Resolve(t.Context(), edgeQueryBytes(t, "later.example", dns.TypeA)); !errors.Is(err, down) {
		t.Errorf("a failed resolver: %v", err)
	}
	resolver.SetFailure(nil)
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := resolver.Resolve(canceled, edgeQueryBytes(t, "canceled.example", dns.TypeA)); !errors.Is(err, context.Canceled) {
		t.Errorf("a canceled query: %v", err)
	}

	if questions := resolver.Questions(); !slices.Equal(questions, []string{"public.example. A", "public.example. AAAA", "later.example. A", "canceled.example. A"}) {
		t.Errorf("questions %v", questions)
	}
	if len(resolver.Queries()) != 5 || !resolver.Asked("PUBLIC.example") || !resolver.Asked("later.example.") || resolver.Asked("never.example") {
		t.Errorf("%d queries, asked %v", len(resolver.Queries()), resolver.Questions())
	}
	if count := net.Capture().ItemCount(PrivacyClassUpstreamResolver); count != 5 {
		t.Errorf("the capture holds %d upstream queries", count)
	}
	for _, finding := range net.Capture().Scan() {
		t.Errorf("%s", finding)
	}

	// a private name must never be passed on: one that is, is found here
	privateLabel := net.Capture().CanaryText("a private name")
	if _, err := resolver.Resolve(t.Context(), edgeQueryBytes(t, privateLabel+".internal", dns.TypeA)); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(net.Capture().Scan(), func(finding *PrivacyFinding) bool {
		return finding.Needle == "a private name" && finding.Class == PrivacyClassUpstreamResolver && finding.Source == "the host's resolver"
	}) {
		t.Error("a private name passed to the upstream resolver was not found")
	}
	if !resolver.Asked(privateLabel + ".internal") {
		t.Error("the resolver does not say it was asked the private name")
	}
}

// Every query a harness's edge is sent is captured as it was sent, over TCP, through the harness's resolver and over
// UDP, whatever the edge answered: a private name queried at a dns edge is found under the dns edge's class, and the
// queries a test makes for its public names leave nothing the scan finds.
func TestDnsHarnessCapturesEveryEdgeQuery(t *testing.T) {
	net := newTestNet(t)
	harness := newTestDnsHarness(t, net, "dns")
	capture := net.Capture()
	if _, err := harness.WriteServed(t.Context(), &dnsservice.DnsZoneWrite{Upserts: harness.NetworkRows("", "net1")}); err != nil {
		t.Fatal(err)
	}
	capture.Canary("a mail body")
	if rcode, _ := dnsHarnessTestAnswer(t, harness, "ns1", "www.net1."+harness.Root(), dns.TypeA); rcode != dns.RcodeSuccess {
		t.Fatalf("a public name answered rcode %d", rcode)
	}
	if _, err := harness.Resolver("ns2").LookupHost(t.Context(), "www.net1."+harness.Root()); err != nil {
		t.Fatal(err)
	}
	if capture.ItemCount(PrivacyClassDnsEdgeQuery) < 2 {
		t.Fatalf("two queries left %d items", capture.ItemCount(PrivacyClassDnsEdgeQuery))
	}
	for _, finding := range capture.Scan() {
		if finding.Class == PrivacyClassDnsEdgeQuery {
			t.Errorf("a public name's query: %s", finding)
		}
	}

	for index, send := range []func(name string) error{
		func(name string) error {
			query := &dns.Msg{}
			query.SetQuestion(name, dns.TypeA)
			_, err := harness.Query(t.Context(), "ns1", query)
			return err
		},
		func(name string) error {
			query := &dns.Msg{}
			query.SetQuestion(name, dns.TypeAAAA)
			_, err := harness.QueryUdp(t.Context(), "ns2", query, netip.MustParseAddr("198.51.100.9"))
			// an edge that drops the datagram has read it all the same
			if errors.Is(err, ErrDnsHarnessNoAnswer) {
				return nil
			}
			return err
		},
		func(name string) error {
			// a name in no root: the lookup fails, and the edge was still asked
			harness.Resolver("ns1").LookupHost(t.Context(), name)
			return nil
		},
	} {
		kind := "a private name " + string(rune('a'+index))
		label := capture.CanaryText(kind)
		if err := send(label + ".net1." + harness.Root()); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if !slices.ContainsFunc(capture.Scan(), func(finding *PrivacyFinding) bool {
			return finding.Needle == kind && finding.Class == PrivacyClassDnsEdgeQuery
		}) {
			t.Errorf("%s queried at a dns edge was not found there", kind)
		}
	}
}

// A world for the certificate rows: one root, two networks, a Team scope under the first, and a key and certificate
// maker.
type edgeCertificateWorld struct {
	t      *testing.T
	world  *PrivacyCertificateWorld
	serial int64
}

const edgeCertificateRoot = "root.example"

func (self *edgeCertificateWorld) key() (*ecdsa.PrivateKey, []byte) {
	self.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		self.t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		self.t.Fatal(err)
	}
	sum := sha256.Sum256(spki)
	return key, sum[:]
}

// A certificate on key naming names, issued in the world.
func (self *edgeCertificateWorld) issue(key *ecdsa.PrivateKey, names ...string) *x509.Certificate {
	self.t.Helper()
	self.serial += 1
	template := &x509.Certificate{
		SerialNumber: big.NewInt(self.serial),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Unix(1_700_000_000, 0),
		NotAfter:     time.Unix(1_700_000_000, 0).Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		self.t.Fatal(err)
	}
	if err := self.world.AddIssued(der); err != nil {
		self.t.Fatal(err)
	}
	return self.world.Issued[len(self.world.Issued)-1]
}

// A device holding one key of its own.
func (self *edgeCertificateWorld) device(name string) (*PrivacyCertificateDevice, *ecdsa.PrivateKey) {
	key, spki := self.key()
	device := &PrivacyCertificateDevice{DeviceId: sidecar.NewId(), Name: name, KeySpkiSha256s: [][]byte{spki}}
	self.world.Devices = append(self.world.Devices, device)
	return device, key
}

// The world's fixtures as §13.8 would leave them: net1's two devices hold its pair, net2's one holds its, the Team
// scope eng.net1 holds its member's consented device's pair and its TLSA, and the platform holds a key with a
// certificate for its own host under the root.
type edgeCertificateParts struct {
	*edgeCertificateWorld
	net1A, net1B, net2A, engConsented, engUnconsented          *PrivacyCertificateDevice
	net1AKey, net1BKey, net2AKey, engConsentedKey, engOtherKey *ecdsa.PrivateKey
	platformKey                                                *ecdsa.PrivateKey
	platformSpki                                               []byte
	net1, net2, eng                                            *PrivacyCertificateScope
}

func newEdgeCertificateParts(t *testing.T) *edgeCertificateParts {
	parts := &edgeCertificateParts{edgeCertificateWorld: &edgeCertificateWorld{t: t, world: &PrivacyCertificateWorld{Root: edgeCertificateRoot, NetworkLabels: []string{"net1", "net2"}}}}
	parts.net1A, parts.net1AKey = parts.device("net1's laptop")
	parts.net1B, parts.net1BKey = parts.device("net1's desktop")
	parts.net2A, parts.net2AKey = parts.device("net2's laptop")
	parts.engConsented, parts.engConsentedKey = parts.device("the member's consented device")
	parts.engUnconsented, parts.engOtherKey = parts.device("the member's unconsented device")
	parts.net1 = &PrivacyCertificateScope{Host: "net1." + edgeCertificateRoot, DeviceIds: []sidecar.Id{parts.net1A.DeviceId, parts.net1B.DeviceId}}
	parts.net2 = &PrivacyCertificateScope{Host: "net2." + edgeCertificateRoot, DeviceIds: []sidecar.Id{parts.net2A.DeviceId}}
	parts.eng = &PrivacyCertificateScope{
		Host: "eng.net1." + edgeCertificateRoot, Member: true,
		DeviceIds:          []sidecar.Id{parts.engConsented.DeviceId, parts.engUnconsented.DeviceId},
		ConsentedDeviceIds: []sidecar.Id{parts.engConsented.DeviceId},
	}
	parts.world.Scopes = []*PrivacyCertificateScope{parts.net1, parts.net2, parts.eng}
	parts.issue(parts.net1AKey, "*.net1."+edgeCertificateRoot, "net1."+edgeCertificateRoot)
	parts.issue(parts.net1BKey, "*.net1."+edgeCertificateRoot, "net1."+edgeCertificateRoot)
	parts.issue(parts.net2AKey, "*.net2."+edgeCertificateRoot, "net2."+edgeCertificateRoot)
	parts.issue(parts.engConsentedKey, "*.eng.net1."+edgeCertificateRoot, "eng.net1."+edgeCertificateRoot)
	parts.platformKey, parts.platformSpki = parts.key()
	parts.world.HeldKeys = []*PrivacyHeldKey{{Holder: "the platform's edge host", SpkiSha256: parts.platformSpki}}
	parts.issue(parts.platformKey, "rpt.platform.example")
	parts.world.Tlsa = []*PrivacyTlsaRecord{
		{Name: "_25._tcp.mx.net1." + edgeCertificateRoot + ".", SpkiSha256: parts.net1A.KeySpkiSha256s[0]},
		{Name: "_25._tcp.mx.eng.net1." + edgeCertificateRoot + ".", SpkiSha256: parts.engConsented.KeySpkiSha256s[0]},
	}
	return parts
}

func edgeCertificateErrors(t *testing.T, world *PrivacyCertificateWorld, wants ...string) {
	t.Helper()
	errs := world.Check()
	if len(errs) != len(wants) {
		t.Errorf("%d violations, want %d: %v", len(errs), len(wants), errs)
		return
	}
	for index, want := range wants {
		if !strings.Contains(errs[index].Error(), want) {
			t.Errorf("violation %d is %q, want it to say %q", index, errs[index], want)
		}
	}
}

// A world that keeps both rows passes: each scope's pair on its own devices' keys, a member scope's on its consented
// device's, each TLSA pinning such a key, and the platform's own certificate outside every network.
func TestCertificateRowsPassAWorldThatKeepsThem(t *testing.T) {
	parts := newEdgeCertificateParts(t)
	edgeCertificateErrors(t, parts.world)
	// a name outside every scope and the root is nobody's to judge
	parts.issue(parts.platformKey, "*.elsewhere.example")
	parts.world.Tlsa = append(parts.world.Tlsa, &PrivacyTlsaRecord{Name: "_25._tcp.mx.elsewhere.example.", SpkiSha256: parts.platformSpki})
	edgeCertificateErrors(t, parts.world)
	// a platform host under the root that is no wildcard and no network's name stands
	parts.issue(parts.platformKey, "probe.edge."+edgeCertificateRoot)
	edgeCertificateErrors(t, parts.world)
	if errs := (&PrivacyCertificateWorld{}).Check(); len(errs) != 1 {
		t.Errorf("a world with no root: %v", errs)
	}
	if err := parts.world.AddIssued([]byte("no certificate")); err == nil {
		t.Error("bytes that are no certificate were added as one")
	}
}

// §22.7's first row: a certificate on a key URnetwork holds that names *.<root>, a network's wildcard, or a network's
// own name fails, each planted alone; the same names on a key no URnetwork process holds do not fail this row.
func TestCertificateRowsFailAHeldKeysNetworkNames(t *testing.T) {
	for name, want := range map[string]string{
		"*." + edgeCertificateRoot:          "every network's hosts",
		"*.net1." + edgeCertificateRoot:     "a network's hosts",
		"*.unknown." + edgeCertificateRoot:  "a network's hosts",
		"net2." + edgeCertificateRoot:       "a network's own name",
		"www.net2." + edgeCertificateRoot:   "a network's own name",
		"*.ENG.net1." + edgeCertificateRoot: "a network's own name",
	} {
		parts := newEdgeCertificateParts(t)
		parts.issue(parts.platformKey, name)
		errs := parts.world.Check()
		if !slices.ContainsFunc(errs, func(err error) bool {
			return strings.Contains(err.Error(), "the platform's edge host") && strings.Contains(err.Error(), want) && strings.Contains(err.Error(), strings.ToLower(name))
		}) {
			t.Errorf("a held key naming %s: %v", name, errs)
		}
	}
	// *.<root> on a key nobody of URnetwork holds names no scope, so neither row reads it
	parts := newEdgeCertificateParts(t)
	strangerKey, _ := parts.key()
	parts.issue(strangerKey, "*."+edgeCertificateRoot)
	edgeCertificateErrors(t, parts.world)
}

// §22.7's second row, the certificate half: a device outside a scope holding its certificate fails, as does a member's
// unconsented device holding the member scope's, a network-level device holding a Team scope's, and a scope's
// certificate on a key nobody in the world holds.
func TestCertificateRowsFailAScopesCertificateOnAnotherDevice(t *testing.T) {
	parts := newEdgeCertificateParts(t)
	parts.issue(parts.net2AKey, "*.net1."+edgeCertificateRoot, "net1."+edgeCertificateRoot)
	edgeCertificateErrors(t, parts.world, "device net2's laptop, which is outside the scope, holds scope net1."+edgeCertificateRoot+"'s certificate")

	parts = newEdgeCertificateParts(t)
	parts.issue(parts.engOtherKey, "*.eng.net1."+edgeCertificateRoot)
	edgeCertificateErrors(t, parts.world, "device the member's unconsented device, which is unconsented in the member scope, holds scope eng.net1."+edgeCertificateRoot+"'s certificate")

	// the Team scope's names are its own: a device of the network that is not in the scope may not hold them
	parts = newEdgeCertificateParts(t)
	parts.issue(parts.net1AKey, "eng.net1."+edgeCertificateRoot)
	edgeCertificateErrors(t, parts.world, "device net1's laptop, which is outside the scope, holds scope eng.net1."+edgeCertificateRoot+"'s certificate")

	parts = newEdgeCertificateParts(t)
	strangerKey, _ := parts.key()
	parts.issue(strangerKey, "www.net2."+edgeCertificateRoot)
	edgeCertificateErrors(t, parts.world, "rests on a key no device of the world holds")

	// a key two devices hold is judged for each: a copied key in a second scope fails for the copy
	parts = newEdgeCertificateParts(t)
	parts.net2A.KeySpkiSha256s = append(parts.net2A.KeySpkiSha256s, parts.net1A.KeySpkiSha256s[0])
	errs := parts.world.Check()
	if len(errs) == 0 || !slices.ContainsFunc(errs, func(err error) bool {
		return strings.Contains(err.Error(), "net2's laptop, which is outside the scope")
	}) {
		t.Errorf("a copied key: %v", errs)
	}
}

// §22.7's second row, the TLSA half: a scope's TLSA pinning the key of a device outside it fails, as does a member
// scope's pinning an unconsented device's key and one pinning a key nobody holds.
func TestCertificateRowsFailAScopesTlsaPinningAnotherDevicesKey(t *testing.T) {
	parts := newEdgeCertificateParts(t)
	parts.world.Tlsa = append(parts.world.Tlsa, &PrivacyTlsaRecord{Name: "_443._tcp.www.net1." + edgeCertificateRoot, SpkiSha256: parts.net2A.KeySpkiSha256s[0]})
	edgeCertificateErrors(t, parts.world, "device net2's laptop, which is outside the scope, has its key in scope net1."+edgeCertificateRoot+"'s TLSA at _443._tcp.www.net1."+edgeCertificateRoot)

	parts = newEdgeCertificateParts(t)
	parts.world.Tlsa = append(parts.world.Tlsa, &PrivacyTlsaRecord{Name: "_25._tcp.mx.eng.net1." + edgeCertificateRoot + ".", SpkiSha256: parts.engUnconsented.KeySpkiSha256s[0]})
	edgeCertificateErrors(t, parts.world, "device the member's unconsented device, which is unconsented in the member scope, has its key in scope eng.net1."+edgeCertificateRoot+"'s TLSA")

	parts = newEdgeCertificateParts(t)
	parts.world.Tlsa = append(parts.world.Tlsa, &PrivacyTlsaRecord{Name: "_25._tcp.mx.net2." + edgeCertificateRoot, SpkiSha256: parts.platformSpki})
	edgeCertificateErrors(t, parts.world, "scope net2."+edgeCertificateRoot+"'s TLSA at _25._tcp.mx.net2."+edgeCertificateRoot+" pins a key no device of the world holds")
}
