// CC4's M5 sources and the certificate rows no area holds whole (TEST-M5-01; §22.7's CC4 line and assert block; R-TEST-3,
// D-TEST-5, I-13, I-14, R-ARCH-3). The sources are in one file so none falls between SOCK, TLS, DNS and SMTP, each a
// class of its own registered here and each with its leak in privacy_edges_leak.go, so §22.7's self-test holds it:
//
//	CC4/edge-record        what an edge wrote of a connection: tlsedge's TlsConnectionRecord (tls-3) and mxedge's
//	                       MxConnectionRecord, every field as the store holds it
//	CC4/report-parse       what the report intake made of a report: its complaint rows, its aggregates' counts and
//	                       what it handed §21's case flow
//	CC4/find               a Find as a dialer sent it and as sockets answered it: POST /socket/find's url and body,
//	                       and the answer's body
//	CC4/dns-edge-query     every query a dns edge was sent, as its bytes arrived
//	CC4/upstream-resolver  every query a device or an engine handed the resolver outside URnetwork, as its bytes arrived
//
// A source only captures; what may be seen there is the scan's to say, through the canaries a test plants, the values it
// forbids and the rows it declares. A private name must reach neither a dns edge nor the upstream resolver (owner
// decision 85), so a test forbids it and the two DNS sources hold every query's bytes, a malformed one's included.
//
// A Find's headers are not captured: its bearer is the caller's service token, which travels there by design, and a
// name or a token path in a header is no shape the route has.
//
// The certificate rows read TLS's and DNS's outputs and make none: PrivacyCertificateWorld is what a world's CT fixture
// issued, what its zone watch read, and who holds which key, and Check is §22.7's "no certificate whose key URnetwork
// holds names *.<root> or *.<net>.<root>, and no device outside a scope, or unconsented in a member scope, holds that
// scope's certificate or gets its key into the scope's TLSA" (owner decision 126).
//
// Safe for concurrent use.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mxedgeservice"
	"github.com/urnetwork/sidecar/smtpedgeservice"
	"github.com/urnetwork/sidecar/tlsedgeservice"
)

// CC4's M5 classes. See the file header.
var (
	PrivacyClassEdgeRecord       = RegisterPrivacyClass("CC4/edge-record")
	PrivacyClassReportParse      = RegisterPrivacyClass("CC4/report-parse")
	PrivacyClassFind             = RegisterPrivacyClass("CC4/find")
	PrivacyClassDnsEdgeQuery     = RegisterPrivacyClass("CC4/dns-edge-query")
	PrivacyClassUpstreamResolver = RegisterPrivacyClass("CC4/upstream-resolver")
)

// The M5 classes, in the file header's order.
func PrivacyEdgeClasses() []PrivacyClass {
	return []PrivacyClass{PrivacyClassEdgeRecord, PrivacyClassReportParse, PrivacyClassFind, PrivacyClassDnsEdgeQuery, PrivacyClassUpstreamResolver}
}

// A record as the scan reads it: one item for each string and byte-slice field, so each is read whole in every form a
// value takes, a compressed one included, and one for everything else it holds, ids as their bytes, numbers and bools
// as text, a time as RFC 3339 and anything that writes itself as text that way, each followed by a zero byte. It walks
// pointers, slices, arrays, maps and structs, so a field added to a record is in the scan without a change here.
// Unexported fields are not read.
func privacyRecordItems(class PrivacyClass, name string, record any) []*PrivacyItem {
	walk := &privacyRecordWalk{class: class, name: name}
	walk.value("", reflect.ValueOf(record))
	if 0 < walk.rest.Len() {
		walk.items = append(walk.items, &PrivacyItem{Class: class, Name: name, Body: walk.rest.Bytes()})
	}
	return walk.items
}

var (
	privacyTextMarshalerType = reflect.TypeFor[encoding.TextMarshaler]()
	privacyTimeType          = reflect.TypeFor[time.Time]()
)

type privacyRecordWalk struct {
	class PrivacyClass
	name  string
	items []*PrivacyItem
	// every value that is no string or byte slice
	rest bytes.Buffer
}

// A string or byte-slice field, an item of its own.
func (self *privacyRecordWalk) field(path string, body []byte) {
	if 0 < len(body) {
		self.items = append(self.items, &PrivacyItem{Class: self.class, Name: self.name + " " + path, Body: bytes.Clone(body)})
	}
}

func (self *privacyRecordWalk) value(path string, value reflect.Value) {
	if !value.IsValid() {
		return
	}
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !value.IsNil() {
			self.value(path, value.Elem())
		}
		return
	case reflect.String:
		self.field(path, []byte(value.String()))
		return
	case reflect.Bool:
		self.rest.WriteString(strconv.FormatBool(value.Bool()))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		self.rest.WriteString(strconv.FormatInt(value.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		self.rest.WriteString(strconv.FormatUint(value.Uint(), 10))
	case reflect.Float32, reflect.Float64:
		self.rest.WriteString(strconv.FormatFloat(value.Float(), 'g', -1, 64))
	case reflect.Slice, reflect.Array:
		if value.Type().Elem().Kind() == reflect.Uint8 {
			body := make([]byte, value.Len())
			for index := range body {
				body[index] = byte(value.Index(index).Uint())
			}
			if value.Kind() == reflect.Slice {
				self.field(path, body)
				return
			}
			// an id
			self.rest.Write(body)
			break
		}
		for index := 0; index < value.Len(); index += 1 {
			self.value(path+"["+strconv.Itoa(index)+"]", value.Index(index))
		}
		return
	case reflect.Map:
		keys := value.MapKeys()
		slices.SortFunc(keys, func(a reflect.Value, b reflect.Value) int {
			return strings.Compare(fmt.Sprint(a), fmt.Sprint(b))
		})
		for index, key := range keys {
			self.value(path+"{key "+strconv.Itoa(index)+"}", key)
			self.value(path+"{value "+strconv.Itoa(index)+"}", value.MapIndex(key))
		}
		return
	case reflect.Struct:
		if value.CanInterface() {
			if value.Type() == privacyTimeType {
				self.rest.WriteString(value.Interface().(time.Time).UTC().Format(time.RFC3339Nano))
				break
			}
			if value.Type().Implements(privacyTextMarshalerType) {
				if text, err := value.Interface().(encoding.TextMarshaler).MarshalText(); err == nil {
					self.rest.Write(text)
					break
				}
			}
		}
		for index := 0; index < value.NumField(); index += 1 {
			if field := value.Type().Field(index); field.IsExported() {
				fieldPath := field.Name
				if path != "" {
					fieldPath = path + "." + field.Name
				}
				self.value(fieldPath, value.Field(index))
			}
		}
		return
	default:
		return
	}
	self.rest.WriteByte(0)
}

// What tlsedge wrote of its connections: FakeTlsEdgeStore, or server's store read back.
type PrivacyTlsEdgeRecords interface {
	Records() []*tlsedgeservice.TlsConnectionRecord
}

// What mxedge wrote of its sessions: FakeMxEdgeStore, or server's store read back.
type PrivacyMxEdgeRecords interface {
	Records() []*mxedgeservice.MxConnectionRecord
}

// CC4's edge records from tlsedge, read at each scan, each record's fields as privacyRecordItems gives them.
func (self *PrivacyCapture) AddTlsEdgeRecords(source string, records PrivacyTlsEdgeRecords) {
	self.AddSource(func() []*PrivacyItem {
		items := []*PrivacyItem{}
		for _, record := range records.Records() {
			items = append(items, privacyRecordItems(PrivacyClassEdgeRecord, source+" tls connection record", record)...)
		}
		return items
	})
}

// CC4's edge records from mxedge, read at each scan, each record's fields as privacyRecordItems gives them.
func (self *PrivacyCapture) AddMxEdgeRecords(source string, records PrivacyMxEdgeRecords) {
	self.AddSource(func() []*PrivacyItem {
		items := []*PrivacyItem{}
		for _, record := range records.Records() {
			items = append(items, privacyRecordItems(PrivacyClassEdgeRecord, source+" mx connection record", record)...)
		}
		return items
	})
}

// What the report intake stored: FakeSmtpEdgeStore's rows.
type PrivacyReportRows interface {
	Complaints() []*smtpedgeservice.SmtpComplaint
	Aggregates() []*smtpedgeservice.SmtpAggregateReport
}

// What the report intake handed §21's case flow: FakeSmtpAbuseSink's reports.
type PrivacyReportCases interface {
	Reports() []*smtpedgeservice.SmtpAbuseReport
}

// CC4's report parse output, read at each scan: every complaint row, its sealed copy a field like any other, which
// only the network's mail key opens, every aggregate with its counts, and every case report. Either of rows and cases
// may be nil.
func (self *PrivacyCapture) AddReportParse(source string, rows PrivacyReportRows, cases PrivacyReportCases) {
	self.AddSource(func() []*PrivacyItem {
		items := []*PrivacyItem{}
		if rows != nil {
			for _, complaint := range rows.Complaints() {
				items = append(items, privacyRecordItems(PrivacyClassReportParse, source+" complaint", complaint)...)
			}
			for _, aggregate := range rows.Aggregates() {
				items = append(items, privacyRecordItems(PrivacyClassReportParse, source+" aggregate", aggregate)...)
			}
		}
		if cases != nil {
			for _, report := range cases.Reports() {
				items = append(items, privacyRecordItems(PrivacyClassReportParse, source+" case report", report)...)
			}
		}
		return items
	})
}

// What a capture point that is called, a Find's or a dns edge's, holds: each call's bytes under its own name, read at
// each scan while a connection is still being written. Safe for concurrent use.
type privacyCallLog struct {
	class PrivacyClass

	stateLock sync.Mutex
	names     []string
	bodies    []*privacyWriter
}

// A new entry named name, which holds what is written to it.
func (self *privacyCallLog) open(name string) *privacyWriter {
	body := &privacyWriter{}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.names = append(self.names, name)
	self.bodies = append(self.bodies, body)
	return body
}

func (self *privacyCallLog) add(name string, body []byte) {
	self.open(name).Write(body)
}

// A source for PrivacyCapture.AddSource.
func (self *privacyCallLog) items() []*PrivacyItem {
	self.stateLock.Lock()
	names := slices.Clone(self.names)
	bodies := slices.Clone(self.bodies)
	self.stateLock.Unlock()
	items := make([]*PrivacyItem, 0, len(names))
	for index, name := range names {
		items = append(items, &PrivacyItem{Class: self.class, Name: name, Body: bodies[index].bytes()})
	}
	return items
}

// The Finds one dialer made, under CC4/find. Safe for concurrent use.
type PrivacyFinds struct {
	source string
	log    *privacyCallLog
}

// CC4's Find calls of the dialer source names, read at each scan: what Transport carries and what Add is given.
func (self *PrivacyCapture) Finds(source string) *PrivacyFinds {
	finds := &PrivacyFinds{source: source, log: &privacyCallLog{class: PrivacyClassFind}}
	self.AddSource(finds.log.items)
	return finds
}

// One Find as its caller made it, for a dialer that calls SidecarApi.SocketFind and no http client of its own: the
// arguments and the answer, every field as privacyRecordItems gives it. result nil for a call that was not answered.
func (self *PrivacyFinds) Add(args *sidecar.SocketFindArgs, result *sidecar.SocketFindResult) {
	items := privacyRecordItems(PrivacyClassFind, self.source+" find", args)
	if result != nil {
		items = append(items, privacyRecordItems(PrivacyClassFind, self.source+" find answer", result)...)
	}
	for _, item := range items {
		self.log.add(item.Name, item.Body)
	}
}

// A transport that captures each request it carries, its url and body, and the answer's body, and sends it on
// through base unchanged: what an edge's Find client is given, so a Find is captured as the dialer sent it, whichever
// process answers. Headers are left out; see the file header.
func (self *PrivacyFinds) Transport(base http.RoundTripper) http.RoundTripper {
	return &privacyFindTransport{finds: self, base: base}
}

// args with its transport capturing, for a dialer built from SocketFindHttpArgs, as tlsedge's and mxedge's are. args
// is not changed.
func (self *PrivacyFinds) WrapArgs(args *sidecar.SocketFindHttpArgs) *sidecar.SocketFindHttpArgs {
	wrapped := *args
	wrapped.Transport = self.Transport(args.Transport)
	return &wrapped
}

type privacyFindTransport struct {
	finds *PrivacyFinds
	base  http.RoundTripper
}

func (self *privacyFindTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	source := self.finds.source
	self.finds.log.add(source+" find's url", []byte(request.URL.RequestURI()))
	if request.Body != nil {
		body, err := io.ReadAll(request.Body)
		request.Body.Close()
		if err != nil {
			return nil, err
		}
		self.finds.log.add(source+" find "+request.URL.Path, body)
		request = request.Clone(request.Context())
		request.Body = io.NopCloser(bytes.NewReader(body))
	}
	response, err := self.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil, err
	}
	self.finds.log.add(source+" find answer "+request.URL.Path, body)
	response.Body = io.NopCloser(bytes.NewReader(body))
	return response, nil
}

// The queries a zone's dns edges were sent, under CC4/dns-edge-query. Safe for concurrent use.
type PrivacyDnsEdgeQueries struct {
	source string
	log    *privacyCallLog
}

// CC4's dns edge queries of the harness or host source names, read at each scan.
func (self *PrivacyCapture) DnsEdgeQueries(source string) *PrivacyDnsEdgeQueries {
	queries := &PrivacyDnsEdgeQueries{source: source, log: &privacyCallLog{class: PrivacyClassDnsEdgeQuery}}
	self.AddSource(queries.log.items)
	return queries
}

// One datagram edge was sent, as its bytes arrived.
func (self *PrivacyDnsEdgeQueries) AddDatagram(edge string, query []byte) {
	self.log.add(self.source+" "+edge+" over udp", query)
}

// A querier's connection to edge, with every byte it writes captured as the edge's queries, read at each scan whether
// or not the connection has closed. What the edge answers is zone data and is not captured here.
func (self *PrivacyDnsEdgeQueries) WrapConn(edge string, conn net.Conn) net.Conn {
	return &privacyQueryConn{Conn: conn, queries: self.log.open(self.source + " " + edge + " over tcp")}
}

type privacyQueryConn struct {
	net.Conn
	queries io.Writer
}

func (self *privacyQueryConn) Write(data []byte) (int, error) {
	self.queries.Write(data)
	return self.Conn.Write(data)
}

// What FakeUpstreamResolver.Resolve answers a query it cannot parse, which it has captured all the same.
var ErrFakeUpstreamMalformed = errors.New("the upstream resolver was sent no dns message")

// A resolver outside URnetwork, the one a device's bridge resolver passes other names to (§12.9) and an engine's
// lookups reach: it answers from what a test set and NXDOMAIN otherwise, and captures every query it is sent, raw,
// under CC4/upstream-resolver, since whatever arrives here has left the device or the engine. Resolve has
// device.BridgeResolverUpstream's shape. Safe for concurrent use.
type FakeUpstreamResolver struct {
	name string

	stateLock sync.Mutex
	queries   [][]byte
	questions []string
	// lower-case owner name and type to its records
	answers map[string][]dns.RR
	failure error
}

// A resolver on net, its queries read by net's capture at each scan. name says which resolver a finding was at.
func NewFakeUpstreamResolver(net *Net, name string) *FakeUpstreamResolver {
	resolver := &FakeUpstreamResolver{name: name, answers: map[string][]dns.RR{}}
	net.Capture().AddSource(resolver.PrivacyItems)
	return resolver
}

func fakeUpstreamAnswerKey(name string, recordType uint16) string {
	return strings.ToLower(dns.Fqdn(name)) + "\x00" + strconv.Itoa(int(recordType))
}

// Sets what the resolver answers for each record's owner name and type, replacing what it answered for them.
func (self *FakeUpstreamResolver) SetAnswer(records ...dns.RR) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	replaced := map[string]bool{}
	for _, record := range records {
		key := fakeUpstreamAnswerKey(record.Header().Name, record.Header().Rrtype)
		if !replaced[key] {
			replaced[key] = true
			self.answers[key] = nil
		}
		self.answers[key] = append(self.answers[key], dns.Copy(record))
	}
}

// Makes every later Resolve fail with err after capturing its query; nil answers again.
func (self *FakeUpstreamResolver) SetFailure(err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.failure = err
}

// One query, captured before it is read, and its answer: the records set for its question, or NXDOMAIN.
func (self *FakeUpstreamResolver) Resolve(ctx context.Context, query []byte) ([]byte, error) {
	message := &dns.Msg{}
	unpackErr := message.Unpack(query)
	self.stateLock.Lock()
	self.queries = append(self.queries, bytes.Clone(query))
	failure := self.failure
	var answers []dns.RR
	if unpackErr == nil && len(message.Question) == 1 {
		question := message.Question[0]
		self.questions = append(self.questions, strings.ToLower(question.Name)+" "+dns.TypeToString[question.Qtype])
		for _, record := range self.answers[fakeUpstreamAnswerKey(question.Name, question.Qtype)] {
			answers = append(answers, dns.Copy(record))
		}
	}
	self.stateLock.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if failure != nil {
		return nil, failure
	}
	if unpackErr != nil || len(message.Question) != 1 {
		return nil, ErrFakeUpstreamMalformed
	}
	reply := &dns.Msg{}
	reply.SetReply(message)
	reply.RecursionAvailable = true
	reply.Answer = answers
	if len(answers) == 0 {
		reply.Rcode = dns.RcodeNameError
	}
	return reply.Pack()
}

// Every query the resolver was sent, raw, in order.
func (self *FakeUpstreamResolver) Queries() [][]byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	queries := make([][]byte, 0, len(self.queries))
	for _, query := range self.queries {
		queries = append(queries, bytes.Clone(query))
	}
	return queries
}

// The question of each well-formed query, "<lower-case name>. <TYPE>", in order.
func (self *FakeUpstreamResolver) Questions() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.questions)
}

// Whether any query asked for name, whatever its type or case.
func (self *FakeUpstreamResolver) Asked(name string) bool {
	prefix := strings.ToLower(dns.Fqdn(name)) + " "
	return slices.ContainsFunc(self.Questions(), func(question string) bool {
		return strings.HasPrefix(question, prefix)
	})
}

// A source for PrivacyCapture.AddSource: each query as it arrived.
func (self *FakeUpstreamResolver) PrivacyItems() []*PrivacyItem {
	items := []*PrivacyItem{}
	for _, query := range self.Queries() {
		items = append(items, &PrivacyItem{Class: PrivacyClassUpstreamResolver, Name: self.name, Body: query})
	}
	return items
}

// A key some URnetwork process holds: an edge host's, a service's, the platform's.
type PrivacyHeldKey struct {
	// Which process, as a failure names it.
	Holder string
	// SHA-256 of the key's SubjectPublicKeyInfo.
	SpkiSha256 []byte
}

// A device and the TLS keys it holds.
type PrivacyCertificateDevice struct {
	DeviceId sidecar.Id
	// As a failure names it.
	Name string
	// SHA-256 of each held key's SubjectPublicKeyInfo.
	KeySpkiSha256s [][]byte
}

// A scope whose certificate only its devices may hold: a network's own, <net>.<root>, or a Team scope's,
// <scope>.<net>.<root> (§13.8; owner decisions 40, 58).
type PrivacyCertificateScope struct {
	// The scope's host. Its identifier set is this name and its wildcard.
	Host string
	// A member scope: its set goes only to its member's consented devices (§8.5; owner decision 126).
	Member bool
	// The devices in the scope.
	DeviceIds []sidecar.Id
	// Of those, the ones consented, read for a member scope alone.
	ConsentedDeviceIds []sidecar.Id
}

// One TLSA record the zone holds, as the zone watch read it: its owner name and the key it pins.
type PrivacyTlsaRecord struct {
	// The owner name, _port._proto.<host>.
	Name string
	// The association data of a 3 1 1 record: SHA-256 of the pinned SubjectPublicKeyInfo.
	SpkiSha256 []byte
}

// What §22.7's certificate rows read of a world. Every field is an output of the world's fixtures: Issued is what its
// CA or CT fixture shows was issued, Tlsa what its zone watch read, and the keys who holds what.
type PrivacyCertificateWorld struct {
	// <root>, the zone networks are under.
	Root string
	// Every network's <net> label.
	NetworkLabels []string
	Issued        []*x509.Certificate
	HeldKeys      []*PrivacyHeldKey
	Devices       []*PrivacyCertificateDevice
	Scopes        []*PrivacyCertificateScope
	Tlsa          []*PrivacyTlsaRecord
}

// Adds one issued certificate from its DER, as a certs row's chain or a CT entry holds its leaf.
func (self *PrivacyCertificateWorld) AddIssued(leafDer []byte) error {
	certificate, err := x509.ParseCertificate(leafDer)
	if err != nil {
		return fmt.Errorf("an issued certificate does not parse: %w", err)
	}
	self.Issued = append(self.Issued, certificate)
	return nil
}

func privacyDnsName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// Whether name is host or under it.
func privacyNameWithin(name string, host string) bool {
	return name == host || strings.HasSuffix(name, "."+host)
}

// The scope a name belongs to: the one whose host it is or is under, the longest such, so a Team scope's names are
// its own and not its network's. nil for a name in no scope.
func (self *PrivacyCertificateWorld) scopeOf(name string) *PrivacyCertificateScope {
	name = strings.TrimPrefix(privacyDnsName(name), "*.")
	var found *PrivacyCertificateScope
	for _, scope := range self.Scopes {
		host := privacyDnsName(scope.Host)
		if privacyNameWithin(name, host) && (found == nil || len(privacyDnsName(found.Host)) < len(host)) {
			found = scope
		}
	}
	return found
}

// The devices holding the key, by its SubjectPublicKeyInfo's hash.
func (self *PrivacyCertificateWorld) holders(spkiSha256 []byte) []*PrivacyCertificateDevice {
	holders := []*PrivacyCertificateDevice{}
	for _, device := range self.Devices {
		if slices.ContainsFunc(device.KeySpkiSha256s, func(held []byte) bool { return bytes.Equal(held, spkiSha256) }) {
			holders = append(holders, device)
		}
	}
	return holders
}

// Why a device may not hold scope's certificate or pin its key in scope's TLSA, "" when it may.
func (self *PrivacyCertificateScope) refusal(device *PrivacyCertificateDevice) string {
	if !slices.Contains(self.DeviceIds, device.DeviceId) {
		return "is outside the scope"
	}
	if self.Member && !slices.Contains(self.ConsentedDeviceIds, device.DeviceId) {
		return "is unconsented in the member scope"
	}
	return ""
}

// §22.7's certificate rows over the world, one error for each violation, none when both rows hold:
//
//   - no issued certificate on a key a URnetwork process holds names *.<root>, any *.<label>.<root>, or a network's
//     <net>.<root> or a name under it, wildcard or not (D-TLS-1: no URnetwork process holds a user-name certificate);
//   - every issued certificate naming a scope's host or a name under it rests on a key some device of the world holds,
//     and each such holder is in the scope, and consented in a member scope;
//   - every TLSA record at a name under a scope's host pins a key some device holds, each such holder in the scope,
//     and consented in a member scope.
//
// A certificate or a TLSA record of a scope on a key no device of the world holds fails too: the row cannot pass on a
// key it cannot place.
func (self *PrivacyCertificateWorld) Check() []error {
	errs := []error{}
	root := privacyDnsName(self.Root)
	if root == "" {
		return []error{errors.New("the certificate rows need the world's <root>")}
	}
	networkHosts := []string{}
	for _, label := range self.NetworkLabels {
		networkHosts = append(networkHosts, privacyDnsName(label)+"."+root)
	}
	for _, certificate := range self.Issued {
		spkiSum := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
		spki := spkiSum[:]
		names := []string{}
		for _, name := range certificate.DNSNames {
			names = append(names, privacyDnsName(name))
		}
		for _, held := range self.HeldKeys {
			if !bytes.Equal(held.SpkiSha256, spki) {
				continue
			}
			for _, name := range names {
				switch rest, wildcard := strings.CutPrefix(name, "*."); {
				case wildcard && rest == root:
					errs = append(errs, fmt.Errorf("a certificate on a key %s holds names %s, every network's hosts (serial %s)", held.Holder, name, certificate.SerialNumber))
				case wildcard && strings.HasSuffix(rest, "."+root) && !strings.Contains(strings.TrimSuffix(rest, "."+root), "."):
					errs = append(errs, fmt.Errorf("a certificate on a key %s holds names %s, a network's hosts (serial %s)", held.Holder, name, certificate.SerialNumber))
				case slices.ContainsFunc(networkHosts, func(host string) bool { return privacyNameWithin(rest, host) }):
					errs = append(errs, fmt.Errorf("a certificate on a key %s holds names %s, a network's own name (serial %s)", held.Holder, name, certificate.SerialNumber))
				}
			}
		}
		checked := []*PrivacyCertificateScope{}
		for _, name := range names {
			scope := self.scopeOf(name)
			if scope == nil || slices.Contains(checked, scope) {
				continue
			}
			checked = append(checked, scope)
			holders := self.holders(spki)
			if len(holders) == 0 {
				errs = append(errs, fmt.Errorf("scope %s's certificate naming %s rests on a key no device of the world holds (serial %s)", scope.Host, name, certificate.SerialNumber))
			}
			for _, device := range holders {
				if refusal := scope.refusal(device); refusal != "" {
					errs = append(errs, fmt.Errorf("device %s, which %s, holds scope %s's certificate naming %s (serial %s)", device.Name, refusal, scope.Host, name, certificate.SerialNumber))
				}
			}
		}
	}
	for _, record := range self.Tlsa {
		scope := self.scopeOf(record.Name)
		if scope == nil {
			continue
		}
		holders := self.holders(record.SpkiSha256)
		if len(holders) == 0 {
			errs = append(errs, fmt.Errorf("scope %s's TLSA at %s pins a key no device of the world holds", scope.Host, record.Name))
		}
		for _, device := range holders {
			if refusal := scope.refusal(device); refusal != "" {
				errs = append(errs, fmt.Errorf("device %s, which %s, has its key in scope %s's TLSA at %s", device.Name, refusal, scope.Host, record.Name))
			}
		}
	}
	return errs
}
