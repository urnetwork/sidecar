// §22.7 for §13 (TLS-M5-25): the schema guard's tls and cert rows, the privacy harness's TLS canaries on the composed
// world (tls_suite_test.go), and the certificates clause of the assert block.
//
// The schema guard (I-18, §13.9's last line): tls-1 to tls-4, cert-1 and cert-2, both ways. Each row is backed by
// something the tree keeps or sends, a field, a family, a table server's half holds or a value only the row's prose
// names; and each value of §13's a server keeps maps to exactly one row, the one that says so: every field of
// TlsEdgeOpen and TlsKeyAttestation, the {tes_} kill keys tlsedge, sockets and api's kill switch share, certs' {tcb_}
// budget key as certs itself builds it, and the four tables. The schema guard proper (schema_guard_test.go) holds the
// map's every line to a live row; this holds §13's own values to theirs, so a tls field, family or table with no row,
// or a tls row nothing keeps, fails here by name. After a composed visit, every Redis key it left is held to a row the
// same way.

package sidecartest_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/reflect/protoreflect"
	"gopkg.in/yaml.v3"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/certsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The §2.8 rows §13.9 names as its server-visible fields, apart from api-11's and api-7's, which other areas back.
var testTlsRows = []string{"cert-1", "cert-2", "tls-1", "tls-2", "tls-3", "tls-4"}

// fields.yml's sections this test reads, and an area file's lines.
type testTlsFieldMap struct {
	Fields map[string]string `yaml:"fields"`
	Values map[string]string `yaml:"values"`
	Rows   map[string]struct {
		Server []string `yaml:"server"`
	} `yaml:"rows"`
}

type testTlsAreaField struct {
	Row string `yaml:"row"`
}

// The Redis family a key is under, by the rule the guard reads stores with (schema_guard_keys.go): the hash tag's
// first word up to its underscore, then what follows the tag, up to and including a colon.
func testTlsRedisFamily(key string) string {
	tagEnd := strings.IndexByte(key, '}')
	if !strings.HasPrefix(key, "{") || tagEnd < 0 {
		return key
	}
	tag := key[1:tagEnd]
	if underscore := strings.IndexByte(tag, '_'); 0 <= underscore {
		tag = tag[:underscore+1]
	}
	suffix := key[tagEnd+1:]
	if colon := strings.IndexByte(suffix, ':'); 0 <= colon {
		suffix = suffix[:colon+1]
	}
	return "{" + tag + "}" + suffix
}

// The live rows whose store names family, of kind.
func testTlsRowsNaming(list *sidecartest.MetadataList, kind sidecartest.MetadataFamilyKind, family string) []string {
	rowIds := []string{}
	for _, row := range list.LiveRows() {
		if slices.Contains(row.Families(), sidecartest.MetadataFamily{Kind: kind, Name: family}) {
			rowIds = append(rowIds, row.Id)
		}
	}
	slices.Sort(rowIds)
	return rowIds
}

// The Redis keys §13's code builds, each from the builder that writes it: the kill switch's hash and trigger
// (TlsKillKey, TlsKillTriggerKey) and certs' budget key, from a spend through certs' own CertsBudget on a FakeRedis.
func testTlsRedisKeys(t *testing.T) []string {
	t.Helper()
	networkId := sidecar.NewId()
	keys := []string{sidecar.TlsKillKey(networkId), sidecar.TlsKillTriggerKey(networkId)}
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	redis := sidecartest.NewFakeRedis(t.Context(), clock, nil, nil, nil)
	t.Cleanup(redis.Close)
	sidecartest.RegisterCertsBudgetTwins(redis)
	settings := certsservice.DefaultCertsSettings()
	settings.RootDomain = "ur.example"
	budget := certsservice.NewCertsBudget(redis, sidecartest.NewFakeCertsStore(nil), settings)
	spent, err := budget.Spend(context.Background(), certsservice.CertsCaLetsEncrypt, sidecar.NewId(), clock.Now())
	if err != nil || !spent {
		t.Fatalf("certs' budget spent %v, %v", spent, err)
	}
	budgetKeys := []string{}
	for key := range redis.Dump() {
		budgetKeys = append(budgetKeys, key)
	}
	if len(budgetKeys) == 0 {
		t.Fatal("certs' spend wrote no key")
	}
	return append(keys, budgetKeys...)
}

// Every field of message, as Message.field.
func testTlsMessageFields(message protoreflect.ProtoMessage) []string {
	descriptor := message.ProtoReflect().Descriptor()
	fields := []string{}
	for index := range descriptor.Fields().Len() {
		fields = append(fields, string(descriptor.Name())+"."+string(descriptor.Fields().Get(index).Name()))
	}
	return fields
}

func TestTlsRowsAndFamiliesMapBothWays(t *testing.T) {
	list, err := sidecartest.LoadMetadataList()
	if err != nil {
		t.Fatal(err)
	}
	rows := []string{}
	for _, row := range list.LiveRows() {
		if strings.HasPrefix(row.Id, "tls-") || strings.HasPrefix(row.Id, "cert-") {
			rows = append(rows, row.Id)
		}
	}
	slices.Sort(rows)
	if !slices.Equal(rows, testTlsRows) {
		t.Fatalf("the list's tls and cert rows are %v", rows)
	}

	fieldsBytes, err := os.ReadFile("../testdata/metadata/fields.yml")
	if err != nil {
		t.Fatal(err)
	}
	fieldMap := &testTlsFieldMap{}
	if err := yaml.Unmarshal(fieldsBytes, fieldMap); err != nil {
		t.Fatal(err)
	}
	areaBytes, err := os.ReadFile("../testdata/tls/metadata_rows.yml")
	if err != nil {
		t.Fatal(err)
	}
	areaFields := map[string]*testTlsAreaField{}
	if err := yaml.Unmarshal(areaBytes, &areaFields); err != nil {
		t.Fatal(err)
	}
	fieldRow := func(field string) string {
		if row, ok := fieldMap.Fields[field]; ok {
			return row
		}
		if areaField := areaFields[field]; areaField != nil {
			return areaField.Row
		}
		return ""
	}

	// one way: every value of §13's maps to the one row that names it. The open's expiry is its ticket's grant
	// expiry, which sock-2 shows as the ticket's; every other field is what tlsedge read off the connection.
	backed := map[string][]string{}
	openRows := map[string]string{
		"TlsEdgeOpen.client_ip":               "tls-2",
		"TlsEdgeOpen.client_port":             "tls-2",
		"TlsEdgeOpen.server_name":             "tls-1",
		"TlsEdgeOpen.alpn":                    "tls-1",
		"TlsEdgeOpen.client_hello_byte_count": "tls-1",
		"TlsEdgeOpen.connection_id":           "tls-3",
		"TlsEdgeOpen.expire_time_millis":      "sock-2",
	}
	for _, field := range testTlsMessageFields(&protocol.TlsEdgeOpen{}) {
		want, known := openRows[field]
		if row := fieldRow(field); !known || row != want {
			t.Errorf("the edge's open field %s maps to %q, and this test places it in %q", field, row, want)
		}
		backed[want] = append(backed[want], field)
	}
	for _, field := range testTlsMessageFields(&protocol.TlsKeyAttestation{}) {
		row := fieldRow(field)
		if row != "cert-1" {
			t.Errorf("the attestation field %s maps to %q, not cert-1", field, row)
		}
		backed[row] = append(backed[row], field)
	}
	familyRows := map[string]string{"{tes_}": "tls-4", "{tes_}n": "tls-4", "{tcb_}": "cert-1"}
	keys := testTlsRedisKeys(t)
	for _, key := range keys {
		family := testTlsRedisFamily(key)
		want, known := familyRows[family]
		if !known {
			t.Errorf("§13's key %s is of family %s, which this test does not place", key, family)
			continue
		}
		if owners := testTlsRowsNaming(list, sidecartest.MetadataFamilyRedis, family); !slices.Equal(owners, []string{want}) {
			t.Errorf("the family %s is named by %v, not %s alone", family, owners, want)
		}
		backed[want] = append(backed[want], family)
	}
	guard, err := sidecartest.LoadSchemaGuard()
	if err != nil {
		t.Fatal(err)
	}
	findings, err := guard.CheckStores(context.Background(), &sidecartest.SchemaGuardStores{RedisKeys: keys})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		t.Error(finding)
	}
	tableRows := map[string]string{
		"network_tls_cert":       "cert-1",
		"network_tls_suspension": "tls-4",
		"tls_connection_record":  "tls-3",
		"tls_connection_day":     "tls-3",
	}
	for table, want := range tableRows {
		if owners := testTlsRowsNaming(list, sidecartest.MetadataFamilyTable, table); !slices.Equal(owners, []string{want}) {
			t.Errorf("the table %s is named by %v, not %s alone", table, owners, want)
		}
		if !slices.Contains(fieldMap.Rows[want].Server, table) {
			t.Errorf("fields.yml's rows section does not say server's %s backs %s", table, want)
		}
		backed[want] = append(backed[want], table)
	}
	for value, row := range fieldMap.Values {
		if slices.Contains(testTlsRows, row) {
			backed[row] = append(backed[row], value)
		}
	}

	// the other: every tls and cert row has something behind it
	for _, row := range testTlsRows {
		if len(backed[row]) == 0 {
			t.Errorf("%s: no field, family, table or value of §13's maps to it", row)
		}
	}
}

// The guard's map no longer carries a tls or cert row as planned: each has its values since M5's tasks landed, so a
// planned line would hide a row losing them.
func TestTlsRowsAreNoLongerPlanned(t *testing.T) {
	fieldsBytes, err := os.ReadFile("../testdata/metadata/fields.yml")
	if err != nil {
		t.Fatal(err)
	}
	planned := &struct {
		Rows map[string]struct {
			Planned string `yaml:"planned"`
		} `yaml:"rows"`
	}{}
	if err := yaml.Unmarshal(fieldsBytes, planned); err != nil {
		t.Fatal(err)
	}
	for _, row := range testTlsRows {
		if entry, ok := planned.Rows[row]; ok && entry.Planned != "" {
			t.Errorf("%s is still planned for %s", row, entry.Planned)
		}
	}
}

// §22.7's privacy harness on §13 (TLS-M5-25; I-13, I-18, X1, R-TLS-4, R-TLS-8), on the composed world: a published
// host's label and the HTTPS bodies of a visit are canaries, and the visitor's address a forbidden value. A visitor
// posts a form to the canary host through tlsedge and the engine's Find, the device answers a page on its own key, the
// host is killed, and tlsedge closes with its records written. The scan reads every call the sockets engine took
// (CC1), tlsedge's own side of the connection as a stream engine's input and output (CC1), the Net's Redis, objects,
// metrics and hints, any log line that reaches the capture (tlsedge, sockets and certs write none on this path), the
// sockets store's families and tlsedge's connection records, and finds:
//
//   - the host only where §2.8 lets a server see it: the sockets service's registrations, Finds and families (sock-1,
//     sock-2, sock-5), the kill's {tes_} field (tls-4), the connection records (tls-3), the projection's publish rules
//     (api-7), and the hello's SNI as tlsedge reads it (tls-1); never in a log, a metric or a hint (I-13);
//   - neither body anywhere: what tlsedge held were records it could not open (X1);
//   - the visitor's address nowhere: a record holds its keyed hash, and only the open the listener receives names it.
//
// Under sidecar_leaktest the host leaked into a log, a metric and a hint is found there, so the clean scan is no blind
// one.

// The canaries of one composed visit, by the kind a finding names.
const (
	tlsPrivacyHostKind    = "published host"
	tlsPrivacyRequestKind = "https request body"
	tlsPrivacyPageKind    = "https page body"
	tlsPrivacyVisitorKind = "visitor address"
)

type tlsPrivacyCanaries struct {
	host        string
	requestBody string
	page        string
}

// Plants the canaries on edge's capture, declares where §2.8 lets a server see the host, adds the sockets store and
// tlsedge's records as sources, and publishes the host.
func tlsPrivacyPlant(t *testing.T, edge *tlsSuiteEdge) *tlsPrivacyCanaries {
	t.Helper()
	capture := edge.net.Capture()
	canaries := &tlsPrivacyCanaries{
		host:        capture.CanaryText(tlsPrivacyHostKind),
		requestBody: capture.CanaryText(tlsPrivacyRequestKind),
		page:        capture.CanaryText(tlsPrivacyPageKind),
	}
	capture.Forbid(tlsPrivacyVisitorKind, []byte(tlsSuiteVisitor.Addr().String()))
	for _, declaration := range []struct {
		row   string
		class sidecartest.PrivacyClass
	}{
		{"sock-1", sidecartest.PrivacyClassHandler},
		{"sock-2", sidecartest.PrivacyClassHandler},
		{"tls-1", sidecartest.PrivacyClassHandler},
		{"sock-1", sidecartest.PrivacyClassRedis},
		{"sock-5", sidecartest.PrivacyClassRedis},
		{"tls-4", sidecartest.PrivacyClassRedis},
		{"tls-3", sidecartest.PrivacyClassPostgres},
		{"api-7", sidecartest.PrivacyClassObject},
	} {
		if err := capture.Declare(declaration.row, tlsPrivacyHostKind, declaration.class); err != nil {
			t.Fatal(err)
		}
	}
	capture.AddSource(edge.socketSuiteWorld.store.PrivacyItems)
	capture.AddSource(func() []*sidecartest.PrivacyItem {
		items := []*sidecartest.PrivacyItem{}
		for _, record := range edge.edgeStore.Records() {
			body := &bytes.Buffer{}
			body.Write(record.ConnectionId.Bytes())
			body.Write(record.NetworkId.Bytes())
			body.WriteString(record.Host)
			body.WriteString(record.StartTime.String())
			body.WriteString(record.EndTime.String())
			body.WriteString(strconv.FormatInt(record.ByteCount, 10))
			body.Write(record.VisitorHash)
			items = append(items, &sidecartest.PrivacyItem{Class: sidecartest.PrivacyClassPostgres, Name: "tls_connection_record", Body: body.Bytes()})
		}
		return items
	})
	edge.publish(canaries.host)
	return canaries
}

// tlsedge's side of a visit as the capture reads it: what it read and wrote on the visitor's connection and on the
// stream, a stream engine's input and output.
func tlsPrivacyAddEdgeView(edge *tlsSuiteEdge, visitorConn *tlsSuiteVisitorConn, stream *tlsSuiteStream) {
	visitorRead, visitorWrote := visitorConn.bytes()
	streamWrote, streamRead := stream.edgeBytes()
	capture := edge.net.Capture()
	capture.Add(sidecartest.PrivacyClassHandler, "tlsedge visitor read", visitorRead)
	capture.Add(sidecartest.PrivacyClassHandler, "tlsedge visitor wrote", visitorWrote)
	capture.Add(sidecartest.PrivacyClassHandler, "tlsedge stream wrote", streamWrote)
	capture.Add(sidecartest.PrivacyClassHandler, "tlsedge stream read", streamRead)
}

// A visit to the canary host: through tlsedge to the device, which answers on its own key and the chain certs ordered
// for it when certificate is given, and otherwise only takes the stream; then the host's kill, and tlsedge's close,
// which writes its records.
func tlsPrivacyVisit(t *testing.T, edge *tlsSuiteEdge, canaries *tlsPrivacyCanaries, certificate *tls.Certificate, roots *x509.CertPool) {
	t.Helper()
	serverName := edge.serverName(canaries.host)
	done := edge.handshake(serverName, []string{"http/1.1"}, roots)
	stream := edge.dialer.awaitOpened(t)
	visitorConn := edge.awaitAccepted()
	if certificate != nil {
		bodies := tlsSuiteServeDevice(stream, certificate, canaries.page)
		handshake := edge.awaitHandshake(done)
		if handshake.err != nil {
			t.Fatalf("the visitor's handshake: %v", handshake.err)
		}
		if _, err := io.WriteString(handshake.conn, tlsSuiteRequest(serverName, canaries.requestBody)); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(handshake.conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		if page, err := io.ReadAll(response.Body); err != nil || string(page) != canaries.page {
			t.Fatalf("the visitor read %q, %v", page, err)
		}
		if body := <-bodies; body != canaries.requestBody {
			t.Fatalf("the device read %q", body)
		}
		handshake.conn.Close()
	} else {
		// the device takes the stream and closes it, and the visitor, its handshake unanswered, leaves
		(&tlsSuiteListenerEnd{stream: stream}).Close()
		edge.awaitHandshake(done).conn.Close()
	}
	edge.awaitEnded(1)
	tlsPrivacyAddEdgeView(edge, visitorConn, stream)
	edge.kill(canaries.host, time.Time{})
	edge.service.Close()
}

func TestTlsCanariesReachOnlyTheirRows(t *testing.T) {
	edge := newTlsSuiteEdgeBare(t)
	canaries := tlsPrivacyPlant(t, edge)
	certs := newTlsSuiteCerts(t)
	identifierSet, err := sidecar.TlsIdentifierSet(tlsSuiteRoot, edge.label, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	device := certs.issue(edge.listener.device, sidecar.Id(edge.networkId), sidecar.Id(edge.listener.clientId), identifierSet)
	tlsPrivacyVisit(t, edge, canaries, device.certificate, certs.pebble.Roots)

	capture := edge.net.Capture()
	for _, finding := range capture.Scan() {
		t.Errorf("%s", finding)
	}
	// the scan read what each row declares: a record of the visit, the kill's field, the store's lease and a call
	records := edge.edgeStore.Records()
	if len(records) != 1 || records[0].Host != canaries.host || len(records[0].VisitorHash) != 16 || records[0].ByteCount == 0 {
		t.Fatalf("tlsedge's records %+v", records)
	}
	fields, err := edge.net.Fakes().Redis.HashGetAll(edge.ctx, sidecar.TlsKillKey(sidecar.Id(edge.networkId)))
	if err != nil || fields[canaries.host] == nil {
		t.Fatalf("the kill's {tes_} fields %v, %v", fields, err)
	}
	found := false
	for _, item := range edge.socketSuiteWorld.store.PrivacyItems() {
		if bytes.Contains(item.Body, []byte("tls/443/"+canaries.host)) {
			found = true
		}
	}
	if !found {
		t.Fatal("the sockets store holds no lease of the canary host, so the scan read nothing there")
	}
	for _, class := range []sidecartest.PrivacyClass{sidecartest.PrivacyClassHandler, sidecartest.PrivacyClassMetric} {
		if capture.ItemCount(class) == 0 {
			t.Fatalf("nothing reached %s, so the scan read nothing there", class)
		}
	}
	// and every Redis key the run left is a family a row names, both ways at run time
	guard, err := sidecartest.LoadSchemaGuard()
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{}
	for key := range edge.net.Fakes().Redis.Dump() {
		keys = append(keys, key)
	}
	findings, err := guard.CheckStores(edge.ctx, &sidecartest.SchemaGuardStores{RedisKeys: keys})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		t.Error(finding)
	}
}

// Under sidecar_leaktest: the host canary leaked through each class I-13 keeps it out of, a log, a metric and a hint,
// is found in that class, so a host that reached one of them would not pass unseen.
func TestTlsCanaryHostLeakedIntoEachClassIsCaught(t *testing.T) {
	if !sidecartest.LeaksLinked {
		t.Skip("the leaks link only under sidecar_leaktest, which test.sh's leak leg builds")
	}
	leaks := sidecartest.LeakClasses()
	for _, class := range []sidecartest.PrivacyClass{sidecartest.PrivacyClassLog, sidecartest.PrivacyClassMetric, sidecartest.PrivacyClassHint} {
		leak := leaks[class]
		if leak == nil {
			t.Fatalf("%s has no leak", class)
		}
		func() {
			edge := newTlsSuiteEdgeBare(t)
			canaries := tlsPrivacyPlant(t, edge)
			tlsPrivacyVisit(t, edge, canaries, nil, nil)
			if findings := edge.net.Capture().Scan(); len(findings) != 0 {
				t.Fatalf("%s: findings before the leak: %v", class, findings)
			}
			leak.Put(t, edge.net, []byte(canaries.host))
			caught := false
			for _, finding := range edge.net.Capture().Scan() {
				if finding.Needle == tlsPrivacyHostKind && finding.Class == class {
					caught = true
				}
			}
			if !caught {
				t.Errorf("the host leaked into %s was not found", class)
			}
		}()
	}
}

// §22.7's "no certificate whose key URnetwork holds names *.<root> or *.<net>.<root>", its M5 half (the scope half is
// TLS-M6-03's): the only certificates in the world are those certs ordered, each on the key the device attested and
// holds, for the network's own set; and that key, planted as a secret, reaches no capture: not certs' rows or Redis, not
// tlsedge's side of the visit, not the sockets service, a log or a metric. certs sees a CSR, tlsedge records.
func TestTlsNoCertificateRestsOnAKeyUrnetworkHolds(t *testing.T) {
	edge := newTlsSuiteEdgeBare(t)
	canaries := tlsPrivacyPlant(t, edge)
	certs := newTlsSuiteCerts(t)
	identifierSet, err := sidecar.TlsIdentifierSet(tlsSuiteRoot, edge.label, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	device := certs.issue(edge.listener.device, sidecar.Id(edge.networkId), sidecar.Id(edge.listener.clientId), identifierSet)
	capture := edge.net.Capture()
	keyDer, err := x509.MarshalPKCS8PrivateKey(device.key)
	if err != nil {
		t.Fatal(err)
	}
	capture.AddSecret("device tls key", keyDer)
	capture.AddSecret("device tls key scalar", device.key.D.FillBytes(make([]byte, 32)))
	capture.AddSource(func() []*sidecartest.PrivacyItem {
		items := []*sidecartest.PrivacyItem{}
		for _, row := range certs.store.Rows() {
			body, err := json.Marshal(row)
			if err != nil {
				continue
			}
			items = append(items, &sidecartest.PrivacyItem{Class: sidecartest.PrivacyClassPostgres, Name: "network_tls_cert", Body: body})
		}
		for key, value := range certs.host.Redis.Dump() {
			items = append(items, &sidecartest.PrivacyItem{Class: sidecartest.PrivacyClassRedis, Name: "certs redis " + key, Body: append([]byte(key+"\x00"), value...)})
		}
		return items
	})
	tlsPrivacyVisit(t, edge, canaries, device.certificate, certs.pebble.Roots)
	for _, finding := range capture.Scan() {
		t.Errorf("%s", finding)
	}

	devicePublicKey, err := x509.MarshalPKIXPublicKey(&device.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	deviceSpki := sha256.Sum256(devicePublicKey)
	rows := certs.store.Rows()
	if len(rows) != 1 {
		t.Fatalf("certs holds %d rows", len(rows))
	}
	for _, row := range rows {
		if len(row.Chain) == 0 {
			t.Fatalf("row %s holds no chain", row.CertId)
		}
		leaf, err := x509.ParseCertificate(row.Chain[0])
		if err != nil {
			t.Fatal(err)
		}
		spki := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		if spki != deviceSpki || !bytes.Equal(row.SpkiSha256, deviceSpki[:]) {
			t.Fatalf("row %s's certificate rests on a key the device did not attest", row.CertId)
		}
		names := slices.Clone(leaf.DNSNames)
		slices.Sort(names)
		want := slices.Clone(identifierSet)
		slices.Sort(want)
		if !slices.Equal(names, want) {
			t.Fatalf("row %s's certificate names %v, not the network's set %v", row.CertId, names, want)
		}
	}
}
