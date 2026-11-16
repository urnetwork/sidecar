// §22.7's schema guard for §13 (TLS-M5-25; I-18, §13.9's last line): tls-1 to tls-4, cert-1 and cert-2, both ways.
// Each row is backed by something the tree keeps or sends, a field, a family, a table server's half holds or a value
// only the row's prose names; and each value of §13's a server keeps maps to exactly one row, the one that says so:
// every field of TlsEdgeOpen and TlsKeyAttestation, the {tes_} kill keys tlsedge, sockets and api's kill switch share,
// certs' {tcb_} budget key as certs itself builds it, and the four tables. The schema guard proper
// (schema_guard_test.go) holds the map's every line to a live row; this holds §13's own values to theirs, so a tls
// field, family or table with no row, or a tls row nothing keeps, fails here by name.

package sidecartest_test

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"

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
