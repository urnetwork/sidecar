// §22.7's privacy harness on sockets (SOCK-M5-16; D-SOCK-13, R-SOCK-9, I-13, I-18, owner decision 67), on the
// suite's world (socket_suite_test.go): application socket names are canaries, as a person's own names would be,
// registered, listed and dialed through the engine as the client side makes them, token paths and seals under the
// network's K_sock; and K_sock is a secret, with K_tok and K_seal too wherever sidecar_testhooks hooks their
// derivation. No handler capture (CC1, where every registration, listing and Find call is captured as the engine
// takes and answers it), no Redis value the store keeps (CC3, the fake store's contents standing for server's
// {sg_}, {sn_}, {sc_} and {svc_}), no log, metric or hint (CC4) holds a name in the clear, a seal's plaintext or a
// key. Under sidecar_leaktest a canary leaked into each class through the class's own leak is found, so the clean
// scan is no blind one.
//
// DESIGN-DETAILS 17.2.10's names (17.7's SOCK-M5-16 line, after TLS-M6-08) are canaries too, on the suite's custom
// world: a custom host a listener is certified for, one it holds an ACME claim for, and one a visitor's Find names
// that no listener lists. A tls/ listener's names travel in the clear by design, so each is declared where §2.8 says a
// server sees it, and nowhere else: a registration's certified and ACME names by the service and in sock-1's group,
// which keeps them; a Find's server name by the service for the request alone (sock-2), which no store keeps. No log,
// metric or hint holds any of them (I-13). The schema guard holds 17.2.16's clauses of sock-1 and sock-2 to the
// fields that carry them, both ways.

package sidecartest_test

import (
	"bytes"
	"net/http"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/socketsservice"
)

// Registers, lists and dials canary names through the engine, with the store's contents joining the capture. The
// canaries.
func socketPrivacyRun(t *testing.T, world *socketSuiteWorld) []string {
	t.Helper()
	capture := world.net.Capture()
	names := []string{}
	registrations := []*sidecar.SocketRegistration{}
	for _, kind := range []string{"socket name one", "socket name two"} {
		name := "app/" + capture.CanaryText(kind)
		names = append(names, name)
		registrations = append(registrations, world.registration(world.listener, name, 256))
	}
	world.registerOk(world.listener, 1, registrations...)
	listed := &sidecar.SocketListResult{}
	if code := world.call("GET", "/socket/list", world.listener.token, nil, listed); code != 200 || len(listed.Names) != len(names) {
		t.Fatalf("the listing answered %d with %d names", code, len(listed.Names))
	}
	for _, name := range names {
		nameToken, err := world.keys.TokenPath(name)
		if err != nil {
			t.Fatal(err)
		}
		networkId := world.networkId
		args := &sidecar.SocketFindArgs{NameToken: nameToken, NetworkId: &networkId}
		result := &sidecar.SocketFindResult{}
		if code := world.call("POST", "/socket/find", world.dialer.token, args, result); code != 200 || result.Error != nil {
			t.Fatalf("a canary's Find answered %d, %+v", code, result.Error)
		}
	}
	capture.AddSource(world.store.PrivacyItems)
	return names
}

// No store, handler, log, metric or hint holds a canary name, a seal's plaintext or K_sock, while the
// store does hold every canary's token path and seal: what the service is meant to see.
func TestSocketCanariesReachNoStore(t *testing.T) {
	world := newSocketSuiteWorld(t, nil)
	names := socketPrivacyRun(t, world)
	for _, finding := range world.net.Capture().Scan() {
		t.Errorf("%s", finding)
	}
	if count := world.net.Capture().ItemCount(sidecartest.PrivacyClassHandler); count == 0 {
		t.Fatal("no call reached the handler capture, so the scan read nothing there")
	}
	items := world.store.PrivacyItems()
	for _, name := range names {
		nameToken, _ := world.keys.TokenPath(name)
		found := false
		for _, item := range items {
			if bytes.Contains(item.Body, nameToken) {
				found = true
			}
		}
		if !found {
			t.Fatalf("the store holds no token path of %q, so the scan read nothing", name)
		}
	}
}

// Under sidecar_leaktest: the own leak of each class a socket name could reach (a handler, a Redis value, a stored
// object, a log, a metric and a hint) carries a canary name, whole, into its class, and the scan finds it there, so
// a name that reached one of them would not pass unseen.
func TestSocketCanaryLeakedIntoEachClassIsCaught(t *testing.T) {
	if !sidecartest.LeaksLinked {
		t.Skip("the leaks link only under sidecar_leaktest, which test.sh's leak leg builds")
	}
	classes := []sidecartest.PrivacyClass{
		sidecartest.PrivacyClassHandler, sidecartest.PrivacyClassRedis, sidecartest.PrivacyClassObject,
		sidecartest.PrivacyClassLog, sidecartest.PrivacyClassMetric, sidecartest.PrivacyClassHint,
	}
	leaks := sidecartest.LeakClasses()
	for _, class := range classes {
		leak := leaks[class]
		if leak == nil {
			t.Fatalf("%s has no leak", class)
		}
		func() {
			world := newSocketSuiteWorld(t, nil)
			names := socketPrivacyRun(t, world)
			if findings := world.net.Capture().Scan(); len(findings) != 0 {
				t.Fatalf("%s: findings before the leak: %v", class, findings)
			}
			leak.Put(t, world.net, []byte(names[0]))
			caught := false
			for _, finding := range world.net.Capture().Scan() {
				if finding.Needle == "socket name one" && finding.Class == class {
					caught = true
				}
			}
			if !caught {
				t.Errorf("a canary name leaked into %s was not found", class)
			}
		}()
	}
}

// §22.7's schema guard for sockets (I-18), both ways: every sock row of metadata_list.yml is one fields.yml names, by
// a family a store keeps or a field; every family the sockets store keeps (§9.8's {sg_} and its ix, {svc_},
// {sn_}names and {sc_}set) is named by exactly one row, a sock row; and every field of a ticket maps to a sock row. A
// socket field or family with no row, or a sock row nothing keeps, fails here.
func TestSocketRowsAndFamiliesMapBothWays(t *testing.T) {
	listBytes, err := os.ReadFile("../metadata_list.yml")
	if err != nil {
		t.Fatal(err)
	}
	list := map[string]any{}
	if err := yaml.Unmarshal(listBytes, &list); err != nil {
		t.Fatal(err)
	}
	sockRows := []string{}
	for row := range list {
		if strings.HasPrefix(row, "sock-") {
			sockRows = append(sockRows, row)
		}
	}
	slices.Sort(sockRows)
	if !slices.Equal(sockRows, []string{"sock-1", "sock-2", "sock-3", "sock-4", "sock-5"}) {
		t.Fatalf("the list's sock rows are %v", sockRows)
	}
	fieldsBytes, err := os.ReadFile("../testdata/metadata/fields.yml")
	if err != nil {
		t.Fatal(err)
	}
	mapped := &struct {
		Rows   map[string]map[string]any `yaml:"rows"`
		Fields map[string]any            `yaml:"fields"`
	}{}
	if err := yaml.Unmarshal(fieldsBytes, mapped); err != nil {
		t.Fatal(err)
	}
	rowFamilies := func(row string) []string {
		families := []string{}
		if server, ok := mapped.Rows[row]["server"].([]any); ok {
			for _, family := range server {
				if text, ok := family.(string); ok {
					families = append(families, text)
				}
			}
		}
		return families
	}
	for _, row := range sockRows {
		named := 0 < len(rowFamilies(row))
		for _, value := range mapped.Fields {
			if value == row {
				named = true
			}
		}
		if !named {
			t.Errorf("%s names no family or field fields.yml maps", row)
		}
	}
	for _, family := range []string{"{sg_}", "{sg_}ix", "{svc_}", "{sn_}names", "{sc_}set"} {
		owners := []string{}
		for row := range mapped.Rows {
			if slices.Contains(rowFamilies(row), family) {
				owners = append(owners, row)
			}
		}
		if len(owners) != 1 || !strings.HasPrefix(owners[0], "sock-") {
			t.Errorf("the sockets family %s is named by %v", family, owners)
		}
	}
	for field, value := range mapped.Fields {
		if !strings.HasPrefix(field, "SocketTicket.") && !strings.HasPrefix(field, "SignedSocketTicket.") {
			continue
		}
		if row, ok := value.(string); !ok || !strings.HasPrefix(row, "sock-") {
			t.Errorf("the ticket field %s maps to %v, no sock row", field, value)
		}
	}
}

// The kinds of 17.2.10's canaries, as a finding names them.
const (
	socketPrivacyCertifiedKind = "certified custom host"
	socketPrivacyAcmeKind      = "acme custom host"
	socketPrivacyUnlistedKind  = "unlisted custom host"
)

// One custom world's canary names.
type socketPrivacyCustomNames struct {
	certified string
	acme      string
	unlisted  string
}

// Plants 17.2.10's canaries on world's capture and declares where §2.8 lets a server see each; then a listener of the
// first device lists the certified and the ACME host, which the facts bear out, a visitor's Find and a challenge's
// Find reach it by them, and a visitor's Find names the unlisted host, which finds no listener. The store's contents
// join the capture.
func socketPrivacyCustomRun(t *testing.T, world *socketSuiteCustomWorld) *socketPrivacyCustomNames {
	t.Helper()
	capture := world.net.Capture()
	names := &socketPrivacyCustomNames{
		certified: capture.CanaryText(socketPrivacyCertifiedKind) + ".customer.example",
		acme:      capture.CanaryText(socketPrivacyAcmeKind) + ".customer.example",
		unlisted:  capture.CanaryText(socketPrivacyUnlistedKind) + ".customer.example",
	}
	for _, declaration := range []struct {
		row   string
		kind  string
		class sidecartest.PrivacyClass
	}{
		// a registration lists them to the service, and sock-1's group keeps them
		{row: "sock-1", kind: socketPrivacyCertifiedKind, class: sidecartest.PrivacyClassHandler},
		{row: "sock-1", kind: socketPrivacyCertifiedKind, class: sidecartest.PrivacyClassRedis},
		{row: "sock-1", kind: socketPrivacyAcmeKind, class: sidecartest.PrivacyClassHandler},
		{row: "sock-1", kind: socketPrivacyAcmeKind, class: sidecartest.PrivacyClassRedis},
		// a Find carries its server name for the request alone
		{row: "sock-2", kind: socketPrivacyCertifiedKind, class: sidecartest.PrivacyClassHandler},
		{row: "sock-2", kind: socketPrivacyAcmeKind, class: sidecartest.PrivacyClassHandler},
		{row: "sock-2", kind: socketPrivacyUnlistedKind, class: sidecartest.PrivacyClassHandler},
	} {
		if err := capture.Declare(declaration.row, declaration.kind, declaration.class); err != nil {
			t.Fatal(err)
		}
	}
	capture.AddSource(world.store.PrivacyItems)
	now := world.net.Clock().Now()
	sidecarId := connect.Id(world.listener.device.SidecarId)
	world.setFacts(func(facts *socketsservice.TlsListenFacts) {
		facts.CustomCertified = []*socketsservice.TlsListenCustomName{
			{SidecarId: sidecarId, Owner: "blog", Name: names.certified, NotAfter: now.Add(30 * 24 * time.Hour)},
		}
		facts.AcmeClaims = []*socketsservice.TlsListenAcmeClaim{
			{SidecarId: sidecarId, Owner: "blog", Name: names.acme, ClaimSeq: 3},
		}
	})
	listener := world.listenerOf(world.listener.device)
	if status := world.heartbeat(listener, "blog", socketSuiteBothAlpns, []string{names.certified},
		[]*sidecar.SocketAcmeName{{Name: names.acme, ClaimSeq: 3}}); status != sidecar.SocketRegistrationStatusOk {
		t.Fatalf("the canaries' heartbeat answered %s", status)
	}
	if primary, _, code := world.edgeFind("blog", []string{"h2"}, names.certified); code != "" || primary != listener {
		t.Fatalf("the certified canary's Find answered %q", code)
	}
	if primary, _, code := world.edgeFind("blog", socketSuiteAcmeAlpns, names.acme); code != "" || primary != listener {
		t.Fatalf("the ACME canary's Find answered %q", code)
	}
	if _, _, code := world.edgeFind("blog", []string{"h2"}, names.unlisted); code != sidecar.SocketErrorCodeNoListener {
		t.Fatalf("the unlisted canary's Find answered %q", code)
	}
	return names
}

// Each custom name is only where its row says a server sees it, and nowhere else: no log, metric or hint holds one,
// and no store keeps the server name of a Find no listener lists. The store does hold the certified and the ACME host,
// so the scan read them where sock-1 keeps them.
func TestSocketCustomNameCanariesReachOnlyTheirRows(t *testing.T) {
	world := newSocketSuiteCustomWorld(t)
	names := socketPrivacyCustomRun(t, world)
	capture := world.net.Capture()
	for _, finding := range capture.Scan() {
		t.Errorf("%s", finding)
	}
	stored := map[string]bool{}
	for _, item := range world.store.PrivacyItems() {
		for _, name := range []string{names.certified, names.acme, names.unlisted} {
			if bytes.Contains(item.Body, []byte(name)) {
				stored[name] = true
			}
		}
	}
	if !stored[names.certified] || !stored[names.acme] {
		t.Fatalf("the store holds the certified host %v and the ACME host %v, so the scan read nothing there", stored[names.certified], stored[names.acme])
	}
	if stored[names.unlisted] {
		t.Fatal("the store keeps a Find's server name")
	}
	for _, class := range []sidecartest.PrivacyClass{sidecartest.PrivacyClassHandler, sidecartest.PrivacyClassMetric} {
		if capture.ItemCount(class) == 0 {
			t.Fatalf("nothing reached %s, so the scan read nothing there", class)
		}
	}
}

// Under sidecar_leaktest: a custom name leaked through a class no row lets it reach is found there, the certified host
// in a stored object, a log, a metric and a hint, and the unlisted host, a Find's server name, in Redis, so a name
// that reached one of them would not pass unseen.
func TestSocketCustomNameLeakedIntoEachClassIsCaught(t *testing.T) {
	if !sidecartest.LeaksLinked {
		t.Skip("the leaks link only under sidecar_leaktest, which test.sh's leak leg builds")
	}
	leaks := sidecartest.LeakClasses()
	for _, c := range []struct {
		class sidecartest.PrivacyClass
		kind  string
	}{
		{class: sidecartest.PrivacyClassObject, kind: socketPrivacyCertifiedKind},
		{class: sidecartest.PrivacyClassLog, kind: socketPrivacyCertifiedKind},
		{class: sidecartest.PrivacyClassMetric, kind: socketPrivacyCertifiedKind},
		{class: sidecartest.PrivacyClassHint, kind: socketPrivacyCertifiedKind},
		{class: sidecartest.PrivacyClassRedis, kind: socketPrivacyUnlistedKind},
	} {
		leak := leaks[c.class]
		if leak == nil {
			t.Fatalf("%s has no leak", c.class)
		}
		func() {
			world := newSocketSuiteCustomWorld(t)
			names := socketPrivacyCustomRun(t, world)
			if findings := world.net.Capture().Scan(); len(findings) != 0 {
				t.Fatalf("%s: findings before the leak: %v", c.class, findings)
			}
			leaked := names.certified
			if c.kind == socketPrivacyUnlistedKind {
				leaked = names.unlisted
			}
			leak.Put(t, world.net, []byte(leaked))
			caught := false
			for _, finding := range world.net.Capture().Scan() {
				if finding.Needle == c.kind && finding.Class == c.class {
					caught = true
				}
			}
			if !caught {
				t.Errorf("the %s leaked into %s was not found", c.kind, c.class)
			}
		}()
	}
}

// 17.2.16's clauses of sock-1 and sock-2 (TLS-M6-08), each with the wire fields, as Type.json_name, that carry its
// value.
var testSocketCustomClauses = []struct {
	row    string
	clause string
	fields []string
}{
	{row: "sock-1", clause: "per tls/ listener the custom hosts and aliases it is certified for", fields: []string{"SocketRegistration.certified_names"}},
	{row: "sock-1", clause: "the names it holds an ACME claim for with the claim sequence", fields: []string{"SocketAcmeName.claim_seq", "SocketAcmeName.name", "SocketRegistration.acme_names"}},
	{row: "sock-2", clause: "the server name of a dial that came by a custom host or an alias", fields: []string{"SocketFindArgs.server_name"}},
}

// The wire types those fields are of, by name.
var testSocketCustomTypes = map[string]reflect.Type{
	"SocketRegistration": reflect.TypeFor[sidecar.SocketRegistration](),
	"SocketAcmeName":     reflect.TypeFor[sidecar.SocketAcmeName](),
	"SocketFindArgs":     reflect.TypeFor[sidecar.SocketFindArgs](),
}

// The fields of value, a struct or a pointer to one, as Type.json_name, that hold a needle: a string, string list or
// bytes containing one of needles, or a whole number among numbers. A field holding a struct, or a list of them, that
// holds one is named with the fields inside that do. Sorted, each once.
func testSocketFieldsHolding(value reflect.Value, needles []string, numbers []uint64) []string {
	for value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return nil
	}
	contains := func(text []byte) bool {
		return slices.ContainsFunc(needles, func(needle string) bool {
			return bytes.Contains(text, []byte(needle))
		})
	}
	fields := []string{}
	structType := value.Type()
	for index := range structType.NumField() {
		field := structType.Field(index)
		jsonName, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if !field.IsExported() || jsonName == "" || jsonName == "-" {
			continue
		}
		holds := false
		var walk func(fieldValue reflect.Value)
		walk = func(fieldValue reflect.Value) {
			switch fieldValue.Kind() {
			case reflect.String:
				holds = holds || contains([]byte(fieldValue.String()))
			case reflect.Uint, reflect.Uint32, reflect.Uint64:
				holds = holds || slices.Contains(numbers, fieldValue.Uint())
			case reflect.Int, reflect.Int32, reflect.Int64:
				holds = holds || (0 <= fieldValue.Int() && slices.Contains(numbers, uint64(fieldValue.Int())))
			case reflect.Slice:
				if fieldValue.Type().Elem().Kind() == reflect.Uint8 {
					holds = holds || contains(fieldValue.Bytes())
					return
				}
				for elementIndex := range fieldValue.Len() {
					walk(fieldValue.Index(elementIndex))
				}
			case reflect.Pointer, reflect.Struct:
				if inner := testSocketFieldsHolding(fieldValue, needles, numbers); 0 < len(inner) {
					holds = true
					fields = append(fields, inner...)
				}
			}
		}
		walk(value.Field(index))
		if holds {
			fields = append(fields, structType.Name()+"."+jsonName)
		}
	}
	slices.Sort(fields)
	return slices.Compact(fields)
}

// §22.7's schema guard for 17.2.16's clauses of sock-1 and sock-2 (I-18), both ways. Each clause is its row's, a live
// one, and no other row's, and each field it names is on the wire. The other way, at run time: of what the store keeps
// for a listener listing a certified host and an ACME claim, the fields holding either name or the claim sequence are
// exactly sock-1's clauses' fields; of a Find naming a custom host, the field holding it is exactly sock-2's clause's;
// and after a Find names a host no listener lists, no store keeps it, as sock-2 has it, for the request alone.
func TestSocketCustomNameClausesMapBothWays(t *testing.T) {
	list, err := sidecartest.LoadMetadataList()
	if err != nil {
		t.Fatal(err)
	}
	rowFields := map[string][]string{}
	for _, clause := range testSocketCustomClauses {
		saying := []string{}
		for _, row := range list.LiveRows() {
			if strings.Contains(row.Sees, clause.clause) {
				saying = append(saying, row.Id)
			}
		}
		if !slices.Equal(saying, []string{clause.row}) {
			t.Errorf("%q is said by %v, not %s alone", clause.clause, saying, clause.row)
		}
		for _, field := range clause.fields {
			typeName, jsonName, _ := strings.Cut(field, ".")
			structType := testSocketCustomTypes[typeName]
			found := false
			if structType != nil {
				for structField := range structType.Fields() {
					if name, _, _ := strings.Cut(structField.Tag.Get("json"), ","); name == jsonName {
						found = true
					}
				}
			}
			if !found {
				t.Errorf("%q names %s, which is on no wire type", clause.clause, field)
			}
		}
		rowFields[clause.row] = append(rowFields[clause.row], clause.fields...)
	}
	for row := range rowFields {
		slices.Sort(rowFields[row])
	}

	// the other way, at run time
	world := newSocketSuiteCustomWorld(t)
	now := world.net.Clock().Now()
	sidecarId := connect.Id(world.listener.device.SidecarId)
	certifiedName := "clause-certified.customer.example"
	acmeName := "clause-acme.customer.example"
	claimSeq := uint64(7340033)
	world.setFacts(func(facts *socketsservice.TlsListenFacts) {
		facts.CustomCertified = []*socketsservice.TlsListenCustomName{
			{SidecarId: sidecarId, Owner: "blog", Name: certifiedName, NotAfter: now.Add(30 * 24 * time.Hour)},
		}
		facts.AcmeClaims = []*socketsservice.TlsListenAcmeClaim{
			{SidecarId: sidecarId, Owner: "blog", Name: acmeName, ClaimSeq: claimSeq},
		}
	})
	listener := world.listenerOf(world.listener.device)
	if status := world.heartbeat(listener, "blog", socketSuiteBothAlpns, []string{certifiedName},
		[]*sidecar.SocketAcmeName{{Name: acmeName, ClaimSeq: claimSeq}}); status != sidecar.SocketRegistrationStatusOk {
		t.Fatalf("the heartbeat answered %s", status)
	}
	stored := world.stored(listener, "blog")
	if held := testSocketFieldsHolding(reflect.ValueOf(stored), []string{certifiedName, acmeName}, []uint64{claimSeq}); !slices.Equal(held, rowFields["sock-1"]) {
		t.Errorf("of the lease the store keeps, %v hold the names and the claim, and sock-1's clauses name %v", held, rowFields["sock-1"])
	}
	unlistedName := "clause-unlisted.customer.example"
	networkId := world.networkId
	find := &sidecar.SocketFindArgs{
		Name:       "tls/443/blog",
		NetworkId:  &networkId,
		ClientIds:  world.edge.clientIds,
		Protocol:   "tls",
		Alpn:       []string{"h2"},
		ServerName: unlistedName,
	}
	if held := testSocketFieldsHolding(reflect.ValueOf(find), []string{unlistedName}, nil); !slices.Equal(held, rowFields["sock-2"]) {
		t.Errorf("of a Find, %v hold its server name, and sock-2's clause names %v", held, rowFields["sock-2"])
	}
	result := &sidecar.SocketFindResult{}
	if code := world.call(http.MethodPost, "/socket/find", world.edge.token, find, result); code != http.StatusOK || result.Error == nil ||
		result.Error.Code != sidecar.SocketErrorCodeNoListener {
		t.Fatalf("the unlisted host's Find answered %d, %+v", code, result.Error)
	}
	for _, item := range world.store.PrivacyItems() {
		if bytes.Contains(item.Body, []byte(unlistedName)) {
			t.Fatalf("%s keeps a Find's server name", item.Name)
		}
	}
}
