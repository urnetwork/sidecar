// §22.7's privacy harness on sockets (SOCK-M5-16; D-SOCK-13, R-SOCK-9, I-13, I-18, owner decision 67), on the
// suite's world (socket_suite_test.go): application socket names are canaries, as a person's own names would be,
// registered, listed and dialed through the engine as the client side makes them, token paths and seals under the
// network's K_sock; and K_sock is a secret, with K_tok and K_seal too wherever sidecar_testhooks hooks their
// derivation. No handler capture (CC1, where every registration, listing and Find call is captured as the engine
// takes and answers it), no Redis value the store keeps (CC3, the fake store's contents standing for server's
// {sg_}, {sn_}, {sc_} and {svc_}), no log, metric or hint (CC4) holds a name in the clear, a seal's plaintext or a
// key. Under sidecar_leaktest a canary leaked into each class through the class's own leak is found, so the clean
// scan is no blind one.

package sidecartest_test

import (
	"bytes"
	"os"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
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
