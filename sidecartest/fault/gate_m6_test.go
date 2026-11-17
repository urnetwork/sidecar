package fault

// M6's sweep (gate_m6.go) and QD-1008's cases as gates.yml shows them: FS-126 at M6 runs sidecartest's P2P tests on
// T2 beside the convention's T3 test, which nothing has written, so the row reads missing and never passes early; FS-25's
// dns-route case at M5 runs the convention's T3 test alone.

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

// FS-126's row names p2p_test.go's tests where they run and the convention's T3 test, nothing else, at M6 alone.
func TestGateFileShowsFs126BySidecartestsP2pTests(t *testing.T) {
	catalog := DefaultCatalog()
	data, err := GateFile(catalog)
	if err != nil {
		t.Fatal(err)
	}
	file := parseGateFileForTest(t, data)
	fs126 := gateFileRow(file, "M6", "FS-126", "")
	if fs126 == nil || len(fs126.Tests) != 2 || fs126.External != "" || fs126.StoreClock {
		t.Fatalf("FS-126 at M6: %+v", fs126)
	}
	t2 := fs126.Tests[0]
	if t2.Repo != "sidecar" || t2.Package != "./sidecartest" || t2.Tags != "" || t2.Stores ||
		!slices.Equal(t2.Names, []string{"TestP2pOffByDefault", "TestP2pPairMovesAndBackUnderALiveRpcAndStream", "TestP2pForgedControlIdStaysDroppedWithP2pOn"}) {
		t.Errorf("FS-126's T2 tests: %+v", t2)
	}
	// the T3 entry is the convention's, so the row reads missing until a T3 test of the schedule is named
	var convention *GateTest
	for _, test := range gateConventionalTests(catalog.Case("FS-126", "")) {
		if test.Repo == "server" {
			convention = test
		}
	}
	if convention == nil || !reflect.DeepEqual(gateFs126T3Test, convention) {
		t.Errorf("FS-126's T3 test %+v, the convention's %+v", gateFs126T3Test, convention)
	}
	if t3 := fs126.Tests[1]; t3.Repo != "server" || t3.Package != "./sidecart3" || !t3.Stores || !slices.Equal(t3.Names, []string{"TestFs126OnT3"}) {
		t.Errorf("FS-126's T3 test in gates.yml: %+v", t3)
	}
	for _, gate := range GateNames() {
		if gate != "M6" && gateFileRow(file, gate, "FS-126", "") != nil {
			t.Errorf("FS-126 sits at %s", gate)
		}
	}
}

// Each test the sweep names for FS-126 on T2 is declared in sidecartest/p2p_test.go, so a rename there fails here
// rather than only reading missing at the gate.
func TestGateFs126TestsAreDeclaredInP2pTest(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "p2p_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range gateFs126T2Test.Names {
		if !bytes.Contains(data, []byte("\nfunc "+name+"(t *testing.T) {")) {
			t.Errorf("sidecartest/p2p_test.go declares no %s", name)
		}
	}
}

// FS-25's dns-route case runs at M5 on T3 alone, by the convention's test; its main case keeps M3 on both tiers.
func TestGateFileShowsFs25sDnsRouteCaseOnT3(t *testing.T) {
	data, err := GateFile(DefaultCatalog())
	if err != nil {
		t.Fatal(err)
	}
	file := parseGateFileForTest(t, data)
	dnsRoute := gateFileRow(file, "M5", "FS-25", "dns-route")
	if dnsRoute == nil || len(dnsRoute.Tests) != 1 || dnsRoute.External != "" {
		t.Fatalf("FS-25's dns-route at M5: %+v", dnsRoute)
	}
	if test := dnsRoute.Tests[0]; test.Repo != "server" || test.Package != "./sidecart3" || !test.Stores || !slices.Equal(test.Names, []string{"TestFs25DnsRouteOnT3"}) {
		t.Errorf("FS-25's dns-route test: %+v", test)
	}
	if main := gateFileRow(file, "M3", "FS-25", ""); main == nil || len(main.Tests) != 2 {
		t.Errorf("FS-25 at M3: %+v", main)
	}
	if gateFileRow(file, "M3", "FS-25", "dns-route") != nil || gateFileRow(file, "M5", "FS-25", "") != nil {
		t.Error("FS-25's cases moved gates")
	}
}
