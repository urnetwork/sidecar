//go:build sidecar_check

// The test rules' planted violations, one per rule and form, each failing with its file and line, and
// the clean forms each allows. A planted address or hostname is built from pieces, so this file's own
// literals stay synthetic under the rule it tests.

package check

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A routable address and a real hostname, assembled so no one literal here holds either.
var (
	plantedRoutableAddress = "198.51." + "99.7"
	plantedRoutableIpv6    = "2a00" + ":1450::7"
	plantedRealHostname    = "api.planted-host." + "com"
)

// A test file of the root package with body inside its one test.
func plantedTestFile(imports string, body string) string {
	return "package sidecar\n\nimport (\n\t\"testing\"\n" + imports + ")\n\nfunc TestPlanted(t *testing.T) {\n" + body + "}\n"
}

func TestTestRulesFailOnASleepInATest(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("planted_test.go", plantedTestFile("\t\"time\"\n", "\ttime.Sleep(time.Millisecond)\n"))
	wantFindings(t, fixture.open().realTimeWaitFindings(t), "planted_test.go:9: time.Sleep waits in real time")
}

// A timeout whose firing is the pass proves absence by waiting: CODESTYLE's short negative timeout.
func TestTestRulesFailOnANegativeTimeout(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("planted_test.go", plantedTestFile("\t\"time\"\n",
		"\tchanged := make(chan struct{})\n\tselect {\n\tcase <-changed:\n\t\tt.Fatal(\"changed\")\n\tcase <-time.After(50 * time.Millisecond):\n\t}\n"))
	wantFindings(t, fixture.open().realTimeWaitFindings(t), "planted_test.go:13: time.After starts a real timer that is no failing guard")
}

// A timer held in a variable is a guard only if every clause receiving it fails the test.
func TestTestRulesFailOnATimerHeldAndNeverFailing(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("planted_test.go", plantedTestFile("\t\"time\"\n",
		"\tchanged := make(chan struct{})\n\tquiet := time.After(time.Second)\n\tselect {\n\tcase <-changed:\n\t\tt.Fatal(\"changed\")\n\tcase <-quiet:\n\t}\n"))
	wantFindings(t, fixture.open().realTimeWaitFindings(t), "planted_test.go:10: time.After starts a real timer that is no failing guard")
}

// Every module's tests are read, a nested module's included.
func TestTestRulesFailOnASleepInANestedModule(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("cli/planted_test.go", "package main\n\nimport (\n\t\"testing\"\n\t\"time\"\n)\n\nfunc TestPlanted(t *testing.T) {\n\ttime.Sleep(time.Millisecond)\n}\n")
	wantFindings(t, fixture.open().realTimeWaitFindings(t), "cli/planted_test.go:9: time.Sleep waits in real time")
}

// A guard that fails the test when it fires is allowed, inline or held in a variable, as is a timeout
// on the fake clock, which is no timer of time's.
func TestTestRulesAllowFailingGuardsAndTheFakeClock(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("planted_test.go", plantedTestFile("\t\"errors\"\n\t\"time\"\n",
		"\tchanged := make(chan struct{})\n"+
			"\tselect {\n\tcase <-changed:\n\tcase <-time.After(10 * time.Second):\n\t\tt.Fatal(\"hung\")\n\t}\n"+
			"\tdeadline := time.After(10 * time.Second)\n\tfor {\n\t\tselect {\n\t\tcase <-changed:\n\t\t\treturn\n\t\tcase <-deadline:\n\t\t\tt.Fatalf(\"hung\")\n\t\t}\n\t}\n"+
			"\twait := func() error {\n\t\tselect {\n\t\tcase <-changed:\n\t\t\treturn nil\n\t\tcase <-time.After(time.Minute):\n\t\t\treturn errors.New(\"hung\")\n\t\t}\n\t}\n\t_ = wait\n"+
			"\tvar clock interface{ After(time.Duration) <-chan time.Time }\n\tif clock != nil {\n\t\t<-clock.After(time.Hour)\n\t}\n"))
	wantFindings(t, fixture.open().realTimeWaitFindings(t))
}

func TestTestRulesFailOnAPositiveSubtest(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("planted_test.go", plantedTestFile("", "\tt.Run(\"case\", func(t *testing.T) {})\n"))
	wantFindings(t, fixture.open().positiveSubtestFindings(t), "planted_test.go:8: TestPlanted runs a subtest and drops its result")
}

// A subtest whose result the test reads is one it expects to fail, which CODESTYLE allows.
func TestTestRulesAllowASubtestExpectedToFail(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("planted_test.go", plantedTestFile("",
		"\tif t.Run(\"planted\", func(t *testing.T) { t.Fail() }) {\n\t\tt.Error(\"the planted failure passed\")\n\t}\n"+
			"\tpassed := t.Run(\"planted again\", func(t *testing.T) { t.Fail() })\n\t_ = passed\n"))
	wantFindings(t, fixture.open().positiveSubtestFindings(t))
}

func TestTestRulesFailOnARoutableAddress(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("planted_test.go", plantedTestFile("", "\t_ = \""+plantedRoutableAddress+":443\"\n"))
	wantFindings(t, fixture.open().testDataFindings(t), "planted_test.go:8: "+plantedRoutableAddress+" is a routable address")
}

func TestTestRulesFailOnARoutableIpv6Address(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("planted_test.go", plantedTestFile("", "\t_ = \"["+plantedRoutableIpv6+"]:443\"\n"))
	wantFindings(t, fixture.open().testDataFindings(t), "planted_test.go:8: "+plantedRoutableIpv6+" is a routable address")
}

// A real hostname, as a bare name, a URL's host, an address's domain and a host with a port.
func TestTestRulesFailOnARealHostname(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("planted_test.go", plantedTestFile("",
		"\t_ = \""+plantedRealHostname+"\"\n"+
			"\t_ = \"https://"+plantedRealHostname+"/v1\"\n"+
			"\t_ = \"someone@"+plantedRealHostname+"\"\n"+
			"\t_ = \""+plantedRealHostname+":25\"\n"))
	wantFindings(t, fixture.open().testDataFindings(t),
		"planted_test.go:8: "+plantedRealHostname+" is a real hostname",
		"planted_test.go:9: "+plantedRealHostname+" is a real hostname",
		"planted_test.go:10: "+plantedRealHostname+" is a real hostname",
		"planted_test.go:11: "+plantedRealHostname+" is a real hostname",
	)
}

// An exception lets through its own file and value and nothing beside it.
func TestTestRulesFailOnAValueBesideAListedException(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("tls_caa_test.go", plantedTestFile("", "\t_ = \"letsencrypt.org\"\n\t_ = \""+plantedRealHostname+"\"\n"))
	fixture.write("planted_test.go", plantedTestFile("", "\t_ = \"letsencrypt.org\"\n"))
	wantFindings(t, fixture.open().testDataFindings(t),
		"planted_test.go:8: letsencrypt.org is a real hostname",
		"tls_caa_test.go:9: "+plantedRealHostname+" is a real hostname",
	)
}

// Documentation addresses, the special-purpose ranges, reserved names and dotted names that name no
// host all pass.
func TestTestRulesAllowSyntheticData(t *testing.T) {
	fixture := newFixture(t)
	values := []string{
		"192.0.2.1", "198.51.100.7:25", "203.0.113.9", "[2001:db8::1]:443", "3fff::7", "10.1.2.3", "100.64.0.1",
		"127.0.0.1:8080", "169.254.1.1", "a.example", "mx.b.test", "c.invalid", "localhost:8080", "example.com",
		"mail.example.org", "https://edge.example/v1", "agent@ur.invalid", "evs.head_cas.before", "snapshot.ndjson",
		"committer.email", "run.sh",
	}
	body := ""
	for _, value := range values {
		body += "\t_ = \"" + value + "\"\n"
	}
	fixture.write("planted_test.go", plantedTestFile("", body))
	wantFindings(t, fixture.open().testDataFindings(t))
}

// A fixture with the inventory this checkout's rules would write for it, so a plant is one change away.
func barrierFixture(t *testing.T) *fixture {
	t.Helper()
	fixture := newFixture(t)
	fixture.write("planted_step.go", "package sidecar\n\nfunc plantedStep() {\n\ttestHookBarrier(\"planted.step.before\", \"\")\n\ttestHookSecret(\"K_planted\", nil)\n}\n")
	repository := fixture.open()
	sites, findings := repository.barrierSites(t)
	if len(findings) != 0 {
		t.Fatalf("the clean fixture's sites: %v", findings)
	}
	fixture.write(barrierInventoryPath, barrierInventoryText(sites))
	return fixture
}

func TestBarrierInventoryFailsOnAnUnlistedSite(t *testing.T) {
	fixture := barrierFixture(t)
	fixture.write("planted_new.go", "package sidecar\n\nfunc plantedNew() {\n\ttestHookBarrier(\"planted.cas.after\", \"\")\n}\n")
	wantFindings(t, fixture.open().barrierInventoryFindings(t), "barrier planted.cas.after planted_new.go is a site testdata/barriers.txt does not list")
}

func TestBarrierInventoryFailsOnAStaleLine(t *testing.T) {
	fixture := barrierFixture(t)
	fixture.remove("planted_step.go")
	wantFindings(t, fixture.open().barrierInventoryFindings(t),
		"testdata/barriers.txt lists barrier planted.step.before planted_step.go, which no site holds now",
		"testdata/barriers.txt lists secret K_planted planted_step.go, which no site holds now",
	)
}

// A barrier named by an expression the inventory cannot read fails; a constant, here or in another of
// this repository's packages, and a hook forwarding its parameter are read.
func TestBarrierInventoryFailsOnANameItCannotRead(t *testing.T) {
	fixture := barrierFixture(t)
	fixture.write("planted_dynamic.go", "package sidecar\n\nconst plantedBefore = \"planted.const.before\"\n\nfunc plantedDynamic(step string) {\n\ttestHookBarrier(plantedBefore, \"\")\n\ttestHookBarrier(\"planted.\"+step, \"\")\n}\n\nfunc plantedForward(name string, key string) {\n\ttestHookBarrier(name, key)\n}\n")
	repository := fixture.open()
	sites, findings := repository.barrierSites(t)
	wantFindings(t, findings, "planted_dynamic.go:7: testHookBarrier's name is no literal or constant")
	if !strings.Contains(barrierInventoryText(sites), "barrier planted.const.before planted_dynamic.go\n") {
		t.Errorf("the constant's site is not read:\n%s", barrierInventoryText(sites))
	}
}

// Regenerating this checkout's inventory writes what is committed: a no-op on a clean tree.
func TestBarrierInventoryRegeneratesToItself(t *testing.T) {
	repository, err := thisCheckout()
	if err != nil {
		t.Fatal(err)
	}
	sites, findings := repository.barrierSites(t)
	failFindings(t, "barriers", findings)
	committed, err := os.ReadFile(filepath.Join(repository.moduleDirectory, barrierInventoryPath))
	if err != nil {
		t.Fatal(err)
	}
	if string(committed) != barrierInventoryText(sites) {
		t.Errorf("regenerating %s changes it", barrierInventoryPath)
	}
}

// A schedule naming a barrier with a typo fails statically.
func TestScheduleFailsOnATypoedBarrier(t *testing.T) {
	fixture := barrierFixture(t)
	fixture.write("sidecartest/fault/fs999.go", "package fault\n\ntype Step struct {\n\tAwait   string\n\tRelease []string\n}\n\nvar plantedSteps = []*Step{\n\t{Await: \"planted.stpe.before\"},\n\t{Release: []string{\"planted.step.before@01JTESTKEY\"}},\n}\n")
	wantFindings(t, fixture.open().scheduleBarrierFindings(t), `sidecartest/fault/fs999.go:9: a schedule names barrier "planted.stpe.before"`)
}

// A schedule naming a site through another package's constant, with a key, or through BarrierSite,
// passes.
func TestScheduleAllowsAConstantBarrierAndItsKey(t *testing.T) {
	fixture := barrierFixture(t)
	fixture.write("evsservice/barriers.go", "package evsservice\n\nconst BarrierPlantedCas = \"planted.cas.before\"\n\nfunc plantedCas() {\n\ttestHookBarrier(BarrierPlantedCas, \"\")\n}\n\nfunc testHookBarrier(name string, key string) {}\n")
	fixture.write("sidecartest/fault/fs999.go", "package fault\n\nimport \"@module@/evsservice\"\n\ntype Step struct {\n\tAwait   string\n\tRelease []string\n}\n\nfunc BarrierSite(name string, key string) string { return name + \"@\" + key }\n\nvar plantedSteps = []*Step{\n\t{Await: evsservice.BarrierPlantedCas},\n\t{Await: BarrierSite(\"planted.step.before\", \"01JTESTKEY\")},\n\t{Release: []string{\"planted.step.before@01JTESTKEY\", \"fault.fired\"}},\n}\n")
	wantFindings(t, fixture.open().scheduleBarrierFindings(t))
}
