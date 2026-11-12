package sidecartest

// The scenario runner (scenario.go) held to what it promises: a scenario with no capture over its stores fails, a
// planted leak fails it, so does a flow that plants nothing and a write outside evs's families, the allowlist is on in
// every run, and a registered scenario missing at its gate reads missing.

import (
	"context"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A scenario that plants a canary and writes only what carries none, so the runner's own checks are all it meets.
func honestScenario(id string) *Scenario {
	return &Scenario{Id: id, Run: func(ctx context.Context, run *ScenarioRun) error {
		run.CanaryText("a repo label")
		cluster, err := run.Host("evs").Blobs.FirstCluster()
		if err != nil {
			return err
		}
		if _, err := cluster.PutIfNoneMatch(ctx, "head/"+sidecar.EvsKeyId(sidecar.NewId())+"/_", []byte("sealed"), nil); err != nil {
			return err
		}
		// {evsl_<repo_id>}v, the lease version §2.8's list names
		return run.Host("evs").Redis.Set(ctx, "{evsl_"+sidecar.NewId().String()+"}v", []byte("1"), 0)
	}}
}

// What a run's report says, as one text.
func scenarioReportText(report *ScenarioReport) string {
	parts := slices.Clone(report.Problems)
	parts = append(parts, report.GuardFindings...)
	parts = append(parts, report.StoredFindings...)
	for _, finding := range report.Findings {
		parts = append(parts, finding.String())
	}
	if report.FlowErr != nil {
		parts = append(parts, report.FlowErr.Error())
	}
	return strings.Join(parts, "\n")
}

// A flow that plants a canary and writes nothing the stores must not hold passes every check.
func TestAnHonestScenarioPasses(t *testing.T) {
	report := RunScenario(t, honestScenario("S3a"), nil)
	if !report.Passed() {
		t.Errorf("an honest scenario: %s", scenarioReportText(report))
	}
}

// A planted leak fails a scenario: a canary the flow writes into an object is found there.
func TestAPlantedLeakFailsAScenario(t *testing.T) {
	report := runScenario(t, &Scenario{Id: "S3a", Run: func(ctx context.Context, run *ScenarioRun) error {
		canary := run.Canary("a commit message")
		cluster, err := run.Host("evs").Blobs.FirstCluster()
		if err != nil {
			return err
		}
		_, err = cluster.PutIfNoneMatch(ctx, "head/"+sidecar.EvsKeyId(sidecar.NewId())+"/_", canary, nil)
		return err
	}}, nil)
	if report.Passed() || !slices.ContainsFunc(report.Findings, func(finding *PrivacyFinding) bool {
		return finding.Needle == "a commit message" && finding.Class == PrivacyClassObject
	}) {
		t.Errorf("a leak into an object: %s", scenarioReportText(report))
	}
}

// A scenario with no capture running over its stores fails: here its engines' host holds objects of a store the Net
// never captures, as a T3 run that left CaptureStores out would.
func TestAScenarioWithNoCaptureRunningFails(t *testing.T) {
	settings := DefaultNetSettings()
	settings.Engines = func(ctx context.Context, net *Net) (*sidecar.ServiceHost, func(), error) {
		host := *net.Fakes().ServiceHost()
		host.Blobs = NewFakeBlobs(net.Clock(), net.Faults(), net.Barriers(), nil)
		return &host, func() {}, nil
	}
	report := runScenario(t, honestScenario("S3a"), &ScenarioSettings{Net: settings})
	if report.Passed() || !strings.Contains(scenarioReportText(report), "no capture runs over the Net's objects") {
		t.Errorf("an uncaptured store: %s", scenarioReportText(report))
	}
}

// A flow that plants no canary fails, since its scan proves nothing of the fields it touched.
func TestAScenarioPlantingNoCanaryFails(t *testing.T) {
	report := runScenario(t, &Scenario{Id: "S3a", Run: func(ctx context.Context, run *ScenarioRun) error {
		return nil
	}}, nil)
	if report.Passed() || !strings.Contains(scenarioReportText(report), "planted no canary") {
		t.Errorf("no canary: %s", scenarioReportText(report))
	}
}

// evs writing outside its families fails the scenario, through the host the flow built it with.
func TestAWriteOutsideItsFamiliesFailsAScenario(t *testing.T) {
	report := runScenario(t, &Scenario{Id: "S4a", Run: func(ctx context.Context, run *ScenarioRun) error {
		run.CanaryText("a device name")
		return run.Host("evs").Redis.Set(ctx, "{tok_x}k", []byte("v"), 0)
	}}, nil)
	if report.Passed() || !strings.Contains(scenarioReportText(report), "evs wrote {tok_x}k by set") {
		t.Errorf("a write outside evs's families: %s", scenarioReportText(report))
	}
}

// The allowlist is on in every run: a strict_exp bearer's request to a route off §7.4's allowlist answers 403 "A
// sidecar token cannot call this route." and is reported, one on it reaches its route, and a request with no strict_exp
// bearer is the route's own.
func TestTheAllowlistIsOnInEveryRun(t *testing.T) {
	report := RunScenario(t, &Scenario{Id: "S3a", Run: func(ctx context.Context, run *ScenarioRun) error {
		run.CanaryText("a client name")
		api, err := run.Net.Api()
		if err != nil {
			return err
		}
		token := api.ClientToken(run.Net.DefaultNetworkId(), sidecar.NewId(), sidecar.NewId())
		client := &http.Client{Transport: api.Transport()}
		call := func(method string, path string) (int, string) {
			request, err := http.NewRequestWithContext(ctx, method, api.Origin()+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Bearer "+token)
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, _ := io.ReadAll(response.Body)
			return response.StatusCode, strings.TrimSpace(string(body))
		}
		if status, body := call(http.MethodPost, "/auth/code-create"); status != http.StatusForbidden || body != "A sidecar token cannot call this route." {
			t.Errorf("an admin route: %d %q", status, body)
		}
		if status, body := call(http.MethodGet, "/subscription/balance"); status != http.StatusForbidden || body != "A sidecar token cannot call this route." {
			t.Errorf("a payment route: %d %q", status, body)
		}
		if status, _ := call(http.MethodGet, "/sidecar/identity/"+sidecar.NewId().String()); status == http.StatusForbidden {
			t.Errorf("an allowlisted route was refused")
		}
		return nil
	}}, nil)
	if !slices.Equal(report.RefusedRoutes, []string{"POST /auth/code-create", "GET /subscription/balance"}) {
		t.Errorf("refused %q", report.RefusedRoutes)
	}
	for _, allowed := range [][2]string{{"GET", "/auth/refresh"}, {"POST", "/network/config/delta"}, {"PUT", "/network/bridge/share/s1"}, {"POST", "/oauth/token"}} {
		if !SidecarRouteAllowed(allowed[0], allowed[1]) {
			t.Errorf("%s %s is off the allowlist", allowed[0], allowed[1])
		}
	}
	for _, refused := range [][2]string{{"POST", "/auth/refresh"}, {"GET", "/network/clients"}, {"POST", "/abuse/status"}, {"POST", "/stats/providers"}} {
		if SidecarRouteAllowed(refused[0], refused[1]) {
			t.Errorf("%s %s is on the allowlist", refused[0], refused[1])
		}
	}
}

// A registered scenario missing at its gate reads missing, part by part: at M2-out on T2 every part of S3a and S4a
// and S2 until registered, and on T3 S1's; a registration takes its part out and leaves its siblings; a registration
// of a part, a tier or a scenario §22.7 does not hold fails.
func TestARegisteredScenarioMissingAtItsGateReadsMissing(t *testing.T) {
	registry := NewScenarioRegistry()
	names := func(parts []*ScenarioPart) []string {
		out := []string{}
		for _, part := range parts {
			out = append(out, part.String())
		}
		return out
	}
	missing := names(registry.Missing("M2-out", ScenarioTierT2))
	for _, want := range []string{"S2", "S3a's forged-admission-refused", "S4a's writers-seal-nothing-to-x"} {
		if !slices.Contains(missing, want) {
			t.Errorf("%s does not read missing at M2-out on T2: %q", want, missing)
		}
	}
	if slices.ContainsFunc(missing, func(name string) bool { return strings.HasPrefix(name, "S1") }) {
		t.Errorf("S1 reads missing on T2, where it never runs: %q", missing)
	}
	if t3 := names(registry.Missing("M2-out", ScenarioTierT3)); !slices.Contains(t3, "S1's code-create-403") {
		t.Errorf("S1 is not missing on T3: %q", t3)
	}
	test := &ScenarioTest{Repo: "sidecar", Package: "github.com/urnetwork/sidecar/sidecartest", Name: "TestPlanted"}
	if err := registry.Register("S3a", "readerkey-valid-over-7-days-refused", ScenarioTierT2, test); err != nil {
		t.Fatal(err)
	}
	after := names(registry.Missing("M2-out", ScenarioTierT2))
	if slices.Contains(after, "S3a's readerkey-valid-over-7-days-refused") || !slices.Contains(after, "S3a's forged-admission-refused") {
		t.Errorf("after one registration: %q", after)
	}
	for _, refused := range []struct {
		id, clause, tier string
	}{
		{id: "S3a", clause: "no-such-clause", tier: ScenarioTierT2},
		{id: "S1", clause: "code-create-403", tier: ScenarioTierT2},
		{id: "S14", clause: "", tier: ScenarioTierT2},
		{id: "S3a", clause: "readerkey-valid-over-7-days-refused", tier: ScenarioTierT2},
	} {
		if err := registry.Register(refused.id, refused.clause, refused.tier, test); err == nil {
			t.Errorf("registered %s's %q on %s", refused.id, refused.clause, refused.tier)
		}
	}
	if len(registry.Rows()) != 15 || registry.Row("S13").Flow != "F13" || registry.Row("S4a").Flow != "F9" {
		t.Errorf("the rows: %d", len(registry.Rows()))
	}
}

// Every scenario row names its flow by D-ARCH-3's map, every tier is a tier, and S1 runs on T3 alone.
func TestScenarioRowsFollowTheFlowMap(t *testing.T) {
	flows := map[string]string{"S1": "F1", "S2": "F2", "S3a": "F3", "S3b": "F3", "S4a": "F9", "S4b": "F9", "S5": "F4", "S6": "F5",
		"S7": "F6", "S8": "F7", "S9": "F8", "S10": "F10", "S11": "F11", "S12": "F12", "S13": "F13"}
	for _, row := range NewScenarioRegistry().Rows() {
		if flows[row.Id] != row.Flow {
			t.Errorf("%s runs %s", row.Id, row.Flow)
		}
		for _, tier := range row.Tiers {
			if tier != ScenarioTierT2 && tier != ScenarioTierT3 && tier != ScenarioTierT6 {
				t.Errorf("%s names tier %s", row.Id, tier)
			}
		}
		if row.Id == "S1" && !slices.Equal(row.Tiers, []string{ScenarioTierT3}) {
			t.Errorf("S1 runs on %v", row.Tiers)
		}
		if t6 := slices.Contains(row.Tiers, ScenarioTierT6); t6 != slices.Contains([]string{"S5", "S6", "S7", "S8", "S10"}, row.Id) {
			t.Errorf("%s runs on T6: %t", row.Id, t6)
		}
	}
}

// What the default registry reads at M2-out for this task's rows (TEST-M2-11): S1's three clauses each have their T3
// test, and S3a's only missing part on either tier is each late wrap judged at its own pin, FS-104's, which waits on
// KEYS-M2-29's oracle; S4a's revocation-suite parts read missing until TEST-M2-12 composes them.
func TestTheDefaultRegistryReadsWhatThisTaskBuilt(t *testing.T) {
	registry := DefaultScenarioRegistry()
	missingOf := func(scenarioId string, tier string) []string {
		out := []string{}
		for _, part := range registry.Missing("M2-out", tier) {
			if part.Row.Id == scenarioId {
				out = append(out, part.Clause)
			}
		}
		return out
	}
	if missing := missingOf("S1", ScenarioTierT3); len(missing) != 0 {
		t.Errorf("S1 reads missing on T3: %q", missing)
	}
	for _, tier := range []string{ScenarioTierT2, ScenarioTierT3} {
		if missing := missingOf("S3a", tier); !slices.Equal(missing, []string{"late-wrap-judged-at-its-pin"}) {
			t.Errorf("S3a's missing parts on %s: %q", tier, missing)
		}
		missing := missingOf("S4a", tier)
		for _, want := range []string{"gates-closed-until-a-covering-generation", "members-refuse-a-bad-commit", "tokens-fail-in-their-windows", "path-epoch-and-checkpoint"} {
			if !slices.Contains(missing, want) {
				t.Errorf("S4a's %s does not read missing on %s: %q", want, tier, missing)
			}
		}
		if slices.Contains(missing, "writers-seal-nothing-to-x") || slices.Contains(missing, "next-generation-fails-under-xs-keys") {
			t.Errorf("S4a's composed parts read missing on %s: %q", tier, missing)
		}
	}
	tests := registry.Tests("S1", "genesis-other-than-the-invites-refused", ScenarioTierT3)
	if len(tests) != 1 || tests[0].Repo != "server" || tests[0].Name != "TestScenarioS1GenesisOnT3" {
		t.Errorf("S1's genesis clause is registered to %v", tests)
	}
}
