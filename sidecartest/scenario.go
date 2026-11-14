// §22.7's scenarios (TEST-M2-11; D-TEST-5, R-TEST-3, R-TEST-4, D-ARCH-3): each of §3.7's flows, S1 to S13 for F1 to
// F13, run under the privacy harness and the schema guard, which RunScenario holds every scenario to, so an area's
// scenario cannot skip them:
//
//   - §7.4's route allowlist on: the Net's api refuses a strict_exp bearer every route off it, 403 "A sidecar token
//     cannot call this route." as route_authz.go's fail-closed gate does (FakeApi.SetRouteGate), on T2 with the
//     design's list (SidecarRouteAllowed) and on T3 with server's own route table;
//   - canaries planted in every user field the flow touches, through the run's Canary and CanaryText, which count
//     them, so a flow that plants none fails;
//   - the Net's capture running over its stores: a store holding what the flow wrote that the capture holds nothing
//     of fails the run, so a tier that left its stores' capture out (T3's CaptureStores) passes nothing;
//   - at the end: the scan finds nothing, SchemaGuard.CheckStores classifies every key the stores hold, the stored
//     commits pass §22.7's PrivateMessage assert (GkmCommitHeader's two fields alone in S3 and S4), and the writers'
//     record (StoredWriters) shows evs and gkm in their families alone.
//
// The registry is §22.7's list with each scenario's flow, tiers (T2 then T3; S1 on T3 alone, since a fake api proves
// nothing about its 403; T6 repeats S5 to S8 and S10), gates and owners, and RegisterScenario ties a test to a row on
// a tier, so a scenario nobody built reads missing at its gates (Missing), never passing. Composition adds no
// mechanism: a scenario runs its owners' flows, and a failure goes back to the owner.
//
// A scenario enrolls through the routes, never a privileged fixture (§22.8's real rule). Safe for concurrent use;
// RunScenario builds one Net at a time, as a Net's hooks require.

package sidecartest

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
)

// One of §22.7's scenarios, as its row stands.
type ScenarioRow struct {
	// "S1", "S3a".
	Id string
	// §3.7's flow it runs (D-ARCH-3): "F1".
	Flow string
	// T2, T3 and T6, those it runs on.
	Tiers []string
	// Where it must pass: Mn-out.
	Gates []string
	// The tasks that build it.
	Owners []string
	// Its stored commits' GkmCommitHeader carries only the generation and the auth pin (S3 and S4, D-KEYS-3).
	HeaderOnly bool
	// Its parts a gate reports one by one, §22.7's clauses, so a gate never reads one part's pass as another's.
	// Empty: the row is one part, named "".
	Clauses []string
}

// The parts of the row, "" for a row of one part.
func (self *ScenarioRow) Parts() []string {
	if len(self.Clauses) == 0 {
		return []string{""}
	}
	return slices.Clone(self.Clauses)
}

// One part of a row, as a gate reports it.
type ScenarioPart struct {
	Row    *ScenarioRow
	Clause string
}

func (self *ScenarioPart) String() string {
	if self.Clause == "" {
		return self.Row.Id
	}
	return self.Row.Id + "'s " + self.Clause
}

// The tiers a scenario row may name (§22.4).
const (
	ScenarioTierT2 = "T2"
	ScenarioTierT3 = "T3"
	ScenarioTierT6 = "T6"
)

// §22.7's scenarios, with the plan's owners and each owner's milestone exit as the gate (TEST.md's scenario row).
func scenarioRows() []*ScenarioRow {
	t2t3 := []string{ScenarioTierT2, ScenarioTierT3}
	t2t3t6 := []string{ScenarioTierT2, ScenarioTierT3, ScenarioTierT6}
	return []*ScenarioRow{
		{Id: "S1", Flow: "F1", Tiers: []string{ScenarioTierT3}, Gates: []string{"M2-out"}, Owners: []string{"TEST-M2-11"}, Clauses: []string{
			"code-create-403", "token-never-in-mcp-env-or-logs", "genesis-other-than-the-invites-refused",
		}},
		{Id: "S2", Flow: "F2", Tiers: t2t3, Gates: []string{"M2-out"}, Owners: []string{"EVS1-M2-42"}},
		{Id: "S3a", Flow: "F3", Tiers: t2t3, Gates: []string{"M2-out"}, Owners: []string{"TEST-M2-11"}, HeaderOnly: true, Clauses: []string{
			"forged-admission-refused", "forged-keypackage-refused", "forged-readerkey-refused", "readerkey-past-its-not-after-refused",
			"readerkey-valid-over-7-days-refused", "adds-and-wraps-only-for-readers", "late-wrap-judged-at-its-pin",
		}},
		{Id: "S3b", Flow: "F3", Tiers: t2t3, Gates: []string{"M6-out"}, Owners: []string{"KEYS-M6-03", "TEAM-M6-12"}, HeaderOnly: true},
		{Id: "S4a", Flow: "F9", Tiers: t2t3, Gates: []string{"M2-out"}, Owners: []string{"TEST-M2-11", "TEST-M2-12"}, HeaderOnly: true, Clauses: []string{
			"writers-seal-nothing-to-x", "gates-closed-until-a-covering-generation", "members-refuse-a-bad-commit",
			"tokens-fail-in-their-windows", "next-generation-fails-under-xs-keys", "path-epoch-and-checkpoint",
		}},
		{Id: "S4b", Flow: "F9", Tiers: t2t3, Gates: []string{"M6-out"}, Owners: []string{"KEYS-M6-03", "TEAM-M6-12"}, HeaderOnly: true},
		{Id: "S5", Flow: "F4", Tiers: t2t3t6, Gates: []string{"M5-out"}, Owners: []string{"TLS-M5-25"}},
		{Id: "S6", Flow: "F5", Tiers: t2t3t6, Gates: []string{"M9-out"}, Owners: []string{"SMTP-M9-31"}},
		{Id: "S7", Flow: "F6", Tiers: t2t3t6, Gates: []string{"M7-out"}, Owners: []string{"MAIL-M7-27"}},
		{Id: "S8", Flow: "F7", Tiers: t2t3t6, Gates: []string{"M4-out"}, Owners: []string{"BRIDGE-M4-22"}},
		{Id: "S9", Flow: "F8", Tiers: t2t3, Gates: []string{"M3-out"}, Owners: []string{"MCP-M3-26"}},
		{Id: "S10", Flow: "F10", Tiers: t2t3t6, Gates: []string{"M9-out"}, Owners: []string{"MAIL-M9-06"}},
		{Id: "S11", Flow: "F11", Tiers: t2t3, Gates: []string{"M10-out"}, Owners: []string{"SEARCH-M10-39"}},
		{Id: "S12", Flow: "F12", Tiers: t2t3, Gates: []string{"M10-out"}, Owners: []string{"SEARCH-M10-39"}},
		{Id: "S13", Flow: "F13", Tiers: t2t3, Gates: []string{"M6-out"}, Owners: []string{"RECORD-M6-26"}},
	}
}

// A test that runs a scenario on a tier: repo, package and top-level name, and the tags it needs.
type ScenarioTest struct {
	Repo    string
	Package string
	Name    string
	Tags    string
}

func (self *ScenarioTest) String() string {
	name := self.Package + "." + self.Name
	if self.Tags != "" {
		name += " (-tags " + self.Tags + ")"
	}
	return name
}

// One registration: a test of a row's part on a tier.
type scenarioRegistration struct {
	clause string
	tier   string
	test   *ScenarioTest
}

// The rows and what is registered against them.
type ScenarioRegistry struct {
	rows []*ScenarioRow

	stateLock     sync.Mutex
	registrations map[string][]*scenarioRegistration
}

func NewScenarioRegistry() *ScenarioRegistry {
	return &ScenarioRegistry{rows: scenarioRows(), registrations: map[string][]*scenarioRegistration{}}
}

var defaultScenarioRegistry = sync.OnceValue(NewScenarioRegistry)

// The registry every registration goes to, which a gate sweep reads.
func DefaultScenarioRegistry() *ScenarioRegistry {
	return defaultScenarioRegistry()
}

// Every row, in §22.7's order.
func (self *ScenarioRegistry) Rows() []*ScenarioRow {
	return slices.Clone(self.rows)
}

// The row with id, or nil.
func (self *ScenarioRegistry) Row(scenarioId string) *ScenarioRow {
	for _, row := range self.rows {
		if row.Id == scenarioId {
			return row
		}
	}
	return nil
}

// Ties test to a part of a row on tier: clause is one of the row's Clauses, or "" for a row of one part. A row the
// registry does not hold, a part it does not name, a tier the row does not name, a test with no repo, package or
// name, and a test registered twice to one part on one tier each fail.
func (self *ScenarioRegistry) Register(scenarioId string, clause string, tier string, test *ScenarioTest) error {
	row := self.Row(scenarioId)
	if row == nil {
		return fmt.Errorf("register %s: §22.7 lists no scenario %q", test, scenarioId)
	}
	if !slices.Contains(row.Parts(), clause) {
		return fmt.Errorf("register %s: %s has no part %q", test, scenarioId, clause)
	}
	if !slices.Contains(row.Tiers, tier) {
		return fmt.Errorf("register %s: %s runs on %v, not %s", test, scenarioId, row.Tiers, tier)
	}
	if test == nil || test.Repo == "" || test.Package == "" || test.Name == "" {
		return fmt.Errorf("register %s: a test needs its repo, package and name", scenarioId)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, other := range self.registrations[scenarioId] {
		if other.clause == clause && other.tier == tier && *other.test == *test {
			return fmt.Errorf("register %s's %q on %s: %s is registered already", scenarioId, clause, tier, test)
		}
	}
	copied := *test
	self.registrations[scenarioId] = append(self.registrations[scenarioId], &scenarioRegistration{clause: clause, tier: tier, test: &copied})
	return nil
}

// The tests registered to a part of a row on tier.
func (self *ScenarioRegistry) Tests(scenarioId string, clause string, tier string) []*ScenarioTest {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	tests := []*ScenarioTest{}
	for _, registration := range self.registrations[scenarioId] {
		if registration.clause == clause && registration.tier == tier {
			copied := *registration.test
			tests = append(tests, &copied)
		}
	}
	return tests
}

// The parts that must pass at gate on tier and that no test is registered to on it, in §22.7's order: what a gate
// reports missing, never passing.
func (self *ScenarioRegistry) Missing(gate string, tier string) []*ScenarioPart {
	missing := []*ScenarioPart{}
	for _, row := range self.rows {
		if !slices.Contains(row.Gates, gate) || !slices.Contains(row.Tiers, tier) {
			continue
		}
		for _, clause := range row.Parts() {
			if len(self.Tests(row.Id, clause, tier)) == 0 {
				missing = append(missing, &ScenarioPart{Row: row, Clause: clause})
			}
		}
	}
	return missing
}

// Ties test to a part of a row of the default registry on tier, from a package-level var: a registration the
// registry refuses panics, so a binary that cannot link its scenarios does not pass.
func RegisterScenario(scenarioId string, clause string, tier string, test *ScenarioTest) *ScenarioTest {
	if err := DefaultScenarioRegistry().Register(scenarioId, clause, tier, test); err != nil {
		panic(err)
	}
	return test
}

// The parts this task composes (TEST-M2-11): S3a's and S4a's, one builder each in sidecartest/scenarios, on T2 here
// and on T3 in server's sidecart3, their remaining parts missing until composed; and S1's three clauses on T3 alone,
// each its own test in server's sidecart3, on sidecars enrolled through server's own api (scenario_sidecar.go there).
var (
	_ = registerScenarioParts("S3a", []string{
		"forged-admission-refused", "forged-keypackage-refused", "forged-readerkey-refused", "readerkey-past-its-not-after-refused",
		"readerkey-valid-over-7-days-refused", "adds-and-wraps-only-for-readers",
	}, "TestScenarioS3a")
	_ = registerScenarioParts("S4a", []string{"writers-seal-nothing-to-x", "next-generation-fails-under-xs-keys"}, "TestScenarioS4a")
	_ = registerScenarioT3("S1", "code-create-403", "TestScenarioS1CodeCreateOnT3")
	_ = registerScenarioT3("S1", "token-never-in-mcp-env-or-logs", "TestScenarioS1TokenOnT3")
	_ = registerScenarioT3("S1", "genesis-other-than-the-invites-refused", "TestScenarioS1GenesisOnT3")
)

// Registers clause of scenarioId on T3 alone, to name in server's sidecart3.
func registerScenarioT3(scenarioId string, clause string, name string) *ScenarioTest {
	return RegisterScenario(scenarioId, clause, ScenarioTierT3, &ScenarioTest{Repo: "server", Package: "github.com/urnetwork/server/sidecart3", Name: name, Tags: "sidecar_testhooks,sidecar_pending,sidecar_localstack"})
}

// Registers clauses of scenarioId on T2, to name in sidecartest, and on T3, to name plus "OnT3" in server's sidecart3.
func registerScenarioParts(scenarioId string, clauses []string, name string) bool {
	for _, clause := range clauses {
		RegisterScenario(scenarioId, clause, ScenarioTierT2, &ScenarioTest{Repo: "sidecar", Package: "github.com/urnetwork/sidecar/sidecartest", Name: name, Tags: "sidecar_testhooks"})
		RegisterScenario(scenarioId, clause, ScenarioTierT3, &ScenarioTest{Repo: "server", Package: "github.com/urnetwork/server/sidecart3", Name: name + "OnT3", Tags: "sidecar_testhooks,sidecar_pending,sidecar_localstack"})
	}
	return true
}

// One route a strict_exp bearer reaches: its method, "" for any, and its path.
type sidecarRoute struct {
	method string
	path   *regexp.Regexp
}

// §7.4's allowlist as the design writes it (07-TEAM.md's stage 1 block): what a strict_exp bearer reaches. Server's
// route_authz.go holds its own table to the same list (TestSidecarTokenRoutes), and T3's scenarios take that table, so
// a divergence between the two shows there.
var sidecarRouteAllowlist = []*sidecarRoute{
	{method: "GET", path: regexp.MustCompile(`^/auth/refresh$`)},
	{method: "POST", path: regexp.MustCompile(`^/network/auth-client$`)},
	{method: "POST", path: regexp.MustCompile(`^/network/remove-client$`)},
	{method: "GET", path: regexp.MustCompile(`^/key/[^/]+$`)},
	{method: "POST", path: regexp.MustCompile(`^/connect/control$`)},
	{path: regexp.MustCompile(`^/sidecar/`)},
	{path: regexp.MustCompile(`^/network/config/`)},
	{method: "POST", path: regexp.MustCompile(`^/network/enroll$`)},
	{path: regexp.MustCompile(`^/network/bridge/share/`)},
	{path: regexp.MustCompile(`^/acl/`)},
	{method: "POST", path: regexp.MustCompile(`^/approval/cancel$`)},
	{path: regexp.MustCompile(`^/tls/`)},
	{path: regexp.MustCompile(`^/mail/`)},
	{path: regexp.MustCompile(`^/smtp/`)},
	{path: regexp.MustCompile(`^/socket/`)},
	{path: regexp.MustCompile(`^/dns/`)},
	{method: "GET", path: regexp.MustCompile(`^/abuse/status$`)},
	{method: "POST", path: regexp.MustCompile(`^/oauth/token$`)},
}

// Whether §7.4's allowlist lets a strict_exp bearer reach method path.
func SidecarRouteAllowed(method string, path string) bool {
	return slices.ContainsFunc(sidecarRouteAllowlist, func(route *sidecarRoute) bool {
		return (route.method == "" || route.method == method) && route.path.MatchString(path)
	})
}

// What a scenario's flow runs with.
type ScenarioRun struct {
	// The world: on T2 the fakes, on T3 server's stores.
	Net *Net
	// The record of what each service the flow builds writes, through Host.
	Writers *StoredWriters

	stateLock sync.Mutex
	// the canaries the flow planted, by kind
	plantedKinds []string
}

// A fresh canary of kind, 32 random bytes, for a field that holds bytes, counted as planted.
func (self *ScenarioRun) Canary(kind string) []byte {
	self.planted(kind)
	return self.Net.Capture().Canary(kind)
}

// A fresh text canary of kind, for a name, a path, a message or a label, counted as planted.
func (self *ScenarioRun) CanaryText(kind string) string {
	self.planted(kind)
	return self.Net.Capture().CanaryText(kind)
}

func (self *ScenarioRun) planted(kind string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.plantedKinds = append(self.plantedKinds, kind)
}

// The kinds of canary planted so far.
func (self *ScenarioRun) Planted() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.plantedKinds)
}

// The Net's host as service is built with it, its writes recorded for the stored-state asserts.
func (self *ScenarioRun) Host(service string) *sidecar.ServiceHost {
	return self.Writers.Host(service, self.Net.Host())
}

// One scenario: its row's id and the flow it runs.
type Scenario struct {
	Id string
	// The flow on run: it plants its canaries, runs §3.7's steps through the routes, and checks its own clauses,
	// an error failing the scenario.
	Run func(ctx context.Context, run *ScenarioRun) error
}

// What a scenario runs on: T2's by default, T3's from server's sidecart3.
type ScenarioSettings struct {
	// The Net's: nil, T2's defaults.
	Net *NetSettings
	// Adds the stores' capture to the Net's, beyond what the Net captures itself: T3's CaptureStores. nil adds none,
	// as on T2, where the fakes are captured from the start.
	CaptureStores func(net *Net) error
	// Every Redis key the Net's stores hold, for the guard: nil reads T2's FakeRedis.
	RedisKeys func(ctx context.Context, net *Net) ([]string, error)
	// §7.4's allowlist: nil is SidecarRouteAllowed.
	RouteAllowed func(method string, path string) bool
	// What the stored-state asserts hold the stores to: nil, the defaults.
	StoredState *StoredStateSettings
}

// What a scenario's run found, each failing it.
type ScenarioReport struct {
	Id string
	// the flow's own error
	FlowErr error
	// a canary or key where it must not be
	Findings []*PrivacyFinding
	// a key family no row of §2.8's list names
	GuardFindings []string
	// a stored commit or a writer breaking §22.7's asserts
	StoredFindings []string
	// what the run's own checks found: no canary planted, a store the capture holds nothing of
	Problems []string
	// each route the allowlist refused, which the flow may expect
	RefusedRoutes []string
}

// Whether the run passed: everything empty but the refused routes.
func (self *ScenarioReport) Passed() bool {
	return self.FlowErr == nil && len(self.Findings) == 0 && len(self.GuardFindings) == 0 && len(self.StoredFindings) == 0 && len(self.Problems) == 0
}

// Runs scenario on a Net of its own under §22.7's harness and guard, failing t with each thing the report holds.
// settings nil takes T2's.
func RunScenario(t testing.TB, scenario *Scenario, settings *ScenarioSettings) *ScenarioReport {
	t.Helper()
	report := runScenario(t, scenario, settings)
	if report.FlowErr != nil {
		t.Errorf("%s: %v", scenario.Id, report.FlowErr)
	}
	for _, finding := range report.Findings {
		t.Errorf("%s: %s", scenario.Id, finding)
	}
	for _, finding := range report.GuardFindings {
		t.Errorf("%s: %s", scenario.Id, finding)
	}
	for _, finding := range report.StoredFindings {
		t.Errorf("%s: %s", scenario.Id, finding)
	}
	for _, problem := range report.Problems {
		t.Errorf("%s: %s", scenario.Id, problem)
	}
	return report
}

// Runs scenario as RunScenario does and returns the report without failing t on it, for a test that judges what it
// holds itself. A finding left unjudged is no pass: Passed says whether the run holds nothing.
func RunScenarioReport(t testing.TB, scenario *Scenario, settings *ScenarioSettings) *ScenarioReport {
	t.Helper()
	return runScenario(t, scenario, settings)
}

func runScenario(t testing.TB, scenario *Scenario, settings *ScenarioSettings) *ScenarioReport {
	t.Helper()
	if settings == nil {
		settings = &ScenarioSettings{}
	}
	report := &ScenarioReport{Id: scenario.Id}
	row := DefaultScenarioRegistry().Row(scenario.Id)
	if row == nil {
		report.Problems = append(report.Problems, fmt.Sprintf("§22.7 lists no scenario %q", scenario.Id))
		return report
	}
	net := NewNet(t.Context(), settings.Net)
	defer net.Close()
	if settings.CaptureStores != nil {
		if err := settings.CaptureStores(net); err != nil {
			report.Problems = append(report.Problems, fmt.Sprintf("the stores' capture did not start: %v", err))
			return report
		}
	}
	api, err := net.Api()
	if err != nil {
		report.Problems = append(report.Problems, fmt.Sprintf("the Net's api: %v", err))
		return report
	}
	routeAllowed := settings.RouteAllowed
	if routeAllowed == nil {
		routeAllowed = SidecarRouteAllowed
	}
	api.SetRouteGate(routeAllowed)
	run := &ScenarioRun{Net: net, Writers: NewStoredWriters(settings.StoredState)}
	ctx := net.Context()
	report.FlowErr = scenario.Run(ctx, run)
	report.RefusedRoutes = api.RefusedRoutes()
	if len(run.Planted()) == 0 {
		report.Problems = append(report.Problems, "the flow planted no canary, so its scan proves nothing of its user fields (§22.7)")
	}
	inspect := InspectContext(ctx)
	report.Problems = append(report.Problems, scenarioCaptureProblems(inspect, net, settings)...)
	report.Findings = net.Capture().Scan()
	guard, err := LoadSchemaGuard()
	if err != nil {
		report.Problems = append(report.Problems, fmt.Sprintf("the schema guard does not load: %v", err))
	} else {
		redisKeys, err := scenarioRedisKeys(inspect, net, settings)
		if err != nil {
			report.Problems = append(report.Problems, fmt.Sprintf("the Net's Redis keys do not read: %v", err))
		}
		guardFindings, err := guard.CheckStores(inspect, &SchemaGuardStores{Blobs: net.Host().Blobs, RedisKeys: redisKeys})
		if err != nil {
			report.Problems = append(report.Problems, fmt.Sprintf("the guard did not read the stores: %v", err))
		}
		report.GuardFindings = guardFindings
	}
	storedFindings, err := CheckStoredCommits(inspect, net.Host().Blobs, settings.StoredState, row.HeaderOnly)
	if err != nil {
		report.Problems = append(report.Problems, fmt.Sprintf("the stored commits do not read: %v", err))
	}
	report.StoredFindings = append(storedFindings, run.Writers.Check()...)
	return report
}

// Every Redis key the Net's stores hold.
func scenarioRedisKeys(ctx context.Context, net *Net, settings *ScenarioSettings) ([]string, error) {
	if settings.RedisKeys != nil {
		return settings.RedisKeys(ctx, net)
	}
	keys := []string{}
	for key := range net.Fakes().Redis.Dump() {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys, nil
}

// Whether the capture holds the Net's stores: a store holding a key the capture holds nothing of is one no scan read.
func scenarioCaptureProblems(ctx context.Context, net *Net, settings *ScenarioSettings) []string {
	problems := []string{}
	capture := net.Capture()
	objectCount := 0
	clusters, err := schemaGuardClusters(net.Host().Blobs)
	if err != nil {
		return append(problems, fmt.Sprintf("the Net's clusters do not read: %v", err))
	}
	for _, cluster := range clusters {
		if err := schemaGuardListKeys(ctx, cluster, func(key string) { objectCount += 1 }); err != nil {
			problems = append(problems, fmt.Sprintf("cluster %s does not list: %v", cluster.ClusterId(), err))
		}
	}
	if 0 < objectCount && capture.ItemCount(PrivacyClassObject) == 0 {
		problems = append(problems, fmt.Sprintf("the stores hold %d objects and the capture none: no capture runs over the Net's objects", objectCount))
	}
	redisKeys, err := scenarioRedisKeys(ctx, net, settings)
	if err == nil && 0 < len(redisKeys) && capture.ItemCount(PrivacyClassRedis) == 0 {
		problems = append(problems, fmt.Sprintf("Redis holds %d keys and the capture none: no capture runs over the Net's Redis", len(redisKeys)))
	}
	return problems
}
