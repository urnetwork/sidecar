//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

package sidecar

// The daemon's label resolution (§5.8's project row, §11.11's names row, §12.5's label row, D-DNS-2; daemon_labels.go,
// dns_label_refresh.go): a daemon hosting two networks picks each by its label, alias or retiring alias, from `.ur` and
// from a git session's <net>, through each network's own label table under the daemon's user root; a row one
// network's table holds about another is never read; a name two hosted tables each claim is refused as ambiguous; with
// no root nothing resolves by name; a legacy name resolves only for a person's typed input and only while every table
// was read. Each network's label refresh files GET /sidecar/label's answer in that table under the Sidecar's user root
// at each client generation, with the token's network_name as the legacy name: what may land later is read again on
// the Sidecar's clock, a refusal for good is not, and with no root nothing is read.

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The two networks' labels, aliases and retiring aliases, synthetic.
const (
	testDaemonLabelA        = "a7q2m9x4k1"
	testDaemonLabelB        = "b3k8p2r6t0"
	testDaemonAliasB        = "team-bravo"
	testDaemonRetiringAlias = "team-old"
)

// A daemon with no listener and no resolver in its settings, so it resolves through its hosted networks' tables,
// under root, its `.ur` search bounded by home.
func newLabelTestDaemon(t *testing.T, root string, home string) *Daemon {
	t.Helper()
	settings := &DaemonSettings{
		Instance:       "default",
		StateDirectory: t.TempDir(),
		Local:          DefaultSidecarSettings().LocalSettings,
		Version:        "synthetic-version",
		LabelRoot:      root,
		Home:           home,
	}
	return newDaemonOn(context.Background(), settings, nopCloser{}, nil)
}

// A Sidecar enrolled in networkId whose own label table holds rows, its dns block answering no zone it is asked for.
func newLabelTestSidecar(t *testing.T, networkId Id, rows ...NetworkLabelRow) *Sidecar {
	t.Helper()
	running, _, _, _ := newTestDnsLabelsSidecar(t, networkId, &DnsZone{NetworkId: networkId, Root: testLabelRoot, Version: 1})
	table, err := running.NetworkLabels()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if err := table.SetNetwork(row); err != nil {
			t.Fatal(err)
		}
	}
	return running
}

// A project directory under home whose `.ur` names network.
func testLabelProject(t *testing.T, home string, name string, network string) string {
	t.Helper()
	directory := filepath.Join(home, name)
	writeTestFile(t, filepath.Join(directory, ".ur"), "network = \""+network+"\"\n")
	return directory
}

// What a git service was handed, session by session.
type testLabelGitSessions struct {
	stateLock sync.Mutex
	sessions  []*DaemonGitSession
}

func (self *testLabelGitSessions) serve(ctx context.Context, session *DaemonGitSession) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.sessions = append(self.sessions, session)
	return nil
}

func (self *testLabelGitSessions) last() *DaemonGitSession {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if len(self.sessions) == 0 {
		return nil
	}
	return self.sessions[len(self.sessions)-1]
}

func (self *testLabelGitSessions) count() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.sessions)
}

// Two hosted networks, each table holding its own row and A's one about a network the daemon does not host: `.ur`
// picks A by its label and B by its alias and by its retiring alias, a git session's <net> goes to each one's Sidecar,
// and with no `.ur` the call is ambiguous, naming both by label; A's row about the other network names nothing, and a
// <net> no table holds is refused in git's own protocol, its service never reached.
func TestDaemonPicksEachHostedNetworkByItsLabel(t *testing.T) {
	home := t.TempDir()
	networkA, networkB, unhosted := testConfigId("network a"), testConfigId("network b"), testConfigId("unhosted network")
	sidecarA := newLabelTestSidecar(t, networkA,
		NetworkLabelRow{Root: testLabelRoot, NetworkId: networkA, Label: testDaemonLabelA},
		NetworkLabelRow{Root: testLabelRoot, NetworkId: unhosted, Label: "c5n1w7d3y9"},
	)
	sidecarB := newLabelTestSidecar(t, networkB,
		NetworkLabelRow{Root: testLabelRoot, NetworkId: networkB, Label: testDaemonLabelB, Alias: testDaemonAliasB, RetiringAliases: []string{testDaemonRetiringAlias}},
	)
	daemon := newLabelTestDaemon(t, testLabelRoot, home)
	if err := daemon.AddSidecar(networkA, sidecarA); err != nil {
		t.Fatal(err)
	}
	if err := daemon.AddSidecar(networkB, sidecarB); err != nil {
		t.Fatal(err)
	}

	for _, project := range []struct {
		network string
		want    Id
	}{
		{network: testDaemonLabelA, want: networkA},
		{network: testDaemonLabelB, want: networkB},
		{network: testDaemonAliasB, want: networkB},
		{network: testDaemonRetiringAlias, want: networkB},
	} {
		directory := testLabelProject(t, home, "project-"+project.network, project.network)
		resolved, err := daemon.ResolveNetwork(&DaemonHello{Mode: DaemonModeMcp, Cwd: directory}, "")
		if err != nil || resolved != project.want {
			t.Errorf(".ur naming %s resolved to %s (%v), want %s", project.network, resolved, err, project.want)
		}
	}
	var networkErr *DaemonNetworkError
	_, err := daemon.ResolveNetwork(&DaemonHello{Mode: DaemonModeMcp, Cwd: t.TempDir()}, "")
	if !errors.As(err, &networkErr) || networkErr.Reason != "ambiguous" || !strings.Contains(err.Error(), testDaemonLabelA) ||
		!strings.Contains(err.Error(), testDaemonLabelB) {
		t.Fatalf("no .ur with two networks: %v", err)
	}
	unhostedProject := testLabelProject(t, home, "project-unhosted", "c5n1w7d3y9")
	if _, err := daemon.ResolveNetwork(&DaemonHello{Mode: DaemonModeMcp, Cwd: unhostedProject}, ""); !errors.As(err, &networkErr) || networkErr.Reason != "unknown" {
		t.Fatalf("a label another network's table holds: %v", err)
	}

	served := &testLabelGitSessions{}
	git := NewDaemonGitMode(daemon, served.serve)
	for _, remote := range []struct {
		net     string
		want    Id
		sidecar *Sidecar
	}{
		{net: testDaemonLabelA, want: networkA, sidecar: sidecarA},
		{net: testDaemonLabelB, want: networkB, sidecar: sidecarB},
		{net: testDaemonAliasB, want: networkB, sidecar: sidecarB},
	} {
		stream := &bytes.Buffer{}
		hello := &DaemonHello{Mode: DaemonModeGit, Repo: remote.net + "/notes", Service: "git-upload-pack"}
		if err := git(t.Context(), hello, stream); err != nil {
			t.Fatalf("ur://%s/notes: %v, %q", remote.net, err, stream.String())
		}
		session := served.last()
		if session == nil || session.NetworkId != remote.want || session.Sidecar != remote.sidecar || session.Repo != "notes" {
			t.Fatalf("ur://%s/notes went to %+v", remote.net, session)
		}
	}
	stream := &bytes.Buffer{}
	before := served.count()
	if err := git(t.Context(), &DaemonHello{Mode: DaemonModeGit, Repo: "c5n1w7d3y9/notes", Service: "git-upload-pack"}, stream); !errors.Is(err, ErrDaemonGitRefused) ||
		!strings.Contains(stream.String(), "ERR ") || served.count() != before {
		t.Fatalf("a <net> no hosted table holds: %v, %q", err, stream.String())
	}
}

// Two hosted tables that each claim one name for their own network, which dns_label's key never allows: the name
// resolves to neither, and every other name still resolves.
func TestDaemonRefusesANameTwoHostedTablesClaim(t *testing.T) {
	home := t.TempDir()
	networkA, networkB := testConfigId("claiming a"), testConfigId("claiming b")
	daemon := newLabelTestDaemon(t, testLabelRoot, home)
	if err := daemon.AddSidecar(networkA, newLabelTestSidecar(t, networkA,
		NetworkLabelRow{Root: testLabelRoot, NetworkId: networkA, Label: testDaemonLabelA, Alias: "shared-name"})); err != nil {
		t.Fatal(err)
	}
	if err := daemon.AddSidecar(networkB, newLabelTestSidecar(t, networkB,
		NetworkLabelRow{Root: testLabelRoot, NetworkId: networkB, Label: testDaemonLabelB, RetiringAliases: []string{"shared-name"}})); err != nil {
		t.Fatal(err)
	}
	var networkErr *DaemonNetworkError
	shared := testLabelProject(t, home, "shared", "shared-name")
	if resolved, err := daemon.ResolveNetwork(&DaemonHello{Mode: DaemonModeMcp, Cwd: shared}, ""); !errors.As(err, &networkErr) || networkErr.Reason != "ambiguous" {
		t.Fatalf("a name two tables claim resolved to %s: %v", resolved, err)
	}
	if _, err := daemon.ResolveNetwork(&DaemonHello{Mode: DaemonModeControl}, "shared-name"); !errors.As(err, &networkErr) || networkErr.Reason != "ambiguous" {
		t.Fatalf("a typed name two tables claim: %v", err)
	}
	if resolved, err := daemon.ResolveNetwork(&DaemonHello{Mode: DaemonModeMcp}, testDaemonLabelB); err != nil || resolved != networkB {
		t.Fatalf("B's label beside the conflict: %s %v", resolved, err)
	}
}

// With no user root, no name resolves: a `.ur` naming a hosted network's label is refused rather than read, while a
// network id still names its network and the only network needs no name.
func TestDaemonResolvesNoNameWithoutARoot(t *testing.T) {
	home := t.TempDir()
	networkId := testConfigId("rootless network")
	daemon := newLabelTestDaemon(t, "", home)
	if err := daemon.AddSidecar(networkId, newLabelTestSidecar(t, networkId,
		NetworkLabelRow{Root: testLabelRoot, NetworkId: networkId, Label: testDaemonLabelA})); err != nil {
		t.Fatal(err)
	}
	var networkErr *DaemonNetworkError
	project := testLabelProject(t, home, "rootless", testDaemonLabelA)
	if _, err := daemon.ResolveNetwork(&DaemonHello{Mode: DaemonModeMcp, Cwd: project}, ""); !errors.As(err, &networkErr) || networkErr.Reason != "unknown" {
		t.Fatalf("a label with no root: %v", err)
	}
	if resolved, err := daemon.ResolveNetwork(&DaemonHello{Mode: DaemonModeControl}, networkId.String()); err != nil || resolved != networkId {
		t.Fatalf("a network id with no root: %s %v", resolved, err)
	}
	if resolved, err := daemon.ResolveNetwork(&DaemonHello{Mode: DaemonModeMcp, Cwd: t.TempDir()}, ""); err != nil || resolved != networkId {
		t.Fatalf("the only network with no root: %s %v", resolved, err)
	}
	if _, _, err := daemon.labels().ResolveNetworkLabel("", testDaemonLabelA, true); !errors.Is(err, ErrNetworkLabelUnknown) {
		t.Fatalf("the hosted tables with no root: %v", err)
	}
}

// A legacy network_name resolves only for a person's typed input, never from `.ur`, and only while every hosted
// network's table was read: with a second network whose table cannot open, the network that holds the name now may be
// that one, so the name resolves to none, while the readable network's label still does.
func TestDaemonLegacyNameNeedsEveryTableRead(t *testing.T) {
	home := t.TempDir()
	networkId, lockedId := testConfigId("legacy network"), testConfigId("locked network")
	daemon := newLabelTestDaemon(t, testLabelRoot, home)
	if err := daemon.AddSidecar(networkId, newLabelTestSidecar(t, networkId,
		NetworkLabelRow{Root: testLabelRoot, NetworkId: networkId, Label: testDaemonLabelA, LegacyName: "acme-team"})); err != nil {
		t.Fatal(err)
	}
	var networkErr *DaemonNetworkError
	if resolved, err := daemon.ResolveNetwork(&DaemonHello{Mode: DaemonModeControl}, "acme-team"); err != nil || resolved != networkId {
		t.Fatalf("a person's typed legacy name: %s %v", resolved, err)
	}
	project := testLabelProject(t, home, "legacy", "acme-team")
	if _, err := daemon.ResolveNetwork(&DaemonHello{Mode: DaemonModeControl, Cwd: project}, ""); !errors.As(err, &networkErr) || networkErr.Reason != "unknown" {
		t.Fatalf(".ur's legacy name: %v", err)
	}

	locked, instance, _, _ := newTestDnsLabelsSidecar(t, lockedId, &DnsZone{NetworkId: lockedId, Root: testLabelRoot, Version: 1})
	instance.Lock()
	if err := daemon.AddSidecar(lockedId, locked); err != nil {
		t.Fatal(err)
	}
	if _, err := daemon.ResolveNetwork(&DaemonHello{Mode: DaemonModeControl}, "acme-team"); !errors.As(err, &networkErr) || networkErr.Reason != "unknown" {
		t.Fatalf("a typed legacy name with a table unread: %v", err)
	}
	if resolved, err := daemon.ResolveNetwork(&DaemonHello{Mode: DaemonModeControl}, testDaemonLabelA); err != nil || resolved != networkId {
		t.Fatalf("a label with a table unread: %s %v", resolved, err)
	}
	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	if resolved, err := daemon.ResolveNetwork(&DaemonHello{Mode: DaemonModeControl}, "acme-team"); err != nil || resolved != networkId {
		t.Fatalf("a typed legacy name once every table reads: %s %v", resolved, err)
	}
}

// A user root is a domain name of lowercase labels with no trailing dot, or none; none is the default, as the urls'.
func TestUserRootSettingIsADomainName(t *testing.T) {
	if root := DefaultSidecarSettings().UserRoot; root != "" {
		t.Fatalf("UserRoot defaults to %q", root)
	}
	for _, root := range []string{"", testLabelRoot, "users.zone.example"} {
		settings := validSidecarSettings()
		settings.UserRoot = root
		if err := settings.validate(); err != nil {
			t.Errorf("%q refused: %v", root, err)
		}
	}
	for _, root := range []string{"Zone.Example", "zone.example.", "example", ".zone.example", "zone..example", "-zone.example", "zone example"} {
		settings := validSidecarSettings()
		settings.UserRoot = root
		if err := settings.validate(); !errors.Is(err, errInvalidSettings) || !strings.Contains(err.Error(), "UserRoot") {
			t.Errorf("%q: %v", root, err)
		}
	}
}

// A clock whose waits a test fires: each After reports its timeout and answers the channel the test fires.
type testLabelRefreshClock struct {
	armed chan time.Duration
	fire  chan time.Time
}

func newTestLabelRefreshClock() *testLabelRefreshClock {
	return &testLabelRefreshClock{armed: make(chan time.Duration, 8), fire: make(chan time.Time)}
}

func (self *testLabelRefreshClock) Now() time.Time {
	return testApiNow
}

func (self *testLabelRefreshClock) After(timeout time.Duration) <-chan time.Time {
	self.armed <- timeout
	return self.fire
}

func (self *testLabelRefreshClock) AfterFunc(timeout time.Duration, function func()) func() bool {
	return func() bool { return false }
}

// The wait the refresh armed next.
func (self *testLabelRefreshClock) requireArmed(t *testing.T) time.Duration {
	t.Helper()
	select {
	case timeout := <-self.armed:
		return timeout
	case <-time.After(10 * time.Second):
		t.Fatal("the refresh armed no wait")
		return 0
	}
}

// An api answering GET /sidecar/label with each status and body in turn, the last one for every request after, and
// counting each request on requests.
func newTestLabelRefreshApi(t *testing.T, answers ...[2]string) (*SidecarApi, *scriptedApiTransport, chan int) {
	t.Helper()
	requests := make(chan int, 16)
	count := 0
	stateLock := sync.Mutex{}
	transport := &scriptedApiTransport{answer: func(request *http.Request, body []byte) (*http.Response, error) {
		stateLock.Lock()
		answer := answers[min(count, len(answers)-1)]
		count += 1
		number := count
		stateLock.Unlock()
		requests <- number
		if request.Method != http.MethodGet || request.URL.Path != "/sidecar/label" {
			return syntheticResponse(request, http.StatusNotFound, `{"code":"not_found"}`, nil), nil
		}
		status := http.StatusOK
		switch answer[0] {
		case "403":
			status = http.StatusForbidden
		case "503":
			status = http.StatusServiceUnavailable
		}
		return syntheticResponse(request, status, answer[1], nil), nil
	}}
	api := newTestSidecarApi(t, transport)
	return api, transport, requests
}

// The label answer for networkId.
func testLabelAnswer(networkId Id, label string, alias string) [2]string {
	body := `{"network_id":"` + networkId.String() + `","label":"` + label + `"`
	if alias != "" {
		body += `,"alias":"` + alias + `"`
	}
	return [2]string{"200", body + "}"}
}

// A request the refresh made by now.
func requireLabelRequest(t *testing.T, requests chan int) int {
	t.Helper()
	select {
	case number := <-requests:
		return number
	case <-time.After(10 * time.Second):
		t.Fatal("the refresh asked api nothing")
		return 0
	}
}

// A Sidecar of networkId whose settings name the test's root and whose label refresh waits on clock.
func newLabelRefreshSidecar(t *testing.T, networkId Id, clock Clock) (*Sidecar, *SidecarInstance) {
	t.Helper()
	running, instance, _, _ := newTestDnsLabelsSidecar(t, networkId, &DnsZone{NetworkId: networkId, Root: testLabelRoot, Version: 1})
	running.settings.UserRoot = testLabelRoot
	running.clock = clock
	return running, instance
}

// A generation's attach reads GET /sidecar/label on the generation's api and files the answer in the network's own
// table under the Sidecar's user root, the token's network_name its legacy name; the read that lands is the
// generation's last; the next generation reads again; and the daemon then resolves the label and the alias through
// that table, the legacy name for a person's typed input alone.
func TestNetworkLabelRefreshFilesTheLabelAtEachGeneration(t *testing.T) {
	networkId := testConfigId("refreshed network")
	clock := newTestLabelRefreshClock()
	running, _ := newLabelRefreshSidecar(t, networkId, clock)
	api, transport, requests := newTestLabelRefreshApi(t, testLabelAnswer(networkId, testDaemonLabelA, "team-alpha"))
	token := testClientJwt(`{"network_id":"` + networkId.String() + `","client_id":"` + NewId().String() + `","network_name":"Alpha-Team"}`)
	api.SetByJwt(token)
	component := running.NewNetworkLabelRefreshComponent(nil)
	if component.Name() != "dns-label" || checkSidecarComponentName(component.Name()) != nil {
		t.Fatalf("component name %q", component.Name())
	}
	if err := component.Attach(&SidecarEnv{Ctx: t.Context(), SidecarApi: api, Log: NewNoopLogger()}); err != nil {
		t.Fatal(err)
	}
	requireLabelRequest(t, requests)
	// the read landed is the generation's last, so Close joins it while the generation still runs
	component.Close()
	request, _ := transport.onlyRequest(t)
	if request.Header.Get("Authorization") != "Bearer "+token {
		t.Fatal("the read went on another token than the generation's")
	}
	table, err := running.NetworkLabels()
	if err != nil {
		t.Fatal(err)
	}
	requireNetworkLabel(t, table, testDaemonLabelA, false, networkId, NetworkLabelKindLabel)
	requireNetworkLabel(t, table, "team-alpha", false, networkId, NetworkLabelKindAlias)
	requireNetworkLabel(t, table, "alpha-team", true, networkId, NetworkLabelKindLegacyName)
	requireNetworkLabelUnknown(t, table, "alpha-team", false)

	// the next generation reads again
	if err := component.Attach(&SidecarEnv{Ctx: t.Context(), SidecarApi: api, Log: NewNoopLogger()}); err != nil {
		t.Fatal(err)
	}
	if number := requireLabelRequest(t, requests); number != 2 {
		t.Fatalf("the next generation's read was request %d", number)
	}
	component.Close()

	home := t.TempDir()
	daemon := newLabelTestDaemon(t, testLabelRoot, home)
	if err := daemon.AddSidecar(networkId, running); err != nil {
		t.Fatal(err)
	}
	project := testLabelProject(t, home, "alpha", "team-alpha")
	if resolved, err := daemon.ResolveNetwork(&DaemonHello{Mode: DaemonModeMcp, Cwd: project}, ""); err != nil || resolved != networkId {
		t.Fatalf(".ur naming the refreshed alias: %s %v", resolved, err)
	}
	if resolved, err := daemon.ResolveNetwork(&DaemonHello{Mode: DaemonModeControl}, "Alpha-Team"); err != nil || resolved != networkId {
		t.Fatalf("a typed legacy name the refresh filed: %s %v", resolved, err)
	}
}

// A read that may land later is read again on the Sidecar's clock: a 503 waits RetryInterval, or the retry_after it
// asked where that is longer, the next failure doubling the wait up to RetryMaxInterval; a keychain locked at the
// attach is read again once it opens; and the generation's end stops the waiting reads, which Close joins.
func TestNetworkLabelRefreshReadsAgainWhatMayLandLater(t *testing.T) {
	networkId := testConfigId("retried network")
	clock := newTestLabelRefreshClock()
	running, _ := newLabelRefreshSidecar(t, networkId, clock)
	unavailable := [2]string{"503", `{"code":"unavailable","retry_after_ms":150000}`}
	unhinted := [2]string{"503", `{"code":"unavailable"}`}
	api, _, requests := newTestLabelRefreshApi(t, unavailable, unhinted, unhinted, unhinted, testLabelAnswer(networkId, testDaemonLabelA, ""))
	settings := &NetworkLabelRefreshSettings{RetryInterval: time.Minute, RetryMaxInterval: 3 * time.Minute}
	component := running.NewNetworkLabelRefreshComponent(settings)
	if err := component.Attach(&SidecarEnv{Ctx: t.Context(), SidecarApi: api, Log: NewNoopLogger()}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []time.Duration{150 * time.Second, 2 * time.Minute, 3 * time.Minute, 3 * time.Minute} {
		requireLabelRequest(t, requests)
		if armed := clock.requireArmed(t); armed != want {
			t.Fatalf("armed %s, want %s", armed, want)
		}
		clock.fire <- testApiNow
	}
	if number := requireLabelRequest(t, requests); number != 5 {
		t.Fatalf("the read that landed was request %d", number)
	}
	component.Close()
	table, err := running.NetworkLabels()
	if err != nil {
		t.Fatal(err)
	}
	requireNetworkLabel(t, table, testDaemonLabelA, false, networkId, NetworkLabelKindLabel)

	// a keychain locked at the attach opens no table, and the read after the wait files the answer
	lockedId := testConfigId("locked refresh")
	lockedClock := newTestLabelRefreshClock()
	locked, instance := newLabelRefreshSidecar(t, lockedId, lockedClock)
	lockedApi, _, lockedRequests := newTestLabelRefreshApi(t, testLabelAnswer(lockedId, testDaemonLabelB, ""))
	instance.Lock()
	lockedComponent := locked.NewNetworkLabelRefreshComponent(settings)
	if err := lockedComponent.Attach(&SidecarEnv{Ctx: t.Context(), SidecarApi: lockedApi, Log: NewNoopLogger()}); err != nil {
		t.Fatal(err)
	}
	if armed := lockedClock.requireArmed(t); armed != time.Minute {
		t.Fatalf("a locked keychain's wait: %s", armed)
	}
	select {
	case <-lockedRequests:
		t.Fatal("a locked keychain's read asked api")
	default:
	}
	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	lockedClock.fire <- testApiNow
	requireLabelRequest(t, lockedRequests)
	lockedComponent.Close()
	lockedTable, err := locked.NetworkLabels()
	if err != nil {
		t.Fatal(err)
	}
	requireNetworkLabel(t, lockedTable, testDaemonLabelB, false, lockedId, NetworkLabelKindLabel)

	// a generation that ends while its read waits reads no more, and Close joins it
	endedId := testConfigId("ended refresh")
	endedClock := newTestLabelRefreshClock()
	ended, _ := newLabelRefreshSidecar(t, endedId, endedClock)
	endedApi, _, endedRequests := newTestLabelRefreshApi(t, unhinted)
	ctx, cancel := context.WithCancel(t.Context())
	endedComponent := ended.NewNetworkLabelRefreshComponent(settings)
	if err := endedComponent.Attach(&SidecarEnv{Ctx: ctx, SidecarApi: endedApi, Log: NewNoopLogger()}); err != nil {
		t.Fatal(err)
	}
	requireLabelRequest(t, endedRequests)
	endedClock.requireArmed(t)
	cancel()
	endedComponent.Close()
	select {
	case <-endedRequests:
		t.Fatal("an ended generation read again")
	default:
	}
}

// A refusal for good, as a forwarding token's 403, and an answer about another network or not of the route's form end
// the generation's reads at once, filing nothing; with no user root, or no api, nothing is read at all.
func TestNetworkLabelRefreshStopsAtARefusalForGood(t *testing.T) {
	networkId := testConfigId("refused network")
	for _, answer := range [][2]string{
		{"403", `{"code":"forbidden"}`},
		testLabelAnswer(NewId(), testDaemonLabelA, ""),
		testLabelAnswer(networkId, "Not A Label", ""),
	} {
		clock := newTestLabelRefreshClock()
		running, _ := newLabelRefreshSidecar(t, networkId, clock)
		api, transport, requests := newTestLabelRefreshApi(t, answer)
		component := running.NewNetworkLabelRefreshComponent(nil)
		if err := component.Attach(&SidecarEnv{Ctx: t.Context(), SidecarApi: api, Log: NewNoopLogger()}); err != nil {
			t.Fatal(err)
		}
		requireLabelRequest(t, requests)
		component.Close()
		select {
		case armed := <-clock.armed:
			t.Fatalf("%s %s armed a wait of %s", answer[0], answer[1], armed)
		default:
		}
		if count := transport.requestCount(); count != 1 {
			t.Fatalf("%s %s: %d requests", answer[0], answer[1], count)
		}
		table, err := running.NetworkLabels()
		if err != nil {
			t.Fatal(err)
		}
		if rows := table.Networks(); len(rows) != 0 {
			t.Fatalf("%s %s filed %+v", answer[0], answer[1], rows)
		}
	}

	rootless, _, _, _ := newTestDnsLabelsSidecar(t, networkId, &DnsZone{NetworkId: networkId, Root: testLabelRoot, Version: 1})
	api, transport, _ := newTestLabelRefreshApi(t, testLabelAnswer(networkId, testDaemonLabelA, ""))
	component := rootless.NewNetworkLabelRefreshComponent(nil)
	if err := component.Attach(&SidecarEnv{Ctx: t.Context(), SidecarApi: api, Log: NewNoopLogger()}); err != nil {
		t.Fatal(err)
	}
	rooted, _ := newLabelRefreshSidecar(t, networkId, newTestLabelRefreshClock())
	apiless := rooted.NewNetworkLabelRefreshComponent(nil)
	if err := apiless.Attach(&SidecarEnv{Ctx: t.Context(), Log: NewNoopLogger()}); err != nil {
		t.Fatal(err)
	}
	component.Close()
	apiless.Close()
	if count := transport.requestCount(); count != 0 {
		t.Fatalf("a Sidecar with no user root asked api %d times", count)
	}
}
