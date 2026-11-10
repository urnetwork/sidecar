package fault

// FS-37 (§22.8, FI-2; §18.8's lease row, D-SDK-17; SDK-M4-08) on T2: HTTPS-only pages (sidecartest.TestHttpPage)
// poll the Net's api on its long-poll, held on the Net's clock, while taskworker's reaper runs one pass a minute
// (FakeApi.ReapEphemeralClients), all on one fake clock with no sleeps. Each clause is its own test:
//
//   - a page polling for 2 h, then killed with no unload: one reap 30-36 min after its last poll, a lost poll answer
//     on the way reaping nothing;
//   - its close beacon reaps it at once, and a retried or wrong beacon does nothing more;
//   - old-generation polls keep nothing alive: a reaped or removed client's polls are 401 and write nothing, and its
//     replacement is reaped on its own lease;
//   - two tabs reap independently;
//   - an ephemeral connected 2 h, then disconnected 2 min, is not reaped, and is 35-36 min after the disconnect;
//   - and, the case plan-SDK-http-only-idle-reap adds (QD-224), a member page Worker polling and refreshing for 31
//     days keeps working, its lease-less client never reaped.
//
// FI-2's oracle (TEST-M2-04) is not bound, so after every reaper pass each world checks FI-2's clauses for the lease
// itself, in its place (fs_team.go does the same for its rows): an unknown outcome never triggers destructive
// cleanup, so nothing is reaped that was not reapable when it was, nor within 30 min of its client's last poll; a
// client is reaped at most once, so a retried close returns what the first did; and a refusal stays true, every poll
// of a reaped client answering 401. The T3 half runs the same clauses on server's model and Postgres
// (server/taskworker/work/fs37_db_test.go), with the 31-day case against server's idle sweep.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/pushservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The reaper's cadence and threshold, and the page's poll hold, as server's defaults and §18.8 give them.
const (
	fs37ReapInterval = 60 * time.Second
	fs37ReapAfter    = 35 * time.Minute
)

var fs37HoldTimeout = pushservice.DefaultLongPollSettings().HoldTimeout

// One FS-37 world: a Net, its api, its clock, and what the schedule saw.
type fs37World struct {
	t     *testing.T
	ctx   context.Context
	net   *sidecartest.Net
	api   *sidecartest.FakeApi
	clock *sidecartest.FakeClock
	start time.Time
	// the reaper's next pass
	nextReap time.Time
	// each page client's last poll's start
	lastPolls map[sidecar.Id]time.Time
	// the clients known reaped or removed, whose polls answer 401
	refused map[sidecar.Id]bool
}

func newFs37World(t *testing.T) *fs37World {
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	api, err := net.Api()
	if err != nil {
		t.Fatal(err)
	}
	clock := net.Clock()
	return &fs37World{
		t:         t,
		ctx:       t.Context(),
		net:       net,
		api:       api,
		clock:     clock,
		start:     clock.Now(),
		nextReap:  clock.Now().Add(fs37ReapInterval),
		lastPolls: map[sidecar.Id]time.Time{},
		refused:   map[sidecar.Id]bool{},
	}
}

// An ephemeral page, its first poll answered at once with a reset.
func (self *fs37World) addPage(name string, ephemeral bool) *sidecartest.TestHttpPage {
	self.t.Helper()
	page, err := self.net.AddHttpPage(name, &sidecartest.TestHttpPageSettings{Ephemeral: ephemeral})
	if err != nil {
		self.t.Fatal(err)
	}
	self.lastPolls[page.ClientId()] = self.clock.Now()
	response, status, err := page.Poll(self.ctx)
	if err != nil || status != http.StatusOK || response.GetReset_() == nil {
		self.t.Fatalf("%s's first poll: %d %v", name, status, err)
	}
	return page
}

// Moves the clock to at, running the reaper's pass at each minute on the way and FI-2's clauses after each.
func (self *fs37World) advanceTo(at time.Time) {
	self.t.Helper()
	for !self.nextReap.After(at) {
		self.clock.AdvanceTo(self.nextReap)
		for _, reap := range self.api.ReapEphemeralClients() {
			self.refused[reap.ClientId] = true
		}
		self.nextReap = self.nextReap.Add(fs37ReapInterval)
		self.requireOutcomes()
	}
	self.clock.AdvanceTo(at)
}

// One poll of each page: those of live clients hold until the clock passes their hold, those of refused clients
// answer 401 at once and write nothing. The statuses, a transport error as status 0.
func (self *fs37World) pollCycle(pages ...*sidecartest.TestHttpPage) map[*sidecartest.TestHttpPage]int {
	self.t.Helper()
	statuses := map[*sidecartest.TestHttpPage]int{}
	// the refused first, one at a time, so no other poll writes a lease meanwhile
	for _, page := range pages {
		if !self.refused[page.ClientId()] {
			continue
		}
		touches := self.api.LeaseTouchCount()
		_, status, err := page.Poll(self.ctx)
		if err != nil || status != http.StatusUnauthorized {
			self.t.Fatalf("%s's poll after its client was refused: %d %v", page.Name, status, err)
		}
		if self.api.LeaseTouchCount() != touches {
			self.t.Fatalf("%s's refused poll wrote a lease", page.Name)
		}
		statuses[page] = status
	}
	mark := self.net.PollHoldMark()
	held := map[*sidecartest.TestHttpPage]*sidecartest.TestHttpPagePoll{}
	for _, page := range pages {
		if self.refused[page.ClientId()] {
			continue
		}
		self.lastPolls[page.ClientId()] = self.clock.Now()
		held[page] = page.StartPoll(self.ctx)
	}
	if err := self.net.AwaitPollHolds(self.ctx, mark, len(held)); err != nil {
		self.t.Fatal(err)
	}
	self.advanceTo(mark.HoldEnd)
	for page, poll := range held {
		response, status, err := poll.Wait(self.ctx)
		switch {
		case err != nil:
			statuses[page] = 0
		case status != http.StatusOK || response.GetReset_() != nil || 0 < len(response.GetHints()):
			self.t.Fatalf("%s's held poll answered %d %v", page.Name, status, response)
		default:
			statuses[page] = status
		}
	}
	return statuses
}

// Polls the pages, cycle after cycle, until the clock reaches at.
func (self *fs37World) pollUntil(at time.Time, pages ...*sidecartest.TestHttpPage) {
	self.t.Helper()
	for self.clock.Now().Before(at) {
		for page, status := range self.pollCycle(pages...) {
			if status != http.StatusOK {
				self.t.Fatalf("%s's poll answered %d while it polled", page.Name, status)
			}
		}
	}
}

// The reaps of a client so far.
func (self *fs37World) reapsOf(clientId sidecar.Id) []*sidecartest.FakeApiReap {
	reaps := []*sidecartest.FakeApiReap{}
	for _, reap := range self.api.Reaps() {
		if reap.ClientId == clientId {
			reaps = append(reaps, reap)
		}
	}
	return reaps
}

// The page's one reap by the reaper, 30-36 min after its last poll.
func (self *fs37World) requireReapedAfterItsLastPoll(page *sidecartest.TestHttpPage) {
	self.t.Helper()
	reaps := self.reapsOf(page.ClientId())
	if len(reaps) != 1 || reaps[0].Close {
		self.t.Fatalf("%s's reaps: %+v", page.Name, reaps)
	}
	after := reaps[0].Time.Sub(self.lastPolls[page.ClientId()])
	if after <= 30*time.Minute || 36*time.Minute < after {
		self.t.Fatalf("%s was reaped %s after its last poll, not 30-36 min", page.Name, after)
	}
	self.t.Logf("%s reaped %s after its last poll, its lease last seen %s before it", page.Name, after, reaps[0].Time.Sub(reaps[0].SeenTime))
}

// FI-2's clauses for the lease, after every reaper pass: no reap of a client that was not reapable when it was, or
// within 30 min of its last poll, and at most one reap of any client.
func (self *fs37World) requireOutcomes() {
	self.t.Helper()
	seen := map[sidecar.Id]bool{}
	for _, reap := range self.api.Reaps() {
		if seen[reap.ClientId] {
			self.t.Fatalf("FI-2: %s was reaped twice", reap.ClientId)
		}
		seen[reap.ClientId] = true
		if reap.Close {
			continue
		}
		cutoff := reap.Time.Add(-fs37ReapAfter)
		if !reap.SeenTime.Before(cutoff) || reap.Connected || !reap.NewestDisconnectTime.Before(cutoff) {
			self.t.Fatalf("FI-2: a reap of a client that was not reapable: %+v", reap)
		}
		if lastPoll, ok := self.lastPolls[reap.ClientId]; ok && reap.Time.Sub(lastPoll) <= 30*time.Minute {
			self.t.Fatalf("FI-2: %s was reaped %s after its last poll", reap.ClientId, reap.Time.Sub(lastPoll))
		}
	}
}

// A page polling for 2 h, then killed with no unload, is reaped once, 30-36 min after its last poll. One poll's answer
// is lost on the way: an unknown outcome, which the page meets by polling again and which reaps nothing.
func TestFs37PageKilledWithNoUnloadReapsOnce(t *testing.T) {
	world := newFs37World(t)
	page := world.addPage("tab", true)
	world.pollUntil(world.start.Add(time.Hour), page)
	if _, err := world.net.Faults().Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHttp, KeyPrefix: "/sidecar/sync/poll", Result: sidecartest.ApplyThenDrop}); err != nil {
		t.Fatal(err)
	}
	if status := world.pollCycle(page)[page]; status != 0 {
		t.Fatalf("the lost answer arrived: %d", status)
	}
	world.pollUntil(world.start.Add(2*time.Hour), page)
	if reaps := world.api.Reaps(); len(reaps) != 0 {
		t.Fatalf("a polling page was reaped: %+v", reaps)
	}
	// a poll every 25 s writes the lease at most once per marker, 300 s: 24 in 2 h
	if touches := world.api.LeaseTouchCount(); touches < 23 || 24 < touches {
		t.Fatalf("2 h of polls wrote the lease %d times", touches)
	}

	page.Kill()
	lastPoll := world.lastPolls[page.ClientId()]
	world.advanceTo(lastPoll.Add(40 * time.Minute))
	world.requireReapedAfterItsLastPoll(page)
	if _, ok := world.api.LeaseSeenTime(page.ClientId()); ok {
		t.Fatal("the reaped page's lease stayed")
	}
	if _, _, err := page.Poll(world.ctx); !errors.Is(err, sidecartest.ErrTestHttpPageKilled) {
		t.Fatalf("a killed page polled: %v", err)
	}
}

// The key-origin document's beacon reaps its page at once; a lost answer, a retry and a wrong capability reap nothing
// more, and another page stays.
func TestFs37CloseBeaconReapsAtOnce(t *testing.T) {
	world := newFs37World(t)
	page := world.addPage("tab", true)
	other := world.addPage("other", true)
	world.pollUntil(world.start.Add(10*time.Minute), page, other)

	// the beacon's answer is lost, as sendBeacon never reads one: the reap committed anyway
	if _, err := world.net.Faults().Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHttp, KeyPrefix: "/sidecar/close", Result: sidecartest.ApplyThenDrop}); err != nil {
		t.Fatal(err)
	}
	if _, err := page.Unload(world.ctx); err == nil {
		t.Fatal("the lost beacon answered")
	}
	reaps := world.reapsOf(page.ClientId())
	if len(reaps) != 1 || !reaps[0].Close || !reaps[0].Time.Equal(world.clock.Now()) {
		t.Fatalf("the beacon's reap: %+v", reaps)
	}
	world.refused[page.ClientId()] = true
	// a retry answers as the first did and reaps nothing more
	if status, err := page.Unload(world.ctx); err != nil || status != http.StatusNoContent {
		t.Fatalf("a retried beacon: %d %v", status, err)
	}
	// a wrong capability does nothing, and answers the same
	if status, err := world.closeWith("AAAAAAAAAAAAAAAAAAAAAA"); err != nil || status != http.StatusNoContent {
		t.Fatalf("a wrong capability: %d %v", status, err)
	}
	if status, err := world.closeWith("not a capability"); err != nil || status != http.StatusNoContent {
		t.Fatalf("a malformed capability: %d %v", status, err)
	}
	if status, err := world.closeWith(strings.Repeat(page.CloseCapability(), 3)); err != nil || status != http.StatusBadRequest {
		t.Fatalf("a body past the route's bound: %d %v", status, err)
	}
	if reaps := world.api.Reaps(); len(reaps) != 1 {
		t.Fatalf("the beacons reaped %+v", reaps)
	}
	statuses := world.pollCycle(page, other)
	if statuses[page] != http.StatusUnauthorized || statuses[other] != http.StatusOK {
		t.Fatalf("after the beacon: %v", statuses)
	}
	world.requireOutcomes()
}

// POST /sidecar/close with body, no Authorization header, as a beacon sends it: its status.
func (self *fs37World) closeWith(body string) (int, error) {
	request, err := http.NewRequestWithContext(self.ctx, http.MethodPost, self.api.Origin()+"/sidecar/close", strings.NewReader(body))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Content-Type", "text/plain;charset=UTF-8")
	response, err := self.api.Transport().RoundTrip(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	return response.StatusCode, nil
}

// A reaped page's old token keeps polling, each poll 401 and writing nothing, while its replacement stops and is
// reaped on its own lease; a removed client's polls are the same.
func TestFs37OldGenerationPollsKeepNothingAlive(t *testing.T) {
	world := newFs37World(t)
	first := world.addPage("tab", true)
	world.pollUntil(world.start.Add(30*time.Minute), first)

	// the tab is suspended: no polls, so its client is reaped
	world.advanceTo(world.lastPolls[first.ClientId()].Add(40 * time.Minute))
	world.requireReapedAfterItsLastPoll(first)

	// on resume its polls are 401 and it enrolls again; the old generation keeps polling beside the new one
	replacement := world.addPage("tab-again", true)
	removed := world.addPage("removed", true)
	world.api.RemoveClient(removed.ClientId())
	world.refused[removed.ClientId()] = true
	replacementSeen, _ := world.api.LeaseSeenTime(replacement.ClientId())
	stop := world.clock.Now().Add(20 * time.Minute)
	for world.clock.Now().Before(stop) {
		world.pollCycle(first, replacement, removed)
	}
	replacementLastPoll := world.lastPolls[replacement.ClientId()]
	if seen, ok := world.api.LeaseSeenTime(replacement.ClientId()); !ok || !replacementSeen.Before(seen) {
		t.Fatal("the replacement's own polls did not keep its lease")
	}

	// the replacement stops; the old generation's polls go on, and keep nothing alive
	replacement.Kill()
	for world.clock.Now().Before(replacementLastPoll.Add(40 * time.Minute)) {
		seen, ok := world.api.LeaseSeenTime(replacement.ClientId())
		world.pollCycle(first, removed)
		if after, afterOk := world.api.LeaseSeenTime(replacement.ClientId()); afterOk && (!ok || !after.Equal(seen)) {
			t.Fatal("an old generation's poll moved the replacement's lease")
		}
	}
	world.requireReapedAfterItsLastPoll(replacement)
	if len(world.reapsOf(first.ClientId())) != 1 || len(world.reapsOf(removed.ClientId())) != 0 {
		t.Fatal("a refused client was reaped again")
	}
}

// Two tabs, each its own ephemeral client, are reaped each on its own lease: the one killed first while the other
// polls on, the other after it stops.
func TestFs37TwoTabsReapIndependently(t *testing.T) {
	world := newFs37World(t)
	first := world.addPage("first", true)
	second := world.addPage("second", true)
	world.pollUntil(world.start.Add(2*time.Hour), first, second)

	first.Kill()
	world.pollUntil(world.lastPolls[first.ClientId()].Add(time.Hour), second)
	world.requireReapedAfterItsLastPoll(first)
	if reaps := world.reapsOf(second.ClientId()); len(reaps) != 0 {
		t.Fatalf("the polling tab was reaped: %+v", reaps)
	}

	second.Kill()
	world.advanceTo(world.lastPolls[second.ClientId()].Add(40 * time.Minute))
	world.requireReapedAfterItsLastPoll(second)
	if reaps := world.api.Reaps(); len(reaps) != 2 {
		t.Fatalf("reaps %+v", reaps)
	}
}

// An ephemeral client connected for 2 h, with no poll since its mint, then disconnected: not reaped 2 min after the
// disconnect, and reaped 35-36 min after it.
func TestFs37ConnectedEphemeralSurvivesAShortDisconnect(t *testing.T) {
	world := newFs37World(t)
	agent, err := world.net.AddHttpPage("agent", &sidecartest.TestHttpPageSettings{Ephemeral: true})
	if err != nil {
		t.Fatal(err)
	}
	disconnect := world.api.OpenConnection(agent.ClientId())
	world.advanceTo(world.start.Add(2 * time.Hour))
	if reaps := world.api.Reaps(); len(reaps) != 0 {
		t.Fatalf("a connected client was reaped: %+v", reaps)
	}

	disconnect()
	disconnectTime := world.clock.Now()
	world.advanceTo(disconnectTime.Add(2 * time.Minute))
	if reaps := world.api.Reaps(); len(reaps) != 0 {
		t.Fatalf("a client 2 min after its disconnect was reaped: %+v", reaps)
	}
	world.advanceTo(disconnectTime.Add(37 * time.Minute))
	reaps := world.reapsOf(agent.ClientId())
	if len(reaps) != 1 {
		t.Fatalf("reaps %+v", reaps)
	}
	after := reaps[0].Time.Sub(disconnectTime)
	if after <= 35*time.Minute || 36*time.Minute < after {
		t.Fatalf("reaped %s after its disconnect, not 35-36 min", after)
	}
}

// A member page Worker, a lease-less strict_exp client, polls hourly and refreshes at 3 days, 40-50% of its 7-day
// token, for 31 days: every poll and refresh answers, and the reaper never takes it. T3 shows server's idle sweep
// keeps it active too, since a strict_exp refresh moves auth_time (plan-SDK-http-only-idle-reap).
func TestFs37MemberPageRefreshingForThirtyOneDaysStaysActive(t *testing.T) {
	world := newFs37World(t)
	page := world.addPage("worker", false)
	nextRefresh := world.start.Add(3 * 24 * time.Hour)
	for world.clock.Now().Before(world.start.Add(31 * 24 * time.Hour)) {
		if status := world.pollCycle(page)[page]; status != http.StatusOK {
			t.Fatalf("day %.1f: a poll answered %d", world.clock.Now().Sub(world.start).Hours()/24, status)
		}
		if !world.clock.Now().Before(nextRefresh) {
			if status, err := page.Refresh(world.ctx); err != nil || status != http.StatusOK {
				t.Fatalf("day %.1f: a refresh answered %d %v", world.clock.Now().Sub(world.start).Hours()/24, status, err)
			}
			nextRefresh = nextRefresh.Add(3 * 24 * time.Hour)
		}
		world.advanceTo(world.clock.Now().Add(time.Hour - fs37HoldTimeout))
	}
	if _, status, err := page.ReadVersions(world.ctx); err != nil || status != http.StatusOK {
		t.Fatalf("a read at day 31: %d %v", status, err)
	}
	if reaps := world.api.Reaps(); len(reaps) != 0 {
		t.Fatalf("a member page was reaped: %+v", reaps)
	}
}
