//go:build !ios_extension && !sidecar_http

// An agent's status (§20.6, D-SKILL-2): written at most once a StatusMinInterval, the newest note winning, held by a
// write the test keeps in flight; refreshed while its run stays open and not after; offline once older than
// OfflineAfter; held to the card's own sidecar, another writer's version passed over and alarmed; never written by a
// sidecar that is not the agent's.

package sidecar

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// A world on a clock the test moves, with the laptop's agent fix registered and a writer whose writes the test hears.
type testAgentStatusEnv struct {
	world   *testAgentCardsWorld
	laptop  *AgentsClient
	phone   *AgentsClient
	writer  *AgentStatusWriter
	written chan testAgentStatusWritten
}

// One write the writer made.
type testAgentStatusWritten struct {
	name AgentName
	err  error
}

func newTestAgentStatusEnv(t *testing.T) *testAgentStatusEnv {
	t.Helper()
	world := newTestAgentCardsWorld(t)
	world.timers = newHarnessTestClock()
	env := &testAgentStatusEnv{world: world, laptop: world.client(world.laptop), phone: world.client(world.phone),
		written: make(chan testAgentStatusWritten, 64)}
	if _, err := env.laptop.Register(world.ctx, &AgentRegisterArgs{Name: "fix", Harness: "ur-harness 1.0", Model: "local-gemma"}); err != nil {
		t.Fatal(err)
	}
	writer, err := NewAgentStatusWriter(&AgentStatusWriterArgs{Client: env.laptop, Written: func(name AgentName, err error) {
		env.written <- testAgentStatusWritten{name: name, err: err}
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(writer.Close)
	env.writer = writer
	return env
}

// The next write the writer made.
func (self *testAgentStatusEnv) next(t *testing.T) testAgentStatusWritten {
	t.Helper()
	return <-self.written
}

// How many versions status/<name>.json holds.
func (self *testAgentStatusEnv) statusVersions(name AgentName) int {
	repo := self.world.agentsRepo()
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	return len(repo.paths[agentStatusPath(name)])
}

// A working status of activity, now.
func (self *testAgentStatusEnv) working(activity string) *AgentStatus {
	return &AgentStatus{State: AgentStateWorking, Activity: activity, Task: "the limiter", Updated: self.world.now(), RunId: testConfigId("run")}
}

func TestStatusRateLimited(t *testing.T) {
	env := newTestAgentStatusEnv(t)
	world := env.world
	// the barrier around the write: the world holds the writer's first write in flight until the test lets it go
	held, release := make(chan struct{}), make(chan struct{})
	func() {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		world.beforeWrite = func() {
			close(held)
			<-release
		}
	}()
	env.writer.Note(&AgentStatusNote{Name: "fix", Status: env.working("one")})
	<-held
	// notes while the write is held and after it coalesce, the newest winning
	env.writer.Note(&AgentStatusNote{Name: "fix", Status: env.working("two")})
	env.writer.Note(&AgentStatusNote{Name: "fix", Status: env.working("three")})
	close(release)
	if written := env.next(t); written.err != nil || written.name != "fix" {
		t.Fatalf("the first write: %+v", written)
	}
	// the writer waits on its timer, a minute after the write: nothing more is written before it
	if err := world.timers.AwaitTimers(world.ctx, 1); err != nil {
		t.Fatal(err)
	}
	world.timers.Advance(world.settings.StatusMinInterval - time.Second)
	if count := env.statusVersions("fix"); count != 1 {
		t.Fatalf("%d status versions within a minute of the first", count)
	}
	world.timers.Advance(time.Second)
	if written := env.next(t); written.err != nil {
		t.Fatal(written.err)
	}
	read, err := env.phone.Status(world.ctx, "fix")
	if err != nil {
		t.Fatal(err)
	}
	if count := env.statusVersions("fix"); count != 2 || read.Status.Activity != "three" {
		t.Fatalf("%d versions, the newest %q: the newest note should win the second write", count, read.Status.Activity)
	}
}

func TestStatusOfflineAfterFifteenMinutes(t *testing.T) {
	env := newTestAgentStatusEnv(t)
	world := env.world
	if err := env.laptop.WriteStatus(world.ctx, &AgentStatusWrite{Name: "fix", Status: env.working("tests")}); err != nil {
		t.Fatal(err)
	}
	read, err := env.phone.Status(world.ctx, "fix")
	if err != nil {
		t.Fatal(err)
	}
	if read.State != AgentStateWorking || !read.Trusted || read.WriterSidecarId != world.laptop {
		t.Fatalf("a fresh status: %+v", read)
	}
	world.timers.Advance(world.settings.OfflineAfter - time.Second)
	if read, _ := env.phone.Status(world.ctx, "fix"); read.State != AgentStateWorking {
		t.Fatalf("a status a second short of the bound reads %s", read.State)
	}
	world.timers.Advance(time.Second)
	read, err = env.phone.Status(world.ctx, "fix")
	if err != nil {
		t.Fatal(err)
	}
	if read.State != AgentStateOffline || read.Status.State != AgentStateWorking || read.Age != world.settings.OfflineAfter {
		t.Fatalf("a status at the bound: shown %s, written %s, age %s", read.State, read.Status.State, read.Age)
	}
}

func TestStatusRefreshWhileRunOpen(t *testing.T) {
	env := newTestAgentStatusEnv(t)
	world := env.world
	runDone := make(chan struct{})
	env.writer.Note(&AgentStatusNote{Name: "fix", Status: env.working("waiting on its inbox"), Done: runDone})
	if written := env.next(t); written.err != nil {
		t.Fatal(written.err)
	}
	// nothing new is noted, and the open run's status is written again at the refresh interval, with a new updated
	world.timers.Advance(world.settings.StatusRefreshInterval)
	if written := env.next(t); written.err != nil {
		t.Fatal(written.err)
	}
	read, err := env.phone.Status(world.ctx, "fix")
	if err != nil {
		t.Fatal(err)
	}
	if env.statusVersions("fix") != 2 || read.Status.Activity != "waiting on its inbox" || !read.Status.Updated.Equal(world.now()) {
		t.Fatalf("the refresh: %d versions, %+v", env.statusVersions("fix"), read.Status)
	}
	// the run closes: no refresh follows; a note of an agent with no card is the test's mark that the writer has run
	// its round past the refresh's time
	close(runDone)
	world.timers.Advance(world.settings.StatusRefreshInterval)
	env.writer.Note(&AgentStatusNote{Name: "unregistered", Status: env.working("nothing")})
	if written := env.next(t); written.name != "unregistered" || !errors.Is(written.err, ErrAgentCardAbsent) {
		t.Fatalf("the mark: %+v", written)
	}
	if count := env.statusVersions("fix"); count != 2 {
		t.Fatalf("%d status versions after the run closed", count)
	}
	if open, _, _ := env.writer.line("fix"); open {
		t.Fatal("a closed run's line is still open")
	}
}

func TestStatusHeldToItsWriter(t *testing.T) {
	env := newTestAgentStatusEnv(t)
	world := env.world
	if err := env.laptop.WriteStatus(world.ctx, &AgentStatusWrite{Name: "fix", Status: env.working("its own")}); err != nil {
		t.Fatal(err)
	}
	// another device of the member and a tagged sidecar it sponsors write at the laptop agent's status path
	forged, err := EncodeAgentStatus(&AgentStatus{State: AgentStateBlocked, Activity: "forged", Updated: world.now()}, world.settings)
	if err != nil {
		t.Fatal(err)
	}
	repo := world.agentsRepo()
	func() {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		repo.put(world.phone, agentStatusPath("fix"), forged)
		repo.put(world.cloud, agentStatusPath("fix"), forged)
	}()
	read, err := env.phone.Status(world.ctx, "fix")
	if err != nil {
		t.Fatal(err)
	}
	if read.Status.Activity != "its own" || len(read.PassedOver) != 2 || world.alarmCount() != 2 {
		t.Fatalf("the status past two forgeries: %+v, %d alarms", read, world.alarmCount())
	}
	// the phone may not write the laptop's agent's status, nor anyone a status for a card that does not stand
	if err := env.phone.WriteStatus(world.ctx, &AgentStatusWrite{Name: "fix", Status: env.working("not mine")}); !errors.Is(err, ErrAgentsNotWriter) {
		t.Fatalf("another sidecar's status write: %v", err)
	}
	if err := env.laptop.WriteStatus(world.ctx, &AgentStatusWrite{Name: "nobody", Status: env.working("x")}); !errors.Is(err, ErrAgentCardAbsent) {
		t.Fatalf("a status with no card: %v", err)
	}
	// a tainted run's status reads untrusted
	if err := env.laptop.WriteStatus(world.ctx, &AgentStatusWrite{Name: "fix", Status: env.working("read the web"), Tainted: true}); err != nil {
		t.Fatal(err)
	}
	if read, _ := env.phone.Status(world.ctx, "fix"); read.Trusted || read.Status.Activity != "read the web" {
		t.Fatalf("a tainted run's status: %+v", read)
	}
}

func TestStatusGrammar(t *testing.T) {
	settings := DefaultSkillSettings()
	at := time.Date(2026, 12, 1, 10, 0, 0, 0, time.UTC)
	status := &AgentStatus{State: AgentStateIdle, Activity: "é", Task: "t", Updated: at}
	data, err := EncodeAgentStatus(status, settings)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"state":"idle","activity":"é","task":"t","updated":"2026-12-01T10:00:00Z","run_id":""}`+"\n" {
		t.Fatalf("the bytes: %s", data)
	}
	refused := []string{
		`{"state":"sleeping","activity":"","task":"","updated":"2026-12-01T10:00:00Z","run_id":""}`,
		`{"state":"idle","activity":"a` + "\\u0007" + `","task":"","updated":"2026-12-01T10:00:00Z","run_id":""}`,
		`{"state":"idle","activity":"","task":"","updated":"yesterday","run_id":""}`,
		`{"state":"idle","activity":"","task":"","updated":"2026-12-01T10:00:00Z","run_id":"ABC"}`,
		`{"state":"idle"} {}`,
	}
	for _, text := range refused {
		if _, err := ParseAgentStatus([]byte(text), settings); !errors.Is(err, ErrAgentStatusInvalid) {
			t.Errorf("%s: %v", text, err)
		}
	}
	long := &AgentStatus{State: AgentStateIdle, Activity: strings.Repeat("é", settings.StatusActivityCharCount+1), Updated: at}
	if _, err := EncodeAgentStatus(long, settings); !errors.Is(err, ErrAgentStatusInvalid) {
		t.Errorf("an activity past its bound: %v", err)
	}
	if cut := AgentStatusText("a\nb  ", 2); cut != "a" {
		t.Errorf("a cut text: %q", cut)
	}
}
