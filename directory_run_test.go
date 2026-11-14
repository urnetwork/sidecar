//go:build !sidecar_http && !ios_extension

// RECORD-M6-16's run announcements on a fake writer and a fake clock: start within 10 s under auto and nothing under
// prompt or off; renewal keeping the version, its jitter inside ±5 min, and no renewal for an idle run; a private
// repo's run; a repo's marker read mid-run rewritten once; the end and a withdrawal; Resume ending a run that ended
// meanwhile at a version above the kept one; SetRuns' off withdrawing a project's runs; and FS-88's canaries absent
// from every entry. The claims are directory_claim_test.go's.

package sidecar_test

import (
	"bytes"
	"errors"
	mathrand "math/rand/v2"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A writer that keeps every announce draft it is handed.
type testRunsWriter struct {
	stateLock sync.Mutex
	drafts    []*sidecar.RecordDraft
}

func (self *testRunsWriter) Append(draft *sidecar.RecordDraft) ([]*sidecar.RecordEntryRef, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.drafts = append(self.drafts, draft)
	return []*sidecar.RecordEntryRef{{EntryId: sidecar.NewId()}}, nil
}

// The items written so far, in order, each a draft's body.
func (self *testRunsWriter) items(t *testing.T) []*protocol.Announcement {
	t.Helper()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	items := []*protocol.Announcement{}
	for _, draft := range self.drafts {
		item, ok := draft.Body.(*protocol.Announcement)
		if draft.Kind != sidecar.RecordKindAnnounce || !ok {
			t.Fatalf("a draft of kind %s, body %T", draft.Kind, draft.Body)
		}
		if err := sidecar.DirectoryCheckItem(item); err != nil {
			t.Fatalf("an item the readers would refuse: %v", err)
		}
		items = append(items, item)
	}
	return items
}

// Each draft's source, in order.
func (self *testRunsWriter) sources() []sidecar.RecordSource {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	sources := []sidecar.RecordSource{}
	for _, draft := range self.drafts {
		sources = append(sources, draft.Source)
	}
	return sources
}

// A reader of fixed bytes, for the runs' ids and the renewal's offset.
type testRunsRandom struct {
	stateLock sync.Mutex
	next      byte
}

func (self *testRunsRandom) Read(p []byte) (int, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for i := range p {
		self.next += 1
		p[i] = self.next
	}
	return len(p), nil
}

// Runs over a fake writer, clock, run view and store, a member's device in a team network whose repos' items a test
// sets.
type testRunsEnv struct {
	t         *testing.T
	clock     *sidecartest.FakeClock
	writer    *testRunsWriter
	runView   *sidecartest.FakeRunView
	files     *sidecartest.FakeStore
	sidecarId sidecar.Id
	memberId  sidecar.Id
	auth      *sidecartest.FakeDirectoryAuth
	repoItems map[sidecar.Id]*sidecar.DirectoryItem
	runs      *sidecar.DirectoryRuns
}

func newTestRunsEnv(t *testing.T) *testRunsEnv {
	t.Helper()
	env := &testRunsEnv{
		t:         t,
		clock:     sidecartest.NewFakeClock(sidecartest.DefaultClockStart()),
		writer:    &testRunsWriter{},
		runView:   sidecartest.NewFakeRunView(),
		files:     sidecartest.NewFakeStore(),
		sidecarId: sidecar.NewId(),
		memberId:  sidecar.NewId(),
		auth:      sidecartest.NewFakeDirectoryAuth(),
		repoItems: map[sidecar.Id]*sidecar.DirectoryItem{},
	}
	directoryId := sidecar.NewId()
	memberId := env.memberId
	env.auth.Append(&sidecartest.FakeDirectoryAuthFixture{
		Sidecars:    map[sidecar.Id]*sidecartest.FakeDirectorySidecar{env.sidecarId: {MemberId: &memberId}},
		DirectoryId: &directoryId,
	})
	env.runs = env.open()
	return env
}

// A process's life of the runs, over what the store holds now.
func (self *testRunsEnv) open() *sidecar.DirectoryRuns {
	self.t.Helper()
	runs, err := sidecar.NewDirectoryRuns(&sidecar.DirectoryRunsArgs{
		SidecarId: self.sidecarId,
		Writer:    self.writer,
		Runs:      self.runView,
		Auth:      func() sidecar.DirectoryAuthView { return self.auth.Tip() },
		RepoItem: func(repoId sidecar.Id) (*sidecar.DirectoryItem, bool) {
			item, ok := self.repoItems[repoId]
			return item, ok
		},
		Store:  self.files.Root(),
		Clock:  self.clock,
		Random: &testRunsRandom{},
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return runs
}

// A run's start, auto, in no evs repo.
func (self *testRunsEnv) start(claims sidecar.DirectoryRunClaims) *sidecar.DirectoryRunStart {
	self.t.Helper()
	runId := sidecar.NewId()
	self.runView.StartRun(runId)
	agentId := sidecar.NewId()
	start := &sidecar.DirectoryRunStart{
		RunId:      runId,
		Claims:     claims,
		ProjectKey: "example.com/team/app",
		AgentId:    &agentId,
		AgentLabel: "builder",
		Harness:    "claude-code",
		Model:      "a-model",
		Title:      "fix the retry path",
		Project:    "example.com/team/app",
		Branch:     "main",
	}
	if err := self.runs.Started(start); err != nil {
		self.t.Fatal(err)
	}
	return start
}

// An active item of a repo, or its private marker.
func testRunsRepoItem(repoId sidecar.Id, private bool) *sidecar.DirectoryItem {
	return &sidecar.DirectoryItem{
		Display:      sidecar.DirectoryItemActive,
		Announcement: &protocol.Announcement{Where: &protocol.AnnounceWhere{RepoId: repoId.Bytes(), Private: private}},
	}
}

// Under claims auto a run is announced within 10 s of its start, at version 1, with its who, what and where, source
// hook and the run's id in the header; prompt and off announce nothing at its start.
func TestDirectoryRunStartWithinTenSeconds(t *testing.T) {
	env := newTestRunsEnv(t)
	start := env.start(sidecar.DirectoryRunClaimsAuto)
	env.start(sidecar.DirectoryRunClaimsPrompt)
	env.start(sidecar.DirectoryRunClaimsOff)
	env.clock.Advance(9 * time.Second)
	if items := env.writer.items(t); len(items) != 0 {
		t.Fatalf("%d items before 10 s", len(items))
	}
	env.clock.Advance(time.Second)
	items := env.writer.items(t)
	if len(items) != 1 {
		t.Fatalf("%d items at 10 s", len(items))
	}
	item := items[0]
	if item.GetVersion() != 1 || item.GetState() != uint32(sidecar.DirectoryAnnouncementStateActive) || item.GetKind() != uint32(sidecar.DirectoryAnnouncementKindRun) ||
		!bytes.Equal(item.GetWho().GetMemberId(), env.memberId.Bytes()) || !bytes.Equal(item.GetWho().GetSidecarId(), env.sidecarId.Bytes()) ||
		item.GetWho().GetAgentLabel() != "builder" || item.GetWho().GetHarness() != "claude-code" || item.GetWhat().GetTitle() != "fix the retry path" ||
		!bytes.Equal(item.GetWhat().GetRunId(), start.RunId.Bytes()) || item.GetWhere().GetProject() != "example.com/team/app" ||
		item.GetWhere().GetBranch() != "main" || item.GetWhere().GetPrivate() || item.GetTainted() {
		t.Fatalf("item %v", item)
	}
	if sources := env.writer.sources(); sources[0] != sidecar.RecordSourceHook {
		t.Fatalf("source %v", sources)
	}
}

// Over many seeded draws each run's first renewal falls hourly at ±5 min, never outside.
func TestDirectoryRunRenewalJitterInsideFiveMinutes(t *testing.T) {
	for seed := byte(0); seed < 64; seed += 1 {
		env := newTestRunsEnv(t)
		runs, err := sidecar.NewDirectoryRuns(&sidecar.DirectoryRunsArgs{
			SidecarId: env.sidecarId,
			Writer:    env.writer,
			Auth:      func() sidecar.DirectoryAuthView { return env.auth.Tip() },
			Clock:     env.clock,
			Random:    mathrand.NewChaCha8([32]byte{seed}),
		})
		if err != nil {
			t.Fatal(err)
		}
		env.runs = runs
		env.start(sidecar.DirectoryRunClaimsAuto)
		env.clock.Advance(10 * time.Second)
		pending := env.clock.PendingTimers()
		if len(pending) != 1 {
			t.Fatalf("seed %d: timers %v", seed, pending)
		}
		if offset := pending[0].Sub(env.clock.Now()); offset < 55*time.Minute || 65*time.Minute < offset {
			t.Fatalf("seed %d: the renewal in %s", seed, offset)
		}
	}
}

// A renewal hourly at ±5 min keeps the version and raises renewed and expires, while the run moved in the past hour;
// an idle run renews nothing, so its item expires.
func TestDirectoryRunRenewalKeepsTheVersion(t *testing.T) {
	env := newTestRunsEnv(t)
	start := env.start(sidecar.DirectoryRunClaimsAuto)
	env.clock.Advance(10 * time.Second)
	first := env.writer.items(t)[0]
	pending := env.clock.PendingTimers()
	if len(pending) != 1 {
		t.Fatalf("timers %v", pending)
	}
	if offset := pending[0].Sub(env.clock.Now()); offset < 55*time.Minute || 65*time.Minute < offset {
		t.Fatalf("the renewal in %s", offset)
	}
	env.clock.Advance(30 * time.Minute)
	env.runs.Moved(start.RunId)
	// the run read untrusted data since: tainted is the writing run's taint at each write
	env.runView.Taint(start.RunId)
	env.clock.AdvanceTo(pending[0])
	items := env.writer.items(t)
	if len(items) != 2 {
		t.Fatalf("%d items after the renewal", len(items))
	}
	renewal := items[1]
	if renewal.GetVersion() != first.GetVersion() || renewal.GetRenewedMillis() <= first.GetRenewedMillis() ||
		renewal.GetExpiresMillis() != renewal.GetRenewedMillis()+sidecar.DirectoryRunExpiry.Milliseconds() || first.GetTainted() || !renewal.GetTainted() {
		t.Fatalf("renewal %v after %v", renewal, first)
	}
	// no move in the next hour: no renewal
	next := env.clock.PendingTimers()
	if len(next) != 1 {
		t.Fatalf("timers %v", next)
	}
	env.clock.AdvanceTo(next[0])
	if items := env.writer.items(t); len(items) != 2 {
		t.Fatalf("an idle run renewed: %d items", len(items))
	}
}

// A run in an evs repo with no live item, or a private marker, announces the repo's id with private true and no
// project or branch; one whose repo is announced names them; and once the repo's marker is read mid-run the item is
// rewritten private, once.
func TestDirectoryRunWhereFollowsTheRepo(t *testing.T) {
	env := newTestRunsEnv(t)
	privateRepo := sidecar.NewId()
	start := env.start(sidecar.DirectoryRunClaimsOff)
	start.RunId = sidecar.NewId()
	start.Claims = sidecar.DirectoryRunClaimsAuto
	start.RepoId = &privateRepo
	if err := env.runs.Started(start); err != nil {
		t.Fatal(err)
	}
	announcedRepo := sidecar.NewId()
	env.repoItems[announcedRepo] = testRunsRepoItem(announcedRepo, false)
	named := *start
	named.RunId = sidecar.NewId()
	named.RepoId = &announcedRepo
	if err := env.runs.Started(&named); err != nil {
		t.Fatal(err)
	}
	env.clock.Advance(10 * time.Second)
	items := env.writer.items(t)
	if len(items) != 2 {
		t.Fatalf("%d items", len(items))
	}
	byRun := map[string]*protocol.Announcement{}
	for _, item := range items {
		byRun[string(item.GetWhat().GetRunId())] = item
	}
	private := byRun[string(start.RunId.Bytes())]
	if !private.GetWhere().GetPrivate() || private.GetWhere().GetProject() != "" || private.GetWhere().GetBranch() != "" ||
		!bytes.Equal(private.GetWhere().GetRepoId(), privateRepo.Bytes()) {
		t.Fatalf("the private repo's run: %v", private.GetWhere())
	}
	shown := byRun[string(named.RunId.Bytes())]
	if shown.GetWhere().GetPrivate() || shown.GetWhere().GetProject() != "example.com/team/app" || shown.GetWhere().GetBranch() != "main" {
		t.Fatalf("the announced repo's run: %v", shown.GetWhere())
	}

	env.repoItems[announcedRepo] = testRunsRepoItem(announcedRepo, true)
	env.runs.Moved(named.RunId)
	env.runs.Moved(named.RunId)
	items = env.writer.items(t)
	if len(items) != 3 {
		t.Fatalf("%d items after the marker", len(items))
	}
	rewritten := items[2]
	if !rewritten.GetWhere().GetPrivate() || rewritten.GetWhere().GetProject() != "" || rewritten.GetVersion() != shown.GetVersion()+1 {
		t.Fatalf("rewritten %v", rewritten)
	}
}

// The end writes the item ended at a raised version and renews nothing after; a withdrawal is a newer entry holding
// only its own fields, after which the run's claims are refused.
func TestDirectoryRunEndAndWithdraw(t *testing.T) {
	env := newTestRunsEnv(t)
	ended := env.start(sidecar.DirectoryRunClaimsAuto)
	withdrawn := env.start(sidecar.DirectoryRunClaimsAuto)
	env.clock.Advance(10 * time.Second)
	if err := env.runs.Ended(ended.RunId); err != nil {
		t.Fatal(err)
	}
	if err := env.runs.Withdraw(withdrawn.RunId); err != nil {
		t.Fatal(err)
	}
	items := env.writer.items(t)
	if len(items) != 4 {
		t.Fatalf("%d items", len(items))
	}
	if items[2].GetState() != uint32(sidecar.DirectoryAnnouncementStateEnded) || items[2].GetVersion() != 2 {
		t.Fatalf("ended %v", items[2])
	}
	withdrawal := items[3]
	if withdrawal.GetState() != uint32(sidecar.DirectoryAnnouncementStateWithdrawn) || withdrawal.GetVersion() != 2 ||
		withdrawal.GetWhat() != nil || withdrawal.GetWhere() != nil || withdrawal.GetWho().GetAgentLabel() != "" {
		t.Fatalf("withdrawal %v", withdrawal)
	}
	runId := withdrawn.RunId
	_, err := env.runs.Coordinate(t.Context(), &sidecar.RecordAppendArgs{Kind: sidecar.RecordKindClaim, RunId: &runId},
		&sidecar.RecordTargets{}, &protocol.CoordinationBody{})
	if !errors.Is(err, sidecar.ErrDirectoryRunsClaimsOff) {
		t.Fatalf("a claim after the withdrawal: %v", err)
	}
	env.clock.Advance(2 * time.Hour)
	if items := env.writer.items(t); len(items) != 4 {
		t.Fatalf("%d items after the end", len(items))
	}
}

// A restart keeps each open run's item: Resume ends the runs that ended meanwhile at a version above the kept one,
// and keeps the rest, which a move renews at their kept version.
func TestDirectoryRunResumeEndsRunsThatEndedMeanwhile(t *testing.T) {
	env := newTestRunsEnv(t)
	gone := env.start(sidecar.DirectoryRunClaimsAuto)
	kept := env.start(sidecar.DirectoryRunClaimsAuto)
	env.clock.Advance(10 * time.Second)
	runId := gone.RunId
	if _, err := env.runs.Coordinate(t.Context(), &sidecar.RecordAppendArgs{Kind: sidecar.RecordKindClaim, RunId: &runId},
		&sidecar.RecordTargets{Paths: []string{"src/"}}, &protocol.CoordinationBody{Text: "the retry path", Targets: []string{"src/"}}); err != nil {
		t.Fatal(err)
	}
	// a restart: the process's timers stop with it, and nothing is in memory
	env.runs.Close()
	env.runs = env.open()
	if err := env.runs.Resume(func(runId sidecar.Id) bool { return runId == gone.RunId }); err != nil {
		t.Fatal(err)
	}
	items := env.writer.items(t)
	last := items[len(items)-1]
	if last.GetState() != uint32(sidecar.DirectoryAnnouncementStateEnded) || last.GetVersion() != 3 || !bytes.Equal(last.GetWhat().GetRunId(), gone.RunId.Bytes()) ||
		len(last.GetClaims()) != 1 {
		t.Fatalf("the resumed end %v", last)
	}
	pending := env.clock.PendingTimers()
	if len(pending) != 1 {
		t.Fatalf("timers %v", pending)
	}
	env.clock.AdvanceTo(pending[0].Add(-time.Minute))
	env.runs.Moved(kept.RunId)
	env.clock.AdvanceTo(pending[0])
	items = env.writer.items(t)
	renewal := items[len(items)-1]
	if !bytes.Equal(renewal.GetWhat().GetRunId(), kept.RunId.Bytes()) || renewal.GetVersion() != 1 {
		t.Fatalf("the kept run's renewal %v", renewal)
	}
}

// SetRuns' off withdraws each running item of its project at once, leaves another project's, and, with no harness
// config writer bound, answers that the value is not kept.
func TestDirectoryClientSetRunsOffWithdraws(t *testing.T) {
	env := newTestRunsEnv(t)
	files := sidecartest.NewFakeStore()
	client, err := sidecar.NewDirectoryClient(&sidecar.DirectoryClientArgs{
		SidecarId: env.sidecarId,
		Store:     files.Root(),
		Auth:      func() sidecar.DirectoryAuthView { return env.auth.Tip() },
		Clock:     env.clock,
		Settings:  sidecar.DefaultSidecarSettings().Directory,
		Writer:    env.writer,
		Runs:      env.runView,
	})
	if err != nil {
		t.Fatal(err)
	}
	env.runs = client.Runs()
	app := env.start(sidecar.DirectoryRunClaimsAuto)
	other := *app
	other.RunId = sidecar.NewId()
	other.ProjectKey = "example.com/team/other"
	if err := env.runs.Started(&other); err != nil {
		t.Fatal(err)
	}
	env.clock.Advance(10 * time.Second)
	if err := client.SetRuns(t.Context(), "example.com/team/app", sidecar.DirectoryRunClaimsOff); !errors.Is(err, sidecar.ErrDirectoryRunsConfigUnavailable) {
		t.Fatalf("SetRuns: %v", err)
	}
	items := env.writer.items(t)
	if len(items) != 3 || items[2].GetState() != uint32(sidecar.DirectoryAnnouncementStateWithdrawn) || items[2].GetVersion() != 2 {
		t.Fatalf("items %v", items)
	}
	withdrawnId := items[2].GetAnnouncementId()
	if !bytes.Equal(withdrawnId, items[0].GetAnnouncementId()) && !bytes.Equal(withdrawnId, items[1].GetAnnouncementId()) {
		t.Fatal("the withdrawal names no announced item")
	}
	// ur directory withdraw <id>: the other project's item by its id; an id no open run holds refused
	otherItem := items[0]
	if bytes.Equal(otherItem.GetAnnouncementId(), withdrawnId) {
		otherItem = items[1]
	}
	if !bytes.Equal(otherItem.GetWhat().GetRunId(), other.RunId.Bytes()) {
		t.Fatal("the other project's run was withdrawn")
	}
	if err := client.Withdraw(sidecar.Id(otherItem.GetAnnouncementId())); err != nil {
		t.Fatal(err)
	}
	if err := client.Withdraw(sidecar.NewId()); !errors.Is(err, sidecar.ErrDirectoryItemNone) {
		t.Fatalf("an unknown id: %v", err)
	}
	if items := env.writer.items(t); len(items) != 4 || items[3].GetState() != uint32(sidecar.DirectoryAnnouncementStateWithdrawn) {
		t.Fatalf("after the withdrawal by id: %d items", len(items))
	}
}

// FS-88's I-20 clause: canaries in a prompt past the title's first line, and in what the session did, never appear in
// an entry; only who, what and where do.
func TestDirectoryRunFs88CanariesNeverAnnounced(t *testing.T) {
	env := newTestRunsEnv(t)
	start := env.start(sidecar.DirectoryRunClaimsOff)
	start.RunId = sidecar.NewId()
	start.Claims = sidecar.DirectoryRunClaimsAuto
	start.Title = "fix the retry path\nCANARY-PROMPT-PAST-THE-FIRST-LINE"
	if err := env.runs.Started(start); err != nil {
		t.Fatal(err)
	}
	env.clock.Advance(10 * time.Second)
	env.runs.Moved(start.RunId)
	runId := start.RunId
	if _, err := env.runs.Coordinate(t.Context(), &sidecar.RecordAppendArgs{Kind: sidecar.RecordKindClaim, RunId: &runId},
		&sidecar.RecordTargets{Paths: []string{"src/retry/"}}, &protocol.CoordinationBody{Text: "taking the retry path", Targets: []string{"src/retry/"}}); err != nil {
		t.Fatal(err)
	}
	env.clock.Advance(65 * time.Minute)
	if err := env.runs.Ended(start.RunId); err != nil {
		t.Fatal(err)
	}
	items := env.writer.items(t)
	if len(items) < 3 {
		t.Fatalf("%d items", len(items))
	}
	for _, item := range items {
		encoded, err := proto.Marshal(item)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(encoded, []byte("CANARY")) {
			t.Fatal("a canary reached an entry")
		}
		if title := item.GetWhat().GetTitle(); title != "" && title != "fix the retry path" {
			t.Fatalf("title %q", title)
		}
	}
	if strings.Contains(items[0].GetWhat().GetTitle(), "\n") {
		t.Fatal("a title holds a line break")
	}
	// nothing else of a session can reach the runs: a start carries its who, what and where and nothing more, so a
	// field that could carry a tool's input or output, a touched path or a diff fails here first
	fields := []string{}
	startType := reflect.TypeOf(sidecar.DirectoryRunStart{})
	for i := 0; i < startType.NumField(); i += 1 {
		fields = append(fields, startType.Field(i).Name)
	}
	want := "RunId,Claims,ProjectKey,AgentId,AgentLabel,Harness,Model,Title,RepoId,Project,Branch"
	if strings.Join(fields, ",") != want {
		t.Fatalf("DirectoryRunStart's fields %v, want %s", fields, want)
	}
}
