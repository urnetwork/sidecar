//go:build !sidecar_http && !js && !ios_extension

// The group repos' hint watch (track mail-group-hint-watch; mail_component_group.go): a group repo was ingested only
// at the mail component's looks, CheckInterval apart, with no watch on its hints as the mailbox's ingestor has, so a
// group's message waited up to CheckInterval before it was listed (TestE2eChurnLoad, as mail-group-ingest-loss found
// it). Each group repo with a role now runs on a goroutine of its own that holds the repo's watch. On the mail
// client's in-memory stand-ins, its clock a test's: a group's message is listed in the member's view at its hint, the
// clock moved by MinPassInterval gaps alone; a reference to a message another writer ingested follows the group's
// hint, raising IDLE's hint; a burst of hints is one pass; a hint that never came is caught at the component's next
// look; and of two groups with room for one watch, one holds it, the other is caught at the looks, and the
// generation's end stops the watch and joins both goroutines.

package sidecar

import (
	"context"
	"slices"
	"testing"
	"time"
)

// Waits for a group's goroutine to end a pass, which it marks by arming its MinPassInterval gap on clock, passing over
// any wait another part of the client arms there.
func testAwaitMailGroupPass(t *testing.T, client *MailClient, clock *testConfigClock) {
	t.Helper()
	for {
		if armed := testAwait(t, clock.armed, "the end of a group's pass"); armed == client.settings.Ingest.MinPassInterval {
			return
		}
	}
}

// A member's device with mail on and groups it created, so it ingests their deposits, each listing its member, so it
// adds the member's references; its client, a restart's over the state the groups were made at, on a test's clock.
type mailGroupHintTestWorld struct {
	*mailClientTestWorld
	clock *testConfigClock
	// the groups' repo ids in the order they were made, and the look's generation once one ran
	groupIds []Id
	run      *mailComponentRun
}

func newMailGroupHintTestWorld(t *testing.T, localParts ...string) *mailGroupHintTestWorld {
	t.Helper()
	ctx := t.Context()
	world := newMailClientTestWorld(t)
	world.enable()
	world.groups = map[Id]*mailIngestTestWorld{}
	hint := &mailGroupHintTestWorld{mailClientTestWorld: world, clock: newTestConfigClock()}
	for _, localPart := range localParts {
		repo, err := world.client.CreateGroup(ctx, &MailCreateGroupArgs{LocalPart: localPart, Confirmed: true})
		if err != nil {
			t.Fatal(err)
		}
		group := newMailIngestTestWorld(t)
		group.repoId = repo.RepoId()
		world.groups[group.repoId] = group
		world.configAuthority.own(group.repoId, world.device)
		if err := world.client.AddGroupMember(ctx, localPart, world.member); err != nil {
			t.Fatal(err)
		}
		hint.groupIds = append(hint.groupIds, group.repoId)
	}
	client := world.newClient()
	client.setNetworkRow(testMailIngestNetwork())
	// mailcfg read on the real clock, so its follower arms nothing on the test's
	if _, err := client.syncedConfig(ctx); err != nil {
		t.Fatal(err)
	}
	client.clock = hint.clock
	world.client = client
	return hint
}

// The group made first.
func (self *mailGroupHintTestWorld) group() *mailIngestTestWorld {
	return self.groups[self.groupIds[0]]
}

// The component's look at the groups, as each of its passes makes one, on a generation whose end the test's end
// brings.
func (self *mailGroupHintTestWorld) look() {
	self.t.Helper()
	if self.run == nil {
		ctx, cancel := context.WithCancel(self.t.Context())
		run := &mailComponentRun{ctx: ctx, cancel: cancel}
		self.run = run
		self.t.Cleanup(func() {
			self.client.stopRun(run)
			cancel()
		})
	}
	binding, _, err := self.client.bound()
	if err != nil {
		self.t.Fatal(err)
	}
	self.client.passGroupInboxes(self.run, binding)
}

// The group's goroutine, nil with none.
func (self *mailGroupHintTestWorld) inbox(groupId Id) *mailGroupInbox {
	self.client.stateLock.Lock()
	defer self.client.stateLock.Unlock()
	return self.run.groupInboxes[groupId]
}

// Waits for a group's pass to end, then lets its MinPassInterval gap run out: its next pass is a wake's.
func (self *mailGroupHintTestWorld) awaitPassAndGap() {
	self.t.Helper()
	testAwaitMailGroupPass(self.t, self.client, self.clock)
	self.clock.Advance(self.client.settings.Ingest.MinPassInterval)
}

// The hint of a change of a group's repo, as its watch's subscription raises one.
func (self *mailGroupHintTestWorld) hint(group *mailIngestTestWorld) {
	self.t.Helper()
	wake, _, _, _ := group.repo.watching()
	if wake == nil {
		self.t.Fatal("no watch on the group repo")
	}
	wake()
}

// How many times the member's view lists each message of the group repo groupId.
func (self *mailGroupHintTestWorld) listed(groupId Id) map[Id]int {
	self.t.Helper()
	page, err := self.client.List(self.t.Context(), &MailListArgs{})
	if err != nil {
		self.t.Fatal(err)
	}
	counts := map[Id]int{}
	for _, entry := range page.Entries {
		if entry.RepoId == groupId {
			counts[mailEntryId(entry.Entry)] += 1
		}
	}
	return counts
}

// A group's message is listed in the member's view at its repo's hint: the component's look starts the group's
// goroutine, which holds the repo's watch, and the deposit's hint brings the pass that writes the message to the
// group's m/ and i/, consumes the deposit and adds the member's r/ reference, raising IDLE's hint for each, with the
// clock moved by the MinPassInterval gaps alone, never toward CheckInterval. Before, nothing watched a group repo, so
// the message waited for the component's next look, and the hint here found no watch to wake.
func TestMailGroupMessageIsListedAtItsHint(t *testing.T) {
	world := newMailGroupHintTestWorld(t, "team")
	group := world.group()
	world.look()
	world.awaitPassAndGap()
	deposit := group.depositMessage(testMailIngestMessage("Team", "Shared at its hint"))
	if listed := world.listed(group.repoId); len(listed) != 0 {
		t.Fatalf("listed before its hint: %v", listed)
	}
	revision, _ := world.client.ImapHints()
	world.hint(group)
	testAwaitMailGroupPass(t, world.client, world.clock)
	if listed := world.listed(group.repoId); len(listed) != 1 || listed[deposit.id] != 1 {
		t.Fatalf("the member's view lists %v at the hint, log %v", listed, world.log.snapshot())
	}
	if group.repo.standingCount(group.receiverId) != 0 || len(group.entries(MailYearMonthOf(testMailIngestReceiveMillis))) != 1 {
		t.Error("the group's deposit was not ingested once")
	}
	// one for the message ingest wrote, one for the reference
	if hinted, _ := world.client.ImapHints(); hinted != revision+2 {
		t.Errorf("IDLE's hint rose %d times", hinted-revision)
	}
	if moved := world.clock.Now().Sub(time.UnixMilli(testConfigStartMs)); world.client.settings.CheckInterval <= moved {
		t.Errorf("the clock moved %s, past CheckInterval %s", moved, world.client.settings.CheckInterval)
	}
}

// A member's reference follows the group repo's hint of another writer's ingest, as a team member's device that only
// reads the group takes the writer's push: the message another device ingested is referenced in the member's mailbox
// and listed at the hint, IDLE's hint raised for the reference alone, this device's own ingest finding nothing.
func TestMailGroupReferenceFollowsAnotherWritersIngestAtItsHint(t *testing.T) {
	world := newMailGroupHintTestWorld(t, "team")
	group := world.group()
	world.look()
	world.awaitPassAndGap()
	deposit := group.depositMessage(testMailIngestMessage("Elsewhere", "Ingested by another writer"))
	if pass := group.ingest(group.ingestor(nil)); pass.Ingested != 1 {
		t.Fatalf("the other writer's pass %+v", pass)
	}
	revision, _ := world.client.ImapHints()
	world.hint(group)
	testAwaitMailGroupPass(t, world.client, world.clock)
	if listed := world.listed(group.repoId); len(listed) != 1 || listed[deposit.id] != 1 {
		t.Fatalf("the member's view lists %v at the hint, log %v", listed, world.log.snapshot())
	}
	if hinted, _ := world.client.ImapHints(); hinted != revision+1 {
		t.Errorf("IDLE's hint rose %d times for one reference", hinted-revision)
	}
	if len(group.entries(MailYearMonthOf(testMailIngestReceiveMillis))) != 1 {
		t.Error("the message was written twice")
	}
}

// A burst of hints for one group is one pass: the hints that come while the group's goroutine waits out the
// MinPassInterval gap after a pass leave one wake, so three deposits hinted together are taken by one pass, its
// depositors listed once and its deposits consumed in one CONSUME, and no pass is owed after it.
func TestMailGroupBurstOfHintsIsOnePass(t *testing.T) {
	world := newMailGroupHintTestWorld(t, "team")
	group := world.group()
	world.look()
	testAwaitMailGroupPass(t, world.client, world.clock)
	// the goroutine waits out its gap: the burst comes within it
	_, _, _, before := group.repo.watching()
	deposits := []*mailIngestTestDeposit{}
	for _, subject := range []string{"First", "Second", "Third"} {
		deposits = append(deposits, group.depositMessage(testMailIngestMessage(subject, "One of a burst")))
		world.hint(group)
	}
	world.clock.Advance(world.client.settings.Ingest.MinPassInterval)
	testAwaitMailGroupPass(t, world.client, world.clock)
	if _, _, _, after := group.repo.watching(); after-before != 1 {
		t.Errorf("the burst brought %d passes", after-before)
	}
	if len(world.inbox(group.repoId).wake) != 0 {
		t.Error("another pass is owed after the burst's")
	}
	consumes := func() []*mailIngestTestConsume {
		group.repo.stateLock.Lock()
		defer group.repo.stateLock.Unlock()
		return slices.Clone(group.repo.consumes)
	}()
	if len(consumes) != 1 || len(consumes[0].depositIds) != len(deposits) {
		t.Fatalf("the burst's deposits were consumed by %d CONSUMEs", len(consumes))
	}
	listed := world.listed(group.repoId)
	for _, deposit := range deposits {
		if listed[deposit.id] != 1 {
			t.Errorf("a deposit of the burst is listed %d times", listed[deposit.id])
		}
	}
}

// A hint that never came is caught at the component's next look, the fallback CheckInterval keeps: a deposit with no
// hint stands while the group's goroutine waits on its watch, and the look wakes the goroutine it already runs,
// whose pass ingests and lists it, with no second watch made.
func TestMailGroupMissedHintIsCaughtAtTheNextLook(t *testing.T) {
	world := newMailGroupHintTestWorld(t, "team")
	group := world.group()
	world.look()
	world.awaitPassAndGap()
	deposit := group.depositMessage(testMailIngestMessage("Missed", "Its hint never came"))
	// nothing wakes the goroutine: its pass waits for a hint or a look
	if group.repo.standingCount(group.receiverId) != 1 || len(world.listed(group.repoId)) != 0 {
		t.Fatal("a deposit whose hint never came was taken with no look")
	}
	world.look()
	testAwaitMailGroupPass(t, world.client, world.clock)
	if listed := world.listed(group.repoId); len(listed) != 1 || listed[deposit.id] != 1 {
		t.Fatalf("the member's view lists %v after the look, log %v", listed, world.log.snapshot())
	}
	if _, watchCount, watchStopCount, _ := group.repo.watching(); watchCount != 1 || watchStopCount != 0 {
		t.Errorf("the look made %d watches and stopped %d", watchCount, watchStopCount)
	}
}

// At most GroupWatchMaxCount groups hold a watch: with room for one, of two groups the first by id holds it and the
// other none, and a deposit to the other, which no hint can announce, is taken at the component's next look. The
// generation's end stops the watch and joins both goroutines.
func TestMailGroupWatchesAreBoundedAndEndWithTheGeneration(t *testing.T) {
	world := newMailGroupHintTestWorld(t, "team", "ops")
	world.client.settings.GroupWatchMaxCount = 1
	groupIds := slices.SortedFunc(slices.Values(world.groupIds), func(a Id, b Id) int { return a.Cmp(b) })
	watched, unwatched := world.groups[groupIds[0]], world.groups[groupIds[1]]
	world.look()
	testAwaitMailGroupPass(t, world.client, world.clock)
	testAwaitMailGroupPass(t, world.client, world.clock)
	if wake, watchCount, _, _ := watched.repo.watching(); wake == nil || watchCount != 1 {
		t.Fatalf("the first group holds %d watches", watchCount)
	}
	if _, watchCount, _, _ := unwatched.repo.watching(); watchCount != 0 {
		t.Fatalf("a group past GroupWatchMaxCount holds %d watches", watchCount)
	}
	world.clock.Advance(world.client.settings.Ingest.MinPassInterval)
	deposit := unwatched.depositMessage(testMailIngestMessage("Unwatched", "Taken at the look"))
	world.look()
	testAwaitMailGroupPass(t, world.client, world.clock)
	testAwaitMailGroupPass(t, world.client, world.clock)
	if listed := world.listed(unwatched.repoId); len(listed) != 1 || listed[deposit.id] != 1 {
		t.Fatalf("the member's view lists %v of the unwatched group, log %v", listed, world.log.snapshot())
	}
	inboxes := []*mailGroupInbox{world.inbox(groupIds[0]), world.inbox(groupIds[1])}
	world.client.stopRun(world.run)
	for _, inbox := range inboxes {
		if !inbox.ended() {
			t.Error("a group's goroutine outlived its generation")
		}
	}
	if wake, _, watchStopCount, _ := watched.repo.watching(); wake != nil || watchStopCount != 1 {
		t.Errorf("the generation's end stopped %d watches", watchStopCount)
	}
}
