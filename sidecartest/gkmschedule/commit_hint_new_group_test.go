package gkmschedule

// A commit hint naming a group a member does not hold yet (v0, owner decision 610), on T2's KeyDelivery world: a re-form
// names a new group, and the claim of its first generation hints the repo's readers on gkm:<new group> alone, which
// every member passed over, so each followed the re-form only at its next sync or resync (gkm-reader-key-upload-retry's
// finding: 43 s in e2e-gkm-concurrency's re-form case, up to the hourly resync by default). Now each member that takes
// the hint looks for the repo whose newest GroupForm names the group and follows a form that verifies at once: every
// member holds the new group's first generation with no clock moved, so within the hint's latency and not a resync's.
// A hint naming a group no verified form names changes nothing, whether no form names it or gkm serves a forged newest
// form naming it, and a look that met a list from before the form, as a gkm process's forms cache serves one, looks
// once more and follows then.

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A KeyDelivery world of a general repo at generation 2: a, its creator and admin, and b, writers, c a read_only reader
// and the agent d, each of b, c and d holding generation 2 by its delivery and its hint intake attached, whose resync
// falls a day on, so none runs within a case. With config, the network's config repo too, which a writes and every
// device holds beside the repo. gkm probes its stores once, so a case that moves the clock never finds a probe in
// flight past its timeout, which would read the stores as unreachable.
type hintedReformWorld struct {
	world      *FsKeysWorld
	reformer   *FsKeysDevice
	writer     *FsKeysDevice
	reader     *FsKeysDevice
	agent      *FsKeysDevice
	oldGroupId sidecar.Id
	hints      map[*FsKeysDevice]*sidecar.GkmHints
}

func newHintedReformWorld(t *testing.T, config bool) *hintedReformWorld {
	world := NewFsKeysWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	ctx, cancel := context.WithTimeout(world.Ctx, 30*time.Second)
	t.Cleanup(cancel)
	world.Ctx = ctx
	// one gkm instance in the first's place, KeyDelivery and probing its stores once, made only once the first has
	// probed: every instance shares the world's settings, and its probe loop reads them after each probe, so a change
	// before the first probe has ended races that read
	awaitStoreProbe(t, world)
	world.Reconfigure(func(settings *gkmservice.GkmServiceSettings) {
		settings.DraftMls = false
		settings.StoreProbeInterval = 0
	})
	awaitStoreProbe(t, world)
	if !world.Engine.Ready() {
		t.Fatal("gkm reads its stores as unreachable")
	}
	self := &hintedReformWorld{world: world, hints: map[*FsKeysDevice]*sidecar.GkmHints{}}
	self.reformer = world.AddMember("a", false)
	self.writer = world.AddMember("b", false)
	self.reader = world.AddMember("c", true)
	self.agent = world.AddAgent("d")
	world.Grant(true, self.reformer, self.writer)
	world.Grant(false, self.reader, self.agent)
	world.Creator(self.reformer)
	if config {
		world.ConfigWriters(self.reformer)
	}
	world.Advance()
	world.Publish()
	if config {
		world.CreateConfig(self.reformer)
	}
	world.Create(self.reformer)
	self.oldGroupId = world.GroupId
	if key, err := self.reformer.Client.RotateRepo(world.Ctx, world.RepoId); err != nil || key.Generation() != 2 {
		t.Fatalf("the rotation to generation 2: %v", err)
	}
	second := world.Generation(2)
	for _, device := range self.members() {
		world.Again(device.Label+"'s sync to generation 2", func() error { return device.Client.SyncRepo(world.Ctx, world.RepoId) })
		awaitHoldsGeneration(t, world, device, second)
		if config {
			world.Again(device.Label+"'s sync of the config", func() error { return device.Client.SyncRepo(world.Ctx, world.ConfigRepoId) })
			if held, _ := device.Client.RepoKeyHeld(world.ConfigRepoId); !held {
				t.Fatalf("%s holds no generation of the config", device.Label)
			}
		}
		hintsSettings := sidecar.DefaultGkmSettings()
		hintsSettings.ResyncInterval = 24 * time.Hour
		hints, err := sidecar.NewGkmHints(world.Ctx, &sidecar.GkmHintsArgs{Settings: hintsSettings, Clock: world.Clock})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(hints.Close)
		device.Client.AttachHints(world.Ctx, hints)
		self.hints[device] = hints
	}
	return self
}

// Waits until the gkm instance standing has finished a probe of its stores, after which its probe loop reads its
// settings no more until its next probe, which the world's clock holds back.
func awaitStoreProbe(t *testing.T, world *FsKeysWorld) {
	t.Helper()
	for {
		count, changed := world.Engine.Probes()
		if 0 < count {
			return
		}
		select {
		case <-changed:
		case <-world.Ctx.Done():
			t.Fatal("gkm never probed its stores")
		}
	}
}

// The members beside the re-former.
func (self *hintedReformWorld) members() []*FsKeysDevice {
	return []*FsKeysDevice{self.writer, self.reader, self.agent}
}

// The re-former's re-form of the repo's group, in full: the form, the ladder and the rotation to generation 3 in the
// new group, staged to every holder. Every hint it raised has gone out on return.
func (self *hintedReformWorld) reform(t *testing.T) (sidecar.Id, *sidecar.GkmGeneration) {
	t.Helper()
	world := self.world
	newGroupId, err := self.reformer.Client.ReformGroup(world.Ctx, &sidecar.GkmReformArgs{RepoId: world.RepoId})
	if err != nil {
		t.Fatalf("the re-form: %v", err)
	}
	if newGroupId == self.oldGroupId {
		t.Fatal("the re-form kept the group")
	}
	third := world.GenerationIn(newGroupId, 3)
	if third == nil || !bytes.Equal(third.Rotate.GetGroupId(), newGroupId.Bytes()) {
		t.Fatal("the re-form's rotation does not name the new group")
	}
	for _, device := range self.members() {
		if !world.WrapRecipientsIn(newGroupId, 3)[device.SidecarId()] {
			t.Fatalf("the re-form's rotation staged %s nothing", device.Label)
		}
	}
	if err := world.Engine.AwaitHints(world.Ctx); err != nil {
		t.Fatal(err)
	}
	return newGroupId, third
}

// Relays to device's intake the commit hint gkm sent it on gkm:<groupId>.
func (self *hintedReformWorld) relayGroupCommit(t *testing.T, device *FsKeysDevice, groupId sidecar.Id) {
	t.Helper()
	topic := sidecar.PushTopicGkmGroup(groupId)
	hint := self.world.AwaitHint(device, func(hint *FsKeysHint) bool {
		return hint.Topic == topic && hint.Hint.GetKind() == protocol.GkmHintKind_GKM_HINT_COMMIT
	})
	relayLateDeliveryHint(t, self.hints[device], hint)
}

// A commit hint on gkm:<groupId> at generation, as gkm sends one: what a forged or replayed hint looks like too.
func groupCommitHint(groupId sidecar.Id, generation uint64) *FsKeysHint {
	return &FsKeysHint{
		Topic:   sidecar.PushTopicGkmGroup(groupId),
		Version: generation,
		Hint:    &protocol.GkmHint{Kind: protocol.GkmHintKind_GKM_HINT_COMMIT, GroupId: groupId.Bytes()},
	}
}

// Waits until the newest key the device holds is generation's, which its keychain answers alone once it holds one,
// looking again each time the device takes a generation of the repo.
func awaitHoldsGeneration(t *testing.T, world *FsKeysWorld, device *FsKeysDevice, generation *sidecar.GkmGeneration) {
	t.Helper()
	for {
		_, changed := device.Client.RepoKeyHeld(world.RepoId)
		key, err := device.Client.CurrentRepoKey(world.Ctx, world.RepoId)
		if err == nil && key.Generation() == generation.Rotate.GetGeneration() && bytes.Equal(key.Commitment(), generation.Rotate.GetCommitment()) {
			return
		}
		select {
		case <-changed:
		case <-world.Ctx.Done():
			t.Fatalf("%s never held generation %d: %v", device.Label, generation.Rotate.GetGeneration(), err)
		}
	}
}

// The path of the repo's forms at gkm.
func (self *hintedReformWorld) formsPath() string {
	return "/gkm/repos/" + hex.EncodeToString(self.world.RepoId.Bytes()) + "/forms"
}

// What a device asked gkm since watchRequests: its forms reads, counted and each told on formsRead once answered, and
// every other request, listed.
type hintedReformRequests struct {
	lock       sync.Mutex
	formsReads int
	others     []string
	formsRead  chan struct{}
}

// Watches what device asks gkm from now on, each forms read answered by answer, which may change gkm's own reply and
// is told how many reads came before it; nil answer leaves gkm's reply as it is.
func (self *hintedReformWorld) watchRequests(device *FsKeysDevice, answer func(reply *protocol.GkmFormsReply, readCount int)) *hintedReformRequests {
	world := self.world
	requests := &hintedReformRequests{formsRead: make(chan struct{}, 64)}
	formsPath := self.formsPath()
	device.Transport.Respond = func(request *http.Request) *http.Response {
		if request.Method != http.MethodGet || request.URL.Path != formsPath {
			requests.lock.Lock()
			requests.others = append(requests.others, request.Method+" "+request.URL.Path)
			requests.lock.Unlock()
			return nil
		}
		recorder := httptest.NewRecorder()
		world.Engine.Handler().ServeHTTP(recorder, request)
		response := recorder.Result()
		requests.lock.Lock()
		readCount := requests.formsReads
		requests.formsReads += 1
		requests.lock.Unlock()
		if response.StatusCode == http.StatusOK && answer != nil {
			reply := &protocol.GkmFormsReply{}
			if err := proto.Unmarshal(recorder.Body.Bytes(), reply); err != nil {
				panic(err)
			}
			answer(reply, readCount)
			body, err := proto.Marshal(reply)
			if err != nil {
				panic(err)
			}
			response = &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(body)), Request: request}
		}
		requests.formsRead <- struct{}{}
		return response
	}
	return requests
}

// Waits for the next forms read device's watch answered.
func (self *hintedReformRequests) awaitFormsRead(t *testing.T, world *FsKeysWorld, label string) {
	t.Helper()
	select {
	case <-self.formsRead:
	case <-world.Ctx.Done():
		pending, _ := world.Clock.WatchTimers()
		reads, others := self.snapshot()
		t.Fatalf("no forms read %s: the clock at %s, its timers %v, %d forms reads and %v", label, world.Clock.Now(), pending, reads, others)
	}
}

// The timers pending on the world's clock at exactly at. A FakeClock's After stays pending until the clock passes it,
// so the engines a setup replaced leave their probes' waits behind, which may fall on a case's own instants.
func timersAt(world *FsKeysWorld, at time.Time) int {
	pending, _ := world.Clock.WatchTimers()
	count := 0
	for _, timer := range pending {
		if timer.Equal(at) {
			count += 1
		}
	}
	return count
}

// Waits until more timers are pending at exactly at than before: a wait set since before was counted, whatever was
// already pending there. False once the world's ctx ends first.
func awaitTimerAddedAt(world *FsKeysWorld, at time.Time, before int) bool {
	for {
		_, added := world.Clock.WatchTimers()
		if before < timersAt(world, at) {
			return true
		}
		select {
		case <-added:
		case <-world.Ctx.Done():
			return false
		}
	}
}

// The forms reads so far, and every other request.
func (self *hintedReformRequests) snapshot() (int, []string) {
	self.lock.Lock()
	defer self.lock.Unlock()
	return self.formsReads, slices.Clone(self.others)
}

// Every member takes the commit hint the re-form's rotation raised on the new group, which none of them holds: each
// looks for the repo the group was re-formed from, follows its form and takes generation 3 in the new group by its
// delivery, with no clock moved, so no resync and no late ask's follow-up brought it, and no alarm raised. Before,
// each passed the hint over, holding generation 2 of the old group until its next sync.
func TestCommitHintNamingAReformedGroupHasEveryMemberHoldItsGenerationAtOnce(t *testing.T) {
	hinted := newHintedReformWorld(t, false)
	world := hinted.world
	startedAt := world.Clock.Now()
	newGroupId, third := hinted.reform(t)
	for _, device := range hinted.members() {
		if _, held := device.Client.GenHead(newGroupId); held {
			t.Fatalf("%s held the new group before its hint", device.Label)
		}
		hinted.relayGroupCommit(t, device, newGroupId)
	}
	for _, device := range hinted.members() {
		awaitHoldsGeneration(t, world, device, third)
		head, held := device.Client.GenHead(newGroupId)
		if !held || head.GetGeneration() != 3 || !bytes.Equal(head.GetCommitment(), third.Rotate.GetCommitment()) {
			t.Errorf("%s's pin is not the new group's generation 3", device.Label)
		}
		if _, held := device.Client.GenHead(hinted.oldGroupId); held {
			t.Errorf("%s still pins the old group", device.Label)
		}
		if len(device.Alarms) != 0 {
			t.Errorf("%s raised %d alarms, the first %s: %s", device.Label, len(device.Alarms), device.Alarms[0].Kind, device.Alarms[0].Detail)
		}
	}
	if !world.Clock.Now().Equal(startedAt) {
		t.Fatalf("the clock moved %s", world.Clock.Now().Sub(startedAt))
	}
}

// A commit hint naming a group no verified form names changes nothing: one no form of the repo names, one a newest form
// gkm forges under a key no row admits names, and one a newest form the read_only reader signed names, as a lying gkm
// serves either. For each the writer reads the repo's forms, once at the hint and once a HintedGroupRecheckWait later,
// and nothing else: it syncs nothing, follows no form, raises no alarm and keeps its pin. Each next hint's recheck is
// waited for, so the look before it has ended when its effects are read; a fourth group's closes the third's.
func TestCommitHintNamingAGroupNoVerifiedFormNamesChangesNothing(t *testing.T) {
	hinted := newHintedReformWorld(t, false)
	world := hinted.world
	writer := hinted.writer
	unknownGroupId, unadmittedGroupId, refusedGroupId, closingGroupId := sidecar.NewId(), sidecar.NewId(), sidecar.NewId(), sidecar.NewId()
	forgedForm := func(groupId sidecar.Id, signer *sidecartest.FakeGkmSigner) *bridge.Signed {
		t.Helper()
		body, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.GroupForm{
			RepoId: world.RepoId.Bytes(), GroupId: groupId.Bytes(), PreviousGroupId: hinted.oldGroupId.Bytes(), Generation: 2,
			Auth: world.Log.Tip().Pin(),
		})
		if err != nil {
			t.Fatal(err)
		}
		signed, err := signer.Sign("group-form", bridge.SignedType_SIGNED_GROUP_FORM, body, nil)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	// each look's forms read meets the forms of whichever forged group's hint went last
	forgedLock := sync.Mutex{}
	var forged *bridge.Signed
	forge := func(form *bridge.Signed) {
		forgedLock.Lock()
		defer forgedLock.Unlock()
		forged = form
	}
	if err := world.Engine.AwaitHints(world.Ctx); err != nil {
		t.Fatal(err)
	}
	requests := hinted.watchRequests(writer, func(reply *protocol.GkmFormsReply, readCount int) {
		forgedLock.Lock()
		defer forgedLock.Unlock()
		if forged != nil {
			reply.Forms = append(reply.Forms, forged)
		}
	})
	recheck := sidecar.DefaultGkmSettings().HintedGroupRecheckWait
	second := world.Generation(2)
	unchanged := func(label string) {
		t.Helper()
		head, held := writer.Client.GenHead(hinted.oldGroupId)
		if !held || head.GetGeneration() != 2 || !bytes.Equal(head.GetCommitment(), second.Rotate.GetCommitment()) {
			t.Fatalf("%s: the writer's pin moved off the old group's generation 2", label)
		}
		for _, groupId := range []sidecar.Id{unknownGroupId, unadmittedGroupId, refusedGroupId, closingGroupId} {
			if _, held := writer.Client.GenHead(groupId); held {
				t.Fatalf("%s: the writer pins a group no verified form names", label)
			}
		}
		if len(writer.Alarms) != 0 {
			t.Fatalf("%s: the writer raised %d alarms, the first %s: %s", label, len(writer.Alarms), writer.Alarms[0].Kind, writer.Alarms[0].Detail)
		}
		if _, others := requests.snapshot(); len(others) != 0 {
			t.Fatalf("%s: the writer asked gkm more than the repo's forms: %v", label, others)
		}
	}
	cases := []struct {
		label   string
		groupId sidecar.Id
		form    *bridge.Signed
	}{
		{label: "no form names it", groupId: unknownGroupId},
		{label: "a form under a key no row admits names it", groupId: unadmittedGroupId, form: forgedForm(unadmittedGroupId, sidecartest.NewFakeGkmSigner())},
		{label: "a form the read_only reader signed names it", groupId: refusedGroupId, form: forgedForm(refusedGroupId, hinted.reader.Signer())},
		{label: "the closing hint's group, which no form names", groupId: closingGroupId},
	}
	for index, c := range cases {
		forge(c.form)
		recheckAt := world.Clock.Now().Add(recheck)
		pendingAtRecheck := timersAt(world, recheckAt)
		relayLateDeliveryHint(t, hinted.hints[writer], groupCommitHint(c.groupId, 3))
		requests.awaitFormsRead(t, world, "at the hint of a group "+c.label)
		// the look found no verified form and waits to look again: the look before it, and any sync it ran, has ended
		recheckSet := awaitTimerAddedAt(world, recheckAt, pendingAtRecheck)
		unchanged(c.label)
		if !recheckSet {
			t.Fatalf("%s: the look set no recheck, as one that followed a form would not", c.label)
		}
		if index == len(cases)-1 {
			break
		}
		world.Clock.Advance(recheck)
		requests.awaitFormsRead(t, world, "a recheck after the hint of a group "+c.label)
	}
	if formsReads, _ := requests.snapshot(); formsReads < 2*len(cases)-1 {
		t.Errorf("%d forms reads, want each group's look and recheck", formsReads)
	}
}

// A look that meets the repo's forms as they stood before the re-form, as a gkm process whose forms cache read them
// moments before serves them, finds no form naming the hinted group and looks once more HintedGroupRecheckWait later,
// meeting the new form then, and the writer follows it and holds generation 3. Until the recheck it follows nothing.
func TestCommitHintLookThatMetFormsFromBeforeTheReformFollowsAtItsRecheck(t *testing.T) {
	hinted := newHintedReformWorld(t, false)
	world := hinted.world
	writer := hinted.writer
	before, err := writer.Api.Forms(world.Ctx, world.RepoId)
	if err != nil {
		t.Fatal(err)
	}
	newGroupId, third := hinted.reform(t)
	requests := hinted.watchRequests(writer, func(reply *protocol.GkmFormsReply, readCount int) {
		if readCount == 0 {
			reply.Forms = before.GetForms()
		}
	})
	recheck := sidecar.DefaultGkmSettings().HintedGroupRecheckWait
	recheckAt := world.Clock.Now().Add(recheck)
	pendingAtRecheck := timersAt(world, recheckAt)
	hinted.relayGroupCommit(t, writer, newGroupId)
	requests.awaitFormsRead(t, world, "at the hint")
	if !awaitTimerAddedAt(world, recheckAt, pendingAtRecheck) {
		t.Fatal("the look that met no form naming the group set no recheck")
	}
	if _, held := writer.Client.GenHead(newGroupId); held {
		t.Fatal("the writer followed a form its look did not meet")
	}
	if _, others := requests.snapshot(); len(others) != 0 {
		t.Fatalf("the writer asked gkm more than the repo's forms before its recheck: %v", others)
	}
	world.Clock.Advance(recheck)
	awaitHoldsGeneration(t, world, writer, third)
	if head, held := writer.Client.GenHead(newGroupId); !held || head.GetGeneration() != 3 {
		t.Fatal("the writer's pin is not the new group's generation 3")
	}
	if len(writer.Alarms) != 0 {
		t.Fatalf("the writer raised %d alarms, the first %s: %s", len(writer.Alarms), writer.Alarms[0].Kind, writer.Alarms[0].Detail)
	}
	if formsReads, _ := requests.snapshot(); formsReads < 2 {
		t.Fatalf("%d forms reads, want the look and its recheck", formsReads)
	}
}

// A look stops reading forms once it has followed every group it took: with the config repo held beside the repo, a
// look for the repo's new group that meets the repo first, in the keychain's order, reads none of the config repo's
// forms, and one that meets the config repo first reads them once. The look's end barrier says it has ended, so this
// needs sidecar_testhooks.
func TestCommitHintLookReadsNoFormsPastTheLastGroupItFollows(t *testing.T) {
	if !sidecartest.HooksLinked {
		t.Skip("the look's end barrier needs sidecar_testhooks")
	}
	hinted := newHintedReformWorld(t, true)
	world := hinted.world
	writer := hinted.writer
	ended := make(chan struct{}, 16)
	remove, err := sidecartest.InstallTestHooks(nil, func(name string, key string) {
		if name == "gkm.hinted_groups.end" {
			select {
			case ended <- struct{}{}:
			default:
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	newGroupId, third := hinted.reform(t)
	requests := hinted.watchRequests(writer, nil)
	hinted.relayGroupCommit(t, writer, newGroupId)
	select {
	case <-ended:
	case <-world.Ctx.Done():
		t.Fatal("the look never ended")
	}
	awaitHoldsGeneration(t, world, writer, third)
	configFormsRead := "GET /gkm/repos/" + hex.EncodeToString(world.ConfigRepoId.Bytes()) + "/forms"
	_, others := requests.snapshot()
	configReads := 0
	for _, request := range others {
		if request == configFormsRead {
			configReads += 1
		}
	}
	// the keychain lists a repo's records under its id in hex, so the look meets the repos in their ids' order
	wantConfigReads := 0
	if bytes.Compare(world.ConfigRepoId.Bytes(), world.RepoId.Bytes()) < 0 {
		wantConfigReads = 1
	}
	if configReads != wantConfigReads {
		t.Fatalf("the look read the config repo's forms %d times, want %d", configReads, wantConfigReads)
	}
}
