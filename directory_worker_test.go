//go:build !sidecar_http && !ios_extension

// RECORD-M6-17's worker item on a fake writer and a fake clock: a daily renewal keeping its version; a service added
// raising it; off, the device's and the team's, withdrawing the item, and on again taking a new id; a phone, a page
// Worker and a host of no stated class refused; a service list past the 32 cap refused whole; a restart writing no
// version again; and the item folding as a worker item for another reader, its platform this build's (owner decision
// 468) as written. QD-1144's erased item, on format 2's carrier through a device's own client: announced no more until
// the device's own on, which announces a new one.

package sidecar_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"runtime"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The platform this build's worker item names, by owner decision 468's numbers for the GOOS values the legs build,
// written out apart from DirectoryPlatformOfGoos, with its name; 0, unknown, on any other GOOS.
func testWorkerPlatform() (uint32, string) {
	platforms := map[string]struct {
		number uint32
		name   string
	}{
		"darwin":  {number: 1, name: "darwin"},
		"linux":   {number: 2, name: "linux"},
		"windows": {number: 3, name: "windows"},
		"android": {number: 4, name: "android"},
		"ios":     {number: 5, name: "ios"},
		"js":      {number: 6, name: "wasm"},
	}
	platform, ok := platforms[runtime.GOOS]
	if !ok {
		return 0, "unknown"
	}
	return platform.number, platform.name
}

// What a test sidecar serves, as its components would say.
type testWorkerServices struct {
	serving *sidecar.DirectoryWorkerServing
	err     error
}

func (self *testWorkerServices) WorkerServing(ctx context.Context) (*sidecar.DirectoryWorkerServing, error) {
	return self.serving, self.err
}

// A worker item over a fake writer, clock and store: a member's desktop daemon in a team whose workers setting a test
// sets.
type testWorkerEnv struct {
	t         *testing.T
	clock     *sidecartest.FakeClock
	writer    *testRunsWriter
	files     *sidecartest.FakeStore
	sidecarId sidecar.Id
	memberId  sidecar.Id
	auth      *sidecartest.FakeDirectoryAuth
	services  *testWorkerServices
	teamOn    bool
	teamKnown bool
	host      sidecar.DirectoryWorkerHost
	worker    *sidecar.DirectoryWorker
}

func newTestWorkerEnv(t *testing.T) *testWorkerEnv {
	t.Helper()
	env := &testWorkerEnv{
		t:         t,
		clock:     sidecartest.NewFakeClock(sidecartest.DefaultClockStart()),
		writer:    &testRunsWriter{},
		files:     sidecartest.NewFakeStore(),
		sidecarId: sidecar.NewId(),
		memberId:  sidecar.NewId(),
		auth:      sidecartest.NewFakeDirectoryAuth(),
		services: &testWorkerServices{serving: &sidecar.DirectoryWorkerServing{
			Harnesses:   []string{"claude-code"},
			AgentLabels: []string{"builder"},
			Services: []*sidecar.DirectoryWorkerService{
				{Kind: sidecar.DirectoryServiceKindBridgePort, Name: "tcp:8080", Description: "a dev server"},
			},
		}},
		teamOn:    true,
		teamKnown: true,
		host:      sidecar.DirectoryWorkerHostDaemon,
	}
	directoryId := sidecar.NewId()
	memberId := env.memberId
	env.auth.Append(&sidecartest.FakeDirectoryAuthFixture{
		Sidecars:    map[sidecar.Id]*sidecartest.FakeDirectorySidecar{env.sidecarId: {MemberId: &memberId}},
		DirectoryId: &directoryId,
	})
	env.worker = env.open()
	return env
}

// A process's life of the worker item, over what the store holds now.
func (self *testWorkerEnv) open() *sidecar.DirectoryWorker {
	self.t.Helper()
	worker, err := sidecar.NewDirectoryWorker(&sidecar.DirectoryWorkerArgs{
		SidecarId:   self.sidecarId,
		Writer:      self.writer,
		Auth:        func() sidecar.DirectoryAuthView { return self.auth.Tip() },
		TeamWorkers: func() (bool, bool) { return self.teamOn, self.teamKnown },
		Host:        self.host,
		Services:    self.services,
		Identity: func() *sidecar.DirectoryWorkerIdentity {
			return &sidecar.DirectoryWorkerIdentity{HostLabel: "build-box"}
		},
		Store:  self.files.Root(),
		Clock:  self.clock,
		Random: &testRunsRandom{},
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return worker
}

// One upkeep, which must answer write.
func (self *testWorkerEnv) mustMaintain(write sidecar.DirectoryWorkerWrite) {
	self.t.Helper()
	did, err := self.worker.Maintain(self.t.Context())
	if err != nil || did != write {
		self.t.Fatalf("upkeep %s, %v; want %s", did, err, write)
	}
}

// The item is announced once at version 1 with what the sidecar serves and the platform it runs on, renews daily at
// that version with renewed and expires raised, 26 h on, and an upkeep between renewals writes nothing.
func TestDirectoryWorkerDailyRenewalKeepsItsVersion(t *testing.T) {
	env := newTestWorkerEnv(t)
	env.mustMaintain(sidecar.DirectoryWorkerAnnounced)
	platform, _ := testWorkerPlatform()
	first := env.writer.items(t)[0]
	if first.GetVersion() != 1 || first.GetKind() != uint32(sidecar.DirectoryAnnouncementKindWorker) ||
		first.GetState() != uint32(sidecar.DirectoryAnnouncementStateActive) ||
		!bytes.Equal(first.GetWho().GetMemberId(), env.memberId.Bytes()) || !bytes.Equal(first.GetWho().GetSidecarId(), env.sidecarId.Bytes()) ||
		len(first.GetWhat().GetServices()) != 1 || first.GetWhat().GetServices()[0].GetName() != "tcp:8080" ||
		first.GetWhat().GetRequests() != uint32(sidecar.DirectoryRequestsOpen) || first.GetWhere().GetHostLabel() != "build-box" ||
		first.GetWhere().GetPlatform() != platform || first.GetTainted() {
		t.Fatalf("item %v", first)
	}
	if first.GetExpiresMillis() != first.GetRenewedMillis()+sidecar.DirectoryWorkerExpiry.Milliseconds() {
		t.Fatalf("expires %d after a renewal at %d", first.GetExpiresMillis(), first.GetRenewedMillis())
	}
	env.clock.Advance(12 * time.Hour)
	env.mustMaintain(sidecar.DirectoryWorkerUnchanged)
	if items := env.writer.items(t); len(items) != 1 {
		t.Fatalf("%d items half a day on", len(items))
	}
	// the renewal's own timer writes it at the day
	env.clock.Advance(12 * time.Hour)
	items := env.writer.items(t)
	if len(items) != 2 {
		t.Fatalf("%d items a day on", len(items))
	}
	renewal := items[1]
	if renewal.GetVersion() != 1 || !bytes.Equal(renewal.GetAnnouncementId(), first.GetAnnouncementId()) ||
		renewal.GetRenewedMillis() != first.GetRenewedMillis()+(24*time.Hour).Milliseconds() ||
		renewal.GetExpiresMillis() != renewal.GetRenewedMillis()+sidecar.DirectoryWorkerExpiry.Milliseconds() ||
		renewal.GetStartedMillis() != first.GetStartedMillis() || renewal.GetWhere().GetPlatform() != platform {
		t.Fatalf("renewal %v after %v", renewal, first)
	}
	env.clock.Advance(24 * time.Hour)
	if items := env.writer.items(t); len(items) != 3 || items[2].GetVersion() != 1 {
		t.Fatalf("%d items two days on", len(items))
	}
	if sources := env.writer.sources(); sources[0] != sidecar.RecordSourceHook {
		t.Fatalf("source %v", sources)
	}
}

// A service the sidecar starts serving raises the version at the next upkeep; the same services listed in another
// order, and twice, raise nothing; a description or a requests change raises it.
func TestDirectoryWorkerServiceAddedRaisesItsVersion(t *testing.T) {
	env := newTestWorkerEnv(t)
	env.mustMaintain(sidecar.DirectoryWorkerAnnounced)
	env.services.serving.Services = append(env.services.serving.Services,
		&sidecar.DirectoryWorkerService{Kind: sidecar.DirectoryServiceKindSocket, Name: "db/primary", Description: "staging Postgres"})
	env.mustMaintain(sidecar.DirectoryWorkerAnnounced)
	items := env.writer.items(t)
	if len(items) != 2 || items[1].GetVersion() != 2 || len(items[1].GetWhat().GetServices()) != 2 ||
		!bytes.Equal(items[1].GetAnnouncementId(), items[0].GetAnnouncementId()) {
		t.Fatalf("items %v", items)
	}
	// kind then name: the socket before the bridge port, whatever order the components list them in
	if items[1].GetWhat().GetServices()[0].GetName() != "db/primary" {
		t.Fatalf("services %v", items[1].GetWhat().GetServices())
	}
	services := env.services.serving.Services
	env.services.serving.Services = []*sidecar.DirectoryWorkerService{services[1], services[0], services[1]}
	env.mustMaintain(sidecar.DirectoryWorkerUnchanged)

	description := "A build box with the staging database."
	did, err := env.worker.Set(t.Context(), &sidecar.DirectoryWorkerSetting{Description: &description, Requests: sidecar.DirectoryRequestsClosed})
	if err != nil || did != sidecar.DirectoryWorkerAnnounced {
		t.Fatalf("set %s, %v", did, err)
	}
	items = env.writer.items(t)
	if len(items) != 3 || items[2].GetVersion() != 3 || items[2].GetWhat().GetDescription() != description ||
		items[2].GetWhat().GetRequests() != uint32(sidecar.DirectoryRequestsClosed) {
		t.Fatalf("items %v", items)
	}
}

// The device's off withdraws the item at version + 1 with a withdrawal's fields alone; on again announces under a new
// id; the team's off withdraws too, and on under it keeps the setting, announces nothing and says so.
func TestDirectoryWorkerOffWithdrawsTheItem(t *testing.T) {
	env := newTestWorkerEnv(t)
	env.mustMaintain(sidecar.DirectoryWorkerAnnounced)
	off, on := false, true
	did, err := env.worker.Set(t.Context(), &sidecar.DirectoryWorkerSetting{On: &off})
	if err != nil || did != sidecar.DirectoryWorkerWithdrawn {
		t.Fatalf("off %s, %v", did, err)
	}
	items := env.writer.items(t)
	withdrawal := items[1]
	if len(items) != 2 || withdrawal.GetVersion() != 2 || withdrawal.GetState() != uint32(sidecar.DirectoryAnnouncementStateWithdrawn) ||
		!bytes.Equal(withdrawal.GetAnnouncementId(), items[0].GetAnnouncementId()) || withdrawal.GetWhat() != nil || withdrawal.GetWhere() != nil {
		t.Fatalf("withdrawal %v", withdrawal)
	}
	// off stays off: no upkeep and no timer writes it again
	env.clock.Advance(48 * time.Hour)
	env.mustMaintain(sidecar.DirectoryWorkerUnchanged)
	if items := env.writer.items(t); len(items) != 2 {
		t.Fatalf("%d items while off", len(items))
	}

	did, err = env.worker.Set(t.Context(), &sidecar.DirectoryWorkerSetting{On: &on})
	if err != nil || did != sidecar.DirectoryWorkerAnnounced {
		t.Fatalf("on %s, %v", did, err)
	}
	items = env.writer.items(t)
	if len(items) != 3 || items[2].GetVersion() != 1 || bytes.Equal(items[2].GetAnnouncementId(), items[0].GetAnnouncementId()) {
		t.Fatalf("a withdrawn id announced again: %v", items[2])
	}

	// the team's setting, not known for a while: nothing is withdrawn on a guess
	env.teamKnown = false
	env.mustMaintain(sidecar.DirectoryWorkerUnchanged)
	env.teamKnown, env.teamOn = true, false
	env.mustMaintain(sidecar.DirectoryWorkerWithdrawn)
	did, err = env.worker.Set(t.Context(), &sidecar.DirectoryWorkerSetting{On: &on})
	if !errors.Is(err, sidecar.ErrDirectoryWorkersOff) || did != sidecar.DirectoryWorkerUnchanged {
		t.Fatalf("on under the team's off: %s, %v", did, err)
	}
	if items := env.writer.items(t); len(items) != 4 {
		t.Fatalf("%d items under the team's off", len(items))
	}
	env.teamOn = true
	env.mustMaintain(sidecar.DirectoryWorkerAnnounced)
}

// A phone, a page Worker, the quick burner and a host whose class nothing stated announce nothing and refuse on.
func TestDirectoryWorkerRefusedOnAPhoneOrPageWorker(t *testing.T) {
	hosts := []sidecar.DirectoryWorkerHost{
		sidecar.DirectoryWorkerHostPhone, sidecar.DirectoryWorkerHostPageWorker, sidecar.DirectoryWorkerHostQuickBurner, 0,
	}
	for _, host := range hosts {
		env := newTestWorkerEnv(t)
		env.host = host
		env.worker = env.open()
		env.mustMaintain(sidecar.DirectoryWorkerUnchanged)
		on := true
		if _, err := env.worker.Set(t.Context(), &sidecar.DirectoryWorkerSetting{On: &on}); !errors.Is(err, sidecar.ErrDirectoryWorkerHost) {
			t.Fatalf("host %d: on answered %v", host, err)
		}
		env.clock.Advance(48 * time.Hour)
		if items := env.writer.items(t); len(items) != 0 {
			t.Fatalf("host %d wrote %d items", host, len(items))
		}
	}
}

// A sidecar serving more than 32 services is refused whole: nothing is written or kept, and the item written before
// stands at its version until the list fits again.
func TestDirectoryWorkerRefusesServicesPastTheCap(t *testing.T) {
	env := newTestWorkerEnv(t)
	env.mustMaintain(sidecar.DirectoryWorkerAnnounced)
	fitting := env.services.serving.Services
	over := []*sidecar.DirectoryWorkerService{}
	for port := 0; port < sidecar.DirectoryServiceCount+1; port += 1 {
		over = append(over, &sidecar.DirectoryWorkerService{Kind: sidecar.DirectoryServiceKindBridgePort, Name: fmt.Sprintf("tcp:%d", 9000+port)})
	}
	env.services.serving.Services = over
	if did, err := env.worker.Maintain(t.Context()); !errors.Is(err, sidecar.ErrDirectoryFormatInvalid) || did != sidecar.DirectoryWorkerUnchanged {
		t.Fatalf("33 services: %s, %v", did, err)
	}
	if items := env.writer.items(t); len(items) != 1 {
		t.Fatalf("%d items after a refusal", len(items))
	}
	env.services.serving.Services = over[:sidecar.DirectoryServiceCount]
	env.mustMaintain(sidecar.DirectoryWorkerAnnounced)
	if items := env.writer.items(t); len(items) != 2 || items[1].GetVersion() != 2 || len(items[1].GetWhat().GetServices()) != sidecar.DirectoryServiceCount {
		t.Fatalf("items %v", items)
	}
	env.services.serving.Services = fitting
	env.mustMaintain(sidecar.DirectoryWorkerAnnounced)

	// what the components cannot say is no service list: nothing is written on a guess
	env.services.err = errors.New("the sockets component is not ready")
	if _, err := env.worker.Maintain(t.Context()); err == nil {
		t.Fatal("an upkeep with no service list wrote")
	}
}

// A restart keeps the item's id, version and the device's setting: the next upkeep writes nothing until the renewal
// is due, and an off set before the restart stays off.
func TestDirectoryWorkerRestartKeepsItsItem(t *testing.T) {
	env := newTestWorkerEnv(t)
	env.mustMaintain(sidecar.DirectoryWorkerAnnounced)
	env.worker.Close()
	if _, err := env.worker.Maintain(t.Context()); !errors.Is(err, sidecar.ErrDirectoryWorkerClosed) {
		t.Fatalf("an upkeep after close answered %v", err)
	}
	env.clock.Advance(time.Hour)
	env.worker = env.open()
	env.mustMaintain(sidecar.DirectoryWorkerUnchanged)
	env.clock.Advance(23 * time.Hour)
	items := env.writer.items(t)
	if len(items) != 2 || items[1].GetVersion() != 1 || !bytes.Equal(items[1].GetAnnouncementId(), items[0].GetAnnouncementId()) {
		t.Fatalf("items after a restart: %v", items)
	}
	off := false
	if _, err := env.worker.Set(t.Context(), &sidecar.DirectoryWorkerSetting{On: &off}); err != nil {
		t.Fatal(err)
	}
	env.worker.Close()
	env.worker = env.open()
	env.clock.Advance(72 * time.Hour)
	env.mustMaintain(sidecar.DirectoryWorkerUnchanged)
	if items := env.writer.items(t); len(items) != 3 {
		t.Fatalf("%d items after an off kept across a restart", len(items))
	}
}

// A device's worker item, written through its record and its directory client, folds as an active worker item for
// another reader, under its member and naming the platform it was written with; SetWorker's off hides it at once; and
// a read_only client and a client no host bound refuse SetWorker.
func TestDirectoryWorkerItemFoldsForReaders(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	memberId := sidecar.NewId()
	writer := world.memberWriter(memberId)
	world.publish()
	device := world.device(writer)
	on := true
	if err := device.client.SetWorker(t.Context(), &sidecar.DirectoryWorkerSetting{On: &on}); !errors.Is(err, sidecar.ErrDirectoryWorkerHost) {
		t.Fatalf("SetWorker with no host bound answered %v", err)
	}
	services := &testWorkerServices{serving: &sidecar.DirectoryWorkerServing{
		Services: []*sidecar.DirectoryWorkerService{{Kind: sidecar.DirectoryServiceKindBridgePort, Name: "tcp:8080"}},
	}}
	device.client.BindWorker(&sidecar.DirectoryWorkerBinding{
		Host:        sidecar.DirectoryWorkerHostDaemon,
		Services:    services,
		TeamWorkers: func() (bool, bool) { return true, true },
	})
	if err := device.client.SetWorker(t.Context(), &sidecar.DirectoryWorkerSetting{On: &on}); err != nil {
		t.Fatal(err)
	}
	device.flush(t)
	reader := world.reader(nil)
	reader.mustSync(t)
	item := testOnlyItemOf(t, reader.items(t), writer.sidecarId)
	if item.Key.Kind != sidecar.DirectoryAnnouncementKindWorker || item.Display != sidecar.DirectoryItemActive ||
		item.MemberId == nil || *item.MemberId != memberId || len(item.Announcement.GetWhat().GetServices()) != 1 {
		t.Fatalf("item %+v", item)
	}
	platform, platformName := testWorkerPlatform()
	if shown := item.Announcement.GetWhere().GetPlatform(); shown != platform || sidecar.DirectoryPlatformName(shown) != platformName {
		t.Fatalf("the reader holds platform %d, shown as %s; written %d", shown, sidecar.DirectoryPlatformName(shown), platform)
	}
	off := false
	if err := device.client.SetWorker(t.Context(), &sidecar.DirectoryWorkerSetting{On: &off}); err != nil {
		t.Fatal(err)
	}
	device.flush(t)
	reader.mustSync(t)
	for _, item := range reader.items(t) {
		if item.SignerSidecarId == writer.sidecarId {
			t.Fatalf("a withdrawn worker item shows: %+v", item)
		}
	}

	readOnly := world.clientFor(writer.sidecarId, device.record.Writer(), true)
	if err := readOnly.client.SetWorker(t.Context(), &sidecar.DirectoryWorkerSetting{On: &on}); !errors.Is(err, sidecar.ErrDirectoryReadOnly) {
		t.Fatalf("a read_only client's SetWorker answered %v", err)
	}
}

// The worker item a directory admin erased while its daemon still announces it (QD-1144), on format 2's carrier through
// the device's own client: its daily renewal is the return, which leaves it out, so the append answers that and the
// upkeep keeps the item as erased, holding no item and writing nothing at its next upkeeps, whatever the team's
// setting does meanwhile. The device's own on announces a new item under a new id, which the card carries above the
// removal, and the erased item stays out.
func TestDirectoryWorkerModeratedItemIsAnnouncedNoMore(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	device := world.format2Device(sidecar.NewId())
	writerId := device.writer.sidecarId
	teamOn := true
	worker := device.client.BindWorker(&sidecar.DirectoryWorkerBinding{
		Host:        sidecar.DirectoryWorkerHostDaemon,
		Services:    &testWorkerServices{serving: &sidecar.DirectoryWorkerServing{Harnesses: []string{"codex"}}},
		TeamWorkers: func() (bool, bool) { return teamOn, true },
	})
	if write, err := worker.Maintain(t.Context()); err != nil || write != sidecar.DirectoryWorkerAnnounced {
		t.Fatalf("the first upkeep: %s, %v", write, err)
	}
	shown, err := worker.Shown()
	if err != nil {
		t.Fatal(err)
	}
	erasedId := shown.AnnouncementId
	world.eraseFromCard(writerId, erasedId, 1)
	device.mustSync(t)

	// the renewal's timer runs the upkeep: the return, which leaves the item out
	reads := world.counts().ErasedReads
	world.clock.Advance(sidecar.DefaultDirectoryWorkerSettings().RenewInterval)
	if world.counts().ErasedReads != reads+1 {
		t.Fatal("the renewal read no erasure set")
	}
	shown, err = worker.Shown()
	if err != nil || !shown.Moderated || !shown.On || shown.AnnouncementId != (sidecar.Id{}) || shown.Version != 0 {
		t.Fatalf("the item after the return: %+v, %v", shown, err)
	}
	reader := world.reader(nil)
	reader.mustSync(t)
	if items := testItemsOf(t, reader, writerId); len(items) != 0 {
		t.Fatalf("a reader after the return: %v", items)
	}

	writes := world.counts().CardWrites
	for _, on := range []bool{false, true} {
		teamOn = on
		if write, err := worker.Maintain(t.Context()); err != nil || write != sidecar.DirectoryWorkerUnchanged {
			t.Fatalf("an upkeep with the team's setting %t: %s, %v", on, write, err)
		}
	}
	world.clock.Advance(sidecar.DefaultDirectoryWorkerSettings().RenewInterval)
	if world.counts().CardWrites != writes {
		t.Fatal("the erased item's upkeep wrote a card")
	}

	on := true
	if err := device.client.SetWorker(t.Context(), &sidecar.DirectoryWorkerSetting{On: &on}); err != nil {
		t.Fatalf("the device's own on: %v", err)
	}
	shown, err = worker.Shown()
	if err != nil || shown.Moderated || shown.AnnouncementId == (sidecar.Id{}) || shown.AnnouncementId == erasedId {
		t.Fatalf("the item after the device's own on: %+v, %v", shown, err)
	}
	reader.mustSync(t)
	items := testItemsOf(t, reader, writerId)
	if len(items) != 1 || items[erasedId] != nil || items[shown.AnnouncementId] == nil || items[shown.AnnouncementId].Announcement.GetVersion() != 3 {
		t.Fatalf("a reader after the new item: %v", items)
	}
	worker.Close()
}

// The worker item an erasure took when a run's start is the return (QD-1144): the card leaves the item out though the
// carrier hands it, and the worker's next upkeep meets the card writer's journal before it writes, keeping the item as
// erased and writing nothing, at its next day's renewal too; a reader shows the run alone.
func TestDirectoryWorkerMeetsTheJournalAfterAnotherItemsReturn(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	device := world.format2Device(sidecar.NewId())
	writerId := device.writer.sidecarId
	worker := device.client.BindWorker(&sidecar.DirectoryWorkerBinding{
		Host:        sidecar.DirectoryWorkerHostDaemon,
		Services:    &testWorkerServices{serving: &sidecar.DirectoryWorkerServing{Harnesses: []string{"codex"}}},
		TeamWorkers: func() (bool, bool) { return true, true },
	})
	if write, err := worker.Maintain(t.Context()); err != nil || write != sidecar.DirectoryWorkerAnnounced {
		t.Fatalf("the first upkeep: %s, %v", write, err)
	}
	shown, err := worker.Shown()
	if err != nil {
		t.Fatal(err)
	}
	erasedId := shown.AnnouncementId
	world.eraseFromCard(writerId, erasedId, 1)
	device.mustSync(t)
	runId := world.startRun(device.client, "tidy the changelog")
	if shown, err := worker.Shown(); err != nil || shown.Moderated || shown.AnnouncementId != erasedId {
		t.Fatalf("the item before its upkeep: %+v, %v", shown, err)
	}

	writes := world.counts().CardWrites
	if write, err := worker.Maintain(t.Context()); err != nil || write != sidecar.DirectoryWorkerModerated {
		t.Fatalf("the upkeep after the return: %s, %v", write, err)
	}
	if shown, err := worker.Shown(); err != nil || !shown.Moderated || shown.AnnouncementId != (sidecar.Id{}) {
		t.Fatalf("the item after its upkeep: %+v, %v", shown, err)
	}
	// the run's renewals stop, so the day's only timer is the item's
	device.client.Runs().Close()
	world.clock.Advance(sidecar.DefaultDirectoryWorkerSettings().RenewInterval)
	if world.counts().CardWrites != writes {
		t.Fatal("the erased item's upkeep wrote a card")
	}
	reader := world.reader(nil)
	reader.mustSync(t)
	items := testItemsOf(t, reader, writerId)
	if len(items) != 1 || items[erasedId] != nil {
		t.Fatalf("a reader after the upkeep: %v", items)
	}
	for _, item := range items {
		if sidecar.Id(item.Announcement.GetWhat().GetRunId()) != runId || item.Announcement.GetVersion() != 3 {
			t.Fatalf("a reader after the upkeep shows %v", item.Announcement)
		}
	}
	worker.Close()
}

// The saved off setting and its outstanding withdrawal are distinct across a restart.
func TestDirectoryWorkerResumesFailedWithdrawal(t *testing.T) {
	env := newTestWorkerEnv(t)
	env.mustMaintain(sidecar.DirectoryWorkerAnnounced)
	off := false
	env.writer.appendErr = errors.New("writer unavailable")
	if _, err := env.worker.Set(t.Context(), &sidecar.DirectoryWorkerSetting{On: &off}); !errors.Is(err, env.writer.appendErr) {
		t.Fatalf("off: %v", err)
	}
	owed := env.writer.refused
	env.worker.Close()
	env.worker = env.open()
	env.clock.Advance(time.Minute)
	env.writer.appendErr = nil
	env.mustMaintain(sidecar.DirectoryWorkerWithdrawn)
	env.mustMaintain(sidecar.DirectoryWorkerUnchanged)
	if items := env.writer.items(t); len(items) != 2 || owed == nil || !proto.Equal(owed, items[1]) {
		t.Fatalf("recovered %d items, wanted the original withdrawal", len(items))
	}
}
