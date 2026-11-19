//go:build sidecar_testhooks

// The team directory on real engines (RECORD-M10-06; §16.11's ref cards and Erasure and removal blocks, §11.12's
// directory row, §11.14's directory row): the evs world (evs_world.go) with its repo a team directory at format 2, and
// on each device a whole DirectoryClient as a daemon composes one, over the directory's own evs binding
// (sidecar.DirectoryEvsCards), the record's (sidecar.RecordEvsStreams) and, through them, the erasure's
// (sidecar.DirectoryEvsErasure) and the in-ref index writer (search_evs_testhooks.go), so FS-87's and FS-99's
// format-2 cases run their cards, their index documents, their CUTs, CLOSUREs and ERASEs through evsservice's engine
// on T2's fakes and, through server's evshost, on T3's stores.
//
//	devices   each device's sidecar is its evs world device's, its identity key the one its evs pushes sign with, so
//	          a card's Signed and the push that carries it verify under one key. A device that is a directory admin
//	          is the evs world's admin: the world's exchange mints it admin, and every other device's tokens are held
//	          to rw whatever its client asks for, as §7.8's exchange mints a directory's writers (heldToWrite)
//	state     §7.9's and §8's state as the directory and the record ask it are sidecartest's fakes, appended once,
//	          each view's pin the evs world's own (dirEvsDirectoryView, dirEvsRecordView), so a push's pin is judged
//	          on the chain it was declared on; every answer is the fixtures' tip's
//	format    every device runs with §19.11's format2 gate admitting the network, so the first card or repo file a
//	          daemon writes is the push that raises the repo to format 2
//
// The world's own checks (EvsWorld.Checks) are left to the evs rows: a directory's cards ref is one shared file-mode
// ref beside the writers' streams, which the world's main-ref ledger does not follow. Each case holds its own.

package fault

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The role an evs token's repo scope names for a writer that is no admin (§7.8), and the scope's prefix.
const (
	dirEvsRoleWrite   = "rw"
	dirEvsScopePrefix = "repo:"
)

// One device of the directory on the evs world.
type DirEvsDeviceSettings struct {
	Name string
	// A directory admin, which evs mints admin.
	Admin bool
	// The member the device is of; zero draws one.
	MemberId sidecar.Id
	// The device's tokens carry what its client asks for, admin among it: the mutant of a writer that is no admin.
	MintsAsked bool
}

type DirEvsWorldSettings struct {
	// The world's devices, the first the directory's creator and an admin.
	Devices []*DirEvsDeviceSettings
	// The repos the fixtures hold beside the directory, each general, by name, with its admins' device names.
	RepoAdmins map[string][]string
}

// One device: its sidecar, key and the directory as its daemon holds it.
type DirEvsDevice struct {
	Name      string
	SidecarId sidecar.Id
	MemberId  sidecar.Id
	Record    *sidecar.SidecarRecord
	Client    *sidecar.DirectoryClient
	Cards     *sidecar.DirectoryEvsCards
	Streams   *sidecar.RecordEvsStreams

	settings *DirEvsDeviceSettings
	world    *DirEvsWorld
	device   *EvsWorldDevice
	// the device's durable state, which a restart opens again: the directory's copy and ledger, the record's chain
	// and spool, and the streams binding's journal
	store        sidecar.SidecarStore
	recordStore  sidecar.SidecarStore
	streamsStore sidecar.SidecarStore
	runner       *sidecar.DirectoryErasureRunner

	stateLock sync.Mutex
	alarms    []*sidecar.RecordAlarm
}

// RecordRunView: every run of the world's is untainted.
func (self *DirEvsDevice) RunTainted(runId sidecar.Id) bool {
	return false
}

// The alarms the device's directory raised for reason naming sidecarId.
func (self *DirEvsDevice) AlarmsNaming(reason sidecar.SidecarRecordAlarm, sidecarId sidecar.Id) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	count := 0
	for _, alarm := range self.alarms {
		if alarm.Reason == reason && alarm.SidecarId != nil && *alarm.SidecarId == sidecarId {
			count += 1
		}
	}
	return count
}

// Every alarm the device's directory raised, as text.
func (self *DirEvsDevice) Alarms() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	alarms := []string{}
	for _, alarm := range self.alarms {
		named := "no sidecar"
		if alarm.SidecarId != nil {
			named = alarm.SidecarId.String()
		}
		alarms = append(alarms, fmt.Sprintf("%s naming %s", alarm.Reason, named))
	}
	return alarms
}

// See the file header.
type DirEvsWorld struct {
	World       *EvsWorld
	DirectoryId sidecar.Id
	NetworkId   sidecar.Id

	settings         *DirEvsWorldSettings
	directoryAuth    *sidecartest.FakeDirectoryAuth
	directoryFixture *sidecartest.FakeDirectoryAuthFixture
	recordAuth       *sidecartest.FakeRecordAuth
	recordFixture    *sidecartest.FakeRecordAuthFixture
	names            []string
	devices          map[string]*DirEvsDevice
	repoIds          map[string]sidecar.Id
}

// A device's transport: a writer that is no admin carries a token of rw on the directory, whatever its client asked.
type dirEvsTransport struct {
	world  *DirEvsWorld
	device string
	lb     http.RoundTripper
}

func (self *dirEvsTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if !self.world.heldToWrite(self.device) || !strings.Contains(request.URL.Path, "/evs/") {
		return self.lb.RoundTrip(request)
	}
	token, err := self.world.World.issueToken(self.world.World.Device(self.device), []string{dirEvsScopePrefix + self.world.DirectoryId.String() + ":" + dirEvsRoleWrite})
	if err != nil {
		return nil, err
	}
	sent := request.Clone(request.Context())
	sent.Header.Set("Authorization", "Bearer "+token)
	return self.lb.RoundTrip(sent)
}

// Whether device's tokens are held to rw: every device that is no directory admin, but a mutant's.
func (self *DirEvsWorld) heldToWrite(device string) bool {
	for _, settings := range self.settings.Devices {
		if settings.Name == device {
			return !settings.Admin && !settings.MintsAsked
		}
	}
	return false
}

// A directory world on net under settings, whose first step is Setup.
func NewDirEvsWorld(net *Net, settings *DirEvsWorldSettings) *DirEvsWorld {
	self := &DirEvsWorld{
		settings: settings,
		devices:  map[string]*DirEvsDevice{},
		repoIds:  map[string]sidecar.Id{},
	}
	worldSettings := DefaultEvsWorldSettings()
	worldSettings.Kind = protocol.RepoKind_REPO_KIND_DIRECTORY
	worldSettings.Instances = []string{"evs1"}
	worldSettings.Format2 = DefaultEvsWorldFormat2Settings()
	worldSettings.InstanceFormats = map[string]uint32{"evs1": sidecar.EvsRepoFormat2}
	worldSettings.Devices = []*EvsWorldDeviceSettings{}
	for _, device := range settings.Devices {
		worldSettings.Devices = append(worldSettings.Devices, &EvsWorldDeviceSettings{
			Name: device.Name, Instances: []string{"evs1"}, Writer: true, Admin: device.Admin, Format2: true,
		})
		self.names = append(self.names, device.Name)
	}
	worldSettings.DeviceTransport = func(device string, lb http.RoundTripper) http.RoundTripper {
		return &dirEvsTransport{world: self, device: device, lb: lb}
	}
	self.World = NewEvsWorld(net, worldSettings)
	self.DirectoryId = self.World.RepoId
	self.NetworkId = self.World.NetworkId
	return self
}

// The device named name, nil before Setup.
func (self *DirEvsWorld) Device(name string) *DirEvsDevice {
	return self.devices[name]
}

// The repo the fixtures hold under name.
func (self *DirEvsWorld) Repo(name string) sidecar.Id {
	return self.repoIds[name]
}

// A record state at a pin of evs's chain: every answer its fixture's tip's, and its pin the evs devices' state's, so
// the reader judges each push's pin on the chain the push declared it on.
type dirEvsRecordView struct {
	sidecar.RecordAuthView
	pin *bridge.AuthPin
	evs sidecar.GkmAuthView
}

func (self *dirEvsRecordView) Pin() *bridge.AuthPin {
	return self.pin
}

func (self *dirEvsRecordView) At(pin *bridge.AuthPin) (sidecar.RecordAuthView, error) {
	switch {
	case self.pin.GetVersion() < pin.GetVersion():
		return nil, sidecar.ErrRecordAuthAhead
	case !self.evs.OnChain(pin):
		return nil, sidecar.ErrRecordAuthOffChain
	}
	return &dirEvsRecordView{RecordAuthView: self.RecordAuthView, pin: pin, evs: self.evs}, nil
}

func (self *dirEvsRecordView) AtPosition(version uint64) (sidecar.RecordAuthView, error) {
	if self.pin.GetVersion() < version {
		return nil, sidecar.ErrRecordAuthAhead
	}
	return &dirEvsRecordView{RecordAuthView: self.RecordAuthView, pin: &bridge.AuthPin{Version: version}, evs: self.evs}, nil
}

// A directory state at a pin of evs's chain, as dirEvsRecordView: every answer at a pin its fixture's tip's.
type dirEvsDirectoryView struct {
	sidecar.DirectoryAuthView
	pin *bridge.AuthPin
	evs sidecar.GkmAuthView
}

func (self *dirEvsDirectoryView) Pin() *bridge.AuthPin {
	return self.pin
}

func (self *dirEvsDirectoryView) At(pin *bridge.AuthPin) (sidecar.DirectoryAuthView, error) {
	switch {
	case self.pin.GetVersion() < pin.GetVersion():
		return nil, sidecar.ErrDirectoryAuthAhead
	case !self.evs.OnChain(pin):
		return nil, sidecar.ErrDirectoryAuthOffChain
	}
	return &dirEvsDirectoryView{DirectoryAuthView: self.DirectoryAuthView, pin: pin, evs: self.evs}, nil
}

func (self *dirEvsDirectoryView) SignerStanding(sidecarId sidecar.Id, pin *bridge.AuthPin) (sidecar.DirectoryStanding, error) {
	return self.DirectoryAuthView.SignerStanding(sidecarId, self.DirectoryAuthView.Pin())
}

func (self *dirEvsDirectoryView) DirectoryAdmins(pin *bridge.AuthPin) ([]sidecar.Id, error) {
	return self.DirectoryAuthView.DirectoryAdmins(self.DirectoryAuthView.Pin())
}

func (self *dirEvsDirectoryView) EligibleApprovers(request *protocol.DirectoryRequest, requesterSidecarId sidecar.Id, pin *bridge.AuthPin) (*sidecar.DirectoryApprovers, error) {
	return self.DirectoryAuthView.EligibleApprovers(request, requesterSidecarId, self.DirectoryAuthView.Pin())
}

func (self *dirEvsDirectoryView) Decides(request *protocol.DirectoryRequest, requesterSidecarId sidecar.Id, deciderSidecarId sidecar.Id, pin *bridge.AuthPin) (bool, error) {
	return self.DirectoryAuthView.Decides(request, requesterSidecarId, deciderSidecarId, self.DirectoryAuthView.Pin())
}

func (self *DirEvsWorld) recordView() sidecar.RecordAuthView {
	view := self.World.currentView()
	return &dirEvsRecordView{RecordAuthView: self.recordAuth.Tip(), pin: view.Pin(), evs: view}
}

func (self *DirEvsWorld) directoryView() sidecar.DirectoryAuthView {
	view := self.World.currentView()
	return &dirEvsDirectoryView{DirectoryAuthView: self.directoryAuth.Tip(), pin: view.Pin(), evs: view}
}

// The schedule's first step, run as the first device's actor: the evs world's Setup, the fixtures of §7.9's and §8's
// state, and every device's directory opened.
func (self *DirEvsWorld) Setup(ctx context.Context, net *Net) error {
	if len(self.settings.Devices) == 0 || !self.settings.Devices[0].Admin {
		return errors.New("the directory world's first device is its creator, a directory admin")
	}
	if err := self.World.Setup(ctx, net); err != nil {
		return err
	}
	directoryId := self.DirectoryId
	self.directoryAuth = sidecartest.NewFakeDirectoryAuth()
	self.recordAuth = sidecartest.NewFakeRecordAuth()
	self.directoryFixture = &sidecartest.FakeDirectoryAuthFixture{
		Sidecars:    map[sidecar.Id]*sidecartest.FakeDirectorySidecar{},
		Repos:       map[sidecar.Id]*sidecartest.FakeDirectoryRepo{directoryId: {Kind: protocol.RepoKind_REPO_KIND_DIRECTORY}},
		DirectoryId: &directoryId,
	}
	self.recordFixture = &sidecartest.FakeRecordAuthFixture{
		IdentityKeys: map[sidecar.Id][]byte{},
		Members:      map[sidecar.Id]sidecar.Id{},
		Repos:        map[sidecar.Id]*sidecartest.FakeRecordRepoAuth{directoryId: {}},
		Logs:         &sidecar.RecordLogIds{Team: true, DirectoryId: &directoryId},
	}
	for _, settings := range self.settings.Devices {
		evsDevice := self.World.Device(settings.Name)
		memberId := settings.MemberId
		if memberId == (sidecar.Id{}) {
			memberId = sidecar.NewId()
		}
		device := &DirEvsDevice{
			Name: settings.Name, SidecarId: evsDevice.Signer.SidecarId, MemberId: memberId,
			settings: settings, world: self, device: evsDevice,
		}
		self.devices[settings.Name] = device
		self.recordFixture.IdentityKeys[device.SidecarId] = evsDevice.Signer.PublicKey()
		self.recordFixture.Members[device.SidecarId] = memberId
		repo := self.recordFixture.Repos[directoryId]
		repo.Readers = append(repo.Readers, device.SidecarId)
		repo.Writers = append(repo.Writers, device.SidecarId)
		if settings.Admin {
			repo.Admins = append(repo.Admins, device.SidecarId)
			directory := self.directoryFixture.Repos[directoryId]
			directory.Admins = append(directory.Admins, sidecartest.FakeDirectoryRepoAdmin{SidecarId: device.SidecarId, At: 1})
		}
		self.directoryFixture.Sidecars[device.SidecarId] = &sidecartest.FakeDirectorySidecar{MemberId: &memberId}
	}
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for name := range self.settings.RepoAdmins {
			if !yield(name) {
				return
			}
		}
	}) {
		repoId := sidecar.NewId()
		self.repoIds[name] = repoId
		repo := &sidecartest.FakeDirectoryRepo{Kind: protocol.RepoKind_REPO_KIND_GENERAL}
		for _, admin := range self.settings.RepoAdmins[name] {
			device := self.devices[admin]
			if device == nil {
				return fmt.Errorf("repo %s's admin %s is no device of the world", name, admin)
			}
			repo.Admins = append(repo.Admins, sidecartest.FakeDirectoryRepoAdmin{SidecarId: device.SidecarId, At: 1})
		}
		self.directoryFixture.Repos[repoId] = repo
	}
	self.recordFixture.TimeMillis = net.Clock().Now().UnixMilli()
	self.directoryFixture.TimeMillis = self.recordFixture.TimeMillis
	self.recordAuth.Append(self.recordFixture)
	self.directoryAuth.Append(self.directoryFixture)
	for _, name := range self.names {
		if err := self.open(net, self.devices[name]); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

// Opens device's record and directory client over its evs client, as a daemon starting does: nothing of an earlier
// client's memory is kept, and the directory's copy is the device's store's.
func (self *DirEvsWorld) open(net *Net, device *DirEvsDevice) error {
	evsDevice := device.device
	if device.store == nil {
		var err error
		if device.store, err = sidecartest.NewFakeStore().Root().Directory("directory", "search"); err != nil {
			return err
		}
		if device.recordStore, err = sidecartest.NewFakeStore().Root().Directory("record", "record"); err != nil {
			return err
		}
		device.streamsStore = sidecartest.NewFakeStore().Root()
	}
	streams, err := sidecar.NewRecordEvsStreams(&sidecar.RecordEvsStreamsArgs{Client: evsDevice.Client, Store: device.streamsStore})
	if err != nil {
		return err
	}
	cards, err := sidecar.NewDirectoryEvsCards(&sidecar.DirectoryEvsCardsArgs{Client: evsDevice.Client})
	if err != nil {
		return err
	}
	recordStore := device.recordStore
	clock := net.Clock()
	record, err := sidecar.NewSidecarRecord(&sidecar.SidecarRecordArgs{
		SidecarId:         device.SidecarId,
		IdentityPublicKey: evsDevice.Signer.PublicKey(),
		Store:             recordStore,
		Sign:              evsDevice.Signer.Sign,
		Streams:           streams,
		Auth:              self.recordView,
		Clock:             clock,
		Settings:          sidecar.DefaultSidecarSettings().Record,
		Runs:              device,
	})
	if err != nil {
		return err
	}
	client, err := sidecar.NewDirectoryClient(&sidecar.DirectoryClientArgs{
		SidecarId:  device.SidecarId,
		Store:      device.store,
		Cards:      cards,
		Streams:    func() sidecar.RecordStreams { return streams },
		Auth:       self.directoryView,
		RecordAuth: self.recordView,
		Alarm: func(alarm *sidecar.RecordAlarm) {
			device.stateLock.Lock()
			defer device.stateLock.Unlock()
			device.alarms = append(device.alarms, alarm)
		},
		Clock:     clock,
		Settings:  sidecar.DefaultSidecarSettings().Directory,
		Writer:    record.Writer(),
		NetworkId: self.NetworkId,
		Sign:      evsDevice.Signer.Sign,
		Runs:      device,
	})
	if err != nil {
		return err
	}
	client.BindFormat2Gate(evsDevice.Client.Format2Admitted)
	client.BindEraser(record.Eraser().Erase)
	device.Record, device.Client, device.Cards, device.Streams = record, client, cards, streams
	device.runner = nil
	return nil
}

// A step action: device's daemon starts again after a kill, its record, directory client and runner built from its
// stores alone, over the evs client its process kept.
func (self *DirEvsWorld) Reopen(device string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		return self.open(net, self.devices[device])
	}
}

// The evs alarms device's client raised, as the evs world keeps them.
func (self *DirEvsWorld) EvsAlarms(device string) []string {
	self.World.stateLock.Lock()
	defer self.World.stateLock.Unlock()
	return slices.Clone(self.World.deviceAlarms[device])
}

// A step action: an in-ref index writer on each of devices' evs clients, as the daemon's composition installs one,
// judging a settings or erasure set version's signer by the fixtures' directory admins.
func (self *DirEvsWorld) InstallIndexWriters(devices ...string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		for _, name := range devices {
			device := self.devices[name]
			if device == nil || device.device.Client == nil {
				return fmt.Errorf("device %s is not started", name)
			}
			remove, err := sidecar.InstallSearchTestIndexWriter(device.device.Client, &sidecar.SearchTestIndexWriterArgs{
				IsAdmin: self.IsAdmin, MayMerge: func() bool { return true },
			})
			if err != nil {
				return err
			}
			context.AfterFunc(net.Context(), remove)
		}
		return nil
	}
}

// Whether signer is a directory admin in the fixtures.
func (self *DirEvsWorld) IsAdmin(signer sidecar.Id) bool {
	for _, settings := range self.settings.Devices {
		if device := self.devices[settings.Name]; device != nil && device.SidecarId == signer {
			return settings.Admin
		}
	}
	return false
}

// The cards ref's index at its head as device reads it through EvsRepo's verifying reader.
func (self *DirEvsWorld) CardsIndex(ctx context.Context, device string) (*sidecar.SearchTestEvsIndex, error) {
	return sidecar.ReadSearchTestEvsIndex(ctx, self.devices[device].device.Repo, sidecar.DirectoryCardsRefName(), self.IsAdmin)
}

// The runner's delay drawn as none: every pass works what its sync showed.
type dirEvsNoDelay struct{}

func (self dirEvsNoDelay) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// The name an announcement's index document is registered under (§16.11's fields row): a run's or a worker's under
// its writer, a repo's under its announcement alone.
func DirEvsDocumentName(writerSidecarId *sidecar.Id, announcementId sidecar.Id) []byte {
	name := "a/"
	if writerSidecarId != nil {
		name += fmt.Sprintf("%x", writerSidecarId[:])
	}
	return []byte(name + fmt.Sprintf("%x", announcementId[:]))
}

// One run a device of the world announces.
type DirEvsRun struct {
	AnnouncementId sidecar.Id
	RunId          sidecar.Id
	AgentId        sidecar.Id
	AgentLabel     string
	Title          string
}

// A run with fresh ids.
func NewDirEvsRun(agentLabel string, title string) *DirEvsRun {
	return &DirEvsRun{AnnouncementId: sidecar.NewId(), RunId: sidecar.NewId(), AgentId: sidecar.NewId(), AgentLabel: agentLabel, Title: title}
}

// Where a run's item says it works: a repo by id with its project and branch, or the repo's private marker's form,
// the id alone.
type DirEvsWhere struct {
	RepoId  *sidecar.Id
	Project string
	Branch  string
	Private bool
}

// The run's item on device's card at version, renewed now, as the device's daemon writes it.
func (self *DirEvsWorld) RunItem(net *Net, device string, run *DirEvsRun, version uint64, where *DirEvsWhere) *protocol.Announcement {
	writer := self.devices[device]
	nowMillis := net.Clock().Now().UnixMilli()
	expiresMillis, _ := sidecar.DirectoryAnnouncementExpiresMillis(sidecar.DirectoryAnnouncementKindRun, nowMillis)
	item := &protocol.Announcement{
		AnnouncementId: run.AnnouncementId.Bytes(), Kind: uint32(sidecar.DirectoryAnnouncementKindRun), Version: version,
		StartedMillis: nowMillis, RenewedMillis: nowMillis, ExpiresMillis: expiresMillis, State: uint32(sidecar.DirectoryAnnouncementStateActive),
		Who: &protocol.AnnounceWho{
			SidecarId: writer.SidecarId.Bytes(), MemberId: writer.MemberId.Bytes(), AgentId: run.AgentId.Bytes(),
			AgentLabel: run.AgentLabel, Harness: "codex",
		},
		What:  &protocol.AnnounceWhat{Title: run.Title, RunId: run.RunId.Bytes()},
		Where: &protocol.AnnounceWhere{},
	}
	if where != nil {
		if where.RepoId != nil {
			item.Where.RepoId = where.RepoId.Bytes()
		}
		if where.Private {
			item.Where.Private = true
		} else {
			item.Where.Project, item.Where.Branch = where.Project, where.Branch
		}
	}
	return item
}

// Syncs device and writes its card holding items, as a daemon's card write after a renewal does.
func (self *DirEvsWorld) WriteCard(ctx context.Context, device string, items ...*protocol.Announcement) (*sidecar.DirectoryCardWritten, error) {
	writer := self.devices[device]
	if err := writer.Client.Sync(ctx); err != nil {
		return nil, fmt.Errorf("%s's sync: %w", device, err)
	}
	written, err := writer.Client.WriteCard(ctx, &sidecar.DirectoryCardWriteArgs{Items: items})
	if err != nil {
		return nil, fmt.Errorf("%s's card: %w", device, err)
	}
	return written, nil
}

// Format 2's erasure calls as device's evs binding sends them, under the tokens evs mints device.
func (self *DirEvsWorld) Erasure(device string) (*sidecar.DirectoryEvsErasure, error) {
	return sidecar.NewDirectoryEvsErasure(&sidecar.DirectoryEvsErasureArgs{Cards: self.devices[device].Cards, IsAdmin: self.IsAdmin})
}

// One pass of device's erasure runner after its sync, the runner made at the device's first pass since it opened and
// drawing no delay.
func (self *DirEvsWorld) Pass(ctx context.Context, device string) (*sidecar.DirectoryErasurePass, error) {
	admin := self.devices[device]
	if admin.runner == nil {
		runner, err := sidecar.NewDirectoryErasureRunner(&sidecar.DirectoryErasureRunnerArgs{
			Client: admin.Client, Erase: admin.Record.Eraser().Erase, Random: dirEvsNoDelay{},
		})
		if err != nil {
			return nil, err
		}
		admin.runner = runner
	}
	if err := admin.Client.Sync(ctx); err != nil {
		return nil, fmt.Errorf("%s's sync: %w", device, err)
	}
	return admin.runner.Pass(ctx)
}

// What an erasure may not touch, as it stood when noted: each path's slot keys with their slots' ETags, the cards
// ref's head and index epoch, and how many ERASEs and cards ref CLOSUREs the repo holds.
type DirEvsNoted struct {
	Keys         map[string][]*sidecar.EvsErasedKey
	Etags        map[sidecar.Id]string
	CardsHead    uint64
	IndexEpoch   uint64
	EraseCount   int
	ClosureCount int
}

// Notes paths of the cards ref and the repo's erasure state, read as device reads them.
func (self *DirEvsWorld) Note(ctx context.Context, net *Net, device string, paths []string) (*DirEvsNoted, error) {
	erasure, err := self.Erasure(device)
	if err != nil {
		return nil, err
	}
	noted := &DirEvsNoted{Keys: map[string][]*sidecar.EvsErasedKey{}, Etags: map[sidecar.Id]string{}}
	for _, path := range paths {
		keys, err := erasure.CardKeys(ctx, self.DirectoryId, []string{path})
		if err != nil {
			return nil, fmt.Errorf("the keys of a cards ref path: %w", err)
		}
		if len(keys) == 0 {
			return nil, errors.New("a cards ref path whose versions name no slot key")
		}
		noted.Keys[path] = keys
		for _, key := range keys {
			if noted.Etags[key.SlotId], err = self.SlotEtag(ctx, net, key.SlotId); err != nil {
				return nil, err
			}
		}
	}
	if noted.CardsHead, err = self.CardsHead(ctx, device); err != nil {
		return nil, err
	}
	if noted.IndexEpoch, err = sidecar.SearchTestEvsIndexEpoch(ctx, self.devices[device].device.Repo, sidecar.DirectoryCardsRefName()); err != nil {
		return nil, err
	}
	erasures, err := self.Erasures(ctx, device)
	if err != nil {
		return nil, err
	}
	closures, err := self.CardClosures(ctx, device)
	if err != nil {
		return nil, err
	}
	noted.EraseCount, noted.ClosureCount = len(erasures), len(closures)
	return noted, nil
}

// What a refusal must leave of noted: every slot object as it was, by its ETag, each key in it, the cards ref's head
// and index epoch, and no ERASE or CLOSURE more.
func (self *DirEvsWorld) Unchanged(ctx context.Context, net *Net, device string, noted *DirEvsNoted) error {
	for slotId, etag := range noted.Etags {
		now, err := self.SlotEtag(ctx, net, slotId)
		if err != nil {
			return err
		}
		if now != etag {
			return fmt.Errorf("slot %s was rewritten", slotId)
		}
	}
	for _, keys := range noted.Keys {
		for _, key := range keys {
			if held, err := self.KeyHeld(ctx, net, key); err != nil || !held {
				return fmt.Errorf("a slot key is gone: %v", err)
			}
		}
	}
	head, err := self.CardsHead(ctx, device)
	if err != nil {
		return err
	}
	epoch, err := sidecar.SearchTestEvsIndexEpoch(ctx, self.devices[device].device.Repo, sidecar.DirectoryCardsRefName())
	if err != nil {
		return err
	}
	if head != noted.CardsHead || epoch != noted.IndexEpoch {
		return fmt.Errorf("the cards ref moved: head %d from %d, index epoch %d from %d", head, noted.CardsHead, epoch, noted.IndexEpoch)
	}
	erasures, err := self.Erasures(ctx, device)
	if err != nil {
		return err
	}
	closures, err := self.CardClosures(ctx, device)
	if err != nil {
		return err
	}
	if len(erasures) != noted.EraseCount || len(closures) != noted.ClosureCount {
		return fmt.Errorf("%d ERASEs and %d CLOSUREs, where %d and %d stood", len(erasures), len(closures), noted.EraseCount, noted.ClosureCount)
	}
	return nil
}

// How many of path's noted keys the stored slot objects still hold.
func (self *DirEvsWorld) KeysHeld(ctx context.Context, net *Net, noted *DirEvsNoted, path string) (int, error) {
	count := 0
	for _, key := range noted.Keys[path] {
		held, err := self.KeyHeld(ctx, net, key)
		if err != nil {
			return 0, err
		}
		if held {
			count += 1
		}
	}
	return count, nil
}

// The file device's copy holds at path, nil where it holds none.
func (self *DirEvsWorld) CopyFile(device string, path string) *sidecar.DirectoryCardFile {
	for _, file := range self.devices[device].Client.Cards() {
		if file.Path == path {
			return file
		}
	}
	return nil
}

// The cards ref's head as evs lists it to device.
func (self *DirEvsWorld) CardsHead(ctx context.Context, device string) (uint64, error) {
	listing, err := self.devices[device].Cards.Refs(ctx, self.DirectoryId, 0)
	if err != nil {
		return 0, err
	}
	for _, ref := range listing.Refs {
		if ref.Kind == sidecar.DirectoryRefCards {
			return ref.Version, nil
		}
	}
	return 0, nil
}

// The repo's ERASEs and the cards ref's CLOSUREs as device reads them, each verified.
func (self *DirEvsWorld) Erasures(ctx context.Context, device string) ([]*sidecar.EvsErasure, error) {
	return self.devices[device].device.Repo.ReadErasures(ctx, 0)
}

func (self *DirEvsWorld) CardClosures(ctx context.Context, device string) ([]*sidecar.EvsClosure, error) {
	return self.devices[device].device.Repo.ReadClosures(ctx, sidecar.DirectoryCardsRefName(), 0)
}

// The slot object's ETag in the store now, read under an inspecting context.
func (self *DirEvsWorld) SlotEtag(ctx context.Context, net *Net, slotId sidecar.Id) (string, error) {
	cluster, err := net.Host().Blobs.FirstCluster()
	if err != nil {
		return "", err
	}
	info, err := cluster.Head(sidecartest.InspectContext(ctx), evsservice.SlotKey(self.DirectoryId, slotId))
	if err != nil {
		return "", fmt.Errorf("slot %s: %w", slotId, err)
	}
	return info.Etag, nil
}

// Whether the stored slot object still holds key: false once an ERASE destroyed it.
func (self *DirEvsWorld) KeyHeld(ctx context.Context, net *Net, key *sidecar.EvsErasedKey) (bool, error) {
	cluster, err := net.Host().Blobs.FirstCluster()
	if err != nil {
		return false, err
	}
	object, err := cluster.Get(sidecartest.InspectContext(ctx), evsservice.SlotKey(self.DirectoryId, key.SlotId))
	if err != nil {
		return false, fmt.Errorf("slot %s: %w", key.SlotId, err)
	}
	slotBytes, err := io.ReadAll(object.Body)
	object.Body.Close()
	if err != nil {
		return false, err
	}
	slot, err := sidecar.EvsDecodeSlotObject(slotBytes)
	if err != nil {
		return false, err
	}
	_, held := sidecar.EvsSlotKeyAt(slot, uint32(key.KeyIndex))
	return held, nil
}
