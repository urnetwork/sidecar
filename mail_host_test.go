//go:build !sidecar_http && !js && !ios_extension

// MAIL-M8-04's receiver hosting, as owner decision 197 changes it: a daemon's SetReceiverEnabled files one mail
// designation at member scope and a retry files none, disabling retires it or keeps its other services, a designation
// it cannot read is left alone; an app is never a mail indexer and a designation is a person's act; an iOS-profile host
// takes mail in the foreground and stops listening in the background; the phone settings keep §15.5's bounds; and the
// spool holds 16 sessions' messages off the heap within §18.4's Android budget.

package sidecar

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A designator that files on the test network, as the Sidecar would, and keeps what it filed.
type testMailHostDesignator struct {
	net       *testConfigNet
	device    testConfigDevice
	stateLock sync.Mutex
	services  map[Id][]protocol.IndexerService
	filed     [][]protocol.IndexerService
	retired   int
}

func (self *testMailHostDesignator) DesignateIndexer(ctx context.Context, scope protocol.IndexerScope, services []protocol.IndexerService, appHost bool,
	configKey func(ctx context.Context) (*EvsRepoKey, error), origin SidecarActOrigin, check SidecarPresenceCheck) error {
	if origin != SidecarActConfirmed || scope != protocol.IndexerScope_INDEXER_SCOPE_MEMBER || appHost {
		return errors.New("a designation filed outside a person's act or scope")
	}
	self.net.mustPost(self.device, bridge.SignedType_SIGNED_INDEXER_SET, self.net.indexerSet(self.device, scope, false))
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.services[self.device.sidecarId] = slices.Clone(services)
	self.filed = append(self.filed, slices.Clone(services))
	return nil
}

func (self *testMailHostDesignator) RetireIndexerScope(ctx context.Context, scope protocol.IndexerScope, origin SidecarActOrigin, check SidecarPresenceCheck) error {
	self.net.mustPost(self.device, bridge.SignedType_SIGNED_INDEXER_SET, self.net.indexerSet(self.device, scope, true))
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.services, self.device.sidecarId)
	self.retired += 1
	return nil
}

// What the designator's network says each designation offers.
func (self *testMailHostDesignator) opener() MailIndexerServices {
	return func(indexer ConfigIndexer) ([]protocol.IndexerService, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		offered, ok := self.services[indexer.SidecarId]
		return slices.Clone(offered), ok
	}
}

// A client of a member's desktop on the test network, its designations filed through the designator.
func newTestMailHostClient(t *testing.T, profile MailHostProfile) (*MailClient, *testMailHostDesignator) {
	t.Helper()
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	desktop := net.device("m desktop", member)
	net.admitDevice(laptop, desktop, 0)
	settings := DefaultMailSettings()
	if profile != MailHostProfileDaemon {
		ApplyMobileMailSettings(settings, profile)
	}
	client, err := NewMailClient(&MailClientArgs{NetworkId: net.networkId, SidecarId: desktop.sidecarId, Store: newTestMemoryStore(), Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	acl, err := net.log.State().Acl()
	if err != nil {
		t.Fatal(err)
	}
	engine := NewAclEngine(desktop.sidecarId, nil, nil, nil)
	if err := engine.Install(acl, nil); err != nil {
		t.Fatal(err)
	}
	designator := &testMailHostDesignator{net: net, device: desktop, services: map[Id][]protocol.IndexerService{}}
	client.partsOverride = &mailClientTestParts{}
	client.Bind(&MailBinding{
		Engine:          engine,
		Config:          func() (*ConfigState, error) { return net.log.State(), nil },
		IndexerServices: designator.opener(),
		Designator:      designator,
	})
	t.Cleanup(client.Close)
	return client, designator
}

// Enabling files one designation for mail, a retry files none, and disabling retires it.
func TestMailHostDaemonFilesAndRetiresOneDesignation(t *testing.T) {
	client, designator := newTestMailHostClient(t, MailHostProfileDaemon)
	ctx := context.Background()
	if err := client.SetReceiverEnabled(ctx, true, SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReceiverEnabled(ctx, true, SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	if len(designator.filed) != 1 || !slices.Equal(designator.filed[0], []protocol.IndexerService{protocol.IndexerService_INDEXER_SERVICE_MAIL}) {
		t.Fatalf("filed %v", designator.filed)
	}
	if indexers := designator.net.log.State().Indexers(); len(indexers) != 1 || indexers[0].Scope != protocol.IndexerScope_INDEXER_SCOPE_MEMBER {
		t.Fatalf("the designations %+v", indexers)
	}
	if err := client.SetReceiverEnabled(ctx, false, SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	if designator.retired != 1 || len(designator.net.log.State().Indexers()) != 0 {
		t.Fatalf("retired %d, designations %+v", designator.retired, designator.net.log.State().Indexers())
	}
	// disabling with nothing filed files nothing
	if err := client.SetReceiverEnabled(ctx, false, SidecarActConfirmed, nil); err != nil || designator.retired != 1 || len(designator.filed) != 1 {
		t.Fatalf("a second disable: %v", err)
	}
}

// A designation's other services stay: mail is added beside search and taken away from it, never retiring search.
func TestMailHostKeepsADesignationsOtherServices(t *testing.T) {
	client, designator := newTestMailHostClient(t, MailHostProfileDaemon)
	ctx := context.Background()
	if err := designator.DesignateIndexer(ctx, protocol.IndexerScope_INDEXER_SCOPE_MEMBER, []protocol.IndexerService{protocol.IndexerService_INDEXER_SERVICE_SEARCH}, false, nil, SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReceiverEnabled(ctx, true, SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	if last := designator.filed[len(designator.filed)-1]; !slices.Equal(last, []protocol.IndexerService{protocol.IndexerService_INDEXER_SERVICE_MAIL, protocol.IndexerService_INDEXER_SERVICE_SEARCH}) {
		t.Fatalf("enable filed %v", last)
	}
	if err := client.SetReceiverEnabled(ctx, false, SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	if last := designator.filed[len(designator.filed)-1]; !slices.Equal(last, []protocol.IndexerService{protocol.IndexerService_INDEXER_SERVICE_SEARCH}) || designator.retired != 0 {
		t.Fatalf("disable filed %v, retired %d", last, designator.retired)
	}
}

// A designation whose services this device cannot open is left alone: nothing is filed over it.
func TestMailHostLeavesADesignationItCannotReadAlone(t *testing.T) {
	client, designator := newTestMailHostClient(t, MailHostProfileDaemon)
	ctx := context.Background()
	designator.net.mustPost(designator.device, bridge.SignedType_SIGNED_INDEXER_SET, designator.net.indexerSet(designator.device, protocol.IndexerScope_INDEXER_SCOPE_MEMBER, false))
	if err := client.SetReceiverEnabled(ctx, true, SidecarActConfirmed, nil); !errors.Is(err, ErrMailHostServicesSealed) || len(designator.filed) != 0 {
		t.Fatalf("over an unread designation: %v, filed %v", err, designator.filed)
	}
}

// No app is a mail indexer (owner decision 197), and a designation is a person's act, never MCP's or a hook's.
func TestMailHostAnAppIsNeverAnIndexer(t *testing.T) {
	for _, profile := range []MailHostProfile{MailHostProfileAndroid, MailHostProfileIos} {
		client, designator := newTestMailHostClient(t, profile)
		if err := client.SetReceiverEnabled(context.Background(), true, SidecarActConfirmed, nil); !errors.Is(err, ErrMailHostNotIndexer) || len(designator.filed) != 0 {
			t.Errorf("%s: %v", profile, err)
		}
		if profile.MayIndex() || !profile.ForegroundOnly() {
			t.Errorf("%s's profile", profile)
		}
	}
	client, designator := newTestMailHostClient(t, MailHostProfileDaemon)
	for _, origin := range []SidecarActOrigin{SidecarActMcp, SidecarActHook, SidecarActUnconfirmed} {
		if err := client.SetReceiverEnabled(context.Background(), true, origin, nil); !errors.Is(err, ErrMailHostNotConfirmed) || len(designator.filed) != 0 {
			t.Errorf("origin %d: %v", origin, err)
		}
	}
}

// An iOS-profile host takes mail in the foreground and stops listening in the background, starting again in the
// foreground; a wake only resyncs.
func TestMailHostAnIosHostTakesMailInTheForegroundOnly(t *testing.T) {
	world := newMailClientTestWorld(t)
	ApplyMobileMailSettings(world.client.settings, MailHostProfileIos)
	receivers := newMailReceiverTestWorld(t, nil)
	started := 0
	world.client.componentSeams = &mailComponentSeams{
		mayReceive: func() bool { return true },
		factory: func(args *mailReceiverFactoryArgs) (*MailReceiver, func(), error) {
			started += 1
			return receivers.newReceiver(nil), func() {}, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run := &mailComponentRun{ctx: ctx, cancel: cancel}
	world.enable()
	binding, _, err := world.client.bound()
	if err != nil {
		t.Fatal(err)
	}
	world.client.passReceive(run, binding)
	receivers.publisher.awaitCount(1)
	if status := world.client.receiverStatus; !status.Running || started != 1 {
		t.Fatalf("in the foreground %+v", status)
	}
	world.client.SetForeground(false)
	world.client.passReceive(run, binding)
	if status := world.client.receiverStatus; status.Running || run.receiver != nil || !strings.Contains(status.Problem, "only while it is open") {
		t.Fatalf("in the background %+v", status)
	}
	// a wake while no generation runs the ingestor does nothing, and never listens
	world.client.Resync()
	if run.receiver != nil {
		t.Fatal("a wake listened")
	}
	world.client.SetForeground(true)
	world.client.passReceive(run, binding)
	if status := world.client.receiverStatus; !status.Running || started != 2 {
		t.Fatalf("back in the foreground %+v, %d started", status, started)
	}
}

// The phone settings keep max_streams' 16 and the 4 check slots, take 2 deposits at once and keep the receiver on, so
// an app listens while open; a daemon's defaults are left as they were.
func TestMailHostMobileSettingsKeepTheReceiverBounds(t *testing.T) {
	for _, profile := range []MailHostProfile{MailHostProfileAndroid, MailHostProfileIos} {
		settings := DefaultMailSettings()
		ApplyMobileMailSettings(settings, profile)
		receive := settings.Receive
		if settings.Profile != profile || !receive.Enabled || receive.Receiver.MaxStreams != 16 || receive.Auth.CheckSlotMaxCount != 4 ||
			receive.Session.DepositConcurrency != 2 || !settings.valid() {
			t.Errorf("%s's settings %+v", profile, receive)
		}
	}
	daemon := DefaultMailSettings()
	if daemon.Profile != MailHostProfileDaemon || daemon.Receive.Session.DepositConcurrency != 4 || !daemon.Profile.MayIndex() {
		t.Errorf("a daemon's defaults %+v", daemon.Receive.Session)
	}
}

// A SidecarStore over a directory, so a spool's chunks sit on disk as a phone's do.
type testMailDiskStore struct {
	directory string
}

func (self *testMailDiskStore) path(name string) string {
	return filepath.Join(self.directory, filepath.FromSlash(name))
}

func (self *testMailDiskStore) Open(name string) (io.ReadCloser, error) {
	file, err := os.Open(self.path(name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrSidecarStoreAbsent
	}
	return file, err
}

func (self *testMailDiskStore) Create(name string) (SidecarStoreWriter, error) {
	target := self.path(name)
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return nil, err
	}
	file, err := os.CreateTemp(filepath.Dir(target), ".partial-*")
	if err != nil {
		return nil, err
	}
	return &testMailDiskWriter{file: file, target: target}, nil
}

func (self *testMailDiskStore) Remove(name string) error {
	if err := os.Remove(self.path(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func (self *testMailDiskStore) List(prefix string) ([]SidecarStoreEntry, error) {
	entries := []SidecarStoreEntry{}
	err := filepath.WalkDir(self.directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || strings.HasPrefix(entry.Name(), ".partial-") {
			return err
		}
		relative, err := filepath.Rel(self.directory, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(relative)
		if strings.HasPrefix(name, prefix) {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			entries = append(entries, SidecarStoreEntry{Name: name, ByteCount: info.Size()})
		}
		return nil
	})
	sort.Slice(entries, func(i int, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, err
}

func (self *testMailDiskStore) Directory(name string, class string) (SidecarStore, error) {
	return &testMailDiskStore{directory: self.path(name)}, nil
}

// A file on its way into the disk store.
type testMailDiskWriter struct {
	file      *os.File
	target    string
	committed bool
}

func (self *testMailDiskWriter) Write(data []byte) (int, error) {
	return self.file.Write(data)
}

func (self *testMailDiskWriter) Commit() error {
	if err := self.file.Close(); err != nil {
		return err
	}
	if err := os.Rename(self.file.Name(), self.target); err != nil {
		return err
	}
	self.committed = true
	return nil
}

func (self *testMailDiskWriter) Close() error {
	if !self.committed {
		self.file.Close()
		os.Remove(self.file.Name())
	}
	return nil
}

// §18.4's working set: 16 sessions' messages spooled at once, each held to its end as a session holds it while its
// deposits run, keep the heap within the Android budget, the spool keeping every byte on disk. 8 MiB a message here;
// the 50 MiB run of the plan is the review phase's (MAIL-M8-04's incomplete).
func TestMailHostSpoolHoldsSixteenSessionsWithinTheAndroidBudget(t *testing.T) {
	settings := DefaultMailSettings()
	ApplyMobileMailSettings(settings, MailHostProfileAndroid)
	sessionCount := settings.Receive.Receiver.MaxStreams
	const messageByteCount = 8 * 1024 * 1024
	const androidBudgetByteCount = 16 * 1024 * 1024
	store := &testMailDiskStore{directory: t.TempDir()}
	runtime.GC()
	before := &runtime.MemStats{}
	runtime.ReadMemStats(before)
	spools := make([]*mailSpool, sessionCount)
	var group sync.WaitGroup
	errs := make([]error, sessionCount)
	for index := range sessionCount {
		group.Go(func() {
			spool, err := newMailSpool(store, settings.Receive.Session.ChunkByteCount)
			if err != nil {
				errs[index] = err
				return
			}
			chunk := make([]byte, settings.Receive.Session.ChunkByteCount)
			for written := 0; written < messageByteCount; written += len(chunk) {
				if _, err := spool.Write(chunk); err != nil {
					errs[index] = err
					return
				}
			}
			errs[index] = spool.finish()
			spools[index] = spool
		})
	}
	group.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	runtime.GC()
	held := &runtime.MemStats{}
	runtime.ReadMemStats(held)
	growth := int64(held.HeapInuse) - int64(before.HeapInuse)
	for _, spool := range spools {
		if spool.Size() != messageByteCount {
			t.Errorf("a spool of %d bytes", spool.Size())
		}
	}
	if androidBudgetByteCount <= growth {
		t.Fatalf("16 sessions' spools grew the heap by %d bytes, past the %d budget", growth, androidBudgetByteCount)
	}
	for _, spool := range spools {
		spool.close()
	}
}
