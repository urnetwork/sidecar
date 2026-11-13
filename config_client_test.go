// TEAM-M2-10's ConfigClient on the test network: a full reader following the log through a reader of api's
// projection, every base's config head built from the log and compiled with a test acl compile (C-05), on a clock the
// test moves. Callbacks fire once per entry in order; a restart resumes with no lower pin; a phone keeps 64 KiB and a
// desktop the whole tail; a withheld entry alarms; a lost hint is recovered by the hourly pass; a new device starts at
// a base with a tail and reaches a long-running reader's state; the anchor refuses another genesis, a head missing a
// record and a run that does not link; and a fork alarms and stops.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A clock the test moves: each After fires once the clock passes its deadline.
type testConfigClock struct {
	stateLock sync.Mutex
	now       time.Time
	waiters   []*testConfigClockWaiter
	// one value each time a wait is armed, so a test knows a loop went idle
	armed chan time.Duration
}

type testConfigClockWaiter struct {
	at      time.Time
	channel chan time.Time
}

func newTestConfigClock() *testConfigClock {
	return &testConfigClock{now: time.UnixMilli(testConfigStartMs), armed: make(chan time.Duration, 1024)}
}

func (self *testConfigClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

func (self *testConfigClock) After(timeout time.Duration) <-chan time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	channel := make(chan time.Time, 1)
	if timeout <= 0 {
		channel <- self.now
	} else {
		self.waiters = append(self.waiters, &testConfigClockWaiter{at: self.now.Add(timeout), channel: channel})
	}
	select {
	case self.armed <- timeout:
	default:
	}
	return channel
}

func (self *testConfigClock) AfterFunc(timeout time.Duration, function func()) func() bool {
	channel := self.After(timeout)
	stopped := make(chan struct{})
	var once sync.Once
	go func() {
		select {
		case <-channel:
			function()
		case <-stopped:
		}
	}()
	return func() bool {
		stop := false
		once.Do(func() {
			close(stopped)
			stop = true
		})
		return stop
	}
}

// Moves the clock, firing every wait it passes.
func (self *testConfigClock) Advance(by time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.now = self.now.Add(by)
	waiting := []*testConfigClockWaiter{}
	for _, waiter := range self.waiters {
		if waiter.at.After(self.now) {
			waiting = append(waiting, waiter)
			continue
		}
		waiter.channel <- self.now
	}
	self.waiters = waiting
}

// A SidecarStore in memory, every leg's.
type testConfigClientStore struct {
	stateLock sync.Mutex
	files     map[string][]byte
	// how many of the next commits fail, as a full disk does
	failCommitCount int
}

func newTestConfigClientStore() *testConfigClientStore {
	return &testConfigClientStore{files: map[string][]byte{}}
}

func (self *testConfigClientStore) Open(name string) (io.ReadCloser, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	data, found := self.files[name]
	if !found {
		return nil, ErrSidecarStoreAbsent
	}
	return io.NopCloser(bytes.NewReader(bytes.Clone(data))), nil
}

func (self *testConfigClientStore) Create(name string) (SidecarStoreWriter, error) {
	return &testConfigClientStoreWriter{store: self, name: name}, nil
}

func (self *testConfigClientStore) Remove(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.files, name)
	return nil
}

func (self *testConfigClientStore) List(prefix string) ([]SidecarStoreEntry, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entries := []SidecarStoreEntry{}
	for name := range self.files {
		if strings.HasPrefix(name, prefix) {
			entries = append(entries, SidecarStoreEntry{Name: name})
		}
	}
	sort.Slice(entries, func(i int, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

func (self *testConfigClientStore) Directory(name string, class string) (SidecarStore, error) {
	return self, nil
}

// The saved document, nil for none.
func (self *testConfigClientStore) document(t testing.TB) *configClientDocument {
	t.Helper()
	self.stateLock.Lock()
	data, found := self.files[configClientFileName]
	self.stateLock.Unlock()
	if !found {
		return nil
	}
	document := &configClientDocument{}
	if err := json.Unmarshal(data, document); err != nil {
		t.Fatal(err)
	}
	return document
}

type testConfigClientStoreWriter struct {
	store  *testConfigClientStore
	name   string
	buffer bytes.Buffer
}

func (self *testConfigClientStoreWriter) Write(data []byte) (int, error) {
	return self.buffer.Write(data)
}

func (self *testConfigClientStoreWriter) Commit() error {
	self.store.stateLock.Lock()
	defer self.store.stateLock.Unlock()
	if 0 < self.store.failCommitCount {
		self.store.failCommitCount -= 1
		return errors.New("the test's store refused a commit")
	}
	self.store.files[self.name] = bytes.Clone(self.buffer.Bytes())
	return nil
}

func (self *testConfigClientStoreWriter) Close() error {
	return nil
}

// api's projection over what the test published of the net's log: a page at most, nothing below retainedFrom, as
// retention deleted it, and nothing from withheldFrom on, as a server hiding it.
type testConfigProjection struct {
	stateLock     sync.Mutex
	networkId     Id
	signedGenesis []byte
	entries       [][]byte
	rows          map[[sha256.Size]byte][]byte
	pageCount     int
	retainedFrom  uint64
	withheldFrom  uint64
	reads         int
}

func newTestConfigProjection(net *testConfigNet) *testConfigProjection {
	self := &testConfigProjection{networkId: net.networkId, signedGenesis: net.signedGenesis, pageCount: 1024, retainedFrom: 1}
	self.publish(net)
	return self
}

// Serves every entry the net sequenced so far.
func (self *testConfigProjection) publish(net *testConfigNet) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.entries = append([][]byte(nil), net.entries...)
	self.rows = map[[sha256.Size]byte][]byte{}
	for rowsSha256, rows := range net.source.rows {
		self.rows[rowsSha256] = rows
	}
}

// How many reads api answered.
func (self *testConfigProjection) readCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.reads
}

func (self *testConfigProjection) ReadConfigProjection(ctx context.Context, after uint64) (*ConfigProjection, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.reads += 1
	projection := &ConfigProjection{}
	if after == 0 {
		projection.SignedGenesis = bytes.Clone(self.signedGenesis)
	}
	for n := max(after+1, self.retainedFrom); n <= uint64(len(self.entries)); n += 1 {
		if self.withheldFrom != 0 && self.withheldFrom <= n {
			break
		}
		if self.pageCount <= len(projection.Entries) {
			projection.More = true
			break
		}
		entryBytes := self.entries[n-1]
		entry := &bridge.AuthEntry{}
		if err := proto.Unmarshal(entryBytes, entry); err != nil {
			return nil, err
		}
		projection.Entries = append(projection.Entries, bytes.Clone(entryBytes))
		chain, _ := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
		projection.Tip = &bridge.AuthPin{Version: n, Chain: chain[:]}
		if entry.GetKind() == bridge.AuthEntryKindBase {
			if _, header, err := configParseBase(entry); err == nil {
				if rows, found := self.rows[[sha256.Size]byte(header.GetRowsSha256())]; found {
					projection.Rows = append(projection.Rows, bytes.Clone(rows))
				}
			}
		}
	}
	return projection, nil
}

// Each config version's head as the net's writer saved it: the genesis, the head's ServiceSettings signed by the
// owner's device, and a fold for each base that advanced folded_through, its records the log's, bases included.
type testConfigHeadReader struct {
	stateLock sync.Mutex
	net       *testConfigNet
	entries   [][]byte
	settings  map[[sha256.Size]byte]*protocol.ServiceSettings
	// a head to answer for every version instead, as a forger's
	forged *ConfigHead
}

func newTestConfigHeadReader(net *testConfigNet) *testConfigHeadReader {
	self := &testConfigHeadReader{net: net}
	self.publish(net)
	return self
}

func (self *testConfigHeadReader) publish(net *testConfigNet) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.entries = append([][]byte(nil), net.entries...)
	self.settings = map[[sha256.Size]byte]*protocol.ServiceSettings{}
	for headSha256, settings := range net.source.settings {
		self.settings[headSha256] = settings
	}
}

func (self *testConfigHeadReader) ReadConfigHead(ctx context.Context, configVersion uint64, configHeadSha256 []byte) (*ConfigHead, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.forged != nil {
		return self.forged, nil
	}
	foldPoints := []uint64{}
	found := false
	for _, entryBytes := range self.entries {
		entry := &bridge.AuthEntry{}
		if err := proto.Unmarshal(entryBytes, entry); err != nil {
			return nil, err
		}
		if entry.GetKind() != bridge.AuthEntryKindBase {
			continue
		}
		_, header, err := configParseBase(entry)
		if err != nil {
			return nil, err
		}
		if foldedThrough := header.GetFoldedThrough(); 0 < foldedThrough && (len(foldPoints) == 0 || foldPoints[len(foldPoints)-1] < foldedThrough) {
			foldPoints = append(foldPoints, foldedThrough)
		}
		if header.GetConfigVersion() == configVersion {
			found = true
			break
		}
	}
	if !found {
		return nil, ErrConfigHeadUnavailable
	}
	files := map[string][]byte{ConfigHeadGenesisPath: self.net.signedGenesis}
	if settings := self.settings[[sha256.Size]byte(configHeadSha256)]; settings != nil {
		files[ConfigHeadServiceSettingsPath] = self.net.sign(self.net.owner, bridge.SignedType_SIGNED_SERVICE_SETTINGS, settings)
	}
	head, err := NewConfigHead(files)
	if err != nil {
		return nil, err
	}
	after := uint64(0)
	for _, point := range foldPoints {
		records := []ConfigFoldRecord{}
		for n := after + 1; n <= point; n += 1 {
			records = append(records, testConfigRecordAt(self.entries, n))
		}
		if head, err = head.WithFold(records, point); err != nil {
			return nil, err
		}
		after = point
	}
	return head, nil
}

// The record a head holds for the entry at n.
func testConfigRecordAt(entries [][]byte, n uint64) ConfigFoldRecord {
	entry := &bridge.AuthEntry{}
	_ = proto.Unmarshal(entries[n-1], entry)
	record := ConfigFoldRecord{N: n, TimeMs: entry.GetTimeMs(), Kind: entry.GetKind(), Body: bytes.Clone(entry.GetBody())}
	switch entry.GetKind() {
	case bridge.AuthEntryKindStatement:
		_, id := configEntryStatementId(entry)
		record.Id = id[:]
	case bridge.AuthEntryKindBase:
		if signed, _, err := configParseBase(entry); err == nil {
			id := bridge.SignedBytesSha256(bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_PROJECTION_HEADER, signed.GetBody())
			record.Id = id[:]
		}
	}
	return record
}

// A GkmClient that counts AuthAdvanced and refuses the rest.
type testConfigGkm struct {
	gkmRefusingClient
	stateLock sync.Mutex
	positions []uint64
}

func (self *testConfigGkm) AuthAdvanced(state GkmAuthView) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.positions = append(self.positions, state.Pin().GetVersion())
}

// The world a client test runs in: the net, api's projection and the heads, a store, the clock and what was raised.
type testConfigClientWorld struct {
	t          *testing.T
	net        *testConfigNet
	projection *testConfigProjection
	heads      *testConfigHeadReader
	store      *testConfigClientStore
	clock      *testConfigClock
	gkm        *testConfigGkm

	stateLock sync.Mutex
	events    []SidecarEvent
	forks     []HeadFork
}

func newTestConfigClientWorld(t *testing.T) *testConfigClientWorld {
	registerTestConfigAclCompiler(t)
	net := newTestConfigNet(t)
	return &testConfigClientWorld{
		t:          t,
		net:        net,
		projection: newTestConfigProjection(net),
		heads:      newTestConfigHeadReader(net),
		store:      newTestConfigClientStore(),
		clock:      newTestConfigClock(),
		gkm:        &testConfigGkm{},
	}
}

// Serves what the net sequenced since the last publish.
func (self *testConfigClientWorld) publish() {
	self.projection.publish(self.net)
	self.heads.publish(self.net)
}

// A client on the world, closed at the test's end.
func (self *testConfigClientWorld) client(settings *ConfigClientSettings) *ConfigClient {
	self.t.Helper()
	if settings == nil {
		settings = DefaultConfigClientSettings()
	}
	settings.LogSettings = testConfigLogSettings()
	settings.Log = NewNoopLogger()
	client, err := NewConfigClient(context.Background(), &ConfigClientArgs{
		NetworkId:    self.net.networkId,
		GenesisChain: bridge.GenesisChain(self.net.signedGenesis),
		Projection:   self.projection,
		Heads:        self.heads,
		Store:        self.store,
		Gkm:          self.gkm,
		Emit: func(event SidecarEvent) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.events = append(self.events, event)
		},
		ReportFork: func(fork HeadFork) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.forks = append(self.forks, fork)
		},
		Clock:    self.clock,
		Settings: settings,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(client.Close)
	return client
}

// Waits for the client to reach the net's tip.
func (self *testConfigClientWorld) caughtUp(client *ConfigClient) *ConfigState {
	self.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	state, err := client.WaitFor(ctx, self.net.n)
	if err != nil {
		self.t.Fatalf("waiting for %d: %v", self.net.n, err)
	}
	return state
}

// The head alarms raised so far, by kind.
func (self *testConfigClientWorld) headAlarms(kind SidecarHeadAlarm) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	count := 0
	for _, event := range self.events {
		if event.Kind == SidecarEventHeadAlarm && event.HeadAlarm == kind {
			count += 1
		}
	}
	return count
}

// A client follows the log as a full reader, every base's head checked, and reaches the net's state; each entry after
// it subscribed reaches its callback once, in order, after which KEYS's AuthAdvanced has seen it.
func TestConfigClientFollowsAndCallsBackInOrder(t *testing.T) {
	world := newTestConfigClientWorld(t)
	net := world.net
	member, first := net.consentedMember("m")
	net.fold(net.owner, net.n, 2)
	world.publish()
	client := world.client(nil)
	testConfigStatesEqual(t, world.caughtUp(client), net.log.State())

	seen := []uint64{}
	var seenLock sync.Mutex
	remove := client.AddEntryCallback(func(entry *SidecarAuthorityEntry) {
		seenLock.Lock()
		defer seenLock.Unlock()
		seen = append(seen, entry.Pin.GetVersion())
	})
	second := net.device("m second", member)
	net.admitDevice(first, second, 0)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("another"))
	net.fold(net.owner, net.n, 3)
	world.publish()
	client.ReceiveNotice(PushNotice{Topic: PushTopicTeam, Version: net.n})
	state := world.caughtUp(client)
	testConfigStatesEqual(t, state, net.log.State())
	seenLock.Lock()
	if len(seen) != 3 || seen[0] != net.n-2 || seen[1] != net.n-1 || seen[2] != net.n {
		t.Errorf("callbacks saw %v", seen)
	}
	seenLock.Unlock()
	remove()
	world.gkm.stateLock.Lock()
	if positions := world.gkm.positions; len(positions) == 0 || positions[len(positions)-1] != net.n {
		t.Errorf("AuthAdvanced saw %v", positions)
	}
	world.gkm.stateLock.Unlock()
	if row := state.SidecarRow(second.sidecarId); row == nil {
		t.Error("the second device is not admitted at the client")
	}
}

// The entries authlog/ holds now, by position, and the pin it holds.
func (self *testConfigClientStore) keptEntries(t testing.TB) (map[uint64]bool, uint64) {
	t.Helper()
	kept := map[uint64]bool{}
	document := self.document(t)
	if document == nil {
		return kept, 0
	}
	for _, entryBytes := range document.Entries {
		entry := &bridge.AuthEntry{}
		if err := proto.Unmarshal(entryBytes, entry); err != nil {
			t.Fatal(err)
		}
		kept[entry.GetN()] = true
	}
	pin := uint64(0)
	if document.Pin != nil {
		pin = document.Pin.N
	}
	return kept, pin
}

// DESIGN-DETAILS 12.2.5's rule, which the bridge's start gate replays from (QD-669): an entry is in the client's
// store before any entry callback runs. A callback that reads authlog/ finds its own entry there and the store's pin
// at or past it, for each entry of a page of several, on a phone's store and a desktop's.
func TestEntriesAreStoredBeforeTheirCallbacks(t *testing.T) {
	for _, retainFullTail := range []bool{false, true} {
		world := newTestConfigClientWorld(t)
		net := world.net
		net.admitMember(net.owner, testConfigId("a"), bridge.MemberRole_MEMBER_ROLE_MEMBER)
		world.publish()
		settings := DefaultConfigClientSettings()
		settings.RetainFullTail = retainFullTail
		client := world.client(settings)
		world.caughtUp(client)
		subscribedAt := net.n

		type seenEntry struct {
			n    uint64
			kept bool
			pin  uint64
		}
		seen := []*seenEntry{}
		var seenLock sync.Mutex
		remove := client.AddEntryCallback(func(entry *SidecarAuthorityEntry) {
			kept, pin := world.store.keptEntries(t)
			seenLock.Lock()
			defer seenLock.Unlock()
			seen = append(seen, &seenEntry{n: entry.Pin.GetVersion(), kept: kept[entry.Pin.GetVersion()], pin: pin})
		})
		for _, label := range []string{"b", "c", "d"} {
			net.admitMember(net.owner, testConfigId(label), bridge.MemberRole_MEMBER_ROLE_MEMBER)
		}
		world.publish()
		client.ReceiveNotice(PushNotice{Topic: PushTopicTeam, Version: net.n})
		world.caughtUp(client)
		remove()

		seenLock.Lock()
		if uint64(len(seen)) != net.n-subscribedAt {
			t.Errorf("full tail %t: %d callbacks for %d entries", retainFullTail, len(seen), net.n-subscribedAt)
		}
		for i, entry := range seen {
			if entry.n != subscribedAt+1+uint64(i) {
				t.Errorf("full tail %t: callback %d saw entry %d", retainFullTail, i, entry.n)
			}
			if !entry.kept || entry.pin < entry.n {
				t.Errorf("full tail %t: entry %d's callback ran with the store at pin %d, the entry kept: %t", retainFullTail, entry.n, entry.pin, entry.kept)
			}
		}
		seenLock.Unlock()
		client.Close()
	}
}

// A write to authlog/ that fails holds no callback back, so the running judge hears of every entry, and the follow
// answers the store's error; the next follow writes the log again, with nothing new to apply, and answers nil.
func TestConfigClientKeepsTheLogAgainAfterAFailedWrite(t *testing.T) {
	world := newTestConfigClientWorld(t)
	net := world.net
	net.admitMember(net.owner, testConfigId("a"), bridge.MemberRole_MEMBER_ROLE_MEMBER)
	world.publish()
	client := world.client(nil)
	world.caughtUp(client)
	if _, pin := world.store.keptEntries(t); pin != net.n {
		t.Fatalf("the store holds pin %d, not %d", pin, net.n)
	}
	keptAt := net.n

	seen := []uint64{}
	var seenLock sync.Mutex
	remove := client.AddEntryCallback(func(entry *SidecarAuthorityEntry) {
		seenLock.Lock()
		defer seenLock.Unlock()
		seen = append(seen, entry.Pin.GetVersion())
	})
	defer remove()
	net.admitMember(net.owner, testConfigId("b"), bridge.MemberRole_MEMBER_ROLE_MEMBER)
	world.publish()
	world.store.stateLock.Lock()
	world.store.failCommitCount = 1
	world.store.stateLock.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := client.CatchUp(ctx); err == nil {
		t.Error("a follow whose store write failed answered no error")
	}
	if got := client.Pin().GetVersion(); got != net.n {
		t.Fatalf("the log stands at %d, not %d", got, net.n)
	}
	seenLock.Lock()
	if len(seen) != int(net.n-keptAt) || seen[len(seen)-1] != net.n {
		t.Errorf("callbacks saw %v", seen)
	}
	seenLock.Unlock()
	if _, pin := world.store.keptEntries(t); pin != keptAt {
		t.Fatalf("the store holds pin %d after a failed write, not %d", pin, keptAt)
	}

	if err := client.CatchUp(ctx); err != nil {
		t.Fatalf("the next follow: %v", err)
	}
	if kept, pin := world.store.keptEntries(t); pin != net.n || !kept[net.n] {
		t.Errorf("the store holds pin %d, entry %d kept: %t", pin, net.n, kept[net.n])
	}
	seenLock.Lock()
	if len(seen) != int(net.n-keptAt) {
		t.Errorf("a write again called back again: %v", seen)
	}
	seenLock.Unlock()
}

// A restart from authlog/ resumes at the same pin with no read, on a desktop that keeps the whole tail; on a phone it
// reads from api, and a run ending below the pin it kept is refused, no state installed.
func TestConfigClientRestartResumesWithNoLowerPin(t *testing.T) {
	world := newTestConfigClientWorld(t)
	net := world.net
	for _, label := range []string{"a", "b", "c"} {
		net.admitMember(net.owner, testConfigId(label), bridge.MemberRole_MEMBER_ROLE_MEMBER)
	}
	net.fold(net.owner, net.n, 2)
	net.admitMember(net.owner, testConfigId("d"), bridge.MemberRole_MEMBER_ROLE_MEMBER)
	world.publish()

	desktop := DefaultConfigClientSettings()
	desktop.RetainFullTail = true
	client := world.client(desktop)
	pin := world.caughtUp(client).Pin()
	client.Close()

	reads := world.projection.readCount()
	world.projection.stateLock.Lock()
	world.projection.withheldFrom = net.n
	world.projection.stateLock.Unlock()
	restarted := world.client(desktop)
	if got := restarted.Pin(); !proto.Equal(got, pin) {
		t.Fatalf("the restart stands at %v, not %v", got, pin)
	}
	if world.projection.readCount() != reads {
		// the follow at start reads, and must not lower the pin
		if got := world.caughtUp(restarted).Pin(); !proto.Equal(got, pin) {
			t.Errorf("after api served less: %v", got)
		}
	}
	restarted.Close()

	// a phone keeps its pin and 64 KiB: a restart reads from api, refusing a run that ends below the pin
	phone := world.client(nil)
	if phone.Pin() != nil && phone.Pin().GetVersion() < pin.GetVersion() {
		t.Fatalf("a phone restarted below its pin: %v", phone.Pin())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := phone.CatchUp(ctx); err == nil && phone.Pin() != nil && phone.Pin().GetVersion() < pin.GetVersion() {
		t.Errorf("the phone landed below its pin: %v", phone.Pin())
	}
}

// §7.9's retain row: a phone keeps its newest entries up to 64 KiB, a desktop every entry from the retention point and
// its bases' rows.
func TestConfigClientRetentionBounds(t *testing.T) {
	world := newTestConfigClientWorld(t)
	net := world.net
	for i := range 320 {
		net.admitMember(net.owner, testConfigId("member "+string(rune('a'+i%26))+string(rune('a'+i/26))), bridge.MemberRole_MEMBER_ROLE_MEMBER)
	}
	world.publish()

	phoneStore := world.store
	phone := world.client(nil)
	world.caughtUp(phone)
	phone.Close()
	document := phoneStore.document(t)
	byteCount := 0
	for _, entry := range document.Entries {
		byteCount += len(entry)
	}
	if 64*1024 < byteCount || len(document.Entries) == 0 || len(document.Entries) == int(net.n) || len(document.Rows) != 0 {
		t.Errorf("a phone kept %d entries, %d bytes, %d rows", len(document.Entries), byteCount, len(document.Rows))
	}
	if document.Pin == nil || document.Pin.N != net.n {
		t.Errorf("a phone kept pin %v", document.Pin)
	}

	world.store = newTestConfigClientStore()
	desktopSettings := DefaultConfigClientSettings()
	desktopSettings.RetainFullTail = true
	desktop := world.client(desktopSettings)
	world.caughtUp(desktop)
	desktop.Close()
	document = world.store.document(t)
	if len(document.Entries) != int(net.n) || len(document.Rows) != 1 {
		t.Errorf("a desktop kept %d entries of %d and %d rows", len(document.Entries), net.n, len(document.Rows))
	}
}

// A hint naming a position api withholds: the client treats itself as withheld, alarms once, and clears once api
// serves it.
func TestConfigClientTreatsAWithheldEntryAsWithheld(t *testing.T) {
	world := newTestConfigClientWorld(t)
	net := world.net
	client := world.client(nil)
	world.caughtUp(client)
	net.admitMember(net.owner, testConfigId("a"), bridge.MemberRole_MEMBER_ROLE_MEMBER)
	net.admitMember(net.owner, testConfigId("b"), bridge.MemberRole_MEMBER_ROLE_MEMBER)
	world.publish()
	world.projection.stateLock.Lock()
	world.projection.withheldFrom = net.n
	world.projection.stateLock.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client.ReceiveNotice(PushNotice{Topic: PushTopicTeam, Version: net.n})
	if err := client.CatchUp(ctx); err != nil {
		t.Fatal(err)
	}
	if client.WithheldSince().IsZero() || world.headAlarms(SidecarHeadAlarmWithheld) != 1 {
		t.Fatalf("withheld since %v, %d alarms", client.WithheldSince(), world.headAlarms(SidecarHeadAlarmWithheld))
	}
	world.projection.stateLock.Lock()
	world.projection.withheldFrom = 0
	world.projection.stateLock.Unlock()
	if err := client.CatchUp(ctx); err != nil {
		t.Fatal(err)
	}
	if !client.WithheldSince().IsZero() || client.Pin().GetVersion() != net.n {
		t.Errorf("still withheld at %d", client.Pin().GetVersion())
	}
}

// A lost team hint: the hourly pass reads what api holds.
func TestConfigClientRecoversALostHintHourly(t *testing.T) {
	world := newTestConfigClientWorld(t)
	net := world.net
	client := world.client(nil)
	world.caughtUp(client)
	// the follower armed its hourly wait
	for timeout := range world.clock.armed {
		if timeout == time.Hour {
			break
		}
	}
	net.admitMember(net.owner, testConfigId("unhinted"), bridge.MemberRole_MEMBER_ROLE_MEMBER)
	world.publish()
	if client.Pin().GetVersion() == net.n {
		t.Fatal("the client moved with no hint and no pass")
	}
	world.clock.Advance(time.Hour)
	testConfigStatesEqual(t, world.caughtUp(client), net.log.State())
}

// DESIGN-DETAILS 5.7: a new device starting where api retains from, at a base with a tail, takes its verdicts and
// reaches the long-running reader's state, and goes on as a reader; its anchor refuses another genesis, a head missing
// a record, and a head another network wrote.
func TestConfigClientStartsAtABaseWithATail(t *testing.T) {
	world := newTestConfigClientWorld(t)
	net := world.net
	member, first := net.consentedMember("m")
	net.fold(net.owner, net.n, 2)
	foldPoint := net.n
	second := net.device("m second", member)
	net.admitDevice(first, second, 0)
	net.post(second, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("refused"))
	net.fold(net.owner, foldPoint, 3)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("after"))
	world.publish()
	world.projection.stateLock.Lock()
	world.projection.retainedFrom = net.log.State().RetentionPoint()
	world.projection.stateLock.Unlock()
	if world.projection.retainedFrom <= 1 {
		t.Fatalf("api retains from %d", world.projection.retainedFrom)
	}

	client := world.client(nil)
	state := world.caughtUp(client)
	testConfigStatesEqual(t, state, net.log.State())
	if state.SidecarRow(second.sidecarId) == nil {
		t.Error("the tail's admission did not re-apply")
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("on the new device"))
	world.publish()
	client.ReceiveNotice(PushNotice{Topic: PushTopicTeam, Version: net.n})
	testConfigStatesEqual(t, world.caughtUp(client), net.log.State())

	// a head missing a record its anchor holds forks the start
	world.store = newTestConfigClientStore()
	head, err := world.heads.ReadConfigHead(context.Background(), 3, testConfigHeadSha256(3))
	if err != nil {
		t.Fatal(err)
	}
	records, err := head.RecordsIn(0, head.FoldedThrough())
	if err != nil {
		t.Fatal(err)
	}
	short := testConfigHead(t, net, testConfigFoldRecords(records[:len(records)-1]))
	world.heads.stateLock.Lock()
	world.heads.forged = short
	world.heads.stateLock.Unlock()
	refused := world.client(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := refused.CatchUp(ctx); !errors.Is(err, ErrConfigFork) {
		t.Errorf("a head missing a record: %v", err)
	}
	if refused.State() != nil {
		t.Error("a refused start installed a state")
	}

	// another genesis than the one this device trusts
	world.heads.stateLock.Lock()
	world.heads.forged = nil
	world.heads.stateLock.Unlock()
	other, err := NewConfigClient(context.Background(), &ConfigClientArgs{
		NetworkId:    net.networkId,
		GenesisChain: sha256.Sum256([]byte("another genesis")),
		Projection:   world.projection,
		Heads:        world.heads,
		Clock:        world.clock,
		Settings:     &ConfigClientSettings{FollowInterval: time.Hour, FollowTimeout: time.Minute, RetryInterval: time.Hour, MaxPagesPerFollow: 4, Log: NewNoopLogger()},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := other.CatchUp(ctx); !errors.Is(err, ErrConfigClientGenesis) {
		t.Errorf("another genesis: %v", err)
	}
}

// Records as a fold takes them.
func testConfigFoldRecords(records []*protocol.ConfigRecord) []ConfigFoldRecord {
	folded := []ConfigFoldRecord{}
	for _, record := range records {
		folded = append(folded, ConfigFoldRecord{Id: record.GetId(), N: record.GetN(), TimeMs: record.GetTimeMs(), Kind: record.GetKind(), Body: record.GetBody()})
	}
	return folded
}

// A second entry at a position the client holds forks it: head_alarm with both pins, the fork reported for
// HeadStopState, and WaitFor answering the fork.
func TestConfigClientForkAlarmsAndStops(t *testing.T) {
	world := newTestConfigClientWorld(t)
	net := world.net
	net.admitMember(net.owner, testConfigId("a"), bridge.MemberRole_MEMBER_ROLE_MEMBER)
	world.publish()
	client := world.client(nil)
	world.caughtUp(client)

	// another history from the same position: api serves a different entry 2
	forked := newTestConfigNet(t)
	forked.admitMember(forked.owner, testConfigId("other"), bridge.MemberRole_MEMBER_ROLE_MEMBER)
	forked.admitMember(forked.owner, testConfigId("next"), bridge.MemberRole_MEMBER_ROLE_MEMBER)
	world.projection.publish(forked)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client.ReceiveNotice(PushNotice{Topic: PushTopicTeam, Version: forked.n})
	err := client.CatchUp(ctx)
	if !errors.Is(err, ErrConfigRunRefused) && !errors.Is(err, ErrConfigFork) {
		t.Fatalf("a second history: %v", err)
	}
	if world.headAlarms(SidecarHeadAlarmFork) == 0 {
		t.Error("no head_alarm for the fork")
	}
	if client.Pin().GetVersion() != 2 {
		t.Errorf("the client moved to %d on another history", client.Pin().GetVersion())
	}
}

// The authority over a client answers from its verified state: admissions, a member's devices, consent, an open
// proposal, the settings, and the first retained entry at or after a loss time.
func TestConfigAuthorityAnswersFromTheState(t *testing.T) {
	world := newTestConfigClientWorld(t)
	team := &testConfigTeam{testConfigNet: world.net}
	net := world.net
	memberB, memberC := testConfigId("admin b"), testConfigId("admin c")
	net.admitMember(net.owner, memberB, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	net.admitMember(net.owner, memberC, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	team.adminB = net.device("admin b laptop", memberB)
	team.adminC = net.device("admin c laptop", memberC)
	net.admitDevice(net.owner, team.adminB, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
	net.admitDevice(net.owner, team.adminC, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
	lostAt := time.UnixMilli(net.timeMs + 1)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_ADMIN_SET, team.adminSet(0))
	phone := net.device("owner phone", net.ownerMemberId)
	_, proposalId := net.propose(net.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(phone, nil, false, 0, 0))
	world.publish()
	client := world.client(nil)
	world.caughtUp(client)
	authority := client.Authority()

	if admission := authority.Admission(team.adminB.sidecarId); admission == nil || admission.MemberId != memberB {
		t.Errorf("admin b's admission: %+v", admission)
	}
	if authority.Admission(phone.sidecarId) != nil {
		t.Error("the proposed phone is admitted")
	}
	if devices := authority.MemberDevices(net.ownerMemberId); len(devices) != 1 || devices[0].Row.GetSidecarId() == nil {
		t.Errorf("the owner's devices: %d", len(devices))
	}
	if !authority.Consented(team.adminB.sidecarId, memberB) || authority.Consented(team.adminB.sidecarId, memberC) {
		t.Error("consent")
	}
	if row := authority.PendingProposal(proposalId); row == nil || row.GetProposedAt() != net.n {
		t.Errorf("the open proposal: %v", row)
	}
	if authority.PendingProposal(make([]byte, sha256.Size)) != nil {
		t.Error("an unknown proposal")
	}
	if settings := authority.Settings(); settings.GetSelfAdmit() != 0 {
		t.Errorf("settings %v", settings)
	}
	if n, at, ok := authority.ProposedSince(lostAt); !ok || n != net.n-1 || at.UnixMilli() < lostAt.UnixMilli() {
		t.Errorf("proposed since: %d %v %v", n, at, ok)
	}
	if !proto.Equal(authority.Pin(), net.log.Pin()) {
		t.Error("the pin")
	}
}
