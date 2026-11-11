// MAIL-M8-02's vault on T1: an in-memory store with mailTestStore's path CAS, beside each path's versions and the
// slots they name as a record-class repo keeps them, whose keys an ERASE destroys, so a test reads what a fresh device
// could open. Its consent, its writes and their merges, Used at, and deletion with its resume.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// One version of a path in the test store: the slot its chain's key sits in, or a removal.
type mailVaultTestVersion struct {
	version uint64
	slotId  Id
	removed bool
}

// A vault store in memory. A write lands through mailTestStore's CAS, then takes its path's next version: a diff under
// its chain's slot while the chain is shorter than chainLength, else a checkpoint in a new slot, as evs_plan.go plans
// a record-class repo's; with slotless set, a version names no slot, as a general repo's. A read of a path whose
// newest version's key is gone fails as evs's tamper read does, and counts. An ERASE destroys the keys it names, one
// naming only keys gone already counts done and commits nothing, as evs's NOTHING_TO_ERASE.
type mailVaultTestStore struct {
	*mailTestStore
	chainLength int
	slotless    bool

	vaultLock   sync.Mutex
	versions    map[string][]*mailVaultTestVersion
	chainCounts map[string]int
	heldSlotIds map[Id]bool
	erasures    []*EvsErasure
	// runs once, with no lock held, before the next removal checks its version
	beforeRemove func()
	// the next removal fails with this, once, after its check: a crash between the ERASE and the removal
	failRemove   error
	tamperReads  int
	removeCount  int
	erasedPaths  []string
	writtenPaths []string
}

func newMailVaultTestStore() *mailVaultTestStore {
	return &mailVaultTestStore{
		mailTestStore: newMailTestStore(),
		chainLength:   4,
		versions:      map[string][]*mailVaultTestVersion{},
		chainCounts:   map[string]int{},
		heldSlotIds:   map[Id]bool{},
	}
}

func (self *mailVaultTestStore) Read(ctx context.Context, path string, maxByteCount int) ([]byte, uint64, error) {
	held := func() bool {
		self.vaultLock.Lock()
		defer self.vaultLock.Unlock()
		versions := self.versions[path]
		if len(versions) == 0 || versions[len(versions)-1].removed || self.slotless {
			return true
		}
		if !self.heldSlotIds[versions[len(versions)-1].slotId] {
			self.tamperReads += 1
			return false
		}
		return true
	}()
	if !held {
		return nil, 0, fmt.Errorf("%w: a slot without its key", ErrEvsEntryRefused)
	}
	return self.mailTestStore.Read(ctx, path, maxByteCount)
}

func (self *mailVaultTestStore) Write(ctx context.Context, writes []*mailStoreWrite) ([]uint64, error) {
	versions, err := self.mailTestStore.Write(ctx, writes)
	if err != nil {
		return nil, err
	}
	self.vaultLock.Lock()
	defer self.vaultLock.Unlock()
	for index, write := range writes {
		self.writtenPaths = append(self.writtenPaths, write.Path)
		pathVersions := self.versions[write.Path]
		version := &mailVaultTestVersion{version: versions[index]}
		switch {
		case self.slotless:
		case 0 < len(pathVersions) && !pathVersions[len(pathVersions)-1].removed && self.chainCounts[write.Path] < self.chainLength:
			version.slotId = pathVersions[len(pathVersions)-1].slotId
			self.chainCounts[write.Path] += 1
		default:
			version.slotId = NewEvsSlotId()
			self.heldSlotIds[version.slotId] = true
			self.chainCounts[write.Path] = 1
		}
		self.versions[write.Path] = append(pathVersions, version)
	}
	return versions, nil
}

func (self *mailVaultTestStore) Versions(ctx context.Context, path string) ([]*EvsHistoryVersion, error) {
	self.vaultLock.Lock()
	defer self.vaultLock.Unlock()
	pathVersions := self.versions[path]
	if len(pathVersions) == 0 {
		return nil, ErrEvsPathAbsent
	}
	history := []*EvsHistoryVersion{}
	for index := len(pathVersions) - 1; 0 <= index; index -= 1 {
		version := pathVersions[index]
		entry := &EvsHistoryVersion{Version: version.version, Removed: version.removed, State: "kept", SlotIds: []Id{}}
		if !version.removed && !self.slotless {
			entry.SlotIds = []Id{version.slotId}
		}
		history = append(history, entry)
	}
	return history, nil
}

func (self *mailVaultTestStore) Remove(ctx context.Context, path string, ifVersion uint64) error {
	hook := func() func() {
		self.vaultLock.Lock()
		defer self.vaultLock.Unlock()
		hook := self.beforeRemove
		self.beforeRemove = nil
		return hook
	}()
	if hook != nil {
		hook()
	}
	file := self.mailTestStore.file(path)
	if file == nil {
		return ErrEvsPathAbsent
	}
	if file.version != ifVersion {
		return &MailStoreConflictError{Paths: []string{path}}
	}
	self.vaultLock.Lock()
	defer self.vaultLock.Unlock()
	if err := self.failRemove; err != nil {
		self.failRemove = nil
		return err
	}
	self.removeCount += 1
	func() {
		self.mailTestStore.stateLock.Lock()
		defer self.mailTestStore.stateLock.Unlock()
		delete(self.mailTestStore.files, path)
	}()
	self.versions[path] = append(self.versions[path], &mailVaultTestVersion{version: ifVersion + 1, removed: true})
	return nil
}

func (self *mailVaultTestStore) Erase(ctx context.Context, args *EvsEraseArgs) error {
	if len(args.Keys) == 0 {
		return fmt.Errorf("%w: an ERASE of no key", ErrEvsWriteInvalid)
	}
	self.vaultLock.Lock()
	defer self.vaultLock.Unlock()
	held := slices.ContainsFunc(args.Keys, func(key *EvsErasedKey) bool { return key.KeyIndex == 0 && self.heldSlotIds[key.SlotId] })
	if !held {
		return nil
	}
	for _, key := range args.Keys {
		if key.KeyIndex == 0 {
			delete(self.heldSlotIds, key.SlotId)
		}
	}
	self.erasures = append(self.erasures, &EvsErasure{
		Version: uint64(len(self.erasures) + 1), ErasureId: args.ErasureId, Complete: args.Complete,
		Keys: slices.Clone(args.Keys), Note: bytes.Clone(args.Note),
	})
	self.erasedPaths = append(self.erasedPaths, string(args.Note))
	return nil
}

func (self *mailVaultTestStore) Erasures(ctx context.Context, afterVersion uint64) ([]*EvsErasure, error) {
	self.vaultLock.Lock()
	defer self.vaultLock.Unlock()
	erasures := []*EvsErasure{}
	for _, erasure := range self.erasures {
		if afterVersion < erasure.Version {
			erasures = append(erasures, erasure)
		}
	}
	return erasures, nil
}

// The versions of path whose key a fresh device could still open: each version not a removal whose slot holds its
// key, by number.
func (self *mailVaultTestStore) openableVersions(path string) []uint64 {
	self.vaultLock.Lock()
	defer self.vaultLock.Unlock()
	openable := []uint64{}
	for _, version := range self.versions[path] {
		if !version.removed && (self.slotless || self.heldSlotIds[version.slotId]) {
			openable = append(openable, version.version)
		}
	}
	return openable
}

// The slots path's versions name, in order, each once.
func (self *mailVaultTestStore) slotIdsOf(path string) []Id {
	self.vaultLock.Lock()
	defer self.vaultLock.Unlock()
	slotIds := []Id{}
	for _, version := range self.versions[path] {
		if !version.removed && !slices.Contains(slotIds, version.slotId) {
			slotIds = append(slotIds, version.slotId)
		}
	}
	return slotIds
}

// The committed ERASEs.
func (self *mailVaultTestStore) committedErasures() []*EvsErasure {
	self.vaultLock.Lock()
	defer self.vaultLock.Unlock()
	return slices.Clone(self.erasures)
}

// Reads of a path whose newest key is gone.
func (self *mailVaultTestStore) tamperReadCount() int {
	self.vaultLock.Lock()
	defer self.vaultLock.Unlock()
	return self.tamperReads
}

// An authority holding the consented pairs it is given.
type mailVaultTestAuthority struct {
	stateLock sync.Mutex
	consented map[[2]Id]bool
}

func newMailVaultTestAuthority(sidecarId Id, memberId Id) *mailVaultTestAuthority {
	return &mailVaultTestAuthority{consented: map[[2]Id]bool{{sidecarId, memberId}: true}}
}

func (self *mailVaultTestAuthority) Consented(sidecarId Id, memberId Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.consented[[2]Id{sidecarId, memberId}]
}

func (self *mailVaultTestAuthority) set(sidecarId Id, memberId Id, consented bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.consented[[2]Id{sidecarId, memberId}] = consented
}

// The owner and devices of the tests' mailbox.
var (
	testMailVaultOwnerId  = evsTestId("vault owner")
	testMailVaultDeviceId = evsTestId("vault owner's phone")
	testMailVaultOtherId  = evsTestId("vault owner's desktop")
)

// A vault for the owner's consented phone over store, on clock, its log kept.
type mailVaultTestDevice struct {
	vault     *MailVault
	store     *mailVaultTestStore
	clock     *mailTestClock
	log       *testLineLogger
	authority *mailVaultTestAuthority
}

func newMailVaultTestDevice(t *testing.T, store *mailVaultTestStore, sidecarId Id, mutate func(settings *MailVaultSettings)) *mailVaultTestDevice {
	t.Helper()
	settings := DefaultMailVaultSettings()
	if mutate != nil {
		mutate(settings)
	}
	clock := &mailTestClock{now: time.UnixMilli(1793923200000)}
	log := &testLineLogger{}
	authority := newMailVaultTestAuthority(sidecarId, testMailVaultOwnerId)
	vault := newMailVault(store, testMailVaultOwnerId, sidecarId, authority, clock, log, settings)
	return &mailVaultTestDevice{vault: vault, store: store, clock: clock, log: log, authority: authority}
}

// A burner's entry with every user field set, its secrets synthetic.
func testMailVaultEntry(address string, password string) *protocol.VaultEntry {
	return &protocol.VaultEntry{
		Address:  address,
		Title:    "a synthetic shop",
		Username: address,
		Password: password,
		Totp:     &protocol.VaultTotp{Secret: []byte("a synthetic totp secret"), Algorithm: protocol.VaultTotpAlgorithm_VAULT_TOTP_SHA1, Digits: 6, Period: 30},
		Urls:     []string{"https://shop.example/login"},
		Notes:    "signed up for the newsletter",
	}
}

// A new entry takes 16 random bytes and its times, reads back field for field, and lists by creation time.
func TestMailVaultPutReadsBackAndListsByCreation(t *testing.T) {
	ctx := context.Background()
	device := newMailVaultTestDevice(t, newMailVaultTestStore(), testMailVaultDeviceId, nil)
	first, err := device.vault.PutVaultEntry(ctx, testMailVaultEntry("shop@otter-4821.acme.root.example", "first password"))
	if err != nil {
		t.Fatal(err)
	}
	if len(first.GetEntryId()) != 16 || first.GetCreated() != 1793923200000 || first.GetUpdated() != first.GetCreated() ||
		first.GetState() != protocol.VaultEntryState_VAULT_ENTRY_LIVE {
		t.Fatalf("a new entry: %d-byte id, created %d, updated %d, state %v", len(first.GetEntryId()), first.GetCreated(), first.GetUpdated(), first.GetState())
	}
	device.clock.now = device.clock.now.Add(time.Minute)
	second, err := device.vault.PutVaultEntry(ctx, testMailVaultEntry("news@heron-1207.acme.root.example", "second password"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.GetEntryId(), second.GetEntryId()) {
		t.Fatal("two new entries under one id")
	}
	listed, err := newMailVaultTestDevice(t, device.store, testMailVaultDeviceId, nil).vault.VaultEntries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 || !proto.Equal(listed[0], first) || !proto.Equal(listed[1], second) {
		t.Fatalf("listed %v", listed)
	}
	firstId, _ := IdFromBytes(first.GetEntryId())
	read, err := device.vault.VaultEntry(ctx, firstId)
	if err != nil || !proto.Equal(read, first) {
		t.Fatalf("read back %v, %v", read, err)
	}
	if path := MailVaultPath(firstId); device.store.file(path) == nil {
		t.Fatalf("no file at %s", path)
	}
}

// A changed password joins password_history, oldest first, held to its bound; an unchanged one adds nothing; the
// history, created and Used at a caller sends are not read.
func TestMailVaultPutKeepsTheEarlierPasswords(t *testing.T) {
	ctx := context.Background()
	device := newMailVaultTestDevice(t, newMailVaultTestStore(), testMailVaultDeviceId, func(settings *MailVaultSettings) {
		settings.PasswordHistoryMaxCount = 2
	})
	entry, err := device.vault.PutVaultEntry(ctx, testMailVaultEntry("shop@otter-4821.acme.root.example", "password one"))
	if err != nil {
		t.Fatal(err)
	}
	for _, password := range []string{"password two", "password three", "password four"} {
		device.clock.now = device.clock.now.Add(time.Hour)
		update := proto.Clone(entry).(*protocol.VaultEntry)
		update.Password = password
		update.PasswordHistory = []string{"a history the caller made up"}
		update.Created = 1
		update.UsedAt = []*protocol.VaultUsedAt{{RegistrableDomain: "made-up.example", First: 1, Last: 1}}
		if entry, err = device.vault.PutVaultEntry(ctx, update); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(entry.GetPasswordHistory(), []string{"password two", "password three"}) || entry.GetPassword() != "password four" {
		t.Fatalf("history %q, password %q", entry.GetPasswordHistory(), entry.GetPassword())
	}
	if entry.GetCreated() != 1793923200000 || entry.GetUpdated() != 1793923200000+3*3600*1000 || len(entry.GetUsedAt()) != 0 {
		t.Fatalf("created %d, updated %d, used at %v", entry.GetCreated(), entry.GetUpdated(), entry.GetUsedAt())
	}
	entryId, _ := IdFromBytes(entry.GetEntryId())
	versionBefore := device.store.file(MailVaultPath(entryId)).version
	device.clock.now = device.clock.now.Add(time.Hour)
	same, err := device.vault.PutVaultEntry(ctx, proto.Clone(entry).(*protocol.VaultEntry))
	if err != nil || !proto.Equal(same, entry) || device.store.file(MailVaultPath(entryId)).version != versionBefore {
		t.Fatalf("a Put that changes nothing wrote: %v", err)
	}
}

// A burned entry stays burned, whatever a later Put says, since its label is never reissued; a Put naming no state
// keeps the entry's.
func TestMailVaultBurnedEntryStaysBurned(t *testing.T) {
	ctx := context.Background()
	device := newMailVaultTestDevice(t, newMailVaultTestStore(), testMailVaultDeviceId, nil)
	entry, err := device.vault.PutVaultEntry(ctx, testMailVaultEntry("shop@otter-4821.acme.root.example", "a password"))
	if err != nil {
		t.Fatal(err)
	}
	burn := proto.Clone(entry).(*protocol.VaultEntry)
	burn.State = protocol.VaultEntryState_VAULT_ENTRY_BURNED
	if entry, err = device.vault.PutVaultEntry(ctx, burn); err != nil || entry.GetState() != protocol.VaultEntryState_VAULT_ENTRY_BURNED {
		t.Fatalf("the burn: %v, %v", entry.GetState(), err)
	}
	revive := proto.Clone(entry).(*protocol.VaultEntry)
	revive.State = protocol.VaultEntryState_VAULT_ENTRY_LIVE
	revive.Notes = "a note after the burn"
	if entry, err = device.vault.PutVaultEntry(ctx, revive); err != nil || entry.GetState() != protocol.VaultEntryState_VAULT_ENTRY_BURNED || entry.GetNotes() != revive.GetNotes() {
		t.Fatalf("a Put after the burn: %v %q, %v", entry.GetState(), entry.GetNotes(), err)
	}
	unnamed := proto.Clone(entry).(*protocol.VaultEntry)
	unnamed.State = protocol.VaultEntryState_VAULT_ENTRY_STATE_UNSPECIFIED
	unnamed.Title = "a new title"
	if entry, err = device.vault.PutVaultEntry(ctx, unnamed); err != nil || entry.GetState() != protocol.VaultEntryState_VAULT_ENTRY_BURNED {
		t.Fatalf("a Put naming no state: %v, %v", entry.GetState(), err)
	}
}

// Another device's Used at landing between a Put's read and its write makes the Put read and apply again, so both
// stand: the person's edit and the other device's use.
func TestMailVaultPutOverARacingWriteKeepsBoth(t *testing.T) {
	ctx := context.Background()
	store := newMailVaultTestStore()
	phone := newMailVaultTestDevice(t, store, testMailVaultDeviceId, nil)
	desktop := newMailVaultTestDevice(t, store, testMailVaultOtherId, nil)
	entry, err := phone.vault.PutVaultEntry(ctx, testMailVaultEntry("shop@otter-4821.acme.root.example", "a password"))
	if err != nil {
		t.Fatal(err)
	}
	store.beforeWrite = func() {
		if err := desktop.vault.NoteUsedAt(ctx, "shop@otter-4821.acme.root.example", "mail.shop.example", desktop.clock.now); err != nil {
			t.Errorf("the desktop's use: %v", err)
		}
	}
	update := proto.Clone(entry).(*protocol.VaultEntry)
	update.Notes = "an edit on the phone"
	written, err := phone.vault.PutVaultEntry(ctx, update)
	if err != nil {
		t.Fatal(err)
	}
	if written.GetNotes() != update.GetNotes() || len(written.GetUsedAt()) != 1 || written.GetUsedAt()[0].GetRegistrableDomain() != "shop.example" {
		t.Fatalf("notes %q, used at %v", written.GetNotes(), written.GetUsedAt())
	}
	if store.writeCount != 4 {
		t.Fatalf("%d writes, not the create, the use, the refused edit and the edit again", store.writeCount)
	}
}

// Used at keeps each sender's registrable domain with its earliest and latest use, whatever order uses arrive in; a
// use within the refresh interval of the last writes nothing; a sender's name with no registrable domain is refused.
func TestMailVaultNoteUsedAtKeepsFirstAndLast(t *testing.T) {
	ctx := context.Background()
	device := newMailVaultTestDevice(t, newMailVaultTestStore(), testMailVaultDeviceId, nil)
	const address = "shop@otter-4821.acme.root.example"
	entry, err := device.vault.PutVaultEntry(ctx, testMailVaultEntry(address, "a password"))
	if err != nil {
		t.Fatal(err)
	}
	entryId, _ := IdFromBytes(entry.GetEntryId())
	base := time.UnixMilli(1793923200000)
	uses := []struct {
		domain string
		at     time.Time
	}{
		{domain: "accounts.shop.example", at: base.Add(48 * time.Hour)},
		{domain: "SHOP.example.", at: base.Add(24 * time.Hour)},
		{domain: "news.shop.example", at: base.Add(72 * time.Hour)},
		{domain: "mail.bank.example.co.uk", at: base},
	}
	for _, use := range uses {
		if err := device.vault.NoteUsedAt(ctx, "Shop@Otter-4821.acme.root.example", use.domain, use.at); err != nil {
			t.Fatalf("%s: %v", use.domain, err)
		}
	}
	usedAts, err := device.vault.UsedAt(ctx, entryId)
	if err != nil {
		t.Fatal(err)
	}
	want := []*protocol.VaultUsedAt{
		{RegistrableDomain: "shop.example", First: uint64(base.Add(24 * time.Hour).UnixMilli()), Last: uint64(base.Add(72 * time.Hour).UnixMilli())},
		{RegistrableDomain: "example.co.uk", First: uint64(base.UnixMilli()), Last: uint64(base.UnixMilli())},
	}
	if len(usedAts) != len(want) || !proto.Equal(usedAts[0], want[0]) || !proto.Equal(usedAts[1], want[1]) {
		t.Fatalf("used at %v", usedAts)
	}
	writes := device.store.writeCount
	if err := device.vault.NoteUsedAt(ctx, address, "shop.example", base.Add(72*time.Hour+59*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if device.store.writeCount != writes {
		t.Fatal("a use within the refresh interval wrote a version")
	}
	if err := device.vault.NoteUsedAt(ctx, address, "shop.example", base.Add(73*time.Hour)); err != nil || device.store.writeCount != writes+1 {
		t.Fatalf("a use past the interval: %d writes, %v", device.store.writeCount-writes, err)
	}
	for _, domain := range []string{"", "co.uk", "example", "192.0.2.1", "shop..example", "shop_example.example", "-shop.example"} {
		if err := device.vault.NoteUsedAt(ctx, address, domain, base); !errors.Is(err, ErrMailVaultDomainInvalid) {
			t.Errorf("%q: %v", domain, err)
		}
	}
	if err := device.vault.NoteUsedAt(ctx, "nobody@otter-4821.acme.root.example", "shop.example", base); !errors.Is(err, ErrMailVaultEntryAbsent) {
		t.Errorf("an address no entry holds: %v", err)
	}
}

// Used at keeps its first and last across a restart: a vault opened again on the same store, as a restarted device,
// reads them, and a later use moves last and leaves first.
func TestMailVaultUsedAtKeepsFirstAndLastAcrossARestart(t *testing.T) {
	ctx := context.Background()
	store := newMailVaultTestStore()
	const address = "shop@otter-4821.acme.root.example"
	device := newMailVaultTestDevice(t, store, testMailVaultDeviceId, nil)
	entry, err := device.vault.PutVaultEntry(ctx, testMailVaultEntry(address, "a password"))
	if err != nil {
		t.Fatal(err)
	}
	entryId, _ := IdFromBytes(entry.GetEntryId())
	first := time.UnixMilli(1793923200000)
	if err := device.vault.NoteUsedAt(ctx, address, "shop.example", first); err != nil {
		t.Fatal(err)
	}
	if err := device.vault.NoteUsedAt(ctx, address, "shop.example", first.Add(5*time.Hour)); err != nil {
		t.Fatal(err)
	}
	restarted := newMailVaultTestDevice(t, store, testMailVaultDeviceId, nil)
	usedAts, err := restarted.vault.UsedAt(ctx, entryId)
	if err != nil || len(usedAts) != 1 || usedAts[0].GetFirst() != uint64(first.UnixMilli()) || usedAts[0].GetLast() != uint64(first.Add(5*time.Hour).UnixMilli()) {
		t.Fatalf("after the restart: %v, %v", usedAts, err)
	}
	if err := restarted.vault.NoteUsedAt(ctx, address, "shop.example", first.Add(10*time.Hour)); err != nil {
		t.Fatal(err)
	}
	usedAts, err = newMailVaultTestDevice(t, store, testMailVaultOtherId, nil).vault.UsedAt(ctx, entryId)
	if err != nil || len(usedAts) != 1 || usedAts[0].GetFirst() != uint64(first.UnixMilli()) || usedAts[0].GetLast() != uint64(first.Add(10*time.Hour).UnixMilli()) {
		t.Fatalf("after a use on the restarted device: %v, %v", usedAts, err)
	}
}

// An entry another device made is found by NoteUsedAt once the address index is older than its refresh interval,
// and a run of misses within it reads the vault no more.
func TestMailVaultNoteUsedAtFindsAnEntryAnotherDeviceMade(t *testing.T) {
	ctx := context.Background()
	store := newMailVaultTestStore()
	desktop := newMailVaultTestDevice(t, store, testMailVaultOtherId, nil)
	phone := newMailVaultTestDevice(t, store, testMailVaultDeviceId, nil)
	if _, err := desktop.vault.VaultEntries(ctx); err != nil {
		t.Fatal(err)
	}
	const address = "shop@otter-4821.acme.root.example"
	entry, err := phone.vault.PutVaultEntry(ctx, testMailVaultEntry(address, "a password"))
	if err != nil {
		t.Fatal(err)
	}
	reads := store.readCount
	if err := desktop.vault.NoteUsedAt(ctx, address, "shop.example", desktop.clock.now); !errors.Is(err, ErrMailVaultEntryAbsent) || store.readCount != reads {
		t.Fatalf("a miss within the interval: %v, %d reads", err, store.readCount-reads)
	}
	desktop.clock.now = desktop.clock.now.Add(time.Minute)
	if err := desktop.vault.NoteUsedAt(ctx, address, "shop.example", desktop.clock.now); err != nil {
		t.Fatalf("a miss past the interval: %v", err)
	}
	entryId, _ := IdFromBytes(entry.GetEntryId())
	if usedAts, err := phone.vault.UsedAt(ctx, entryId); err != nil || len(usedAts) != 1 {
		t.Fatalf("the phone reads %v, %v", usedAts, err)
	}
}

// Used at holds UsedAtMaxCount domains, dropping the one used longest ago.
func TestMailVaultUsedAtKeepsItsBound(t *testing.T) {
	ctx := context.Background()
	device := newMailVaultTestDevice(t, newMailVaultTestStore(), testMailVaultDeviceId, func(settings *MailVaultSettings) {
		settings.UsedAtMaxCount = 2
	})
	const address = "shop@otter-4821.acme.root.example"
	entry, err := device.vault.PutVaultEntry(ctx, testMailVaultEntry(address, "a password"))
	if err != nil {
		t.Fatal(err)
	}
	base := time.UnixMilli(1793923200000)
	for index, domain := range []string{"b.example", "a.example", "c.example"} {
		if err := device.vault.NoteUsedAt(ctx, address, domain, base.Add(time.Duration(index)*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	entryId, _ := IdFromBytes(entry.GetEntryId())
	usedAts, err := device.vault.UsedAt(ctx, entryId)
	if err != nil || len(usedAts) != 2 || usedAts[0].GetRegistrableDomain() != "c.example" || usedAts[1].GetRegistrableDomain() != "a.example" {
		t.Fatalf("used at %v, %v", usedAts, err)
	}
}

// A device that is not a consented device of the mailbox's owner, or one with no authority, reads and writes
// nothing: every call refuses before the store sees it.
func TestMailVaultRefusesANonConsentedReader(t *testing.T) {
	ctx := context.Background()
	store := newMailVaultTestStore()
	owner := newMailVaultTestDevice(t, store, testMailVaultDeviceId, nil)
	entry, err := owner.vault.PutVaultEntry(ctx, testMailVaultEntry("shop@otter-4821.acme.root.example", "a password"))
	if err != nil {
		t.Fatal(err)
	}
	entryId, _ := IdFromBytes(entry.GetEntryId())
	parked := newMailVaultTestDevice(t, store, testMailVaultOtherId, nil)
	parked.authority.set(testMailVaultOtherId, testMailVaultOwnerId, false)
	noAuthority := newMailVault(store, testMailVaultOwnerId, testMailVaultDeviceId, nil, owner.clock, nil, DefaultMailVaultSettings())
	otherMember := newMailVault(store, evsTestId("another member"), testMailVaultDeviceId, owner.authority, owner.clock, nil, DefaultMailVaultSettings())
	reads, writes := store.readCount, store.writeCount
	for name, vault := range map[string]*MailVault{"unconsented": parked.vault, "no authority": noAuthority, "another member's mailbox": otherMember} {
		calls := map[string]error{}
		_, calls["entries"] = vault.VaultEntries(ctx)
		_, calls["entry"] = vault.VaultEntry(ctx, entryId)
		_, calls["used at"] = vault.UsedAt(ctx, entryId)
		_, calls["put"] = vault.PutVaultEntry(ctx, testMailVaultEntry("shop@otter-4821.acme.root.example", "another password"))
		calls["note"] = vault.NoteUsedAt(ctx, "shop@otter-4821.acme.root.example", "shop.example", owner.clock.now)
		calls["delete"] = vault.DeleteVaultEntry(ctx, entryId)
		calls["resume"] = vault.ResumeVaultDeletions(ctx)
		for call, err := range calls {
			if !errors.Is(err, ErrMailVaultNotConsented) {
				t.Errorf("%s: %s: %v", name, call, err)
			}
		}
	}
	if store.readCount != reads || store.writeCount != writes || len(store.committedErasures()) != 0 {
		t.Fatalf("a refused device reached the store: %d reads, %d writes", store.readCount-reads, store.writeCount-writes)
	}
	parked.authority.set(testMailVaultOtherId, testMailVaultOwnerId, true)
	if entries, err := parked.vault.VaultEntries(ctx); err != nil || len(entries) != 1 {
		t.Fatalf("once consented: %v, %v", entries, err)
	}
}

// Deleting an entry shreds every version: one ERASE, complete, names the key of every chain its versions used, its
// note the entry's path, then the path is removed; a fresh device opens no version, lists nothing, takes no new entry
// at the id, and a second delete is done already.
func TestMailVaultDeleteLeavesNoVersionOpenable(t *testing.T) {
	ctx := context.Background()
	store := newMailVaultTestStore()
	device := newMailVaultTestDevice(t, store, testMailVaultDeviceId, nil)
	const address = "shop@otter-4821.acme.root.example"
	entry, err := device.vault.PutVaultEntry(ctx, testMailVaultEntry(address, "password 0"))
	if err != nil {
		t.Fatal(err)
	}
	for index := 1; index < 10; index += 1 {
		update := proto.Clone(entry).(*protocol.VaultEntry)
		update.Password = fmt.Sprintf("password %d", index)
		if entry, err = device.vault.PutVaultEntry(ctx, update); err != nil {
			t.Fatal(err)
		}
	}
	keep, err := device.vault.PutVaultEntry(ctx, testMailVaultEntry("news@heron-1207.acme.root.example", "a password kept"))
	if err != nil {
		t.Fatal(err)
	}
	entryId, _ := IdFromBytes(entry.GetEntryId())
	path := MailVaultPath(entryId)
	slotIds := store.slotIdsOf(path)
	if len(slotIds) != 3 || len(store.openableVersions(path)) != 10 {
		t.Fatalf("%d slots and %d openable versions before the delete", len(slotIds), len(store.openableVersions(path)))
	}
	if err := device.vault.DeleteVaultEntry(ctx, entryId); err != nil {
		t.Fatal(err)
	}
	erasures := store.committedErasures()
	if len(erasures) != 1 || !erasures[0].Complete || string(erasures[0].Note) != path || len(erasures[0].Keys) != len(slotIds) {
		t.Fatalf("erasures %v", erasures)
	}
	for _, key := range erasures[0].Keys {
		if !slices.Contains(slotIds, key.SlotId) || key.KeyIndex != 0 {
			t.Fatalf("an erased key of no version: %v", key)
		}
	}
	if openable := store.openableVersions(path); len(openable) != 0 || store.file(path) != nil {
		t.Fatalf("versions %v openable after the delete", openable)
	}
	fresh := newMailVaultTestDevice(t, store, testMailVaultOtherId, nil)
	entries, err := fresh.vault.VaultEntries(ctx)
	if err != nil || len(entries) != 1 || !bytes.Equal(entries[0].GetEntryId(), keep.GetEntryId()) {
		t.Fatalf("a fresh device lists %v, %v", entries, err)
	}
	if _, err := fresh.vault.VaultEntry(ctx, entryId); !errors.Is(err, ErrMailVaultEntryDeleted) {
		t.Fatalf("a fresh device reads the deleted entry: %v", err)
	}
	again := proto.Clone(entry).(*protocol.VaultEntry)
	if _, err := fresh.vault.PutVaultEntry(ctx, again); !errors.Is(err, ErrMailVaultEntryDeleted) {
		t.Fatalf("a new entry at a deleted id: %v", err)
	}
	if err := fresh.vault.DeleteVaultEntry(ctx, entryId); err != nil || len(store.committedErasures()) != 1 {
		t.Fatalf("a second delete: %v, %d erasures", err, len(store.committedErasures()))
	}
	if err := device.vault.NoteUsedAt(ctx, address, "shop.example", device.clock.now); !errors.Is(err, ErrMailVaultEntryAbsent) {
		t.Fatalf("a use of the deleted entry's address: %v", err)
	}
	if store.tamperReadCount() != 0 {
		t.Fatalf("%d reads of an erased version", store.tamperReadCount())
	}
	if err := device.vault.DeleteVaultEntry(ctx, evsTestId("no such entry")); !errors.Is(err, ErrMailVaultEntryAbsent) {
		t.Fatalf("an entry never written: %v", err)
	}
}

// A crash after the ERASE and before the removal leaves no version openable; another of the owner's devices passes
// the entry over without reading it, and its resume removes it under the same erasure.
func TestMailVaultDeleteResumesAfterACrashBeforeTheRemoval(t *testing.T) {
	ctx := context.Background()
	store := newMailVaultTestStore()
	device := newMailVaultTestDevice(t, store, testMailVaultDeviceId, nil)
	entry, err := device.vault.PutVaultEntry(ctx, testMailVaultEntry("shop@otter-4821.acme.root.example", "a password"))
	if err != nil {
		t.Fatal(err)
	}
	entryId, _ := IdFromBytes(entry.GetEntryId())
	path := MailVaultPath(entryId)
	crash := errors.New("a crash before the removal")
	store.failRemove = crash
	if err := device.vault.DeleteVaultEntry(ctx, entryId); !errors.Is(err, crash) {
		t.Fatalf("the crashed delete: %v", err)
	}
	if store.file(path) == nil || len(store.openableVersions(path)) != 0 || len(store.committedErasures()) != 1 {
		t.Fatalf("after the crash: openable %v, %d erasures", store.openableVersions(path), len(store.committedErasures()))
	}
	other := newMailVaultTestDevice(t, store, testMailVaultOtherId, nil)
	if entries, err := other.vault.VaultEntries(ctx); err != nil || len(entries) != 0 {
		t.Fatalf("the other device lists %v, %v", entries, err)
	}
	if err := other.vault.ResumeVaultDeletions(ctx); err != nil {
		t.Fatal(err)
	}
	erasures := store.committedErasures()
	if store.file(path) != nil || store.removeCount != 1 || len(erasures) != 1 {
		t.Fatalf("after the resume: file %v, %d removals, %d erasures", store.file(path) != nil, store.removeCount, len(erasures))
	}
	if store.tamperReadCount() != 0 {
		t.Fatalf("%d reads of an erased version", store.tamperReadCount())
	}
	if err := other.vault.ResumeVaultDeletions(ctx); err != nil || store.removeCount != 1 {
		t.Fatalf("a second resume: %v, %d removals", err, store.removeCount)
	}
}

// A version another device commits between History's read and the removal moves the path, so the delete names that
// version's new slot in a second ERASE of the same erasure, and only then removes the path.
func TestMailVaultDeleteNamesARacingWritersVersion(t *testing.T) {
	ctx := context.Background()
	store := newMailVaultTestStore()
	store.chainLength = 1
	phone := newMailVaultTestDevice(t, store, testMailVaultDeviceId, nil)
	desktop := newMailVaultTestDevice(t, store, testMailVaultOtherId, nil)
	const address = "shop@otter-4821.acme.root.example"
	entry, err := phone.vault.PutVaultEntry(ctx, testMailVaultEntry(address, "a password"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := desktop.vault.VaultEntries(ctx); err != nil {
		t.Fatal(err)
	}
	entryId, _ := IdFromBytes(entry.GetEntryId())
	path := MailVaultPath(entryId)
	store.beforeRemove = func() {
		// the desktop read the entry before the ERASE, and writes its use on that read
		current, version, err := desktop.vault.readEntry(ctx, entryId)
		if err == nil {
			t.Error("the desktop read a version whose key the ERASE took")
			return
		}
		current = proto.Clone(entry).(*protocol.VaultEntry)
		version = store.file(path).version
		current.Notes = "a racing write"
		if _, err := desktop.vault.writeEntry(ctx, current, version); err != nil {
			t.Errorf("the racing write: %v", err)
		}
	}
	if err := phone.vault.DeleteVaultEntry(ctx, entryId); err != nil {
		t.Fatal(err)
	}
	erasures := store.committedErasures()
	if len(erasures) != 2 || erasures[0].ErasureId != erasures[1].ErasureId || len(erasures[1].Keys) != 2 {
		t.Fatalf("erasures %v", erasures)
	}
	if openable := store.openableVersions(path); len(openable) != 0 || store.file(path) != nil {
		t.Fatalf("versions %v openable", openable)
	}
}

// Versions whose keys ride no slot, as a general repo's do, cannot be shredded one entry at a time: the delete
// refuses and erases nothing, and the entry still reads.
func TestMailVaultDeleteRefusesVersionsNoSlotHolds(t *testing.T) {
	ctx := context.Background()
	store := newMailVaultTestStore()
	store.slotless = true
	device := newMailVaultTestDevice(t, store, testMailVaultDeviceId, nil)
	entry, err := device.vault.PutVaultEntry(ctx, testMailVaultEntry("shop@otter-4821.acme.root.example", "a password"))
	if err != nil {
		t.Fatal(err)
	}
	entryId, _ := IdFromBytes(entry.GetEntryId())
	if err := device.vault.DeleteVaultEntry(ctx, entryId); !errors.Is(err, ErrMailVaultNotShreddable) {
		t.Fatalf("the delete: %v", err)
	}
	if len(store.committedErasures()) != 0 || store.removeCount != 0 {
		t.Fatal("a refused delete erased or removed")
	}
	if read, err := device.vault.VaultEntry(ctx, entryId); err != nil || !proto.Equal(read, entry) {
		t.Fatalf("the entry after a refused delete: %v", err)
	}
}

// What a Put refuses, naming no value: an id that is not 16 bytes, an address with a slash, an unknown state, a totp
// a writer did not fill, text that is not UTF-8, and an entry past its bound. Nothing is written.
func TestMailVaultPutRefusesAnEntryOutOfShape(t *testing.T) {
	ctx := context.Background()
	store := newMailVaultTestStore()
	device := newMailVaultTestDevice(t, store, testMailVaultDeviceId, func(settings *MailVaultSettings) {
		settings.EntryMaxByteCount = 4 * 1024
	})
	const canary = "a canary password 61c3"
	cases := map[string]func(entry *protocol.VaultEntry){
		"a short id":       func(entry *protocol.VaultEntry) { entry.EntryId = []byte("short") },
		"a slash":          func(entry *protocol.VaultEntry) { entry.Address = "shop/x@otter-4821.acme.root.example" },
		"a state":          func(entry *protocol.VaultEntry) { entry.State = 9 },
		"a totp":           func(entry *protocol.VaultEntry) { entry.Totp.Digits = 0 },
		"not utf-8":        func(entry *protocol.VaultEntry) { entry.Password = canary + "\xff" },
		"past the bound":   func(entry *protocol.VaultEntry) { entry.Notes = strings.Repeat(canary, 200) },
		"a long address":   func(entry *protocol.VaultEntry) { entry.Address = strings.Repeat("a", 400) },
		"no entry at all":  nil,
		"an empty totp id": func(entry *protocol.VaultEntry) { entry.Totp = &protocol.VaultTotp{} },
	}
	for name, mutate := range cases {
		var entry *protocol.VaultEntry
		if mutate != nil {
			entry = testMailVaultEntry("shop@otter-4821.acme.root.example", canary)
			mutate(entry)
		}
		_, err := device.vault.PutVaultEntry(ctx, entry)
		if !errors.Is(err, ErrMailVaultEntryInvalid) {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if strings.Contains(err.Error(), "canary") || strings.Contains(err.Error(), "otter") {
			t.Errorf("%s: the error names a value: %v", name, err)
		}
	}
	if store.writeCount != 0 {
		t.Fatalf("%d writes of refused entries", store.writeCount)
	}
}

// A file under a vault path that is no entry, or another path's entry, is passed over with its id logged, and the
// listing goes on; a name that is no entry id, or sits in another shard, is never read.
func TestMailVaultPassesOverAFileThatIsNotItsPathsEntry(t *testing.T) {
	ctx := context.Background()
	store := newMailVaultTestStore()
	device := newMailVaultTestDevice(t, store, testMailVaultDeviceId, nil)
	good, err := device.vault.PutVaultEntry(ctx, testMailVaultEntry("shop@otter-4821.acme.root.example", "a password"))
	if err != nil {
		t.Fatal(err)
	}
	misplacedId := evsTestId("a misplaced entry")
	misplaced, err := proto.Marshal(&protocol.VaultEntry{EntryId: evsTestId("another id").Bytes(), Title: "elsewhere"})
	if err != nil {
		t.Fatal(err)
	}
	store.put(MailVaultPath(misplacedId), misplaced)
	garbledId := evsTestId("a garbled entry")
	store.put(MailVaultPath(garbledId), []byte{0xff, 0xff, 0xff})
	store.put("vault/zz/notanid", []byte("x"))
	wrongShardId := evsTestId("a wrong shard")
	wrongShardName := mailBinaryName(wrongShardId[:])
	wrongShard := "00"
	if MailShard(wrongShardName) == wrongShard {
		wrongShard = "01"
	}
	store.put("vault/"+wrongShard+"/"+wrongShardName, []byte("x"))
	reads := store.readCount
	entries, err := device.vault.VaultEntries(ctx)
	if err != nil || len(entries) != 1 || !proto.Equal(entries[0], good) {
		t.Fatalf("listed %v, %v", entries, err)
	}
	if store.readCount-reads != 3 {
		t.Fatalf("%d reads, not the good, misplaced and garbled entries'", store.readCount-reads)
	}
	if text := device.log.text(); !strings.Contains(text, misplacedId.String()) || !strings.Contains(text, garbledId.String()) {
		t.Fatalf("the log: %q", text)
	}
}

// Every path the vault writes, removes or erases is under vault/, so no index or other family takes a vault value
// (D-MAIL-16), and an ERASE's note is a vault path alone.
func TestMailVaultWritesNothingOutsideVault(t *testing.T) {
	ctx := context.Background()
	store := newMailVaultTestStore()
	device := newMailVaultTestDevice(t, store, testMailVaultDeviceId, nil)
	const address = "shop@otter-4821.acme.root.example"
	entry, err := device.vault.PutVaultEntry(ctx, testMailVaultEntry(address, "a password"))
	if err != nil {
		t.Fatal(err)
	}
	if err := device.vault.NoteUsedAt(ctx, address, "shop.example", device.clock.now); err != nil {
		t.Fatal(err)
	}
	entryId, _ := IdFromBytes(entry.GetEntryId())
	if err := device.vault.DeleteVaultEntry(ctx, entryId); err != nil {
		t.Fatal(err)
	}
	for _, path := range append(slices.Clone(store.writtenPaths), store.erasedPaths...) {
		if _, ok := parseMailVaultPath(path); !ok {
			t.Errorf("the vault wrote or erased %q", path)
		}
	}
	if len(store.writtenPaths) != 2 || len(store.erasedPaths) != 1 {
		t.Fatalf("%d writes and %d erasures", len(store.writtenPaths), len(store.erasedPaths))
	}
}

// A password, an earlier password and a totp secret reach no log line and no error, whatever path a call takes,
// refusals included; only the store sees them.
func TestMailVaultSecretsReachNoLogOrError(t *testing.T) {
	ctx := context.Background()
	store := newMailVaultTestStore()
	device := newMailVaultTestDevice(t, store, testMailVaultDeviceId, func(settings *MailVaultSettings) {
		settings.EntryMaxByteCount = 2 * 1024
	})
	const address = "shop@otter-4821.acme.root.example"
	const passwordCanary, oldPasswordCanary, totpCanary = "password canary 0a1b2c", "old password canary 3d4e5f", "totp secret canary 6a7b8c"
	errs := []error{}
	entry := testMailVaultEntry(address, oldPasswordCanary)
	entry.Totp.Secret = []byte(totpCanary)
	written, err := device.vault.PutVaultEntry(ctx, entry)
	if err != nil {
		t.Fatal(err)
	}
	update := proto.Clone(written).(*protocol.VaultEntry)
	update.Password = passwordCanary
	written, err = device.vault.PutVaultEntry(ctx, update)
	if err != nil {
		t.Fatal(err)
	}
	oversized := proto.Clone(written).(*protocol.VaultEntry)
	oversized.Notes = strings.Repeat(passwordCanary, 100)
	_, err = device.vault.PutVaultEntry(ctx, oversized)
	errs = append(errs, err)
	errs = append(errs, device.vault.NoteUsedAt(ctx, address, passwordCanary, device.clock.now))
	if _, _, err := MailTotpCode(written.GetTotp(), device.clock.now); err != nil {
		t.Fatal(err)
	}
	store.put(MailVaultPath(evsTestId("a garbled entry")), []byte(passwordCanary))
	_, err = device.vault.VaultEntries(ctx)
	errs = append(errs, err)
	entryId, _ := IdFromBytes(written.GetEntryId())
	errs = append(errs, device.vault.DeleteVaultEntry(ctx, entryId))
	device.authority.set(testMailVaultDeviceId, testMailVaultOwnerId, false)
	_, err = device.vault.PutVaultEntry(ctx, update)
	errs = append(errs, err)
	text := device.log.text()
	for _, err := range errs {
		if err != nil {
			text += "\n" + err.Error()
		}
	}
	for _, canary := range []string{passwordCanary, oldPasswordCanary, totpCanary, "canary"} {
		if strings.Contains(text, canary) {
			t.Fatalf("%q reached a log line or an error: %q", canary, text)
		}
	}
	for _, path := range append(slices.Clone(store.writtenPaths), store.erasedPaths...) {
		if strings.Contains(path, "canary") {
			t.Fatalf("a path names a secret: %q", path)
		}
	}
}

// A sender's name and its registrable domain, the public suffix list's eTLD+1, and the names with none.
func TestMailRegistrableDomain(t *testing.T) {
	cases := map[string]string{
		"shop.example":                        "shop.example",
		"mail.accounts.shop.example":          "shop.example",
		"Mail.Shop.Example.":                  "shop.example",
		"mail.bank.example.co.uk":             "example.co.uk",
		"user.github.io":                      "user.github.io",
		"co.uk":                               "",
		"":                                    "",
		"192.0.2.1":                           "",
		"shop..example":                       "",
		"shop_x.example":                      "",
		"-shop.example":                       "",
		strings.Repeat("a.", 130) + "example": "",
	}
	for domain, want := range cases {
		got, ok := mailRegistrableDomain(domain)
		if got != want || ok != (want != "") {
			t.Errorf("%q: %q, %v", domain, got, ok)
		}
	}
}

// An erasure's note is its vault paths, one a line; any other note names none.
func TestMailVaultErasedPathsReadOnlyVaultNotes(t *testing.T) {
	first, second := MailVaultPath(evsTestId("first")), MailVaultPath(evsTestId("second"))
	if paths := mailVaultErasedPaths([]byte(first + "\n" + second)); !slices.Equal(paths, []string{first, second}) {
		t.Fatalf("%v", paths)
	}
	for _, note := range []string{"", "m/202611/00/x", first + "\nnot a path", first + "\n", strings.Replace(first, "vault/", "vault/0", 1)} {
		if paths := mailVaultErasedPaths([]byte(note)); len(paths) != 0 {
			t.Errorf("%q names %v", note, paths)
		}
	}
}
