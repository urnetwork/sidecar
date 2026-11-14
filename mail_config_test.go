// MAIL-M7-04's tests: mailcfg's records replayed per version on an in-memory repo with evs's path CAS, versions
// and signers, the outward actions through a stand-in gate that spends as §16.6's does, and the same paths over the
// evs stand-in, where every server-visible byte is scanned for an alias.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One version of a path in the test repo.
type mailConfigTestVersion struct {
	version    uint64
	signerId   Id
	removed    bool
	versioning uint32
	content    []byte
}

// A mailcfg repo in memory: every version of every path with its signer, evs's path CAS, and History's reach, a
// standing life or a removed path's last one. beforeWrite, when set, runs once with no lock held at the start of the
// next write, so a test lands a racing write between a writer's read and its write; loseAnswer commits the next
// write and answers it with an error, as a lost reply does.
type mailConfigTestRepo struct {
	repoId Id

	stateLock    sync.Mutex
	pathVersions map[string][]*mailConfigTestVersion
	beforeWrite  func()
	loseAnswer   error
	refuseWrite  error
	followers    map[int]func()
	nextFollower int
	writeCount   int
	failReads    error
}

func newMailConfigTestRepo() *mailConfigTestRepo {
	return &mailConfigTestRepo{
		repoId:       evsTestId("mailcfg repo"),
		pathVersions: map[string][]*mailConfigTestVersion{},
		followers:    map[int]func(){},
	}
}

// The newest version of path, nil where it never stood.
func (self *mailConfigTestRepo) newestWithLock(path string) *mailConfigTestVersion {
	versions := self.pathVersions[path]
	if len(versions) == 0 {
		return nil
	}
	return versions[len(versions)-1]
}

// Appends a version of path signed by signerId, a removal with nil content, with no CAS: what a writer outside the
// code under test commits. The version it made.
func (self *mailConfigTestRepo) commit(path string, signerId Id, content []byte) uint64 {
	version := func() uint64 {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.commitWithLock(path, signerId, content, 0)
	}()
	self.notify()
	return version
}

func (self *mailConfigTestRepo) commitWithLock(path string, signerId Id, content []byte, versioning uint32) uint64 {
	version := uint64(1)
	if newest := self.newestWithLock(path); newest != nil {
		version = newest.version + 1
	}
	self.pathVersions[path] = append(self.pathVersions[path], &mailConfigTestVersion{
		version: version, signerId: signerId, removed: content == nil, versioning: versioning, content: bytes.Clone(content),
	})
	return version
}

// Calls every follower, as a hint's read does.
func (self *mailConfigTestRepo) notify() {
	followers := func() []func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		followers := []func(){}
		for _, follower := range self.followers {
			followers = append(followers, follower)
		}
		return followers
	}()
	for _, follower := range followers {
		follower()
	}
}

// The paths that stand, sorted.
func (self *mailConfigTestRepo) standingPaths() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	paths := []string{}
	for path := range self.pathVersions {
		if newest := self.newestWithLock(path); newest != nil && !newest.removed {
			paths = append(paths, path)
		}
	}
	slices.Sort(paths)
	return paths
}

// How many versions path has, removals included.
func (self *mailConfigTestRepo) versionCount(path string) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.pathVersions[path])
}

// One device's mailConfigStore over the repo: its writes are signed by its sidecar.
type mailConfigTestStore struct {
	repo      *mailConfigTestRepo
	sidecarId Id
	unseated  bool
}

func (self *mailConfigTestStore) RepoId() Id { return self.repo.repoId }

func (self *mailConfigTestStore) Refresh(ctx context.Context) error {
	self.repo.stateLock.Lock()
	defer self.repo.stateLock.Unlock()
	return self.repo.failReads
}

func (self *mailConfigTestStore) Read(ctx context.Context, path string, maxByteCount int) ([]byte, uint64, error) {
	self.repo.stateLock.Lock()
	defer self.repo.stateLock.Unlock()
	if err := self.repo.failReads; err != nil {
		return nil, 0, err
	}
	newest := self.repo.newestWithLock(path)
	if newest == nil || newest.removed {
		return nil, 0, ErrEvsPathAbsent
	}
	if maxByteCount < len(newest.content) {
		return nil, 0, ErrMailStoreTooLarge
	}
	return bytes.Clone(newest.content), newest.version, nil
}

func (self *mailConfigTestStore) List(ctx context.Context, directory string) ([]string, error) {
	self.repo.stateLock.Lock()
	defer self.repo.stateLock.Unlock()
	if err := self.repo.failReads; err != nil {
		return nil, err
	}
	names := []string{}
	for path := range self.repo.pathVersions {
		if newest := self.repo.newestWithLock(path); newest == nil || newest.removed {
			continue
		}
		rest, ok := strings.CutPrefix(path, directory+"/")
		if !ok {
			continue
		}
		name, _, _ := strings.Cut(rest, "/")
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil, ErrEvsPathAbsent
	}
	slices.Sort(names)
	return names, nil
}

func (self *mailConfigTestStore) Write(ctx context.Context, writes []*mailStoreWrite) ([]uint64, error) {
	hook := func() func() {
		self.repo.stateLock.Lock()
		defer self.repo.stateLock.Unlock()
		hook := self.repo.beforeWrite
		self.repo.beforeWrite = nil
		return hook
	}()
	if hook != nil {
		hook()
	}
	versions, err := func() ([]uint64, error) {
		self.repo.stateLock.Lock()
		defer self.repo.stateLock.Unlock()
		self.repo.writeCount += 1
		if err := self.repo.refuseWrite; err != nil {
			self.repo.refuseWrite = nil
			return nil, err
		}
		conflicts := []string{}
		for _, write := range writes {
			current := uint64(0)
			if newest := self.repo.newestWithLock(write.Path); newest != nil && !newest.removed {
				current = newest.version
			}
			if current != write.IfVersion {
				conflicts = append(conflicts, write.Path)
			}
		}
		if 0 < len(conflicts) {
			return nil, &MailStoreConflictError{Paths: conflicts}
		}
		versions := []uint64{}
		for _, write := range writes {
			versions = append(versions, self.repo.commitWithLock(write.Path, self.sidecarId, write.Content, 0))
		}
		if err := self.repo.loseAnswer; err != nil {
			self.repo.loseAnswer = nil
			return nil, err
		}
		return versions, nil
	}()
	self.repo.notify()
	return versions, err
}

func (self *mailConfigTestStore) Versions(ctx context.Context, path string, maxCount int) ([]*mailConfigVersion, error) {
	self.repo.stateLock.Lock()
	defer self.repo.stateLock.Unlock()
	if err := self.repo.failReads; err != nil {
		return nil, err
	}
	all := self.repo.pathVersions[path]
	if len(all) == 0 {
		return nil, ErrEvsPathAbsent
	}
	// newest first, back to the creation of the newest life: History's reach
	versions := []*mailConfigVersion{}
	for index := len(all) - 1; 0 <= index; index -= 1 {
		version := all[index]
		versions = append(versions, &mailConfigVersion{
			Version: version.version, SignerSidecarId: version.signerId, Removed: version.removed, Versioning: version.versioning,
		})
		if !version.removed && (index == 0 || all[index-1].removed) {
			break
		}
	}
	if maxCount < len(versions) {
		return nil, ErrMailConfigReplayBound
	}
	return versions, nil
}

func (self *mailConfigTestStore) ReadVersion(ctx context.Context, path string, version uint64, maxByteCount int) ([]byte, error) {
	self.repo.stateLock.Lock()
	defer self.repo.stateLock.Unlock()
	for _, held := range self.repo.pathVersions[path] {
		if held.version == version && !held.removed {
			if maxByteCount < len(held.content) {
				return nil, ErrMailStoreTooLarge
			}
			return bytes.Clone(held.content), nil
		}
	}
	return nil, ErrEvsPathAbsent
}

func (self *mailConfigTestStore) Remove(ctx context.Context, path string, ifVersion uint64) error {
	err := func() error {
		self.repo.stateLock.Lock()
		defer self.repo.stateLock.Unlock()
		self.repo.writeCount += 1
		newest := self.repo.newestWithLock(path)
		if newest == nil || newest.removed {
			return ErrEvsPathAbsent
		}
		if newest.version != ifVersion {
			return &MailStoreConflictError{Paths: []string{path}}
		}
		self.repo.commitWithLock(path, self.sidecarId, nil, 0)
		return nil
	}()
	self.repo.notify()
	return err
}

func (self *mailConfigTestStore) Writable(ctx context.Context) error {
	if self.unseated {
		return ErrMailConfigUnseated
	}
	return nil
}

func (self *mailConfigTestStore) Follow(ctx context.Context, changed func()) (func(), error) {
	self.repo.stateLock.Lock()
	defer self.repo.stateLock.Unlock()
	index := self.repo.nextFollower
	self.repo.nextFollower += 1
	self.repo.followers[index] = changed
	return func() {
		self.repo.stateLock.Lock()
		defer self.repo.stateLock.Unlock()
		delete(self.repo.followers, index)
	}, nil
}

// Policy and the access log as a test sets them: which aliases each sidecar may listen on, by exact name or "*",
// and which sidecars may change a mailbox's records.
type mailConfigTestAuthority struct {
	stateLock       sync.Mutex
	listenAliases   map[Id][]string
	mailboxChangers map[Id][]Id
}

func newMailConfigTestAuthority() *mailConfigTestAuthority {
	return &mailConfigTestAuthority{listenAliases: map[Id][]string{}, mailboxChangers: map[Id][]Id{}}
}

func (self *mailConfigTestAuthority) HonorsRecord(creatorSidecarId Id, alias string, now time.Time) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	aliases := self.listenAliases[creatorSidecarId]
	return slices.Contains(aliases, "*") || slices.Contains(aliases, alias)
}

func (self *mailConfigTestAuthority) MayChangeRecord(signerSidecarId Id, mailboxRepoId Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Contains(self.mailboxChangers[mailboxRepoId], signerSidecarId)
}

func (self *mailConfigTestAuthority) grant(sidecarId Id, aliases ...string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.listenAliases[sidecarId] = aliases
}

func (self *mailConfigTestAuthority) own(mailboxRepoId Id, sidecarIds ...Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.mailboxChangers[mailboxRepoId] = sidecarIds
}

// §5.4's gate as §16.6 spends: an action's use is keyed by its stored bytes, its effect runs under that use's key,
// and a retry of the same action answers the recorded outcome without running the effect again unless that outcome
// is uncertain. standing runs every effect at once with an empty key and records nothing.
type mailConfigTestGate struct {
	stateLock sync.Mutex
	lookups   map[SidecarActionKind]SidecarEffectLookup
	outcomes  map[string]*SidecarOutcome
	actions   []*SidecarAction
	runCount  int
	pending   bool
	refusal   error
	standing  bool
}

func newMailConfigTestGate() *mailConfigTestGate {
	return &mailConfigTestGate{lookups: map[SidecarActionKind]SidecarEffectLookup{}, outcomes: map[string]*SidecarOutcome{}}
}

// The key of the use an action's bytes are spent under.
func mailConfigTestEffectKey(canonical []byte) []byte {
	key := sha256.Sum256(append([]byte("use of "), canonical...))
	return key[:]
}

func (self *mailConfigTestGate) Authorize(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error {
	recorded, err := func() (*SidecarOutcome, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.actions = append(self.actions, action)
		switch {
		case self.refusal != nil:
			return nil, self.refusal
		case self.pending:
			return nil, &ApprovalPendingError{ApprovalId: evsTestId("pending approval")}
		case self.lookups[action.Kind] == nil:
			return nil, errors.New("a kind with no registered lookup is refused before its reserve")
		}
		if outcome := self.outcomes[string(action.Canonical)]; outcome != nil && outcome.State != ApprovalOutcomeUncertain {
			return &SidecarOutcome{State: outcome.State, EffectRef: bytes.Clone(outcome.EffectRef)}, nil
		}
		self.runCount += 1
		return nil, nil
	}()
	if err != nil {
		return err
	}
	if recorded != nil {
		action.Outcome = recorded
		return nil
	}
	var effectKey []byte
	if !self.standing {
		effectKey = mailConfigTestEffectKey(action.Canonical)
	}
	effectRef, runErr := action.Effect.Run(ctx, effectKey)
	outcome := &SidecarOutcome{State: ApprovalOutcomeUncertain, Err: runErr}
	switch {
	case runErr == nil:
		outcome = &SidecarOutcome{State: ApprovalOutcomeDone, EffectRef: bytes.Clone(effectRef)}
	case errors.Is(runErr, ErrSidecarEffectNotDone):
		outcome = &SidecarOutcome{State: ApprovalOutcomeNotDone, Err: runErr}
	}
	if !self.standing {
		self.stateLock.Lock()
		self.outcomes[string(action.Canonical)] = outcome
		self.stateLock.Unlock()
	}
	action.Outcome = outcome
	return nil
}

func (self *mailConfigTestGate) RegisterEffectLookup(kind SidecarActionKind, lookup SidecarEffectLookup) func() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lookups[kind] = lookup
	return func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.lookups, kind)
	}
}

// The actions Authorize was handed, and how many effects it ran.
func (self *mailConfigTestGate) counts() (int, int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.actions), self.runCount
}

func (self *mailConfigTestGate) lastAction() *SidecarAction {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.actions[len(self.actions)-1]
}

var (
	testMailConfigPhoneId    = evsTestId("mailcfg owner's phone")
	testMailConfigDesktopId  = evsTestId("mailcfg owner's desktop")
	testMailConfigOtherId    = evsTestId("mailcfg another member's device")
	testMailConfigMailboxId  = evsTestId("mailcfg owner's mailbox")
	testMailConfigOtherBoxId = evsTestId("mailcfg another member's mailbox")
	testMailConfigGroupId    = evsTestId("mailcfg group repo")
)

const testMailConfigRoot = "root.example"

// The network every test device belongs to: label acme, alias widgets, an alias in its 90 days of retiring.
func testMailConfigNetwork() NetworkLabelRow {
	return NetworkLabelRow{Root: testMailConfigRoot, NetworkId: testNetworkId, Label: "acme", Alias: "widgets", RetiringAliases: []string{"gadgets"}}
}

// One device's MailConfig over the shared repo, with its own gate and alarms kept.
type mailConfigTestDevice struct {
	config    *MailConfig
	store     *mailConfigTestStore
	gate      *mailConfigTestGate
	authority *mailConfigTestAuthority
	clock     *mailTestClock
	stateLock sync.Mutex
	alarms    []*MailConfigAlarm
}

// The reasons of the alarms raised so far, in order.
func (self *mailConfigTestDevice) alarmReasons() []MailConfigAlarmReason {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	reasons := []MailConfigAlarmReason{}
	for _, alarm := range self.alarms {
		reasons = append(reasons, alarm.Reason)
	}
	return reasons
}

func newMailConfigTestDevice(t *testing.T, repo *mailConfigTestRepo, authority *mailConfigTestAuthority, sidecarId Id, mutate func(args *MailConfigArgs)) *mailConfigTestDevice {
	t.Helper()
	device := &mailConfigTestDevice{
		store:     &mailConfigTestStore{repo: repo, sidecarId: sidecarId},
		gate:      newMailConfigTestGate(),
		authority: authority,
		clock:     &mailTestClock{now: time.UnixMilli(1793923200000)},
	}
	args := &MailConfigArgs{
		Network:   testMailConfigNetwork,
		SidecarId: sidecarId,
		Authority: authority,
		Gate:      device.gate,
		Clock:     device.clock,
		Alarm: func(alarm *MailConfigAlarm) {
			device.stateLock.Lock()
			defer device.stateLock.Unlock()
			device.alarms = append(device.alarms, alarm)
		},
		Settings: DefaultMailConfigSettings(),
	}
	if mutate != nil {
		mutate(args)
	}
	device.config = newMailConfig(device.store, args)
	t.Cleanup(device.config.Close)
	return device
}

// The world most tests start in: the owner's phone and desktop may change the owner's mailbox's records, another
// member's device its own, and policy grants every device every alias.
func newMailConfigTestWorld(t *testing.T) (*mailConfigTestRepo, *mailConfigTestAuthority) {
	t.Helper()
	authority := newMailConfigTestAuthority()
	for _, sidecarId := range []Id{testMailConfigPhoneId, testMailConfigDesktopId, testMailConfigOtherId} {
		authority.grant(sidecarId, "*")
	}
	authority.own(testMailConfigMailboxId, testMailConfigPhoneId, testMailConfigDesktopId)
	authority.own(testMailConfigOtherBoxId, testMailConfigOtherId)
	authority.own(testMailConfigGroupId, testMailConfigPhoneId)
	return newMailConfigTestRepo(), authority
}

// address parsed under the test root.
func testMailConfigRecipient(t *testing.T, address string) MailRecipient {
	t.Helper()
	recipient, err := ParseMailRecipient(testMailConfigRoot, address)
	if err != nil {
		t.Fatalf("%s: %v", address, err)
	}
	return recipient
}

// Resolve of address, failing the test on an error.
func (self *mailConfigTestDevice) resolve(t *testing.T, address string) *MailAddressLookup {
	t.Helper()
	lookup, err := self.config.Resolve(context.Background(), testMailConfigRecipient(t, address))
	if err != nil {
		t.Fatalf("resolve %s: %v", address, err)
	}
	return lookup
}

// Sync, failing the test on an error.
func (self *mailConfigTestDevice) sync(t *testing.T) {
	t.Helper()
	if err := self.config.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// An id address of the owner's mailbox, created through the gate.
func (self *mailConfigTestDevice) createId(t *testing.T, localPart string) *MailAddressLookup {
	t.Helper()
	lookup, err := self.config.CreateAddress(context.Background(), &MailCreateAddressArgs{
		LocalPart: localPart, Kind: protocol.MailAddressKind_MAIL_ADDRESS_ID, MailboxRepoId: testMailConfigMailboxId,
	})
	if err != nil {
		t.Fatalf("create %s: %v", localPart, err)
	}
	return lookup
}

// An encoded MailAddress as a writer outside the code under test would commit it.
func testMailConfigAddressBytes(t *testing.T, kind protocol.MailAddressKind, mailboxRepoId Id, creatorId Id) []byte {
	t.Helper()
	content, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.MailAddress{Kind: kind, Mailbox: mailboxRepoId.Bytes(), Creator: creatorId.Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	return content
}

// An encoded MailBurner.
func testMailConfigBurnerBytes(t *testing.T, mailboxRepoId Id, state protocol.MailBurnerState) []byte {
	t.Helper()
	content, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.MailBurner{Mailbox: mailboxRepoId.Bytes(), State: state, Created: 1793923200000})
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func testMailConfigAddressPath(t *testing.T, address string) string {
	t.Helper()
	path, err := MailAddressPath(address)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func testMailConfigBurnerPath(t *testing.T, label string) string {
	t.Helper()
	path, err := MailBurnerPath(label)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// A created address resolves to its mailbox under the label, the alias and a retiring alias, on the creating device
// and on another after its Sync; admin's aliases reach admin's record; anything else is unknown.
func TestMailConfigCreatedAddressResolves(t *testing.T) {
	repo, authority := newMailConfigTestWorld(t)
	phone := newMailConfigTestDevice(t, repo, authority, testMailConfigPhoneId, nil)
	lookup := phone.createId(t, "ada")
	if !lookup.Known || lookup.MailboxRepoId != testMailConfigMailboxId || lookup.Address != "ada@acme.root.example" ||
		lookup.Kind != protocol.MailAddressKind_MAIL_ADDRESS_ID || lookup.CreatorSidecarId != testMailConfigPhoneId {
		t.Fatalf("created %+v", lookup)
	}
	if _, err := phone.config.CreateAddress(context.Background(), &MailCreateAddressArgs{
		Kind: protocol.MailAddressKind_MAIL_ADDRESS_ADMIN, MailboxRepoId: testMailConfigMailboxId,
	}); err != nil {
		t.Fatal(err)
	}
	if paths := repo.standingPaths(); !slices.Equal(paths, []string{
		testMailConfigAddressPath(t, "ada@acme.root.example"), testMailConfigAddressPath(t, "admin@acme.root.example"),
	}) && !slices.Equal(paths, []string{
		testMailConfigAddressPath(t, "admin@acme.root.example"), testMailConfigAddressPath(t, "ada@acme.root.example"),
	}) {
		t.Fatalf("paths %v", paths)
	}

	desktop := newMailConfigTestDevice(t, repo, authority, testMailConfigDesktopId, nil)
	desktop.sync(t)
	for _, device := range []*mailConfigTestDevice{phone, desktop} {
		for _, address := range []string{"ada@acme.root.example", "ADA@Acme.Root.Example", "ada@widgets.root.example", "ada@gadgets.root.example"} {
			if lookup := device.resolve(t, address); !lookup.Known || lookup.MailboxRepoId != testMailConfigMailboxId || lookup.Address != "ada@acme.root.example" {
				t.Errorf("%s: %+v", address, lookup)
			}
		}
		for _, address := range []string{"admin@acme.root.example", "postmaster@acme.root.example", "abuse@widgets.root.example"} {
			if lookup := device.resolve(t, address); !lookup.Known || lookup.Kind != protocol.MailAddressKind_MAIL_ADDRESS_ADMIN || lookup.Address != "admin@acme.root.example" {
				t.Errorf("%s: %+v", address, lookup)
			}
		}
		for _, address := range []string{
			// no record; another network's label and a released alias; a scope this mailcfg is not; a burner label
			// no record holds; a reverse alias; a bounce no record holds
			"grace@acme.root.example", "ada@other.root.example", "ada@released.root.example", "ada@team.acme.root.example",
			"shop@otter-4821.acme.root.example", "r-token@otter-4821.acme.root.example", "bounces+token@b.acme.root.example",
		} {
			if lookup := device.resolve(t, address); lookup.Known || lookup.MailboxRepoId != (Id{}) {
				t.Errorf("%s: %+v", address, lookup)
			}
		}
	}
	addresses, err := desktop.config.Addresses()
	if err != nil || len(addresses) != 2 || addresses[0].Address != "ada@acme.root.example" || addresses[1].Address != "admin@acme.root.example" {
		t.Fatalf("addresses %v, %v", addresses, err)
	}
	if reasons := append(phone.alarmReasons(), desktop.alarmReasons()...); len(reasons) != 0 {
		t.Errorf("alarms %v", reasons)
	}
}

// Before its first Sync a MailConfig answers neither known nor unknown, and a Sync that fails leaves it so; a
// network with no label resolves and creates nothing.
func TestMailConfigAnswersNothingBeforeItsFirstSync(t *testing.T) {
	repo, authority := newMailConfigTestWorld(t)
	phone := newMailConfigTestDevice(t, repo, authority, testMailConfigPhoneId, nil)
	phone.createId(t, "ada")
	desktop := newMailConfigTestDevice(t, repo, authority, testMailConfigDesktopId, nil)
	if _, err := desktop.config.Addresses(); !errors.Is(err, ErrMailConfigNotSynced) {
		t.Errorf("addresses before a sync: %v", err)
	}
	repo.failReads = errors.New("the store is away")
	recipient := testMailConfigRecipient(t, "ada@acme.root.example")
	if lookup, err := desktop.config.Resolve(context.Background(), recipient); !errors.Is(err, ErrMailConfigNotSynced) || lookup.Known {
		t.Fatalf("resolve with no sync: %+v, %v", lookup, err)
	}
	// the misses of an interval share that one failed Sync and its error
	if lookup, err := desktop.config.Resolve(context.Background(), recipient); !errors.Is(err, ErrMailConfigNotSynced) || lookup.Known {
		t.Fatalf("a second resolve: %+v, %v", lookup, err)
	}
	repo.failReads = nil
	desktop.clock.now = desktop.clock.now.Add(desktop.config.settings.MissRefreshInterval)
	if lookup := desktop.resolve(t, "ada@acme.root.example"); !lookup.Known {
		t.Fatalf("after the store came back: %+v", lookup)
	}

	unlabeled := newMailConfigTestDevice(t, repo, authority, testMailConfigPhoneId, func(args *MailConfigArgs) {
		args.Network = func() NetworkLabelRow { return NetworkLabelRow{Root: testMailConfigRoot, NetworkId: testNetworkId} }
	})
	if err := unlabeled.config.Sync(context.Background()); !errors.Is(err, ErrMailConfigNoZone) {
		t.Errorf("sync with no label: %v", err)
	}
	if _, err := unlabeled.config.CreateAddress(context.Background(), &MailCreateAddressArgs{
		LocalPart: "grace", Kind: protocol.MailAddressKind_MAIL_ADDRESS_ID, MailboxRepoId: testMailConfigMailboxId,
	}); !errors.Is(err, ErrMailConfigNoZone) {
		t.Errorf("create with no label: %v", err)
	}
}

// A record whose creator policy does not grant the alias's listen is ignored (D-ACL-12), judged at each read: it
// routes once the grant exists and stops when the grant ends. A device with no grant creates nothing.
func TestMailConfigIgnoresACreatorWithoutTheGrant(t *testing.T) {
	repo, authority := newMailConfigTestWorld(t)
	authority.grant(testMailConfigOtherId, "billing")
	path := testMailConfigAddressPath(t, "sales@acme.root.example")
	repo.commit(path, testMailConfigOtherId, testMailConfigAddressBytes(t, protocol.MailAddressKind_MAIL_ADDRESS_ID, testMailConfigOtherBoxId, testMailConfigOtherId))
	phone := newMailConfigTestDevice(t, repo, authority, testMailConfigPhoneId, nil)
	phone.sync(t)
	if lookup := phone.resolve(t, "sales@acme.root.example"); lookup.Known {
		t.Fatalf("a record from a creator with no grant: %+v", lookup)
	}
	authority.grant(testMailConfigOtherId, "billing", "sales")
	if lookup := phone.resolve(t, "sales@acme.root.example"); !lookup.Known || lookup.MailboxRepoId != testMailConfigOtherBoxId {
		t.Fatalf("once granted: %+v", lookup)
	}
	authority.grant(testMailConfigOtherId, "billing")
	if lookup := phone.resolve(t, "sales@acme.root.example"); lookup.Known {
		t.Fatalf("once the grant ended: %+v", lookup)
	}
	addresses, err := phone.config.Addresses()
	if err != nil || len(addresses) != 1 || addresses[0].Known {
		t.Errorf("listed %v, %v", addresses, err)
	}

	other := newMailConfigTestDevice(t, repo, authority, testMailConfigOtherId, nil)
	_, err = other.config.CreateAddress(context.Background(), &MailCreateAddressArgs{
		LocalPart: "support", Kind: protocol.MailAddressKind_MAIL_ADDRESS_ID, MailboxRepoId: testMailConfigOtherBoxId,
	})
	if !errors.Is(err, ErrMailConfigNoGrant) {
		t.Fatalf("a creation with no grant: %v", err)
	}
	if actions, _ := other.gate.counts(); actions != 0 || repo.versionCount(testMailConfigAddressPath(t, "support@acme.root.example")) != 0 {
		t.Error("a creation with no grant reached the gate or the repo")
	}
}

// A first version counts only when its creator field is its push's signer, and only as its path's record: each
// version passed over raises one alarm naming its signer and no address.
func TestMailConfigHoldsAFirstVersionToItsSigner(t *testing.T) {
	repo, authority := newMailConfigTestWorld(t)
	// another member's device writes a record naming the owner's phone as its creator
	forged := testMailConfigAddressPath(t, "forged@acme.root.example")
	repo.commit(forged, testMailConfigOtherId, testMailConfigAddressBytes(t, protocol.MailAddressKind_MAIL_ADDRESS_ID, testMailConfigOtherBoxId, testMailConfigPhoneId))
	// an admin record at a name that is not admin's, bytes that are no record, a record past its bound, and a name
	// that is no address of this zone
	repo.commit(testMailConfigAddressPath(t, "boss@acme.root.example"), testMailConfigOtherId,
		testMailConfigAddressBytes(t, protocol.MailAddressKind_MAIL_ADDRESS_ADMIN, testMailConfigOtherBoxId, testMailConfigOtherId))
	repo.commit(testMailConfigAddressPath(t, "junk@acme.root.example"), testMailConfigOtherId, []byte{0xff, 0xff, 0xff})
	repo.commit(testMailConfigAddressPath(t, "huge@acme.root.example"), testMailConfigOtherId, bytes.Repeat([]byte{0x0a, 0x00}, 16*1024))
	repo.commit(testMailConfigAddressPath(t, "ada@other.root.example"), testMailConfigOtherId,
		testMailConfigAddressBytes(t, protocol.MailAddressKind_MAIL_ADDRESS_ID, testMailConfigOtherBoxId, testMailConfigOtherId))
	phone := newMailConfigTestDevice(t, repo, authority, testMailConfigPhoneId, nil)
	phone.sync(t)
	for _, address := range []string{"forged@acme.root.example", "boss@acme.root.example", "junk@acme.root.example", "huge@acme.root.example"} {
		if lookup := phone.resolve(t, address); lookup.Known {
			t.Errorf("%s: %+v", address, lookup)
		}
	}
	reasons := phone.alarmReasons()
	slices.Sort(reasons)
	if !slices.Equal(reasons, []MailConfigAlarmReason{MailConfigAlarmCreator, MailConfigAlarmInvalid, MailConfigAlarmInvalid, MailConfigAlarmInvalid, MailConfigAlarmInvalid}) {
		t.Fatalf("alarms %v", reasons)
	}
	phone.stateLock.Lock()
	for _, alarm := range phone.alarms {
		if alarm.RepoId != repo.repoId || (alarm.Reason == MailConfigAlarmCreator && (alarm.SidecarId != testMailConfigOtherId || alarm.Version != 1)) {
			t.Errorf("alarm %+v", alarm)
		}
		if text := fmt.Sprintf("%+v", alarm); strings.Contains(text, "forged") || strings.Contains(text, "acme") {
			t.Errorf("an alarm names an address: %s", text)
		}
	}
	phone.stateLock.Unlock()
	// a second Sync replays nothing that did not move, and raises nothing twice
	phone.sync(t)
	if again := phone.alarmReasons(); len(again) != len(reasons) {
		t.Errorf("alarms raised again: %v", again)
	}
	// the forged name is taken all the same: created only if absent
	_, err := phone.config.CreateAddress(context.Background(), &MailCreateAddressArgs{
		LocalPart: "forged", Kind: protocol.MailAddressKind_MAIL_ADDRESS_ID, MailboxRepoId: testMailConfigMailboxId,
	})
	if !errors.Is(err, ErrMailConfigAddressTaken) || !errors.Is(err, ErrSidecarEffectNotDone) {
		t.Fatalf("a creation over a standing path: %v", err)
	}
}

// A later version counts only from a device that may change the record, and only when it keeps what no version
// changes (reading 15): another member's pause, redirect and removal of the owner's burner are passed over with
// alarms, the owner's own pause, resume and burn count, and a burned label stays burned whoever writes after it.
func TestMailConfigLaterVersionsCountOnlyFromTheOwner(t *testing.T) {
	repo, authority := newMailConfigTestWorld(t)
	path := testMailConfigBurnerPath(t, "otter-4821")
	repo.commit(path, testMailConfigPhoneId, testMailConfigBurnerBytes(t, testMailConfigMailboxId, protocol.MailBurnerState_MAIL_BURNER_LIVE))
	desktop := newMailConfigTestDevice(t, repo, authority, testMailConfigDesktopId, nil)
	const address = "shop@otter-4821.acme.root.example"
	check := func(step string, known bool, reasons ...MailConfigAlarmReason) {
		t.Helper()
		desktop.sync(t)
		lookup := desktop.resolve(t, address)
		if lookup.Known != known || (known && (lookup.MailboxRepoId != testMailConfigMailboxId || lookup.BurnerLabel != "otter-4821")) {
			t.Fatalf("%s: %+v", step, lookup)
		}
		if got := desktop.alarmReasons(); !slices.Equal(got, reasons) {
			t.Fatalf("%s: alarms %v, want %v", step, got, reasons)
		}
	}
	check("created", true)
	// any local part of a live label is the burner's
	if lookup := desktop.resolve(t, "anything.else@otter-4821.widgets.root.example"); !lookup.Known || lookup.Kind != protocol.MailAddressKind_MAIL_ADDRESS_BURNER {
		t.Fatalf("another local part: %+v", lookup)
	}

	repo.commit(path, testMailConfigOtherId, testMailConfigBurnerBytes(t, testMailConfigMailboxId, protocol.MailBurnerState_MAIL_BURNER_PAUSED))
	check("another member's pause", true, MailConfigAlarmSigner)
	repo.commit(path, testMailConfigOtherId, testMailConfigBurnerBytes(t, testMailConfigOtherBoxId, protocol.MailBurnerState_MAIL_BURNER_LIVE))
	check("another member's redirect", true, MailConfigAlarmSigner, MailConfigAlarmSigner)
	repo.commit(path, testMailConfigPhoneId, testMailConfigBurnerBytes(t, testMailConfigOtherBoxId, protocol.MailBurnerState_MAIL_BURNER_LIVE))
	check("the owner's own redirect", true, MailConfigAlarmSigner, MailConfigAlarmSigner, MailConfigAlarmChange)

	repo.commit(path, testMailConfigPhoneId, testMailConfigBurnerBytes(t, testMailConfigMailboxId, protocol.MailBurnerState_MAIL_BURNER_PAUSED))
	check("the owner's pause", false, MailConfigAlarmSigner, MailConfigAlarmSigner, MailConfigAlarmChange)
	repo.commit(path, testMailConfigDesktopId, testMailConfigBurnerBytes(t, testMailConfigMailboxId, protocol.MailBurnerState_MAIL_BURNER_LIVE))
	check("the owner's resume", true, MailConfigAlarmSigner, MailConfigAlarmSigner, MailConfigAlarmChange)
	repo.commit(path, testMailConfigPhoneId, testMailConfigBurnerBytes(t, testMailConfigMailboxId, protocol.MailBurnerState_MAIL_BURNER_BURNED))
	check("the owner's burn", false, MailConfigAlarmSigner, MailConfigAlarmSigner, MailConfigAlarmChange)
	repo.commit(path, testMailConfigPhoneId, testMailConfigBurnerBytes(t, testMailConfigMailboxId, protocol.MailBurnerState_MAIL_BURNER_LIVE))
	check("a resume of a burned label", false, MailConfigAlarmSigner, MailConfigAlarmSigner, MailConfigAlarmChange, MailConfigAlarmChange)

	// a device that reads the repo for the first time comes to the same record
	fresh := newMailConfigTestDevice(t, repo, authority, testMailConfigOtherId, nil)
	fresh.sync(t)
	if lookup := fresh.resolve(t, address); lookup.Known {
		t.Fatalf("a fresh reader: %+v", lookup)
	}
	burners, err := fresh.config.Burners()
	if err != nil || len(burners) != 1 || burners[0].Label != "otter-4821" || burners[0].State != protocol.MailBurnerState_MAIL_BURNER_BURNED ||
		burners[0].CreatorSidecarId != testMailConfigPhoneId {
		t.Fatalf("burners %+v, %v", burners, err)
	}
}

// A version written versionless counts for nothing in a mailcfg (§11.7's 409 VERSIONING, which a reader holds a
// server to): the record reads as the version before it.
func TestMailConfigPassesOverAVersionlessVersion(t *testing.T) {
	repo, authority := newMailConfigTestWorld(t)
	path := testMailConfigBurnerPath(t, "otter-4821")
	repo.commit(path, testMailConfigPhoneId, testMailConfigBurnerBytes(t, testMailConfigMailboxId, protocol.MailBurnerState_MAIL_BURNER_LIVE))
	func() {
		repo.stateLock.Lock()
		defer repo.stateLock.Unlock()
		repo.commitWithLock(path, testMailConfigPhoneId, testMailConfigBurnerBytes(t, testMailConfigMailboxId, protocol.MailBurnerState_MAIL_BURNER_BURNED), 1)
	}()
	phone := newMailConfigTestDevice(t, repo, authority, testMailConfigPhoneId, nil)
	phone.sync(t)
	if lookup := phone.resolve(t, "shop@otter-4821.acme.root.example"); !lookup.Known {
		t.Fatalf("after a versionless version: %+v", lookup)
	}
	if reasons := phone.alarmReasons(); !slices.Equal(reasons, []MailConfigAlarmReason{MailConfigAlarmVersioning}) {
		t.Fatalf("alarms %v", reasons)
	}
	// and a versionless first version is no record at all
	versionless := testMailConfigBurnerPath(t, "heron-0007")
	func() {
		repo.stateLock.Lock()
		defer repo.stateLock.Unlock()
		repo.commitWithLock(versionless, testMailConfigPhoneId, testMailConfigBurnerBytes(t, testMailConfigMailboxId, protocol.MailBurnerState_MAIL_BURNER_LIVE), 1)
	}()
	phone.sync(t)
	if lookup := phone.resolve(t, "shop@heron-0007.acme.root.example"); lookup.Known {
		t.Fatalf("a versionless first version: %+v", lookup)
	}
}

// A removal by a signer that may not change the record is passed over by a reader that holds it, and the record a
// life made after it replaces only when its creator may change the one it replaces: so another member's removal and
// re-creation of the owner's address route nothing to the new mailbox (I-14, R-MAIL-11), while the owner's own
// removal ends the address and frees the name.
func TestMailConfigAReleasedNameRoutesNothingToANewOwner(t *testing.T) {
	repo, authority := newMailConfigTestWorld(t)
	phone := newMailConfigTestDevice(t, repo, authority, testMailConfigPhoneId, nil)
	phone.createId(t, "ada")
	receiver := newMailConfigTestDevice(t, repo, authority, testMailConfigDesktopId, nil)
	receiver.sync(t)
	path := testMailConfigAddressPath(t, "ada@acme.root.example")
	takeover := testMailConfigAddressBytes(t, protocol.MailAddressKind_MAIL_ADDRESS_ID, testMailConfigOtherBoxId, testMailConfigOtherId)

	// the removal is seen first, then the re-creation
	repo.commit(path, testMailConfigOtherId, nil)
	receiver.sync(t)
	if lookup := receiver.resolve(t, "ada@acme.root.example"); !lookup.Known || lookup.MailboxRepoId != testMailConfigMailboxId {
		t.Fatalf("after another member's removal: %+v", lookup)
	}
	repo.commit(path, testMailConfigOtherId, takeover)
	receiver.sync(t)
	if lookup := receiver.resolve(t, "ada@acme.root.example"); !lookup.Known || lookup.MailboxRepoId != testMailConfigMailboxId {
		t.Fatalf("after another member's re-creation: %+v", lookup)
	}
	if reasons := receiver.alarmReasons(); !slices.Equal(reasons, []MailConfigAlarmReason{MailConfigAlarmSigner, MailConfigAlarmRecreated}) {
		t.Fatalf("alarms %v", reasons)
	}

	// both land between two Syncs of another reader, which never saw the removal
	late := newMailConfigTestDevice(t, repo, authority, testMailConfigPhoneId, nil)
	repo.commit(path, testMailConfigOtherId, nil)
	repo.commit(path, testMailConfigPhoneId, testMailConfigAddressBytes(t, protocol.MailAddressKind_MAIL_ADDRESS_ID, testMailConfigMailboxId, testMailConfigPhoneId))
	late.sync(t)
	repo.commit(path, testMailConfigOtherId, nil)
	repo.commit(path, testMailConfigOtherId, takeover)
	late.sync(t)
	if lookup := late.resolve(t, "ada@acme.root.example"); !lookup.Known || lookup.MailboxRepoId != testMailConfigMailboxId {
		t.Fatalf("a removal and re-creation between two syncs: %+v", lookup)
	}
	if reasons := late.alarmReasons(); !slices.Equal(reasons, []MailConfigAlarmReason{MailConfigAlarmRecreated}) {
		t.Fatalf("alarms %v", reasons)
	}

	// the owner's device takes the name back by removing the squat and creating the record again: the readers that
	// held the owner's record take it, since its creator may change that record
	if err := (&mailConfigTestStore{repo: repo, sidecarId: testMailConfigPhoneId}).Remove(context.Background(), path, uint64(repo.versionCount(path))); err != nil {
		t.Fatal(err)
	}
	repo.commit(path, testMailConfigDesktopId, testMailConfigAddressBytes(t, protocol.MailAddressKind_MAIL_ADDRESS_ID, testMailConfigMailboxId, testMailConfigDesktopId))
	receiver.sync(t)
	if lookup := receiver.resolve(t, "ada@acme.root.example"); !lookup.Known || lookup.CreatorSidecarId != testMailConfigDesktopId {
		t.Fatalf("after the owner made it again: %+v", lookup)
	}

	// the owner's own removal ends the address, and the name is free for another member
	if err := phone.config.DeleteAddress(context.Background(), &MailDeleteAddressArgs{LocalPart: "ada"}); err != nil {
		t.Fatal(err)
	}
	receiver.sync(t)
	if lookup := receiver.resolve(t, "ada@acme.root.example"); lookup.Known {
		t.Fatalf("after the owner's removal: %+v", lookup)
	}
	other := newMailConfigTestDevice(t, repo, authority, testMailConfigOtherId, nil)
	if _, err := other.config.CreateAddress(context.Background(), &MailCreateAddressArgs{
		LocalPart: "ada", Kind: protocol.MailAddressKind_MAIL_ADDRESS_ID, MailboxRepoId: testMailConfigOtherBoxId,
	}); err != nil {
		t.Fatal(err)
	}
	receiver.sync(t)
	if lookup := receiver.resolve(t, "ada@acme.root.example"); !lookup.Known || lookup.MailboxRepoId != testMailConfigOtherBoxId {
		t.Fatalf("a name its owner released, made by another member: %+v", lookup)
	}
}

// Creating an address is an outward action (I-8): nothing is written while the approval is pending, when the gate
// refuses or with no gate, and the record written once the gate passes carries the use's effect_key and this
// sidecar as creator. The action names the alias and nothing else.
func TestMailConfigCreatesOnlyOnceAuthorizePasses(t *testing.T) {
	repo, authority := newMailConfigTestWorld(t)
	phone := newMailConfigTestDevice(t, repo, authority, testMailConfigPhoneId, nil)
	path := testMailConfigAddressPath(t, "ada@acme.root.example")
	args := &MailCreateAddressArgs{
		LocalPart: "ada", Kind: protocol.MailAddressKind_MAIL_ADDRESS_ID, MailboxRepoId: testMailConfigMailboxId,
		Action: MailConfigActionArgs{Summary: "an agent's words"},
	}
	ctx := context.Background()

	phone.gate.pending = true
	var pending *ApprovalPendingError
	if _, err := phone.config.CreateAddress(ctx, args); !errors.As(err, &pending) {
		t.Fatalf("while pending: %v", err)
	}
	phone.gate.pending = false
	phone.gate.refusal = errors.New("the gate refuses")
	if _, err := phone.config.CreateAddress(ctx, args); err == nil || err.Error() != "the gate refuses" {
		t.Fatalf("refused: %v", err)
	}
	phone.gate.refusal = nil
	ungated := newMailConfigTestDevice(t, repo, authority, testMailConfigPhoneId, func(args *MailConfigArgs) { args.Gate = nil })
	if _, err := ungated.config.CreateAddress(ctx, args); !errors.Is(err, ErrMailConfigNoGate) {
		t.Fatalf("with no gate: %v", err)
	}
	if repo.versionCount(path) != 0 || repo.writeCount != 0 {
		t.Fatal("a record was written before Authorize passed")
	}

	lookup, err := phone.config.CreateAddress(ctx, args)
	if err != nil || !lookup.Known {
		t.Fatalf("created %+v, %v", lookup, err)
	}
	action := phone.gate.lastAction()
	stored, err := ParseStoredCanonicalAction(action.Canonical)
	if err != nil {
		t.Fatal(err)
	}
	want := &protocol.CanonicalAction{Kind: uint32(SidecarActionAliasCreate), Alias: "ada", Version: 1}
	if !proto.Equal(stored.Action, want) || action.Kind != SidecarActionAliasCreate || action.Risk != SidecarRiskNormal || action.Summary != "an agent's words" {
		t.Fatalf("action %+v", stored.Action)
	}
	content, version, err := phone.store.Read(ctx, path, 1024)
	if err != nil || version != 1 {
		t.Fatalf("the record: %v at %d", err, version)
	}
	record := &protocol.MailAddress{}
	if err := proto.Unmarshal(content, record); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(record.GetEffectKey(), mailConfigTestEffectKey(action.Canonical)) || !bytes.Equal(record.GetCreator(), testMailConfigPhoneId.Bytes()) ||
		!bytes.Equal(record.GetMailbox(), testMailConfigMailboxId.Bytes()) || record.GetKind() != protocol.MailAddressKind_MAIL_ADDRESS_ID {
		t.Fatalf("record %+v", record)
	}
	// reserved names and names out of grammar never reach the gate
	actions, _ := phone.gate.counts()
	for _, localPart := range []string{"admin", "postmaster", "r-token", "Ada", "", "a b"} {
		_, err := phone.config.CreateAddress(ctx, &MailCreateAddressArgs{LocalPart: localPart, Kind: protocol.MailAddressKind_MAIL_ADDRESS_ID, MailboxRepoId: testMailConfigMailboxId})
		if !errors.Is(err, ErrMailLocalPartInvalid) && !errors.Is(err, ErrMailLocalPartReserved) {
			t.Errorf("%q: %v", localPart, err)
		}
	}
	if after, _ := phone.gate.counts(); after != actions {
		t.Error("a name out of grammar reached the gate")
	}
}

// An unseated device waits keyless and creates no address (§8.12): refused before any approval is asked for.
func TestMailConfigAnUnseatedDeviceCreatesNothing(t *testing.T) {
	repo, authority := newMailConfigTestWorld(t)
	phone := newMailConfigTestDevice(t, repo, authority, testMailConfigPhoneId, func(args *MailConfigArgs) {
		args.BurnerLabels = func(effectKey []byte) []string { return []string{"otter-4821"} }
	})
	seated := newMailConfigTestDevice(t, repo, authority, testMailConfigDesktopId, nil)
	seated.createId(t, "ada")
	path := testMailConfigBurnerPath(t, "heron-0007")
	repo.commit(path, testMailConfigDesktopId, testMailConfigBurnerBytes(t, testMailConfigMailboxId, protocol.MailBurnerState_MAIL_BURNER_LIVE))
	writes := repo.writeCount
	phone.store.unseated = true
	ctx := context.Background()
	if _, err := phone.config.CreateAddress(ctx, &MailCreateAddressArgs{LocalPart: "grace", Kind: protocol.MailAddressKind_MAIL_ADDRESS_ID, MailboxRepoId: testMailConfigMailboxId}); !errors.Is(err, ErrMailConfigUnseated) {
		t.Errorf("create: %v", err)
	}
	if _, err := phone.config.CreateBurnerRecord(ctx, &MailCreateBurnerArgs{Alias: "shop", MailboxRepoId: testMailConfigMailboxId}); !errors.Is(err, ErrMailConfigUnseated) {
		t.Errorf("create burner: %v", err)
	}
	if err := phone.config.DeleteAddress(ctx, &MailDeleteAddressArgs{LocalPart: "ada"}); !errors.Is(err, ErrMailConfigUnseated) {
		t.Errorf("delete: %v", err)
	}
	if err := phone.config.SetBurnerState(ctx, "heron-0007", protocol.MailBurnerState_MAIL_BURNER_BURNED); !errors.Is(err, ErrMailConfigUnseated) {
		t.Errorf("burn: %v", err)
	}
	if actions, _ := phone.gate.counts(); actions != 0 || repo.writeCount != writes {
		t.Error("an unseated device reached the gate or the repo")
	}
	// it still reads
	phone.sync(t)
	if lookup := phone.resolve(t, "ada@acme.root.example"); !lookup.Known {
		t.Errorf("an unseated device's read: %+v", lookup)
	}
}

// Two creators of one address: one wins, and the other is answered that the address is taken and sees the winner.
func TestMailConfigTwoCreatorsOfOneAddress(t *testing.T) {
	repo, authority := newMailConfigTestWorld(t)
	phone := newMailConfigTestDevice(t, repo, authority, testMailConfigPhoneId, nil)
	other := newMailConfigTestDevice(t, repo, authority, testMailConfigOtherId, nil)
	ctx := context.Background()
	// the other's creation lands between the phone's read of the path and its write
	repo.beforeWrite = func() {
		if _, err := other.config.CreateAddress(ctx, &MailCreateAddressArgs{
			LocalPart: "sales", Kind: protocol.MailAddressKind_MAIL_ADDRESS_ID, MailboxRepoId: testMailConfigOtherBoxId,
		}); err != nil {
			t.Errorf("the racing creation: %v", err)
		}
	}
	_, err := phone.config.CreateAddress(ctx, &MailCreateAddressArgs{LocalPart: "sales", Kind: protocol.MailAddressKind_MAIL_ADDRESS_ID, MailboxRepoId: testMailConfigMailboxId})
	if !errors.Is(err, ErrMailConfigAddressTaken) || !errors.Is(err, ErrSidecarEffectNotDone) {
		t.Fatalf("the loser: %v", err)
	}
	if strings.Contains(err.Error(), "sales") {
		t.Errorf("the error names the address: %v", err)
	}
	path := testMailConfigAddressPath(t, "sales@acme.root.example")
	if repo.versionCount(path) != 1 {
		t.Fatalf("%d versions of the address", repo.versionCount(path))
	}
	for _, device := range []*mailConfigTestDevice{phone, other} {
		if lookup := device.resolve(t, "sales@acme.root.example"); !lookup.Known || lookup.MailboxRepoId != testMailConfigOtherBoxId || lookup.CreatorSidecarId != testMailConfigOtherId {
			t.Errorf("the winner as each sees it: %+v", lookup)
		}
	}
	// the loser's use is spent as not_done: the same action again runs no effect and writes nothing
	_, runs := phone.gate.counts()
	_, err = phone.config.CreateAddress(ctx, &MailCreateAddressArgs{LocalPart: "sales", Kind: protocol.MailAddressKind_MAIL_ADDRESS_ID, MailboxRepoId: testMailConfigMailboxId})
	if _, after := phone.gate.counts(); !errors.Is(err, ErrSidecarEffectNotDone) || after != runs || repo.versionCount(path) != 1 {
		t.Fatalf("the loser's retry: %v", err)
	}
}

// A creation whose answer is lost finds its own record by the use's effect_key and writes no second one; a restart's
// Lookup, from the stored action and the key alone, answers done for a record this sidecar created under the key,
// not_done where another's holds the address, and uncertain while nothing stands.
func TestMailConfigLookupFindsItsOwnRecord(t *testing.T) {
	repo, authority := newMailConfigTestWorld(t)
	phone := newMailConfigTestDevice(t, repo, authority, testMailConfigPhoneId, nil)
	ctx := context.Background()
	path := testMailConfigAddressPath(t, "ada@acme.root.example")

	stored, err := NewCanonicalAction(&protocol.CanonicalAction{Kind: uint32(SidecarActionAliasCreate), Alias: "ada"})
	if err != nil {
		t.Fatal(err)
	}
	key := mailConfigTestEffectKey(stored.Bytes)
	lookup := phone.gate.lookups[SidecarActionAliasCreate]
	if lookup == nil || phone.gate.lookups[SidecarActionAliasDelete] == nil {
		t.Fatal("the lookups are not registered")
	}
	if outcome, err := lookup(ctx, stored.Bytes, key); err != nil || outcome.State != ApprovalOutcomeUncertain {
		t.Fatalf("before any write: %+v, %v", outcome, err)
	}

	repo.loseAnswer = errors.New("the answer was lost")
	created, err := phone.config.CreateAddress(ctx, &MailCreateAddressArgs{LocalPart: "ada", Kind: protocol.MailAddressKind_MAIL_ADDRESS_ID, MailboxRepoId: testMailConfigMailboxId})
	if err != nil || !created.Known || repo.versionCount(path) != 1 {
		t.Fatalf("a creation whose answer was lost: %+v, %v, %d versions", created, err, repo.versionCount(path))
	}

	// a restart: another MailConfig of the same sidecar, with no caller alive
	restarted := newMailConfigTestDevice(t, repo, authority, testMailConfigPhoneId, nil)
	outcome, err := restarted.config.Lookup(ctx, stored.Bytes, key)
	version, label, ok := parseMailConfigEffectRef(outcome.EffectRef)
	if err != nil || outcome.State != ApprovalOutcomeDone || !ok || version != 1 || label != "" {
		t.Fatalf("after a restart: %+v, %v", outcome, err)
	}
	// the same use run again finds the record and writes nothing
	effect := &mailConfigCreateAddressEffect{config: restarted.config, name: &mailConfigName{key: "ada@acme.root.example", alias: "ada", path: path},
		address: &protocol.MailAddress{Kind: protocol.MailAddressKind_MAIL_ADDRESS_ID, Mailbox: testMailConfigMailboxId.Bytes(), Creator: testMailConfigPhoneId.Bytes()}}
	if effectRef, err := effect.Run(ctx, key); err != nil || !bytes.Equal(effectRef, outcome.EffectRef) || repo.versionCount(path) != 1 {
		t.Fatalf("the use run again: %x, %v", effectRef, err)
	}

	// another use, or another sidecar, is not this record's: the address is another's
	otherKey := mailConfigTestEffectKey([]byte("another use"))
	if outcome, err := restarted.config.Lookup(ctx, stored.Bytes, otherKey); err != nil || outcome.State != ApprovalOutcomeNotDone {
		t.Fatalf("another use's key: %+v, %v", outcome, err)
	}
	other := newMailConfigTestDevice(t, repo, authority, testMailConfigOtherId, nil)
	if outcome, err := other.config.Lookup(ctx, stored.Bytes, key); err != nil || outcome.State != ApprovalOutcomeNotDone {
		t.Fatalf("another sidecar under the same key: %+v, %v", outcome, err)
	}
	// with a label drawer installed the action alone does not say whether it made an address or a burner
	restarted.config.SetBurnerLabels(func(effectKey []byte) []string { return []string{"otter-4821"} })
	if outcome, err := restarted.config.Lookup(ctx, stored.Bytes, otherKey); err != nil || outcome.State != ApprovalOutcomeUncertain {
		t.Fatalf("another use's key with a drawer: %+v, %v", outcome, err)
	}
	// a standing grant's creation keeps no row, and an action of another kind is not this component's
	if outcome, err := restarted.config.Lookup(ctx, stored.Bytes, nil); err != nil || outcome.State != ApprovalOutcomeUncertain {
		t.Fatalf("an empty key: %+v, %v", outcome, err)
	}
	if _, err := restarted.config.Lookup(ctx, []byte{0xff}, key); !errors.Is(err, ErrMailConfigInvalid) {
		t.Fatalf("bytes that are no action: %v", err)
	}
	// Close removes the lookups, so the kinds are refused before their reserve again
	restarted.config.Close()
	if len(restarted.gate.lookups) != 0 {
		t.Error("Close left a lookup registered")
	}
}

// A write that evs refuses for a due path epoch is tried again and lands; a full directory is a refusal, never a
// retry; and under a standing grant, with no key, a creation is still created only if absent.
func TestMailConfigCreationRetriesAndRefusals(t *testing.T) {
	repo, authority := newMailConfigTestWorld(t)
	phone := newMailConfigTestDevice(t, repo, authority, testMailConfigPhoneId, nil)
	ctx := context.Background()
	repo.refuseWrite = ErrEvsPathEpochDue
	if lookup, err := phone.config.CreateAddress(ctx, &MailCreateAddressArgs{LocalPart: "ada", Kind: protocol.MailAddressKind_MAIL_ADDRESS_ID, MailboxRepoId: testMailConfigMailboxId}); err != nil || !lookup.Known {
		t.Fatalf("after a due path epoch: %+v, %v", lookup, err)
	}
	if repo.writeCount != 2 {
		t.Errorf("%d writes", repo.writeCount)
	}
	full := &EvsError{Status: 409, Code: protocol.EvsRefusalCode_EVS_REFUSAL_DIRECTORY_FULL}
	repo.refuseWrite = full
	_, err := phone.config.CreateAddress(ctx, &MailCreateAddressArgs{LocalPart: "grace", Kind: protocol.MailAddressKind_MAIL_ADDRESS_ID, MailboxRepoId: testMailConfigMailboxId})
	if !IsMailDirectoryFull(err) || !errors.Is(err, ErrSidecarEffectNotDone) || repo.writeCount != 3 {
		t.Fatalf("a full directory: %v after %d writes", err, repo.writeCount)
	}

	standing := newMailConfigTestDevice(t, repo, authority, testMailConfigDesktopId, nil)
	standing.gate.standing = true
	args := &MailCreateAddressArgs{LocalPart: "lin", Kind: protocol.MailAddressKind_MAIL_ADDRESS_ID, MailboxRepoId: testMailConfigMailboxId}
	if _, err := standing.config.CreateAddress(ctx, args); err != nil {
		t.Fatal(err)
	}
	path := testMailConfigAddressPath(t, "lin@acme.root.example")
	content, _, err := standing.store.Read(ctx, path, 1024)
	record := &protocol.MailAddress{}
	if err != nil || proto.Unmarshal(content, record) != nil || len(record.GetEffectKey()) != 0 {
		t.Fatalf("a standing grant's record: %+v, %v", record, err)
	}
	// the same creation again is the same record; another device's is refused
	if _, err := standing.config.CreateAddress(ctx, args); err != nil || repo.versionCount(path) != 1 {
		t.Fatalf("the same creation again: %v", err)
	}
	other := newMailConfigTestDevice(t, repo, authority, testMailConfigOtherId, nil)
	other.gate.standing = true
	if _, err := other.config.CreateAddress(ctx, &MailCreateAddressArgs{LocalPart: "lin", Kind: protocol.MailAddressKind_MAIL_ADDRESS_ID, MailboxRepoId: testMailConfigOtherBoxId}); !errors.Is(err, ErrMailConfigAddressTaken) {
		t.Fatalf("another device's creation of a standing address: %v", err)
	}
}

// Deleting an address is an outward action whose effect is the record's removal, held to the version read: only a
// device that may change the record deletes it, the action names the repo, the path and that version, and a
// restart's Lookup finds this sidecar's removal.
func TestMailConfigDeleteAddress(t *testing.T) {
	repo, authority := newMailConfigTestWorld(t)
	phone := newMailConfigTestDevice(t, repo, authority, testMailConfigPhoneId, nil)
	other := newMailConfigTestDevice(t, repo, authority, testMailConfigOtherId, nil)
	ctx := context.Background()
	phone.createId(t, "ada")
	path := testMailConfigAddressPath(t, "ada@acme.root.example")

	if err := other.config.DeleteAddress(ctx, &MailDeleteAddressArgs{LocalPart: "ada"}); !errors.Is(err, ErrMailConfigNotOwner) {
		t.Fatalf("another member's delete: %v", err)
	}
	if err := phone.config.DeleteAddress(ctx, &MailDeleteAddressArgs{LocalPart: "grace"}); !errors.Is(err, ErrMailConfigAddressAbsent) {
		t.Fatalf("a delete of no address: %v", err)
	}
	phone.gate.pending = true
	var pending *ApprovalPendingError
	if err := phone.config.DeleteAddress(ctx, &MailDeleteAddressArgs{LocalPart: "ada"}); !errors.As(err, &pending) || repo.versionCount(path) != 1 {
		t.Fatalf("while pending: %v", err)
	}
	phone.gate.pending = false

	stored, err := NewCanonicalAction(&protocol.CanonicalAction{
		Kind: uint32(SidecarActionAliasDelete), RepoId: repo.repoId.Bytes(), Path: path, Alias: "ada", BaseVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome, err := phone.config.Lookup(ctx, stored.Bytes, nil); err != nil || outcome.State != ApprovalOutcomeUncertain {
		t.Fatalf("before the removal: %+v, %v", outcome, err)
	}
	if err := phone.config.DeleteAddress(ctx, &MailDeleteAddressArgs{LocalPart: "ada"}); err != nil {
		t.Fatal(err)
	}
	if action := phone.gate.lastAction(); !bytes.Equal(action.Canonical, stored.Bytes) || action.Kind != SidecarActionAliasDelete {
		t.Fatalf("the action is not the alias's removal at its version")
	}
	if lookup := phone.resolve(t, "ada@acme.root.example"); lookup.Known || len(repo.standingPaths()) != 0 {
		t.Fatalf("after the delete: %+v", lookup)
	}
	restarted := newMailConfigTestDevice(t, repo, authority, testMailConfigPhoneId, nil)
	outcome, err := restarted.config.Lookup(ctx, stored.Bytes, nil)
	if version, _, ok := parseMailConfigEffectRef(outcome.EffectRef); err != nil || outcome.State != ApprovalOutcomeDone || !ok || version != 2 {
		t.Fatalf("after a restart: %+v, %v", outcome, err)
	}
	// another sidecar's removal is not this sidecar's effect, and an action of another repo or path is refused
	if outcome, err := other.config.Lookup(ctx, stored.Bytes, nil); err != nil || outcome.State != ApprovalOutcomeNotDone {
		t.Fatalf("another sidecar's lookup: %+v, %v", outcome, err)
	}
	foreign, err := NewCanonicalAction(&protocol.CanonicalAction{
		Kind: uint32(SidecarActionAliasDelete), RepoId: evsTestId("another repo").Bytes(), Path: path, Alias: "ada", BaseVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := phone.config.Lookup(ctx, foreign.Bytes, nil); !errors.Is(err, ErrMailConfigInvalid) {
		t.Fatalf("an action of another repo: %v", err)
	}
	// a path that moved past the action's version can never take its removal
	phone.createId(t, "lin")
	linPath := testMailConfigAddressPath(t, "lin@acme.root.example")
	effect := &mailConfigDeleteAddressEffect{config: phone.config, name: &mailConfigName{key: "lin@acme.root.example", alias: "lin", path: linPath}, baseVersion: 7}
	if _, err := effect.Run(ctx, nil); !errors.Is(err, ErrSidecarEffectNotDone) || repo.versionCount(linPath) != 1 {
		t.Fatalf("a removal on a version the path is not at: %v", err)
	}
}

// A burner's record takes the first of its use's labels whose path never stood, so a burned or removed label is
// never reissued (§15.9, R-MAIL-11); a retry under the same use leaves one burner; a burn and a pause are local and
// answer unknown from then on; a burned label stays burned.
func TestMailConfigBurnerRecords(t *testing.T) {
	repo, authority := newMailConfigTestWorld(t)
	drawn := []string{"otter-4821", "heron-0007", "lynx-1234"}
	phone := newMailConfigTestDevice(t, repo, authority, testMailConfigPhoneId, func(args *MailConfigArgs) {
		args.BurnerLabels = func(effectKey []byte) []string { return drawn }
	})
	ctx := context.Background()
	undrawn := newMailConfigTestDevice(t, repo, authority, testMailConfigPhoneId, nil)
	if _, err := undrawn.config.CreateBurnerRecord(ctx, &MailCreateBurnerArgs{Alias: "shop", MailboxRepoId: testMailConfigMailboxId}); !errors.Is(err, ErrMailConfigNoGate) {
		t.Fatalf("with no label drawer: %v", err)
	}

	// the first creation's answer is lost: the same use again finds its label and makes no second burner
	repo.loseAnswer = errors.New("the answer was lost")
	first, err := phone.config.CreateBurnerRecord(ctx, &MailCreateBurnerArgs{Alias: "shop", MailboxRepoId: testMailConfigMailboxId})
	if err != nil || first.Label != "otter-4821" || first.State != protocol.MailBurnerState_MAIL_BURNER_LIVE || first.CreatedMillis != 1793923200000 || !first.Granted {
		t.Fatalf("the first burner: %+v, %v", first, err)
	}
	again, err := phone.config.CreateBurnerRecord(ctx, &MailCreateBurnerArgs{Alias: "shop", MailboxRepoId: testMailConfigMailboxId})
	if err != nil || again.Label != "otter-4821" || len(repo.standingPaths()) != 1 {
		t.Fatalf("the same use again: %+v, %v", again, err)
	}
	if lookup := phone.resolve(t, "shop@otter-4821.acme.root.example"); !lookup.Known || lookup.MailboxRepoId != testMailConfigMailboxId {
		t.Fatalf("a live burner: %+v", lookup)
	}
	action := phone.gate.lastAction()
	if outcome, err := phone.config.Lookup(ctx, action.Canonical, mailConfigTestEffectKey(action.Canonical)); err != nil || outcome.State != ApprovalOutcomeDone {
		t.Fatalf("the burner's lookup: %+v, %v", outcome, err)
	}

	// another use draws the same labels and takes the next one that never stood
	second, err := phone.config.CreateBurnerRecord(ctx, &MailCreateBurnerArgs{Alias: "news", MailboxRepoId: testMailConfigMailboxId})
	if err != nil || second.Label != "heron-0007" {
		t.Fatalf("the second burner: %+v, %v", second, err)
	}

	// pause and resume, then burn: local, with no approval
	actions, _ := phone.gate.counts()
	if err := phone.config.SetBurnerState(ctx, "otter-4821", protocol.MailBurnerState_MAIL_BURNER_PAUSED); err != nil {
		t.Fatal(err)
	}
	if lookup := phone.resolve(t, "shop@otter-4821.acme.root.example"); lookup.Known {
		t.Fatalf("a paused burner: %+v", lookup)
	}
	if err := phone.config.SetBurnerState(ctx, "otter-4821", protocol.MailBurnerState_MAIL_BURNER_LIVE); err != nil {
		t.Fatal(err)
	}
	if lookup := phone.resolve(t, "shop@otter-4821.acme.root.example"); !lookup.Known {
		t.Fatalf("a resumed burner: %+v", lookup)
	}
	if err := phone.config.SetBurnerState(ctx, "otter-4821", protocol.MailBurnerState_MAIL_BURNER_BURNED); err != nil {
		t.Fatal(err)
	}
	versions := repo.versionCount(testMailConfigBurnerPath(t, "otter-4821"))
	if err := phone.config.SetBurnerState(ctx, "otter-4821", protocol.MailBurnerState_MAIL_BURNER_BURNED); err != nil || repo.versionCount(testMailConfigBurnerPath(t, "otter-4821")) != versions {
		t.Fatalf("a burn of a burned label: %v", err)
	}
	for _, state := range []protocol.MailBurnerState{protocol.MailBurnerState_MAIL_BURNER_LIVE, protocol.MailBurnerState_MAIL_BURNER_PAUSED} {
		if err := phone.config.SetBurnerState(ctx, "otter-4821", state); !errors.Is(err, ErrMailConfigBurned) {
			t.Fatalf("state %v of a burned label: %v", state, err)
		}
	}
	if after, _ := phone.gate.counts(); after != actions {
		t.Error("a burn or a pause asked the gate")
	}
	if lookup := phone.resolve(t, "shop@otter-4821.acme.root.example"); lookup.Known {
		t.Fatalf("a burned burner: %+v", lookup)
	}
	// another member's device changes none of it
	other := newMailConfigTestDevice(t, repo, authority, testMailConfigOtherId, nil)
	if err := other.config.SetBurnerState(ctx, "heron-0007", protocol.MailBurnerState_MAIL_BURNER_BURNED); !errors.Is(err, ErrMailConfigNotOwner) {
		t.Fatalf("another member's burn: %v", err)
	}
	if err := phone.config.SetBurnerState(ctx, "wolf-9999", protocol.MailBurnerState_MAIL_BURNER_BURNED); !errors.Is(err, ErrMailConfigAddressAbsent) {
		t.Fatalf("a burn of no label: %v", err)
	}

	// the owner removes a label outright: burned for good to a reader that held it, and never drawn again even
	// once its path stands absent
	lynx := testMailConfigBurnerPath(t, "lynx-1234")
	repo.commit(lynx, testMailConfigPhoneId, testMailConfigBurnerBytes(t, testMailConfigMailboxId, protocol.MailBurnerState_MAIL_BURNER_LIVE))
	phone.sync(t)
	repo.commit(lynx, testMailConfigDesktopId, nil)
	phone.sync(t)
	if lookup := phone.resolve(t, "shop@lynx-1234.acme.root.example"); lookup.Known {
		t.Fatalf("a removed label: %+v", lookup)
	}
	_, err = phone.config.CreateBurnerRecord(ctx, &MailCreateBurnerArgs{Alias: "forum", MailboxRepoId: testMailConfigMailboxId})
	if !errors.Is(err, ErrMailConfigAddressTaken) || !errors.Is(err, ErrSidecarEffectNotDone) {
		t.Fatalf("a use whose every label stood: %v", err)
	}
	if len(repo.standingPaths()) != 2 {
		t.Fatalf("paths %v", repo.standingPaths())
	}
	// and another member making the removed label again routes nothing to its mailbox on that reader
	repo.commit(lynx, testMailConfigOtherId, testMailConfigBurnerBytes(t, testMailConfigOtherBoxId, protocol.MailBurnerState_MAIL_BURNER_LIVE))
	phone.sync(t)
	if lookup := phone.resolve(t, "shop@lynx-1234.acme.root.example"); lookup.Known {
		t.Fatalf("a removed label made again: %+v", lookup)
	}
	burners, err := phone.config.Burners()
	if err != nil || len(burners) != 3 || burners[0].Label != "heron-0007" || burners[1].Label != "lynx-1234" || burners[1].State != protocol.MailBurnerState_MAIL_BURNER_BURNED ||
		burners[2].Label != "otter-4821" || burners[2].State != protocol.MailBurnerState_MAIL_BURNER_BURNED {
		t.Fatalf("burners %+v, %v", burners, err)
	}
	// a label policy grants no listen on is passed over for the next
	authority.grant(testMailConfigDesktopId, "wren-0001")
	desktop := newMailConfigTestDevice(t, repo, authority, testMailConfigDesktopId, func(args *MailConfigArgs) {
		args.BurnerLabels = func(effectKey []byte) []string { return []string{"crow-0002", "wren-0001"} }
	})
	if burner, err := desktop.config.CreateBurnerRecord(ctx, &MailCreateBurnerArgs{Alias: "shop", MailboxRepoId: testMailConfigMailboxId}); err != nil || burner.Label != "wren-0001" {
		t.Fatalf("a burner past an ungranted label: %+v, %v", burner, err)
	}
}

// A group address's members change as later versions within mail_group_members, by a device that may change the
// group's records; an alias of a group delivers to the group's repo.
func TestMailConfigGroupMembers(t *testing.T) {
	repo, authority := newMailConfigTestWorld(t)
	phone := newMailConfigTestDevice(t, repo, authority, testMailConfigPhoneId, func(args *MailConfigArgs) {
		args.Settings.GroupMemberMaxCount = 3
	})
	ctx := context.Background()
	members := []Id{evsTestId("member a"), evsTestId("member b"), evsTestId("member c"), evsTestId("member d")}
	if _, err := phone.config.CreateAddress(ctx, &MailCreateAddressArgs{
		LocalPart: "team", Kind: protocol.MailAddressKind_MAIL_ADDRESS_GROUP, MailboxRepoId: testMailConfigGroupId, MemberIds: members,
	}); !errors.Is(err, ErrMailConfigGroupFull) {
		t.Fatalf("a group created past its bound: %v", err)
	}
	created, err := phone.config.CreateAddress(ctx, &MailCreateAddressArgs{
		LocalPart: "team", Kind: protocol.MailAddressKind_MAIL_ADDRESS_GROUP, MailboxRepoId: testMailConfigGroupId, MemberIds: members[:1],
	})
	if err != nil || len(created.MemberIds) != 1 || created.MailboxRepoId != testMailConfigGroupId {
		t.Fatalf("the group: %+v, %v", created, err)
	}
	for _, memberId := range members[1:3] {
		if err := phone.config.AddGroupMember(ctx, "team", memberId); err != nil {
			t.Fatal(err)
		}
	}
	path := testMailConfigAddressPath(t, "team@acme.root.example")
	versions := repo.versionCount(path)
	if err := phone.config.AddGroupMember(ctx, "team", members[1]); err != nil || repo.versionCount(path) != versions {
		t.Fatalf("a member added twice: %v", err)
	}
	if err := phone.config.AddGroupMember(ctx, "team", members[3]); !errors.Is(err, ErrMailConfigGroupFull) || repo.versionCount(path) != versions {
		t.Fatalf("a member past the bound: %v", err)
	}
	held, mailboxRepoId, err := phone.config.GroupMembers(ctx, "team")
	want := slices.Clone(members[:3])
	slices.SortFunc(want, Id.Cmp)
	if err != nil || !slices.Equal(held, want) || mailboxRepoId != testMailConfigGroupId {
		t.Fatalf("members %v, %v", held, err)
	}
	other := newMailConfigTestDevice(t, repo, authority, testMailConfigOtherId, nil)
	if err := other.config.AddGroupMember(ctx, "team", members[3]); !errors.Is(err, ErrMailConfigNotOwner) {
		t.Fatalf("another member's add: %v", err)
	}
	// a racing writer's version is read and the change made again
	repo.beforeWrite = func() {
		if err := newMailConfigTestDevice(t, repo, authority, testMailConfigPhoneId, nil).config.RemoveGroupMember(ctx, "team", members[0]); err != nil {
			t.Errorf("the racing removal: %v", err)
		}
	}
	if err := phone.config.RemoveGroupMember(ctx, "team", members[1]); err != nil {
		t.Fatal(err)
	}
	if held, _, err := phone.config.GroupMembers(ctx, "team"); err != nil || !slices.Equal(held, []Id{members[2]}) {
		t.Fatalf("after two racing removals: %v, %v", held, err)
	}
	if lookup := phone.resolve(t, "team@acme.root.example"); !lookup.Known || !slices.Equal(lookup.MemberIds, []Id{members[2]}) {
		t.Fatalf("the group resolved: %+v", lookup)
	}
	if err := phone.config.AddGroupMember(ctx, "nobody", members[0]); !errors.Is(err, ErrMailConfigAddressAbsent) {
		t.Fatalf("a member of no group: %v", err)
	}

	// mail_alias_create(alias, group): the alias takes the group's repo, and its action names the group
	alias, err := phone.config.CreateAddress(ctx, &MailCreateAddressArgs{LocalPart: "crew", Kind: protocol.MailAddressKind_MAIL_ADDRESS_ID, Group: "team"})
	if err != nil || alias.MailboxRepoId != testMailConfigGroupId || alias.Kind != protocol.MailAddressKind_MAIL_ADDRESS_GROUP {
		t.Fatalf("an alias of the group: %+v, %v", alias, err)
	}
	stored, err := ParseStoredCanonicalAction(phone.gate.lastAction().Canonical)
	if err != nil || stored.Action.GetAlias() != "crew" || stored.Action.GetAliasGroup() != "team" {
		t.Fatalf("its action: %+v, %v", stored, err)
	}
	if _, err := phone.config.CreateAddress(ctx, &MailCreateAddressArgs{LocalPart: "band", Kind: protocol.MailAddressKind_MAIL_ADDRESS_ID, Group: "nobody"}); !errors.Is(err, ErrMailConfigAddressAbsent) {
		t.Fatalf("an alias of no group: %v", err)
	}
}

// A path with more versions than a reader replays is unknown, not read again until it moves, and fails no Sync.
func TestMailConfigHoldsAReplayToItsBound(t *testing.T) {
	repo, authority := newMailConfigTestWorld(t)
	path := testMailConfigBurnerPath(t, "otter-4821")
	for index := 0; index < 5; index += 1 {
		state := protocol.MailBurnerState_MAIL_BURNER_LIVE
		if index%2 == 1 {
			state = protocol.MailBurnerState_MAIL_BURNER_PAUSED
		}
		repo.commit(path, testMailConfigPhoneId, testMailConfigBurnerBytes(t, testMailConfigMailboxId, state))
	}
	phone := newMailConfigTestDevice(t, repo, authority, testMailConfigPhoneId, func(args *MailConfigArgs) {
		args.Settings.ReplayVersionMaxCount = 4
	})
	phone.sync(t)
	if lookup := phone.resolve(t, "shop@otter-4821.acme.root.example"); lookup.Known {
		t.Fatalf("a record past the replay bound: %+v", lookup)
	}
	if burners, err := phone.config.Burners(); err != nil || len(burners) != 0 {
		t.Fatalf("burners %v, %v", burners, err)
	}
}

// A clock whose timers fire only when a test says, so the follower waits on its changes alone.
type mailConfigTestHeldClock struct {
	stateLock sync.Mutex
	now       time.Time
	timers    []chan time.Time
}

func (self *mailConfigTestHeldClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

func (self *mailConfigTestHeldClock) After(timeout time.Duration) <-chan time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	timer := make(chan time.Time, 1)
	self.timers = append(self.timers, timer)
	return timer
}

func (self *mailConfigTestHeldClock) AfterFunc(timeout time.Duration, function func()) func() bool {
	return func() bool { return true }
}

// Fires every timer taken so far.
func (self *mailConfigTestHeldClock) fire() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, timer := range self.timers {
		select {
		case timer <- self.now:
		default:
		}
	}
	self.timers = nil
}

// The follower syncs at once, again once its subscription stands, and at each change the store raises; a Sync that
// fails is tried again after its interval; Close ends it.
func TestMailConfigFollowerSyncsAtEachChange(t *testing.T) {
	repo, authority := newMailConfigTestWorld(t)
	writer := newMailConfigTestDevice(t, repo, authority, testMailConfigPhoneId, nil)
	clock := &mailConfigTestHeldClock{now: time.UnixMilli(1793923200000)}
	follower := newMailConfigTestDevice(t, repo, authority, testMailConfigDesktopId, func(args *MailConfigArgs) {
		args.Clock = clock
	})
	synced := make(chan error, 16)
	follower.config.afterFollowerSync = func(err error) { synced <- err }
	follower.config.startFollower()
	// the first Sync, then the one that covers the gap before the subscription stood
	for index := 0; index < 2; index += 1 {
		if err := <-synced; err != nil {
			t.Fatal(err)
		}
	}
	if addresses, err := follower.config.Addresses(); err != nil || len(addresses) != 0 {
		t.Fatalf("before any record: %v, %v", addresses, err)
	}
	writer.createId(t, "ada")
	if err := <-synced; err != nil {
		t.Fatal(err)
	}
	if addresses, err := follower.config.Addresses(); err != nil || len(addresses) != 1 || !addresses[0].Known {
		t.Fatalf("after the change: %v, %v", addresses, err)
	}
	// a failed Sync is tried again when its retry timer fires, not before
	repo.stateLock.Lock()
	repo.failReads = errors.New("the store is away")
	repo.stateLock.Unlock()
	repo.notify()
	if err := <-synced; err == nil {
		t.Fatal("a Sync of a failing store passed")
	}
	repo.stateLock.Lock()
	repo.failReads = nil
	repo.stateLock.Unlock()
	writer.createId(t, "grace")
	// the creation's change woke it, or the retry timer does
	clock.fire()
	for {
		if err := <-synced; err != nil {
			t.Fatal(err)
		}
		if addresses, err := follower.config.Addresses(); err == nil && len(addresses) == 2 {
			break
		}
	}
	follower.config.Close()
	if len(repo.followers) != 0 {
		t.Error("Close left the subscription")
	}
	// a change after Close reaches nothing
	writer.createId(t, "lin")
	select {
	case err := <-synced:
		t.Fatalf("a Sync after Close: %v", err)
	default:
	}
}

// Every request a device sends evs, kept: what a server sees of mailcfg.
type mailConfigTestCapture struct {
	handler   http.Handler
	stateLock sync.Mutex
	captured  [][]byte
}

func (self *mailConfigTestCapture) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	body, _ := io.ReadAll(request.Body)
	request.Body = io.NopCloser(bytes.NewReader(body))
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.captured = append(self.captured, []byte(request.Method+" "+request.URL.String()), body)
		for name, values := range request.Header {
			self.captured = append(self.captured, []byte(name+": "+strings.Join(values, ",")))
		}
	}()
	self.handler.ServeHTTP(writer, request)
}

// A MailConfig over a writer of the evs stand-in, every request of its client captured.
func newMailConfigEvsDevice(t *testing.T, writer *evsTestWriter, capture *mailConfigTestCapture, authority *mailConfigTestAuthority) *mailConfigTestDevice {
	t.Helper()
	writer.test.client.args.Transport = &evsTestTransport{handler: capture}
	writer.test.client.http.transport = wrapSidecarApiTransport(writer.test.client.args.Transport)
	sidecarId := writer.test.client.args.Identity().SidecarId
	device := &mailConfigTestDevice{gate: newMailConfigTestGate(), authority: authority, clock: &mailTestClock{now: time.UnixMilli(1793923200000)}}
	device.config = newMailConfig(&mailConfigEvsStore{mailEvsStore: newMailEvsStore(writer.repo, nil, nil)}, &MailConfigArgs{
		Network:   testMailConfigNetwork,
		SidecarId: sidecarId,
		Authority: authority,
		Gate:      device.gate,
		Clock:     device.clock,
		Alarm: func(alarm *MailConfigAlarm) {
			device.stateLock.Lock()
			defer device.stateLock.Unlock()
			device.alarms = append(device.alarms, alarm)
		},
		BurnerLabels: func(effectKey []byte) []string { return []string{"otter-4821"} },
	})
	t.Cleanup(device.config.Close)
	return device
}

// mailcfg over evs, on the stand-in: a record created through one device's MailConfig is read by another with its
// push's signer, so the creator and each later version are judged on evs's own history; every version is written
// with versioning on; a removal is found by a restart's Lookup; and an alias canary and a burner label are absent
// from every request either device sent (I-13), the paths, addresses and records being sealed.
func TestMailConfigOverEvsKeepsAliasesFromTheServer(t *testing.T) {
	const canary = "canary-alias-7f3a"
	const address = canary + "@acme.root.example"
	const burnerAddress = "shop@otter-4821.acme.root.example"
	ownerWriter := newEvsTestWriter(t)
	otherWriter := ownerWriter.otherWriter(t, "mailcfg other member")
	addressPath := testMailConfigAddressPath(t, address)
	burnerPath := testMailConfigBurnerPath(t, "otter-4821")
	ownerWriter.server.know(addressPath, burnerPath)
	capture := &mailConfigTestCapture{handler: ownerWriter.server}
	ownerId := ownerWriter.test.client.args.Identity().SidecarId
	otherId := otherWriter.test.client.args.Identity().SidecarId
	authority := newMailConfigTestAuthority()
	authority.grant(ownerId, "*")
	authority.grant(otherId, "*")
	authority.own(testMailConfigMailboxId, ownerId)
	owner := newMailConfigEvsDevice(t, ownerWriter, capture, authority)
	other := newMailConfigEvsDevice(t, otherWriter, capture, authority)
	ctx := context.Background()

	// an empty repo syncs to nothing
	other.sync(t)
	if lookup := other.resolve(t, address); lookup.Known {
		t.Fatalf("before any record: %+v", lookup)
	}
	created := owner.createId(t, canary)
	if !created.Known || created.CreatorSidecarId != ownerId {
		t.Fatalf("created %+v", created)
	}
	// its own action, since the stand-in gate keys a use by its action's bytes
	burner, err := owner.config.CreateBurnerRecord(ctx, &MailCreateBurnerArgs{Alias: canary + "-burner", MailboxRepoId: testMailConfigMailboxId})
	if err != nil || burner.Label != "otter-4821" {
		t.Fatalf("the burner: %+v, %v", burner, err)
	}
	other.sync(t)
	if lookup := other.resolve(t, address); !lookup.Known || lookup.MailboxRepoId != testMailConfigMailboxId || lookup.CreatorSidecarId != ownerId {
		t.Fatalf("the other device's read: %+v", lookup)
	}
	if lookup := other.resolve(t, burnerAddress); !lookup.Known || lookup.CreatorSidecarId != ownerId {
		t.Fatalf("the other device's read of the burner: %+v", lookup)
	}

	// the other member's pause of the owner's burner is a later version evs takes and no reader counts
	otherStore := newMailEvsStore(otherWriter.repo, nil, nil)
	content, version, err := otherStore.Read(ctx, burnerPath, 1024)
	if err != nil {
		t.Fatal(err)
	}
	paused := &protocol.MailBurner{}
	if err := proto.Unmarshal(content, paused); err != nil {
		t.Fatal(err)
	}
	paused.State = protocol.MailBurnerState_MAIL_BURNER_PAUSED
	pausedBytes, _ := proto.MarshalOptions{Deterministic: true}.Marshal(paused)
	if _, err := otherStore.Write(ctx, []*mailStoreWrite{{Path: burnerPath, Content: pausedBytes, IfVersion: version}}); err != nil {
		t.Fatal(err)
	}
	owner.sync(t)
	if lookup := owner.resolve(t, burnerAddress); !lookup.Known {
		t.Fatalf("after another member's pause: %+v", lookup)
	}
	if reasons := owner.alarmReasons(); !slices.Equal(reasons, []MailConfigAlarmReason{MailConfigAlarmSigner}) {
		t.Fatalf("alarms %v", reasons)
	}
	// the owner's burn counts, on the version the other member left
	if err := owner.config.SetBurnerState(ctx, "otter-4821", protocol.MailBurnerState_MAIL_BURNER_BURNED); err != nil {
		t.Fatal(err)
	}
	other.sync(t)
	if lookup := other.resolve(t, burnerAddress); lookup.Known {
		t.Fatalf("after the owner's burn: %+v", lookup)
	}
	versions, err := owner.config.store.Versions(ctx, burnerPath, 16)
	if err != nil || len(versions) != 3 || versions[0].SignerSidecarId != ownerId || versions[1].SignerSidecarId != otherId || versions[2].SignerSidecarId != ownerId {
		t.Fatalf("the burner's versions: %v, %v", versions, err)
	}
	for _, version := range versions {
		if version.Versioning != 0 || version.Removed {
			t.Errorf("version %+v", version)
		}
	}

	// the owner deletes the address: a removal held to its version, which a restart's Lookup finds
	if err := owner.config.DeleteAddress(ctx, &MailDeleteAddressArgs{LocalPart: canary}); err != nil {
		t.Fatal(err)
	}
	action := owner.gate.lastAction()
	if outcome, err := owner.config.Lookup(ctx, action.Canonical, nil); err != nil || outcome.State != ApprovalOutcomeDone {
		t.Fatalf("the removal's lookup: %+v, %v", outcome, err)
	}
	other.sync(t)
	if lookup := other.resolve(t, address); lookup.Known {
		t.Fatalf("after the delete: %+v", lookup)
	}
	if reasons := other.alarmReasons(); !slices.Equal(reasons, []MailConfigAlarmReason{MailConfigAlarmSigner}) {
		t.Fatalf("the other device's alarms %v", reasons)
	}

	capture.stateLock.Lock()
	defer capture.stateLock.Unlock()
	if len(capture.captured) == 0 {
		t.Fatal("nothing was captured")
	}
	for _, needle := range []string{canary, "otter-4821", "acme.root.example", mailAddressFamily + "/", mailBurnerFamily + "/"} {
		for _, captured := range capture.captured {
			if bytes.Contains(captured, []byte(needle)) {
				t.Fatalf("%q reached the server in a request of %d bytes", needle, len(captured))
			}
		}
	}
}

// MailConfigAclAuthority over the installed engine: a record is honored while policy grants its creator the alias's
// listen, as the device's own alias detail says; a mailbox's records change only from a consented device of its
// owner and a group repo's only from its admins; no engine, no state and any other repo allow nothing.
func TestMailConfigAclAuthorityReadsTheInstalledState(t *testing.T) {
	world := newAclCompileWorld("mailcfg authority")
	owner := world.member("owner@acme.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
	creator := world.device("creator", owner)
	agent := world.agent("agent", owner, "worker")
	world.setPolicy(t, `{
  "grants": [
    { "src": ["autogroup:member"], "dst": ["mail:ops-*"], "allow": ["listen"] },
  ],
}`)
	local, err := CompileAclLocal(world.input())
	if err != nil {
		t.Fatal(err)
	}
	engine := NewAclEngine(creator, nil, nil, nil)
	if err := engine.Install(world.state(t), local); err != nil {
		t.Fatal(err)
	}
	authority := &MailConfigAclAuthority{Engine: engine}
	if !authority.HonorsRecord(creator, "ops-pager", aclTestNow) {
		t.Error("a creator holding the listen grant is not honored")
	}
	if authority.HonorsRecord(creator, "sales", aclTestNow) || authority.HonorsRecord(agent, "ops-pager", aclTestNow) {
		t.Error("a record outside its creator's grant is honored")
	}

	fixture := newAclTestFixture()
	ownerId := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	otherId := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	laptop := fixture.invitedDevice(ownerId)
	otherLaptop := fixture.invitedDevice(otherId)
	mailboxId, _ := fixture.repo(protocol.RepoKind_REPO_KIND_MAILBOX, ownerId)
	vaultId, _ := fixture.repo(protocol.RepoKind_REPO_KIND_VAULT, ownerId)
	groupId, group := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	group.Admins = []*protocol.AclRepoAdminRow{{SidecarId: otherLaptop.Bytes(), Signer: otherLaptop.Bytes(), At: fixture.next()}}
	engine = NewAclEngine(laptop, nil, nil, nil)
	if err := engine.Install(fixture.state(t), nil); err != nil {
		t.Fatal(err)
	}
	authority = &MailConfigAclAuthority{Engine: engine}
	cases := []struct {
		signerId Id
		repoId   Id
		want     bool
	}{
		{signerId: laptop, repoId: mailboxId, want: true},
		{signerId: otherLaptop, repoId: mailboxId, want: false},
		{signerId: otherLaptop, repoId: groupId, want: true},
		{signerId: laptop, repoId: groupId, want: false},
		{signerId: laptop, repoId: vaultId, want: false},
		{signerId: laptop, repoId: evsTestId("a repo the state does not hold"), want: false},
		{signerId: evsTestId("no sidecar"), repoId: mailboxId, want: false},
	}
	for index, c := range cases {
		if got := authority.MayChangeRecord(c.signerId, c.repoId); got != c.want {
			t.Errorf("case %d: %t", index, got)
		}
	}
	// with no alias detail on the device a rule takes no alias, and with no engine or state nothing is allowed
	if authority.HonorsRecord(laptop, "ops-pager", aclTestNow) {
		t.Error("a rule this device holds no detail of honored a record")
	}
	for _, empty := range []*MailConfigAclAuthority{nil, {}, {Engine: NewAclEngine(laptop, nil, nil, nil)}} {
		if empty.HonorsRecord(laptop, "ops-pager", aclTestNow) || empty.MayChangeRecord(laptop, mailboxId) {
			t.Error("an authority with nothing installed allowed something")
		}
	}
}
