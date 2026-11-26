//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"bytes"
	"context"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
)

// One secret repo in a test's world.
type testInferCacheRepo struct {
	owner   Id
	content []byte
	version uint64
	deleted bool
}

// The world a member's devices share as their hosts see it: members' consented lists, the secret repos with their
// cache.json, and each device's ReaderKeys, newest last. Safe for concurrent use; its hooks run with no lock held.
type testInferCacheWorld struct {
	t testing.TB

	stateLock  sync.Mutex
	repos      map[Id]*testInferCacheRepo
	consented  map[Id][]Id
	readerKeys map[Id][]hpke.PrivateKey
	writeCount int
	// runs once a repo is created, before its creator writes; nil for none
	onCreate func(repoId Id)
	// runs before each write is judged; nil for none
	beforeWrite func(repoId Id)
}

func newTestInferCacheWorld(t testing.TB) *testInferCacheWorld {
	return &testInferCacheWorld{
		t:          t,
		repos:      map[Id]*testInferCacheRepo{},
		consented:  map[Id][]Id{},
		readerKeys: map[Id][]hpke.PrivateKey{},
	}
}

// Lists device on memberId's consented list.
func (self *testInferCacheWorld) consent(memberId Id, device Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !slices.Contains(self.consented[memberId], device) {
		self.consented[memberId] = append(self.consented[memberId], device)
	}
}

// Takes device off memberId's consented list: a revocation, an incarnation's stop or a withdrawn consent.
func (self *testInferCacheWorld) withdraw(memberId Id, device Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.consented[memberId] = slices.DeleteFunc(self.consented[memberId], func(listed Id) bool { return listed == device })
}

// A new ReaderKey for device, its newest.
func (self *testInferCacheWorld) newReaderKey(device Id) {
	key, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		self.t.Fatal(err)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.readerKeys[device] = append(self.readerKeys[device], key)
}

// The repos memberId owns that stand.
func (self *testInferCacheWorld) standingRepos(memberId Id) []Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	repoIds := []Id{}
	for repoId, repo := range self.repos {
		if repo.owner == memberId && !repo.deleted {
			repoIds = append(repoIds, repoId)
		}
	}
	slices.SortFunc(repoIds, func(a Id, b Id) int { return a.Cmp(b) })
	return repoIds
}

// The cache.json repoId holds, parsed.
func (self *testInferCacheWorld) file(repoId Id) *InferCacheFile {
	self.stateLock.Lock()
	content := bytes.Clone(self.repos[repoId].content)
	self.stateLock.Unlock()
	file, err := parseInferCacheFile(content, DefaultInferSettings())
	if err != nil {
		self.t.Fatalf("cache.json of %s: %v", repoId, err)
	}
	return file
}

// Replaces repoId's cache.json, as another writer's push would.
func (self *testInferCacheWorld) replace(repoId Id, file *InferCacheFile) {
	content, err := json.Marshal(file)
	if err != nil {
		self.t.Fatal(err)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	repo := self.repos[repoId]
	repo.content = content
	repo.version += 1
}

// The bytes every cache.json and own secret in the world holds, for a scan.
func (self *testInferCacheWorld) everything() [][]byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	everything := [][]byte{}
	for _, repo := range self.repos {
		everything = append(everything, bytes.Clone(repo.content))
	}
	return everything
}

// What the world counts of writes.
func (self *testInferCacheWorld) writes() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.writeCount
}

// One device of the world: its host and its seal.
type testInferCacheDevice struct {
	world *testInferCacheWorld
	me    inferCacheSelf

	stateLock sync.Mutex
	own       []byte
	ownErr    error
}

func (self *testInferCacheDevice) self() (*inferCacheSelf, error) {
	me := self.me
	return &me, nil
}

func (self *testInferCacheDevice) consentedDevices(memberId Id) ([]Id, error) {
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	devices := slices.Clone(self.world.consented[memberId])
	slices.SortFunc(devices, func(a Id, b Id) int { return a.Cmp(b) })
	return devices, nil
}

func (self *testInferCacheDevice) secretRepos(memberId Id) ([]Id, error) {
	return self.world.standingRepos(memberId), nil
}

func (self *testInferCacheDevice) readCache(ctx context.Context, repoId Id, maxByteCount int) ([]byte, uint64, error) {
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	repo := self.world.repos[repoId]
	if repo == nil || repo.deleted || repo.content == nil {
		return nil, 0, nil
	}
	if maxByteCount < len(repo.content) {
		return nil, 0, fmt.Errorf("%w: longer than %d bytes", errInferCacheFile, maxByteCount)
	}
	return bytes.Clone(repo.content), repo.version, nil
}

func (self *testInferCacheDevice) writeCache(ctx context.Context, repoId Id, content []byte, ifVersion uint64) error {
	self.world.stateLock.Lock()
	beforeWrite := self.world.beforeWrite
	self.world.stateLock.Unlock()
	if beforeWrite != nil {
		beforeWrite(repoId)
	}
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	repo := self.world.repos[repoId]
	if repo == nil || repo.deleted {
		return errors.New("no such repo")
	}
	if repo.version != ifVersion {
		return errInferCacheConflict
	}
	repo.content = bytes.Clone(content)
	repo.version += 1
	self.world.writeCount += 1
	return nil
}

func (self *testInferCacheDevice) createRepo(ctx context.Context, memberId Id) (Id, error) {
	repoId := NewId()
	self.world.stateLock.Lock()
	self.world.repos[repoId] = &testInferCacheRepo{owner: memberId}
	onCreate := self.world.onCreate
	self.world.stateLock.Unlock()
	if onCreate != nil {
		onCreate(repoId)
	}
	return repoId, nil
}

func (self *testInferCacheDevice) deleteRepo(ctx context.Context, repoId Id) error {
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	if repo := self.world.repos[repoId]; repo != nil {
		repo.deleted = true
	}
	return nil
}

func (self *testInferCacheDevice) loadOwn() ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return bytes.Clone(self.own), self.ownErr
}

func (self *testInferCacheDevice) storeOwn(secret []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.ownErr != nil {
		return self.ownErr
	}
	self.own = bytes.Clone(secret)
	return nil
}

// The SHA-256 of a ReaderKey's public half.
func testInferCacheKeySha256(key hpke.PrivateKey) []byte {
	sum := sha256.Sum256(key.PublicKey().Bytes())
	return sum[:]
}

// The info a test seal names: the purpose, then the repo's id.
func testInferCacheSealInfo(repoId Id, purpose string) []byte {
	return append([]byte(purpose), repoId.Bytes()...)
}

// See InferCacheSealer: HPKE-XWing to the recipient's newest ReaderKey, as CONN's inner seal does.
func (self *testInferCacheDevice) ReaderKeySha256(ctx context.Context) ([]byte, error) {
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	keys := self.world.readerKeys[self.me.SidecarId]
	if len(keys) == 0 {
		return nil, errors.New("no reader key")
	}
	return testInferCacheKeySha256(keys[len(keys)-1]), nil
}

func (self *testInferCacheDevice) Seal(ctx context.Context, repoId Id, purpose string, recipient Id, value []byte) (*InferCacheCopy, error) {
	self.world.stateLock.Lock()
	keys := slices.Clone(self.world.readerKeys[recipient])
	self.world.stateLock.Unlock()
	if len(keys) == 0 {
		return nil, errors.New("the recipient has no reader key")
	}
	key := keys[len(keys)-1]
	keySha256 := testInferCacheKeySha256(key)
	encapsulation, sender, err := hpke.NewSender(key.PublicKey(), hpke.HKDFSHA256(), hpke.AES128GCM(), testInferCacheSealInfo(repoId, purpose))
	if err != nil {
		return nil, err
	}
	sealed, err := sender.Seal(keySha256, value)
	if err != nil {
		return nil, err
	}
	return &InferCacheCopy{SidecarId: recipient, ReaderKeySha256: hex.EncodeToString(keySha256), Sealed: append(encapsulation, sealed...)}, nil
}

func (self *testInferCacheDevice) Open(ctx context.Context, repoId Id, purpose string, copy *InferCacheCopy) ([]byte, error) {
	if copy.SidecarId != self.me.SidecarId {
		return nil, errors.New("a copy sealed to another device")
	}
	return testInferCacheOpenWith(self.world, self.me.SidecarId, repoId, purpose, copy)
}

// Opens copy with every ReaderKey device holds, whatever device the copy names: how a device that holds the repo's
// bytes tries another's copy.
func testInferCacheOpenWith(world *testInferCacheWorld, device Id, repoId Id, purpose string, copy *InferCacheCopy) ([]byte, error) {
	world.stateLock.Lock()
	keys := slices.Clone(world.readerKeys[device])
	world.stateLock.Unlock()
	const encapsulationByteCount = 1120
	if len(copy.Sealed) < encapsulationByteCount {
		return nil, errors.New("a seal too short")
	}
	for _, key := range keys {
		keySha256 := testInferCacheKeySha256(key)
		recipient, err := hpke.NewRecipient(copy.Sealed[:encapsulationByteCount], key, hpke.HKDFSHA256(), hpke.AES128GCM(), testInferCacheSealInfo(repoId, purpose))
		if err != nil {
			continue
		}
		if value, err := recipient.Open(keySha256, copy.Sealed[encapsulationByteCount:]); err == nil {
			return value, nil
		}
	}
	return nil, errors.New("no reader key of the device opens it")
}

// What a test device is made as.
type testInferCacheDeviceArgs struct {
	member   *Id
	readOnly bool
	enclave  bool
	// no inner seal, as a build before CONN's
	noSealer bool
	settings *InferSettings
	clock    Clock
	log      Logger
	random   io.Reader
}

// A device of the world with a ReaderKey, and its cache secret.
func (self *testInferCacheWorld) device(args *testInferCacheDeviceArgs) (*testInferCacheDevice, *InferCacheSecret) {
	self.t.Helper()
	if args == nil {
		args = &testInferCacheDeviceArgs{}
	}
	device := &testInferCacheDevice{world: self}
	device.me = inferCacheSelf{SidecarId: NewId(), MemberId: args.member, ReadOnly: args.readOnly, Enclave: args.enclave}
	self.newReaderKey(device.me.SidecarId)
	if args.member != nil {
		self.consent(*args.member, device.me.SidecarId)
	}
	return device, self.secretOf(device, args)
}

// A cache secret over device, as a restart of its process builds one.
func (self *testInferCacheWorld) secretOf(device *testInferCacheDevice, args *testInferCacheDeviceArgs) *InferCacheSecret {
	self.t.Helper()
	settings := args.settings
	if settings == nil {
		settings = DefaultInferSettings()
	}
	cacheArgs := &inferCacheSecretArgs{Host: device, Settings: settings, Clock: args.clock, Log: args.log, Random: args.random}
	if !args.noSealer {
		cacheArgs.Sealer = device
	}
	secret, err := newInferCacheSecret(cacheArgs)
	if err != nil {
		self.t.Fatal(err)
	}
	return secret
}

// The TEE line a secret's key gives for provider, failing the test where it gives none.
func testInferCacheTeeLine(t testing.TB, secret *InferCacheSecret, provider string) (string, InferCacheSecretSource) {
	t.Helper()
	key, err := secret.Secret(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	line, err := key.TeeSaltLine(provider)
	if err != nil {
		t.Fatal(err)
	}
	return line, key.Source()
}

// The secret every TEE salt of one draw derives from, read by opening device's copy with its keys.
func testInferCacheOpened(t testing.TB, world *testInferCacheWorld, device *testInferCacheDevice, repoId Id) []byte {
	t.Helper()
	file := world.file(repoId)
	index := slices.IndexFunc(file.Copies, func(copy *InferCacheCopy) bool { return copy.SidecarId == device.me.SidecarId })
	if index < 0 {
		t.Fatalf("%s holds no copy for %s", repoId, device.me.SidecarId)
	}
	value, err := testInferCacheOpenWith(world, device.me.SidecarId, repoId, inferCachePurpose(file.DrawId), file.Copies[index])
	if err != nil {
		t.Fatal(err)
	}
	return value
}

// A member's desktop, phone and agents' enclave derive one salt for one provider, the enclave drawing nothing: the
// first untagged device to make a remote call creates the repo and seals a copy to each device on the consented list.
func TestSaltSameAcrossMembersDevicesAndEnclave(t *testing.T) {
	world := newTestInferCacheWorld(t)
	member := NewId()
	_, desktop := world.device(&testInferCacheDeviceArgs{member: &member})
	_, phone := world.device(&testInferCacheDeviceArgs{member: &member})
	_, enclave := world.device(&testInferCacheDeviceArgs{member: &member, enclave: true})
	desktopLine, source := testInferCacheTeeLine(t, desktop, "chutes")
	if source != InferCacheSecretMember {
		t.Fatalf("the desktop salts with its %s secret", source)
	}
	repos := world.standingRepos(member)
	if len(repos) != 1 {
		t.Fatalf("%d cache repos stand", len(repos))
	}
	if file := world.file(repos[0]); len(file.Copies) != 3 {
		t.Errorf("the draw sealed %d copies, not one per device on the list", len(file.Copies))
	}
	for name, secret := range map[string]*InferCacheSecret{"phone": phone, "enclave": enclave} {
		line, source := testInferCacheTeeLine(t, secret, "chutes")
		if line != desktopLine || source != InferCacheSecretMember {
			t.Errorf("the %s salts %q from its %s secret, the desktop %q", name, line, source, desktopLine)
		}
	}
	if file := world.file(repos[0]); file.DrawnBy == (Id{}) || len(file.Asks) != 0 {
		t.Errorf("the file after every device synced: %+v", file)
	}
}

// Another member's device, holding the same K_sock, directory and repo id, opens no copy of the member's and salts
// with a secret of its own member's.
func TestSecondMemberDerivesNothing(t *testing.T) {
	world := newTestInferCacheWorld(t)
	memberA := NewId()
	memberB := NewId()
	_, deviceA := world.device(&testInferCacheDeviceArgs{member: &memberA})
	otherDevice, deviceB := world.device(&testInferCacheDeviceArgs{member: &memberB})
	lineA, _ := testInferCacheTeeLine(t, deviceA, "chutes")
	repoA := world.standingRepos(memberA)[0]
	// it holds the repo's id and every byte of its cache.json, and none of its copies opens to it
	fileA := world.file(repoA)
	for _, copy := range fileA.Copies {
		if _, err := testInferCacheOpenWith(world, otherDevice.me.SidecarId, repoA, inferCachePurpose(fileA.DrawId), copy); err == nil {
			t.Error("another member's device opened a copy")
		}
	}
	lineB, source := testInferCacheTeeLine(t, deviceB, "chutes")
	if lineB == lineA {
		t.Error("another member's device derived the member's salt")
	}
	if source != InferCacheSecretMember || len(world.standingRepos(memberB)) != 1 {
		t.Errorf("the other member salts from its %s secret, with %d repos of its own", source, len(world.standingRepos(memberB)))
	}
	// what it would read the member's repos as is its own member's: none of the member's repos is its
	if slices.Contains(world.standingRepos(memberB), repoA) {
		t.Error("the member's repo is listed as the other member's")
	}
}

// A Team's audit reader holds the repo and reads its cache.json, and opens no copy: none is sealed to it, a copy it
// tries does not open, and its ask is dropped rather than answered.
func TestAuditReaderOpensNoCopy(t *testing.T) {
	world := newTestInferCacheWorld(t)
	member := NewId()
	auditMember := NewId()
	_, desktop := world.device(&testInferCacheDeviceArgs{member: &member})
	auditor, _ := world.device(&testInferCacheDeviceArgs{member: &auditMember})
	testInferCacheTeeLine(t, desktop, "chutes")
	repoId := world.standingRepos(member)[0]
	file := world.file(repoId)
	for _, copy := range file.Copies {
		if copy.SidecarId == auditor.me.SidecarId {
			t.Error("a copy is sealed to the audit reader")
		}
		if _, err := testInferCacheOpenWith(world, auditor.me.SidecarId, repoId, inferCachePurpose(file.DrawId), copy); err == nil {
			t.Error("the audit reader opened a copy")
		}
	}
	// an ask written into the file by a device off the consented list
	keySha256, err := auditor.ReaderKeySha256(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	file.Asks = append(file.Asks, &InferCacheAsk{SidecarId: auditor.me.SidecarId, ReaderKeySha256: hex.EncodeToString(keySha256), AskedAtMs: 1})
	world.replace(repoId, file)
	desktop.forget()
	testInferCacheTeeLine(t, desktop, "chutes")
	after := world.file(repoId)
	if len(after.Asks) != 0 || slices.ContainsFunc(after.Copies, func(copy *InferCacheCopy) bool { return copy.SidecarId == auditor.me.SidecarId }) {
		t.Errorf("the audit reader's ask was answered or kept: %+v", after)
	}
}

// A tagged sidecar never takes a member's secret: it draws its own at its first remote call, keeps it in its sealed
// state, and writes nothing of the member's.
func TestTaggedRunnerUsesItsOwnSecret(t *testing.T) {
	world := newTestInferCacheWorld(t)
	member := NewId()
	_, desktop := world.device(&testInferCacheDeviceArgs{member: &member})
	memberLine, _ := testInferCacheTeeLine(t, desktop, "chutes")
	writes := world.writes()
	runner, runnerSecret := world.device(nil)
	line, source := testInferCacheTeeLine(t, runnerSecret, "chutes")
	if source != InferCacheSecretOwn || line == memberLine {
		t.Errorf("the tagged runner salts %q from its %s secret", line, source)
	}
	if world.writes() != writes || len(world.standingRepos(member)) != 1 {
		t.Error("the tagged runner wrote to the member's repos")
	}
	// its runs share cache hits with each other: a restart reads the same secret from its sealed state
	restarted := world.secretOf(runner, &testInferCacheDeviceArgs{})
	again, _ := testInferCacheTeeLine(t, restarted, "chutes")
	if again != line {
		t.Errorf("after a restart it salts %q, before %q", again, line)
	}
}

// When a device that held a copy leaves the consented list, the first remaining device to sync draws a new secret
// sealed to the devices that remain, the others take it at their next sync, and the former device derives none of the
// new salts.
func TestNewSecretAfterRevocation(t *testing.T) {
	for _, leaving := range []string{"a revocation", "an enclave incarnation's stop", "a withdrawn consent"} {
		clock := newTestEnvelopeClock()
		world := newTestInferCacheWorld(t)
		member := NewId()
		_, desktop := world.device(&testInferCacheDeviceArgs{member: &member, clock: clock})
		_, phone := world.device(&testInferCacheDeviceArgs{member: &member, clock: clock})
		var former *testInferCacheDevice
		var formerSecret *InferCacheSecret
		switch leaving {
		case "an enclave incarnation's stop":
			settings := DefaultInferSettings()
			settings.CacheSecretEnclaveWaitTimeout = 0
			former, formerSecret = world.device(&testInferCacheDeviceArgs{member: &member, enclave: true, clock: clock, settings: settings})
		default:
			former, formerSecret = world.device(&testInferCacheDeviceArgs{member: &member, clock: clock})
		}
		oldLine, _ := testInferCacheTeeLine(t, desktop, "chutes")
		if line, _ := testInferCacheTeeLine(t, formerSecret, "chutes"); line != oldLine {
			t.Fatalf("%s: the former device did not share the secret before it left", leaving)
		}
		repoId := world.standingRepos(member)[0]
		oldDraw := world.file(repoId).DrawId
		world.withdraw(member, former.me.SidecarId)
		clock.Advance(DefaultInferSettings().CacheSecretSyncInterval)
		newLine, source := testInferCacheTeeLine(t, desktop, "chutes")
		if newLine == oldLine || source != InferCacheSecretMember {
			t.Errorf("%s: the desktop still salts with the old secret", leaving)
		}
		file := world.file(repoId)
		if file.DrawId == oldDraw {
			t.Errorf("%s: no new draw", leaving)
		}
		if slices.ContainsFunc(file.Copies, func(copy *InferCacheCopy) bool { return copy.SidecarId == former.me.SidecarId }) {
			t.Errorf("%s: the new secret is sealed to the former device", leaving)
		}
		clock.Advance(DefaultInferSettings().CacheSecretSyncInterval)
		if line, _ := testInferCacheTeeLine(t, phone, "chutes"); line != newLine {
			t.Errorf("%s: the phone salts %q, the desktop %q", leaving, line, newLine)
		}
		// the former device holds the bytes and opens none of the new copies
		for _, copy := range file.Copies {
			if _, err := testInferCacheOpenWith(world, former.me.SidecarId, repoId, inferCachePurpose(file.DrawId), copy); err == nil {
				t.Errorf("%s: the former device opened a copy of the new secret", leaving)
			}
		}
		key, err := formerSecret.Secret(context.Background())
		switch {
		case leaving == "an enclave incarnation's stop":
			if !errors.Is(err, ErrInferCacheSecretPending) {
				t.Errorf("the stopped incarnation got %v, %v", key, err)
			}
		case err != nil:
			t.Errorf("%s: the former device: %v", leaving, err)
		default:
			if line, _ := key.TeeSaltLine("chutes"); line == newLine || key.Source() != InferCacheSecretOwn {
				t.Errorf("%s: the former device derived the new salt", leaving)
			}
		}
	}
}

// Two devices that race the repo's creation keep one: the lower repo id stands, the other is deleted, and both salt
// alike; two that race a new draw after a device left keep one draw too.
func TestRacingDrawsKeepOne(t *testing.T) {
	world := newTestInferCacheWorld(t)
	member := NewId()
	clock := newTestEnvelopeClock()
	_, first := world.device(&testInferCacheDeviceArgs{member: &member, clock: clock})
	_, second := world.device(&testInferCacheDeviceArgs{member: &member, clock: clock})
	raced := false
	var secondLine string
	world.onCreate = func(repoId Id) {
		if raced {
			return
		}
		raced = true
		// the second device creates and writes its own repo while the first's is still empty
		secondLine, _ = testInferCacheTeeLine(t, second, "chutes")
	}
	firstLine, _ := testInferCacheTeeLine(t, first, "chutes")
	world.onCreate = nil
	repos := world.standingRepos(member)
	if !raced || len(repos) != 1 {
		t.Fatalf("raced %t, %d repos stand", raced, len(repos))
	}
	if secondLine == firstLine {
		t.Fatal("the race did not draw twice")
	}
	clock.Advance(DefaultInferSettings().CacheSecretSyncInterval)
	if line, _ := testInferCacheTeeLine(t, second, "chutes"); line != firstLine {
		t.Errorf("after the race the second device salts %q, the first %q", line, firstLine)
	}

	// a device leaves, and both remaining devices draw at once: the write that lands second is refused, reads again
	// and takes the winner's
	_, third := world.device(&testInferCacheDeviceArgs{member: &member, clock: clock})
	clock.Advance(DefaultInferSettings().CacheSecretSyncInterval)
	testInferCacheTeeLine(t, first, "chutes")
	testInferCacheTeeLine(t, second, "chutes")
	testInferCacheTeeLine(t, third, "chutes")
	thirdDevice := world.file(repos[0]).Copies
	var leaving Id
	for _, copy := range thirdDevice {
		listed := slices.ContainsFunc([]*InferCacheSecret{first, second}, func(secret *InferCacheSecret) bool {
			return copy.SidecarId == secret.host.(*testInferCacheDevice).me.SidecarId
		})
		if !listed {
			leaving = copy.SidecarId
		}
	}
	world.withdraw(member, leaving)
	clock.Advance(DefaultInferSettings().CacheSecretSyncInterval)
	racedDraw := false
	world.beforeWrite = func(repoId Id) {
		if racedDraw {
			return
		}
		racedDraw = true
		testInferCacheTeeLine(t, second, "chutes")
	}
	drawnLine, _ := testInferCacheTeeLine(t, first, "chutes")
	world.beforeWrite = nil
	file := world.file(repos[0])
	if file.DrawnBy != second.host.(*testInferCacheDevice).me.SidecarId {
		t.Errorf("the draw that stands is %s's, not the one that landed first", file.DrawnBy)
	}
	if line, _ := testInferCacheTeeLine(t, second, "chutes"); line != drawnLine {
		t.Errorf("after the racing draws the two devices salt %q and %q", line, drawnLine)
	}
}

// A newly listed device with no copy asks for one and salts with its own secret meanwhile; at its next sync a device
// that holds the secret seals it one and drops the ask, and then the new device salts as the member does.
func TestNewDeviceSaltsWithOwnUntilSealed(t *testing.T) {
	world := newTestInferCacheWorld(t)
	member := NewId()
	clock := newTestEnvelopeClock()
	_, desktop := world.device(&testInferCacheDeviceArgs{member: &member, clock: clock})
	memberLine, _ := testInferCacheTeeLine(t, desktop, "chutes")
	repoId := world.standingRepos(member)[0]
	// a new device, admitted after the draw: its first sync finds no copy of its own
	newcomer, newcomerSecret := world.device(&testInferCacheDeviceArgs{member: &member, clock: clock})
	line, source := testInferCacheTeeLine(t, newcomerSecret, "chutes")
	if source != InferCacheSecretOwn || line == memberLine {
		t.Fatalf("the new device salts %q from its %s secret before any copy is sealed to it", line, source)
	}
	if asks := world.file(repoId).Asks; len(asks) != 1 || asks[0].SidecarId != newcomer.me.SidecarId {
		t.Fatalf("the new device's ask: %+v", asks)
	}
	clock.Advance(DefaultInferSettings().CacheSecretSyncInterval)
	testInferCacheTeeLine(t, desktop, "chutes")
	if file := world.file(repoId); len(file.Asks) != 0 || !slices.ContainsFunc(file.Copies, func(copy *InferCacheCopy) bool {
		return copy.SidecarId == newcomer.me.SidecarId
	}) {
		t.Fatalf("the desktop did not answer the ask: %+v", file)
	}
	clock.Advance(DefaultInferSettings().CacheSecretSyncInterval)
	if line, source := testInferCacheTeeLine(t, newcomerSecret, "chutes"); line != memberLine || source != InferCacheSecretMember {
		t.Errorf("once sealed, the new device salts %q from its %s secret", line, source)
	}
}

// A read_only device writes nothing: it opens the copy sealed to it, and with none salts with its own secret, asking
// nothing.
func TestCacheSecretReadOnlyWritesNothing(t *testing.T) {
	world := newTestInferCacheWorld(t)
	member := NewId()
	clock := newTestEnvelopeClock()
	_, readerSecret := world.device(&testInferCacheDeviceArgs{member: &member, readOnly: true, clock: clock})
	if _, source := testInferCacheTeeLine(t, readerSecret, "chutes"); source != InferCacheSecretOwn {
		t.Errorf("with no repo the read_only device salts from its %s secret", source)
	}
	if world.writes() != 0 || len(world.standingRepos(member)) != 0 {
		t.Fatal("a read_only device created or wrote the repo")
	}
	_, desktop := world.device(&testInferCacheDeviceArgs{member: &member, clock: clock})
	memberLine, _ := testInferCacheTeeLine(t, desktop, "chutes")
	writes := world.writes()
	clock.Advance(DefaultInferSettings().CacheSecretSyncInterval)
	if line, source := testInferCacheTeeLine(t, readerSecret, "chutes"); line != memberLine || source != InferCacheSecretMember {
		t.Errorf("the read_only device salts %q from its %s secret", line, source)
	}
	if world.writes() != writes {
		t.Error("the read_only device wrote")
	}
}

// An agents' enclave never creates the repo or draws: with no copy sealed to it its remote call waits, its ask
// written, until a sponsor's device seals one at its next sync, and is refused pending past its wait.
func TestCacheSecretEnclaveWaitsForItsCopy(t *testing.T) {
	world := newTestInferCacheWorld(t)
	member := NewId()
	clock := newTestEnvelopeClock()
	clock.firesWaits = true
	settings := DefaultInferSettings()
	_, enclave := world.device(&testInferCacheDeviceArgs{member: &member, enclave: true, clock: clock, settings: settings})
	// no repo stands: it waits, drawing nothing, and is refused at its wait's end
	done := make(chan error, 1)
	go func() {
		_, err := enclave.Secret(context.Background())
		done <- err
	}()
	clock.awaitWaitCount(2)
	clock.Advance(settings.CacheSecretEnclaveWaitTimeout)
	if err := <-done; !errors.Is(err, ErrInferCacheSecretPending) {
		t.Fatalf("with no repo: %v", err)
	}
	if world.writes() != 0 || len(world.standingRepos(member)) != 0 {
		t.Fatal("the enclave created or wrote the repo")
	}
	// a sponsor's device draws, sealing to the enclave on the list: its next call opens it at once
	_, desktop := world.device(&testInferCacheDeviceArgs{member: &member, clock: clock})
	memberLine, _ := testInferCacheTeeLine(t, desktop, "chutes")
	enclave.forget()
	if line, source := testInferCacheTeeLine(t, enclave, "chutes"); line != memberLine || source != InferCacheSecretMember {
		t.Errorf("the enclave salts %q from its %s secret", line, source)
	}
}

// Until CONN's inner seal registers, no device writes the member's repo: each salts with a secret of its own.
func TestCacheSecretWithoutTheInnerSealSaltsWithOwn(t *testing.T) {
	world := newTestInferCacheWorld(t)
	member := NewId()
	_, desktop := world.device(&testInferCacheDeviceArgs{member: &member, noSealer: true})
	_, phone := world.device(&testInferCacheDeviceArgs{member: &member, noSealer: true})
	desktopLine, desktopSource := testInferCacheTeeLine(t, desktop, "chutes")
	phoneLine, phoneSource := testInferCacheTeeLine(t, phone, "chutes")
	if desktopSource != InferCacheSecretOwn || phoneSource != InferCacheSecretOwn || desktopLine == phoneLine {
		t.Errorf("without the seal: %s %q and %s %q", desktopSource, desktopLine, phoneSource, phoneLine)
	}
	if world.writes() != 0 || len(world.standingRepos(member)) != 0 {
		t.Error("a device without the seal wrote the member's repo")
	}
	// a locked sealed state answers no secret rather than an unkept one
	locked, lockedSecret := world.device(nil)
	locked.ownErr = ErrSidecarStoreLocked
	if _, err := lockedSecret.Secret(context.Background()); !errors.Is(err, ErrInferCacheSecretUnavailable) {
		t.Errorf("a locked store: %v", err)
	}
}

// A cache.json that does not hold to its format is no secret: a device that may draw replaces it at the version read.
func TestCacheFileRefusedIsReplaced(t *testing.T) {
	world := newTestInferCacheWorld(t)
	member := NewId()
	clock := newTestEnvelopeClock()
	_, desktop := world.device(&testInferCacheDeviceArgs{member: &member, clock: clock})
	before, _ := testInferCacheTeeLine(t, desktop, "chutes")
	repoId := world.standingRepos(member)[0]
	for _, content := range []string{`{"format":2}`, `{"format":1,"draw_id":"zz"}`, `[]`, strings.Repeat("x", 64)} {
		func() {
			world.stateLock.Lock()
			defer world.stateLock.Unlock()
			repo := world.repos[repoId]
			repo.content = []byte(content)
			repo.version += 1
		}()
		if _, err := parseInferCacheFile([]byte(content), DefaultInferSettings()); !errors.Is(err, errInferCacheFile) {
			t.Errorf("%q parsed: %v", content, err)
		}
		clock.Advance(DefaultInferSettings().CacheSecretSyncInterval)
		after, source := testInferCacheTeeLine(t, desktop, "chutes")
		if source != InferCacheSecretMember || after == before {
			t.Errorf("after %q: %s %q", content, source, after)
		}
		before = after
		if file := world.file(repoId); file.Format != inferCacheFileFormat {
			t.Errorf("after %q the file is %+v", content, file)
		}
	}
}

// A reader that yields its canary first, then randomness.
type testInferCacheCanaryReader struct {
	canary []byte
}

func (self *testInferCacheCanaryReader) Read(buffer []byte) (int, error) {
	if 0 < len(self.canary) {
		count := copy(buffer, self.canary)
		self.canary = self.canary[count:]
		return count, nil
	}
	return rand.Read(buffer)
}

// A logger that keeps every line, safe for concurrent use.
type testInferCacheLog struct {
	stateLock sync.Mutex
	lines     []string
}

func (self *testInferCacheLog) add(line string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lines = append(self.lines, line)
}

func (self *testInferCacheLog) Info(args ...any) { self.add(fmt.Sprint(args...)) }
func (self *testInferCacheLog) Infof(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}
func (self *testInferCacheLog) Warningf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}
func (self *testInferCacheLog) Errorf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}
func (self *testInferCacheLog) V(level int32) Verbose { return testInferCacheVerbose{log: self} }
func (self *testInferCacheLog) text() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return strings.Join(self.lines, "\n")
}

type testInferCacheVerbose struct {
	log *testInferCacheLog
}

func (self testInferCacheVerbose) Enabled() bool                    { return true }
func (self testInferCacheVerbose) Info(args ...any)                 { self.log.Info(args...) }
func (self testInferCacheVerbose) Infof(format string, args ...any) { self.log.Infof(format, args...) }

// The secret is drawn as a canary and found nowhere it must not be: in no log line at any verbosity, in no form a key
// prints or marshals to, in no error, and never in the clear in the repo's bytes, which hold it only sealed.
func TestSecretInNoRecordLogOrToolResult(t *testing.T) {
	canary := bytes.Repeat([]byte("CANARY-S_m-"), 3)[:inferCacheSecretByteCount]
	forms := [][]byte{
		canary,
		[]byte(hex.EncodeToString(canary)),
		[]byte(base64.StdEncoding.EncodeToString(canary)),
		[]byte(base64.RawURLEncoding.EncodeToString(canary)),
		[]byte(fmt.Sprint(canary)),
	}
	log := &testInferCacheLog{}
	world := newTestInferCacheWorld(t)
	member := NewId()
	clock := newTestEnvelopeClock()
	_, desktop := world.device(&testInferCacheDeviceArgs{member: &member, clock: clock, log: log, random: &testInferCacheCanaryReader{canary: bytes.Clone(canary)}})
	key, err := desktop.Secret(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	repoId := world.standingRepos(member)[0]
	if opened := testInferCacheOpened(t, world, desktop.host.(*testInferCacheDevice), repoId); !bytes.Equal(opened, canary) {
		t.Fatal("the draw did not take the canary")
	}
	// a failing sync and a refused seal, so the paths that log and err run
	_, phone := world.device(&testInferCacheDeviceArgs{member: &member, clock: clock, log: log})
	world.stateLock.Lock()
	delete(world.readerKeys, phone.host.(*testInferCacheDevice).me.SidecarId)
	world.stateLock.Unlock()
	clock.Advance(DefaultInferSettings().CacheSecretSyncInterval)
	testInferCacheTeeLine(t, desktop, "chutes")
	_, phoneErr := phone.Secret(context.Background())
	printed, err := json.Marshal(map[string]any{"key": key})
	if err != nil {
		t.Fatal(err)
	}
	surfaces := map[string][]byte{
		"the log":       []byte(log.text()),
		"%v":            []byte(fmt.Sprintf("%v", key)),
		"%+v":           []byte(fmt.Sprintf("%+v", key)),
		"%#v":           []byte(fmt.Sprintf("%#v", key)),
		"%x":            []byte(fmt.Sprintf("%x", key)),
		"%s":            []byte(fmt.Sprintf("%s", key)),
		"a tool result": printed,
		"an error":      []byte(fmt.Sprint(phoneErr)),
	}
	for _, content := range world.everything() {
		surfaces["the repo"] = append(surfaces["the repo"], content...)
	}
	for name, surface := range surfaces {
		for _, form := range forms {
			if bytes.Contains(surface, form) {
				t.Errorf("%s holds the secret as %q", name, form)
			}
		}
	}
	if line, err := key.TeeSaltLine("chutes"); err != nil || bytes.Contains([]byte(line), []byte(hex.EncodeToString(canary))) {
		t.Errorf("the salt line shows the secret: %q, %v", line, err)
	}
}
