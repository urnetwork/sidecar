// Key upkeep (KEYS-M2-18), pass by pass on a clock the test moves: FS-106's steps at unit level, a ReaderKey every
// 6 days, its private key kept exactly 30 days past its not_after, the self-check, KeyPackages and acks.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
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

// keychain.ur's namespace in memory.
type gkmTestSecrets struct {
	stateLock  sync.Mutex
	nameValues map[string][]byte
}

func newGkmTestSecrets() *gkmTestSecrets {
	return &gkmTestSecrets{nameValues: map[string][]byte{}}
}

func (self *gkmTestSecrets) Get(name string) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	value, ok := self.nameValues[name]
	if !ok {
		return nil, ErrSidecarStoreAbsent
	}
	return bytes.Clone(value), nil
}

func (self *gkmTestSecrets) Put(name string, value []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.nameValues[name] = bytes.Clone(value)
	return nil
}

func (self *gkmTestSecrets) Delete(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.nameValues, name)
	return nil
}

func (self *gkmTestSecrets) List(prefix string) ([]string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	names := []string{}
	for name := range maps.Keys(self.nameValues) {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names, nil
}

// gkm as upkeep sees it: what it was sent, and answers a test sets.
type gkmTestUpkeepApi struct {
	stateLock    sync.Mutex
	readerKeys   []*bridge.Signed
	readerKeyErr error
	// what the next ReaderKey uploads answer, in order, before readerKeyErr does
	readerKeyRefusals []error
	// every ReaderKey upload, refused or not
	readerKeyTries int
	// when set, each ReaderKey upload tells entered and waits for release, outside the lock
	readerKeyEntered   chan struct{}
	readerKeyRelease   chan struct{}
	served             *bridge.Signed
	servedSet          bool
	keyPackageUploads  [][][]byte
	keyPackageErr      error
	acks               []*GkmAckGroup
	selfCheckReadCount int
}

func (self *gkmTestUpkeepApi) UploadReaderKey(ctx context.Context, readerKey *bridge.Signed) error {
	entered, release := func() (chan struct{}, chan struct{}) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.readerKeyEntered, self.readerKeyRelease
	}()
	if entered != nil {
		entered <- struct{}{}
		<-release
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.readerKeyTries += 1
	if 0 < len(self.readerKeyRefusals) {
		err := self.readerKeyRefusals[0]
		self.readerKeyRefusals = self.readerKeyRefusals[1:]
		return err
	}
	if self.readerKeyErr != nil {
		return self.readerKeyErr
	}
	self.readerKeys = append(self.readerKeys, readerKey)
	return nil
}

// The ReaderKey uploads gkm took and the uploads tried, refused ones included.
func (self *gkmTestUpkeepApi) readerKeyCounts() (taken int, tried int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.readerKeys), self.readerKeyTries
}

// What gkm serves: what a test set, else the newest upload.
func (self *gkmTestUpkeepApi) ReaderKey(ctx context.Context, sidecarId Id) (*bridge.Signed, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.selfCheckReadCount += 1
	if self.servedSet {
		return self.served, nil
	}
	if len(self.readerKeys) == 0 {
		return nil, nil
	}
	return self.readerKeys[len(self.readerKeys)-1], nil
}

func (self *gkmTestUpkeepApi) UploadKeyPackages(ctx context.Context, keyPackages [][]byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.keyPackageErr != nil && 1 < len(keyPackages) {
		return self.keyPackageErr
	}
	self.keyPackageUploads = append(self.keyPackageUploads, keyPackages)
	return nil
}

func (self *gkmTestUpkeepApi) Ack(ctx context.Context, repoId Id, groupId Id, epoch uint64) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.acks = append(self.acks, &GkmAckGroup{RepoId: repoId, GroupId: groupId, Epoch: epoch})
	return nil
}

// A sidecar's upkeep on a test clock, keychain and gkm, driven pass by pass.
type gkmUpkeepFixture struct {
	t          *testing.T
	clock      *gkmTestClock
	secrets    *gkmTestSecrets
	api        *gkmTestUpkeepApi
	upkeep     *GkmUpkeep
	sidecarId  Id
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	role       GkmUpkeepRole
	ackGroups  []*GkmAckGroup
	events     []SidecarEvent
	created    int
}

func newGkmUpkeepFixture(t *testing.T, role GkmUpkeepRole) *gkmUpkeepFixture {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &gkmUpkeepFixture{
		t:          t,
		clock:      newGkmTestClock(),
		secrets:    newGkmTestSecrets(),
		api:        &gkmTestUpkeepApi{},
		sidecarId:  NewId(),
		publicKey:  publicKey,
		privateKey: privateKey,
		role:       role,
	}
	fixture.upkeep, err = newGkmUpkeep(context.Background(), &GkmUpkeepArgs{
		SidecarId: fixture.sidecarId,
		Api:       fixture.api,
		Sign:      fixture.sign,
		Secrets:   fixture.secrets,
		CreateKeyPackage: func(lastResort bool) (*MlsKeyPackage, error) {
			fixture.created += 1
			return &MlsKeyPackage{Encoded: []byte{byte(fixture.created)}, LastResort: lastResort}, nil
		},
		Role:      func() GkmUpkeepRole { return fixture.role },
		AckGroups: func() []*GkmAckGroup { return fixture.ackGroups },
		Emit:      func(event SidecarEvent) { fixture.events = append(fixture.events, event) },
		Clock:     fixture.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (self *gkmUpkeepFixture) sign(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error) {
	return &bridge.Signed{
		Body:      bytes.Clone(body),
		SignerId:  self.sidecarId.Bytes(),
		Signature: ed25519.Sign(self.privateKey, bridge.SignedBytes(purpose, signedType, body)),
		Type:      uint32(signedType),
	}, nil
}

// One pass at the clock's now.
func (self *gkmUpkeepFixture) pass() {
	self.upkeep.pass(context.Background())
}

// The digests of the ReaderKeys whose private keys the keychain holds.
func (self *gkmUpkeepFixture) heldDigests() [][]byte {
	self.t.Helper()
	names, err := self.secrets.List(gkmUpkeepReaderKeyPrefix)
	if err != nil {
		self.t.Fatal(err)
	}
	digests := [][]byte{}
	for _, name := range names {
		record, err := decodeGkmReaderKeyRecord(self.secrets.nameValues[name])
		if err != nil {
			self.t.Fatal(err)
		}
		digests = append(digests, record.keySha256)
	}
	return digests
}

// A ReaderKey's key digest and not_after.
func gkmTestReaderKeyOf(t *testing.T, signed *bridge.Signed) ([]byte, time.Time) {
	t.Helper()
	body := &protocol.ReaderKey{}
	if err := proto.Unmarshal(signed.GetBody(), body); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body.GetXwingPublicKey())
	return digest[:], time.UnixMilli(body.GetNotAfter())
}

// FS-106 at unit level over 35 days on a fake clock, a reader-only member device holding only r scopes: a ReaderKey
// every 6 days, each valid 7, each checked under the identity key and named for this sidecar; acks once a day; a
// key-packages-low hint's refill.
func TestGkmUpkeepKeepsAReaderKeyEverySixDaysAndAcksDaily(t *testing.T) {
	fixture := newGkmUpkeepFixture(t, GkmUpkeepRole{MemberDevice: true})
	repoId, groupId := NewId(), NewId()
	fixture.ackGroups = []*GkmAckGroup{{RepoId: repoId, GroupId: groupId, Epoch: 1}}
	start := fixture.clock.Now()
	for hour := 0; hour <= 35*24; hour += 1 {
		if hour == 10*24 {
			fixture.upkeep.RefillKeyPackages()
		}
		fixture.ackGroups[0].Epoch = uint64(1 + hour/24)
		fixture.pass()
		fixture.clock.Advance(time.Hour)
	}
	uploads := fixture.api.readerKeys
	// days 0, 6, 12, 18, 24, 30
	if len(uploads) != 6 {
		t.Fatalf("%d ReaderKeys in 35 days, want 6", len(uploads))
	}
	for i, signed := range uploads {
		readerKey, err := CheckGkmReaderKey(signed, fixture.sidecarId, fixture.publicKey, start.Add(time.Duration(i)*6*24*time.Hour).UnixMilli())
		if err != nil {
			t.Fatalf("ReaderKey %d: %v", i, err)
		}
		if notAfter := time.UnixMilli(readerKey.Body.GetNotAfter()); !notAfter.Equal(start.Add(time.Duration(i)*6*24*time.Hour + 7*24*time.Hour)) {
			t.Errorf("ReaderKey %d valid to %s", i, notAfter)
		}
		for j := 0; j < i; j += 1 {
			if bytes.Equal(uploads[j].GetBody(), signed.GetBody()) {
				t.Error("a ReaderKey was signed again")
			}
		}
	}
	if len(fixture.api.acks) != 36 {
		t.Errorf("%d acks in 35 days, want 36", len(fixture.api.acks))
	}
	if ack := fixture.api.acks[len(fixture.api.acks)-1]; ack.GroupId != groupId || ack.Epoch != 36 {
		t.Errorf("the last ack %+v", ack)
	}
	// a full set and a last-resort at first, a refill at the hint's ask
	keyPackages := fixture.api.keyPackageUploads
	if len(keyPackages) != 2 || len(keyPackages[0]) != 129 || len(keyPackages[1]) != 97 {
		t.Errorf("KeyPackage uploads of %d sets", len(keyPackages))
	}
}

// D-KEYS-25: a replaced or lapsed private key is kept until exactly 30 days past its not_after, opening what was
// sealed to it until then, and is gone after.
func TestGkmUpkeepKeepsAPrivateKeyExactlyThirtyDaysPastItsNotAfter(t *testing.T) {
	fixture := newGkmUpkeepFixture(t, GkmUpkeepRole{})
	fixture.pass()
	first := fixture.api.readerKeys[0]
	digest, notAfter := gkmTestReaderKeyOf(t, first)
	privateKey, err := fixture.upkeep.ReaderPrivateKey(digest)
	if err != nil {
		t.Fatal(err)
	}
	if publicKeySha256 := sha256.Sum256(privateKey.PublicKey().Bytes()); !bytes.Equal(publicKeySha256[:], digest) {
		t.Fatal("the kept private key is not the ReaderKey's")
	}
	keptUntil := notAfter.Add(30 * 24 * time.Hour)
	fixture.clock.Advance(keptUntil.Sub(fixture.clock.Now()) - time.Millisecond)
	fixture.pass()
	if _, err := fixture.upkeep.ReaderPrivateKey(digest); err != nil {
		t.Errorf("a millisecond before 30 days past its not_after: %v", err)
	}
	fixture.clock.Advance(time.Millisecond)
	fixture.pass()
	if _, err := fixture.upkeep.ReaderPrivateKey(digest); !errors.Is(err, ErrGkmKeyMissing) {
		t.Errorf("30 days past its not_after: %v", err)
	}
	if slices.ContainsFunc(fixture.heldDigests(), func(held []byte) bool { return bytes.Equal(held, digest) }) {
		t.Error("the keychain still holds its record")
	}
}

// A ReaderKey goes into the keychain before its upload, so a failed upload sends the same bytes at the next pass,
// never a key signed again; a parked device's waits for its lift.
func TestGkmUpkeepSendsTheSameReaderKeyAfterAFailedUpload(t *testing.T) {
	fixture := newGkmUpkeepFixture(t, GkmUpkeepRole{})
	fixture.api.readerKeyErr = &GkmError{Status: http.StatusForbidden}
	fixture.pass()
	digests := fixture.heldDigests()
	if len(digests) != 1 || len(fixture.api.readerKeys) != 0 {
		t.Fatalf("after a refused upload: %d keys held, %d uploaded", len(digests), len(fixture.api.readerKeys))
	}
	fixture.clock.Advance(time.Hour)
	fixture.api.readerKeyErr = nil
	fixture.pass()
	if len(fixture.api.readerKeys) != 1 {
		t.Fatal("the ReaderKey did not go up after the lift")
	}
	if digest, _ := gkmTestReaderKeyOf(t, fixture.api.readerKeys[0]); !bytes.Equal(digest, digests[0]) {
		t.Error("another key went up in its place")
	}
	fixture.pass()
	if len(fixture.api.readerKeys) != 1 {
		t.Error("an uploaded ReaderKey went up again")
	}
}

// The daily self-check (g0-recheck-0-readerkey-forgery #2): a valid key gkm serves that this keychain never signed
// raises key_changed naming its digest; gkm serving none, or an older key of its own, sends the current one again.
func TestGkmUpkeepSelfCheckRaisesKeyChangedForAForeignKey(t *testing.T) {
	fixture := newGkmUpkeepFixture(t, GkmUpkeepRole{})
	fixture.pass()
	if fixture.api.selfCheckReadCount != 1 || len(fixture.events) != 0 {
		t.Fatalf("the first self-check: %d reads, %d events", fixture.api.selfCheckReadCount, len(fixture.events))
	}
	// an active clone's key, signed by this sidecar's identity key outside this keychain
	now := fixture.clock.Now()
	foreign, _, err := NewGkmReaderKey(fixture.sidecarId, now, now.Add(7*24*time.Hour), fixture.sign)
	if err != nil {
		t.Fatal(err)
	}
	fixture.api.servedSet = true
	fixture.api.served = foreign
	fixture.clock.Advance(23 * time.Hour)
	fixture.pass()
	if len(fixture.events) != 0 {
		t.Error("the self-check ran within its day")
	}
	fixture.clock.Advance(time.Hour)
	fixture.pass()
	foreignDigest, _ := gkmTestReaderKeyOf(t, foreign)
	if len(fixture.events) != 1 || fixture.events[0].Kind != SidecarEventKeyChanged || !bytes.Equal(fixture.events[0].Evidence[0], foreignDigest) {
		t.Fatalf("events %+v", fixture.events)
	}
	// gkm lost it: the next pass sends the current one again
	fixture.api.served = nil
	fixture.clock.Advance(24 * time.Hour)
	fixture.pass()
	fixture.pass()
	if len(fixture.api.readerKeys) != 2 || !bytes.Equal(fixture.api.readerKeys[0].GetBody(), fixture.api.readerKeys[1].GetBody()) {
		t.Errorf("after gkm lost it: %d uploads", len(fixture.api.readerKeys))
	}
}

// Agents upload only a ReaderKey, and a device recovering by its member's code none of its KeyPackages until it has
// anchored (§7.9's anchor); a read_only member device keeps its upkeep under r, KeyPackages included (FS-106).
func TestGkmUpkeepKeyPackagesOnlyFromAnchoredMemberDevices(t *testing.T) {
	agent := newGkmUpkeepFixture(t, GkmUpkeepRole{})
	agent.pass()
	if len(agent.api.readerKeys) != 1 || len(agent.api.keyPackageUploads) != 0 || agent.created != 0 {
		t.Errorf("an agent: %d ReaderKeys, %d KeyPackage uploads", len(agent.api.readerKeys), len(agent.api.keyPackageUploads))
	}
	restored := newGkmUpkeepFixture(t, GkmUpkeepRole{MemberDevice: true, AwaitingAnchor: true})
	restored.pass()
	if len(restored.api.readerKeys) != 1 || len(restored.api.keyPackageUploads) != 0 {
		t.Error("a device waiting to anchor uploaded KeyPackages")
	}
	restored.role.AwaitingAnchor = false
	restored.clock.Advance(time.Hour)
	restored.pass()
	if len(restored.api.keyPackageUploads) != 1 {
		t.Error("an anchored device uploaded no KeyPackage")
	}
}

// KeyPackages renew on their own schedule: the last-resort at 60 days, a full set at 90 once every earlier one has
// lapsed, and a renewal gkm refuses past its count goes up again an hour later with the last-resort sent alone.
func TestGkmUpkeepRenewsKeyPackagesBeforeTheyLapse(t *testing.T) {
	fixture := newGkmUpkeepFixture(t, GkmUpkeepRole{MemberDevice: true})
	fixture.pass()
	if len(fixture.api.keyPackageUploads) != 1 {
		t.Fatal("no first set")
	}
	fixture.clock.Advance(60 * 24 * time.Hour)
	fixture.pass()
	if uploads := fixture.api.keyPackageUploads; len(uploads) != 2 || len(uploads[1]) != 1 {
		t.Fatalf("the last-resort's renewal: %d uploads", len(uploads))
	}
	fixture.clock.Advance(30 * 24 * time.Hour)
	fixture.api.keyPackageErr = &GkmError{Status: http.StatusTooManyRequests}
	fixture.pass()
	if len(fixture.api.keyPackageUploads) != 2 {
		t.Fatal("a refused renewal was recorded as sent")
	}
	fixture.clock.Advance(59 * time.Minute)
	fixture.pass()
	created := fixture.created
	if created != 129+1+128 {
		t.Errorf("%d KeyPackages made, a retry within the hour", created)
	}
	fixture.api.keyPackageErr = nil
	fixture.clock.Advance(time.Minute)
	fixture.pass()
	if uploads := fixture.api.keyPackageUploads; len(uploads) != 3 || len(uploads[2]) != 128 {
		t.Errorf("the renewal an hour on: %d uploads", len(uploads))
	}
}

// A join through the last-resort KeyPackage replaces it at the next pass, well before its 60 days, since its leaf
// key is every Welcome's that package served; a pass after the replacement uploads nothing more (DESIGN-DETAILS
// 6.2.2, TestALastResortJoinSelfUpdatesAtOnce's upkeep half).
func TestGkmUpkeepReplacesTheLastResortKeyPackageAfterAJoinThroughIt(t *testing.T) {
	fixture := newGkmUpkeepFixture(t, GkmUpkeepRole{MemberDevice: true})
	fixture.pass()
	if len(fixture.api.keyPackageUploads) != 1 {
		t.Fatal("no first set")
	}
	fixture.clock.Advance(time.Hour)
	fixture.pass()
	if len(fixture.api.keyPackageUploads) != 1 {
		t.Fatal("a KeyPackage went up with nothing due")
	}
	fixture.role.LastResortJoinedAt = fixture.clock.Now()
	fixture.clock.Advance(time.Hour)
	fixture.pass()
	if uploads := fixture.api.keyPackageUploads; len(uploads) != 2 || len(uploads[1]) != 1 {
		t.Fatalf("the last-resort's replacement after a join through it: %d uploads", len(uploads))
	}
	fixture.clock.Advance(time.Hour)
	fixture.pass()
	if len(fixture.api.keyPackageUploads) != 2 {
		t.Errorf("the replaced last-resort KeyPackage went up again")
	}
}

// A running upkeep on a test clock, its loop started, with hints when given.
func startGkmTestUpkeep(t *testing.T, clock *gkmTestClock, hints *GkmHints, api *gkmTestUpkeepApi) *GkmUpkeep {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	upkeep, err := NewGkmUpkeep(context.Background(), &GkmUpkeepArgs{
		SidecarId: NewId(),
		Api:       api,
		Sign: func(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error) {
			return &bridge.Signed{Body: bytes.Clone(body), Signature: ed25519.Sign(privateKey, bridge.SignedBytes(purpose, signedType, body)), Type: uint32(signedType)}, nil
		},
		Secrets: newGkmTestSecrets(),
		CreateKeyPackage: func(lastResort bool) (*MlsKeyPackage, error) {
			return &MlsKeyPackage{Encoded: []byte{1}, LastResort: lastResort}, nil
		},
		Role:  func() GkmUpkeepRole { return GkmUpkeepRole{MemberDevice: true} },
		Hints: hints,
		Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(upkeep.Close)
	return upkeep
}

// Waits until upkeep has finished more than after passes.
func awaitGkmUpkeepPasses(upkeep *GkmUpkeep, after int) {
	for {
		count, changed := upkeep.Passes()
		if after < count {
			return
		}
		<-changed
	}
}

// The loop runs a pass at start, at each ask, and every UpkeepInterval.
func TestGkmUpkeepLoopRunsOnItsIntervalAndOnAsks(t *testing.T) {
	clock := newGkmTestClock()
	upkeep := startGkmTestUpkeep(t, clock, nil, &gkmTestUpkeepApi{})
	awaitGkmUpkeepPasses(upkeep, 0)
	<-clock.armed
	upkeep.RefillKeyPackages()
	awaitGkmUpkeepPasses(upkeep, 1)
	<-clock.armed
	clock.Advance(DefaultGkmSettings().UpkeepInterval)
	awaitGkmUpkeepPasses(upkeep, 2)
}

// A key-packages-low hint reaches upkeep through the intake and refills at once.
func TestGkmUpkeepRefillsAtAKeyPackagesLowHint(t *testing.T) {
	clock := newGkmTestClock()
	hints, err := NewGkmHints(context.Background(), &GkmHintsArgs{Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	defer hints.Close()
	api := &gkmTestUpkeepApi{}
	upkeep := startGkmTestUpkeep(t, clock, hints, api)
	awaitGkmUpkeepPasses(upkeep, 0)
	count, _ := upkeep.Passes()
	hints.Receive(gkmTestNotice(t, PushTopicGkm, 1, &protocol.GkmHint{Kind: protocol.GkmHintKind_GKM_HINT_KEY_PACKAGES_LOW}))
	awaitGkmUpkeepPasses(upkeep, count)
	api.stateLock.Lock()
	defer api.stateLock.Unlock()
	if len(api.keyPackageUploads) != 2 || len(api.keyPackageUploads[1]) != 97 {
		t.Errorf("after the hint: %d uploads", len(api.keyPackageUploads))
	}
}

// Waits until upkeep has finished more than after ReaderKey tries between passes.
func awaitGkmUpkeepRetries(upkeep *GkmUpkeep, after int) {
	for {
		count, changed := upkeep.ReaderKeyRetries()
		if after < count {
			return
		}
		<-changed
	}
}

// Waits until clock arms a wait of timeout, passing over the waits armed before it.
func awaitGkmTestArmed(clock *gkmTestClock, timeout time.Duration) {
	for armed := range clock.armed {
		if armed == timeout {
			return
		}
	}
}

// The fixture's upkeep with its loop running until the test ends.
func (self *gkmUpkeepFixture) run() {
	go self.upkeep.run()
	self.t.Cleanup(self.upkeep.Close)
}

// The upkeep's ReaderKey retry as it stands, nil for none.
func (self *gkmUpkeepFixture) readerKeyRetry() *gkmReaderKeyRetry {
	self.upkeep.stateLock.Lock()
	defer self.upkeep.stateLock.Unlock()
	return self.upkeep.readerKeyRetry
}

// A network's first device makes its first ReaderKey upload while gkm is still loading the network's state, which gkm
// refuses with 503 and then the token exchange with its own temporary refusal: the upkeep tries again a second later
// and two seconds after that, and the key stands at gkm 3 s after the first try on the upkeep's clock, with no pass
// between, the same key the keychain kept before the first try. Then no try is due and none is made, and the next
// pass, an UpkeepInterval on, uploads nothing more.
func TestGkmUpkeepTriesARefusedReaderKeyUploadAgainWithinSeconds(t *testing.T) {
	fixture := newGkmUpkeepFixture(t, GkmUpkeepRole{})
	fixture.api.readerKeyRefusals = []error{
		&GkmError{Status: http.StatusServiceUnavailable},
		errors.New("gkm POST /gkm/reader-key: no service token: sidecar api POST /oauth/token refused: 503 temporarily_unavailable"),
	}
	start := fixture.clock.Now()
	fixture.run()
	awaitGkmUpkeepPasses(fixture.upkeep, 0)
	if taken, tried := fixture.api.readerKeyCounts(); taken != 0 || tried != 1 {
		t.Fatalf("the first pass: %d ReaderKeys taken of %d tried", taken, tried)
	}
	digests := fixture.heldDigests()
	if len(digests) != 1 || fixture.upkeep.CurrentReaderKeySha256() != nil {
		t.Fatalf("after the refused upload: %d keys held", len(digests))
	}
	if retry := fixture.readerKeyRetry(); retry == nil || retry.backoff != time.Second {
		t.Fatalf("the retry after the refused upload: %+v", retry)
	}
	awaitGkmTestArmed(fixture.clock, time.Second)
	fixture.clock.Advance(time.Second)
	awaitGkmUpkeepRetries(fixture.upkeep, 0)
	if taken, tried := fixture.api.readerKeyCounts(); taken != 0 || tried != 2 {
		t.Fatalf("the first try again: %d ReaderKeys taken of %d tried", taken, tried)
	}
	awaitGkmTestArmed(fixture.clock, 2*time.Second)
	fixture.clock.Advance(2 * time.Second)
	awaitGkmUpkeepRetries(fixture.upkeep, 1)
	if taken, tried := fixture.api.readerKeyCounts(); taken != 1 || tried != 3 {
		t.Fatalf("the second try again: %d ReaderKeys taken of %d tried", taken, tried)
	}
	if elapsed := fixture.clock.Now().Sub(start); elapsed != 3*time.Second {
		t.Errorf("the ReaderKey stood %s after the first try", elapsed)
	}
	if count, _ := fixture.upkeep.Passes(); count != 1 {
		t.Errorf("%d passes before the ReaderKey stood", count)
	}
	uploaded, _ := gkmTestReaderKeyOf(t, fixture.api.readerKeys[0])
	if !bytes.Equal(uploaded, digests[0]) || !bytes.Equal(fixture.upkeep.CurrentReaderKeySha256(), uploaded) {
		t.Error("the key that stood is not the one kept before the first try")
	}
	if retry := fixture.readerKeyRetry(); retry != nil {
		t.Errorf("a retry is still due after the upload stood: %+v", retry)
	}
	fixture.clock.Advance(DefaultGkmSettings().UpkeepInterval - 3*time.Second)
	awaitGkmUpkeepPasses(fixture.upkeep, 1)
	if taken, tried := fixture.api.readerKeyCounts(); taken != 1 || tried != 3 {
		t.Errorf("after the next pass: %d ReaderKeys taken of %d tried", taken, tried)
	}
	if count, _ := fixture.upkeep.ReaderKeyRetries(); count != 2 {
		t.Errorf("%d tries between passes, want 2", count)
	}
}

// The retry's wait: ReaderKeyRetryWait, twice as long each failed try in a row up to ReaderKeyRetryMaxWait, across a
// pass too; a 429's Retry-After at least; none after gkm's 401 or 400 or an upload that stood, a later failure starting
// over at ReaderKeyRetryWait; none with ReaderKeyRetryWait zero. An upload that found no scope to present, on an api
// that cannot tell its scopes, waits the backoff too.
func TestGkmUpkeepReaderKeyRetryBacksOffToItsCap(t *testing.T) {
	fixture := newGkmUpkeepFixture(t, GkmUpkeepRole{})
	ctx := context.Background()
	backoff := func() time.Duration {
		t.Helper()
		retry := fixture.readerKeyRetry()
		if retry == nil {
			t.Fatal("no retry is due")
		}
		return retry.backoff
	}
	fixture.api.readerKeyErr = &GkmError{Status: http.StatusServiceUnavailable}
	fixture.pass()
	waits := []time.Duration{backoff()}
	for i := 0; i < 6; i += 1 {
		fixture.upkeep.retryReaderKey(ctx)
		waits = append(waits, backoff())
	}
	fixture.pass()
	waits = append(waits, backoff())
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, time.Minute, time.Minute}
	if !slices.Equal(waits, want) {
		t.Fatalf("the waits %v, want %v", waits, want)
	}

	fixture.api.readerKeyErr = &GkmError{Status: http.StatusTooManyRequests, RetryAfter: 10 * time.Minute}
	fixture.upkeep.retryReaderKey(ctx)
	if retry := fixture.readerKeyRetry(); retry.backoff != time.Minute || retry.retryAfter != 10*time.Minute {
		t.Fatalf("after a 429: %+v", retry)
	}
	retryDue, _ := fixture.upkeep.readerKeyRetryWait()
	if retryDue == nil {
		t.Fatal("no wait after a 429")
	}
	awaitGkmTestArmed(fixture.clock, 10*time.Minute)

	for _, definite := range []error{
		fmt.Errorf("%w: POST /gkm/reader-key", ErrGkmTokenRefused),
		&GkmError{Status: http.StatusBadRequest},
		nil,
	} {
		fixture.api.readerKeyErr = &GkmError{Status: http.StatusServiceUnavailable}
		fixture.upkeep.retryReaderKey(ctx)
		fixture.api.readerKeyErr = definite
		fixture.upkeep.retryReaderKey(ctx)
		if retry := fixture.readerKeyRetry(); retry != nil {
			t.Errorf("a retry after %v: %+v", definite, retry)
		}
		if definite == nil {
			break
		}
		fixture.api.readerKeyErr = &GkmError{Status: http.StatusServiceUnavailable}
		fixture.upkeep.retryReaderKey(ctx)
		if wait := backoff(); wait != time.Second {
			t.Errorf("after %v the backoff starts at %s", definite, wait)
		}
	}

	// a fresh key whose upload finds no scope to present, on an api that cannot tell its scopes
	noScope := newGkmUpkeepFixture(t, GkmUpkeepRole{})
	noScope.api.readerKeyErr = ErrGkmNoScope
	noScope.pass()
	if retry := noScope.readerKeyRetry(); retry == nil || !retry.noScope || retry.backoff != time.Second {
		t.Fatalf("after no scope: %+v", retry)
	}
	if retryDue, scopesChanged := noScope.upkeep.readerKeyRetryWait(); retryDue == nil || scopesChanged != nil {
		t.Error("an api that cannot tell its scopes waits on something else than the backoff")
	}
	// an api that says it holds a scope its uploads do not find is tried again on the backoff, never at once
	inconsistent := newGkmUpkeepFixture(t, GkmUpkeepRole{})
	inconsistent.upkeep.args.Api = &gkmTestHeldScopesApi{gkmTestUpkeepApi: inconsistent.api}
	inconsistent.api.readerKeyErr = ErrGkmNoScope
	inconsistent.pass()
	if retry := inconsistent.readerKeyRetry(); retry == nil || retry.noScope || retry.backoff != time.Second {
		t.Fatalf("after no scope with one held: %+v", retry)
	}
	if retryDue, scopesChanged := inconsistent.upkeep.readerKeyRetryWait(); retryDue == nil || scopesChanged != nil {
		t.Error("an api that holds a scope its upload found none of is not tried on the backoff")
	}
	awaitGkmTestArmed(inconsistent.clock, time.Second)

	settings := DefaultGkmSettings()
	settings.ReaderKeyRetryWait = 0
	off := newGkmUpkeepFixture(t, GkmUpkeepRole{})
	off.upkeep.settings = settings
	off.api.readerKeyErr = &GkmError{Status: http.StatusServiceUnavailable}
	off.pass()
	if retry := off.readerKeyRetry(); retry != nil {
		t.Errorf("a retry with ReaderKeyRetryWait 0: %+v", retry)
	}
}

// An api that says it holds a scope a ReaderKey's upload can present, though its uploads find none.
type gkmTestHeldScopesApi struct {
	*gkmTestUpkeepApi
}

func (self *gkmTestHeldScopesApi) accessScopes() (bool, <-chan struct{}) {
	return true, make(chan struct{})
}

// The POSTs to /gkm/reader-key a fake gkm took.
func gkmTestReaderKeyPosts(transport *gkmTestTransport) []*gkmTestRequest {
	posts := []*gkmTestRequest{}
	for _, request := range transport.taken() {
		if request.method == http.MethodPost && request.path == "/gkm/reader-key" {
			posts = append(posts, request)
		}
	}
	return posts
}

// A network's first device starts its upkeep before any state gives it a repo scope, so its first upload finds no
// scope to present ("gkm: no repo scope to present") and reaches no gkm. A deposit scope alone presents nothing for a
// call on no repo and tries nothing; the state that first gives it an r scope has the key up at once, by the scope's
// change and no clock moved, under a token carrying that scope.
func TestGkmUpkeepPublishesTheReaderKeyWhenItFirstHasAScopeToPresent(t *testing.T) {
	fixture := newGkmUpkeepFixture(t, GkmUpkeepRole{})
	transport := &gkmTestTransport{}
	tokens := newGkmTestTokens()
	api := newGkmTestApi(t, transport, tokens, fixture.clock)
	fixture.upkeep.args.Api = api
	start := fixture.clock.Now()
	fixture.run()
	awaitGkmUpkeepPasses(fixture.upkeep, 0)
	if posts := gkmTestReaderKeyPosts(transport); len(posts) != 0 {
		t.Fatalf("%d uploads with no scope to present", len(posts))
	}
	if retry := fixture.readerKeyRetry(); retry == nil || !retry.noScope {
		t.Fatalf("the retry after no scope: %+v", retry)
	}
	api.SetRepoScopes([]GkmRepoScope{{RepoId: NewId(), Role: GkmScopeRoleDeposit}})
	repoId := NewId()
	api.SetRepoScopes([]GkmRepoScope{{RepoId: NewId(), Role: GkmScopeRoleDeposit}, {RepoId: repoId, Role: GkmScopeRoleRead}})
	awaitGkmUpkeepRetries(fixture.upkeep, 0)
	if count, _ := fixture.upkeep.ReaderKeyRetries(); count != 1 {
		t.Errorf("%d tries, the deposit scope's among them", count)
	}
	posts := gkmTestReaderKeyPosts(transport)
	if len(posts) != 1 {
		t.Fatalf("%d uploads once a scope stands", len(posts))
	}
	if !slices.Contains(tokens.scopesOf(posts[0].token), GkmRepoScope{RepoId: repoId, Role: GkmScopeRoleRead}.scope()) {
		t.Errorf("the upload's token holds %v", tokens.scopesOf(posts[0].token))
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(posts[0].body, signed); err != nil {
		t.Fatal(err)
	}
	digests := fixture.heldDigests()
	if uploaded, _ := gkmTestReaderKeyOf(t, signed); len(digests) != 1 || !bytes.Equal(uploaded, digests[0]) || !bytes.Equal(fixture.upkeep.CurrentReaderKeySha256(), uploaded) {
		t.Error("the key that went up is not the one kept before the first pass")
	}
	if retry := fixture.readerKeyRetry(); retry != nil {
		t.Errorf("a retry is still due after the upload stood: %+v", retry)
	}
	if now := fixture.clock.Now(); !now.Equal(start) {
		t.Errorf("the clock moved to %s", now)
	}
}

// One ReaderKey upload is in flight at most: a try between passes holds passLock across its upload, which every pass
// takes, so a pass a test or the loop asks for meanwhile waits for it and then finds the key up.
func TestGkmUpkeepKeepsOneReaderKeyUploadInFlight(t *testing.T) {
	fixture := newGkmUpkeepFixture(t, GkmUpkeepRole{})
	fixture.api.readerKeyRefusals = []error{&GkmError{Status: http.StatusServiceUnavailable}}
	fixture.run()
	awaitGkmUpkeepPasses(fixture.upkeep, 0)
	awaitGkmTestArmed(fixture.clock, time.Second)
	entered := make(chan struct{})
	release := make(chan struct{})
	func() {
		fixture.api.stateLock.Lock()
		defer fixture.api.stateLock.Unlock()
		fixture.api.readerKeyEntered, fixture.api.readerKeyRelease = entered, release
	}()
	fixture.clock.Advance(time.Second)
	<-entered
	if fixture.upkeep.passLock.TryLock() {
		fixture.upkeep.passLock.Unlock()
		t.Fatal("a try between passes uploads without passLock")
	}
	func() {
		fixture.api.stateLock.Lock()
		defer fixture.api.stateLock.Unlock()
		fixture.api.readerKeyEntered, fixture.api.readerKeyRelease = nil, nil
	}()
	close(release)
	awaitGkmUpkeepRetries(fixture.upkeep, 0)
	fixture.upkeep.Refresh()
	awaitGkmUpkeepPasses(fixture.upkeep, 1)
	if taken, tried := fixture.api.readerKeyCounts(); taken != 1 || tried != 2 {
		t.Errorf("%d ReaderKeys taken of %d tried", taken, tried)
	}
}

// GkmSettings refuses a ReaderKey valid past §10.5's 7 days or not past its replacement, a refill point past the
// count, a last-resort renewed no sooner than the set, and a ReaderKey retry whose wait shrinks or stops below where
// it starts.
func TestGkmSettingsRefuseWhatTheDesignCannotTake(t *testing.T) {
	if err := DefaultGkmSettings().validate(); err != nil {
		t.Fatalf("the defaults: %v", err)
	}
	for _, edit := range []func(settings *GkmSettings){
		func(settings *GkmSettings) { settings.ReaderKeyLifetime = GkmReaderKeyLifetime + time.Minute },
		func(settings *GkmSettings) { settings.ReaderKeyReplaceAge = settings.ReaderKeyLifetime },
		func(settings *GkmSettings) { settings.KeyPackageLowCount = settings.KeyPackageCount + 1 },
		func(settings *GkmSettings) { settings.KeyPackageLastResortRenewAge = settings.KeyPackageRenewAge },
		func(settings *GkmSettings) { settings.ReaderKeyRetryFactor = 0.5 },
		func(settings *GkmSettings) { settings.ReaderKeyRetryMaxWait = settings.ReaderKeyRetryWait / 2 },
	} {
		settings := DefaultGkmSettings()
		edit(settings)
		if err := settings.validate(); !errors.Is(err, errInvalidSettings) {
			t.Errorf("a refused value passed: %v", err)
		}
	}
}
