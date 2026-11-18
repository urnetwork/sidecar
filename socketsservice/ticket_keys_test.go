// SocketTicketKeySet (SOCK-M5-08) on a fake clock and an in-memory key file: a rotation keeps the old key verifying
// while the new one settles and then signs, an expired key verifies nothing, a file that cannot be used is refused
// whole with the last good keys kept, and keygen's add drops the expired. A key settles from the later of its
// creation and its first sight (QD-1016): one placed long after its creation waits SettleTime from the read that
// first sees it, a restarted set signs with the oldest live key outliving SignMargin for its first SettleTime, one
// seen at its creation settles as before, and a key that leaves the file, or an id that comes back naming another
// key, is seen anew.

package socketsservice_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/socketsservice"
)

// A key file a test rewrites, read as vault's secret_files are.
type testTicketKeyFile struct {
	stateLock sync.Mutex
	data      []byte
	err       error
}

func (self *testTicketKeyFile) set(data []byte, err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.data, self.err = data, err
}

func (self *testTicketKeyFile) read() ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.data, self.err
}

// The ids of the keys that verify.
func testTicketVerifyKeyIds(keySet *socketsservice.SocketTicketKeySet) []string {
	keyIds := []string{}
	for _, key := range keySet.VerifyKeys() {
		keyIds = append(keyIds, key.KeyId)
	}
	return keyIds
}

// A set on clock reading file, and what reads the file again now. Each test rereads by hand, so no clock move
// races a read; the reread on its interval is its own test. A test changes the file and rereads it with no clock
// move between, so a reread on the interval in that gap, which the set serializes with the hand's, sees it at the
// same time and the first sight is the hand's time either way.
func testTicketKeySet(t *testing.T, clock *sidecartest.FakeClock, file *testTicketKeyFile) (*socketsservice.SocketTicketKeySet, func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	keySet, err := socketsservice.NewSocketTicketKeySet(ctx, file.read, clock, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return keySet, keySet.ReloadForTest
}

// One key as the file holds it, its seed included, which only a test reads.
type testTicketKeyYaml struct {
	KeyId         string `yaml:"key_id"`
	Seed          string `yaml:"seed"`
	CreatedMillis int64  `yaml:"created_millis"`
	ExpireMillis  int64  `yaml:"expire_millis"`
}

// A key file as a test reads and rewrites it.
type testTicketKeyFileYaml struct {
	Keys []*testTicketKeyYaml `yaml:"keys"`
}

// data with keyId naming the key of seed, its times as they were: an id that comes back naming another key.
func testTicketKeyFileReseeded(t *testing.T, data []byte, keyId string, seed []byte) []byte {
	t.Helper()
	file := &testTicketKeyFileYaml{}
	if err := yaml.Unmarshal(data, file); err != nil {
		t.Fatal(err)
	}
	reseededCount := 0
	for _, key := range file.Keys {
		if key.KeyId == keyId {
			key.Seed = base64.StdEncoding.EncodeToString(seed)
			reseededCount += 1
		}
	}
	if reseededCount != 1 {
		t.Fatalf("the file names %s %d times", keyId, reseededCount)
	}
	reseeded, err := yaml.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	return reseeded
}

// A deployment's first key signs at once; a second verifies at once and signs once it has settled, the first
// verifying on through its overlap; past its expiry the first verifies nothing.
func TestTicketKeyRotationSignsTheNewestSettledKey(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	settings := socketsservice.DefaultSocketTicketKeySettings()
	first, err := socketsservice.SocketTicketKeyFileAdd(nil, clock.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	file := &testTicketKeyFile{data: first}
	keySet, reload := testTicketKeySet(t, clock, file)
	firstKeyId, firstKey, signs := keySet.SigningKey()
	if !signs || len(firstKey) != ed25519.PrivateKeySize || len(keySet.VerifyKeys()) != 1 {
		t.Fatal("a first key does not sign")
	}

	clock.Advance(settings.RotationInterval)
	second, err := socketsservice.SocketTicketKeyFileAdd(first, clock.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	file.set(second, nil)
	reload()
	verifyKeyIds := testTicketVerifyKeyIds(keySet)
	if len(verifyKeyIds) != 2 || verifyKeyIds[0] != firstKeyId {
		t.Fatalf("after the rotation %v verify", verifyKeyIds)
	}
	secondKeyId := verifyKeyIds[1]
	if keyId, _, _ := keySet.SigningKey(); keyId != firstKeyId {
		t.Fatal("a key that has not settled signs")
	}
	clock.Advance(settings.SettleTime)
	if keyId, _, _ := keySet.SigningKey(); keyId != secondKeyId {
		t.Fatal("the settled key does not sign")
	}
	clock.Advance(settings.KeyOverlap)
	reload()
	if verifyKeyIds := testTicketVerifyKeyIds(keySet); len(verifyKeyIds) != 1 || verifyKeyIds[0] != secondKeyId {
		t.Fatalf("past its expiry the old key still verifies: %v", verifyKeyIds)
	}
	third, err := socketsservice.SocketTicketKeyFileAdd(second, clock.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(third), firstKeyId) {
		t.Fatal("keygen kept an expired key")
	}
}

// The file is read again every ReloadInterval, so a rotation in vault lands with no restart.
func TestTicketKeyFileIsReadAgainOnItsInterval(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	first, err := socketsservice.SocketTicketKeyFileAdd(nil, clock.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	file := &testTicketKeyFile{data: first}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	keySet, err := socketsservice.NewSocketTicketKeySet(ctx, file.read, clock, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := keySet.AwaitReads(ctx, 1); err != nil {
		t.Fatal(err)
	}
	second, err := socketsservice.SocketTicketKeyFileAdd(first, clock.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	file.set(second, nil)
	clock.Advance(socketsservice.DefaultSocketTicketKeySettings().ReloadInterval)
	if err := keySet.AwaitReads(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if verifyKeyIds := testTicketVerifyKeyIds(keySet); len(verifyKeyIds) != 2 {
		t.Fatalf("after its interval the file's keys are %v", verifyKeyIds)
	}
}

// A key near its expiry signs nothing, so no ticket outlives its key.
func TestTicketKeyNearItsExpirySignsNothing(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	settings := socketsservice.DefaultSocketTicketKeySettings()
	data, err := socketsservice.SocketTicketKeyFileAdd(nil, clock.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	keySet, _ := testTicketKeySet(t, clock, &testTicketKeyFile{data: data})
	clock.Advance(settings.RotationInterval + settings.KeyOverlap - settings.SignMargin)
	if _, _, signs := keySet.SigningKey(); signs {
		t.Fatal("a key inside its sign margin signs")
	}
	if len(keySet.VerifyKeys()) != 1 {
		t.Fatal("a key before its expiry does not verify")
	}
}

// A file that cannot be read, or that names a key twice, holds a seed that is no Ed25519 seed, expires a key before
// its creation or does not parse, is refused whole and the last good keys stand; a set that never read a good file
// signs nothing.
func TestTicketKeyFileRefusalsKeepTheLastGoodKeys(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	good, err := socketsservice.SocketTicketKeyFileAdd(nil, clock.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	file := &testTicketKeyFile{data: good}
	keySet, reload := testTicketKeySet(t, clock, file)
	keyId, _, _ := keySet.SigningKey()
	for _, refused := range []struct {
		data string
		err  error
	}{
		{err: errors.New("vault unreadable")},
		{data: "keys: [{key_id: a, seed: AAAA, created_millis: 1, expire_millis: 2}]"},
		{data: "keys: [{key_id: a, seed: " + strings.Repeat("A", 43) + "=, created_millis: 2, expire_millis: 1}]"},
		{data: "keys: [{key_id: a, seed: " + strings.Repeat("A", 43) + "=, created_millis: 1, expire_millis: 2}, {key_id: a, seed: " + strings.Repeat("A", 43) + "=, created_millis: 1, expire_millis: 2}]"},
		{data: "keys: [{key_id: a, unknown: 1}]"},
		{data: "not: [yaml"},
	} {
		file.set([]byte(refused.data), refused.err)
		reload()
		if signingKeyId, _, signs := keySet.SigningKey(); !signs || signingKeyId != keyId {
			t.Fatalf("a refused file %q replaced the good keys", refused.data)
		}
	}

	empty := &testTicketKeyFile{err: errors.New("no file")}
	emptySet, _ := testTicketKeySet(t, clock, empty)
	if _, _, signs := emptySet.SigningKey(); signs || len(emptySet.VerifyKeys()) != 0 {
		t.Fatal("a set that read no file has a key")
	}
	if _, err := socketsservice.SocketTicketKeyFileAdd([]byte("not: [yaml"), clock.Now(), nil); !errors.Is(err, socketsservice.ErrSocketTicketKeyFileRefused) {
		t.Fatalf("keygen over a broken file answered %v", err)
	}
}

// A key that reaches vault long after its creation, as a slow hand placement leaves it, is given out from the reread
// on the interval that first sees it and signs only SettleTime after that reread, the older key signing until then:
// settled from its creation it would have signed at that reread, before any listener held it (QD-1016).
func TestTicketKeyPlacedLateSignsSettleTimeAfterItsFirstSight(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	settings := socketsservice.DefaultSocketTicketKeySettings()
	// a key a day old, and its successor, made two hours before the file holding it reaches vault
	older, err := socketsservice.SocketTicketKeyFileAdd(nil, clock.Now().Add(-24*time.Hour), nil)
	if err != nil {
		t.Fatal(err)
	}
	newer, err := socketsservice.SocketTicketKeyFileAdd(older, clock.Now().Add(-2*time.Hour), nil)
	if err != nil {
		t.Fatal(err)
	}
	file := &testTicketKeyFile{data: older}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	keySet, err := socketsservice.NewSocketTicketKeySet(ctx, file.read, clock, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := keySet.AwaitReads(ctx, 1); err != nil {
		t.Fatal(err)
	}
	olderKeyId, _, signs := keySet.SigningKey()
	if !signs {
		t.Fatal("a set's only key does not sign")
	}

	// the file reaches vault, and the reread on the interval takes it: exactly one, since the next wait is armed past
	// the move
	file.set(newer, nil)
	clock.Advance(settings.ReloadInterval)
	if err := keySet.AwaitReads(ctx, 2); err != nil {
		t.Fatal(err)
	}
	firstSightTime := clock.Now()
	verifyKeyIds := testTicketVerifyKeyIds(keySet)
	if len(verifyKeyIds) != 2 || verifyKeyIds[0] != olderKeyId {
		t.Fatalf("after the placement %v verify", verifyKeyIds)
	}
	newerKeyId := verifyKeyIds[1]
	if keyId, _, _ := keySet.SigningKey(); keyId != olderKeyId {
		t.Fatal("a key placed two hours after its creation signs at its first sight, before any listener holds it")
	}
	clock.AdvanceTo(firstSightTime.Add(settings.SettleTime - time.Millisecond))
	if keyId, _, _ := keySet.SigningKey(); keyId != olderKeyId {
		t.Fatal("a key signs before SettleTime has passed since its first sight")
	}
	clock.Advance(time.Millisecond)
	if keyId, _, _ := keySet.SigningKey(); keyId != newerKeyId {
		t.Fatal("a key SettleTime past its first sight does not sign")
	}
}

// A restarted process sees every key as new, so through its first SettleTime the oldest live key that outlives
// SignMargin signs, the one the blocks have given out longest, while a process that has run on signs with the newest
// settled key; every listener verifies both. From SettleTime after its start the restarted process signs with the
// newest too.
func TestTicketKeyRestartedSetSignsTheOldestLiveKeyForItsFirstSettleTime(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	settings := socketsservice.DefaultSocketTicketKeySettings()
	// a key made a rotation ago, and the successor made an hour ago
	older, err := socketsservice.SocketTicketKeyFileAdd(nil, clock.Now().Add(-settings.RotationInterval), nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := socketsservice.SocketTicketKeyFileAdd(older, clock.Now().Add(-time.Hour), nil)
	if err != nil {
		t.Fatal(err)
	}
	running, _ := testTicketKeySet(t, clock, &testTicketKeyFile{data: data})
	verifyKeyIds := testTicketVerifyKeyIds(running)
	if len(verifyKeyIds) != 2 {
		t.Fatalf("the file's keys are %v", verifyKeyIds)
	}
	olderKeyId, newerKeyId := verifyKeyIds[0], verifyKeyIds[1]
	clock.Advance(settings.SettleTime)
	if keyId, _, _ := running.SigningKey(); keyId != newerKeyId {
		t.Fatal("a process that has seen both keys for SettleTime does not sign with the newest")
	}

	restartTime := clock.Now()
	restarted, _ := testTicketKeySet(t, clock, &testTicketKeyFile{data: data})
	for _, at := range []time.Time{restartTime, restartTime.Add(settings.SettleTime - time.Millisecond)} {
		clock.AdvanceTo(at)
		if keyId, _, _ := restarted.SigningKey(); keyId != olderKeyId {
			t.Fatalf("%v after its restart a set signs with %q, not the oldest live key", at.Sub(restartTime), keyId)
		}
		if keyId, _, _ := running.SigningKey(); keyId != newerKeyId {
			t.Fatalf("%v after the restart the running set signs with %q", at.Sub(restartTime), keyId)
		}
		if keyIds := testTicketVerifyKeyIds(restarted); !slices.Equal(keyIds, verifyKeyIds) {
			t.Fatalf("a restarted set verifies under %v", keyIds)
		}
	}
	clock.Advance(time.Millisecond)
	if keyId, _, _ := restarted.SigningKey(); keyId != newerKeyId {
		t.Fatal("SettleTime after its restart a set does not sign with the newest key")
	}
}

// A restarted process passes over a key inside its sign margin, so through its first SettleTime the oldest key that
// outlives SignMargin signs, and the newest after.
func TestTicketKeyRestartedSetPassesOverAKeyInsideItsSignMargin(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	settings := socketsservice.DefaultSocketTicketKeySettings()
	lifetime := settings.RotationInterval + settings.KeyOverlap
	// a key half its sign margin from its expiry, one made two hours ago and one made an hour ago
	data, err := socketsservice.SocketTicketKeyFileAdd(nil, clock.Now().Add(settings.SignMargin/2-lifetime), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, age := range []time.Duration{2 * time.Hour, time.Hour} {
		if data, err = socketsservice.SocketTicketKeyFileAdd(data, clock.Now().Add(-age), nil); err != nil {
			t.Fatal(err)
		}
	}
	keySet, _ := testTicketKeySet(t, clock, &testTicketKeyFile{data: data})
	verifyKeyIds := testTicketVerifyKeyIds(keySet)
	if len(verifyKeyIds) != 3 {
		t.Fatalf("the file's keys are %v", verifyKeyIds)
	}
	if keyId, _, _ := keySet.SigningKey(); keyId != verifyKeyIds[1] {
		t.Fatalf("a restarted set signs with %q, not the oldest key outliving its sign margin", keyId)
	}
	clock.Advance(settings.SettleTime - time.Millisecond)
	if keyId, _, _ := keySet.SigningKey(); keyId != verifyKeyIds[1] {
		t.Fatalf("before SettleTime a restarted set signs with %q", keyId)
	}
	clock.Advance(time.Millisecond)
	if keyId, _, _ := keySet.SigningKey(); keyId != verifyKeyIds[2] {
		t.Fatalf("SettleTime after its restart a set signs with %q, not the newest key", keyId)
	}
}

// A key read at its creation, as when the file reaches vault at once, settles SettleTime after its creation, as it
// did before first sights were kept. One read before its creation, as a file made on a clock ahead of the block's
// is, signs nothing before its creation and settles SettleTime after it, the later of the two.
func TestTicketKeySeenAtItsCreationSettlesAsBefore(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	settings := socketsservice.DefaultSocketTicketKeySettings()
	first, err := socketsservice.SocketTicketKeyFileAdd(nil, clock.Now().Add(-24*time.Hour), nil)
	if err != nil {
		t.Fatal(err)
	}
	file := &testTicketKeyFile{data: first}
	keySet, reload := testTicketKeySet(t, clock, file)
	firstKeyId, _, _ := keySet.SigningKey()
	clock.Advance(settings.SettleTime)

	createTime := clock.Now()
	second, err := socketsservice.SocketTicketKeyFileAdd(first, createTime, nil)
	if err != nil {
		t.Fatal(err)
	}
	file.set(second, nil)
	reload()
	secondKeyId := testTicketVerifyKeyIds(keySet)[1]
	for _, c := range []struct {
		at          time.Time
		wantKeyId   string
		wantKeyName string
	}{
		{at: createTime, wantKeyId: firstKeyId, wantKeyName: "the first"},
		{at: createTime.Add(settings.SettleTime - time.Millisecond), wantKeyId: firstKeyId, wantKeyName: "the first"},
		{at: createTime.Add(settings.SettleTime), wantKeyId: secondKeyId, wantKeyName: "the second"},
	} {
		clock.AdvanceTo(c.at)
		if keyId, _, _ := keySet.SigningKey(); keyId != c.wantKeyId {
			t.Fatalf("%v after the second key's creation and first sight %q signs, not %s key", c.at.Sub(createTime), keyId, c.wantKeyName)
		}
	}

	// a key made five minutes ahead of the block's clock, read at once
	readTime := clock.Now()
	aheadCreateTime := readTime.Add(5 * time.Minute)
	third, err := socketsservice.SocketTicketKeyFileAdd(second, aheadCreateTime, nil)
	if err != nil {
		t.Fatal(err)
	}
	file.set(third, nil)
	reload()
	if verifyKeyIds := testTicketVerifyKeyIds(keySet); len(verifyKeyIds) != 3 {
		t.Fatalf("after the third key's placement %v verify", verifyKeyIds)
	}
	thirdKeyId := testTicketVerifyKeyIds(keySet)[2]
	for _, c := range []struct {
		at        time.Time
		wantKeyId string
	}{
		{at: readTime, wantKeyId: secondKeyId},
		{at: aheadCreateTime, wantKeyId: secondKeyId},
		{at: readTime.Add(settings.SettleTime), wantKeyId: secondKeyId},
		{at: aheadCreateTime.Add(settings.SettleTime - time.Millisecond), wantKeyId: secondKeyId},
		{at: aheadCreateTime.Add(settings.SettleTime), wantKeyId: thirdKeyId},
	} {
		clock.AdvanceTo(c.at)
		if keyId, _, _ := keySet.SigningKey(); keyId != c.wantKeyId {
			t.Fatalf("%v after the third key's first sight %q signs, not %q", c.at.Sub(readTime), keyId, c.wantKeyId)
		}
	}
}

// A read the set refuses keeps the last good keys with their first sights. A key gone from the file leaves the map,
// so when it comes back it is seen anew and settles SettleTime after that read, and so does an id that comes back
// naming another key, which listeners have not been given.
func TestTicketKeyGoneFromTheFileIsSeenAnewWhenItComesBack(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	settings := socketsservice.DefaultSocketTicketKeySettings()
	first, err := socketsservice.SocketTicketKeyFileAdd(nil, clock.Now().Add(-24*time.Hour), nil)
	if err != nil {
		t.Fatal(err)
	}
	file := &testTicketKeyFile{data: first}
	keySet, reload := testTicketKeySet(t, clock, file)
	firstKeyId, _, _ := keySet.SigningKey()
	clock.Advance(settings.SettleTime)
	second, err := socketsservice.SocketTicketKeyFileAdd(first, clock.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	file.set(second, nil)
	reload()
	secondKeyId := testTicketVerifyKeyIds(keySet)[1]

	// a refused read between the first sight and the settling
	clock.Advance(settings.SettleTime / 2)
	file.set(nil, errors.New("vault unreadable"))
	reload()
	clock.Advance(settings.SettleTime - settings.SettleTime/2)
	if keyId, _, _ := keySet.SigningKey(); keyId != secondKeyId {
		t.Fatal("a refused read moved a key's first sight")
	}

	// the second key leaves the file, and comes back an hour later
	file.set(first, nil)
	reload()
	if keyId, _, _ := keySet.SigningKey(); keyId != firstKeyId {
		t.Fatalf("with the second key gone %q signs", keyId)
	}
	clock.Advance(time.Hour)
	file.set(second, nil)
	reload()
	if keyId, _, _ := keySet.SigningKey(); keyId != firstKeyId {
		t.Fatal("a key that came back to the file kept the first sight it had before it left")
	}
	clock.Advance(settings.SettleTime)
	if keyId, _, _ := keySet.SigningKey(); keyId != secondKeyId {
		t.Fatal("a key that came back does not sign SettleTime after it was seen again")
	}

	// the second key's id comes back naming another key; a test-only seed
	otherSeed := bytes.Repeat([]byte{0x5a}, ed25519.SeedSize)
	file.set(testTicketKeyFileReseeded(t, second, secondKeyId, otherSeed), nil)
	reload()
	if keyIds := testTicketVerifyKeyIds(keySet); !slices.Equal(keyIds, []string{firstKeyId, secondKeyId}) {
		t.Fatalf("after the reseed %v verify", keyIds)
	}
	if keyId, _, _ := keySet.SigningKey(); keyId != firstKeyId {
		t.Fatal("an id naming another key kept the first sight of the key it named before")
	}
	clock.Advance(settings.SettleTime)
	if keyId, privateKey, _ := keySet.SigningKey(); keyId != secondKeyId || !bytes.Equal(privateKey.Seed(), otherSeed) {
		t.Fatal("the key an id names anew does not sign SettleTime after it was first seen")
	}
}
