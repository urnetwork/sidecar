// SocketTicketKeySet (SOCK-M5-08) on a fake clock and an in-memory key file: a rotation keeps the old key verifying
// while the new one settles and then signs, an expired key verifies nothing, a file that cannot be used is refused
// whole with the last good keys kept, and keygen's add drops the expired.

package socketsservice_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

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
// races a read; the reread on its interval is its own test.
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
