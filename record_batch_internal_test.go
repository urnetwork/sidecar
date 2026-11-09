//go:build !js

// record_batch.go's loop against a log this device can no longer reach: the attempt backs off, so the loop's next wake
// is a timer ahead, never one already due, which would wake it at once and again, a hot spin.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A clock that stands still, whose timers never fire: the test moves it by hand.
type testRecordStillClock struct {
	now time.Time
}

func (self *testRecordStillClock) Now() time.Time {
	return self.now
}

func (self *testRecordStillClock) After(timeout time.Duration) <-chan time.Time {
	return make(chan time.Time)
}

func (self *testRecordStillClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	return func() bool { return true }
}

// fuzzRecordAuth's state with every right of the writer taken away.
type testRecordRightsGone struct {
	*fuzzRecordAuth
}

func (self *testRecordRightsGone) Consented(repoId Id, sidecarId Id) bool {
	return false
}

func (self *testRecordRightsGone) Writes(repoId Id, sidecarId Id) bool {
	return false
}

// Entries queued for a log this device lost every right to wait, backing off: the next wake is ahead, past the
// interval, rather than due at once.
func TestRecordWriterBacksOffALogItCannotReach(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	writerId := NewId()
	logId := NewId()
	admitted := &fuzzRecordAuth{
		pin:       &bridge.AuthPin{Version: 7, Chain: bytes.Repeat([]byte{0x07}, 32)},
		writerId:  writerId,
		logId:     logId,
		publicKey: key.Public().(ed25519.PublicKey),
	}
	var auth RecordAuthView = admitted
	clock := &testRecordStillClock{now: time.UnixMilli(1762387200000)}
	settings := defaultSidecarRecordSettings()
	writer := newRecordWriter(&SidecarRecordArgs{
		SidecarId:         writerId,
		IdentityPublicKey: admitted.publicKey,
		Store:             testRecordStore(t),
		Sign:              testRecordSigner(writerId, key),
		Auth:              func() RecordAuthView { return auth },
		Clock:             clock,
		Settings:          settings,
	})
	sealed, err := RecordSeal(&RecordSealEnv{Chain: writer.chain, Sign: writer.sign}, &RecordSealArgs{
		LogId:      logId,
		Kind:       RecordKindNote,
		Source:     RecordSourceAgent,
		TimeMillis: clock.now.UnixMilli(),
		Tainted:    true,
		Body:       &protocol.CoordinationBody{Text: "queued"},
	})
	if err != nil {
		t.Fatal(err)
	}
	writer.enqueue(&recordRoute{logId: logId}, sealed, RecordKindNote)
	auth = &testRecordRightsGone{fuzzRecordAuth: admitted}
	clock.now = clock.now.Add(settings.DepositInterval + time.Second)
	if err := writer.pump(t.Context(), false); err == nil {
		t.Fatal("a log with no right took the batch")
	}
	timeout, ok := writer.nextWake()
	if !ok || timeout < settings.PushCoalesce {
		t.Fatalf("the next wake is %v away (%t): the loop would spin", timeout, ok)
	}
}
