package gkmschedule

// What a device's ReaderKey upkeep and late asks do when gkm, or the push between it and the holders, loses what they
// sent (v0, owner decision 610), on T2's KeyDelivery world: a device whose first upload gkm refused while it loaded the
// network's state, which asks nothing, stands at gkm for the next rotation because its upkeep tries the upload again
// within seconds; and a late ask whose wrap-pending hint no holder took, as a holder's push batch drops the bytes of
// every gkm hint but its last, is asked again a LateAskInterval on, which a holder answers, where the holders'
// resyncs answer nothing for a device the claim's state held.

import (
	"bytes"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Starts device's ReaderKey upkeep as StartUpkeep does, on settings and with no hint intake: a device that asks
// nothing, its client restarted over the upkeep's ReaderKeys.
func startUpkeepOn(t *testing.T, device *FsKeysDevice, settings *sidecar.GkmSettings) *sidecar.GkmUpkeep {
	t.Helper()
	world := device.world
	upkeep, err := sidecar.NewGkmUpkeep(world.Ctx, &sidecar.GkmUpkeepArgs{
		SidecarId: device.SidecarId(),
		Api:       device.Api,
		Sign:      device.signer.Sign,
		Secrets:   device.secrets,
		Settings:  settings,
		Clock:     world.Clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(upkeep.Close)
	device.upkeep = upkeep
	device.Restart()
	return upkeep
}

// Has gkm refuse the device's ReaderKey uploads with 503, as it does before it has loaded the network's state, until
// the returned function is called; and counts the device's late asks, its wraps reads with a want.
func refuseReaderKeyUploads(device *FsKeysDevice) (stopRefusing func(), asks func() int) {
	lock := sync.Mutex{}
	refusing := true
	askCount := 0
	device.Transport.Respond = func(request *http.Request) *http.Response {
		lock.Lock()
		defer lock.Unlock()
		if request.Method == http.MethodGet && request.URL.Query().Get("want") != "" {
			askCount += 1
		}
		if refusing && request.Method == http.MethodPost && request.URL.Path == "/gkm/reader-key" {
			return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: http.Header{}, Body: http.NoBody, Request: request}
		}
		return nil
	}
	stopRefusing = func() {
		lock.Lock()
		defer lock.Unlock()
		refusing = false
	}
	asks = func() int {
		lock.Lock()
		defer lock.Unlock()
		return askCount
	}
	return stopRefusing, asks
}

// Waits until the upkeep has finished at least count passes, or count tries between them.
func awaitUpkeepCounts(t *testing.T, world *FsKeysWorld, upkeep *sidecar.GkmUpkeep, passCount int, retryCount int) {
	t.Helper()
	for {
		passes, passed := upkeep.Passes()
		retries, retried := upkeep.ReaderKeyRetries()
		if passCount <= passes && retryCount <= retries {
			return
		}
		select {
		case <-passed:
		case <-retried:
		case <-world.Ctx.Done():
			t.Fatalf("the upkeep never reached %d passes and %d tries", passCount, retryCount)
		}
	}
}

// A reader whose upkeep's first ReaderKey upload gkm refused, before it had loaded the network's state, and which asks
// nothing: its upkeep tries the upload again ReaderKeyRetryWait later, so the writer's next rotation stages the reader
// a delivery, which it opens, no late ask of its own made. With the retry off, the pre-fix upkeep's next try waits for
// its next pass, an hour on, and the rotation passes the reader by.
func TestDeviceThatAsksNothingIsInTheNextRotationOnceItsRefusedReaderKeyIsTriedAgain(t *testing.T) {
	for _, retry := range []bool{true, false} {
		pending := newPendingDeliveryWorld(t, false, false)
		world := pending.world
		reader := pending.reader
		stopRefusing, asks := refuseReaderKeyUploads(reader)
		settings := sidecar.DefaultGkmSettings()
		if !retry {
			settings.ReaderKeyRetryWait = 0
		}
		start := world.Clock.Now()
		upkeep := startUpkeepOn(t, reader, settings)
		awaitUpkeepCounts(t, world, upkeep, 1, 0)
		if upkeep.CurrentReaderKeySha256() != nil {
			t.Fatalf("retry %t: a refused upload left a current ReaderKey", retry)
		}
		// gkm has loaded the network's state
		stopRefusing()
		if retry {
			awaitTimerAt(t, world, start.Add(settings.ReaderKeyRetryWait))
			world.Clock.Advance(settings.ReaderKeyRetryWait)
			awaitUpkeepCounts(t, world, upkeep, 1, 1)
			if upkeep.CurrentReaderKeySha256() == nil {
				t.Fatal("the try again left no current ReaderKey")
			}
		}
		key, err := pending.granter.Client.RotateRepo(world.Ctx, world.RepoId)
		if err != nil {
			t.Fatalf("retry %t: the rotation: %v", retry, err)
		}
		if staged := world.WrapRecipients(key.Generation())[reader.SidecarId()]; staged != retry {
			t.Fatalf("retry %t: the rotation staged the reader a delivery: %t", retry, staged)
		}
		if !retry {
			continue
		}
		held, err := reader.Client.CurrentRepoKey(world.Ctx, world.RepoId)
		if err != nil || held.Generation() != key.Generation() || !bytes.Equal(held.Commitment(), key.Commitment()) {
			t.Fatalf("the reader's key of the rotation: %v", err)
		}
		if count := asks(); count != 0 {
			t.Errorf("the reader asked %d times", count)
		}
	}
}

// Whether hint is a wrap-pending naming device's late ask in the world's group, sent after version.
func wrapPendingFor(world *FsKeysWorld, device *FsKeysDevice, after uint64) func(hint *FsKeysHint) bool {
	return func(hint *FsKeysHint) bool {
		return hint.Topic == sidecar.PushTopicGkm && hint.Hint.GetKind() == protocol.GkmHintKind_GKM_HINT_WRAP_PENDING &&
			bytes.Equal(hint.Hint.GetGroupId(), world.GroupId.Bytes()) && string(hint.Hint.GetRecipient()) == fsKeysRecipient(device.SidecarId()) &&
			after < hint.Version
	}
}

// A reader the writer's rotation passed for want of a ReaderKey, as a re-former's rotation passes a device that
// published its key late, publishes one and asks for its delivery; the ask's wrap-pending hint is lost, as at a holder
// whose push batch carried another gkm hint after it, so no holder answers, and the granter's resync, which delivers
// to holders that joined since a claim, delivers nothing to one the claim held. A LateAskInterval after the ask, and
// not before, the reader's repo is synced again and asks again; the granter takes that hint and delivers, and the
// reader holds the rotation.
func TestLateAskWhoseHintIsLostIsAskedAgainAfterTheLateAskInterval(t *testing.T) {
	pending := newPendingDeliveryWorld(t, false, false)
	world := pending.world
	reader := pending.reader
	stopRefusing, asks := refuseReaderKeyUploads(reader)
	stopRefusing()
	key, err := pending.granter.Client.RotateRepo(world.Ctx, world.RepoId)
	if err != nil {
		t.Fatal(err)
	}
	if world.WrapRecipients(key.Generation())[reader.SidecarId()] {
		t.Fatal("the rotation staged a delivery to a reader with no ReaderKey")
	}
	reader.PublishReaderKey()
	granterHints := attachPendingHints(t, world, pending.granter)
	readerHints := attachPendingHints(t, world, reader)
	askedAt := world.Clock.Now()
	if err := reader.Client.SyncRepo(world.Ctx, world.RepoId); err == nil {
		t.Fatal("the reader synced a key before any delivery")
	}
	first := world.AwaitHint(pending.granter, wrapPendingFor(world, reader, 0))
	if count := asks(); count != 1 {
		t.Fatalf("%d asks at the first sync", count)
	}
	// the hint is lost, never relayed; the granter's resync delivers to the holders that joined since the claim
	if err := pending.granter.Client.SyncRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatal(err)
	}
	if world.WrapRecipients(key.Generation())[reader.SidecarId()] {
		t.Fatal("the granter's resync delivered to a holder the claim held")
	}
	interval := sidecar.DefaultGkmSettings().LateAskInterval
	awaitTimerAt(t, world, askedAt.Add(interval))
	world.Clock.Advance(interval - time.Millisecond)
	if count := asks(); count != 1 {
		t.Fatalf("%d asks within the LateAskInterval", count)
	}
	world.Clock.Advance(time.Millisecond)
	again := world.AwaitHint(pending.granter, wrapPendingFor(world, reader, first.Version))
	if count := asks(); count != 2 {
		t.Errorf("%d asks a LateAskInterval on", count)
	}
	relayLateDeliveryHint(t, granterHints, again)
	relayLateDeliveryHint(t, readerHints, world.AwaitHint(reader, world.pendingHint))
	for {
		held, changed := reader.Client.RepoKeyHeld(world.RepoId)
		if held {
			break
		}
		select {
		case <-changed:
		case <-world.Ctx.Done():
			t.Fatal("the reader never held the rotation")
		}
	}
	if held, err := reader.Client.CurrentRepoKey(world.Ctx, world.RepoId); err != nil || held.Generation() != key.Generation() || !bytes.Equal(held.Commitment(), key.Commitment()) {
		t.Fatalf("the reader's key of the rotation: %v", err)
	}
	if signer := deliverySignerAt(t, world, reader, key.Generation()); signer == nil || *signer != pending.granter.SidecarId() {
		t.Error("the reader's delivery is not the granter's")
	}
}

// The signer of the delivery gkm holds of generation to device, nil for none.
func deliverySignerAt(t *testing.T, world *FsKeysWorld, device *FsKeysDevice, generation uint64) *sidecar.Id {
	t.Helper()
	recipient := "/" + fsKeysRecipient(device.SidecarId()) + "/"
	for key, body := range world.objects(gkmservice.GkmWrapGenerationPrefix(world.GroupId, generation)) {
		if !strings.Contains(key, recipient) {
			continue
		}
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(body, signed); err != nil {
			t.Fatalf("a stored delivery: %v", err)
		}
		delivery, err := sidecar.ParseGkmDelivery(signed, sidecar.GkmWrapTypeReader, sidecar.GkmIdentityKeys(world.Log.Tip()))
		if err != nil {
			t.Fatalf("a stored delivery: %v", err)
		}
		return &delivery.SignerId
	}
	return nil
}
