package gkmschedule

// What a device's ReaderKey upkeep and late asks do when gkm, or the push between it and the holders, loses what they
// sent (v0, owner decision 610), on T2's KeyDelivery world: a device whose first upload gkm refused while it loaded the
// network's state, which asks nothing, stands at gkm for the next rotation because its upkeep tries the upload again
// within seconds; and a late ask whose wrap-pending hint no holder took, as a holder's push batch drops the bytes of
// every gkm hint but its last, is asked again a LateAskInterval on, which a holder answers, where the holders'
// resyncs answer nothing for a device the claim's state held, and its asks follow on no longer than a ResyncInterval.

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
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

// Has gkm probe its stores once, at its start, and waits for that probe. A probe in flight when a test moves the world's
// clock past StoreProbeTimeout reads the stores as unreachable, and gkm then answers 503 until its next probe,
// StoreProbeInterval on, on a clock the test moves only once a read it waits for has gone, while that read waits out
// its Retry-After on the same clock: a test that moves the clock a minute at a time stalls there.
func probeStoresOnce(t *testing.T, world *FsKeysWorld) {
	t.Helper()
	world.Reconfigure(func(settings *gkmservice.GkmServiceSettings) { settings.StoreProbeInterval = 0 })
	for {
		count, changed := world.Engine.Probes()
		if 0 < count {
			break
		}
		select {
		case <-changed:
		case <-world.Ctx.Done():
			t.Fatal("gkm never probed its stores")
		}
	}
	if !world.Engine.Ready() {
		t.Fatal("gkm reads its stores as unreachable")
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
	probeStoresOnce(t, world)
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

// The follow-ups of a late ask no holder answers end once its first ask is a ResyncInterval old: the reader asks again
// each LateAskInterval for that hour, every ask but the hour's last taken into the one follow-up the first started,
// and the follow-up ends at its next wake. Neither the ask its last sync makes nor one a sync makes after it starts
// another, so from then on the reader asks only at the syncs other things bring. The reader's intake resyncs a day
// apart here, so no resync of its own asks within the hour.
func TestLateAskFollowUpsEndOnceTheFirstAskIsAResyncIntervalOld(t *testing.T) {
	if !sidecartest.HooksLinked {
		t.Skip("the follow-up's barriers need sidecar_testhooks")
	}
	pending := newPendingDeliveryWorld(t, false, false)
	world := pending.world
	probeStoresOnce(t, world)
	reader := pending.reader
	askLock := sync.Mutex{}
	askCount := 0
	asked := make(chan struct{}, 128)
	// each ask told once gkm has answered it, so the clock moves under no request gkm is still serving, whose
	// deadline the move would end
	reader.Transport.Respond = func(request *http.Request) *http.Response {
		recorder := httptest.NewRecorder()
		world.Engine.Handler().ServeHTTP(recorder, request)
		if request.Method == http.MethodGet && request.URL.Query().Get("want") != "" {
			askLock.Lock()
			askCount += 1
			askLock.Unlock()
			asked <- struct{}{}
		}
		return recorder.Result()
	}
	awaitAsk := func(label string) {
		t.Helper()
		select {
		case <-asked:
		case <-world.Ctx.Done():
			t.Fatalf("the reader never asked %s", label)
		}
	}
	key, err := pending.granter.Client.RotateRepo(world.Ctx, world.RepoId)
	if err != nil {
		t.Fatal(err)
	}
	reader.PublishReaderKey()
	followLock := sync.Mutex{}
	followCount := 0
	ended := make(chan struct{}, 8)
	remove, err := sidecartest.InstallTestHooks(nil, func(name string, key string) {
		switch name {
		case "gkm.late-ask.follow":
			followLock.Lock()
			followCount += 1
			followLock.Unlock()
		case "gkm.late-ask.follow.end":
			ended <- struct{}{}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	hintsSettings := sidecar.DefaultGkmSettings()
	hintsSettings.ResyncInterval = 24 * time.Hour
	hints, err := sidecar.NewGkmHints(world.Ctx, &sidecar.GkmHintsArgs{Settings: hintsSettings, Clock: world.Clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hints.Close)
	reader.Client.AttachHints(world.Ctx, hints)

	settings := sidecar.DefaultGkmSettings()
	interval := settings.LateAskInterval
	reAskCount := int(settings.ResyncInterval / interval)
	askedAt := world.Clock.Now()
	if err := reader.Client.SyncRepo(world.Ctx, world.RepoId); err == nil {
		t.Fatal("the reader synced a key before any delivery")
	}
	awaitAsk("at its first sync")
	for index := 1; index <= reAskCount; index += 1 {
		awaitTimerAt(t, world, askedAt.Add(time.Duration(index)*interval))
		world.Clock.Advance(interval)
		awaitAsk(fmt.Sprintf("at follow-up %d", index))
	}
	awaitTimerAt(t, world, askedAt.Add(time.Duration(reAskCount+1)*interval))
	world.Clock.Advance(interval)
	select {
	case <-ended:
	case <-world.Ctx.Done():
		t.Fatal("the follow-up never ended")
	}
	// a sync past the hour asks again, and taking the group's flow after the hour's last ask, finds its ask counted
	if err := reader.Client.SyncRepo(world.Ctx, world.RepoId); err != nil && !errors.Is(err, sidecar.ErrGkmKeyMissing) {
		t.Fatalf("the sync after the hour: %v", err)
	}
	awaitAsk("at the sync after the hour")
	if held, _ := reader.Client.RepoKeyHeld(world.RepoId); held {
		t.Fatal("the reader holds a key no holder delivered")
	}
	askLock.Lock()
	asks := askCount
	askLock.Unlock()
	followLock.Lock()
	follows := followCount
	followLock.Unlock()
	if asks != reAskCount+2 {
		t.Errorf("%d asks, want the first, %d follow-ups' and the sync's after the hour", asks, reAskCount)
	}
	if follows != reAskCount {
		t.Errorf("%d asks would start a follow-up, want the %d of the hour before its last", follows, reAskCount)
	}
	if world.WrapRecipients(key.Generation())[reader.SidecarId()] {
		t.Error("a delivery stood with no holder told")
	}
	select {
	case <-ended:
		t.Error("a second follow-up ended")
	default:
	}
}
