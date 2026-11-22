package gkmschedule

// What a device's ReaderKey upkeep does when gkm refuses what it sends (v0, owner decision 610), on T2's KeyDelivery
// world: a device whose first upload gkm refused while it loaded the network's state, which asks nothing, stands at
// gkm for the next rotation because its upkeep tries the upload again within seconds.

import (
	"bytes"
	"net/http"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
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
