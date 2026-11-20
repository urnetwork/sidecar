//go:build sidecar_http

// §5.9's Failed for a client generation on the sidecar_http leg's subprotocol store (owner decision 616), as
// sidecar_generation_test.go holds it for the connect legs: the topic versions the page Worker's poll keeps there are
// read as the generation starts, so a damaged sealed file leaves the sidecar Offline at the generation with
// subprotocol_store_failed and one refused, each retry until the file reads again changing nothing, and the wake after
// it does brings the sidecar online. A poll client started again later in the generation, after a 401, that finds the
// file damaged does the same, and the next one that reads it ends the reason before it polls. Run under Node by
// sidecartest/legs, or by hand with go_js_wasm_exec.

package sidecar

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
	"time"
)

// The instance's backend, counting the opens of one path and holding each until gate closes, so a test knows each
// start that read the path and adds its event callback before the first.
type httpCountingBackend struct {
	SidecarStoreBackend
	path  string
	gate  chan struct{}
	opens *MonitorValue[int]
}

func (self *httpCountingBackend) Open(path string) (io.ReadCloser, error) {
	if path == self.path {
		<-self.gate
		self.opens.Update(func(count int) int { return count + 1 })
	}
	return self.SidecarStoreBackend.Open(path)
}

// Waits until the path has been opened count times.
func (self *httpCountingBackend) awaitOpens(t *testing.T, count int) {
	t.Helper()
	deadline := time.After(httpSidecarTestTimeout)
	for {
		opens, changed := self.opens.Get()
		if count <= opens {
			return
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("%d opens of the versions file, want %d", opens, count)
		}
	}
}

// The page Worker's host, counting the run loop's scans for a credential store on this machine. The loop scans as its
// first pass ends and then each SyncRefetchInterval, an hour here, and reconciles again after each scan, so the first
// scan is when a failed start's second try comes.
type httpScanCountingHost struct {
	store    SidecarStore
	keyStore SidecarKeyStore
	scans    *MonitorValue[int]
}

func (self *httpScanCountingHost) Store() SidecarStore {
	return self.store
}

func (self *httpScanCountingHost) KeyStore() SidecarKeyStore {
	return self.keyStore
}

func (self *httpScanCountingHost) TokenSource() SidecarTokenSource {
	return nil
}

func (self *httpScanCountingHost) HostCredentialStores() []SidecarHostCredentialStore {
	self.scans.Update(func(count int) int { return count + 1 })
	return nil
}

// Waits until the run loop has scanned count times.
func (self *httpScanCountingHost) awaitScans(t *testing.T, count int) {
	t.Helper()
	deadline := time.After(httpSidecarTestTimeout)
	for {
		scans, changed := self.scans.Get()
		if count <= scans {
			return
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("%d scans, want %d", scans, count)
		}
	}
}

// An enrolled page Worker's sidecar whose network's subprotocol store held push versions, and then what damage made of
// them, running with its events recorded from before its first start read the store.
type httpStoreFailedTestWorld struct {
	instance *SidecarInstance
	api      *httpTestApi
	host     *httpScanCountingHost
	// the instance's backend, and the counting one in its place
	inner   SidecarStoreBackend
	backend *httpCountingBackend
	sidecar *Sidecar
	events  *alarmTestEvents
	// the backend path of the push versions file, and its sealed bytes before any damage
	versionsPath  string
	versionsBytes []byte
}

// A world on settings, its token issued at iat, whose versions file is what damage makes of its sealed bytes, which
// damage may change in place; nil damage leaves the file whole.
func newHttpStoreFailedTestWorld(t *testing.T, settings *SidecarSettings, iat time.Time, damage func(sealed []byte) []byte) *httpStoreFailedTestWorld {
	t.Helper()
	instance, keyStore, api := newHttpTestEnrollment(t, iat, 7*24*time.Hour)
	networkId := api.networkId
	world := &httpStoreFailedTestWorld{instance: instance, api: api, inner: instance.backend, events: &alarmTestEvents{}}
	store, err := instance.Store(&networkId).Directory(sidecarHttpPushStoreName, sidecarHttpPushStoreName)
	if err != nil {
		t.Fatal(err)
	}
	if err := storePushVersions(store, map[string]uint64{PushTopicTeam: 7}); err != nil {
		t.Fatal(err)
	}
	world.versionsPath = networkFilePath(networkId, sidecarHttpPushStoreName+"/"+pushVersionsFileName)
	reader, err := world.inner.Open(world.versionsPath)
	if err != nil {
		t.Fatal(err)
	}
	world.versionsBytes, err = io.ReadAll(reader)
	reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	if damage != nil {
		world.damage(t, damage)
	}
	// nothing runs on the instance yet, so its backend changes under no reader
	world.backend = &httpCountingBackend{
		SidecarStoreBackend: world.inner,
		path:                world.versionsPath,
		gate:                make(chan struct{}),
		opens:               NewMonitorValue(0),
	}
	instance.backend = world.backend

	world.host = &httpScanCountingHost{store: instance.Store(&networkId), keyStore: keyStore, scans: NewMonitorValue(0)}
	sidecar, err := newHttpSidecar(context.Background(), world.host, settings, api)
	if err != nil {
		t.Fatal(err)
	}
	world.sidecar = sidecar
	t.Cleanup(func() {
		world.close(t)
	})
	sidecar.AddEventCallback(world.events.add)
	close(world.backend.gate)
	return world
}

// Writes what damage makes of the sealed versions in their place.
func (self *httpStoreFailedTestWorld) damage(t *testing.T, damage func(sealed []byte) []byte) {
	t.Helper()
	if err := writeBackendFile(self.inner, self.versionsPath, damage(bytes.Clone(self.versionsBytes))); err != nil {
		t.Fatal(err)
	}
}

// Writes the sealed versions back.
func (self *httpStoreFailedTestWorld) restore(t *testing.T) {
	t.Helper()
	if err := writeBackendFile(self.inner, self.versionsPath, self.versionsBytes); err != nil {
		t.Fatal(err)
	}
}

// Closes the sidecar and joins its run loop, so everything the loop did is done and nothing more starts.
func (self *httpStoreFailedTestWorld) close(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), httpSidecarTestTimeout)
	defer cancel()
	if err := self.sidecar.CloseAndWait(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// The state events from the first that named the failed store on, in their order.
func (self *httpStoreFailedTestWorld) statesSinceFailure() []SidecarEvent {
	self.events.stateLock.Lock()
	defer self.events.stateLock.Unlock()
	states := []SidecarEvent{}
	for _, event := range self.events.events {
		if event.Kind != SidecarEventState {
			continue
		}
		if 0 < len(states) || event.Reason == SidecarReasonSubprotocolStoreFailed {
			states = append(states, event)
		}
	}
	return states
}

// How many polls api has seen, with bearer when it is not empty.
func (self *httpStoreFailedTestWorld) polls(bearer string) int {
	count := 0
	for _, request := range self.api.requestsSoFar() {
		if request.path == "/sidecar/sync/poll" && (bearer == "" || request.bearer == bearer) {
			count += 1
		}
	}
	return count
}

// Whether the status is Offline with the failed store's reason.
func atHttpSubprotocolStoreFailed(status SidecarStatus) bool {
	return status.State == SidecarStateOffline && status.Reason == SidecarReasonSubprotocolStoreFailed
}

// Whether the status is state at generation 1.
func atHttpStatus(state SidecarState) func(status SidecarStatus) bool {
	return func(status SidecarStatus) bool {
		return status.State == state && status.Generation == 1
	}
}

// A file that is no sealed file, a kill's torn write, in place of the sealed versions.
func httpDamageToNoSealedFile(sealed []byte) []byte {
	return bytes.Repeat([]byte("synthetic damage "), 8)
}

// The sealed versions with their AEAD's last byte flipped.
func httpDamageToAFailedAead(sealed []byte) []byte {
	sealed[len(sealed)-1] ^= 0x01
	return sealed
}

// Checks the state events since the failure against want, each at generation 1.
func checkHttpStatesSinceFailure(t *testing.T, world *httpStoreFailedTestWorld, name string, want []sidecarLifecycle) {
	t.Helper()
	states := world.statesSinceFailure()
	if len(states) != len(want) {
		t.Fatalf("%s: state events %+v", name, states)
	}
	for i, event := range states {
		if got := (sidecarLifecycle{state: event.State, reason: event.Reason, generation: event.Generation}); got != want[i] {
			t.Errorf("%s: state event %d: %+v, want %+v", name, i, got, want[i])
		}
	}
}

// A start whose versions file is damaged, no sealed file or one whose AEAD fails, is §5.9's Failed: the sidecar stays
// Offline at the generation with subprotocol_store_failed and raises refused once, and no poll runs. Nothing wakes the
// loop: the scan's pass and a wake each try once more and fail again, raising nothing and moving nothing, and no
// other start runs (owner decision 616).
func TestHttpSubprotocolStoreFailureRefusesOnceAndWaits(t *testing.T) {
	for _, c := range []struct {
		name   string
		damage func(sealed []byte) []byte
	}{
		{name: "no sealed file", damage: httpDamageToNoSealedFile},
		{name: "a failed AEAD", damage: httpDamageToAFailedAead},
	} {
		world := newHttpStoreFailedTestWorld(t, cheapKeychainSettings(), time.Now(), c.damage)
		status := awaitHttpSidecarStatus(t, world.sidecar, atHttpSubprotocolStoreFailed)
		if status.Generation != 1 {
			t.Errorf("%s: generation %d", c.name, status.Generation)
		}
		// the first pass's start failed before its scan ran, and woke nothing; the scan's pass tried again
		world.host.awaitScans(t, 1)
		if wakes := world.sidecar.wakes.Value(); wakes != 0 {
			t.Errorf("%s: the failed start woke the loop %d times", c.name, wakes)
		}
		world.backend.awaitOpens(t, 2)
		// a wake tries once more, and fails the same way
		world.sidecar.wake()
		world.backend.awaitOpens(t, 3)
		world.close(t)

		if opens := world.backend.opens.Value(); opens != 3 {
			t.Errorf("%s: %d starts read the store, want the first pass's, the scan's and the wake's", c.name, opens)
		}
		if wakes := world.sidecar.wakes.Value(); wakes != 1 {
			t.Errorf("%s: %d wakes, want the test's one", c.name, wakes)
		}
		refused := world.events.of(SidecarEventRefused)
		if len(refused) != 1 {
			t.Fatalf("%s: %d refused events, want 1: %+v", c.name, len(refused), refused)
		}
		if refused[0].Generation != 1 || refused[0].State != SidecarStateOffline || refused[0].Reason != SidecarReasonSubprotocolStoreFailed {
			t.Errorf("%s: refused %+v", c.name, refused[0])
		}
		// the retries that failed again moved nothing: no state between tries, and no reason dropped and raised again
		checkHttpStatesSinceFailure(t, world, c.name, []sidecarLifecycle{
			{state: SidecarStateOffline, reason: SidecarReasonSubprotocolStoreFailed, generation: 1},
		})
		if status := world.sidecar.Status(); !atHttpSubprotocolStoreFailed(status) || status.Generation != 1 {
			t.Errorf("%s: status %+v", c.name, status)
		}
		if world.sidecar.runningGeneration() != nil || world.sidecar.Stats().GenerationCount != 0 {
			t.Errorf("%s: a generation ran on the damaged store", c.name)
		}
		if polls := world.polls(""); polls != 0 {
			t.Errorf("%s: %d polls ran on the damaged store", c.name, polls)
		}
		if world.sidecar.sidecarApi.currentByJwt() != "" {
			t.Errorf("%s: the token stayed in the api client with no generation running", c.name)
		}
	}
}

// The wake after the store reads again brings the sidecar online: that start reads the restored versions, the reason
// ends at Offline before the generation is published, and the poll's first answer brings it online, with no other
// refused (owner decision 616).
func TestHttpRestoredSubprotocolStoreStartsAtTheNextWake(t *testing.T) {
	world := newHttpStoreFailedTestWorld(t, cheapKeychainSettings(), time.Now(), httpDamageToNoSealedFile)
	awaitHttpSidecarStatus(t, world.sidecar, atHttpSubprotocolStoreFailed)
	world.host.awaitScans(t, 1)
	world.backend.awaitOpens(t, 2)

	world.restore(t)
	world.sidecar.wake()
	// the start's read and the poll client's
	world.backend.awaitOpens(t, 4)
	world.api.await(t, func(requests []httpTestRequest) bool {
		return 0 < world.polls("")
	})
	world.api.pollAnswers <- httpTestCorePoll(t)
	status := awaitHttpSidecarStatus(t, world.sidecar, atHttpStatus(SidecarStateOnline))
	if status.Reason != "" {
		t.Errorf("online with reason %q", status.Reason)
	}
	world.close(t)

	if refused := world.events.of(SidecarEventRefused); len(refused) != 1 {
		t.Errorf("refused events %+v", refused)
	}
	checkHttpStatesSinceFailure(t, world, "restored", []sidecarLifecycle{
		{state: SidecarStateOffline, reason: SidecarReasonSubprotocolStoreFailed, generation: 1},
		{state: SidecarStateOffline, generation: 1},
		{state: SidecarStateOnline, generation: 1},
	})
}

// Waits until a wait of timeout from clock's now is pending.
func awaitHttpPendingWait(t *testing.T, clock *tokenTestClock, timeout time.Duration) {
	t.Helper()
	deadline := time.After(httpSidecarTestTimeout)
	for {
		_, changed := clock.armed.Get()
		pending := func() bool {
			clock.stateLock.Lock()
			defer clock.stateLock.Unlock()
			for _, wait := range clock.waits {
				if wait.at.Equal(clock.now.Add(timeout)) {
					return true
				}
			}
			return false
		}()
		if pending {
			return
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("no wait of %s pending", timeout)
		}
	}
}

// A poll client started again later in the generation, after a 401, on a versions file damaged since the generation
// started is §5.9's Failed as a start is: Offline at the generation with subprotocol_store_failed and one refused. The
// poll loop tries again at RetryMaxInterval, changing nothing while the file stays damaged, and the poll client that
// reads it restored ends the reason at Offline before it polls; its poll's answer brings the sidecar online (owner
// decision 616).
func TestHttpPollClientOnADamagedStoreRefusesOnceAndClearsAtItsNextStart(t *testing.T) {
	clock := newTokenTestClock()
	settings := cheapKeychainSettings()
	settings.Clock = clock
	world := newHttpStoreFailedTestWorld(t, settings, clock.Now(), nil)
	next := world.api.token(clock.Now(), 7*24*time.Hour)
	world.api.stateLock.Lock()
	world.api.refreshByJwt = next
	world.api.stateLock.Unlock()
	pushSettings := DefaultPushClientSettings()

	// the generation starts on the whole file, and its poll client reads it too
	world.api.await(t, func(requests []httpTestRequest) bool {
		return 0 < world.polls("")
	})
	world.backend.awaitOpens(t, 2)
	world.damage(t, httpDamageToNoSealedFile)
	// a 401 ends the poll client; the refresh installs next, and the loop starts another after RetryMinInterval
	world.api.pollAnswers <- http.StatusUnauthorized
	awaitHttpPendingWait(t, clock, pushSettings.RetryMinInterval)
	clock.Advance(pushSettings.RetryMinInterval)
	awaitHttpSidecarStatus(t, world.sidecar, atHttpSubprotocolStoreFailed)
	// it tries again at RetryMaxInterval, and fails the same way
	awaitHttpPendingWait(t, clock, pushSettings.RetryMaxInterval)
	clock.Advance(pushSettings.RetryMaxInterval)
	world.backend.awaitOpens(t, 4)
	awaitHttpPendingWait(t, clock, pushSettings.RetryMaxInterval)

	world.restore(t)
	clock.Advance(pushSettings.RetryMaxInterval)
	world.api.await(t, func(requests []httpTestRequest) bool {
		return 0 < world.polls(next)
	})
	if status := world.sidecar.Status(); status.State != SidecarStateOffline || status.Reason != "" || status.Generation != 1 {
		t.Errorf("status %+v as the poll client polls on the restored store", status)
	}
	world.api.pollAnswers <- httpTestCorePoll(t)
	awaitHttpSidecarStatus(t, world.sidecar, atHttpStatus(SidecarStateOnline))
	world.close(t)

	refused := world.events.of(SidecarEventRefused)
	if len(refused) != 1 || refused[0].Generation != 1 || refused[0].Reason != SidecarReasonSubprotocolStoreFailed {
		t.Errorf("refused events %+v", refused)
	}
	checkHttpStatesSinceFailure(t, world, "after a 401", []sidecarLifecycle{
		{state: SidecarStateOffline, reason: SidecarReasonSubprotocolStoreFailed, generation: 1},
		{state: SidecarStateOffline, generation: 1},
		{state: SidecarStateOnline, generation: 1},
	})
}
