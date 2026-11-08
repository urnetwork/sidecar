//go:build sidecar_testhooks

// What needs the hooks linked: each key reaches testHookSecret, each linearization point reaches
// testHookBarrier, and a barrier really holds the step it names.

package mxedgeservice_test

import (
	"bytes"
	"context"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/urnetwork/sidecar/mxedgeservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Records what the hooks saw, until the test ends.
type testHookRecord struct {
	stateLock sync.Mutex
	kinds     []string
	secrets   [][]byte
	barriers  []string
}

// Installs the hooks. onBarrier, which may be nil, runs at each barrier and may hold it.
func installTestHooks(t *testing.T, onBarrier func(name string)) *testHookRecord {
	t.Helper()
	record := &testHookRecord{}
	remove, err := sidecartest.InstallTestHooks(func(kind string, secret []byte) {
		record.stateLock.Lock()
		defer record.stateLock.Unlock()
		record.kinds = append(record.kinds, kind)
		record.secrets = append(record.secrets, secret)
	}, func(name string, key string) {
		func() {
			record.stateLock.Lock()
			defer record.stateLock.Unlock()
			record.barriers = append(record.barriers, name)
		}()
		if onBarrier != nil {
			onBarrier(name)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(remove)
	return record
}

// What has been seen so far.
func (self *testHookRecord) snapshot() (kinds []string, secrets [][]byte, barriers []string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.kinds), slices.Clone(self.secrets), slices.Clone(self.barriers)
}

// Each daily k reaches the harness, made here or read, and turns up nowhere it scans but its own home,
// {vhk}mx:, which holds it by design (mx-foundation-closed-handshake-key).
func TestHooksSeeEveryKeyAndNoneLeaks(t *testing.T) {
	record := installTestHooks(t, nil)
	engine := newTestEngine(t, &testEngineOptions{unseeded: true})
	second := newTestEngine(t, &testEngineOptions{clock: engine.clock, host: engine.host})
	engine.closeHandshakeFrom(testSender)
	second.plaintextReplyTo("198.51.100.1")

	kinds, secrets, _ := record.snapshot()
	if !slices.Equal(kinds, []string{"K_mxc_day", "K_mxc_day"}) {
		t.Fatalf("hooked %v", kinds)
	}
	dump := engine.host.Redis.Dump()
	dayKeyName := mxedgeservice.DailyKeyName(engine.clock.Now())
	for _, secret := range secrets {
		if !bytes.Equal(secret, dump[dayKeyName]) {
			t.Error("hooked a key Redis does not hold as k")
		}
	}
	capture := sidecartest.NewPrivacyCapture()
	for index, secret := range secrets {
		capture.AddSecret(kinds[index], secret)
	}
	for key, value := range dump {
		if key != dayKeyName {
			capture.AddItem(&sidecartest.PrivacyItem{Class: "CC3", Name: "redis", Body: append([]byte(key), value...)})
		}
	}
	if count := capture.ItemCount("CC3"); count != 1 {
		t.Errorf("%d Redis items besides k", count)
	}
	for _, line := range engine.host.Metrics.Dump() {
		capture.AddItem(&sidecartest.PrivacyItem{Class: "CC4", Name: "metric", Body: []byte(line)})
	}
	for _, engine := range []*testEngine{engine, second} {
		for _, line := range engine.log.Lines() {
			capture.AddItem(&sidecartest.PrivacyItem{Class: "CC4", Name: "log", Body: []byte(line)})
		}
	}
	if hits := capture.Scan(); len(hits) != 0 {
		t.Errorf("%v", hits)
	}
}

// A k reaches the hooks once a process, when it is made or first read, and not at every probe, nor
// again after a re-read finds the same k. A new k after a lost one is a new key and reaches them.
func TestHooksSeeEachDailyKeyOnce(t *testing.T) {
	record := installTestHooks(t, nil)
	ctx := context.Background()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	memory := newTestMemory(host, clock)
	for range 3 {
		if _, err := memory.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if kinds, _, _ := record.snapshot(); len(kinds) != 1 {
		t.Errorf("hooked %v", kinds)
	}
	host.Redis.LoseKeys(mxedgeservice.DailyKeyPrefix)
	seedDailyKey(t, ctx, host, clock.Now(), testDailyKey)
	if _, err := memory.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, secrets, _ := record.snapshot(); len(secrets) != 2 || !bytes.Equal(secrets[1], testDailyKey) {
		t.Errorf("hooked %d keys", len(secrets))
	}
}

func TestBarriersMarkEveryLinearizationPoint(t *testing.T) {
	record := installTestHooks(t, nil)
	engine := newTestEngine(t, &testEngineOptions{unseeded: true})
	engine.closeHandshakeFrom(testSender)
	engine.plaintextReplyTo("198.51.100.1")
	_, _, barriers := record.snapshot()
	for _, name := range []string{
		"mxedge.daily_key_create.before",
		"mxedge.daily_key_create.after",
		"mxedge.starttls.before",
		"mxedge.starttls.after",
		"mxedge.closed_handshake_write.before",
		"mxedge.closed_handshake_write.after",
		"mxedge.closed_handshake_read.before",
		"mxedge.closed_handshake_read.after",
	} {
		if !slices.Contains(barriers, name) {
			t.Errorf("no %s in %v", name, barriers)
		}
	}
}

// Two processes making the day's k at once: the one whose SET NX loses reads the winner's, so the fleet
// holds one k. The barrier holds the first process between its read, which found nothing, and its
// SET NX, while the second makes k.
func TestRacingCreatorsAgreeOnOneKey(t *testing.T) {
	held := make(chan struct{})
	release := make(chan struct{})
	// not a sync.Once, whose Do would make the second process wait for the first's release
	var holding atomic.Bool
	installTestHooks(t, func(name string) {
		if name == "mxedge.daily_key_create.before" && holding.CompareAndSwap(false, true) {
			close(held)
			<-release
		}
	})
	ctx := context.Background()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	first, second := newTestMemory(host, clock), newTestMemory(host, clock)
	firstResult := make(chan string, 1)
	go func() {
		result, err := first.Refresh(ctx)
		if err != nil {
			result = err.Error()
		}
		firstResult <- result
	}()
	<-held
	if result, err := second.Refresh(ctx); result != "created" || err != nil {
		t.Fatalf("second: %s, %v", result, err)
	}
	close(release)
	if result := <-firstResult; result != "read" {
		t.Errorf("first: %s", result)
	}
	sender := netip.MustParseAddr(testSender)
	if first.Key(sender, clock.Now()) != second.Key(sender, clock.Now()) {
		t.Error("the fleet holds two k for one day")
	}
}

// A schedule holding the memory's write holds the alert too: the sender cannot see the close, and so
// cannot retry, before the fleet remembers.
func TestAlertWaitsForTheMemorysWrite(t *testing.T) {
	held := make(chan struct{})
	release := make(chan struct{})
	installTestHooks(t, func(name string) {
		if name == "mxedge.closed_handshake_write.after" {
			close(held)
			<-release
		}
	})
	engine := newTestEngine(t, nil)
	client := engine.open(testSender)
	engine.startTls(client)
	client.write("hello mx.net.example")
	<-held
	// the write has happened and the alert has not, so the memory leads
	if count := engine.memoryKeyCount(); count != 1 {
		t.Errorf("%d keys at the barrier", count)
	}
	close(release)
	client.expectBytes(testAlertRecord(mxedgeservice.MxTlsAlertUnrecognizedName))
	client.expectEnd()
}
