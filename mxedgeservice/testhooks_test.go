//go:build sidecar_testhooks

// What needs the hooks linked: each key reaches testHookSecret, each linearization point reaches
// testHookBarrier, and a barrier really holds the step it names.

package mxedgeservice_test

import (
	"slices"
	"sync"
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

// The fleet's secret and each daily k reach the harness, and none of them turns up anywhere it scans.
func TestHooksSeeEveryKeyAndNoneLeaks(t *testing.T) {
	record := installTestHooks(t, nil)
	engine := newTestEngine(t, nil)
	engine.closeHandshakeFrom(testSender)
	engine.plaintextReplyTo("198.51.100.1")

	kinds, secrets, _ := record.snapshot()
	if !slices.Contains(kinds, "K_mxc") || !slices.Contains(kinds, "K_mxc_day") {
		t.Errorf("hooked %v", kinds)
	}
	capture := sidecartest.NewPrivacyCapture()
	for index, secret := range secrets {
		capture.AddSecret(kinds[index], secret)
	}
	for key, value := range engine.host.Redis.Dump() {
		capture.AddItem(&sidecartest.PrivacyItem{Class: "CC3", Name: "redis", Body: append([]byte(key), value...)})
	}
	for _, line := range engine.host.Metrics.Dump() {
		capture.AddItem(&sidecartest.PrivacyItem{Class: "CC4", Name: "metric", Body: []byte(line)})
	}
	for _, line := range engine.log.Lines() {
		capture.AddItem(&sidecartest.PrivacyItem{Class: "CC4", Name: "log", Body: []byte(line)})
	}
	if hits := capture.Scan(); len(hits) != 0 {
		t.Errorf("%v", hits)
	}
}

// A secret too short to use is no key, and reporting it would have a scan look for nothing.
func TestHooksSkipAMissingSecret(t *testing.T) {
	record := installTestHooks(t, nil)
	newTestEngine(t, &testEngineOptions{
		deps: func(deps *mxedgeservice.MxEdgeDeps) {
			deps.ClosedHandshakeSecret = nil
		},
	})
	if kinds, _, _ := record.snapshot(); slices.Contains(kinds, "K_mxc") {
		t.Errorf("hooked %v", kinds)
	}
}

func TestBarriersMarkEveryLinearizationPoint(t *testing.T) {
	record := installTestHooks(t, nil)
	engine := newTestEngine(t, nil)
	engine.closeHandshakeFrom(testSender)
	engine.plaintextReplyTo("198.51.100.1")
	_, _, barriers := record.snapshot()
	for _, name := range []string{
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
