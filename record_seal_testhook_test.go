//go:build sidecar_testhooks && !sidecar_http

// What needs the hooks linked: every entry's key and salt reach testHookSecret where they are drawn, read back from
// the journal and opened, and the privacy harness's scan finds each in a capture that holds it and in no entry a
// push carries; the journal's fsync is a barrier keyed by its log; and a writer killed at each step between signing
// and pushing leaves a chain with no gap and no seq signed twice.

package sidecar_test

import (
	"bytes"
	"encoding/hex"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// What the hooks saw.
type testRecordHooks struct {
	stateLock   sync.Mutex
	kindSecrets map[string][][]byte
	barriers    []string
}

// Installs the hooks until remove runs or the test ends. onBarrier, which may be nil, runs at each barrier on its
// caller's goroutine.
func installTestRecordHooks(t *testing.T, onBarrier func(name string, key string)) (hooks *testRecordHooks, remove func()) {
	t.Helper()
	hooks = &testRecordHooks{kindSecrets: map[string][][]byte{}}
	uninstall, err := sidecartest.InstallTestHooks(func(kind string, secret []byte) {
		hooks.stateLock.Lock()
		defer hooks.stateLock.Unlock()
		hooks.kindSecrets[kind] = append(hooks.kindSecrets[kind], secret)
	}, func(name string, key string) {
		func() {
			hooks.stateLock.Lock()
			defer hooks.stateLock.Unlock()
			hooks.barriers = append(hooks.barriers, name+" "+key)
		}()
		if onBarrier != nil {
			onBarrier(name, key)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	remove = func() { once.Do(uninstall) }
	t.Cleanup(remove)
	return hooks, remove
}

// How many times secret reached the hook as kind.
func (self *testRecordHooks) count(kind string, secret []byte) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	count := 0
	for _, hooked := range self.kindSecrets[kind] {
		if bytes.Equal(hooked, secret) {
			count += 1
		}
	}
	return count
}

// Each entry's key and salt reach the hook as they are drawn, again as the next life reads them from its journal and
// as a reader opens the body; a push's entry files hold neither, nor the body's plaintext, by the privacy harness's
// scan, which does find both in the slot row's plaintext, so the scan looks for exactly what was hooked.
func TestRecordSealHooksEveryKeyAndSalt(t *testing.T) {
	hooks, _ := installTestRecordHooks(t, nil)
	capture := sidecartest.NewPrivacyCapture()
	writer := newTestRecordWriter(t)
	logId := sidecar.NewId()
	env := writer.open()
	entries := []*sidecar.RecordSealedEntry{}
	for range 3 {
		args := testChainNote(logId, capture.CanaryText("record note"))
		sealed, err := sidecar.RecordSeal(env, args)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, sealed)
	}
	for _, sealed := range entries {
		if hooks.count("record_entry_key", sealed.Key) != 1 || hooks.count("record_entry_salt", sealed.Salt) != 1 {
			t.Errorf("seq %d's key or salt did not reach the hook as it was drawn", sealed.Seq)
		}
	}
	pending, err := writer.open().Chain.Pending(logId)
	if err != nil {
		t.Fatal(err)
	}
	for index, sealed := range pending {
		header, err := sealed.Header()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sidecar.RecordOpen(header, sealed.SealedBody, sealed.Key, sealed.Salt); err != nil {
			t.Fatal(err)
		}
		if hooks.count("record_entry_key", entries[index].Key) != 3 || hooks.count("record_entry_salt", entries[index].Salt) != 3 {
			t.Errorf("seq %d's key or salt did not reach the hook at the journal's read and at the open", sealed.Seq)
		}
	}

	hooks.stateLock.Lock()
	for kind, secrets := range hooks.kindSecrets {
		for _, secret := range secrets {
			capture.AddSecret(kind, secret)
		}
	}
	hooks.stateLock.Unlock()
	slotId := sidecar.NewId()
	for index, sealed := range entries {
		capture.Add(sidecartest.PrivacyClassObject, "record entry", sealed.EntryBytes(&slotId, uint32(index)))
		capture.Add(sidecartest.PrivacyClassObject, "record deposit entry", sealed.Deposit().GetEntry())
	}
	if findings := capture.Scan(); len(findings) != 0 {
		t.Fatalf("a pushed entry holds a key, a salt or its body: %v", findings)
	}
	capture.Add(sidecartest.PrivacyClassObject, "a slot row unwrapped", entries[0].SlotRow(0).Row)
	findings := capture.Scan()
	kinds := []string{}
	for _, finding := range findings {
		kinds = append(kinds, finding.String())
	}
	if len(findings) < 2 {
		t.Errorf("the scan missed the slot row's key and salt: %v", kinds)
	}
}

// The journal's fsync is the linearization point: each append passes record.chain.fsync.before and .after, keyed by
// its log's id in hex, and an acknowledgment that compacts passes record.chain.head.
func TestRecordChainBarriersNameTheirLog(t *testing.T) {
	hooks, _ := installTestRecordHooks(t, nil)
	writer := newTestRecordWriter(t)
	logId := sidecar.NewId()
	env := writer.open()
	writer.seal(env, logId, 2)
	if err := env.Chain.Acknowledge(logId, []uint64{1, 2}); err != nil {
		t.Fatal(err)
	}
	key := hex.EncodeToString(logId[:])
	want := []string{
		"record.chain.fsync.before " + key, "record.chain.fsync.after " + key,
		"record.chain.fsync.before " + key, "record.chain.fsync.after " + key,
		"record.chain.head.before " + key, "record.chain.head.after " + key,
	}
	hooks.stateLock.Lock()
	defer hooks.stateLock.Unlock()
	if !slices.Equal(hooks.barriers, want) {
		t.Errorf("barriers %v", hooks.barriers)
	}
}

// RECORD.md section 20's chains case: a writer killed at each step between signing and pushing. Killed before the
// fsync, the entry never existed, and the next life signs that seq afresh; killed after it, the next life finds the
// entry pending and sends it as signed. Either way the chain has no gap and no seq is signed twice where a reader
// could see both.
func TestRecordChainCrashAtEachStepBeforeThePush(t *testing.T) {
	for _, step := range []string{"record.chain.fsync.before", "record.chain.fsync.after"} {
		writer := newTestRecordWriter(t)
		logId := sidecar.NewId()
		first := writer.seal(writer.open(), logId, 1)

		var killed atomic.Bool
		func() {
			_, remove := installTestRecordHooks(t, func(name string, key string) {
				if name == step && killed.CompareAndSwap(false, true) {
					runtime.Goexit()
				}
			})
			defer remove()
			done := make(chan struct{})
			go func() {
				defer close(done)
				sidecar.RecordSeal(writer.open(), testChainNote(logId, "killed at "+step))
				t.Errorf("%s: the seal returned past its kill", step)
			}()
			<-done
		}()
		if !killed.Load() {
			t.Fatalf("%s: never reached", step)
		}

		next := writer.open()
		pending, err := next.Chain.Pending(logId)
		if err != nil {
			t.Fatal(err)
		}
		testRequireChain(t, pending, 1, [32]byte{})
		after := writer.seal(next, logId, 1)
		switch step {
		case "record.chain.fsync.before":
			if len(pending) != 1 {
				t.Errorf("%s: %d pending", step, len(pending))
			}
			testRequireChain(t, after, 2, first[0].Leaf)
		case "record.chain.fsync.after":
			if len(pending) != 2 {
				t.Fatalf("%s: %d pending", step, len(pending))
			}
			body, err := testOpenNote(pending[1])
			if err != nil || body.GetText() != "killed at "+step {
				t.Errorf("%s: the journaled entry is not the one killed: %v", step, err)
			}
			testRequireChain(t, after, 3, pending[1].Leaf)
		}
	}
}

// The note a pending entry holds.
func testOpenNote(sealed *sidecar.RecordSealedEntry) (*protocol.CoordinationBody, error) {
	header, err := sealed.Header()
	if err != nil {
		return nil, err
	}
	body, err := sidecar.RecordOpen(header, sealed.SealedBody, sealed.Key, sealed.Salt)
	if err != nil {
		return nil, err
	}
	note := &protocol.CoordinationBody{}
	return note, proto.Unmarshal(body, note)
}
