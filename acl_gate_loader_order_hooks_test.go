//go:build sidecar_testhooks && !sidecar_http && !ios_extension

// The race tip-check caught at sidecar ed6b9300, held at the install's own barriers (acl_gate.install.before,
// acl_gate.install, acl_gate.install.after): a second trigger lands while a load installs and the log moves before the
// owed load reads. Until the snapshot is stored State answers the state before; from the store it answers the new one;
// the index has moved by .after; and only past .after is the install told, once, OnLoad after it. The owed load is
// told the moved state past its own barriers, and a load at the held position reaches none and tells nothing.

package sidecar

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
)

// At each install barrier: State and the index hold the state before until the store, the snapshot from it, the index
// by .after, and nothing is told until the barriers have passed.
func TestAclGateInstallIsToldOnlyPastItsBarriers(t *testing.T) {
	net := newTestConfigNet(t)
	source := newAclGateTestSource()
	source.publish(net)
	held := net.log.Pin()
	lateSidecarId := testConfigId("barrier late device")
	barrierKey := net.networkId.String()

	reached := make(chan string)
	proceed := make(chan struct{})
	// frees a loader held at a barrier once the test ends, so the cleanup's CloseAndWait returns
	done := make(chan struct{})
	SetTestHooks(&TestHooks{Barrier: func(name string, key string) {
		if key != barrierKey || !strings.HasPrefix(name, "acl_gate.install") {
			return
		}
		select {
		case reached <- name:
		case <-done:
			return
		}
		select {
		case <-proceed:
		case <-done:
		}
	}})
	t.Cleanup(func() { SetTestHooks(nil) })
	cache, events := newAclGateLoaderOrderCache(t, source, lateSidecarId)
	t.Cleanup(func() { close(done) })

	await := func(want string) {
		t.Helper()
		select {
		case name := <-reached:
			if name != want {
				t.Fatalf("reached %s, want %s", name, want)
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("no %s", want)
		}
	}
	quiet := func(step string) {
		t.Helper()
		select {
		case event := <-events:
			t.Fatalf("at %s: told %t at %d before the install passed its barriers", step, event.told, event.pin.GetVersion())
		default:
		}
	}
	state := func() *AclGateSnapshot {
		snapshot, _ := cache.State(net.networkId)
		return snapshot
	}
	indexed := func(sidecarId Id) bool {
		_, found := cache.SidecarNetwork(sidecarId)
		return found
	}

	// the first install, held at each barrier; the entry's second event lands during it and the log moves
	cache.Changed(net.networkId)
	await("acl_gate.install.before")
	quiet("the first install's before")
	if snapshot := state(); snapshot != nil {
		t.Fatalf("a snapshot before the first store: %d", snapshot.Pin.GetVersion())
	}
	cache.Changed(net.networkId)
	net.admitMemberDevice("barrier late")
	source.publish(net)
	moved := net.log.Pin()
	proceed <- struct{}{}
	await("acl_gate.install")
	quiet("the first store")
	if snapshot := state(); snapshot == nil || !proto.Equal(snapshot.Pin, held) {
		t.Fatalf("State after the first store: %v", snapshot)
	}
	if indexed(net.owner.sidecarId) {
		t.Error("the owner indexed before the first install moved the index")
	}
	proceed <- struct{}{}
	await("acl_gate.install.after")
	quiet("the first install's after")
	if !indexed(net.owner.sidecarId) {
		t.Error("the owner not indexed by the first install's after")
	}
	proceed <- struct{}{}
	aclGateLoaderOrderExpect(t, events, true, held, false)
	aclGateLoaderOrderExpect(t, events, false, held, false)

	// the owed load reads the moved log, and its install is held the same way
	await("acl_gate.install.before")
	quiet("the owed install's before")
	if snapshot := state(); snapshot == nil || !proto.Equal(snapshot.Pin, held) {
		t.Fatalf("State before the owed store: %v", snapshot)
	}
	proceed <- struct{}{}
	await("acl_gate.install")
	quiet("the owed store")
	if snapshot := state(); snapshot == nil || !proto.Equal(snapshot.Pin, moved) {
		t.Fatalf("State after the owed store: %v", snapshot)
	}
	if indexed(lateSidecarId) {
		t.Error("the late device indexed before the owed install moved the index")
	}
	proceed <- struct{}{}
	await("acl_gate.install.after")
	quiet("the owed install's after")
	if !indexed(lateSidecarId) {
		t.Error("the late device not indexed by the owed install's after")
	}
	proceed <- struct{}{}
	aclGateLoaderOrderExpect(t, events, true, moved, true)
	aclGateLoaderOrderExpect(t, events, false, moved, false)

	// nothing new: the load installs nothing, so it reaches no barrier and tells nothing
	cache.Changed(net.networkId)
	aclGateLoaderOrderExpect(t, events, false, moved, false)
	cache.CloseAndWait()
	select {
	case name := <-reached:
		t.Fatalf("a barrier after every loader returned: %s", name)
	case event := <-events:
		t.Fatalf("an event after every loader returned: told %t at %d", event.told, event.pin.GetVersion())
	default:
	}
}
