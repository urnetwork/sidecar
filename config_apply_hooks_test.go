//go:build sidecar_testhooks

package sidecar

import (
	"slices"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Each apply passes its three barriers in order, keyed by the network, so a schedule can hold one network's step.
func TestConfigApplyPassesItsBarriersInOrder(t *testing.T) {
	net := newTestConfigNet(t)
	stateLock := sync.Mutex{}
	passed := []string{}
	SetTestHooks(&TestHooks{Barrier: func(name string, key string) {
		stateLock.Lock()
		defer stateLock.Unlock()
		if key == net.networkId.String() {
			passed = append(passed, name)
		}
	}})
	t.Cleanup(func() { SetTestHooks(nil) })
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("m"))
	stateLock.Lock()
	defer stateLock.Unlock()
	if want := []string{"config.apply.before", "config.apply", "config.apply.after"}; !slices.Equal(passed, want) {
		t.Errorf("passed %v", passed)
	}
}

// Held at config.apply, the linearization point, readers still see the state before the entry, and the entry's state
// appears the moment the barrier releases.
func TestConfigApplyPublishesAtItsBarrier(t *testing.T) {
	net := newTestConfigNet(t)
	held := make(chan struct{})
	release := make(chan struct{})
	SetTestHooks(&TestHooks{Barrier: func(name string, key string) {
		if name == "config.apply" {
			close(held)
			<-release
		}
	}})
	t.Cleanup(func() { SetTestHooks(nil) })
	before := net.log.Pin().GetVersion()
	entryBytes := net.makeEntry(bridge.AuthEntryKindStatement, net.sign(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("m")))
	applied := make(chan error, 1)
	go func() {
		_, err := net.log.Apply(entryBytes, net.source)
		applied <- err
	}()
	<-held
	if got := net.log.Pin().GetVersion(); got != before {
		t.Errorf("published at %d before the barrier released", got)
	}
	close(release)
	if err := <-applied; err != nil {
		t.Fatal(err)
	}
	if got := net.log.Pin().GetVersion(); got != before+1 {
		t.Errorf("at %d after the release", got)
	}
}
