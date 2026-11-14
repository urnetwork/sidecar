//go:build sidecar_testhooks && !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !ios_extension

package sidecar

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A pairing's move from generation 1 to 2, held where the run loop has read the keychain's new identity and is about
// to end generation 1's client: the keychain names generation 2 and holds bind's re-mint, and Status still names
// generation 1, whose client is the one up, never Online at a generation that has not started. Every state the
// sidecar then reports at generation 2 finds the re-mint in the api client already (QD-797).
func TestPairStatusNamesTheGenerationThatRuns(t *testing.T) {
	world := newPairTestWorld(t)
	first := world.sidecar.currentIdentity()
	secrets := world.instance.secrets(first.NetworkId, sidecarCoreSecretsNamespace)
	firstToken, _ := loadSidecarByJwt(secrets)

	reached := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseRunLoop := func() {
		releaseOnce.Do(func() { close(release) })
	}
	var held atomic.Bool
	SetTestHooks(&TestHooks{
		Barrier: func(name string, key string) {
			if name == "sidecar.generation.stop.before" && key == first.SidecarId.String() && held.CompareAndSwap(false, true) {
				reached <- struct{}{}
				<-release
			}
		},
	})
	t.Cleanup(func() {
		releaseRunLoop()
		SetTestHooks(nil)
	})

	// the token the api client holds at each state the sidecar reports at generation 2
	var stateLock sync.Mutex
	secondStates := []SidecarState{}
	secondTokens := []string{}
	remove := world.sidecar.AddEventCallback(func(event SidecarEvent) {
		if event.Kind != SidecarEventState || event.Generation != 2 {
			return
		}
		byJwt := world.sidecar.sidecarApi.currentByJwt()
		stateLock.Lock()
		defer stateLock.Unlock()
		secondStates = append(secondStates, event.State)
		secondTokens = append(secondTokens, byJwt)
	})
	defer remove()

	childToken := testPairChildToken(world.api.networkId, NewId(), true)
	if err := world.sidecar.Pair(context.Background(), childToken); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reached:
	case <-time.After(sidecarTestTimeout):
		t.Fatal("the run loop never came to end generation 1")
	}
	kept, _ := loadSidecarByJwt(secrets)
	reminted := world.api.remintedTokens()
	if world.sidecar.BoundGeneration() != 2 || kept == childToken || kept != reminted[len(reminted)-1] {
		t.Fatalf("the keychain names generation %d, holding the re-mint: %t", world.sidecar.BoundGeneration(), kept == reminted[len(reminted)-1])
	}
	if byJwt := world.sidecar.sidecarApi.currentByJwt(); byJwt != firstToken {
		t.Fatal("generation 1's token left the api client before its generation ended")
	}
	if status := world.sidecar.Status(); status.State != SidecarStateOnline || status.Generation != 1 {
		t.Errorf("status %s at generation %d while generation 1's client is up and the api client holds its token", status.State, status.Generation)
	}

	releaseRunLoop()
	awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateOnline, 2))
	if world.sidecar.sidecarApi.currentByJwt() != kept {
		t.Error("generation 2 is online and the api client does not hold bind's re-mint")
	}
	stateLock.Lock()
	defer stateLock.Unlock()
	if len(secondStates) < 2 || secondStates[0] != SidecarStateOffline || secondStates[len(secondStates)-1] != SidecarStateOnline {
		t.Fatalf("generation 2's states: %v", secondStates)
	}
	for i, byJwt := range secondTokens {
		if byJwt != kept {
			t.Errorf("generation 2 reported %s before the api client held bind's re-mint", secondStates[i])
		}
	}
}
