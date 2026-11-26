//go:build sidecar_testhooks && !ios_extension && !sidecar_http && !js

// The store's commits against a rise memory holds first (ATTEST-M12-01), on its barriers: a commit that read the state
// before a ticket's version rose in memory must not write or set it back, and the rise is written once its writer holds
// the file.

package sidecar

import (
	"testing"
)

// A version seen while a policy commit is held between its read of the state and its write survives the commit, in
// memory and across a restart. Before the fix the commit set the state it read, version 7 was lost, and the rise's
// own write then wrote what the commit had left, 4.
func TestComputePolicyStoreKeepsAVersionSeenDuringACommit(t *testing.T) {
	world := newTestAttestStoreWorld(t)
	store := world.open(t, 3)
	commitReached := make(chan struct{})
	commitRelease := make(chan struct{})
	seenReached := make(chan struct{})
	seenRelease := make(chan struct{})
	SetTestHooks(&TestHooks{
		Barrier: func(name string, key string) {
			switch {
			case name == "attest_policy_store.commit.before" && key == "4":
				close(commitReached)
				<-commitRelease
			case name == "attest_policy_store.seen.raised" && key == "7":
				close(seenReached)
				<-seenRelease
			}
		},
	})
	t.Cleanup(func() {
		SetTestHooks(nil)
	})
	document, signature := world.policy(t, 4)
	offered := make(chan error, 1)
	go func() {
		_, err := store.Offer(document, signature)
		offered <- err
	}()
	<-commitReached
	noted := make(chan error, 1)
	go func() {
		noted <- store.noteVersionSeen(7)
	}()
	<-seenReached
	close(commitRelease)
	if err := <-offered; err != nil {
		t.Fatal(err)
	}
	if store.HighestSeen() != 7 {
		t.Errorf("after the commit the highest seen is %d, not 7", store.HighestSeen())
	}
	close(seenRelease)
	if err := <-noted; err != nil {
		t.Fatal(err)
	}
	if store.HighestSeen() != 7 || testAttestNewestVersion(store) != 4 {
		t.Errorf("highest %d, newest %d", store.HighestSeen(), testAttestNewestVersion(store))
	}
	SetTestHooks(nil)
	if restarted := world.open(t, 3); restarted.HighestSeen() != 7 {
		t.Errorf("after a restart the highest seen is %d, not 7", restarted.HighestSeen())
	}
}
