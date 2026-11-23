//go:build !sidecar_http && !js

// Posting a list of pending statements read earlier (identity_pending.go's postPendingStatements, which a generation's
// repost runs over what was pending at its start): a statement another post landed and dropped since the list was
// read is passed over, so it is not posted twice.

package sidecar

import (
	"context"
	"errors"
	"testing"
)

// How many statements the fake api took on POST /network/config/delta.
func (self *testEnrollApi) deltaPostCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.deltaPosts)
}

// Sets the fake api's next answers on POST /network/config/delta.
func (self *testEnrollApi) setDeltaAnswers(answers ...string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.deltaAnswers = answers
}

// A sign-out left pending by a lost answer, read as pending, then landed and dropped by the caller's own repost: posting
// the list read before passes it over, and a statement still standing in such a list is posted.
func TestPostPendingPassesOverAStatementAnotherPostHandled(t *testing.T) {
	world := newTestEnrollWorld(t)
	ctx := context.Background()
	if err := world.enroll(ctx); err != nil {
		t.Fatal(err)
	}
	awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateOffline, 1))
	// the generation's own repost of what was pending at its start has run, so only this test's posts count
	for {
		number, changed := world.sidecar.runningGenerationNumber.Get()
		if number == 1 {
			break
		}
		<-changed
	}
	<-world.sidecar.runningGeneration().pendingDone
	identity := world.sidecar.currentIdentity()
	world.installAuthority(t, testAdmissionRow(identity.SidecarId, 0))
	world.api.setDeltaAnswers("lost", "lost")
	if err := world.sidecar.Logout(ctx); !errors.Is(err, ErrSidecarLogoutPending) {
		t.Fatalf("a logout whose post's answer is lost: %v", err)
	}
	read, err := world.sidecar.pendingStatements()
	if err != nil || len(read) != 1 {
		t.Fatalf("the pending sign-out: %d %v", len(read), err)
	}

	// still standing: posted, its answer lost again, and kept
	if err := world.sidecar.postPendingStatements(ctx, read); err == nil {
		t.Fatal("a post whose answer is lost answered no error")
	}
	if count := world.api.deltaPostCount(); count != 2 {
		t.Fatalf("%d posts, not the logout's and the list's", count)
	}

	// landed and dropped by another post: passed over
	if err := world.sidecar.PostPendingStatements(ctx); err != nil {
		t.Fatal(err)
	}
	if count := world.api.deltaPostCount(); count != 3 {
		t.Fatalf("%d posts after the repost that landed it", count)
	}
	if err := world.sidecar.postPendingStatements(ctx, read); err != nil {
		t.Fatal(err)
	}
	if count := world.api.deltaPostCount(); count != 3 {
		t.Fatalf("a statement another post landed was posted again: %d posts", count)
	}
}
