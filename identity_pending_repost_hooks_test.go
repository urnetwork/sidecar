//go:build sidecar_testhooks && !sidecar_http && !js

// A generation's repost of pending statements (identity_pending.go, sidecar_generation.go) against a statement kept
// after the generation started, on the repost's barrier: the repost posts only what was pending at the start, so a
// statement an act keeps once the generation runs stays its caller's to post again. Before, a repost the scheduler ran
// late read the records when it ran and posted such a statement beside its caller's retry, which is how fault's
// TestFs97AWorkerThatResyncsBeforeThePostOrDuringARetryIsNotRevoked once saw a stale revocation land after the retry
// had dropped it (D-TEAM-29's re-check before each post or retry). Nothing sleeps: the repost is held at its barrier
// until the test lets it go.

package sidecar

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// The first generation's repost, held at its start while a logout's sign-out, whose post's answer is lost, is kept
// and left pending, posts nothing once let go: the sign-out stays pending for its caller, whose retry posts it once.
func TestGenerationRepostLeavesAStatementKeptAfterItsStart(t *testing.T) {
	reached := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	SetTestHooks(&TestHooks{Barrier: func(name string, key string) {
		if name != "sidecar.generation.repost.before" {
			return
		}
		held := false
		once.Do(func() { held = true })
		if held {
			close(reached)
			<-release
		}
	}})
	t.Cleanup(func() { SetTestHooks(nil) })

	world := newTestEnrollWorld(t)
	ctx := context.Background()
	if err := world.enroll(ctx); err != nil {
		t.Fatal(err)
	}
	awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateOffline, 1))
	testAwait(t, reached, "the generation's repost at its barrier")
	identity := world.sidecar.currentIdentity()
	world.installAuthority(t, testAdmissionRow(identity.SidecarId, 0))
	world.api.setDeltaAnswers("lost")
	if err := world.sidecar.Logout(ctx); !errors.Is(err, ErrSidecarLogoutPending) {
		t.Fatalf("a logout whose post's answer is lost: %v", err)
	}
	posts := world.api.deltaPostCount()
	if posts != 1 {
		t.Fatalf("%d posts before the repost goes on", posts)
	}

	close(release)
	testAwait(t, world.sidecar.runningGeneration().pendingDone, "the generation's repost to end")
	if count := world.api.deltaPostCount(); count != posts {
		t.Fatalf("the generation's repost posted %d statements kept after it started", count-posts)
	}
	pendings, err := world.sidecar.pendingSignOuts(identity.SidecarId)
	if err != nil || len(pendings) != 1 {
		t.Fatalf("the kept sign-out: %d %v", len(pendings), err)
	}

	if err := world.sidecar.Logout(ctx); err != nil {
		t.Fatalf("the caller's retry: %v", err)
	}
	if count := world.api.deltaPostCount(); count != posts+1 {
		t.Fatalf("the caller's retry made %d posts", count-posts)
	}
}
