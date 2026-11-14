//go:build sidecar_testhooks

// MAIL-M7-16's hook sites: an erasure's first ERASE, each part's CLOSURE and ERASE, and a resumed CLOSURE's ERASE sit
// between barriers a fault schedule holds. A device stopped at any of them leaves an erasure another admin's device
// finishes from evs alone, and the stopped device, let go, destroys nothing more and writes no row back.

package sidecar

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
)

// A device held at each of the eraser's barriers, as a kill there leaves it, while another admin's device resumes.
// Before the first ERASE nothing is begun and the resume finds nothing; from then on the resume completes the
// erasure. Each ends with the body's keys gone, the row out of its segment, one version of the segment holding a
// key, and the erasure complete.
func TestMailEraseResumeFinishesADeviceHeldAtEachBarrier(t *testing.T) {
	for _, barrier := range []string{
		"mail.erase.message.before", "mail.erase.message.after", "mail.erase.closure.before", "mail.erase.closure.after",
		"mail.erase.keys.before", "mail.erase.keys.after", "mail.erase.orphan.before", "mail.erase.orphan.after",
	} {
		world := newMailEraseTestWorld(t)
		ctx := context.Background()
		ids := world.ingestMessages("One", "Two")
		segmentPath := MailIndexPath(world.month, 0)
		orphan := strings.HasPrefix(barrier, "mail.erase.orphan.")
		if orphan {
			// a device killed between a CLOSURE and its ERASE, which the held device then resumes
			killed := errors.New("killed between the closure and its erase")
			world.eraseStore.failErase = killed
			if _, err := world.eraser().Erase(ctx, world.month, ids[:1]); !errors.Is(err, killed) {
				t.Fatalf("%s: the kill: %v", barrier, err)
			}
		}
		reached := make(chan struct{})
		release := make(chan struct{})
		var once sync.Once
		SetTestHooks(&TestHooks{Barrier: func(name string, barrierKey string) {
			if name != barrier {
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
		crashing := world.eraser()
		finished := make(chan error, 1)
		go func() {
			if orphan {
				_, err := crashing.Resume(ctx)
				finished <- err
				return
			}
			_, err := crashing.Erase(ctx, world.month, ids[:1])
			finished <- err
		}()
		<-reached

		resumed, err := world.eraser().Resume(ctx)
		if err != nil {
			t.Fatalf("resume at %s: %v", barrier, err)
		}
		switch barrier {
		case "mail.erase.message.before":
			if len(resumed) != 0 || len(world.rowIds()) != 2 {
				t.Errorf("resume at %s: %+v", barrier, resumed)
			}
		case "mail.erase.keys.after", "mail.erase.orphan.after":
			if len(resumed) != 0 {
				t.Errorf("resume at %s took up a complete erasure: %+v", barrier, resumed)
			}
		default:
			if len(resumed) != 1 || resumed[0].State != MailErasureDone {
				t.Errorf("resume at %s: %+v", barrier, resumed)
			}
		}
		close(release)
		if err := <-finished; err != nil {
			t.Errorf("the held device at %s: %v", barrier, err)
		}
		SetTestHooks(nil)

		if rows := world.rowIds(); !slices.Equal(rows, ids[1:]) {
			t.Errorf("after %s: %d rows", barrier, len(rows))
		}
		if len(world.eraseStore.openableVersions(MailMessagePath(world.month, ids[0]))) != 0 {
			t.Errorf("after %s: the erased body keeps a key", barrier)
		}
		if openable := world.eraseStore.openableVersions(segmentPath); len(openable) != 1 {
			t.Errorf("after %s: %d versions of the segment keep a key", barrier, len(openable))
		}
		erasures, _ := world.eraseStore.Erasures(ctx, 0)
		if len(erasures) != 2 || !erasures[1].Complete || erasures[0].ErasureId != erasures[1].ErasureId {
			t.Errorf("after %s: %d erases", barrier, len(erasures))
		}
		if len(world.eraseStore.closedPaths) != 1 {
			t.Errorf("after %s: %d closures", barrier, len(world.eraseStore.closedPaths))
		}
	}
}
