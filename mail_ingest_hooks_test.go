//go:build sidecar_testhooks

// MAIL-M7-15's hook sites: ingest's push and its CONSUME sit between barriers a fault schedule holds, and a process
// stopped at any of them leaves a mailbox a restarted ingest finishes with one message and no deposit (FS-13's core).

package sidecar

import (
	"context"
	"sync"
	"testing"
)

// A process held at each of ingest's barriers, as a kill there leaves it: before the push nothing stands and the
// restart ingests; after the push and before the CONSUME the message stands with its deposit, and the restart only
// consumes; after the CONSUME nothing is left for the restart. Each ends with one message, one row and no deposit,
// and the held process, let go, changes nothing.
func TestMailIngestRestartFinishesAProcessHeldAtEachBarrier(t *testing.T) {
	for _, barrier := range []string{"mail.ingest.push.before", "mail.ingest.push.after", "mail.ingest.consume.before", "mail.ingest.consume.after"} {
		world := newMailIngestTestWorld(t)
		deposit := world.depositMessage(testMailIngestMessage("Hello", "body"))
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
		crashing := world.ingestor(nil)
		finished := make(chan error, 1)
		go func() {
			_, err := crashing.Ingest(context.Background())
			finished <- err
		}()
		<-reached

		month := MailYearMonthOf(testMailIngestReceiveMillis)
		messageStands := world.store.file(MailMessagePath(month, deposit.id)) != nil
		depositStands := world.repo.standingCount(world.receiverId) == 1
		wantMessage := barrier != "mail.ingest.push.before"
		wantDeposit := barrier != "mail.ingest.consume.after"
		if messageStands != wantMessage || depositStands != wantDeposit {
			t.Fatalf("held at %s: message %t, deposit %t", barrier, messageStands, depositStands)
		}

		restarted, err := world.ingestor(nil).Ingest(context.Background())
		if err != nil {
			t.Fatalf("restart at %s: %v", barrier, err)
		}
		switch barrier {
		case "mail.ingest.push.before":
			if restarted.Ingested != 1 || restarted.Consumed != 1 {
				t.Errorf("restart at %s: %+v", barrier, restarted)
			}
		case "mail.ingest.consume.after":
			if *restarted != (MailIngestPass{}) {
				t.Errorf("restart at %s: %+v", barrier, restarted)
			}
		default:
			if restarted.Present != 1 || restarted.Ingested != 0 || restarted.Consumed != 1 {
				t.Errorf("restart at %s: %+v", barrier, restarted)
			}
		}
		close(release)
		if err := <-finished; err != nil {
			t.Errorf("the held process at %s: %v", barrier, err)
		}
		SetTestHooks(nil)
		if len(world.messagePaths()) != 1 || len(world.entries(month)) != 1 || world.repo.standingCount(world.receiverId) != 0 {
			t.Errorf("after %s: %v, %d rows, %d deposits", barrier, world.messagePaths(), len(world.entries(month)), world.repo.standingCount(world.receiverId))
		}
	}
}
