//go:build sidecar_testhooks

// Two ingest passes racing on a group's deposits on ingest's push barriers: both read the same deposit and plan its
// push from the same i/, one lands, and the other's push, sent after it, meets the conflict on m/ and only consumes;
// the rest of the two passes then run side by side. Each message lands once whichever pass writes it.

package sidecar

import (
	"context"
	"sync"
	"testing"
)

// Both passes held at mail.ingest.push.before on their first message, the first released and let land, then the
// second: the second meets the first's m/ and i/ moved under it and only consumes that message, and the two passes go
// on racing over the receiver's second message and the sender's deposit with no barrier held. Each of the three
// messages ends with one m/ and one i/ row, announced once, its deposit consumed.
func TestMailIngestPassesHeldAtThePushLandEachGroupMessageOnce(t *testing.T) {
	world := newMailIngestTestWorld(t)
	senderId := NewId()
	ids := []Id{}
	for _, subject := range []string{"First", "Second"} {
		message := testMailIngestMessage(subject, "body")
		trailer := testMailIngestTrailer(world.receiverId, message)
		trailer.Recipients = []string{testMailIngestGroupAddress}
		ids = append(ids, world.repo.deposit(world.receiverId, world.receiverId, testMailIngestPlaintext(t, message, trailer)).id)
	}
	ids = append(ids, world.repo.deposit(senderId, senderId, testMailIngestGroupSend(t, testMailIngestRecipient, "lunch")).id)

	var stateLock sync.Mutex
	arrivals, pushes := 0, 0
	held := []chan struct{}{make(chan struct{}), make(chan struct{})}
	bothHeld := make(chan struct{})
	firstPushed := make(chan struct{})
	SetTestHooks(&TestHooks{Barrier: func(name string, barrierKey string) {
		switch name {
		case "mail.ingest.push.before":
			index := func() int {
				stateLock.Lock()
				defer stateLock.Unlock()
				arrivals += 1
				return arrivals - 1
			}()
			if len(held) <= index {
				return
			}
			if index == len(held)-1 {
				close(bothHeld)
			}
			<-held[index]
		case "mail.ingest.push.after":
			first := func() bool {
				stateLock.Lock()
				defer stateLock.Unlock()
				pushes += 1
				return pushes == 1
			}()
			if first {
				close(firstPushed)
			}
		}
	}})
	t.Cleanup(func() { SetTestHooks(nil) })

	passes := make(chan *MailIngestPass, 2)
	var messagesLock sync.Mutex
	for range 2 {
		ingestor := world.ingestor(func(args *MailIngestArgs) {
			// the two passes announce side by side
			args.Message = func(message *MailMessage) {
				messagesLock.Lock()
				defer messagesLock.Unlock()
				world.messages = append(world.messages, message)
			}
		})
		go func() {
			pass, err := ingestor.Ingest(context.Background())
			if err != nil {
				t.Error(err)
			}
			passes <- pass
		}()
	}
	<-bothHeld
	close(held[0])
	<-firstPushed
	close(held[1])
	ingested, present := 0, 0
	for range 2 {
		pass := <-passes
		if pass == nil {
			t.Fatal("a pass failed")
		}
		ingested += pass.Ingested
		present += pass.Present
		if pass.Left+pass.Refused+pass.Erased != 0 {
			t.Errorf("a pass %+v", pass)
		}
	}
	SetTestHooks(nil)
	if ingested != 3 || present < 1 {
		t.Errorf("%d messages ingested and %d found standing across the two passes", ingested, present)
	}
	months := []MailYearMonth{MailYearMonthOf(testMailIngestReceiveMillis), MailYearMonthOf(testMailIngestReceiveMillis), MailYearMonthOf(uint64(testMailIngestPushMillis))}
	rows := map[Id]int{}
	for _, month := range []MailYearMonth{months[0], months[2]} {
		for _, entry := range world.entries(month) {
			rows[Id(entry.GetId())] += 1
		}
	}
	for i, id := range ids {
		if world.store.file(MailMessagePath(months[i], id)) == nil || rows[id] != 1 {
			t.Errorf("message %d: m/ %v, %d rows", i, world.messagePaths(), rows[id])
		}
	}
	announced := map[Id]int{}
	for _, message := range world.messages {
		announced[message.Id] += 1
	}
	if len(world.messagePaths()) != 3 || len(rows) != 3 || len(announced) != 3 || announced[ids[0]] != 1 || announced[ids[1]] != 1 || announced[ids[2]] != 1 {
		t.Errorf("%d messages, %d ids in i/, announced %v", len(world.messagePaths()), len(rows), announced)
	}
	if world.repo.standingCount(world.receiverId) != 0 || world.repo.standingCount(senderId) != 0 {
		t.Errorf("standing %d and %d", world.repo.standingCount(world.receiverId), world.repo.standingCount(senderId))
	}
}
