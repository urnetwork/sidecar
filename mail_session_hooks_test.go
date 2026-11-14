//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// MAIL-M7-14's hook sites: the spool's per-message key reaches testHookSecret, each repo's deposit sits between its
// barriers, and mail.deposit.durable sits before the 250, so a fault schedule holding it holds the reply.

package sidecar

import (
	"slices"
	"sync"
	"testing"
)

// Held at mail.deposit.durable, the sender has no reply; released, it reads 250, every repo's after barrier having
// fired first; and the message's spool key reached the secret hook.
func TestMailSessionDurableBarrierHoldsThe250(t *testing.T) {
	var stateLock sync.Mutex
	kinds := map[string]int{}
	order := []string{}
	reached := make(chan struct{})
	release := make(chan struct{})
	SetTestHooks(&TestHooks{
		Secret: func(kind string, secret []byte) {
			stateLock.Lock()
			defer stateLock.Unlock()
			kinds[kind] += 1
		},
		Barrier: func(name string, key string) {
			stateLock.Lock()
			order = append(order, name)
			stateLock.Unlock()
			if name == "mail.deposit.durable" {
				close(reached)
				<-release
			}
		},
	})
	t.Cleanup(func() { SetTestHooks(nil) })
	world := newMailSessionTestWorld(t, nil)
	sender := world.open(testMailSessionIngress(t))
	sender.envelope(testMailSessionAlice, testMailSessionCarol)
	codes, _ := sender.data(testMailSessionMessage("barrier"))
	<-reached
	select {
	case code := <-codes:
		t.Fatalf("a reply %d while the durable barrier held", code)
	default:
	}
	if deposits := world.takenDeposits(); len(deposits) != 2 {
		t.Fatalf("%d deposits durable at the barrier", len(deposits))
	}
	close(release)
	if code := <-codes; code != 250 {
		t.Fatalf("reply %d", code)
	}
	stateLock.Lock()
	defer stateLock.Unlock()
	if kinds["mail_spool_key"] != 1 {
		t.Errorf("the spool key reached the hook %d times", kinds["mail_spool_key"])
	}
	durable := slices.Index(order, "mail.deposit.durable")
	afters := 0
	for index, name := range order {
		if name == "mail.deposit.repo.after" {
			afters += 1
			if durable < index {
				t.Error("a repo's deposit finished after the durable barrier")
			}
		}
	}
	if afters != 2 {
		t.Errorf("%d repos' after barriers", afters)
	}
}
