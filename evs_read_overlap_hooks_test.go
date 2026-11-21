//go:build sidecar_testhooks

// A read held at its pin's raise (evs.pin.raise.before), its head already checked against the pin it asked at, while
// another read of the same client raises the pin: the raise judges the head again against the pin as it then stands
// (evs_pin_store.go's header). Before the fix the first case's raise refused as a regression (ErrEvsPinLower, with a
// fork alarm), and the second's raised the pin past a fork with no alarm.

package sidecar

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// Holds the first raise of the world's ref at its barrier until the test lets it go; every other raise passes.
func evsTestHoldFirstRaise(t *testing.T, world *evsTestWorld) (chan struct{}, func()) {
	key := world.repoId.String() + ":" + world.refId.String()
	held := make(chan struct{})
	release := make(chan struct{})
	taken := atomic.Bool{}
	SetTestHooks(&TestHooks{Barrier: func(name string, barrierKey string) {
		if name != "evs.pin.raise.before" || barrierKey != key || !taken.CompareAndSwap(false, true) {
			return
		}
		close(held)
		<-release
	}})
	once := sync.Once{}
	let := func() { once.Do(func() { close(release) }) }
	t.Cleanup(func() {
		let()
		SetTestHooks(nil)
	})
	return held, let
}

// Another read raises the pin past a read's head between that read's check and its raise, walking over the head: the
// held raise finds the head on the pinned history and the read stands as read, with no alarm.
func TestEvsReadRaisedPastBetweenItsCheckAndItsPinStands(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("asked")})
	reader := world.reader(t, evsTestId("reader"))
	if result := evsTestReadOf(reader, world, "a.txt"); result.err != nil {
		t.Fatal(result.err)
	}
	world.push(&evsTestChange{path: "b.txt", content: []byte("b")})
	held, let := evsTestHoldFirstRaise(t, world)
	reads := make(chan evsTestReadResult, 1)
	go func() { reads <- evsTestReadOf(reader, world, "a.txt") }()
	<-held
	world.push(&evsTestChange{path: "c.txt", content: []byte("c")})
	if result := evsTestReadOf(reader, world, "c.txt"); result.err != nil {
		t.Fatal(result.err)
	}
	let()
	result := <-reads
	if result.err != nil || string(result.content) != "asked" || result.info.HeadVersion != 2 {
		t.Fatalf("the held read: %q %+v %v", result.content, result.info, result.err)
	}
	if alarms := reader.alarms(); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
	pin, _, _ := reader.client.pins.Pin(world.repoId, world.refId)
	if pin.Version != 3 {
		t.Errorf("the pin %d", pin.Version)
	}
}

// Another read raises the pin, on the other side of a fork, below a read's head between that read's check and its
// raise: the held raise finds the head's walk crossing the pin on another chain, refuses it as a fork with
// head_alarm, both RefHeads as evidence, and leaves the pin where the other read raised it.
func TestEvsReadAboveAPinRaisedOnAnotherChainBetweenItsCheckAndItsPinIsAFork(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("asked")})
	route := &evsTestWorldRoute{world: world}
	reader := evsTestOverlapReader(t, world, route)
	if result := evsTestReadOf(reader, world, "a.txt"); result.err != nil {
		t.Fatal(result.err)
	}
	fork := evsTestForkWorld(t, world)
	world.push(&evsTestChange{path: "b.txt", content: []byte("one side")})
	world.push(&evsTestChange{path: "c.txt", content: []byte("c")})
	fork.push(&evsTestChange{path: "b.txt", content: []byte("the other side")})
	held, let := evsTestHoldFirstRaise(t, world)
	reads := make(chan evsTestReadResult, 1)
	go func() { reads <- evsTestReadOf(reader, world, "a.txt") }()
	<-held
	route.to(fork)
	if result := evsTestReadOf(reader, fork, "b.txt"); result.err != nil || string(result.content) != "the other side" {
		t.Fatalf("the read beside it: %q %v", result.content, result.err)
	}
	let()
	if result := <-reads; !errors.Is(result.err, ErrEvsPinFork) || 0 < len(result.content) {
		t.Fatalf("the held read: %q %v", result.content, result.err)
	}
	forks := reader.eventsOf(SidecarEventHeadAlarm)
	if len(forks) != 1 || forks[0].HeadAlarm != SidecarHeadAlarmFork {
		t.Fatalf("fork alarms %v", forks)
	}
	mine, served := &protocol.RefHead{}, &protocol.RefHead{}
	if proto.Unmarshal(forks[0].Evidence[0], mine) != nil || proto.Unmarshal(forks[0].Evidence[1], served) != nil {
		t.Fatal("the evidence does not parse")
	}
	if mine.GetVersion() != 2 || !bytes.Equal(mine.GetChain(), fork.commits[1].chain[:]) ||
		served.GetVersion() != 2 || !bytes.Equal(served.GetChain(), world.commits[1].chain[:]) {
		t.Errorf("evidence %v %v", mine, served)
	}
	pin, _, _ := reader.client.pins.Pin(world.repoId, world.refId)
	if pin.Version != 2 || pin.Chain != fork.commits[1].chain {
		t.Errorf("the pin moved: %d", pin.Version)
	}
}
