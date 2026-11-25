//go:build sidecar_testhooks && !ios_extension && !sidecar_http

package sidecar

import (
	"context"
	"testing"
	"time"
)

// Taint is write-ahead: held at record.taint.before the run already reads tainted in memory while its file does not
// say so and Taint has not returned; held at record.taint.after its file says so, fsynced, and Taint still has not
// returned, so the data that tainted it cannot have reached the model or a result. A mark is held the same way.
func TestHarnessTaintFsyncsBeforeResultReturns(t *testing.T) {
	instance, runs, clock := newTestRunStoreOn(t, NewSidecarMemoryBackend())
	run := newHarnessTestRun(t, runs, nil)
	key := run.Id().String()

	reached := make(chan string, 4)
	release := make(chan struct{})
	SetTestHooks(&TestHooks{Barrier: func(name string, barrierKey string) {
		switch name {
		case "record.taint.before", "record.taint.after", "record.mark.before", "record.mark.after":
		default:
			return
		}
		if barrierKey != key {
			return
		}
		reached <- name
		<-release
	}})
	defer SetTestHooks(nil)
	guard := func() <-chan time.Time {
		return time.After(10 * time.Second)
	}

	returned := make(chan error, 1)
	go func() {
		returned <- run.Taint(context.Background(), RunTaintUntrustedData)
	}()
	select {
	case name := <-reached:
		if name != "record.taint.before" {
			t.Fatalf("reached %s first", name)
		}
	case <-guard():
		t.Fatal("Taint never reached its first barrier")
	}
	if !run.Tainted() {
		t.Fatal("a taint in flight does not read tainted in memory")
	}
	if file, err := runs.Get(run.Id()); err != nil || file.Tainted {
		t.Fatalf("the file says tainted before its write: %+v, %v", file, err)
	}
	release <- struct{}{}
	select {
	case name := <-reached:
		if name != "record.taint.after" {
			t.Fatalf("reached %s second", name)
		}
	case <-guard():
		t.Fatal("Taint never reached its second barrier")
	}
	select {
	case err := <-returned:
		t.Fatalf("Taint returned %v before its write was done", err)
	default:
	}
	// what a restarted daemon reads: the file, fsynced
	if !reopenTestRunStore(t, instance, clock).Tainted(run.Id()) {
		t.Fatal("the file does not say tainted at record.taint.after")
	}
	release <- struct{}{}
	select {
	case err := <-returned:
		if err != nil {
			t.Fatal(err)
		}
	case <-guard():
		t.Fatal("Taint did not return")
	}

	marked := make(chan error, 1)
	go func() {
		marked <- run.Mark(context.Background(), HarnessMarkPrivate)
	}()
	if name := <-reached; name != "record.mark.before" {
		t.Fatalf("reached %s for a mark", name)
	}
	if marks, _ := run.Marks(); marks&HarnessMarkPrivate == 0 {
		t.Fatal("a mark in flight does not read in memory")
	}
	release <- struct{}{}
	if name := <-reached; name != "record.mark.after" {
		t.Fatalf("reached %s for a mark", name)
	}
	if names, _ := reopenTestRunStore(t, instance, clock).Marks(run.Id()); len(names) != 1 || names[0] != "private" {
		t.Fatalf("the file holds %v at record.mark.after", names)
	}
	select {
	case err := <-marked:
		t.Fatalf("Mark returned %v before its write was done", err)
	default:
	}
	release <- struct{}{}
	if err := <-marked; err != nil {
		t.Fatal(err)
	}
}
