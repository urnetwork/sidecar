//go:build sidecar_testhooks

// The barriers around a stream call's wait (stream_conn.go's stream.read_wait and stream.write_wait) on the
// BarrierDriver every Net installs in this build, used as a schedule uses them: armed by name, they hold a stream's
// read and write at their waits while the Net's clock passes the deadline, and their keys are opaque ids, so the
// driver records no violation of testhook.go's rule for them.

package sidecartest

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"
	"time"
)

// A read and a write, each held by the Net's driver at its wait while the Net's clock passes its deadline, end with
// os.ErrDeadlineExceeded once released: the deadline's wait fired after each had read the deadline and subscribed.
// Each barrier is traced under a key of its stream's, and none broke the rule.
func TestStreamWaitBarriersHoldACallAtItsWait(t *testing.T) {
	testNet, a, b, accepted := newTestStreamPair(t)
	opened, stream := testOpenStream(t, a, b, accepted)
	clock := testNet.Clock()
	barriers := testNet.Barriers()
	names := []string{"stream.read_wait.before", "stream.write_wait.before"}
	// after the streams' own cleanups are set, so it runs before them: a held write keeps its stream's writeLock,
	// which Close waits for
	t.Cleanup(func() {
		for _, name := range names {
			barriers.Release(name)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), testStreamTimeout)
	defer cancel()
	for _, name := range names {
		if err := barriers.Arm(name, "", 0); err != nil {
			t.Fatal(err)
		}
	}
	deadline := clock.Now().Add(time.Second)
	if err := stream.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := opened.SetWriteDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	readErr := make(chan error, 1)
	go func() {
		_, err := stream.Read(make([]byte, 1))
		readErr <- err
	}()
	written := make(chan error, 1)
	go func() {
		// past any window the reader grants, and nothing reads it
		_, err := opened.Write(make([]byte, 4*1024*1024))
		written <- err
	}()
	for _, name := range names {
		if err := barriers.AwaitHeld(ctx, name, ""); err != nil {
			t.Fatal(err)
		}
	}
	clock.Advance(time.Second)
	for _, name := range names {
		if err := barriers.Release(name); err != nil {
			t.Fatal(err)
		}
	}
	for what, ended := range map[string]chan error{"the read": readErr, "the write": written} {
		select {
		case err := <-ended:
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Errorf("%s past its deadline: %v", what, err)
			}
		case <-ctx.Done():
			t.Fatalf("%s past its deadline never ended", what)
		}
	}
	for _, name := range names {
		if !slices.ContainsFunc(barriers.Trace(), func(event *BarrierEvent) bool {
			return event.Kind == BarrierHeld && event.Name == name && event.Key != ""
		}) {
			t.Errorf("%s: no hold traced under a stream's key", name)
		}
	}
	if violations := barriers.Violations(); len(violations) != 0 {
		t.Fatalf("the stream barriers broke testhook.go's rule: %q", violations)
	}
}
