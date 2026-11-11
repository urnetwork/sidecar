//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind && !windows && !sidecar_http && !ios_extension

// ur share's hooks, under the tag: socket.share.reserve.before sits outside the share's mutex, so a schedule parks two
// getters racing the last use there, and once released exactly one reserves it (§22.5); and the share's secret reaches
// the secret hook where it is drawn and where a link yields it, so the privacy harness scans for it.

package sidecar

import (
	"bytes"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Two getters parked together at the Reserve's barrier, released at once: one is served, the other is spent, and the
// record holds one Reserve.
func TestShareRacersParkAtReserveBarrier(t *testing.T) {
	fixture := newTestShareFixture(t)
	link := fixture.add(fixture.file("data.bin", testShareContent), 1, time.Hour)
	arrived, release := parkAtBarrier(t, "socket.share.reserve.before")
	results := make(chan error, 2)
	var group sync.WaitGroup
	for _, name := range []string{"left", "right"} {
		group.Add(1)
		go func() {
			defer group.Done()
			results <- fixture.get(link, testSocketId(name), filepath.Join(fixture.directory, name))
		}()
	}
	testSocketAwait(t, arrived, "the first racer at the barrier")
	testSocketAwait(t, arrived, "the second racer at the barrier")
	close(release)
	group.Wait()
	close(results)
	served, spent := 0, 0
	for err := range results {
		switch {
		case err == nil:
			served += 1
		case errors.Is(err, ErrShareSpent), errors.Is(err, ErrShareRefused):
			// spent, or reset by the share's end once the winner's Done came first
			spent += 1
		default:
			t.Errorf("a racer: %v", err)
		}
	}
	if served != 1 || spent != 1 {
		t.Errorf("served %d, spent %d", served, spent)
	}
}

// The secret reaches the secret hook as share_secret where ur draws it and where a link yields it.
func TestShareSecretReachesTheHook(t *testing.T) {
	var stateLock sync.Mutex
	seen := [][]byte{}
	t.Cleanup(func() { SetTestHooks(nil) })
	SetTestHooks(&TestHooks{Secret: func(kind string, secret []byte) {
		if kind == "share_secret" {
			stateLock.Lock()
			defer stateLock.Unlock()
			seen = append(seen, secret)
		}
	}})
	token, secret := NewShareCredentials()
	if _, err := ParseShareLink(FormatShareLink("abcdefghij", token, testSocketId("sharer"), secret)); err != nil {
		t.Fatal(err)
	}
	stateLock.Lock()
	defer stateLock.Unlock()
	if len(seen) != 2 || !bytes.Equal(seen[0], secret) || !bytes.Equal(seen[1], secret) {
		t.Errorf("the hook saw %d secrets", len(seen))
	}
}
