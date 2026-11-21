// The pin store's judgment of a head read at an ask (evs_pin_store.go's header) as a table of raises, and a read that
// is stale each time it is read again, on the stand-in evs.

package sidecar

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// One ref's raises judged against their asks: a raise past the pin; a head that raise walked over stands, the pin
// unmoved, and one there on another chain, or whose walk crosses the pin on another chain, is a fork; a head below the
// pin it asked at is a regression; the chains are kept only while a read of the ref is in flight, at most
// PinChainCount, so a head they no longer reach is stale; and a reseed while a read is in flight leaves its head stale.
func TestEvsPinStoreJudgesAHeadAgainstItsAsk(t *testing.T) {
	world := newEvsTestWorld(t)
	reader := world.reader(t, evsTestId("reader"))
	pins := reader.client.pins
	repoId, refId := world.repoId, world.refId
	chains := [][sha256.Size]byte{EvsChainStart(repoId, refId)}
	for version := 1; version <= 6; version += 1 {
		chains = append(chains, EvsChainNext(chains[version-1], evsTestId(fmt.Sprint("push ", version)), sha256.Sum256([]byte(fmt.Sprint("statement ", version)))))
	}
	other := EvsChainNext(chains[2], evsTestId("the other push 3"), sha256.Sum256([]byte("the other statement 3")))
	// a head verified from ask, walked from fromVersion, its chain at each version chains' but where swapped
	head := func(ask *evsPinAsk, fromVersion uint64, version uint64, swapped map[uint64][sha256.Size]byte) *EvsVerifiedHead {
		chainAt := func(at uint64) [sha256.Size]byte {
			if chain, ok := swapped[at]; ok {
				return chain
			}
			return chains[at]
		}
		verified := &EvsVerifiedHead{
			RepoId: repoId, RefId: refId, Head: &protocol.EvsHeadSummary{}, Version: version, Chain: chainAt(version),
			FromVersion: fromVersion, ask: ask, fromChain: chainAt(fromVersion),
		}
		for at := fromVersion + 1; at <= version; at += 1 {
			verified.Statements = append(verified.Statements, &EvsVerifiedStatement{Version: at, Chain: chainAt(at)})
		}
		return verified
	}
	raise := func(verified *EvsVerifiedHead) (evsPinStanding, *EvsPin, error) {
		return pins.raiseRead(&EvsPin{RepoId: repoId, RefId: refId, Version: verified.Version, Chain: verified.Chain}, verified)
	}
	ask := func() *evsPinAsk {
		asked, err := pins.ask(repoId, refId)
		if err != nil {
			t.Fatal(err)
		}
		return asked
	}
	pinned := func(version uint64) {
		t.Helper()
		pin, ok, _ := pins.Pin(repoId, refId)
		if !ok || pin.Version != version || pin.Chain != chains[version] {
			t.Fatalf("the pin %+v, want %d", pin, version)
		}
	}

	done := pins.beginRead(repoId, refId)
	if standing, _, err := raise(head(ask(), 0, 2, nil)); err != nil || standing != evsPinAbove {
		t.Fatalf("the first raise: %d %v", standing, err)
	}
	pinned(2)
	second := ask()
	if standing, _, err := raise(head(second, 2, 4, nil)); err != nil || standing != evsPinAbove {
		t.Fatalf("the raise past: %d %v", standing, err)
	}
	pinned(4)
	if standing, _, err := raise(head(second, 2, 3, nil)); err != nil || standing != evsPinPassed {
		t.Errorf("a head the raise walked over: %d %v", standing, err)
	}
	pinned(4)
	if _, mine, err := raise(head(second, 2, 3, map[uint64][sha256.Size]byte{3: other})); !errors.Is(err, ErrEvsPinFork) || mine.Version != 3 || mine.Chain != chains[3] {
		t.Errorf("a head on another chain: %+v %v", mine, err)
	}
	if _, mine, err := raise(head(second, 2, 5, map[uint64][sha256.Size]byte{3: other})); !errors.Is(err, ErrEvsPinFork) || mine.Version != 3 {
		t.Errorf("a walk past the pin through another chain: %+v %v", mine, err)
	}
	if _, mine, err := raise(head(ask(), 2, 3, nil)); !errors.Is(err, ErrEvsPinLower) || mine.Version != 4 {
		t.Errorf("a head below the pin it asked at: %+v %v", mine, err)
	}
	pinned(4)
	done()
	// no read in flight, nothing kept: the head the raise walked over can no longer be placed
	if standing, _, err := raise(head(second, 2, 3, nil)); err != nil || standing != evsPinStale {
		t.Errorf("a head after the reads ended: %d %v", standing, err)
	}

	// the oldest kept out first past PinChainCount
	pins.settings.PinChainCount = 2
	done = pins.beginRead(repoId, refId)
	fourth := ask()
	if standing, _, err := raise(head(fourth, 4, 6, nil)); err != nil || standing != evsPinAbove {
		t.Fatalf("the raise to 6: %d %v", standing, err)
	}
	if standing, _, err := raise(head(second, 2, 4, nil)); err != nil || standing != evsPinStale {
		t.Errorf("a head the count let go: %d %v", standing, err)
	}
	if standing, _, err := raise(head(fourth, 4, 5, nil)); err != nil || standing != evsPinPassed {
		t.Errorf("a head the count keeps: %d %v", standing, err)
	}
	done()

	// a reseed while a read is in flight
	done = pins.beginRead(repoId, refId)
	defer done()
	sixth := ask()
	if err := pins.lowerByReseed(&EvsPin{RepoId: repoId, RefId: refId, Version: 2, Chain: chains[2]}, []byte("incident"), reader.clock.Now(), 1); err != nil {
		t.Fatal(err)
	}
	if standing, _, err := raise(head(sixth, 6, 6, nil)); err != nil || standing != evsPinStale {
		t.Errorf("a head read across a reseed: %d %v", standing, err)
	}
	pinned(2)
}

// A read that each time it is read again meets a head another raise passed while it was in flight, a raise that
// walked nothing, answers ErrEvsReadStale once ReadStaleRetryCount reads again ran out, with no alarm.
func TestEvsOverlappingReadStaleEachTimeAnswersStale(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("asked")})
	hold := &evsTestHold{handler: world}
	reader := evsTestOverlapReader(t, world, hold)
	reader.client.settings.ReadStaleRetryCount = 1
	if result := evsTestReadOf(reader, world, "a.txt"); result.err != nil {
		t.Fatal(result.err)
	}
	pushes := 0
	push := func() {
		pushes += 1
		world.push(&evsTestChange{path: fmt.Sprint("p", pushes), content: []byte("p")})
	}
	raiseAhead := func() {
		push()
		version, chain := world.head()
		if err := reader.client.pins.Raise(&EvsPin{RepoId: world.repoId, RefId: world.refId, Version: version, Chain: chain}); err != nil {
			t.Fatal(err)
		}
	}
	push()
	first := hold.arm(evsTestIsRead, false)
	t.Cleanup(first.let)
	reads := make(chan evsTestReadResult, 1)
	go func() { reads <- evsTestReadOf(reader, world, "a.txt") }()
	<-first.held
	raiseAhead()
	// the read again asks at that pin and is answered a version above it
	push()
	second := hold.arm(evsTestIsRead, false)
	t.Cleanup(second.let)
	first.let()
	<-second.held
	raiseAhead()
	second.let()
	if result := <-reads; !errors.Is(result.err, ErrEvsReadStale) || 0 < len(result.content) {
		t.Fatalf("the stale read: %q %v", result.content, result.err)
	}
	if alarms := reader.alarms(); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
}
