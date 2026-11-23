// QD-1209's line between a fork a start holds and an error after which the next follow starts again (configStartFork):
// an entry's fork is held as it is, and a restore whose anchor does not link is held at the newest base of its page,
// while a head or rows api withheld, a run refused and a page below the pin hold nothing. The client's rows source names
// rows api did not serve as withheld, so a start's anchor that wraps them in its fork holds none. Every leg: root types
// only.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// An entry of networkId at n, of kind, chaining onto prevChain, as api serves it, and its digest.
func testStartForkEntry(t *testing.T, networkId Id, n uint64, kind uint32, prevChain []byte) ([]byte, [sha256.Size]byte) {
	t.Helper()
	entry := &bridge.AuthEntry{NetworkId: networkId.Bytes(), N: n, PrevChain: prevChain, Kind: kind, TimeMs: 1, Body: []byte{byte(n)}}
	entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := bridge.AuthChainDigest(n, prevChain, kind, entry.GetTimeMs(), entry.GetBody())
	if err != nil {
		t.Fatal(err)
	}
	return entryBytes, chain
}

// An entry's own fork is held as it is, wrapped or not.
func TestAStartHoldsAnEntrysForkAsItIs(t *testing.T) {
	fork := &ConfigForkError{N: 9, Reason: "base: not a header"}
	for _, err := range []error{fork, fmt.Errorf("a start: %w", fork)} {
		if held := configStartFork(err, nil); held != fork {
			t.Fatalf("%v held %v, want the entry's fork", err, held)
		}
	}
}

// A restore whose anchor does not link holds a fork at the newest base of the page the start anchored on, with the
// digest that entry gives and what did not hold; at the page's first entry where the page holds no base.
func TestAStartHoldsItsAnchorsForkAtThePagesNewestBase(t *testing.T) {
	networkId := NewId()
	statement5, chain5 := testStartForkEntry(t, networkId, 5, bridge.AuthEntryKindStatement, bytes.Repeat([]byte{0x01}, sha256.Size))
	base6, chain6 := testStartForkEntry(t, networkId, 6, bridge.AuthEntryKindBase, chain5[:])
	statement7, _ := testStartForkEntry(t, networkId, 7, bridge.AuthEntryKindStatement, chain6[:])
	err := fmt.Errorf("%w: base %d: %w", ErrConfigFork, 6, errors.New("no header"))

	held := configStartFork(err, [][]byte{statement5, base6, statement7})
	if held == nil || held.N != 6 || held.RemoteChain != chain6 || !bytes.Equal(held.Entry, base6) || held.HasLocalChain ||
		!strings.Contains(held.Reason, "base 6: no header") {
		t.Fatalf("the anchor's fork held %+v, want one at base 6", held)
	}
	if !errors.Is(held, ErrConfigFork) {
		t.Fatalf("the held fork %v is no ErrConfigFork", held)
	}
	held = configStartFork(err, [][]byte{statement5, statement7})
	if held == nil || held.N != 5 || held.RemoteChain != chain5 || !bytes.Equal(held.Entry, statement5) {
		t.Fatalf("with no base on the page the anchor's fork held %+v, want one at the page's first entry 5", held)
	}
}

// An error after which the next follow starts again holds nothing: a head or rows api withheld, where a restore wraps
// it in ErrConfigFork too, a run refused, a page below the pin, and any other.
func TestAStartHoldsNoForkForWhatTheNextFollowReadsAgain(t *testing.T) {
	for _, err := range []error{
		nil,
		ErrConfigHeadUnavailable,
		fmt.Errorf("%w: base %d's config head: %w", ErrConfigFork, 6, ErrConfigHeadUnavailable),
		fmt.Errorf("%w: base %d's rows: %w", ErrConfigFork, 6, fmt.Errorf("%w: api served no rows", ErrConfigRowsUnavailable)),
		fmt.Errorf("%w: base %d: %w", ErrConfigRowsUnavailable, 6, errors.New("api served no rows")),
		&ConfigRunError{N: 6, Reason: "a second A_n at the reader's own pin"},
		fmt.Errorf("%w: %d below %d", ErrConfigBelowPin, 5, 6),
		errors.New("api unreachable"),
	} {
		if held := configStartFork(err, nil); held != nil {
			t.Fatalf("%v held %v, want none", err, held)
		}
	}
}

// The client's rows source names rows the page does not carry as withheld, as a run's prefetch does.
func TestTheClientsRowsSourceNamesUnservedRowsWithheld(t *testing.T) {
	source := &configClientRowsSource{rows: map[[sha256.Size]byte][]byte{}}
	if _, err := source.Rows(NewId(), bytes.Repeat([]byte{0x02}, sha256.Size)); !errors.Is(err, ErrConfigRowsUnavailable) {
		t.Fatalf("rows api did not serve answered %v, want ErrConfigRowsUnavailable", err)
	}
}
