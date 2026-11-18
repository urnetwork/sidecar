//go:build !ios_extension

// The checked DROP bodies a device keeps, and a listed version's state by the reader's clock (EVS2-M10-22; DESIGN-DETAILS
// 10.6's evs_drop_state_test.go rows): a kept body read back as written, named by its version in held_drops; the keep
// bound evicting the least recently used and removing its file; a body past the bound not kept; and drop_pending
// turning dropped at not_before_ms, or at once when evs withheld the entry version.

package sidecar

import (
	"bytes"
	"testing"
	"time"
)

// Kept bodies read back as written, are named newest first in held_drops, and past the bound the least recently used
// goes, its file with it.
func TestEvsDropBodiesKeepWithinTheirBound(t *testing.T) {
	store := newEvsTestStore(t)
	bodies := newEvsDropBodies(store, 300)
	repoId, refId := evsTestId("repo"), evsTestId("ref")
	first, second, third := evsTestId("drop 1"), evsTestId("drop 2"), evsTestId("drop 3")
	if err := bodies.put(repoId, refId, first, 5, []byte("statement 1"), bytes.Repeat([]byte{1}, 100)); err != nil {
		t.Fatal(err)
	}
	if err := bodies.put(repoId, refId, second, 9, []byte("statement 2"), bytes.Repeat([]byte{2}, 100)); err != nil {
		t.Fatal(err)
	}
	body, version, statement, ok, err := bodies.get(repoId, refId, first)
	if err != nil || !ok || version != 5 || !bytes.Equal(statement, []byte("statement 1")) || !bytes.Equal(body, bytes.Repeat([]byte{1}, 100)) {
		t.Fatalf("a kept body read back: %v %v %d", ok, err, version)
	}
	// the first was used last, so the second is the least recently used when a third passes the bound
	if err := bodies.put(repoId, refId, third, 12, nil, bytes.Repeat([]byte{3}, 150)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok, _ := bodies.get(repoId, refId, second); ok {
		t.Fatalf("the least recently used body kept past the bound")
	}
	if entries, err := store.List(evsDropBodyName(repoId, refId, second)); err != nil || len(entries) != 0 {
		t.Fatalf("an evicted body's file stayed: %v", entries)
	}
	if held := bodies.heldVersions(repoId, refId, 64); len(held) != 2 || held[0] != 12 || held[1] != 5 {
		t.Fatalf("held_drops %v", held)
	}
	if held := bodies.heldVersions(repoId, evsTestId("another ref"), 64); len(held) != 0 {
		t.Fatalf("another ref's held_drops %v", held)
	}
	// a body past the whole bound is not kept
	if err := bodies.put(repoId, refId, evsTestId("drop 4"), 20, nil, make([]byte, 301)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok, _ := bodies.get(repoId, refId, evsTestId("drop 4")); ok {
		t.Fatalf("a body past the bound kept")
	}
}

// drop_pending before not_before_ms by this device's clock, dropped from then on, and dropped at once where evs
// withheld the entry version; nil is neither.
func TestEvsDropStateByTheReadersClock(t *testing.T) {
	notBefore := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	state := &EvsDropState{NotBefore: notBefore}
	if state.Dropped(notBefore.Add(-time.Millisecond)) || state.Name(notBefore.Add(-time.Millisecond)) != EvsVersionStateDropPending {
		t.Fatalf("before the window's end")
	}
	if !state.Dropped(notBefore) || state.Name(notBefore) != EvsVersionStateDropped {
		t.Fatalf("at the window's end")
	}
	withheld := &EvsDropState{NotBefore: notBefore, Withheld: true}
	if !withheld.Dropped(notBefore.Add(-time.Hour)) {
		t.Fatalf("a withheld entry version read as pending")
	}
	var none *EvsDropState
	if none.Dropped(notBefore) || none.Name(notBefore) != "" {
		t.Fatalf("no drop read as one")
	}
}
