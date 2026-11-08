package dnsservice

import (
	"fmt"
	"maps"
	"math/rand/v2"
	"testing"
)

// The trie against a map, through random writes, with every earlier handle kept and checked at the
// end: a change must reach no handle made before it.
func TestZoneNamesMatchAMapAndKeepEveryEarlierHandle(t *testing.T) {
	random := rand.New(rand.NewPCG(1, 2))
	type version struct {
		names zoneNames
		want  map[string]*zoneNode
	}
	names := newZoneNames()
	want := map[string]*zoneNode{}
	versions := []version{}
	for generation := uint64(1); generation <= 200; generation += 1 {
		// a build writes many names at one generation, in place where it may
		for range 1 + random.IntN(50) {
			name := fmt.Sprintf("n%d.zone.example.", random.IntN(500))
			if random.IntN(3) == 0 {
				names.remove(generation, name)
				delete(want, name)
			} else {
				node := &zoneNode{childCount: random.Int()}
				names.set(generation, name, node)
				want[name] = node
			}
		}
		versions = append(versions, version{names: names, want: maps.Clone(want)})
	}
	for index := range versions {
		names := &versions[index].names
		for name, node := range versions[index].want {
			if got := names.get(name); got != node {
				t.Fatalf("version %d: %s holds %v", index, name, got)
			}
		}
		visited := 0
		for name, node := range names.all() {
			visited += 1
			if versions[index].want[name] != node {
				t.Fatalf("version %d: all gave %s", index, name)
			}
		}
		if visited != len(versions[index].want) {
			t.Fatalf("version %d: %d names for %d", index, visited, len(versions[index].want))
		}
	}
}

func TestZoneNamesHoldNothingOnceEmptied(t *testing.T) {
	names := newZoneNames()
	for index := range 1000 {
		names.set(1, fmt.Sprintf("n%d.zone.example.", index), &zoneNode{})
	}
	for index := range 1000 {
		names.remove(2, fmt.Sprintf("n%d.zone.example.", index))
	}
	if len(names.root.slots) != 0 || names.root.bitmap != 0 {
		t.Errorf("root %+v", names.root)
	}
	if names.get("n1.zone.example.") != nil {
		t.Error("a removed name is still there")
	}
}

func TestZoneNamesRemoveWhatIsNotThere(t *testing.T) {
	names := newZoneNames()
	names.set(1, "a.zone.example.", &zoneNode{})
	root := names.root
	names.remove(2, "b.zone.example.")
	if names.root != root {
		t.Error("removing a missing name changed the trie")
	}
}

// A name that is not there copies nothing, however far down its path runs before it ends.
func TestZoneBranchRemovalOfAMissingNameKeepsTheBranch(t *testing.T) {
	first := &zoneName{hash: 1, name: "a", node: &zoneNode{}}
	// shares a's first level, so the two sit in a branch below it
	second := &zoneName{hash: 1 + 32, name: "b", node: &zoneNode{}}
	branch := zoneTrieWith(1, first, second)
	if replacement := branch.without(2, 1+64, "c", 0); replacement != any(branch) {
		t.Errorf("a missing name left %v", replacement)
	}
}

// A trie by hand, on chosen hashes.
func zoneTrieWith(generation uint64, entries ...*zoneName) *zoneBranch {
	branch := &zoneBranch{}
	for _, entry := range entries {
		branch = branch.with(generation, entry, 0)
	}
	return branch
}

// Names whose full hashes collide share a slot and stay apart.
func TestZoneBranchKeepsFullHashCollisionsApart(t *testing.T) {
	first := &zoneNode{childCount: 1}
	second := &zoneNode{childCount: 2}
	third := &zoneNode{childCount: 3}
	hash := uint64(0xabcdef)
	branch := zoneTrieWith(1,
		&zoneName{hash: hash, name: "a", node: first},
		&zoneName{hash: hash, name: "b", node: second},
		&zoneName{hash: hash, name: "c", node: third},
		// in a slot of its own, so the branch stands whatever leaves the chain
		&zoneName{hash: hash + 1, name: "neighbour", node: &zoneNode{}},
	)
	for name, want := range map[string]*zoneNode{"a": first, "b": second, "c": third, "d": nil} {
		if got := branch.get(hash, name); got != want {
			t.Errorf("%s holds %v", name, got)
		}
	}
	replaced := &zoneNode{childCount: 4}
	branch = branch.with(2, &zoneName{hash: hash, name: "b", node: replaced}, 0)
	if branch.get(hash, "b") != replaced || branch.get(hash, "a") != first || branch.get(hash, "c") != third {
		t.Error("a replacement disturbed its neighbours")
	}
	after, ok := branch.without(3, hash, "b", 0).(*zoneBranch)
	if !ok {
		t.Fatalf("after removing one of three: %T", after)
	}
	if after.get(hash, "b") != nil || after.get(hash, "a") != first || after.get(hash, "c") != third {
		t.Error("a removal disturbed its neighbours")
	}
	if branch.get(hash, "b") != replaced {
		t.Error("a removal reached the earlier trie")
	}
	if same := after.without(4, hash, "d", 0); same != any(after) {
		t.Error("removing a name not in the chain changed the trie")
	}
	// a chain alone in its branch moves up whole, and its last link leaves the branch empty
	alone := zoneTrieWith(1, &zoneName{hash: hash, name: "a", node: first}, &zoneName{hash: hash, name: "b", node: second})
	chain, ok := alone.without(2, hash, "b", 0).(*zoneName)
	if !ok || chain.name != "a" || chain.next != nil {
		t.Errorf("chain %+v", chain)
	}
	lone := zoneTrieWith(1, &zoneName{hash: hash, name: "a", node: first})
	if replacement := lone.without(2, hash, "a", 0); replacement != nil {
		t.Errorf("replacement %v", replacement)
	}
}

// Hashes that differ only in their last bits use every level, and the level past them is never read.
func TestZoneBranchReachesTheLastHashBits(t *testing.T) {
	first := &zoneNode{childCount: 1}
	second := &zoneNode{childCount: 2}
	low := uint64(0)
	high := uint64(1) << 63
	branch := zoneTrieWith(1, &zoneName{hash: low, name: "a", node: first}, &zoneName{hash: high, name: "b", node: second})
	if branch.get(low, "a") != first || branch.get(high, "b") != second {
		t.Fatal("two deep names lost")
	}
	if branch.get(low|1<<60, "a") != nil {
		t.Error("a hash that differs found a name")
	}
	// taking one out brings the other all the way back up
	replacement := branch.without(2, high, "b", 0)
	entry, ok := replacement.(*zoneName)
	if !ok || entry.name != "a" {
		t.Errorf("replacement %T", replacement)
	}
}

// A published branch is never written, however many names a later build adds beside it.
func TestZoneBranchWritesInPlaceOnlyInItsGeneration(t *testing.T) {
	branch := zoneTrieWith(1, &zoneName{hash: 1, name: "a", node: &zoneNode{}})
	same := branch.with(1, &zoneName{hash: 2, name: "b", node: &zoneNode{}}, 0)
	if same != branch {
		t.Error("a build copied its own branch")
	}
	next := same.with(2, &zoneName{hash: 3, name: "c", node: &zoneNode{}}, 0)
	if next == same || same.get(3, "c") != nil {
		t.Error("a later build wrote an earlier branch")
	}
}
