// The names of one ZoneView: a persistent hash array mapped trie. An edge holds every owner of a root
// in memory and takes a journal row every few seconds, so a view cannot copy its names per serial, and
// a reader cannot take a lock per query. Here a change copies only the path to what it touches, about
// log32 of the name count, and every view built earlier stays whole and readable with no lock at all.
//
// Nothing here is safe to change once a view is published, and nothing a published view reaches is
// changed: a build writes in place only the branches of its own generation, which no earlier view can
// reach, since a view at generation g reaches nothing above g and its next build writes at g+1. So a
// load of a whole zone costs one copy of each branch and not one per name.

package dnsservice

import (
	"hash/maphash"
	"iter"
	"math/bits"
	"slices"
)

// Hash bits a level of the trie consumes, so a branch has at most 32 slots.
const (
	zoneTrieBits = 5
	zoneTrieMask = 1<<zoneTrieBits - 1
)

// One name and its node. Names whose full hashes collide share a slot through next.
type zoneName struct {
	hash uint64
	name string
	node *zoneNode
	next *zoneName
}

// This chain with entry in it, in place of any link of the same name.
func (self *zoneName) withChained(entry *zoneName) *zoneName {
	chain := &zoneName{hash: entry.hash, name: entry.name, node: entry.node}
	for link := self; link != nil; link = link.next {
		if link.name != entry.name {
			chain = &zoneName{hash: link.hash, name: link.name, node: link.node, next: chain}
		}
	}
	return chain
}

// This chain without name, nil when that empties it, and whether name was in it.
func (self *zoneName) withoutChained(name string) (chain *zoneName, found bool) {
	for link := self; link != nil; link = link.next {
		if link.name == name {
			found = true
			continue
		}
		chain = &zoneName{hash: link.hash, name: link.name, node: link.node, next: chain}
	}
	return chain, found
}

// A trie level. slots holds a *zoneBranch or *zoneName for each bit set in bitmap, in bit order.
type zoneBranch struct {
	generation uint64
	bitmap     uint32
	slots      []any
}

// The hash bit a name takes at this level.
func zoneTrieBit(hash uint64, shift uint) uint32 {
	return 1 << ((hash >> shift) & zoneTrieMask)
}

// This branch if generation may write it, else a copy that it may.
func (self *zoneBranch) writable(generation uint64) *zoneBranch {
	if self.generation == generation {
		return self
	}
	return &zoneBranch{generation: generation, bitmap: self.bitmap, slots: slices.Clone(self.slots)}
}

// A branch holding two names of different hashes, one level per bit they share.
func newZoneBranch(generation uint64, first *zoneName, second *zoneName, shift uint) *zoneBranch {
	firstBit := zoneTrieBit(first.hash, shift)
	secondBit := zoneTrieBit(second.hash, shift)
	switch {
	case firstBit == secondBit:
		return &zoneBranch{
			generation: generation,
			bitmap:     firstBit,
			slots:      []any{newZoneBranch(generation, first, second, shift+zoneTrieBits)},
		}
	case firstBit < secondBit:
		return &zoneBranch{generation: generation, bitmap: firstBit | secondBit, slots: []any{first, second}}
	}
	return &zoneBranch{generation: generation, bitmap: firstBit | secondBit, slots: []any{second, first}}
}

// The node of name, or nil.
func (self *zoneBranch) get(hash uint64, name string) *zoneNode {
	branch := self
	for shift := uint(0); ; shift += zoneTrieBits {
		bit := zoneTrieBit(hash, shift)
		if branch.bitmap&bit == 0 {
			return nil
		}
		switch slot := branch.slots[bits.OnesCount32(branch.bitmap&(bit-1))].(type) {
		case *zoneBranch:
			branch = slot
		case *zoneName:
			for link := slot; link != nil; link = link.next {
				if link.name == name {
					return link.node
				}
			}
			return nil
		}
	}
}

// This branch with entry in it. Writes in place only what generation may.
func (self *zoneBranch) with(generation uint64, entry *zoneName, shift uint) *zoneBranch {
	bit := zoneTrieBit(entry.hash, shift)
	index := bits.OnesCount32(self.bitmap & (bit - 1))
	next := self.writable(generation)
	if self.bitmap&bit == 0 {
		next.bitmap |= bit
		next.slots = slices.Insert(next.slots, index, any(entry))
		return next
	}
	switch slot := next.slots[index].(type) {
	case *zoneBranch:
		next.slots[index] = slot.with(generation, entry, shift+zoneTrieBits)
	case *zoneName:
		if slot.hash == entry.hash {
			next.slots[index] = slot.withChained(entry)
		} else {
			next.slots[index] = newZoneBranch(generation, slot, entry, shift+zoneTrieBits)
		}
	}
	return next
}

// What stands in this branch's place once name is gone: this branch when name was not here, a smaller
// branch, the one *zoneName left, which moves up so no chain of lone branches stays behind, or nil.
func (self *zoneBranch) without(generation uint64, hash uint64, name string, shift uint) any {
	bit := zoneTrieBit(hash, shift)
	if self.bitmap&bit == 0 {
		return self
	}
	index := bits.OnesCount32(self.bitmap & (bit - 1))
	var replacement any
	switch slot := self.slots[index].(type) {
	case *zoneBranch:
		replacement = slot.without(generation, hash, name, shift+zoneTrieBits)
		if replacement == any(slot) {
			return self
		}
	case *zoneName:
		chain, found := slot.withoutChained(name)
		if !found {
			return self
		}
		if chain != nil {
			replacement = chain
		}
	}
	if replacement == nil {
		if len(self.slots) == 1 {
			return nil
		}
		if len(self.slots) == 2 {
			if entry, ok := self.slots[1-index].(*zoneName); ok {
				return entry
			}
		}
		next := self.writable(generation)
		next.bitmap &^= bit
		next.slots = slices.Delete(next.slots, index, index+1)
		return next
	}
	if entry, ok := replacement.(*zoneName); ok && len(self.slots) == 1 {
		return entry
	}
	next := self.writable(generation)
	next.slots[index] = replacement
	return next
}

// Every name below this branch.
func (self *zoneBranch) visit(yield func(name string, node *zoneNode) bool) bool {
	for _, slot := range self.slots {
		switch slot := slot.(type) {
		case *zoneBranch:
			if !slot.visit(yield) {
				return false
			}
		case *zoneName:
			for link := slot; link != nil; link = link.next {
				if !yield(link.name, link.node) {
					return false
				}
			}
		}
	}
	return true
}

// A view's names. The value is a handle: copying it forks the map, and the two then change apart.
type zoneNames struct {
	// Per process, so a name's place in the trie cannot be chosen from outside.
	seed maphash.Seed
	root *zoneBranch
}

// An empty map.
func newZoneNames() zoneNames {
	return zoneNames{seed: maphash.MakeSeed(), root: &zoneBranch{}}
}

// The node of name, or nil.
func (self *zoneNames) get(name string) *zoneNode {
	return self.root.get(maphash.String(self.seed, name), name)
}

// Gives name this node.
func (self *zoneNames) set(generation uint64, name string, node *zoneNode) {
	self.root = self.root.with(generation, &zoneName{hash: maphash.String(self.seed, name), name: name, node: node}, 0)
}

// Takes name out, if it is in.
func (self *zoneNames) remove(generation uint64, name string) {
	switch replacement := self.root.without(generation, maphash.String(self.seed, name), name, 0).(type) {
	case *zoneBranch:
		self.root = replacement
	case *zoneName:
		self.root = (&zoneBranch{}).with(generation, replacement, 0)
	default:
		self.root = &zoneBranch{}
	}
}

// Every name, in no order a caller may rely on.
func (self *zoneNames) all() iter.Seq2[string, *zoneNode] {
	return func(yield func(name string, node *zoneNode) bool) {
		self.root.visit(yield)
	}
}
