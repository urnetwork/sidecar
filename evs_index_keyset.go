// Key sets and deltas (§11.14's key set row; protocol/INDEX-FORMAT.md). A document's set of trigram keys is written
// whole in a full entry, or as what a diff added to and removed from its base's set. Composing deltas lives here
// because a reader's chains and a writer's head rule must agree on it (D-EVS-46).

package sidecar

// The largest key: three bytes.
const indexKeyMax = 0xFFFFFF

// Past this a key set is skipped, since nearly every query would match its chunk (§11.14's sniff row), so no entry
// holds a longer one.
const indexKeySetMaxByteCount = 512 * 1024

// Distinct keys, ascending, which encoding relies on and checks.
type indexKeySet []uint32

// Refuses keys out of order, repeated or past 24 bits.
func (self indexKeySet) check() error {
	for index, key := range self {
		if indexKeyMax < key {
			return indexMalformed("a key past 24 bits")
		}
		if 0 < index && key <= self[index-1] {
			return indexMalformed("keys out of order")
		}
	}
	return nil
}

// The bytes this set encodes to, which is what §11.14's 512 KiB skip reads.
func (self indexKeySet) encodedByteCount() int {
	byteCount := indexVByteLength(uint64(len(self)))
	last := -1
	for _, key := range self {
		byteCount += indexVByteLength(uint64(int(key) - last))
		last = int(key)
	}
	return byteCount
}

// Appends VByte count, then VByte gaps, the first gap key + 1.
func (self indexKeySet) appendEncoded(dst []byte) ([]byte, error) {
	if err := self.check(); err != nil {
		return nil, err
	}
	start := len(dst)
	dst = indexAppendVByte(dst, uint64(len(self)))
	last := -1
	for _, key := range self {
		dst = indexAppendVByte(dst, uint64(int(key)-last))
		last = int(key)
	}
	if indexKeySetMaxByteCount < len(dst)-start {
		return nil, indexMalformed("a key set past its cap")
	}
	return dst, nil
}

// Reads a key set. Every key takes at least a byte, so a count past the bytes left is refused before it sizes
// anything, and a gap of zero, which a repeated key would need, never decodes.
func (self *indexDecoder) keySet() indexKeySet {
	start := self.remaining()
	count := self.vbyte()
	if uint64(self.remaining()) < count {
		self.refuse("a key count past the end of its input")
	}
	if self.err != nil {
		return nil
	}
	keys := make(indexKeySet, 0, count)
	last := -1
	for range count {
		gap := self.vbyte()
		if gap == 0 || indexKeyMax+1 < gap {
			self.refuse("a key gap out of range")
		}
		if self.err != nil {
			return nil
		}
		key := last + int(gap)
		if indexKeyMax < key {
			self.refuse("a key past 24 bits")
			return nil
		}
		keys = append(keys, uint32(key))
		last = key
	}
	if indexKeySetMaxByteCount < start-self.remaining() {
		self.refuse("a key set past its cap")
		return nil
	}
	return keys
}

// Keys of this set that other does not hold. Both ascend, so this is one walk.
func (self indexKeySet) without(other indexKeySet) indexKeySet {
	keys := indexKeySet{}
	otherIndex := 0
	for _, key := range self {
		for otherIndex < len(other) && other[otherIndex] < key {
			otherIndex += 1
		}
		if otherIndex == len(other) || other[otherIndex] != key {
			keys = append(keys, key)
		}
	}
	return keys
}

// Every key of two sets that share none, ascending, in one walk.
func (self indexKeySet) with(other indexKeySet) indexKeySet {
	keys := make(indexKeySet, 0, len(self)+len(other))
	otherIndex := 0
	for _, key := range self {
		for otherIndex < len(other) && other[otherIndex] < key {
			keys = append(keys, other[otherIndex])
			otherIndex += 1
		}
		keys = append(keys, key)
	}
	return append(keys, other[otherIndex:]...)
}

// Whether a key is in both sets.
func (self indexKeySet) overlaps(other indexKeySet) bool {
	return len(self.without(other)) != len(self)
}

// What a diff changes: its base's set less removed, plus added. added holds no key of the base, and removed only keys
// of it, so a delta has one meaning against one base.
type indexDelta struct {
	added   indexKeySet
	removed indexKeySet
}

// Refuses a delta that adds and removes one key, or whose sets are not key sets.
func (self indexDelta) check() error {
	if err := self.added.check(); err != nil {
		return err
	}
	if err := self.removed.check(); err != nil {
		return err
	}
	if self.added.overlaps(self.removed) {
		return indexMalformed("a key both added and removed")
	}
	return nil
}

// The delta from base to next.
func indexDeltaBetween(base indexKeySet, next indexKeySet) indexDelta {
	return indexDelta{added: next.without(base), removed: base.without(next)}
}

// The set this delta makes of base, refused when base is not the set the delta was taken against, which is how a
// chain that does not resolve shows (§11.14's chains row).
func (self indexDelta) applyTo(base indexKeySet) (indexKeySet, error) {
	if err := self.check(); err != nil {
		return nil, err
	}
	if base.overlaps(self.added) {
		return nil, indexMalformed("a delta adds a key its base holds")
	}
	kept := base.without(self.removed)
	if len(kept)+len(self.removed) != len(base) {
		return nil, indexMalformed("a delta removes a key its base lacks")
	}
	return kept.with(self.added), nil
}

// One delta equal to first and then second, for a diff that takes over its head entry's base and for a reader walking
// a chain. A delta's effect is the set of keys it flips, so composing is the symmetric difference of those sets, which
// is what makes it associative. Two deltas that could not apply in turn are refused: a key added twice, or removed
// twice, without the other delta undoing it between.
func indexComposeDelta(first indexDelta, second indexDelta) (indexDelta, error) {
	if err := first.check(); err != nil {
		return indexDelta{}, err
	}
	if err := second.check(); err != nil {
		return indexDelta{}, err
	}
	if first.added.overlaps(second.added) || first.removed.overlaps(second.removed) {
		return indexDelta{}, indexMalformed("two deltas that do not compose")
	}
	return indexDelta{
		added:   first.added.without(second.removed).with(second.added.without(first.removed)),
		removed: first.removed.without(second.added).with(second.removed.without(first.added)),
	}, nil
}
