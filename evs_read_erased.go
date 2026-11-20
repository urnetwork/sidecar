//go:build !ios_extension

// The keyless-slot rule (§11.12's push, closure and after rows; owner decisions 61, 400): what a read makes of a key
// its slot no longer holds. An ERASE's statement names the keys it destroys, and evs commits it before it rewrites
// any slot it names (§11.12's push row; evsservice's afterCommitted), so a key gone from its slot is either one a
// committed ERASE destroyed, which reads as erased, or one evs withheld, which alarms tamper: a slot that stands is
// rewritten only to drop erased keys (§11.8's fences row), and it holds the one stored copy of each key (owner decision
// 400).
//
//	judge     each read's keys (evsReadKeys) carry one judge, made at the first key gone, which reads the repo's
//	          committed ERASEs (EvsRepo.ReadErasures, a fresh read of the erasure ref) when it first judges one. A
//	          key the list in hand names is erased: an ERASE once committed stays so. One it does not name is judged
//	          on the list read again, once, from the newest ERASE it holds: the list in hand may be older than the
//	          slot, as when a read takes a page of versions one at a time and an ERASE commits between the version
//	          whose emptied slot made it read the ERASEs and the next version's slot read. That second read is after
//	          the slot was read, so an ERASE that emptied the slot shows in it, and a key it still does not name was
//	          withheld. A read with no key gone reads no ERASE
//	keys      the verifying reader (reconstructContent) judges a record's key by its slot and key index, as an
//	          ERASE's list names it; a stream's reader judges a file whose every chain slot came back emptied by its
//	          slots, each named by some committed ERASE, each stream entry keeping its keys in a slot of its own
//	          (evs_streams.go, directory_evs.go)
//	cost      a withheld key costs one more read of the ERASEs before its alarm; a version whose key an ERASE named
//	          costs none past the first, unless the list in hand is older than its slot
//
// The forwarding role's legs register no judge: they read no erasure ref, so there every key gone from its slot is
// one evs withheld, as it was (evs_reconstruct.go's newEvsErasureJudge, a deliberate seam off the legs, QD-1145).
//
// On every leg but the ios_extension legs. Not safe for concurrent use: one per read, as the read's keys are.

package sidecar

import (
	"context"

	"github.com/urnetwork/sidecar/protocol"
)

// Registers the judge a read's keys make at their first key gone (evs_reconstruct.go's seam).
func init() {
	newEvsErasureJudge = func() evsErasureJudge {
		return &evsErasedKeys{}
	}
}

// The keys the repo's committed ERASEs name, as one read last read them: see the file header.
type evsErasedKeys struct {
	// whether the ERASEs were read, and the erasure ref's version of the newest one read
	read    bool
	through uint64
	// each key a committed ERASE names, by slot and key index, and each slot it names a key of
	keys  map[EvsErasedKey]bool
	slots map[Id]bool
}

// The judge keys carry, made now where they carry none: the one every reconstruction of the read judges by too.
func evsErasedKeysOf(keys *evsReadKeys) *evsErasedKeys {
	if erased, ok := keys.erasures.(*evsErasedKeys); ok {
		return erased
	}
	erased := &evsErasedKeys{}
	keys.erasures = erased
	return erased
}

// Whether a committed ERASE names slotId's key at keyIndex. See evsErasureJudge.
func (self *evsErasedKeys) namesKey(ctx context.Context, repo *EvsRepo, slotId Id, keyIndex uint16) (bool, error) {
	return self.names(ctx, repo, func() bool {
		return self.keys[EvsErasedKey{SlotId: slotId, KeyIndex: keyIndex}]
	})
}

// Whether a committed ERASE names a key of each slot entry keeps its chain's keys in: a stream file whose every slot
// came back emptied reads as erased only so (evsStreamFileEmptied).
func (self *evsErasedKeys) namesSlots(ctx context.Context, repo *EvsRepo, entry *protocol.EvsEntryVersion) (bool, error) {
	return self.names(ctx, repo, func() bool {
		if len(entry.GetSlotIds()) == 0 {
			return false
		}
		for _, slotIdBytes := range entry.GetSlotIds() {
			slotId, err := IdFromBytes(slotIdBytes)
			if err != nil || !self.slots[slotId] {
				return false
			}
		}
		return true
	})
}

// named on the list in hand; where it says no, or no list was read, on the ERASEs read now, after the slot it judges.
func (self *evsErasedKeys) names(ctx context.Context, repo *EvsRepo, named func() bool) (bool, error) {
	if self.read && named() {
		return true, nil
	}
	if err := self.readAfter(ctx, repo); err != nil {
		return false, err
	}
	return named(), nil
}

// Adds the ERASEs committed after the newest one read, all of them the first time.
func (self *evsErasedKeys) readAfter(ctx context.Context, repo *EvsRepo) error {
	erasures, err := repo.ReadErasures(ctx, self.through)
	if err != nil {
		return err
	}
	if self.keys == nil {
		self.keys = map[EvsErasedKey]bool{}
		self.slots = map[Id]bool{}
	}
	for _, erasure := range erasures {
		for _, key := range erasure.Keys {
			self.keys[*key] = true
			self.slots[key.SlotId] = true
		}
		self.through = max(self.through, erasure.Version)
	}
	self.read = true
	return nil
}
