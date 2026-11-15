// IP listings (§15.4's Listings, owner decision 111, D-MAIL-2, I-13; MAIL-M7-20): a licensed commercial
// feed's local mirror, so no sender address ever leaves for a lookup (§2.8 ext-4). MxListingSource reads the
// mirror, the one adapter a feed's format needs, and the engine loads what it gives into a prefix set every
// ListingRefreshInterval (5 min), swapped in whole through an atomic pointer, so a read during a swap sees
// the old set or the new one and never half of either.
//
//	reject   only a commercial feed's botnet and exploit categories answer 554 5.7.1 at the banner
//	pass     every other category a sender is listed under rides MailIngress.ip_listings to the receiver
//	stale    a set whose feed was current more than ListingStaleTimeout ago, or none at all, lists no one:
//	         with the feed down nothing is rejected and nothing is passed on
//
// Never greylisting: a listing is a 554 or nothing, decided at the banner, and no state about a sender is
// kept past its connection. A lookup reads one immutable set with no lock and allocates nothing, so a banner
// waits on nothing (I-12). No address, prefix or category reaches a log or a metric (I-13).
//
// Safe for concurrent use.

package mxedgeservice

import (
	"context"
	"errors"
	"fmt"
	"math/bits"
	"net/netip"
	"slices"
	"sort"
	"sync/atomic"
	"time"

	"github.com/urnetwork/sidecar"
)

// The categories owner decision 111 rejects at the banner. A source names its feed's categories in these
// words where they mean these things; any other word passes on.
const (
	MxListingCategoryBotnet  = "botnet"
	MxListingCategoryExploit = "exploit"
)

// How many distinct categories one set holds: the width of a lookup's mask, a structural size.
const mxListingCategoryMaskBitCount = 64

// What a source gives the engine, one entry at a time. An error from add ends the load.
type MxListingAdd func(prefix netip.Prefix, category string) error

// A feed's local mirror, as one adapter reads its format (server/mxedgehost's feed mirror). Load streams
// every entry of the mirror's current data through add and answers when that data was current, the mirror's
// last pull: a set older than ListingStaleTimeout lists no one. An error is a mirror that cannot be read
// now, and the engine keeps the set it has until that goes stale. Implementations are safe for concurrent
// use.
type MxListingSource interface {
	Load(ctx context.Context, add MxListingAdd) (currentTime time.Time, err error)
}

// One prefix length's entries in one family: the networks' keys sorted, each with its categories' index.
type mxListingLength4 struct {
	bitCount int
	keys     []uint32
	sets     []uint16
}

type mxListingKey6 struct {
	high uint64
	low  uint64
}

type mxListingLength6 struct {
	bitCount int
	keys     []mxListingKey6
	sets     []uint16
}

// One loaded set, never changed once made.
type mxListingSet struct {
	currentTime time.Time
	// the category names, by bit
	categories []string
	// the distinct masks entries carry, by index
	masks []uint64
	// the bits of the categories that answer 554
	rejectMask uint64
	lengths4   []*mxListingLength4
	lengths6   []*mxListingLength6
}

// The mask of every category addr is listed under. No lock and no allocation.
func (self *mxListingSet) lookup(addr netip.Addr) uint64 {
	addr = addr.Unmap()
	mask := uint64(0)
	if addr.Is4() {
		bytes := addr.As4()
		value := uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
		for _, length := range self.lengths4 {
			key := uint32(0)
			if 0 < length.bitCount {
				key = value >> (32 - length.bitCount)
			}
			index, found := slices.BinarySearch(length.keys, key)
			if found {
				mask |= self.masks[length.sets[index]]
			}
		}
		return mask
	}
	key := mxListingKey6Of(addr.As16())
	for _, length := range self.lengths6 {
		masked := mxListingKey6Masked(key, length.bitCount)
		index, found := slices.BinarySearchFunc(length.keys, masked, mxListingKey6Compare)
		if found {
			mask |= self.masks[length.sets[index]]
		}
	}
	return mask
}

func mxListingKey6Of(bytes [16]byte) mxListingKey6 {
	high, low := uint64(0), uint64(0)
	for i := range 8 {
		high = high<<8 | uint64(bytes[i])
		low = low<<8 | uint64(bytes[8+i])
	}
	return mxListingKey6{high: high, low: low}
}

// key with every bit past bitCount cleared.
func mxListingKey6Masked(key mxListingKey6, bitCount int) mxListingKey6 {
	switch {
	case bitCount <= 0:
		return mxListingKey6{}
	case bitCount < 64:
		return mxListingKey6{high: key.high &^ (^uint64(0) >> bitCount)}
	case bitCount == 64:
		return mxListingKey6{high: key.high}
	case bitCount < 128:
		return mxListingKey6{high: key.high, low: key.low &^ (^uint64(0) >> (bitCount - 64))}
	}
	return key
}

func mxListingKey6Compare(a mxListingKey6, b mxListingKey6) int {
	switch {
	case a.high < b.high:
		return -1
	case b.high < a.high:
		return 1
	case a.low < b.low:
		return -1
	case b.low < a.low:
		return 1
	}
	return 0
}

// A set, built as a source streams its entries. Not safe for concurrent use.
type mxListingBuilder struct {
	settings     *MxEdgeSettings
	categoryBits map[string]int
	categories   []string
	entryCount   int
	// prefix to its mask, merged across categories
	prefixes4 map[netip.Prefix]uint64
	prefixes6 map[netip.Prefix]uint64
}

var errMxListingRefused = errors.New("the listing mirror holds more than the engine takes")

func newMxListingBuilder(settings *MxEdgeSettings) *mxListingBuilder {
	return &mxListingBuilder{
		settings:     settings,
		categoryBits: map[string]int{},
		prefixes4:    map[netip.Prefix]uint64{},
		prefixes6:    map[netip.Prefix]uint64{},
	}
}

// Takes one entry. A category that is not a printable word within the format's bound, past the mask's
// width, or an entry past ListingPrefixCount ends the load: a set the engine would cut is not loaded at all.
func (self *mxListingBuilder) add(prefix netip.Prefix, category string) error {
	if !prefix.IsValid() || category == "" || self.settings.Ingress.ListingMaxByteCount < len(category) {
		return fmt.Errorf("%w: an entry with no prefix or an unusable category", errMxListingRefused)
	}
	for i := range len(category) {
		if c := category[i]; c <= ' ' || 0x7f <= c {
			return fmt.Errorf("%w: a category that is not a printable word", errMxListingRefused)
		}
	}
	bit, ok := self.categoryBits[category]
	if !ok {
		if mxListingCategoryMaskBitCount <= len(self.categories) {
			return fmt.Errorf("%w: more than %d categories", errMxListingRefused, mxListingCategoryMaskBitCount)
		}
		bit = len(self.categories)
		self.categoryBits[category] = bit
		self.categories = append(self.categories, category)
	}
	self.entryCount += 1
	if self.settings.ListingPrefixCount < self.entryCount {
		return fmt.Errorf("%w: past ListingPrefixCount", errMxListingRefused)
	}
	// an IPv4-mapped prefix is held as the IPv4 prefix it names, as a lookup unmaps its address
	addr, bitCount := prefix.Addr().WithZone(""), prefix.Bits()
	if addr.Is4In6() && 96 <= bitCount {
		addr, bitCount = addr.Unmap(), bitCount-96
	}
	prefix = netip.PrefixFrom(addr, bitCount).Masked()
	if prefix.Addr().Is4() {
		self.prefixes4[prefix] |= uint64(1) << bit
	} else {
		self.prefixes6[prefix] |= uint64(1) << bit
	}
	return nil
}

// The immutable set, current at currentTime.
func (self *mxListingBuilder) build(currentTime time.Time) *mxListingSet {
	set := &mxListingSet{currentTime: currentTime, categories: slices.Clone(self.categories)}
	maskIndexes := map[uint64]uint16{}
	maskIndex := func(mask uint64) uint16 {
		index, ok := maskIndexes[mask]
		if !ok {
			index = uint16(len(set.masks))
			maskIndexes[mask] = index
			set.masks = append(set.masks, mask)
		}
		return index
	}
	for _, category := range []string{MxListingCategoryBotnet, MxListingCategoryExploit} {
		if bit, ok := self.categoryBits[category]; ok {
			set.rejectMask |= uint64(1) << bit
		}
	}
	byLength4 := map[int]*mxListingLength4{}
	for prefix, mask := range self.prefixes4 {
		length, ok := byLength4[prefix.Bits()]
		if !ok {
			length = &mxListingLength4{bitCount: prefix.Bits()}
			byLength4[prefix.Bits()] = length
		}
		bytes := prefix.Addr().As4()
		value := uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
		key := uint32(0)
		if 0 < prefix.Bits() {
			key = value >> (32 - prefix.Bits())
		}
		length.keys = append(length.keys, key)
		length.sets = append(length.sets, maskIndex(mask))
	}
	for _, length := range byLength4 {
		sort.Sort(&mxListingSort4{length: length})
		set.lengths4 = append(set.lengths4, length)
	}
	byLength6 := map[int]*mxListingLength6{}
	for prefix, mask := range self.prefixes6 {
		length, ok := byLength6[prefix.Bits()]
		if !ok {
			length = &mxListingLength6{bitCount: prefix.Bits()}
			byLength6[prefix.Bits()] = length
		}
		length.keys = append(length.keys, mxListingKey6Masked(mxListingKey6Of(prefix.Addr().As16()), prefix.Bits()))
		length.sets = append(length.sets, maskIndex(mask))
	}
	for _, length := range byLength6 {
		sort.Sort(&mxListingSort6{length: length})
		set.lengths6 = append(set.lengths6, length)
	}
	// longest first is no rule: every length is read, since categories add up across them
	slices.SortFunc(set.lengths4, func(a *mxListingLength4, b *mxListingLength4) int { return a.bitCount - b.bitCount })
	slices.SortFunc(set.lengths6, func(a *mxListingLength6, b *mxListingLength6) int { return a.bitCount - b.bitCount })
	return set
}

// Sorts one length's keys with its sets beside them.
type mxListingSort4 struct {
	length *mxListingLength4
}

func (self *mxListingSort4) Len() int           { return len(self.length.keys) }
func (self *mxListingSort4) Less(i, j int) bool { return self.length.keys[i] < self.length.keys[j] }
func (self *mxListingSort4) Swap(i, j int) {
	self.length.keys[i], self.length.keys[j] = self.length.keys[j], self.length.keys[i]
	self.length.sets[i], self.length.sets[j] = self.length.sets[j], self.length.sets[i]
}

type mxListingSort6 struct {
	length *mxListingLength6
}

func (self *mxListingSort6) Len() int { return len(self.length.keys) }
func (self *mxListingSort6) Less(i, j int) bool {
	return mxListingKey6Compare(self.length.keys[i], self.length.keys[j]) < 0
}
func (self *mxListingSort6) Swap(i, j int) {
	self.length.keys[i], self.length.keys[j] = self.length.keys[j], self.length.keys[i]
	self.length.sets[i], self.length.sets[j] = self.length.sets[j], self.length.sets[i]
}

// How a load went, a metric's result.
const (
	mxListingLoadResultLoaded = "loaded"
	mxListingLoadResultFailed = "failed"
)

// The engine's listings: the set in use and the loop that loads the next.
type mxListings struct {
	source   MxListingSource
	settings *MxEdgeSettings
	clock    sidecar.Clock
	metrics  *mxMetrics
	set      atomic.Pointer[mxListingSet]
	// loads finished, failed or not, each counted once the wait for the next is armed
	loadCount *sidecar.MonitorValue[int]
}

func newMxListings(source MxListingSource, settings *MxEdgeSettings, clock sidecar.Clock, metrics *mxMetrics) *mxListings {
	return &mxListings{
		source:    source,
		settings:  settings,
		clock:     clock,
		metrics:   metrics,
		loadCount: sidecar.NewMonitorValue(0),
	}
}

// The set if it is fresh, else nil: no set, or one whose feed was current more than ListingStaleTimeout
// ago.
func (self *mxListings) current() *mxListingSet {
	set := self.set.Load()
	if set == nil || self.settings.ListingStaleTimeout < self.clock.Now().Sub(set.currentTime) {
		return nil
	}
	return set
}

// Whether sender gets 554 at the banner: listed under botnet or exploit in a fresh set. No lock and no
// allocation.
func (self *mxListings) Refused(sender netip.Addr) bool {
	set := self.current()
	return set != nil && set.lookup(sender)&set.rejectMask != 0
}

// The categories sender is listed under in a fresh set, sorted, for MailIngress; nil when none.
func (self *mxListings) Categories(sender netip.Addr) []string {
	set := self.current()
	if set == nil {
		return nil
	}
	mask := set.lookup(sender)
	if mask == 0 {
		return nil
	}
	categories := make([]string, 0, bits.OnesCount64(mask))
	for bit, category := range set.categories {
		if mask&(uint64(1)<<bit) != 0 {
			categories = append(categories, category)
		}
	}
	slices.Sort(categories)
	return categories
}

// Loads the mirror into a new set and swaps it in. A failure keeps the set in use, which goes stale on its
// own.
func (self *mxListings) load(ctx context.Context) {
	builder := newMxListingBuilder(self.settings)
	currentTime, err := func() (time.Time, error) {
		loadCtx, cancel := context.WithCancel(ctx)
		stop := self.clock.AfterFunc(self.settings.ListingLoadTimeout, cancel)
		defer func() {
			stop()
			cancel()
		}()
		return self.source.Load(loadCtx, builder.add)
	}()
	if err != nil {
		self.metrics.listingLoads.Add(1, mxListingLoadResultFailed)
		return
	}
	set := builder.build(currentTime)
	testHookBarrier("mxedge.listings_swap.before", "")
	self.set.Store(set)
	testHookBarrier("mxedge.listings_swap.after", "")
	self.metrics.listingLoads.Add(1, mxListingLoadResultLoaded)
}

// Loads the mirror at once and then each ListingRefreshInterval until ctx ends.
func (self *mxListings) run(ctx context.Context) {
	for {
		self.load(ctx)
		next := self.clock.After(self.settings.ListingRefreshInterval)
		self.loadCount.Update(func(count int) int { return count + 1 })
		select {
		case <-ctx.Done():
			return
		case <-next:
		}
	}
}
