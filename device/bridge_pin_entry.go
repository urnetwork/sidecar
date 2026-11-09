// One sender entry's advertisers as the pins see them (§17.5, D-BRIDGE-7, D-BRIDGE-9): each link with its weight, its
// drain and its health, and the window an entry opens when it first offers a choice. Edits run off the packet path
// and publish an immutable snapshot by pointer, so a Pick reads the whole entry with one atomic load and no lock;
// health is an atomic of its own, carried from snapshot to snapshot, since a down mark must not wait for an edit.
//
//	kept     an advertiser joining, a weight change or another link's health leaves every link serving what it did
//	removed  Withdraw and Retarget leave the old link in the entry, draining: it serves its pinned pairs, and every
//	         pair while nothing else remains, for TCP until max(its drain's end, the drain's start plus 600 s) and
//	         otherwise until max(its drain's end, its start plus 5 min); a rebuilt link drains to its strict_exp
//	health   MarkDown takes a link out of new pairs for 30 s while another advertiser is up, and keeps its pins
//	window   an entry that offered no choice (one link, so no pins) and now offers one sends a pinless pair, at first
//	         sight, to the link it had, for 600 s after the change for TCP and 5 min otherwise, while that link
//	         stays in the entry
//	reset    Reset takes a revoked advertiser out at once, with no drain; the pin table drops its pins
//
// A BridgeEntryState is safe for concurrent use.

package device

import (
	"cmp"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// A link as the pins know one: a number its bridge gives each link it builds, never 0, never reused while the bridge
// runs.
type BridgeLinkId uint32

// One advertiser of an entry, as an edit gives it.
type BridgeEntryLink struct {
	Link BridgeLinkId
	// Its rendezvous weight (D-BRIDGE-9); 0 is 1.
	Weight uint32
	// A drain: zero DrainingSince for a live link; DrainUntil is the rule's own end, before §17.5's floors.
	DrainingSince time.Time
	DrainUntil    time.Time
}

// A link's health, shared by every snapshot of the entry.
type bridgeLinkHealth struct {
	// unix ns until which the link is down; 0 for up
	downUntil atomic.Int64
}

// One link in a snapshot.
type bridgeEntryLinkState struct {
	link   BridgeLinkId
	weight float64
	// zero while live
	drainingSince time.Time
	// the last moments a draining link serves TCP pairs and everything else
	tcpServesUntil   time.Time
	otherServesUntil time.Time
	health           *bridgeLinkHealth
}

// Whether the link serves pairs of the protocol at now: live, or draining and short of its end.
func (self *bridgeEntryLinkState) serves(tcp bool, now time.Time) bool {
	if self.drainingSince.IsZero() {
		return true
	}
	if tcp {
		return now.Before(self.tcpServesUntil)
	}
	return now.Before(self.otherServesUntil)
}

// Whether the link takes new pairs as an up advertiser: live and not marked down.
func (self *bridgeEntryLinkState) up(nowNano int64) bool {
	return self.drainingSince.IsZero() && self.health.downUntil.Load() <= nowNano
}

// What a Pick reads of an entry: never changed once published.
type bridgeEntrySnapshot struct {
	// by link, ascending
	links []bridgeEntryLinkState
	// the window, zero windowSince for none
	windowLink  BridgeLinkId
	windowSince time.Time
}

// Whether the entry offers a choice: two links or more, draining ones included (§17.5's record row).
func (self *bridgeEntrySnapshot) offersChoice() bool {
	return 1 < len(self.links)
}

// The link's state in the snapshot, or nil.
func (self *bridgeEntrySnapshot) find(link BridgeLinkId) *bridgeEntryLinkState {
	for i := range self.links {
		if self.links[i].link == link {
			return &self.links[i]
		}
	}
	return nil
}

// One entry's advertisers. See the file's comment.
type BridgeEntryState struct {
	settings *BridgeSettings
	clock    Clock
	// names the entry in the pins it holds, so a pin of one entry never serves another
	entryId uint32

	snapshot atomic.Pointer[bridgeEntrySnapshot]

	// serializes edits; Pick never takes it
	stateLock sync.Mutex
}

// The ids entries take in pins, from 1, wrapping within bridgePinEntryIdMask.
var bridgeEntryIdCounter atomic.Uint32

// An entry advertised by links, as a state first names it: no window, since nothing changed yet. Nil settings are
// DefaultBridgeSettings.
func NewBridgeEntryState(links []BridgeEntryLink, settings *BridgeSettings) *BridgeEntryState {
	if settings == nil {
		settings = DefaultBridgeSettings()
	}
	entryId := bridgeEntryIdCounter.Add(1) & bridgePinEntryIdMask
	if entryId == 0 {
		entryId = bridgeEntryIdCounter.Add(1) & bridgePinEntryIdMask
	}
	self := &BridgeEntryState{settings: settings, clock: settings.clock(), entryId: entryId}
	self.snapshot.Store(self.buildWithLock(nil, links, time.Time{}))
	return self
}

// The snapshot of links, carrying each link's health from previous, and the window: an entry that offered no choice in
// previous and offers one now opens a window to its one link at now; one already open stays while there is a choice.
func (self *BridgeEntryState) buildWithLock(previous *bridgeEntrySnapshot, links []BridgeEntryLink, now time.Time) *bridgeEntrySnapshot {
	snapshot := &bridgeEntrySnapshot{links: make([]bridgeEntryLinkState, 0, len(links))}
	for _, link := range links {
		if link.Link == 0 {
			continue
		}
		state := bridgeEntryLinkState{
			link:          link.Link,
			weight:        float64(max(link.Weight, 1)),
			drainingSince: link.DrainingSince,
		}
		if !link.DrainingSince.IsZero() {
			state.tcpServesUntil = bridgeLaterTime(link.DrainUntil, link.DrainingSince.Add(self.settings.PinTcpIdleTimeout))
			state.otherServesUntil = bridgeLaterTime(link.DrainUntil, link.DrainingSince.Add(self.settings.PinIdleTimeout))
		}
		if previous != nil {
			if held := previous.find(link.Link); held != nil {
				state.health = held.health
			}
		}
		if state.health == nil {
			state.health = &bridgeLinkHealth{}
		}
		// a link named twice keeps its first state
		if snapshot.find(link.Link) == nil {
			snapshot.links = append(snapshot.links, state)
		}
	}
	slices.SortFunc(snapshot.links, func(a bridgeEntryLinkState, b bridgeEntryLinkState) int {
		return cmp.Compare(a.link, b.link)
	})
	if previous == nil || !snapshot.offersChoice() {
		return snapshot
	}
	switch {
	case !previous.offersChoice() && len(previous.links) == 1 && snapshot.find(previous.links[0].link) != nil:
		snapshot.windowLink = previous.links[0].link
		snapshot.windowSince = now
	case !previous.windowSince.IsZero() && snapshot.find(previous.windowLink) != nil:
		snapshot.windowLink = previous.windowLink
		snapshot.windowSince = previous.windowSince
	}
	return snapshot
}

// The later of two times.
func bridgeLaterTime(a time.Time, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// The links as an edit gives them, from a snapshot.
func (self *bridgeEntrySnapshot) entryLinks() []BridgeEntryLink {
	links := make([]BridgeEntryLink, 0, len(self.links))
	for _, link := range self.links {
		entryLink := BridgeEntryLink{Link: link.link, Weight: uint32(link.weight), DrainingSince: link.drainingSince}
		if !link.drainingSince.IsZero() {
			entryLink.DrainUntil = link.tcpServesUntil
			if link.otherServesUntil.After(entryLink.DrainUntil) {
				entryLink.DrainUntil = link.otherServesUntil
			}
		}
		links = append(links, entryLink)
	}
	return links
}

// Publishes the next snapshot: edit names the links from the one in force at now, under the edit lock. The swap is
// the entry's linearization point, a Pick seeing the whole of one snapshot or of the other, and the barriers around it
// run with no lock held.
func (self *BridgeEntryState) edit(edit func(previous *bridgeEntrySnapshot, now time.Time) []BridgeEntryLink) {
	testHookBarrier("bridge_pin_entry.swap.before", "")
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		previous := self.snapshot.Load()
		now := self.clock.Now()
		self.snapshot.Store(self.buildWithLock(previous, edit(previous, now), now))
	}()
	testHookBarrier("bridge_pin_entry.swap.after", "")
}

// Replaces the advertisers with links, as a new state names them: a joining one, a weight change and a drain each
// keep what other links serve (§17.5's kept row), and health carries over.
func (self *BridgeEntryState) Set(links []BridgeEntryLink) {
	self.edit(func(previous *bridgeEntrySnapshot, now time.Time) []BridgeEntryLink {
		return links
	})
}

// Marks the link down for LinkDownTimeout: a refusal or a connect timeout (§17.5's health row,
// plan-BRIDGE-small-readings #15). It takes no new pairs while another advertiser is up, and keeps its pins.
func (self *BridgeEntryState) MarkDown(link BridgeLinkId) {
	held := self.snapshot.Load().find(link)
	if held == nil {
		return
	}
	testHookBarrier("bridge_pin_entry.mark_down.before", "")
	held.health.downUntil.Store(self.clock.Now().Add(self.settings.LinkDownTimeout).UnixNano())
	testHookBarrier("bridge_pin_entry.mark_down.after", "")
}

// Withdraws the link with a drain (§17.5's removed row): it stays in the entry, serving its pinned pairs and every pair
// while nothing else remains, until max(drainUntil, now plus the idle of each protocol). A link already draining keeps
// its earlier drain.
func (self *BridgeEntryState) Withdraw(link BridgeLinkId, drainUntil time.Time) {
	self.edit(func(previous *bridgeEntrySnapshot, now time.Time) []BridgeEntryLink {
		links := previous.entryLinks()
		for i := range links {
			if links[i].Link == link && links[i].DrainingSince.IsZero() {
				links[i].DrainingSince = now
				links[i].DrainUntil = drainUntil
			}
		}
		return links
	})
}

// Replaces the link from with to, from draining as Withdraw drains it: a retarget, an address or block change, or a
// rebuild, whose old link drains to its strict_exp (§17.5's removed row). A one-advertiser entry so opens a window.
func (self *BridgeEntryState) Retarget(from BridgeLinkId, to BridgeEntryLink, drainUntil time.Time) {
	self.edit(func(previous *bridgeEntrySnapshot, now time.Time) []BridgeEntryLink {
		links := previous.entryLinks()
		for i := range links {
			if links[i].Link == from && links[i].DrainingSince.IsZero() {
				links[i].DrainingSince = now
				links[i].DrainUntil = drainUntil
			}
		}
		return append(links, to)
	})
}

// Takes the link out at once, with no drain: a revocation (§17.8's revocation row). The caller drops its pins from the
// pin table, BridgePinTable.Reset.
func (self *BridgeEntryState) Reset(link BridgeLinkId) {
	self.edit(func(previous *bridgeEntrySnapshot, now time.Time) []BridgeEntryLink {
		return slices.DeleteFunc(previous.entryLinks(), func(entryLink BridgeEntryLink) bool {
			return entryLink.Link == link
		})
	})
}

// The links that serve the entry at now: live ones, and draining ones short of their end for either protocol.
func (self *BridgeEntryState) Links() []BridgeLinkId {
	now := self.clock.Now()
	links := []BridgeLinkId{}
	for _, link := range self.snapshot.Load().links {
		if link.serves(true, now) || link.serves(false, now) {
			links = append(links, link.link)
		}
	}
	return links
}
