// Session caps (§15.4's last row, readings 1 and 2), all in memory: Redis and the store are never
// asked, so a sender over a cap costs one lock. Counts are of sessions now open in this process, so a
// block's caps do not add across blocks, and an entry is deleted when its count reaches zero: the maps
// hold only what is connected, never more than the process cap allows, and nothing about a sender
// outlives its connection (§2.8 mx-1).
//
// A cap has two moments, because a network is known only from SNI, after STARTTLS's 220, when no SMTP
// reply can follow in the clear. Admit runs before the banner, and past a cap the session gets 421.
// AdmitNetwork runs once SNI names a network, and past a cap the handshake closes instead (reading 1).
//
// Safe for concurrent use.

package mxedgeservice

import (
	"net/netip"
	"sync"

	"github.com/urnetwork/sidecar"
)

// Which cap refused a session, a metric's result. Empty admits.
type mxCapRefusal string

const (
	mxCapRefusalNone            mxCapRefusal = ""
	mxCapRefusalProcess         mxCapRefusal = "process"
	mxCapRefusalSender          mxCapRefusal = "sender"
	mxCapRefusalSenderAggregate mxCapRefusal = "sender_aggregate"
	mxCapRefusalNetwork         mxCapRefusal = "network"
	mxCapRefusalNetworkSender   mxCapRefusal = "network_sender"
)

// A sender /24 or /48 at one network, the unit of §15.4's "2 sessions per sender /24 per network".
type mxNetworkSender struct {
	networkId sidecar.Id
	aggregate netip.Prefix
}

// One session's share of the counters. Give it back with Release.
type mxCapHold struct {
	sender    netip.Prefix
	aggregate netip.Prefix
	// Zero until AdmitNetwork.
	networkSender mxNetworkSender
	inNetwork     bool
	released      bool
}

// Counts of the sessions now open, by what each cap counts.
type mxCaps struct {
	settings *MxEdgeSettings

	stateLock           sync.Mutex
	sessionCount        int
	senderCounts        map[netip.Prefix]int
	aggregateCounts     map[netip.Prefix]int
	networkCounts       map[sidecar.Id]int
	networkSenderCounts map[mxNetworkSender]int
}

// Counters at zero, read against settings' caps.
func newMxCaps(settings *MxEdgeSettings) *mxCaps {
	return &mxCaps{
		settings:            settings,
		senderCounts:        map[netip.Prefix]int{},
		aggregateCounts:     map[netip.Prefix]int{},
		networkCounts:       map[sidecar.Id]int{},
		networkSenderCounts: map[mxNetworkSender]int{},
	}
}

// The prefix a sender's cap counts by and the aggregate above it: /32 and /24 for IPv4, /64 and /48
// for IPv6. An IPv4-mapped address is IPv4, or one sender would count against two sets of caps.
func mxSenderPrefixes(sender netip.Addr) (senderPrefix netip.Prefix, aggregatePrefix netip.Prefix) {
	unmapped := sender.Unmap()
	senderBits, aggregateBits := 64, 48
	if unmapped.Is4() {
		senderBits, aggregateBits = 32, 24
	}
	// neither fails: each bit count fits the family chosen above
	senderPrefix, _ = unmapped.Prefix(senderBits)
	aggregatePrefix, _ = unmapped.Prefix(aggregateBits)
	return senderPrefix, aggregatePrefix
}

// Counts a new session against the process and sender caps, or says which refused it and counts
// nothing.
func (self *mxCaps) Admit(sender netip.Addr) (*mxCapHold, mxCapRefusal) {
	senderPrefix, aggregatePrefix := mxSenderPrefixes(sender)

	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.settings.ProcessSessionCount <= self.sessionCount {
		return nil, mxCapRefusalProcess
	}
	if self.settings.SenderSessionCount <= self.senderCounts[senderPrefix] {
		return nil, mxCapRefusalSender
	}
	if self.settings.SenderAggregateSessionCount <= self.aggregateCounts[aggregatePrefix] {
		return nil, mxCapRefusalSenderAggregate
	}
	self.sessionCount += 1
	self.senderCounts[senderPrefix] += 1
	self.aggregateCounts[aggregatePrefix] += 1
	return &mxCapHold{sender: senderPrefix, aggregate: aggregatePrefix}, mxCapRefusalNone
}

// Counts an admitted session against networkId's caps, or says which refused it and counts nothing. A
// session names one network, so a second call on a hold refuses.
func (self *mxCaps) AdmitNetwork(hold *mxCapHold, networkId sidecar.Id) mxCapRefusal {
	networkSender := mxNetworkSender{networkId: networkId, aggregate: hold.aggregate}

	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if hold.inNetwork || hold.released || self.settings.NetworkSessionCount <= self.networkCounts[networkId] {
		return mxCapRefusalNetwork
	}
	if self.settings.NetworkSenderSessionCount <= self.networkSenderCounts[networkSender] {
		return mxCapRefusalNetworkSender
	}
	self.networkCounts[networkId] += 1
	self.networkSenderCounts[networkSender] += 1
	hold.networkSender = networkSender
	hold.inNetwork = true
	return mxCapRefusalNone
}

// Gives a session's share back, at the end of the session. A second call does nothing, so no path can
// drive a count below what is connected.
func (self *mxCaps) Release(hold *mxCapHold) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if hold.released {
		return
	}
	hold.released = true
	self.sessionCount -= 1
	mxCapDecrement(self.senderCounts, hold.sender)
	mxCapDecrement(self.aggregateCounts, hold.aggregate)
	if hold.inNetwork {
		mxCapDecrement(self.networkCounts, hold.networkSender.networkId)
		mxCapDecrement(self.networkSenderCounts, hold.networkSender)
	}
}

// Takes one from key's count, dropping the entry at zero so a map holds only what is connected.
func mxCapDecrement[K comparable](counts map[K]int, key K) {
	if counts[key] <= 1 {
		delete(counts, key)
		return
	}
	counts[key] -= 1
}
