// A bridge to private fixtures for mxedgeservice_test, which is a separate package because sidecartest
// imports this one for FakeMxEdgeStore, so a test of this package importing sidecartest would be a
// cycle (connect/CODESTYLE.md:37).

package mxedgeservice

import (
	"net"
	"net/netip"
	"time"

	"github.com/urnetwork/sidecar"
)

type (
	Caps             = mxCaps
	CapHold          = mxCapHold
	CapRefusal       = mxCapRefusal
	ClosedHandshakes = mxClosedHandshakes
)

const (
	CapRefusalNone            = mxCapRefusalNone
	CapRefusalProcess         = mxCapRefusalProcess
	CapRefusalSender          = mxCapRefusalSender
	CapRefusalSenderAggregate = mxCapRefusalSenderAggregate
	CapRefusalNetwork         = mxCapRefusalNetwork
	CapRefusalNetworkSender   = mxCapRefusalNetworkSender

	ClosedHandshakeSecretMinByteCount = mxClosedHandshakeSecretMinByteCount
	ReadyProbeKey                     = mxReadyProbeKey
)

// Caps on settings' numbers.
func NewCaps(settings *MxEdgeSettings) *Caps {
	return newMxCaps(settings)
}

// How many entries every map holds, and the sessions counted, so a test can see nothing lingers.
func (self *mxCaps) State() (sessionCount int, entryCount int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.sessionCount, len(self.senderCounts) + len(self.aggregateCounts) + len(self.networkCounts) + len(self.networkSenderCounts)
}

// The prefixes sender counts by.
func SenderPrefixes(sender netip.Addr) (netip.Prefix, netip.Prefix) {
	return mxSenderPrefixes(sender)
}

// The memory on one Redis.
func NewClosedHandshakes(redis sidecar.Redis, secret []byte, ttl time.Duration, clock MxEdgeClock) *ClosedHandshakes {
	return newMxClosedHandshakes(redis, secret, ttl, clock)
}

// The key for sender's /24 or /48 under day's k.
func (self *mxClosedHandshakes) Key(sender netip.Addr, day time.Time) string {
	_, aggregate := mxSenderPrefixes(sender)
	return self.key(aggregate, day)
}

// The sender a conn's peer address gives.
func SenderAddr(addr net.Addr) (netip.Addr, bool) {
	return mxSenderAddr(addr)
}

// Ends conn with a reset where it can.
func ResetConnection(conn net.Conn) {
	mxResetConnection(conn)
}

// Stands in for MAIL-M7-20's listings. Call it before any session starts.
func (self *MxEdgeService) SetBannerRefused(bannerRefused func(sender netip.Addr) bool) {
	self.bannerRefused = bannerRefused
}

// Returns once the last probe has found this, with no wait past the moment it does.
func (self *MxEdgeService) AwaitStoresReachable(want bool) {
	for {
		reachable, update := self.storesReachable.Get()
		if reachable == want {
			return
		}
		<-update
	}
}

// Returns once this many sessions are running.
func (self *MxEdgeService) AwaitSessionCount(want int) {
	for {
		count, update := self.sessionCount.Get()
		if count == want {
			return
		}
		<-update
	}
}
