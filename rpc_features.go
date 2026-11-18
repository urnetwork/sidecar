//go:build !sidecar_http

// Hello's feature bits (§6.11's registry; D-PROTO-21, R-PROTO-12): what a sidecar tells a peer it
// implements, in Hello and HelloResult alike. A sender sets only bits it implements; a receiver ignores
// bits it does not know and grants or refuses nothing by a peer's bit, each side deciding by its own
// state (§6.4's floor: Required, the Signed rules, the identity check and the chunk limits are never
// gated by one). A bit is permanent once released.
//
//   - bit 0, serves remote search: set by a sidecar that serves §11.14's remote search, a designated
//     search indexer (§7.9). On a control contract this side accepts SEARCH only while it sets it
//     (rpc_contract_class.go): its own bit, never the asker's.
//   - bit 1, asks remote search: set by an app host toward each indexer its remote-search mode lets it
//     ask (§18.4), never toward anyone else. It marks nothing: the pair's contracts are accounted like
//     any peer's (§6.10; owner decision 609).
//
// Callers decide both through SetFeatures: designation is §7.9's and mode is §18.4's, so SEARCH's tasks
// set them, and the dispatcher only carries them.
//
// Beside bit 1, an app host's asking role tells the dispatcher two things HeadCheck reads: whether the
// host is in the foreground (SetForeground) and its first-choice own search indexer (SetSearchIndexer),
// which the hourly round counts among its own picks there, the others staying random (§6.4's round row,
// D-SDK-27). Neither keeps a pair warm or sends anything (owner decision 609).

package sidecar

import (
	"errors"
	"fmt"

	"github.com/urnetwork/connect"
)

// Hello.features' bits (§6.11). Protocol values, permanent once released.
const (
	// Bit 0: this sidecar serves §11.14's remote search.
	SubprotocolFeatureServesSearch uint64 = 1 << 0
	// Bit 1: this sidecar asks the peer it sends this to for remote search.
	SubprotocolFeatureAsksSearch uint64 = 1 << 1
	// Every bit this release implements, the only bits it may send.
	subprotocolFeaturesImplemented = SubprotocolFeatureServesSearch | SubprotocolFeatureAsksSearch
)

var (
	// A bit this release does not implement, or bit 1 asked toward every peer.
	errSubprotocolFeatures = errors.New("subprotocol features: a bit this side may not send so")
)

// What this side sends: bits toward every peer, and the function naming the peers bit 1 goes to.
type subprotocolFeatureSet struct {
	features   uint64
	asksSearch func(clientId Id) bool
}

// Sets the bits this side's Hello and HelloResult carry from now on: features toward every peer, which
// may hold only SubprotocolFeatureServesSearch, set while this sidecar serves remote search; and
// SubprotocolFeatureAsksSearch toward each peer asksSearch names, the indexers the host's remote-search
// mode lets it ask, nil naming none. A Hello that stands keeps the bits it was verified with until the
// next one. Refuses a bit this release does not implement, and bit 1 in features.
func (self *Subprotocol) SetFeatures(features uint64, asksSearch func(clientId Id) bool) error {
	if features&^subprotocolFeaturesImplemented != 0 || features&SubprotocolFeatureAsksSearch != 0 {
		return fmt.Errorf("%w: %#x", errSubprotocolFeatures, features)
	}
	self.features.Store(&subprotocolFeatureSet{features: features, asksSearch: asksSearch})
	return nil
}

// The bits this side sends peerId: its features, and bit 1 if asksSearch names the peer.
func (self *Subprotocol) featuresToward(peerId connect.Id) uint64 {
	features := uint64(0)
	if set := self.features.Load(); set != nil {
		features = set.features
		if set.asksSearch != nil && set.asksSearch(Id(peerId)) {
			features |= SubprotocolFeatureAsksSearch
		}
	}
	return features & subprotocolFeaturesImplemented
}

// Whether this side serves remote search now, as its own bit 0 says: what the control class reads.
func (self *Subprotocol) servesSearch() bool {
	set := self.features.Load()
	return set != nil && set.features&SubprotocolFeatureServesSearch != 0
}

// Tells the dispatcher whether its host is in the foreground (plan-SEARCH-foreground-signal): only then
// does HeadCheck's round count the search indexer SetSearchIndexer names. A host that never calls it is
// in the background.
func (self *Subprotocol) SetForeground(foreground bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.searchForeground = foreground
}

// Names the app host's first-choice own search indexer by its sidecar_id (§11.14's order row), which
// HeadCheck's round counts among its own picks while the host is in the foreground (D-SDK-27), in place
// of the one named before; the zero Id names none. SEARCH names it at each foreground and as its mode,
// its notices' answers and the config's indexers move. It opens no session and sends nothing.
func (self *Subprotocol) SetSearchIndexer(sidecarId Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.searchIndexerId = sidecarId
}

// The search indexer SetSearchIndexer named, while the host is in the foreground: what HeadCheck's round
// counts among its own picks. False in the background or with none named.
func (self *Subprotocol) foregroundSearchIndexer() (Id, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !self.searchForeground || self.searchIndexerId == (Id{}) {
		return Id{}, false
	}
	return self.searchIndexerId, true
}
