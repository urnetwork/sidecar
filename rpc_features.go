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
//     ask (§18.4), never toward anyone else; a sidecar that sends or receives it puts that peer in C19's
//     mode (rpc_marked_pair.go).
//
// Callers decide both through SetFeatures: designation is §7.9's and mode is §18.4's, so SEARCH's tasks
// set them, and the dispatcher only carries them.

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

// The bits this side sends peerId: its features, and bit 1 if asksSearch names the peer or it is the
// first-choice indexer MarkSearchPeer named.
func (self *Subprotocol) featuresToward(peerId connect.Id) uint64 {
	features := uint64(0)
	if set := self.features.Load(); set != nil {
		features = set.features
		if set.asksSearch != nil && set.asksSearch(Id(peerId)) {
			features |= SubprotocolFeatureAsksSearch
		}
	}
	if pair, _ := self.markedPair.Get(); pair.hasPeer && pair.peerId == peerId {
		features |= SubprotocolFeatureAsksSearch
	}
	return features & subprotocolFeaturesImplemented
}

// Whether this side serves remote search now, as its own bit 0 says: what the control class reads.
func (self *Subprotocol) servesSearch() bool {
	set := self.features.Load()
	return set != nil && set.features&SubprotocolFeatureServesSearch != 0
}
