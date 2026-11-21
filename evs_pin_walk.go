//go:build !ios_extension

// The readers that walk a ref's statements themselves, not through a head read's VerifyHead (export and its
// verified history, the desktop sync engine, record streams, the streams read, the directory's cards and stream logs,
// mirrors and the config head reader), held to the pin as their read asked at it and raised by the pin store's
// judgment (evs_pin_store.go's header), as a head read is (the e2e-client-origins bug's other readers):
//
//	ask      before the request whose answer it judges, the reader takes the ref's pin and count of reseeds
//	         (EvsPinStore.ask), a mirror every ref of its repo at once before its listing (askRepo), and notes its
//	         read in flight until its raise (beginRead), so another read's raise meanwhile keeps the chains that place
//	         its head
//	head     a head served below the pin asked at, or at its version on another chain, is a fork, alarmed with both
//	         RefHeads (checkAsked); a pin another call of the client raised since is never what the head is held to
//	walk     the head raised carries the reader's walk: its start, C_0 or the reader's own state, and C at every
//	         version after it, as statements or, for a walk read a page at a time, as chains alone kept from the
//	         asked pin's version on (evsWalkTrail), since below it nothing the store holds lies that the asked pin
//	         does not place
//	raise    Pin judges the head against the pin as it then stands (EvsPinStore.raiseRead): above, raised; passed by
//	         another raise on its history, stands as read; a walk that crosses a chain the store holds with another
//	         chain, a fork; where nothing places a head the pin stands past, ErrEvsReadStale, which the reader reads
//	         again, fresh, at most EvsSettings.ReadStaleRetryCount times
//	page     a walk that stops short of the head, a cards or stream log page, is a page: it raises the pin to its end
//	         where that stands above it, and is judged but raises nothing below it
//
// On every leg but the ios_extension legs, whose config head reader asks and raises through the pin store alone.
// Safe for concurrent use but for an evsWalkTrail, which one walk owns.

package sidecar

import (
	"crypto/sha256"
)

// The chains a walk read a page at a time passed, kept from the version of the pin its read asked at on, or from the
// walk's start where that is above it, 32 bytes a version and nothing of a statement: what the walk's raise is judged
// by. Below the asked pin the store holds nothing the asked pin does not place, a walk reaching it there with the
// asked chain lying on the pinned history all the way down. Not safe for concurrent use.
type evsWalkTrail struct {
	// the asked pin's version, 0 for none
	floor uint64
	// the version the chains follow and C there, once the walk reached the floor
	started     bool
	fromVersion uint64
	fromChain   [sha256.Size]byte
	chains      [][sha256.Size]byte
}

// A trail for a walk of a read that asked at ask.
func newEvsWalkTrail(ask *evsPinAsk) *evsWalkTrail {
	trail := &evsWalkTrail{}
	if ask != nil && ask.pin != nil {
		trail.floor = ask.pin.Version
	}
	return trail
}

// Notes where the walk starts: version, and C there.
func (self *evsWalkTrail) start(version uint64, chain [sha256.Size]byte) {
	if self.started || version < self.floor {
		return
	}
	self.started, self.fromVersion, self.fromChain = true, version, chain
}

// Notes each statement the walk verified, in order, after those noted before.
func (self *evsWalkTrail) add(statements []*EvsVerifiedStatement) {
	for _, statement := range statements {
		switch {
		case self.started:
			self.chains = append(self.chains, statement.Chain)
		case statement.Version == self.floor:
			self.started, self.fromVersion, self.fromChain = true, statement.Version, statement.Chain
		}
	}
}

// The head a read walked, as its raise judges it: a copy of head with the trail as its walk, from the reader's own
// start, head's own fields left as they are. A trail that never reached the asked pin's version judges the head
// alone.
func (self *evsWalkTrail) head(head *EvsVerifiedHead) *EvsVerifiedHead {
	raised := *head
	raised.Statements, raised.walkChains, raised.ownStart = nil, nil, true
	if self.started {
		raised.FromVersion, raised.fromChain, raised.walkChains = self.fromVersion, self.fromChain, self.chains
	} else {
		raised.FromVersion, raised.fromChain = head.Version, head.Chain
	}
	return &raised
}

// The pin rule (I-16) at the pin a read asked at: a head below it, or at its version with another chain, is a fork,
// alarmed with head_alarm and both RefHeads, unless a verified reseed lowered the pin to exactly that head first. A
// pin another call of the client raised since the read asked is never what the head is held to; the raise judges it
// against that (EvsPinStore.raiseRead).
func (self *EvsVerifier) checkAsked(repoId Id, refId Id, ask *evsPinAsk, version uint64, chain [sha256.Size]byte) error {
	pin := ask.pin
	if pin == nil || (pin.Version < version) || (pin.Version == version && pin.Chain == chain) {
		return nil
	}
	self.alarmFork(repoId, refId, pin, version, chain)
	return ErrEvsHeadForked
}

// Every ref's pin of one repo and its count of reseeds, as one request that answers them all asks at them: a
// listing's, whose heads a mirror judges each against its own ref's.
type evsPinRepoAsk struct {
	refIdPins    map[Id]*EvsPin
	refIdReseeds map[Id]uint64
}

// The repo's pins and counts of reseeds as a request that answers every ref of it asks at them.
func (self *EvsPinStore) askRepo(repoId Id) (*evsPinRepoAsk, error) {
	if err := self.load(); err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	asks := &evsPinRepoAsk{refIdPins: map[Id]*EvsPin{}, refIdReseeds: map[Id]uint64{}}
	if state := self.repoIdRepos[repoId]; state != nil {
		for refId, pin := range state.refIdPins {
			asks.refIdPins[refId] = pin.clone()
		}
	}
	for key, count := range self.refReseedCounts {
		if key.repoId == repoId {
			asks.refIdReseeds[key.refId] = count
		}
	}
	return asks, nil
}

// One ref's ask, as the request asked at it.
func (self *evsPinRepoAsk) of(refId Id) *evsPinAsk {
	ask := &evsPinAsk{reseeds: self.refIdReseeds[refId]}
	if pin := self.refIdPins[refId]; pin != nil {
		ask.pin = pin.clone()
	}
	return ask
}
