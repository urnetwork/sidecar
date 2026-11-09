//go:build !sidecar_http

// HeadCheck's schedule (§6.4's round row; owner decision 129): when the transport (rpc_headcheck.go)
// runs an exchange, and with whom.
//
//   - The first RPC or stream per peer per HeadCheckInterval: a call this side makes, or a stream it
//     opens (PROTO-M5-02 calls the hook), starts an exchange with that peer in the background, unless
//     one ran within the interval, either way. The side that starts the RPC or stream runs it: one
//     exchange reconciles and witnesses on both sides, so the side that serves the request does not
//     start a second. HeadCheck's own messages and Hello do not count.
//   - Each HeadCheckInterval, and at each start: a round of up to HeadCheckRoundPeerCount admitted
//     sidecars, at random, those sharing a repo with this device first, else any: up to
//     HeadCheckRoundOtherMemberCount of other members (their devices or the agents they sponsor), the
//     rest this member's own devices and agents. A round with fewer candidates picks fewer. Each pick's
//     client comes from its standing Hello or from api's binding, checked against its admission before
//     dialing; its Hello runs first, and a pick that fails it is skipped this round. Each call waits
//     HeadCheckTimeout. The round first runs HeadStopState's round step, which asks claimants api is
//     past due for and retries the highest UNVERIFIED pin.
//   - At once when HeadStopState asks (RequestRound: the revoker's retries), but never closer than
//     HeadCheckTimeout after the last round, so a burst of asks is one round.
//
// The random source is injected (HeadCheckEnv.Random), so a schedule is deterministic in a test. The run
// loop takes the transport's ctx and waits on the dispatcher's clock.

package sidecar

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

// §6.4's round row: of a round's picks, at most this many are other members' devices or agents, the rest
// this member's own. A protocol value beside HeadCheckRoundPeerCount, which is the setting.
const HeadCheckRoundOtherMemberCount = 2

// One sidecar a round may pick, as this device's verified state holds it. TEAM-M2-10's ConfigClient and
// the repo sources it reads say which.
type HeadCheckCandidate struct {
	SidecarId Id
	// Its member is this device's, or it is an agent this device's member sponsors: an own device or
	// agent. Otherwise another member's.
	Own bool
	// It reads a repo this device reads.
	SharesRepo bool
}

// A uniform draw in [0, n) from crypto/rand, n positive.
func cryptoRandomInt(n int) int {
	var drawBytes [8]byte
	limit := ^uint64(0) - ^uint64(0)%uint64(n)
	for {
		if _, err := rand.Read(drawBytes[:]); err != nil {
			panic(err)
		}
		if draw := binary.BigEndian.Uint64(drawBytes[:]); draw < limit {
			return int(draw % uint64(n))
		}
	}
}

// Picks a round's peers from candidates: those not standing, or suspended, left out; up to count in
// all, at most HeadCheckRoundOtherMemberCount of other members, the rest own; within each, those
// sharing a repo first, each group in a random order random draws. selfId is never picked.
func headCheckRoundPicks(candidates []HeadCheckCandidate, peers HeadCheckPeerState, selfId Id, count int, random func(n int) int) []Id {
	return headCheckRoundPicksWith(candidates, peers, selfId, count, random, nil)
}

// headCheckRoundPicks, with firstOwn, an own candidate counted first among the own picks when it stands:
// an app host's first-choice search indexer in the foreground (D-SDK-27), the other picks staying
// random.
func headCheckRoundPicksWith(candidates []HeadCheckCandidate, peers HeadCheckPeerState, selfId Id, count int, random func(n int) int, firstOwn *Id) []Id {
	shuffle := func(ids []Id) {
		for i := len(ids) - 1; 0 < i; i -= 1 {
			j := random(i + 1)
			ids[i], ids[j] = ids[j], ids[i]
		}
	}
	// sharing first, then the rest, each shuffled
	ordered := func(own bool) []Id {
		sharing := []Id{}
		rest := []Id{}
		for _, candidate := range candidates {
			if candidate.Own != own || candidate.SidecarId == selfId {
				continue
			}
			peer := peers.HeadCheckPeer(candidate.SidecarId)
			if !headCheckStanding(peer) || peer.Suspended {
				continue
			}
			if candidate.SharesRepo {
				sharing = append(sharing, candidate.SidecarId)
			} else {
				rest = append(rest, candidate.SidecarId)
			}
		}
		shuffle(sharing)
		shuffle(rest)
		return append(sharing, rest...)
	}
	others := ordered(false)
	own := ordered(true)
	if firstOwn != nil {
		if index := slices.Index(own, *firstOwn); 0 <= index {
			own = append([]Id{*firstOwn}, slices.Delete(own, index, index+1)...)
		}
	}
	picks := []Id{}
	for _, sidecarId := range others {
		if HeadCheckRoundOtherMemberCount <= len(picks) || count <= len(picks) {
			break
		}
		picks = append(picks, sidecarId)
	}
	for _, sidecarId := range own {
		if count <= len(picks) {
			break
		}
		picks = append(picks, sidecarId)
	}
	return picks
}

// Asks the run loop for a round now, coalescing with one already asked. Never blocks: HeadStopState
// calls it as RequestRound.
func (self *headCheckTransport) requestRound() {
	select {
	case self.roundRequests <- struct{}{}:
	default:
	}
}

// Rounds at each start, each HeadCheckInterval and at each request, until the transport ends. A
// request inside HeadCheckTimeout of the last round waits out the rest of it, so the loop never spins.
func (self *headCheckTransport) run() {
	defer self.workers.Done()
	lastRound := time.Time{}
	for {
		if !lastRound.IsZero() {
			if gap := self.settings.HeadCheckTimeout - self.clock.Now().Sub(lastRound); 0 < gap {
				select {
				case <-self.clock.After(gap):
				case <-self.ctx.Done():
					return
				}
			}
		}
		lastRound = self.clock.Now()
		self.round(self.ctx)
		// armed before the round is counted, so whoever waits on roundCount finds the next round's timer set
		interval := self.clock.After(self.settings.HeadCheckInterval)
		self.roundCount.Update(func(count uint64) uint64 {
			return count + 1
		})
		select {
		case <-interval:
		case <-self.roundRequests:
		case <-self.ctx.Done():
			return
		}
	}
}

// One round: HeadStopState's round step and its acts, then an exchange with each pick, at once.
func (self *headCheckTransport) round(ctx context.Context) {
	testHookBarrier("rpc.head_check_round.before", self.stop.env.SidecarId.String())
	defer testHookBarrier("rpc.head_check_round.after", self.stop.env.SidecarId.String())
	step := self.stop.round()
	self.runActs(ctx, step.acts)
	self.prune()
	// in the foreground, the first-choice search indexer counts among the own picks (D-SDK-27)
	var firstOwn *Id
	if peerId, ok := self.subprotocol.foregroundSearchPeer(); ok {
		if peer, ok := self.subprotocol.PeerIdentity(Id(peerId)); ok {
			firstOwn = &peer.SidecarId
		}
	}
	picks := headCheckRoundPicksWith(self.env.Candidates(), self.sources.Peers, self.stop.env.SidecarId, self.settings.HeadCheckRoundPeerCount, self.random, firstOwn)
	var wait sync.WaitGroup
	for _, sidecarId := range picks {
		wait.Add(1)
		go func() {
			defer wait.Done()
			clientId, err := self.resolve(ctx, sidecarId)
			if err != nil {
				if self.subprotocol.log.V(1).Enabled() {
					self.subprotocol.log.Infof("[headcheck]round skips %s: %s\n", sidecarId, err)
				}
				return
			}
			if _, err := self.exchange(ctx, clientId, true); err != nil && self.subprotocol.log.V(1).Enabled() {
				self.subprotocol.log.Infof("[headcheck]round with %s: %s\n", sidecarId, err)
			}
		}()
	}
	wait.Wait()
}

// Drops what is kept of peers past an interval: rotations and exchange times of peers no exchange has
// touched since, so the maps hold the peers this device talks to and no more.
func (self *headCheckTransport) prune() {
	cutoff := self.clock.Now().Add(-self.settings.HeadCheckInterval)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for sidecarId, exchangeTime := range self.peerExchangeTimes {
		if exchangeTime.Before(cutoff) {
			delete(self.peerExchangeTimes, sidecarId)
			delete(self.peerRotations, sidecarId)
		}
	}
}

// Whether a message type is one whose exchange starts the hourly HeadCheck: an application RPC, not §6's
// own Hello, Ping, Cancel and HeadCheck exchanges.
func headCheckCountsAsExchange(messageType protocol.MessageType) bool {
	switch messageType {
	case protocol.MessageType_HELLO, protocol.MessageType_HELLO_RESULT, protocol.MessageType_PING,
		protocol.MessageType_PONG, protocol.MessageType_CANCEL, protocol.MessageType_ERROR,
		protocol.MessageType_HEAD_CHECK, protocol.MessageType_HEAD_CHECK_RESULT,
		protocol.MessageType_HEAD_CHECK_PROOF_REQUEST, protocol.MessageType_HEAD_CHECK_PROOF:
		return false
	}
	return true
}

// The first-exchange hook: an RPC or stream this side starts with the peer behind clientId, of
// messageType, starts an exchange in the background if none ran with that peer within
// HeadCheckInterval. Returns at once and never blocks, so Call and PROTO-M5-02's stream opens call it
// on their own paths.
func (self *Subprotocol) headCheckOnExchange(clientId connect.Id, messageType protocol.MessageType) {
	transport := self.headCheck.Load()
	if transport == nil || !headCheckCountsAsExchange(messageType) {
		return
	}
	peer, ok := self.PeerIdentity(Id(clientId))
	if !ok {
		return
	}
	now := self.clock.Now()
	due := func() bool {
		transport.stateLock.Lock()
		defer transport.stateLock.Unlock()
		if transport.peerExchangesRunning[peer.SidecarId] {
			return false
		}
		exchangeTime, exchanged := transport.peerExchangeTimes[peer.SidecarId]
		if exchanged && now.Sub(exchangeTime) < self.settings.HeadCheckInterval {
			return false
		}
		// counted now, so a burst of calls starts one exchange
		transport.peerExchangeTimes[peer.SidecarId] = now
		return true
	}()
	if !due {
		return
	}
	transport.goWorker(func() {
		if _, err := transport.exchange(transport.ctx, clientId, true); err != nil && self.log.V(1).Enabled() {
			self.log.Infof("[headcheck]first exchange with %s: %s\n", peer.SidecarId, err)
		}
	})
}
