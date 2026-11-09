// HeadCheck's ref source (§6.4, §11.8's witness row; owner decision 129, D-TRUST-10): the ref pins an EvsClient holds,
// which §6.4's reconcile engine compares with an admitted peer's, and the forward read that settles a difference.
//
// RefHeads answers from memory, never blocking: the pins of repos the peer reads in this device's newest verified
// state, in a stable order, at most 16 a call, rotating so every pin is compared in turn (HeadCheckMaxListCount).
// CatchUpRef is the act: it reads the ref's statements from this device's pin up to the peer's (GET .../log), checks
// each as a head read does and recomputes C forward (§11.9), and pins the peer's head only if C reaches it. A chain
// that does not extend this pin, or misses the peer's C at its version, is a fork, alarmed and refused; a store that
// did not serve proves nothing.
//
// On every leg. Safe for concurrent use.

package sidecar

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"

	"github.com/urnetwork/sidecar/protocol"
)

// RefHeads' place in its rotation, per peer.
type evsWitnessCursors struct {
	peerIdOffsets map[Id]int
}

var _ HeadCheckRefSource = (*EvsClient)(nil)

// The ref pins this device holds for repos the peer reads, at most HeadCheckMaxListCount, rotating. Memory only:
// before the pins have loaded, or with no verified config state, none.
func (self *EvsClient) RefHeads(peerSidecarId Id) []*protocol.RefHead {
	pins := self.pins.loadedPins()
	if len(pins) == 0 || self.args.Config == nil {
		return nil
	}
	state := self.args.Config()
	if state == nil {
		return nil
	}
	readable := map[Id]bool{}
	shared := []*EvsPin{}
	for _, pin := range pins {
		reads, ok := readable[pin.RepoId]
		if !ok {
			reads = slices.Contains(state.RepoReaders(pin.RepoId), peerSidecarId)
			readable[pin.RepoId] = reads
		}
		if reads {
			shared = append(shared, pin)
		}
	}
	if len(shared) == 0 {
		return nil
	}
	offset := func() int {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.witnessCursors.peerIdOffsets == nil {
			self.witnessCursors.peerIdOffsets = map[Id]int{}
		}
		offset := self.witnessCursors.peerIdOffsets[peerSidecarId] % len(shared)
		self.witnessCursors.peerIdOffsets[peerSidecarId] = offset + min(len(shared), HeadCheckMaxListCount)
		return offset
	}()
	heads := []*protocol.RefHead{}
	for i := 0; i < min(len(shared), HeadCheckMaxListCount); i += 1 {
		pin := shared[(offset+i)%len(shared)]
		heads = append(heads, &protocol.RefHead{
			RepoId:  pin.RepoId.Bytes(),
			RefId:   pin.RefId.Bytes(),
			Version: pin.Version,
			Chain:   pin.Chain[:],
		})
	}
	return heads
}

// This device's pin for one ref, with its repo's group, false when it holds none. Memory only.
func (self *EvsClient) RefHead(repoId Id, refId Id) (HeadCheckRef, bool) {
	for _, pin := range self.pins.loadedPins() {
		if pin.RepoId == repoId && pin.RefId == refId {
			return HeadCheckRef{
				Head:    &protocol.RefHead{RepoId: repoId.Bytes(), RefId: refId.Bytes(), Version: pin.Version, Chain: pin.Chain[:]},
				GroupId: pin.GroupId,
			}, true
		}
	}
	return HeadCheckRef{}, false
}

// Reads the ref's statements from this device's pin up to through, checking each and recomputing C, and pins
// through's head once C reaches it (§11.9). Forked when the chain does not reach through's C, or through is below the
// pin with another chain at the pin's version; Unserved when evs did not serve the statements.
func (self *EvsClient) CatchUpRef(ctx context.Context, through *protocol.RefHead) (HeadCheckCatchUp, error) {
	repoId, err := IdFromBytes(through.GetRepoId())
	if err != nil {
		return HeadCheckCatchUpUnserved, fmt.Errorf("%w: a ref head's repo", ErrEvsReplyInvalid)
	}
	refId, err := IdFromBytes(through.GetRefId())
	if err != nil {
		return HeadCheckCatchUpUnserved, fmt.Errorf("%w: a ref head's ref", ErrEvsReplyInvalid)
	}
	throughChain, err := EvsChainFromBytes(through.GetChain())
	if err != nil {
		return HeadCheckCatchUpUnserved, err
	}
	pin, ok, err := self.pins.Pin(repoId, refId)
	if err != nil {
		return HeadCheckCatchUpUnserved, err
	}
	fromVersion := uint64(0)
	fromChain := EvsChainStart(repoId, refId)
	if ok {
		fromVersion, fromChain = pin.Version, pin.Chain
	}
	switch {
	case through.GetVersion() == fromVersion && ok:
		if throughChain != fromChain {
			self.verifier.alarmFork(repoId, refId, pin, through.GetVersion(), throughChain)
			return HeadCheckCatchUpForked, ErrEvsHeadForked
		}
		return HeadCheckCaughtUp, nil
	case through.GetVersion() < fromVersion:
		// the peer is behind: its version is below this pin, which this device holds no chain for
		return HeadCheckCatchUpUnserved, nil
	}
	statements, err := self.readLog(ctx, repoId, refId, fromVersion+1, through.GetVersion())
	if err != nil {
		return HeadCheckCatchUpUnserved, err
	}
	walked, err := self.verifier.walk(repoId, refId, fromVersion, fromChain, statements, through.GetVersion())
	if err != nil {
		if errors.Is(err, ErrEvsChainBroken) || errors.Is(err, ErrEvsStatementRefused) {
			return HeadCheckCatchUpForked, err
		}
		return HeadCheckCatchUpUnserved, err
	}
	reached := fromChain
	if 0 < len(walked) {
		reached = walked[len(walked)-1].Chain
	}
	if reached != throughChain {
		held := pin
		if held == nil {
			held = &EvsPin{RepoId: repoId, RefId: refId, Chain: fromChain}
		}
		self.verifier.alarmFork(repoId, refId, held, through.GetVersion(), throughChain)
		return HeadCheckCatchUpForked, ErrEvsHeadForked
	}
	raised := &EvsPin{RepoId: repoId, RefId: refId, Version: through.GetVersion(), Chain: [sha256.Size]byte(reached), PinnedAt: self.clock.Now()}
	if err := self.pins.Raise(raised); err != nil {
		return HeadCheckCatchUpUnserved, err
	}
	return HeadCheckCaughtUp, nil
}

// The ref's statements from version since through version through, paging GET .../log.
func (self *EvsClient) readLog(ctx context.Context, repoId Id, refId Id, since uint64, through uint64) ([]*protocol.EvsReadStatement, error) {
	statements := []*protocol.EvsReadStatement{}
	for since <= through {
		reply := &protocol.EvsLogReply{}
		err := self.http.callMessage(ctx, &evsCall{
			route:  "GET /evs/v1/repos/{repo_id}/log",
			method: http.MethodGet,
			path:   "/evs/v1/repos/" + evsUrlId(repoId) + "/log?ref=" + evsUrlId(refId) + "&since=" + strconv.FormatUint(since, 10),
			repoId: repoId,
			role:   evsScopeRead,
			retry:  true,
		}, reply)
		if err != nil {
			return nil, err
		}
		for _, statement := range reply.GetStatements() {
			if through < statement.GetVersion() {
				return statements, nil
			}
			statements = append(statements, statement)
		}
		next := reply.GetNextVersion()
		if next == 0 || len(reply.GetStatements()) == 0 {
			return statements, nil
		}
		if next <= since {
			return nil, fmt.Errorf("%w: a log page that does not move forward", ErrEvsReplyInvalid)
		}
		since = next
	}
	return statements, nil
}
