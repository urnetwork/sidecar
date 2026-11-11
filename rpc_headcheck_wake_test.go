//go:build !sidecar_http && !js

package sidecar

// §6.4's Bound from M8 (PROTO-M8-02): a scheduled HeadCheck that an own app host leaves unanswered past
// HeadCheckTimeout summons it, once a WakeInterval; a desktop, another member's device and a peer that answered
// with an error are not summoned; and a summoned host that answers counts as a witness (FS-85's and FS-100's wakes
// rest on this). On the rpc pair's fake clock, with the summons recorded where POST /sidecar/wake would go.

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// Re-attaches side's HeadCheck with a summons that records each ask and an app host test, and the world's
// identities.
func testAttachHeadCheckWake(t *testing.T, world *testHeadCheckWorld, side *testHeadCheckSide, appHost func(sidecarId Id) bool) chan Id {
	t.Helper()
	side.detach()
	asks := make(chan Id, 16)
	detach, err := side.subprotocol.AttachHeadCheck(&HeadCheckEnv{
		Stop: side.stop,
		Candidates: func() []HeadCheckCandidate {
			side.stateLock.Lock()
			defer side.stateLock.Unlock()
			return slices.Clone(side.candidates)
		},
		Identity: func(ctx context.Context, sidecarId Id) (*SidecarIdentityRecord, error) {
			for _, other := range world.sides {
				if other.sidecarId == sidecarId {
					return &SidecarIdentityRecord{SidecarId: sidecarId, Binding: other.binding}, nil
				}
			}
			return nil, errors.New("no such sidecar")
		},
		Wake: func(ctx context.Context, sidecarId Id) error {
			asks <- sidecarId
			return nil
		},
		AppHost: appHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(detach)
	side.detach = detach
	// the round at start, with no candidates yet
	side.awaitRounds(1)
	return asks
}

// Waits until the side's transport has finished count summonses, either way.
func testAwaitWakes(t *testing.T, side *testHeadCheckSide, count uint64) {
	t.Helper()
	transport := side.subprotocol.headCheck.Load()
	for {
		wakeCount, notify := transport.wakeCount.Get()
		if count <= wakeCount {
			return
		}
		select {
		case <-notify:
		case <-time.After(testSubprotocolAwaitTimeout):
			t.Fatalf("%d summonses of %d", wakeCount, count)
		}
	}
}

// The decision alone: a silent own app host is summoned, at most once a WakeInterval; a desktop, another member's
// device and a peer that answered with an error are not.
func TestHeadCheckWakeSummonsOnlyASilentOwnAppHost(t *testing.T) {
	world := newTestHeadCheckWorldOf(t, 10)
	a := world.add(testMainChain, 10, nil)
	phone := world.add(testMainChain, 10, nil)
	desktop := world.add(testMainChain, 10, nil)
	asks := testAttachHeadCheckWake(t, world, a, func(sidecarId Id) bool { return sidecarId == phone.sidecarId })
	transport := a.subprotocol.headCheck.Load()
	silent := &SubprotocolError{Code: protocol.ErrorCode_ERR_DEADLINE_EXCEEDED}

	transport.wakeIfSilent(desktop.sidecarId, true, silent)
	transport.wakeIfSilent(phone.sidecarId, false, silent)
	transport.wakeIfSilent(phone.sidecarId, true, &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAVAILABLE})
	transport.wakeIfSilent(phone.sidecarId, true, errors.New("not a protocol error"))
	transport.wakeIfSilent(phone.sidecarId, true, silent)
	testAwaitWakes(t, a, 1)
	if asked := testAwait(t, asks, "a summons"); asked != phone.sidecarId {
		t.Fatalf("summoned %s", asked)
	}
	// within the interval: held
	a.clock.Advance(a.settings.WakeInterval - time.Second)
	transport.wakeIfSilent(phone.sidecarId, true, silent)
	if stats := transport.wakeStats(); stats.WakeCount != 1 || stats.WakeHeldCount != 1 {
		t.Fatalf("stats %+v", stats)
	}
	// past it: summoned again
	a.clock.Advance(time.Second)
	transport.wakeIfSilent(phone.sidecarId, true, silent)
	testAwaitWakes(t, a, 2)
	if asked := testAwait(t, asks, "the second summons"); asked != phone.sidecarId {
		t.Fatalf("summoned %s", asked)
	}
	select {
	case asked := <-asks:
		t.Fatalf("summoned %s too", asked)
	default:
	}
}

// Through a round: the own app host's HeadCheck is lost, the round's call waits out HeadCheckTimeout and the host is
// summoned; once it answers, its exchange is a witness.
func TestHeadCheckRoundSummonsASilentAppHostThatThenWitnesses(t *testing.T) {
	world := newTestHeadCheckWorldOf(t, 10)
	a := world.add(testMainChain, 10, nil)
	phone := world.add(testMainChain, 10, nil)
	asks := testAttachHeadCheckWake(t, world, a, func(sidecarId Id) bool { return sidecarId == phone.sidecarId })
	if _, err := a.subprotocol.HeadCheckNow(t.Context(), Id(phone.clientId)); err != nil {
		t.Fatal(err)
	}
	witnessedBefore := a.stop.WitnessedAt()

	// the phone's app is suspended: what reaches it is lost
	// each lost HeadCheck tells the test how many waits the clock held as it was lost, so the test knows when the
	// call's own wait is set
	dropped := make(chan int, 4)
	a.setDeliver(func(from *testRpcSide, to *testRpcSide, envelope *protocol.Envelope) *protocol.Envelope {
		if from == a.testRpcSide && to == phone.testRpcSide && protocol.MessageType(envelope.Type) == protocol.MessageType_HEAD_CHECK {
			waitCount, _ := a.clock.waitCount.Get()
			dropped <- waitCount
			return nil
		}
		return envelope
	})
	func() {
		a.stateLock.Lock()
		defer a.stateLock.Unlock()
		a.candidates = []HeadCheckCandidate{{SidecarId: phone.sidecarId, Own: true}}
	}()
	waitCount, _ := a.clock.waitCount.Get()
	a.subprotocol.headCheck.Load().requestRound()
	// the request waits out HeadCheckTimeout from the last round, then the round's call waits it out again
	a.clock.awaitWaitCount(waitCount + 1)
	a.clock.Advance(a.settings.HeadCheckTimeout)
	droppedWaitCount := testAwait(t, dropped, "the lost HeadCheck")
	a.clock.awaitWaitCount(droppedWaitCount + 1)
	a.clock.Advance(a.settings.HeadCheckTimeout)
	testAwaitWakes(t, a, 1)
	if asked := testAwait(t, asks, "the summons"); asked != phone.sidecarId {
		t.Fatalf("summoned %s", asked)
	}

	// woken, it answers, and the exchange counts as a witness
	a.setDeliver(nil)
	a.clock.Advance(time.Second)
	witnessed, err := a.subprotocol.HeadCheckNow(t.Context(), Id(phone.clientId))
	if err != nil || !witnessed {
		t.Fatalf("the woken host: witnessed %t, %v", witnessed, err)
	}
	if !witnessedBefore.Before(a.stop.WitnessedAt()) {
		t.Errorf("witnessed_at %s, before the summons %s", a.stop.WitnessedAt(), witnessedBefore)
	}
}
