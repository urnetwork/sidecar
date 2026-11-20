// A slot takeover's hold read held to its bound at the DELETE (owner decision 629; DESIGN-DETAILS 14.2.4's fifth
// condition), on T2's fakes and the fake clock: the cover a takeover reads before its settle wait binds its DELETE
// only while that read is younger than the bound, so a hold acknowledged during the wait stops the DELETE once the
// wait aged the read past it, a quick takeover deletes on the cached read with no read of hold/ added, and a reread
// that comes back past the bound, or fails, answers 503 with nothing deleted.

package evsservice

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A store whose first cluster counts the LISTs of hold/ a HoldCache makes, its reads of the holds, and runs onList at
// each first: a read that stalls, the hook moving the clock on, or one that fails, the hook's error.
type takeoverHoldBlobs struct {
	sidecar.BlobStore
	stateLock sync.Mutex
	listCount int
	onList    func(count int) error
}

func (self *takeoverHoldBlobs) FirstCluster() (sidecar.BlobCluster, error) {
	cluster, err := self.BlobStore.FirstCluster()
	if err != nil {
		return nil, err
	}
	return &takeoverHoldCluster{BlobCluster: cluster, blobs: self}, nil
}

// How many LISTs of hold/ the store has taken.
func (self *takeoverHoldBlobs) reads() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.listCount
}

// Sets the hook every later LIST of hold/ runs first, given its count.
func (self *takeoverHoldBlobs) setOnList(onList func(count int) error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.onList = onList
}

type takeoverHoldCluster struct {
	sidecar.BlobCluster
	blobs *takeoverHoldBlobs
}

func (self *takeoverHoldCluster) List(ctx context.Context, keyPrefix string, startAfter string, limit int) ([]*sidecar.BlobInfo, bool, error) {
	if strings.HasPrefix(keyPrefix, "hold/") {
		count, onList := func() (int, func(count int) error) {
			self.blobs.stateLock.Lock()
			defer self.blobs.stateLock.Unlock()
			self.blobs.listCount += 1
			return self.blobs.listCount, self.blobs.onList
		}()
		if onList != nil {
			if err := onList(count); err != nil {
				return nil, false, err
			}
		}
	}
	return self.BlobCluster.List(ctx, keyPrefix, startAfter, limit)
}

// newTakeoverCase's ground, unsettled, with the engine's hold/ reads through a store that counts them: the engine's
// cache reads hold/ readAhead before o's object is stored, as another request's read would leave it, so the cover the
// retoken judges on first is readAhead old as it arrives and the settle wait ages it by SlotSettleAge more. The
// engine's cache is set before anything runs on it; only a takeover reads it.
func newHoldTakeoverCase(t *testing.T, label string, readAhead time.Duration) (*takeoverCase, *takeoverHoldBlobs) {
	fixture := newPushFixture(t, nil)
	blobs := &takeoverHoldBlobs{BlobStore: fixture.host.Blobs}
	fixture.engine.holds = NewHoldCache(blobs, fixture.clock, nil)
	commitment := fixture.crossRemove(false)
	fixture.awaitStepEights()
	if _, err := fixture.engine.holds.Covering(fixture.ctx, fixture.check.networkId, fixture.check.repoId); err != nil {
		t.Fatal(err)
	}
	fixture.clock.Advance(readAhead)
	slotId, _, slotBody := checkTestSlot(t, "takeover "+label)
	refused := fixture.planAtTwo(commitment)
	fixture.createWithSlot(refused, checkTestPath("s"), slotId, slotBody)
	_, refusedOrigin := fixture.bodyAndOrigin(refused)
	fixture.plantSlot(slotId, slotBody, refusedOrigin)
	fixture.cutOverToEpochTwo(commitment, pathEpochTestMoveAt(2, []uint64{1}, "a"))
	takeover := &takeoverCase{fixture: fixture, commitment: commitment, slotId: slotId, slotBody: slotBody, refused: refusedOrigin, planted: refusedOrigin}
	return takeover, blobs
}

// The retoken posted on its own goroutine, its answer to come on the channel, once its settle wait's timer is pending
// on the fake clock: the time the wait ends, when the clock is advanced to it, and the retoken's origin.
func (self *takeoverCase) postRetokenToTheWait() (<-chan *httptest.ResponseRecorder, time.Time, EvsSlotOrigin) {
	fixture := self.fixture
	fixture.t.Helper()
	_, _, storedAt, _ := fixture.slotObject(self.slotId)
	body, origin := fixture.bodyAndOrigin(self.retoken("s"))
	answered := make(chan *httptest.ResponseRecorder, 1)
	token := fixture.token(fixture.check.signerId)
	go func() {
		answered <- fixture.post(token, body)
	}()
	settledAt := storedAt.Add(fixture.settings.SlotSettleAge)
	fixture.awaitTimerAt(settledAt)
	return answered, settledAt, origin
}

// The refused statement's object stands as it was stored, and the retoken did not commit.
func (self *takeoverCase) requireUntaken(storedAt time.Time) {
	fixture := self.fixture
	fixture.t.Helper()
	fixture.requireSlotOrigin(self.slotId, self.slotBody, self.refused)
	if _, _, lastModified, _ := fixture.slotObject(self.slotId); !lastModified.Equal(storedAt) {
		fixture.t.Fatal("the refused statement's object was replaced")
	}
	if head := fixture.head(); head.Version() != 3 {
		fixture.t.Fatalf("the retoken committed at %d", head.Version())
	}
}

// Owner decision 629 at the takeover's DELETE: the cover the retoken read as it arrived was 4 s old, the settle wait
// aged it past the bound, and hold/ read again shows a hold api acknowledged during the wait, so no DELETE issues
// and the retoken is refused 409 SLOT_STALE, as under a hold standing before the wait; the object stands.
func TestPushSlotTakeoverHoldAcknowledgedDuringTheSettleWaitStopsTheDelete(t *testing.T) {
	takeover, blobs := newHoldTakeoverCase(t, "held in the wait", 4*time.Second)
	fixture := takeover.fixture
	_, _, storedAt, _ := fixture.slotObject(takeover.slotId)
	answered, settledAt, _ := takeover.postRetokenToTheWait()
	placeTestHold(t, fixture.ctx, fixture.host.Blobs, fixture.clock, fixture.check.networkId, "settle wait case")
	fixture.clock.AdvanceTo(settledAt)
	requireRefusal(t, <-answered, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_STALE)
	takeover.requireUntaken(storedAt)
	if got := blobs.reads(); got != 2 {
		t.Fatalf("%d hold/ reads, want the cached one and the one at the DELETE", got)
	}
	if foreign, _ := fixture.slotCounts(); foreign != 1 {
		t.Fatalf("counted %v foreign", foreign)
	}
}

// A quick takeover deletes on the cached read, as before: the cover read as the retoken arrived is still under the
// bound when the settle wait ends, so a hold api acknowledged during the wait, under the bound before the DELETE,
// does not bind it yet, and no read of hold/ is added. The retoken commits, its own object in the slot.
func TestPushSlotTakeoverQuickDeletesOnTheCachedRead(t *testing.T) {
	takeover, blobs := newHoldTakeoverCase(t, "quick", 0)
	fixture := takeover.fixture
	answered, settledAt, origin := takeover.postRetokenToTheWait()
	placeTestHold(t, fixture.ctx, fixture.host.Blobs, fixture.clock, fixture.check.networkId, "recent case")
	fixture.clock.AdvanceTo(settledAt)
	fixture.requireCommitted(<-answered, 4)
	fixture.requireSlotOrigin(takeover.slotId, takeover.slotBody, origin)
	if got := blobs.reads(); got != 1 {
		t.Fatalf("%d hold/ reads, want the cached one alone", got)
	}
}

// A slow reread refuses: the settle wait aged the cover past the bound, and hold/ read again comes back past the
// bound itself (ErrHoldReadStale), so the takeover sends no DELETE and answers 503, refusing nothing; the object
// stands.
func TestPushSlotTakeoverSlowRereadAnswers503(t *testing.T) {
	takeover, blobs := newHoldTakeoverCase(t, "slow reread", 4*time.Second)
	fixture := takeover.fixture
	_, _, storedAt, _ := fixture.slotObject(takeover.slotId)
	blobs.setOnList(func(count int) error {
		if count == 2 {
			fixture.clock.Advance(holdTestStall)
		}
		return nil
	})
	answered, settledAt, _ := takeover.postRetokenToTheWait()
	fixture.clock.AdvanceTo(settledAt)
	requireRefusal(t, <-answered, http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	takeover.requireUntaken(storedAt)
	if got := blobs.reads(); got != 2 {
		t.Fatalf("%d hold/ reads, want the cached one and the one at the DELETE", got)
	}
	if foreign, _ := fixture.slotCounts(); foreign != 0 {
		t.Fatalf("counted %v foreign", foreign)
	}
}

// A reread that fails is an unknown cover: the takeover sends no DELETE and answers 503, refusing nothing.
func TestPushSlotTakeoverFailedRereadAnswers503(t *testing.T) {
	takeover, blobs := newHoldTakeoverCase(t, "failed reread", 4*time.Second)
	fixture := takeover.fixture
	_, _, storedAt, _ := fixture.slotObject(takeover.slotId)
	blobs.setOnList(func(count int) error {
		if count == 2 {
			return errors.New("hold/ unreachable")
		}
		return nil
	})
	answered, settledAt, _ := takeover.postRetokenToTheWait()
	fixture.clock.AdvanceTo(settledAt)
	requireRefusal(t, <-answered, http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	takeover.requireUntaken(storedAt)
	if got := blobs.reads(); got != 2 {
		t.Fatalf("%d hold/ reads, want the cached one and the one at the DELETE", got)
	}
}
