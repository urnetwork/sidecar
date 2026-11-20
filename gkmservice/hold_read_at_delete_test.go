package gkmservice

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// A store whose first cluster runs a hook after each LIST of hold/ has read the store and before its answer comes
// back: a LIST slow to answer, during which the hook can place a hold the answer does not show.
type gkmSlowHoldListBlobs struct {
	sidecar.BlobStore
	stateLock sync.Mutex
	listCount int
	afterList func(count int)
}

func (self *gkmSlowHoldListBlobs) FirstCluster() (sidecar.BlobCluster, error) {
	cluster, err := self.BlobStore.FirstCluster()
	if err != nil {
		return nil, err
	}
	return &gkmSlowHoldListCluster{BlobCluster: cluster, blobs: self}, nil
}

func (self *gkmSlowHoldListBlobs) lists() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.listCount
}

type gkmSlowHoldListCluster struct {
	sidecar.BlobCluster
	blobs *gkmSlowHoldListBlobs
}

func (self *gkmSlowHoldListCluster) List(ctx context.Context, keyPrefix string, startAfter string, limit int) ([]*sidecar.BlobInfo, bool, error) {
	objects, more, err := self.BlobCluster.List(ctx, keyPrefix, startAfter, limit)
	if strings.HasPrefix(keyPrefix, "hold/") {
		count := func() int {
			self.blobs.stateLock.Lock()
			defer self.blobs.stateLock.Unlock()
			self.blobs.listCount += 1
			return self.blobs.listCount
		}()
		if self.blobs.afterList != nil {
			self.blobs.afterList(count)
		}
	}
	return objects, more, err
}

// A budget whose P2 turn comes once a hook has run: the wait for the turn, which the hook makes as long as it likes.
type gkmWaitingBudget struct {
	sidecar.WriteBudget
	beforeP2 func()
}

func (self *gkmWaitingBudget) AcquireP2(ctx context.Context, clusterId string, work *sidecar.WriteP2Work) (sidecar.WriteGrant, error) {
	if self.beforeP2 != nil {
		self.beforeP2()
	}
	return self.WriteBudget.AcquireP2(ctx, clusterId, work)
}

// A reconciler over a slow-listing hold store and a waiting budget, with one sidecar's KeyPackage past its 90 d. The
// budget's first turn comes past the bound, so the turn's recheck reads hold/ again; slow sets that read to answer past
// the bound too, missing a hold acknowledged while it was out.
func runGkmSweepAtABudgetTurnPastTheBound(t *testing.T, slow bool) (stands bool, lists int) {
	fixture := newGkmFixture(t)
	state := newFakeGkmReconcilerState()
	networkId, leaf := testId("network-a"), testId("sc-leaf")
	state.sidecarNetworks[leaf] = networkId
	holdBlobs := &gkmSlowHoldListBlobs{BlobStore: fixture.host.Blobs}
	host := fixture.host.ServiceHost()
	budget := &gkmWaitingBudget{WriteBudget: host.Budget}
	host.Budget = budget
	reconciler, err := NewGkmReconciler(fixture.ctx, host, DefaultGkmReconcilerSettings(), &GkmReconcilerDeps{
		State: state, Holds: sidecar.NewHoldSet(holdBlobs, fixture.clock, nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reconciler.Close)
	kpKey, _ := GkmKeyPackageKey(leaf, bytes.Repeat([]byte{0x11}, gkmKeyPackageRefByteCount))
	fixture.put("meta-1", kpKey, []byte("a KeyPackage"))
	fixture.clock.Advance(91 * 24 * time.Hour)

	bound := sidecar.DefaultHoldSetSettings().RereadInterval
	waited := false
	budget.beforeP2 = func() {
		if !waited {
			waited = true
			fixture.clock.Advance(bound + time.Second)
		}
	}
	holdBlobs.afterList = func(count int) {
		if count != 2 || !slow {
			return
		}
		// the recheck's LIST read the store before the hold; its answer comes back past the bound
		fixture.clock.Advance(500 * time.Millisecond)
		holdBytes, err := sidecar.EncodeHoldRecord(&sidecar.HoldRecord{
			NetworkId: networkId, CaseId: testId("case-during-the-list"), Kind: sidecar.HoldKindPreserve2703f,
			Scope: sidecar.HoldScopeNetwork(), PlaceTime: fixture.clock.Now(), ExpireTime: fixture.clock.Now().Add(365 * 24 * time.Hour),
		})
		if err != nil {
			t.Fatal(err)
		}
		fixture.put("meta-1", sidecar.HoldObjectKey(networkId, testId("case-during-the-list")), holdBytes)
		fixture.clock.Advance(bound + time.Second - 500*time.Millisecond)
	}
	cursor := &GkmSweepCursor{}
	for i := 0; ; i += 1 {
		next, done, err := reconciler.SweepPage(fixture.ctx, cursor)
		if err != nil {
			t.Fatal(err)
		}
		if done {
			break
		}
		if 10000 < i {
			t.Fatal("a sweep pass that never ends")
		}
		cursor = next
	}
	if !waited {
		t.Fatal("the KeyPackage's DELETE never asked the budget")
	}
	return fixture.object("meta-1", kpKey) != nil, holdBlobs.lists()
}

// Owner decision 629 at gkm's DELETE: the budget's recheck is the last request before the DELETE, and its read of hold/
// came back past the bound, missing a hold acknowledged while it was out, so the KeyPackage stays.
func TestGkmSweepKeepsWhatAReadPastItsBoundCannotClear(t *testing.T) {
	stands, lists := runGkmSweepAtABudgetTurnPastTheBound(t, true)
	if !stands {
		t.Fatal("the KeyPackage went on a read of hold/ older than its bound")
	}
	if lists != 2 {
		t.Fatalf("%d LISTs of hold/, want the first check's and the recheck's", lists)
	}
}

// The same turn with a read that answers at once deletes: the recheck read hold/ again, once, and found nothing.
func TestGkmSweepDeletesOnAQuickReadAtItsBudgetTurn(t *testing.T) {
	stands, lists := runGkmSweepAtABudgetTurnPastTheBound(t, false)
	if stands {
		t.Fatal("the KeyPackage stayed on a fresh read that shows no hold")
	}
	if lists != 2 {
		t.Fatalf("%d LISTs of hold/, want the first check's and one at the turn", lists)
	}
}
