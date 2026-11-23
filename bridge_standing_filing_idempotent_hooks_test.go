//go:build sidecar_testhooks && !ios_extension

// Two standing filings of one effect at once, on the filer's barriers (bridge_standing_filing_idempotent_test.go's
// world, its view behind the log): one held once it has taken its id and kept it in its marker, before it signs, and
// the other files under that id, a filing of the held id when the first then files too; one held once its post landed
// and its bytes are kept, and the other posts those bytes again, which api answers with the entry it holds. Either way
// both answer one id and one rule of the host is in force. Each a top-level test.

package sidecar

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Holds the first caller to reach the barrier name until release runs, closing reached when it does; every other
// caller passes. The test's end releases it too, so a test that fails while it is held leaves nothing waiting.
func testStandingHoldFirst(t *testing.T, name string) (chan struct{}, func()) {
	t.Helper()
	reached, released := make(chan struct{}), make(chan struct{})
	var holdOnce, releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() { close(released) })
	}
	SetTestHooks(&TestHooks{Barrier: func(barrier string, key string) {
		if barrier != name {
			return
		}
		first := false
		holdOnce.Do(func() { first = true })
		if first {
			close(reached)
			<-released
		}
	}})
	t.Cleanup(func() {
		release()
		SetTestHooks(nil)
	})
	return reached, release
}

// One filing's answer.
type testStandingAnswer struct {
	filing *BridgeFiling
	err    error
}

// Waits for the held filing to reach its barrier, failing the test where it answers first, as one whose path holds no
// such barrier does.
func testStandingAwait(t *testing.T, reached chan struct{}, answers chan testStandingAnswer) {
	t.Helper()
	select {
	case <-reached:
	case answer := <-answers:
		t.Fatalf("the first filing answered without reaching its barrier: %+v %v", answer.filing, answer.err)
	}
}

// The first filing holds after its id is taken and kept, before it signs; the second finds the marker with no bytes
// and nothing pending under its id, files under it, and lands first; the first then files under it too, a filing of
// the held id. Both answer the id, the log took two filings of it, the first in force and the second held, and the
// host holds one route.
func TestConcurrentStandingFilingsOfOneEffectTakeOneId(t *testing.T) {
	world, lag := newTestStandingWorld(t, false)
	ctx := context.Background()
	reached, release := testStandingHoldFirst(t, "bridge_file.standing.after")
	request := testStandingRouteRequest("10.80.0.0/24")
	answers := make(chan testStandingAnswer, 1)
	go func() {
		filing, err := world.filer.Expose(ctx, world.mcp(), request)
		answers <- testStandingAnswer{filing: filing, err: err}
	}()
	testStandingAwait(t, reached, answers)
	_, marker := world.standingMarker()
	if len(marker.Signed) != 0 {
		t.Fatal("the held filing kept bytes before it signed")
	}
	second, err := world.filer.Expose(ctx, world.mcp(), request)
	if err != nil {
		t.Fatal(err)
	}
	release()
	first := <-answers
	if first.err != nil {
		t.Fatal(first.err)
	}
	if !bytes.Equal(second.RuleId, marker.RuleId) || !bytes.Equal(first.filing.RuleId, marker.RuleId) {
		t.Fatalf("the filings answered %x and %x, the marker's id %x", second.RuleId, first.filing.RuleId, marker.RuleId)
	}
	filings := world.filingsOf(marker.RuleId)
	if len(filings) != 2 || len(world.hostFilings(bridge.SignedType_SIGNED_BRIDGE_ROUTE)) != 2 {
		t.Fatalf("%d filings of the id", len(filings))
	}
	ledger := world.ledger()
	testBridgeDisposition(t, ledger, filings[0].N, BridgeDispositionActive)
	testBridgeDisposition(t, ledger, filings[1].N, BridgeDispositionHeld)
	lag.catchUp()
	if rules := world.hostRules(bridge.SignedType_SIGNED_BRIDGE_ROUTE); len(rules) != 1 || !rules[0].Active() {
		t.Fatalf("the host's routes: %+v", rules)
	}
}

// The first filing holds once its post landed and its bytes are kept, before it appends its route entry; the second,
// whose view does not show the route, posts those bytes again, which api answers with the entry it holds, and appends
// the entry the first owed. Both answer the id, the log took one route of the host, and one route entry names it.
func TestAStandingFilingAskedWhileItsPostLandsIsAnsweredOnce(t *testing.T) {
	world, lag := newTestStandingWorld(t, false)
	ctx := context.Background()
	reached, release := testStandingHoldFirst(t, "bridge_file.rule.after")
	request := testStandingRouteRequest("10.81.0.0/24")
	answers := make(chan testStandingAnswer, 1)
	go func() {
		filing, err := world.filer.Expose(ctx, world.mcp(), request)
		answers <- testStandingAnswer{filing: filing, err: err}
	}()
	testStandingAwait(t, reached, answers)
	if lag.State().Bridge().Len() != 0 {
		t.Fatal("the view shows the route")
	}
	second, err := world.filer.Expose(ctx, world.mcp(), request)
	if err != nil {
		t.Fatal(err)
	}
	release()
	first := <-answers
	if first.err != nil {
		t.Fatal(first.err)
	}
	if !bytes.Equal(first.filing.RuleId, second.RuleId) {
		t.Fatalf("the filings answered %x and %x", first.filing.RuleId, second.RuleId)
	}
	posted := world.api.postedBytes()
	if len(posted) != 2 || !bytes.Equal(posted[0], posted[1]) {
		t.Fatalf("%d posts, not each the route's same bytes", len(posted))
	}
	if filings := world.hostFilings(bridge.SignedType_SIGNED_BRIDGE_ROUTE); len(filings) != 1 {
		t.Fatalf("the log took %d routes of the host", len(filings))
	}
	if routes := world.records.routes(t); len(routes) != 1 {
		t.Errorf("%d route entries for one route", len(routes))
	}
}
